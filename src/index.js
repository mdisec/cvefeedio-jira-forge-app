/**
 * CVEFeed.io Forge app — resolver functions.
 *
 * Every Forge module (issue panel, dashboard, admin page, etc.) communicates
 * with its Custom UI frontend through resolver functions defined here.
 * The frontend calls `invoke("functionName", { payload })` and receives
 * the return value.
 */

import crypto from "crypto";
import Resolver from "@forge/resolver";
import { route, asUser, asApp, webTrigger } from "@forge/api";
import {
  searchVulnerabilities,
  advancedSearchVulnerabilities,
  getVulnerability,
  getVulnerabilityHistory,
  getProjectVulnerabilities,
  getProjectAlerts,
  getAllProjectAlerts,
  markAlertRead,
  getProductSubscriptions,
  searchProducts,
  getProjectDetails,
  validateApiToken,
  checkTokenPermissions,
  extractCveIds,
  extractKeywords,
  registerWebhook,
  deregisterWebhook,
  syncIssueConfig,
  CveFeedApiError,
} from "./api";
import {
  getConfig,
  saveConfig,
  deleteConfig,
  isConfigured,
  getProjects,
  getProject,
  addProject,
  removeProject,
  getProjectToken,
  saveProjectToken,
  deleteProjectToken,
  getProjectIssueConfig,
  saveProjectIssueConfig,
  deleteProjectIssueConfig,
  getProjectWebhookSecret,
  saveProjectWebhookSecret,
  deleteProjectWebhookSecret,
  getCached,
  setCached,
  clearProjectCache,
  clearAllCaches,
  migrateIfNeeded,
} from "./storage";

const resolver = new Resolver();

// ═══════════════════════════════════════════════════════════════
// LICENSE CHECK
// ═══════════════════════════════════════════════════════════════

function checkLicense(context) {
  const license = context?.license;
  if (!license) return { active: false, reason: "no_license" };
  if (license.isActive) return { active: true };
  return { active: false, reason: license.billingPeriod ? "expired" : "inactive" };
}

/**
 * Check whether the calling user has CREATE_ISSUES permission in the given
 * Jira project.  Uses asUser() so the check runs against the invoking
 * user's actual permissions rather than the app's elevated identity.
 *
 * Required by Atlassian FSRT authorization policy — resolvers that perform
 * write operations via asApp() must first verify the caller is authorized.
 * @see https://developer.atlassian.com/platform/forge/runtime-reference/authorize-api/
 */
async function checkUserCanCreateIssues(projectKey) {
  try {
    const response = await asUser().requestJira(
      route`/rest/api/3/mypermissions?projectKey=${projectKey}&permissions=CREATE_ISSUES`
    );
    if (!response.ok) return false;
    const data = await response.json();
    return data.permissions?.CREATE_ISSUES?.havePermission === true;
  } catch {
    return false;
  }
}

/**
 * Helper: get the first available project token for read-only API calls
 * (vulnerability search, CVE detail) that don't need a specific project context.
 */
async function getAnyProjectToken() {
  const projects = await getProjects();
  const projectIds = Object.keys(projects);
  if (projectIds.length === 0) return null;
  return getProjectToken(projectIds[0]);
}

// ═══════════════════════════════════════════════════════════════
// ISSUE PANEL RESOLVERS
// ═══════════════════════════════════════════════════════════════

/**
 * Get vulnerability data for the current Jira issue.
 * Extracts CVE IDs from the issue and fetches details from CVEFeed.io.
 */
resolver.define("getIssueVulnerabilities", async ({ payload, context }) => {
  const license = checkLicense(context);
  if (!license.active) {
    return { licensed: false, reason: license.reason, configured: false, vulnerabilities: [], cveIds: [] };
  }

  const configured = await isConfigured();
  if (!configured) {
    return { configured: false, vulnerabilities: [], cveIds: [] };
  }

  const apiToken = await getAnyProjectToken();
  if (!apiToken) {
    return { configured: false, vulnerabilities: [], cveIds: [] };
  }

  const { issueKey } = payload;

  try {
    // Fetch issue details from Jira to extract CVE IDs
    const issueResponse = await asUser().requestJira(
      route`/rest/api/3/issue/${issueKey}?fields=summary,description,labels,components,comment`
    );
    const issue = await issueResponse.json();

    // Extract CVE IDs from all text fields
    const textSources = [
      issue.fields?.summary || "",
      extractPlainText(issue.fields?.description) || "",
      ...(issue.fields?.labels || []),
      ...(issue.fields?.components?.map((c) => c.name) || []),
    ];

    // Also extract from comments
    if (issue.fields?.comment?.comments) {
      issue.fields.comment.comments.forEach((comment) => {
        textSources.push(extractPlainText(comment.body) || "");
      });
    }

    const allText = textSources.join(" ");
    const cveIds = extractCveIds(allText);

    if (cveIds.length === 0) {
      // No CVE IDs found — try keyword-based search
      const keywords = extractKeywords(issue);
      return {
        configured: true,
        vulnerabilities: [],
        cveIds: [],
        keywords,
        searchMode: "keywords",
      };
    }

    // Fetch vulnerability details for each CVE ID
    const vulnerabilities = await Promise.allSettled(
      cveIds.map((cveId) => getVulnerability(apiToken, cveId))
    );

    const results = vulnerabilities
      .filter((r) => r.status === "fulfilled")
      .map((r) => r.value);

    return {
      configured: true,
      vulnerabilities: results,
      cveIds,
      searchMode: "cve",
    };
  } catch (err) {
    console.error("Error fetching issue vulnerabilities:", err);
    return {
      configured: true,
      vulnerabilities: [],
      cveIds: [],
      error: err.message,
    };
  }
});

/**
 * Search vulnerabilities by keyword from the issue panel.
 */
resolver.define("searchVulnerabilities", async ({ payload }) => {
  const { query, page } = payload;
  try {
    const apiToken = await getAnyProjectToken();
    if (!apiToken) return { success: false, error: "Not configured." };
    const results = await searchVulnerabilities(apiToken, query, page || 1);
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Get full details for a specific CVE.
 */
resolver.define("getVulnerabilityDetail", async ({ payload }) => {
  const { cveId } = payload;
  try {
    const apiToken = await getAnyProjectToken();
    if (!apiToken) return { success: false, error: "Not configured." };
    const data = await getVulnerability(apiToken, cveId);
    return { success: true, data };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Get change history for a CVE.
 */
resolver.define("getVulnerabilityHistory", async ({ payload }) => {
  const { cveId } = payload;
  try {
    const apiToken = await getAnyProjectToken();
    if (!apiToken) return { success: false, error: "Not configured." };
    const data = await getVulnerabilityHistory(apiToken, cveId);
    return { success: true, data };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ═══════════════════════════════════════════════════════════════
// ISSUE GLANCE RESOLVER
// ═══════════════════════════════════════════════════════════════

resolver.define("getGlanceData", async ({ payload, context }) => {
  const license = checkLicense(context);
  if (!license.active) {
    return { label: "Unlicensed", status: "inactive" };
  }

  const configured = await isConfigured();
  if (!configured) {
    return { label: "Not configured", status: "inactive" };
  }

  try {
    const apiToken = await getAnyProjectToken();
    if (!apiToken) return { label: "Not configured", status: "inactive" };

    const { issueKey } = payload;
    const issueResponse = await asUser().requestJira(
      route`/rest/api/3/issue/${issueKey}?fields=summary,labels`
    );
    const issue = await issueResponse.json();

    const allText = [
      issue.fields?.summary || "",
      ...(issue.fields?.labels || []),
    ].join(" ");

    const cveIds = extractCveIds(allText);

    if (cveIds.length === 0) {
      return { label: "No CVEs", status: "empty", count: 0 };
    }

    // Quick severity check for the first few CVEs
    const results = await Promise.allSettled(
      cveIds.slice(0, 5).map((id) => getVulnerability(apiToken, id))
    );

    const vulns = results.filter((r) => r.status === "fulfilled").map((r) => r.value);
    const maxSeverity = getMaxSeverity(vulns);

    return {
      label: `${cveIds.length} CVE${cveIds.length > 1 ? "s" : ""}`,
      status: maxSeverity,
      count: cveIds.length,
    };
  } catch (err) {
    return { label: "Error", status: "error" };
  }
});

// ═══════════════════════════════════════════════════════════════
// DASHBOARD GADGET RESOLVERS
// ═══════════════════════════════════════════════════════════════

/**
 * Get dashboard data — recent alerts and vulnerability summary.
 * Accepts optional { projectId } to scope to a specific project.
 */
resolver.define("getDashboardData", async ({ payload, context }) => {
  const license = checkLicense(context);
  if (!license.active) {
    return { licensed: false, reason: license.reason, configured: false };
  }

  const configured = await isConfigured();
  if (!configured) {
    return { configured: false };
  }

  const projects = await getProjects();
  const projectIds = Object.keys(projects);
  if (projectIds.length === 0) return { configured: false };

  // Use specified project or first available
  const projectId = payload?.projectId || projectIds[0];
  const project = projects[projectId];
  if (!project) return { configured: false, error: "Project not found." };

  const apiToken = await getProjectToken(projectId);
  if (!apiToken) return { configured: false, error: "Project token not found." };

  try {
    // Fetch in parallel: alerts, subscriptions, project details
    const [alerts, subscriptions, projectDetails] = await Promise.all([
      getProjectAlerts(apiToken, projectId, { page_size: 10, order_by: "-created_at" }),
      getProductSubscriptions(apiToken, projectId),
      getProjectDetails(apiToken, projectId),
    ]);

    // Compute severity distribution from recent alerts
    const severityDistribution = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const alertResults = alerts.results || alerts;
    if (Array.isArray(alertResults)) {
      alertResults.forEach((alert) => {
        const severity = alert.vulnerability?.severity?.toUpperCase();
        if (severity && severityDistribution[severity] !== undefined) {
          severityDistribution[severity]++;
        }
      });
    }

    return {
      configured: true,
      projectId,
      projectName: project.projectName || projectDetails.name,
      alerts: alertResults.slice(0, 10),
      totalAlerts: alerts.count || alertResults.length,
      subscriptions: subscriptions.results || subscriptions,
      subscriptionUsage: projectDetails.product_subscriptions,
      severityDistribution,
      // Include project list so dashboard can show selector
      projects: Object.values(projects).map((p) => ({
        projectId: p.projectId,
        projectName: p.projectName,
      })),
    };
  } catch (err) {
    console.error("Dashboard data error:", err);
    return { configured: true, error: err.message };
  }
});

/**
 * Dashboard edit resolver — returns current gadget configuration.
 */
resolver.define("getDashboardConfig", async () => {
  const projects = await getProjects();
  const projectList = Object.values(projects).map((p) => ({
    projectId: p.projectId,
    projectName: p.projectName,
  }));
  return { projects: projectList };
});

/**
 * Mark an alert as read from the dashboard.
 */
resolver.define("markAlertRead", async ({ payload }) => {
  const { projectId, alertId } = payload;
  if (!projectId) return { success: false, error: "projectId is required." };

  const apiToken = await getProjectToken(projectId);
  if (!apiToken) return { success: false, error: "Project not configured." };

  try {
    await markAlertRead(apiToken, projectId, alertId);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ═══════════════════════════════════════════════════════════════
// ADMIN PAGE RESOLVERS
// ═══════════════════════════════════════════════════════════════

/**
 * Get current configuration status — returns project list with status.
 */
resolver.define("getAdminConfig", async ({ context }) => {
  await migrateIfNeeded();

  const license = checkLicense(context);
  const config = await getConfig();
  const projects = await getProjects();
  const projectIds = Object.keys(projects);

  if (projectIds.length === 0) {
    return { configured: false, projects: [], license };
  }

  // Enrich each project with issue config status
  const projectList = [];
  for (const pid of projectIds) {
    const proj = projects[pid];
    const issueConfig = await getProjectIssueConfig(pid);
    projectList.push({
      projectId: proj.projectId,
      projectName: proj.projectName,
      projectSlug: proj.projectSlug,
      addedAt: proj.addedAt,
      issueConfigured: !!(issueConfig && issueConfig.jiraProjectKey),
      jiraProjectKey: issueConfig?.jiraProjectKey || null,
      issueTypeName: issueConfig?.issueTypeName || null,
      autoCreateIssues: issueConfig?.autoCreateIssues ?? false,
    });
  }

  return {
    configured: true,
    projects: projectList,
    configuredAt: config?.configuredAt,
    configuredBy: config?.configuredBy,
    license,
  };
});

/**
 * Add a new CVEFeed project (replaces saveAdminConfig).
 */
resolver.define("addProject", async ({ payload, context }) => {
  const { apiToken, projectId } = payload;

  if (!apiToken || !projectId) {
    return { success: false, error: "API token and project ID are required." };
  }

  // Check if project already exists
  const existing = await getProject(projectId);
  if (existing) {
    return { success: false, error: `Project ${projectId} is already configured.` };
  }

  // Validate the token by calling the API
  const validation = await validateApiToken(apiToken, projectId);
  if (!validation.valid) {
    return {
      success: false,
      error: `Invalid credentials: ${validation.error}`,
    };
  }

  // Check token scopes before proceeding
  try {
    const permissions = await checkTokenPermissions(apiToken, projectId);
    if (!permissions.sufficient) {
      const missingList = Object.entries(permissions.missing)
        .map(([resource, info]) => `${resource}: needs '${info.required}', has '${info.current}'`)
        .join("; ");
      return {
        success: false,
        error: `Insufficient API token permissions. Missing scopes: ${missingList}. Please create a new API token with the required scopes on CVEFeed.io.`,
        permissionDetails: permissions,
      };
    }
  } catch (err) {
    return {
      success: false,
      error: `Permission check failed: ${err.message}. Ensure your API token has 'write' access to 'integrations'.`,
    };
  }

  // Save project token
  await saveProjectToken(projectId, apiToken);

  // Add project to registry
  const projectName = validation.project.name || `Project #${projectId}`;
  const projectSlug = validation.project.slug || "";
  await addProject({ projectId, projectName, projectSlug });

  // Ensure global config exists
  const globalConfig = await getConfig();
  if (!globalConfig) {
    await saveConfig({ configuredBy: context.accountId || "unknown" });
  }

  // Auto-register webhook URL with CVEFeed.io
  let webhookRegistered = false;
  try {
    const webhookUrl = await webTrigger.getUrl("cvefeed-incoming-webhook");
    const webhookResult = await registerWebhook(apiToken, projectId, webhookUrl);
    if (webhookResult.signing_secret) {
      await saveProjectWebhookSecret(projectId, webhookResult.signing_secret);
    }
    webhookRegistered = true;
  } catch (err) {
    console.error("Webhook registration failed:", err.message);
  }

  // Run initial sync for this project
  let syncResult = null;
  try {
    syncResult = await runSync(projectId);
  } catch (err) {
    console.error("Initial sync failed:", err.message);
  }

  return {
    success: true,
    projectId,
    projectName,
    projectSlug,
    sync: syncResult,
    webhookRegistered,
  };
});

/**
 * Remove a project (replaces deleteAdminConfig).
 */
resolver.define("removeProject", async ({ payload }) => {
  const { projectId } = payload;
  if (!projectId) return { success: false, error: "projectId is required." };

  // Deregister webhook
  try {
    const apiToken = await getProjectToken(projectId);
    if (apiToken) {
      await deregisterWebhook(apiToken, projectId);
    }
  } catch (err) {
    console.error("Webhook deregistration failed:", err.message);
  }

  // Delete all project-scoped data
  await deleteProjectToken(projectId);
  await deleteProjectIssueConfig(projectId);
  await deleteProjectWebhookSecret(projectId);
  await clearProjectCache(projectId);
  await removeProject(projectId);

  // If last project, also clear global config
  const remaining = await getProjects();
  if (Object.keys(remaining).length === 0) {
    await deleteConfig();
  }

  return { success: true };
});

/**
 * Test the API connection for a specific project.
 */
resolver.define("testConnection", async ({ payload }) => {
  const { projectId } = payload;
  if (!projectId) return { success: false, error: "projectId is required." };

  const apiToken = await getProjectToken(projectId);
  if (!apiToken) return { success: false, error: "Project token not found." };

  try {
    const details = await getProjectDetails(apiToken, projectId);
    return {
      success: true,
      projectName: details.name,
      subscriptions: details.product_subscriptions,
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ═══════════════════════════════════════════════════════════════
// JIRA ISSUE CREATION CONFIGURATION
// ═══════════════════════════════════════════════════════════════

const SEVERITY_PRIORITY_MAP = {
  critical: "Highest",
  high: "High",
  medium: "Medium",
  low: "Low",
};

/**
 * Fetch Jira projects accessible to the current user.
 */
resolver.define("getJiraProjects", async () => {
  function toProjectList(items) {
    return (Array.isArray(items) ? items : []).map((p) => ({
      id: p.id,
      key: p.key,
      name: p.name,
    }));
  }

  async function fetchFallbackProjects() {
    const fallback = await asUser().requestJira(route`/rest/api/3/project`);
    if (!fallback.ok) {
      const body = await fallback.text().catch(() => "");
      return { success: false, error: `Jira API error: ${fallback.status} — ${body}` };
    }
    const data = await fallback.json();
    return { success: true, projects: toProjectList(data) };
  }

  try {
    const response = await asUser().requestJira(
      route`/rest/api/3/project/search?maxResults=${100}&orderBy=${"name"}&status=${"live"}`
    );

    if (!response.ok) {
      return fetchFallbackProjects();
    }

    const data = await response.json();
    const projects = toProjectList(data.values || []);

    if (projects.length === 0) {
      const fallbackResult = await fetchFallbackProjects();
      if (fallbackResult.success && fallbackResult.projects.length > 0) {
        return fallbackResult;
      }
    }

    return { success: true, projects };
  } catch (err) {
    console.error("getJiraProjects error:", err);
    return { success: false, error: err.message || String(err) };
  }
});

/**
 * Fetch issue types for a specific Jira project.
 */
resolver.define("getJiraIssueTypes", async ({ payload }) => {
  const { projectKey } = payload;
  try {
    const response = await asUser().requestJira(
      route`/rest/api/3/issue/createmeta/${projectKey}/issuetypes`
    );
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      return { success: false, error: `Jira API error: ${response.status} — ${body}` };
    }
    const data = await response.json();
    const issueTypes = (data.issueTypes || data.values || [])
      .filter((t) => !t.subtask)
      .map((t) => ({
        id: t.id,
        name: t.name,
        description: t.description,
        iconUrl: t.iconUrl,
      }));
    return { success: true, issueTypes };
  } catch (err) {
    console.error("getJiraIssueTypes error:", err);
    return { success: false, error: err.message || String(err) };
  }
});

/**
 * Get current issue creation configuration for a project.
 */
resolver.define("getIssueConfig", async ({ payload }) => {
  const { projectId } = payload || {};
  if (!projectId) {
    return { configured: false, priorityMapping: SEVERITY_PRIORITY_MAP };
  }

  const config = await getProjectIssueConfig(projectId);
  if (!config) {
    return { configured: false, priorityMapping: SEVERITY_PRIORITY_MAP };
  }
  return {
    configured: true,
    ...config,
    markAsReadOnSync: config.markAsReadOnSync ?? true,
    priorityMapping: config.priorityMapping || SEVERITY_PRIORITY_MAP,
  };
});

/**
 * Save issue creation configuration for a project.
 */
resolver.define("saveIssueConfig", async ({ payload }) => {
  const {
    projectId,
    jiraProjectKey,
    jiraProjectName,
    issueTypeId,
    issueTypeName,
    labels,
    autoCreateIssues,
    markAsReadOnSync,
    priorityMapping,
  } = payload;

  if (!projectId) return { success: false, error: "projectId is required." };
  if (!jiraProjectKey || !issueTypeId) {
    return { success: false, error: "Jira project and issue type are required." };
  }

  const config = await saveProjectIssueConfig(projectId, {
    jiraProjectKey,
    jiraProjectName,
    issueTypeId,
    issueTypeName,
    labels: labels || [],
    autoCreateIssues: autoCreateIssues ?? true,
    markAsReadOnSync: markAsReadOnSync ?? true,
    priorityMapping: priorityMapping || SEVERITY_PRIORITY_MAP,
  });

  // Sync settings to Django for display on the integrations page
  let synced = false;
  try {
    const apiToken = await getProjectToken(projectId);
    if (apiToken) {
      await syncIssueConfig(apiToken, projectId, {
        jiraProjectKey,
        issueTypeId,
        labels: labels || [],
        autoCreateIssues: autoCreateIssues ?? true,
        markAsReadOnSync: markAsReadOnSync ?? true,
      });
      synced = true;
    }
  } catch (err) {
    console.error("Config sync to CVEFeed.io failed:", err.message);
  }

  return { success: true, config, synced };
});

/**
 * Delete issue creation configuration for a project.
 */
resolver.define("deleteIssueConfig", async ({ payload }) => {
  const { projectId } = payload || {};
  if (!projectId) return { success: false, error: "projectId is required." };
  await deleteProjectIssueConfig(projectId);
  return { success: true };
});

/**
 * Create a test Jira issue to verify configuration.
 */
resolver.define("createTestIssue", async ({ payload }) => {
  const { projectId } = payload || {};
  if (!projectId) return { success: false, error: "projectId is required." };

  const issueConfig = await getProjectIssueConfig(projectId);
  if (!issueConfig || !issueConfig.jiraProjectKey || !issueConfig.issueTypeId) {
    return { success: false, error: "Issue creation not configured." };
  }

  try {
    const fields = {
      project: { key: issueConfig.jiraProjectKey },
      issuetype: { id: issueConfig.issueTypeId },
      summary: "[CVEFeed.io] Test Issue — Configuration Verified",
      description: {
        version: 1,
        type: "doc",
        content: [
          {
            type: "paragraph",
            content: [
              {
                type: "text",
                text: "This is a test issue created by the CVEFeed.io Forge app to verify your Jira issue creation configuration. You can safely delete this issue.",
              },
            ],
          },
          {
            type: "paragraph",
            content: [
              {
                type: "text",
                text: "Configuration verified at: " + new Date().toISOString(),
              },
            ],
          },
        ],
      },
      priority: { name: "Low" },
    };

    if (issueConfig.labels && issueConfig.labels.length > 0) {
      fields.labels = issueConfig.labels;
    }

    const response = await asUser().requestJira(route`/rest/api/3/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fields }),
    });

    if (!response.ok) {
      const errorBody = await response.text().catch(() => "");
      return {
        success: false,
        error: `Failed to create issue: ${response.status} — ${errorBody}`,
      };
    }

    const result = await response.json();
    return {
      success: true,
      issueKey: result.key,
      issueId: result.id,
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Manually trigger a sync for a specific project.
 */
resolver.define("syncNow", async ({ payload }) => {
  const { projectId } = payload || {};
  if (!projectId) return { success: false, error: "projectId is required." };

  try {
    const result = await runSync(projectId);
    return { success: true, ...result };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Preview how many Jira issues would be created from unread alerts.
 */
resolver.define("previewSyncIssues", async ({ payload }) => {
  const { projectId } = payload || {};
  if (!projectId) return { success: false, error: "projectId is required." };

  const apiToken = await getProjectToken(projectId);
  if (!apiToken) return { success: false, error: "Project token not found." };

  const issueConfig = await getProjectIssueConfig(projectId);
  if (!issueConfig || !issueConfig.jiraProjectKey || !issueConfig.issueTypeId) {
    return { success: false, error: "Issue creation is not configured. Set up a Jira project and issue type in Issue Settings first." };
  }

  try {
    const firstPage = await getProjectAlerts(apiToken, projectId, {
      page_size: 50,
      order_by: "-created_at",
      is_read: false,
    });

    const alerts = firstPage.results || firstPage || [];
    const totalCount = firstPage.count || alerts.length;

    const preview = [];
    for (const alert of alerts) {
      const cveId = alert.vulnerability?.id;
      if (!cveId) continue;
      preview.push({
        cveId,
        severity: alert.vulnerability?.severity || "N/A",
        title: alert.vulnerability?.title || cveId,
        product: alert.affected_products?.name || "N/A",
      });
    }

    return {
      success: true,
      totalAlerts: totalCount,
      toCreate: totalCount,
      duplicates: 0,
      preview: preview.slice(0, 50),
      projectKey: issueConfig.jiraProjectKey,
      markAsReadOnSync: issueConfig.markAsReadOnSync ?? true,
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Create Jira issues in batches to stay within the 25s Forge timeout.
 */
const BATCH_SIZE = 10;

resolver.define("createIssuesBatch", async ({ payload, context }) => {
  const { projectId } = payload || {};
  if (!projectId) return { success: false, error: "projectId is required." };

  const apiToken = await getProjectToken(projectId);
  if (!apiToken) return { success: false, error: "Project token not found." };

  const project = await getProject(projectId);
  const projectSlug = project?.projectSlug || "";

  const issueConfig = await getProjectIssueConfig(projectId);
  if (!issueConfig || !issueConfig.jiraProjectKey || !issueConfig.issueTypeId) {
    return { success: false, error: "Issue creation is not configured." };
  }

  // Verify the calling user has CREATE_ISSUES permission in the target
  // Jira project before proceeding with asApp() calls (FSRT requirement).
  const canCreate = await checkUserCanCreateIssues(issueConfig.jiraProjectKey);
  if (!canCreate) {
    return {
      success: false,
      error: "You do not have permission to create issues in this project.",
    };
  }

  try {
    const currentPage = payload?.page || 1;
    const response = await getProjectAlerts(apiToken, projectId, {
      page_size: BATCH_SIZE,
      page: currentPage,
      order_by: "-created_at",
      is_read: false,
    });

    const alerts = response.results || response || [];
    const totalCount = response.count || 0;

    if (alerts.length === 0) {
      return {
        success: true,
        issuesCreated: 0,
        issuesSkipped: 0,
        issueErrors: 0,
        created: [],
        hasMore: false,
        nextPage: null,
        total: 0,
        processed: 0,
      };
    }

    let issuesCreated = 0;
    let issuesSkipped = 0;
    let issueErrors = 0;
    const created = [];

    for (const alert of alerts) {
      const cveId = alert.vulnerability?.id;
      const alertId = alert.id;
      if (!cveId) continue;

      try {
        const duplicate = await findExistingIssue(cveId, issueConfig.jiraProjectKey);
        if (duplicate) {
          issuesSkipped++;
        } else {
          const result = await createJiraIssueFromAlert(alert, issueConfig, projectSlug);
          issuesCreated++;
          created.push({ cveId, issueKey: result.issueKey });
        }
        // Mark alert as read so it drops off the unread list for next batch
        if (issueConfig.markAsReadOnSync !== false && alertId) {
          try {
            await markAlertRead(apiToken, projectId, alertId);
          } catch (markErr) {
            console.error(`Failed to mark alert ${alertId} as read:`, markErr.message);
          }
        }
      } catch (err) {
        console.error(`Failed to create issue for ${cveId}:`, err.message);
        issueErrors++;
      }
    }

    const remaining = totalCount - alerts.length;
    const hasMore = alerts.length === BATCH_SIZE && remaining > 0;
    const markAsRead = issueConfig.markAsReadOnSync !== false;
    const nextPage = hasMore ? (markAsRead ? 1 : currentPage + 1) : null;

    return {
      success: true,
      issuesCreated,
      issuesSkipped,
      issueErrors,
      created,
      hasMore,
      nextPage,
      total: totalCount,
      processed: alerts.length,
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ═══════════════════════════════════════════════════════════════
// GLOBAL PAGE RESOLVERS
// ═══════════════════════════════════════════════════════════════

/**
 * Advanced vulnerability search for the global page.
 */
resolver.define("advancedSearch", async ({ payload }) => {
  try {
    const apiToken = await getAnyProjectToken();
    if (!apiToken) return { success: false, error: "Not configured." };
    const data = await advancedSearchVulnerabilities(apiToken, payload.filters || {});
    return { success: true, data };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Get project vulnerabilities for the global page.
 */
resolver.define("getProjectVulnerabilities", async ({ payload }) => {
  const { projectId } = payload || {};
  const projects = await getProjects();
  const pid = projectId || Object.keys(projects)[0];
  if (!pid) return { success: false, error: "Not configured" };

  const apiToken = await getProjectToken(pid);
  if (!apiToken) return { success: false, error: "Project token not found." };

  try {
    const data = await getProjectVulnerabilities(apiToken, pid, payload.params || {});
    return { success: true, data };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Search products for subscription management.
 */
resolver.define("searchProducts", async ({ payload }) => {
  const { projectId } = payload || {};
  const projects = await getProjects();
  const pid = projectId || Object.keys(projects)[0];
  if (!pid) return { success: false, error: "Not configured" };

  const apiToken = await getProjectToken(pid);
  if (!apiToken) return { success: false, error: "Project token not found." };

  try {
    const data = await searchProducts(apiToken, pid, payload.keyword);
    return { success: true, data };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ═══════════════════════════════════════════════════════════════
// WEB TRIGGER — INCOMING WEBHOOK FROM CVEFEED.IO
// ═══════════════════════════════════════════════════════════════

/**
 * Receives real-time vulnerability alert pushes from CVEFeed.io.
 * Routes to the correct project based on project_id in the payload.
 */
export async function incomingWebhookHandler(request) {
  await migrateIfNeeded();

  let payload;
  try {
    payload = JSON.parse(request.body);
  } catch (err) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Invalid JSON payload" }),
    };
  }

  // Extract project_id from payload for routing
  const projectId = payload.project_id || payload.project?.id;
  if (!projectId) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Missing project_id in payload" }),
    };
  }

  // Look up project in registry
  const project = await getProject(String(projectId));
  if (!project) {
    return {
      statusCode: 404,
      body: JSON.stringify({ error: `Project ${projectId} not registered` }),
    };
  }

  // Verify per-project signing secret
  const signingSecret = await getProjectWebhookSecret(String(projectId));
  if (signingSecret) {
    let headerSecret = request.headers?.["x-webhook-secret"];
    if (Array.isArray(headerSecret)) {
      headerSecret = headerSecret[0];
    }
    const secretBuf = Buffer.from(signingSecret, "utf8");
    const headerBuf = Buffer.from(headerSecret || "", "utf8");
    if (secretBuf.length !== headerBuf.length || !crypto.timingSafeEqual(secretBuf, headerBuf)) {
      console.warn(`Webhook signature verification failed for project ${projectId}`);
      return {
        statusCode: 403,
        body: JSON.stringify({ error: "Invalid webhook signature" }),
      };
    }
  }

  if (!payload.vulnerability?.id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Invalid payload: missing vulnerability.id" }),
    };
  }

  const cveId = payload.vulnerability.id;

  // Cache the alert under the project
  const cacheKey = `alert:${cveId}`;
  await setCached(String(projectId), cacheKey, payload);

  // Auto-create Jira issue if enabled — use per-project issue config
  let issueCreated = null;
  const issueConfig = await getProjectIssueConfig(String(projectId));
  if (issueConfig && issueConfig.autoCreateIssues && issueConfig.jiraProjectKey && issueConfig.issueTypeId) {
    try {
      const duplicate = await findExistingIssue(cveId, issueConfig.jiraProjectKey);
      if (duplicate) {
        issueCreated = { skipped: true, existingKey: duplicate };
      } else {
        const result = await createJiraIssueFromAlert(payload, issueConfig, project.projectSlug || "");
        issueCreated = result;
      }
    } catch (err) {
      console.error("Failed to create Jira issue:", err.message);
      issueCreated = { error: err.message };
    }
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      received: true,
      projectId,
      cveId,
      issueCreated,
    }),
  };
}

/**
 * Search for an existing Jira issue with the same CVE ID to prevent duplicates.
 */
async function findExistingIssue(cveId, projectKey) {
  try {
    const jql = `project = "${projectKey}" AND summary ~ "${cveId}" ORDER BY created DESC`;
    const response = await asApp().requestJira(
      route`/rest/api/3/search?jql=${jql}&maxResults=${1}&fields=${"key"}`
    );
    if (!response.ok) return null;
    const data = await response.json();
    if (data.issues && data.issues.length > 0) {
      return data.issues[0].key;
    }
    return null;
  } catch (err) {
    console.error("Duplicate check failed:", err.message);
    return null; // Don't block creation if search fails
  }
}

/**
 * Create a Jira issue from a CVEFeed alert payload.
 * Mirrors the existing backend's build_jira_issue_fields logic.
 */
async function createJiraIssueFromAlert(alert, issueConfig, projectSlug) {
  const vuln = alert.vulnerability;
  const product = alert.affected_products || {};
  const vendor = product.vendor || {};
  const severity = (vuln.severity || "medium").toLowerCase();
  const priorityMapping = issueConfig.priorityMapping || SEVERITY_PRIORITY_MAP;
  const priorityName = priorityMapping[severity] || "Medium";
  const isRansomware = !!alert.ransomware_notified_at || alert.reason === "ransomware_status_changed";

  // Build summary: [CVEFeed] CVE-ID — Product Name
  let summary = `[CVEFeed] ${vuln.id}`;
  if (product.name) summary += ` — ${product.name}`;
  if (isRansomware) summary = `[RANSOMWARE] ${summary}`;
  summary = summary.slice(0, 255);

  // Build ADF description
  const descriptionContent = [];

  // Heading
  descriptionContent.push({
    type: "heading",
    attrs: { level: 2 },
    content: [{ type: "text", text: `Vulnerability Alert: ${vuln.id}` }],
  });

  // Ransomware warning panel
  if (isRansomware) {
    descriptionContent.push({
      type: "panel",
      attrs: { panelType: "error" },
      content: [{
        type: "paragraph",
        content: [{
          type: "text",
          text: "CISA has confirmed this CVE is being actively used in known ransomware campaigns. Immediate action recommended.",
          marks: [{ type: "strong" }],
        }],
      }],
    });
  }

  // Info table
  const tableRows = [
    ["CVE ID", vuln.id],
    ["Severity", (vuln.severity || "N/A").toUpperCase()],
    ["CVSS Score", String(vuln.cvss_score || "N/A")],
    ["Vendor", vendor.name || "N/A"],
    ["Product", product.name || "N/A"],
    ["Published", vuln.published ? new Date(vuln.published).toLocaleDateString() : "N/A"],
  ];

  descriptionContent.push({
    type: "table",
    attrs: { isNumberColumnEnabled: false, layout: "default" },
    content: tableRows.map(([label, value]) => ({
      type: "tableRow",
      content: [
        {
          type: "tableHeader",
          content: [{ type: "paragraph", content: [{ type: "text", text: label }] }],
        },
        {
          type: "tableCell",
          content: [{ type: "paragraph", content: [{ type: "text", text: value }] }],
        },
      ],
    })),
  });

  // Description text
  if (vuln.description) {
    descriptionContent.push({
      type: "paragraph",
      content: [{ type: "text", text: vuln.description.slice(0, 2000) }],
    });
  }

  // Solution section
  if (vuln.solution) {
    descriptionContent.push({
      type: "heading",
      attrs: { level: 3 },
      content: [{ type: "text", text: "Solution" }],
    });

    // solution can be: string, array of strings, or object with { overview, actions[] }
    let solutionSteps = [];
    if (typeof vuln.solution === "string") {
      solutionSteps = [vuln.solution];
    } else if (Array.isArray(vuln.solution)) {
      solutionSteps = vuln.solution.map((s) => (typeof s === "string" ? s : JSON.stringify(s)));
    } else if (typeof vuln.solution === "object" && vuln.solution !== null) {
      if (vuln.solution.overview) solutionSteps.push(vuln.solution.overview);
      if (Array.isArray(vuln.solution.actions)) {
        solutionSteps.push(...vuln.solution.actions.map((a) => (typeof a === "string" ? a : JSON.stringify(a))));
      }
    }

    if (solutionSteps.length > 0) {
      descriptionContent.push({
        type: "bulletList",
        content: solutionSteps.map((step) => ({
          type: "listItem",
          content: [{ type: "paragraph", content: [{ type: "text", text: String(step) }] }],
        })),
      });
    }

    if (vuln.patch) {
      descriptionContent.push({
        type: "paragraph",
        content: [
          { type: "text", text: "Patch: ", marks: [{ type: "strong" }] },
          { type: "text", text: vuln.patch, marks: [{ type: "code" }] },
        ],
      });
    }
  }

  // Link to CVEFeed
  const cvefeedUrl = vuln.url || `https://cvefeed.io/vuln/detail/${vuln.id}`;
  descriptionContent.push({
    type: "paragraph",
    content: [
      { type: "text", text: "View full details on CVEFeed.io: " },
      {
        type: "text",
        text: cvefeedUrl,
        marks: [{ type: "link", attrs: { href: cvefeedUrl } }],
      },
    ],
  });

  const fields = {
    project: { key: issueConfig.jiraProjectKey },
    issuetype: { id: issueConfig.issueTypeId },
    summary,
    description: {
      version: 1,
      type: "doc",
      content: descriptionContent,
    },
    priority: { name: isRansomware ? "Highest" : priorityName },
  };

  // Labels — always include project slug for routing/filtering
  const labels = [...(issueConfig.labels || [])];
  if (projectSlug && !labels.includes(projectSlug)) {
    labels.push(projectSlug);
  }
  if (isRansomware && !labels.includes("ransomware")) {
    labels.push("ransomware");
  }
  if (labels.length > 0) {
    fields.labels = labels;
  }

  // Web triggers run without user context — use asApp()
  const response = await asApp().requestJira(route`/rest/api/3/issue`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fields }),
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => "");
    throw new Error(`Jira API ${response.status}: ${errorBody}`);
  }

  const result = await response.json();
  return { issueKey: result.key, issueId: result.id };
}

// ═══════════════════════════════════════════════════════════════
// SCHEDULED SYNC — HOURLY VULNERABILITY REFRESH
// ═══════════════════════════════════════════════════════════════

/**
 * Shared sync logic — used by addProject, and syncNow.
 * Fetches recent alerts and project details for dashboard display.
 */
async function runSync(projectId) {
  const apiToken = await getProjectToken(projectId);
  if (!apiToken) throw new Error(`No API token for project ${projectId}`);

  const details = await getProjectDetails(apiToken, projectId);
  await setCached(projectId, "project-details", details);

  // Fetch recent alerts (single page) — Forge storage has a 256 KB per-key limit,
  // so we only cache what the dashboard actually needs instead of all pages.
  const alertsResponse = await getProjectAlerts(apiToken, projectId, {
    page_size: 50,
    order_by: "-created_at",
  });

  const alertResults = alertsResponse.results || alertsResponse;
  const recentAlerts = Array.isArray(alertResults) ? alertResults : [];

  await setCached(projectId, "recent-alerts", { results: recentAlerts.slice(0, 20) });

  const subscriptions = await getProductSubscriptions(apiToken, projectId);
  await setCached(projectId, "subscriptions", subscriptions);

  const subCount = (subscriptions.results || subscriptions || []).length;

  return {
    alertCount: alertsResponse.count || recentAlerts.length,
    subscriptionCount: subCount,
    projectName: details.name,
    syncedAt: new Date().toISOString(),
  };
}

export async function scheduledSyncHandler() {
  await migrateIfNeeded();

  const projects = await getProjects();
  const projectIds = Object.keys(projects);

  if (projectIds.length === 0) {
    console.log("Scheduled sync skipped: no projects configured.");
    return;
  }

  for (const projectId of projectIds) {
    try {
      await runSync(projectId);
      console.log(`Scheduled sync complete for project ${projectId}`);
    } catch (err) {
      console.error(`Scheduled sync failed for project ${projectId}:`, err.message);
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// APP LIFECYCLE — INSTALL / UPGRADE
// ═══════════════════════════════════════════════════════════════

export async function webhookTriggerHandler(event) {
  // App lifecycle event handler (install/upgrade)
  // Run migration on upgrade
  await migrateIfNeeded();
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

/**
 * Extract plain text from an ADF (Atlassian Document Format) document.
 */
function extractPlainText(adfDoc) {
  if (!adfDoc) return "";
  if (typeof adfDoc === "string") return adfDoc;

  let text = "";
  function walk(node) {
    if (node.text) text += node.text + " ";
    if (node.content) node.content.forEach(walk);
  }
  walk(adfDoc);
  return text.trim();
}

/**
 * Get the highest severity from a list of vulnerabilities.
 */
function getMaxSeverity(vulns) {
  const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  let max = 0;
  let maxLabel = "low";

  vulns.forEach((v) => {
    const severity = (v.severity || "").toUpperCase();
    if (order[severity] > max) {
      max = order[severity];
      maxLabel = severity.toLowerCase();
    }
  });

  return maxLabel;
}

// ═══════════════════════════════════════════════════════════════
// EXPORTED HANDLER FUNCTIONS (referenced by manifest.yml)
// ═══════════════════════════════════════════════════════════════

// The resolver handles all Custom UI `invoke()` calls.
export const issuePanelResolver = resolver.getDefinitions();
export const issueGlanceResolver = resolver.getDefinitions();
export const dashboardResolver = resolver.getDefinitions();
export const dashboardEditResolver = resolver.getDefinitions();
export const adminResolver = resolver.getDefinitions();
export const globalPageResolver = resolver.getDefinitions();
