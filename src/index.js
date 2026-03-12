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
  getCached,
  setCached,
  clearCache,
  getIssueConfig,
  saveIssueConfig,
  deleteIssueConfig,
  saveWebhookSecret,
  getWebhookSecret,
  deleteWebhookSecret,
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
      cveIds.map((cveId) => getVulnerability(cveId))
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
    const results = await searchVulnerabilities(query, page || 1);
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
    const data = await getVulnerability(cveId);
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
    const data = await getVulnerabilityHistory(cveId);
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
      cveIds.slice(0, 5).map((id) => getVulnerability(id))
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

  const config = await getConfig();
  const projectId = config.projectId;

  try {
    // Fetch in parallel: alerts, subscriptions, project details
    const [alerts, subscriptions, projectDetails] = await Promise.all([
      getProjectAlerts(projectId, { page_size: 10, order_by: "-created_at" }),
      getProductSubscriptions(projectId),
      getProjectDetails(projectId),
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
      projectName: config.projectName || projectDetails.name,
      alerts: alertResults.slice(0, 10),
      totalAlerts: alerts.count || alertResults.length,
      subscriptions: subscriptions.results || subscriptions,
      subscriptionUsage: projectDetails.product_subscriptions,
      severityDistribution,
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
  const config = await getConfig();
  return {
    projectId: config?.projectId || "",
    projectName: config?.projectName || "",
  };
});

/**
 * Mark an alert as read from the dashboard.
 */
resolver.define("markAlertRead", async ({ payload }) => {
  const config = await getConfig();
  if (!config) return { success: false, error: "Not configured" };

  try {
    await markAlertRead(config.projectId, payload.alertId);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ═══════════════════════════════════════════════════════════════
// ADMIN PAGE RESOLVERS
// ═══════════════════════════════════════════════════════════════

/**
 * Get current configuration status.
 */
resolver.define("getAdminConfig", async ({ context }) => {
  const license = checkLicense(context);
  const config = await getConfig();
  if (!config) {
    return { configured: false, license };
  }
  return {
    configured: true,
    projectId: config.projectId,
    projectName: config.projectName,
    configuredAt: config.configuredAt,
    configuredBy: config.configuredBy,
    tokenConfigured: !!config.apiToken,
    license,
  };
});

/**
 * Save CVEFeed.io API configuration (token + project ID).
 */
resolver.define("saveAdminConfig", async ({ payload, context }) => {
  const { apiToken, projectId } = payload;

  if (!apiToken || !projectId) {
    return { success: false, error: "API token and project ID are required." };
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

  // Store the configuration
  const config = await saveConfig({
    apiToken,
    projectId,
    projectName: validation.project.name || `Project #${projectId}`,
    configuredBy: context.accountId || "unknown",
  });

  // Clear any stale caches and run initial sync
  await clearCache();
  const syncResult = await runSync(config.projectId);

  // Auto-register webhook URL with CVEFeed.io
  let webhookRegistered = false;
  try {
    const webhookUrl = await webTrigger.getUrl("cvefeed-incoming-webhook");
    const webhookResult = await registerWebhook(apiToken, projectId, webhookUrl);
    if (webhookResult.signing_secret) {
      await saveWebhookSecret(webhookResult.signing_secret);
    }
    webhookRegistered = true;
  } catch (err) {
    console.error("Webhook registration failed:", err.message);
    // Don't fail the config save — webhook can be retried
  }

  return {
    success: true,
    projectName: config.projectName,
    configuredAt: config.configuredAt,
    sync: syncResult,
    webhookRegistered,
  };
});

/**
 * Disconnect / remove configuration.
 */
resolver.define("deleteAdminConfig", async () => {
  const config = await getConfig();
  if (config) {
    try {
      await deregisterWebhook(config.projectId);
    } catch (err) {
      console.error("Webhook deregistration failed:", err.message);
    }
  }
  await deleteConfig();
  await deleteIssueConfig();
  await deleteWebhookSecret();
  await clearCache();
  return { success: true };
});

/**
 * Test the current API connection.
 */
resolver.define("testConnection", async () => {
  const config = await getConfig();
  if (!config) {
    return { success: false, error: "Not configured." };
  }

  try {
    const details = await getProjectDetails(config.projectId);
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
 * Uses the Forge-provided Jira REST API (no separate OAuth needed).
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
 * Get current issue creation configuration.
 */
resolver.define("getIssueConfig", async () => {
  const config = await getIssueConfig();
  if (!config) {
    return { configured: false, priorityMapping: SEVERITY_PRIORITY_MAP };
  }
  return {
    configured: true,
    ...config,
    priorityMapping: config.priorityMapping || SEVERITY_PRIORITY_MAP,
  };
});

/**
 * Save issue creation configuration.
 */
resolver.define("saveIssueConfig", async ({ payload }) => {
  const {
    jiraProjectKey,
    jiraProjectName,
    issueTypeId,
    issueTypeName,
    labels,
    autoCreateIssues,
    priorityMapping,
  } = payload;

  if (!jiraProjectKey || !issueTypeId) {
    return { success: false, error: "Jira project and issue type are required." };
  }

  const config = await saveIssueConfig({
    jiraProjectKey,
    jiraProjectName,
    issueTypeId,
    issueTypeName,
    labels: labels || [],
    autoCreateIssues: autoCreateIssues ?? false,
    priorityMapping: priorityMapping || SEVERITY_PRIORITY_MAP,
  });

  // Sync settings to Django for display on the integrations page
  let synced = false;
  try {
    const cvefeedConfig = await getConfig();
    if (cvefeedConfig && cvefeedConfig.projectId) {
      await syncIssueConfig(cvefeedConfig.projectId, {
        jiraProjectKey,
        issueTypeId,
        labels: labels || [],
        autoCreateIssues: autoCreateIssues ?? false,
      });
      synced = true;
    }
  } catch (err) {
    console.error("Config sync to CVEFeed.io failed:", err.message);
  }

  return { success: true, config, synced };
});

/**
 * Delete issue creation configuration.
 */
resolver.define("deleteIssueConfig", async () => {
  await deleteIssueConfig();
  return { success: true };
});

/**
 * Create a test Jira issue to verify configuration.
 */
resolver.define("createTestIssue", async () => {
  const issueConfig = await getIssueConfig();
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
 * Manually trigger a sync from the admin page.
 */
resolver.define("syncNow", async () => {
  const config = await getConfig();
  if (!config) {
    return { success: false, error: "Not configured." };
  }

  try {
    const result = await runSync(config.projectId);
    return { success: true, ...result };
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
    const data = await advancedSearchVulnerabilities(payload.filters || {});
    return { success: true, data };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Get project vulnerabilities for the global page.
 */
resolver.define("getProjectVulnerabilities", async ({ payload }) => {
  const config = await getConfig();
  if (!config) return { success: false, error: "Not configured" };

  try {
    const data = await getProjectVulnerabilities(config.projectId, payload.params || {});
    return { success: true, data };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Search products for subscription management.
 */
resolver.define("searchProducts", async ({ payload }) => {
  const config = await getConfig();
  if (!config) return { success: false, error: "Not configured" };

  try {
    const data = await searchProducts(config.projectId, payload.keyword);
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
 * The CVEFeed.io backend sends alerts to this web trigger URL
 * when new vulnerabilities are detected for subscribed products.
 */
export async function incomingWebhookHandler(request) {
  // Verify signing secret to ensure request is from CVEFeed.io
  const signingSecret = await getWebhookSecret();
  if (signingSecret) {
    let headerSecret = request.headers?.["x-webhook-secret"];
    if (Array.isArray(headerSecret)) {
      headerSecret = headerSecret[0];
    }
    const secretBuf = Buffer.from(signingSecret, "utf8");
    const headerBuf = Buffer.from(headerSecret || "", "utf8");
    if (secretBuf.length !== headerBuf.length || !crypto.timingSafeEqual(secretBuf, headerBuf)) {
      console.warn("Webhook signature verification failed");
      return {
        statusCode: 403,
        body: JSON.stringify({ error: "Invalid webhook signature" }),
      };
    }
  }

  const payload = JSON.parse(request.body);

  const config = await getConfig();
  if (!config) {
    return {
      statusCode: 503,
      body: JSON.stringify({ error: "App not configured" }),
    };
  }

  if (!payload.vulnerability?.id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Invalid payload: missing vulnerability.id" }),
    };
  }

  const cveId = payload.vulnerability.id;

  // Cache the alert
  const cacheKey = `alert:${cveId}`;
  await setCached(cacheKey, payload);

  // Auto-create Jira issue if enabled
  let issueCreated = null;
  const issueConfig = await getIssueConfig();
  if (issueConfig && issueConfig.autoCreateIssues && issueConfig.jiraProjectKey && issueConfig.issueTypeId) {
    try {
      const duplicate = await findExistingIssue(cveId, issueConfig.jiraProjectKey);
      if (duplicate) {
        issueCreated = { skipped: true, existingKey: duplicate };
      } else {
        const result = await createJiraIssueFromAlert(payload, issueConfig);
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
async function createJiraIssueFromAlert(alert, issueConfig) {
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

  // Link to CVEFeed
  if (vuln.url) {
    descriptionContent.push({
      type: "paragraph",
      content: [
        { type: "text", text: "View on CVEFeed.io: " },
        {
          type: "text",
          text: vuln.url,
          marks: [{ type: "link", attrs: { href: vuln.url } }],
        },
      ],
    });
  }

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

  // Labels
  const labels = [...(issueConfig.labels || [])];
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
 * Shared sync logic — used by scheduledSyncHandler, saveAdminConfig, and syncNow.
 * Fetches recent alerts and project details for dashboard display.
 */
async function runSync(projectId) {
  const details = await getProjectDetails(projectId);
  await setCached("project-details", details);

  // Fetch recent alerts (single page) — Forge storage has a 256 KB per-key limit,
  // so we only cache what the dashboard actually needs instead of all pages.
  const alertsResponse = await getProjectAlerts(projectId, {
    page_size: 50,
    order_by: "-created_at",
  });

  const alertResults = alertsResponse.results || alertsResponse;
  const recentAlerts = Array.isArray(alertResults) ? alertResults : [];

  await setCached("recent-alerts", { results: recentAlerts.slice(0, 20) });

  const subscriptions = await getProductSubscriptions(projectId);
  await setCached("subscriptions", subscriptions);

  const subCount = (subscriptions.results || subscriptions || []).length;

  return {
    alertCount: alertsResponse.count || recentAlerts.length,
    subscriptionCount: subCount,
    projectName: details.name,
    syncedAt: new Date().toISOString(),
  };
}

export async function scheduledSyncHandler() {
  const config = await getConfig();
  if (!config) {
    console.log("Scheduled sync skipped: app not configured.");
    return;
  }

  try {
    await runSync(config.projectId);
  } catch (err) {
    console.error("Scheduled sync failed:", err.message);
  }
}

// ═══════════════════════════════════════════════════════════════
// APP LIFECYCLE — INSTALL / UPGRADE
// ═══════════════════════════════════════════════════════════════

export async function webhookTriggerHandler(event) {
  // App lifecycle event handler (install/upgrade)
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
