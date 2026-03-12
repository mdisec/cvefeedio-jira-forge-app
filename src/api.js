/**
 * CVEFeed.io API client for Forge backend.
 *
 * Uses @forge/api `fetch` (the only HTTP client allowed in Forge runtime)
 * to call CVEFeed.io endpoints. All methods require a valid API token
 * stored in Forge app storage.
 */

import { fetch } from "@forge/api";
import { getConfig } from "./storage";

const CVEFEED_BASE_URL = "https://cvefeed.io";
const API_PREFIX = "/api";
const DEFAULT_PAGE_SIZE = 25;

// ── Helpers ──────────────────────────────────────────────────

class CveFeedApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = "CveFeedApiError";
    this.status = status;
    this.body = body;
  }
}

function buildBearerHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    Accept: "application/json",
    "User-Agent": "CVEFeed-Forge/1.0",
  };
}

async function getApiHeaders() {
  const config = await getConfig();
  if (!config || !config.apiToken) {
    throw new CveFeedApiError("CVEFeed.io API token not configured.", 401);
  }
  return buildBearerHeaders(config.apiToken);
}

function buildUrl(path, params = {}) {
  const url = new URL(`${API_PREFIX}${path}`, CVEFEED_BASE_URL);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function apiRequest(path, params = {}, options = {}) {
  const headers = await getApiHeaders();
  const url = buildUrl(path, params);

  const response = await fetch(url, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new CveFeedApiError(
      `CVEFeed API error: ${response.status} ${response.statusText}`,
      response.status,
      body
    );
  }

  return response.json();
}

/**
 * Fetch all pages from a paginated DRF endpoint.
 * Returns the full array of results, following `next` URLs until exhausted.
 */
async function apiRequestAllPages(path, params = {}) {
  const headers = await getApiHeaders();
  let url = buildUrl(path, { page_size: 100, ...params });
  const allResults = [];

  while (url) {
    const response = await fetch(url, { method: "GET", headers });
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new CveFeedApiError(
        `CVEFeed API error: ${response.status} ${response.statusText}`,
        response.status,
        body
      );
    }
    const data = await response.json();
    const results = data.results || [];
    allResults.push(...results);
    url = data.next || null;
  }

  return allResults;
}

// ── Public API Methods ───────────────────────────────────────

/**
 * Search vulnerabilities by keyword (CVE ID, product name, description).
 */
export async function searchVulnerabilities(query, page = 1) {
  return apiRequest("/vulnerability/quick-search", {
    q: query,
    page,
  });
}

/**
 * Advanced vulnerability search with filters.
 */
export async function advancedSearchVulnerabilities(filters = {}) {
  return apiRequest("/vulnerability/advanced-search", {
    page_size: DEFAULT_PAGE_SIZE,
    ...filters,
  });
}

/**
 * Get a single vulnerability by CVE ID.
 */
export async function getVulnerability(cveId) {
  return apiRequest(`/vulnerability/${cveId}/`);
}

/**
 * Get the change history for a CVE.
 */
export async function getVulnerabilityHistory(cveId) {
  return apiRequest(`/vulnerability/${cveId}/change-history/`);
}

/**
 * List vulnerabilities for a CVEFeed project (project-scoped).
 */
export async function getProjectVulnerabilities(projectId, params = {}) {
  return apiRequest(`/projects/${projectId}/vulns/`, {
    page_size: DEFAULT_PAGE_SIZE,
    ...params,
  });
}

/**
 * List alerts for a CVEFeed project.
 */
export async function getProjectAlerts(projectId, params = {}) {
  return apiRequest(`/projects/${projectId}/alerts/`, {
    page_size: DEFAULT_PAGE_SIZE,
    ...params,
  });
}

/**
 * Fetch ALL alerts for a project, following pagination.
 */
export async function getAllProjectAlerts(projectId, params = {}) {
  return apiRequestAllPages(`/projects/${projectId}/alerts/`, params);
}

/**
 * Mark an alert as read.
 */
export async function markAlertRead(projectId, alertId) {
  return apiRequest(`/projects/${projectId}/alerts/${alertId}/mark-as-read/`, {}, { method: "POST" });
}

/**
 * List product subscriptions for a project.
 */
export async function getProductSubscriptions(projectId) {
  return apiRequest(`/projects/${projectId}/products/`);
}

/**
 * Search products to subscribe.
 */
export async function searchProducts(projectId, keyword) {
  return apiRequest(`/projects/${projectId}/products/search`, {
    keyword,
  });
}

/**
 * Get project details (subscription limits, etc.).
 */
export async function getProjectDetails(projectId) {
  return apiRequest(`/projects/${projectId}/`);
}

/**
 * Validate the API token by fetching project details.
 * Returns { valid: true, project: {...} } or { valid: false, error: "..." }.
 */
export async function validateApiToken(apiToken, projectId) {
  try {
    const headers = buildBearerHeaders(apiToken);
    const url = buildUrl(`/projects/${projectId}/`);
    const response = await fetch(url, { method: "GET", headers });

    if (!response.ok) {
      return {
        valid: false,
        error: `API returned ${response.status}: ${response.statusText}`,
      };
    }
    const project = await response.json();
    return { valid: true, project };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

/**
 * Extract CVE IDs from text (issue summary, description, comments, labels).
 * Matches patterns like CVE-2024-12345.
 */
export function extractCveIds(text) {
  if (!text) return [];
  const pattern = /CVE-\d{4}-\d{4,}/gi;
  const matches = text.match(pattern) || [];
  return [...new Set(matches.map((id) => id.toUpperCase()))];
}

/**
 * Extract potential product/vendor keywords from Jira issue metadata.
 */
export function extractKeywords(issue) {
  const keywords = new Set();

  // From labels
  if (issue.fields?.labels) {
    issue.fields.labels.forEach((label) => keywords.add(label.toLowerCase()));
  }

  // From components
  if (issue.fields?.components) {
    issue.fields.components.forEach((comp) => {
      if (comp.name) keywords.add(comp.name.toLowerCase());
    });
  }

  // Common software names from summary
  if (issue.fields?.summary) {
    const summary = issue.fields.summary.toLowerCase();
    // Extract words that could be software names (capitalized, version-like patterns)
    const tokens = summary.split(/[\s,;:()[\]{}]+/).filter((t) => t.length > 2);
    tokens.forEach((t) => keywords.add(t));
  }

  return [...keywords];
}

/**
 * Check if the API token has sufficient scopes for Jira Forge integration.
 * Returns { sufficient, token_scopes, required_scopes, missing }.
 */
export async function checkTokenPermissions(apiToken, projectId) {
  const headers = buildBearerHeaders(apiToken);
  const url = buildUrl(`/projects/${projectId}/integrations/jira-forge/register/`);
  const response = await fetch(url, { method: "GET", headers });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new CveFeedApiError(
      `Permission check failed: ${response.status}`,
      response.status,
      body
    );
  }
  return response.json();
}

/**
 * Register a webhook URL with CVEFeed.io for a project.
 * Returns { registered, created, signing_secret }.
 */
export async function registerWebhook(apiToken, projectId, webhookUrl) {
  const headers = buildBearerHeaders(apiToken);
  const url = buildUrl(`/projects/${projectId}/integrations/jira-forge/register/`);
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ webhook_url: webhookUrl }),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new CveFeedApiError(
      `Webhook registration failed: ${response.status}`,
      response.status,
      body
    );
  }
  return response.json();
}

/**
 * Deregister the webhook URL from CVEFeed.io.
 */
export async function deregisterWebhook(projectId) {
  return apiRequest(
    `/projects/${projectId}/integrations/jira-forge/register/`,
    {},
    { method: "DELETE" }
  );
}

/**
 * Sync issue creation settings to CVEFeed.io for display on the Django UI.
 */
export async function syncIssueConfig(projectId, issueConfig) {
  return apiRequest(
    `/projects/${projectId}/integrations/jira-forge/config/`,
    {},
    {
      method: "PUT",
      body: {
        jira_project_key: issueConfig.jiraProjectKey || "",
        issue_type_id: issueConfig.issueTypeId || "",
        labels: issueConfig.labels || [],
        auto_create_issues: issueConfig.autoCreateIssues || false,
      },
    }
  );
}

export { CveFeedApiError };
