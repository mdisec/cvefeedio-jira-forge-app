/**
 * Forge app storage utilities.
 *
 * Uses @forge/api `storage` to persist configuration (API token, project ID)
 * at the Jira site level. All values are encrypted at rest by Forge.
 */

import { storage } from "@forge/api";

const STORAGE_KEYS = {
  CONFIG: "cvefeed:config",
  ISSUE_CONFIG: "cvefeed:issue-config",
  WEBHOOK_SIGNING_SECRET: "cvefeed:webhook-signing-secret",
  CACHE_PREFIX: "cvefeed:cache:",
};

// Cache TTL: 5 minutes (in ms)
const CACHE_TTL = 5 * 60 * 1000;

// ── Configuration ────────────────────────────────────────────

/**
 * Get the CVEFeed.io configuration for this Jira site.
 * Returns: { apiToken, projectId, projectName, configuredAt, configuredBy }
 */
export async function getConfig() {
  return storage.getSecret(STORAGE_KEYS.CONFIG);
}

/**
 * Save the CVEFeed.io configuration.
 */
export async function saveConfig({ apiToken, projectId, projectName, configuredBy }) {
  const config = {
    apiToken,
    projectId,
    projectName,
    configuredBy,
    configuredAt: new Date().toISOString(),
  };
  await storage.setSecret(STORAGE_KEYS.CONFIG, config);
  return config;
}

/**
 * Delete the CVEFeed.io configuration (disconnect).
 */
export async function deleteConfig() {
  await storage.deleteSecret(STORAGE_KEYS.CONFIG);
}

/**
 * Check if the app is configured.
 */
export async function isConfigured() {
  const config = await getConfig();
  return !!(config && config.apiToken && config.projectId);
}

// ── Issue Creation Configuration ────────────────────────────

/**
 * Get Jira issue creation settings.
 * Returns: { jiraProjectKey, jiraProjectName, issueTypeId, issueTypeName,
 *            labels, autoCreateIssues, priorityMapping }
 */
export async function getIssueConfig() {
  return storage.get(STORAGE_KEYS.ISSUE_CONFIG);
}

/**
 * Save Jira issue creation settings.
 */
export async function saveIssueConfig(config) {
  const issueConfig = {
    ...config,
    updatedAt: new Date().toISOString(),
  };
  await storage.set(STORAGE_KEYS.ISSUE_CONFIG, issueConfig);
  return issueConfig;
}

/**
 * Delete Jira issue creation settings.
 */
export async function deleteIssueConfig() {
  await storage.delete(STORAGE_KEYS.ISSUE_CONFIG);
}

// ── Webhook Signing Secret ───────────────────────────────────

/**
 * Store the webhook signing secret (persistent, not cache-TTL'd).
 */
export async function saveWebhookSecret(secret) {
  await storage.setSecret(STORAGE_KEYS.WEBHOOK_SIGNING_SECRET, secret);
}

/**
 * Get the webhook signing secret.
 */
export async function getWebhookSecret() {
  return storage.getSecret(STORAGE_KEYS.WEBHOOK_SIGNING_SECRET);
}

/**
 * Delete the webhook signing secret.
 */
export async function deleteWebhookSecret() {
  await storage.deleteSecret(STORAGE_KEYS.WEBHOOK_SIGNING_SECRET);
}

// ── Caching ──────────────────────────────────────────────────

/**
 * Get a cached value. Returns null if expired or missing.
 */
export async function getCached(key) {
  const cacheKey = `${STORAGE_KEYS.CACHE_PREFIX}${key}`;
  const entry = await storage.get(cacheKey);
  if (!entry) return null;

  if (Date.now() - entry.timestamp > CACHE_TTL) {
    await storage.delete(cacheKey);
    return null;
  }
  return entry.data;
}

/**
 * Set a cached value.
 */
export async function setCached(key, data) {
  const cacheKey = `${STORAGE_KEYS.CACHE_PREFIX}${key}`;
  await storage.set(cacheKey, {
    data,
    timestamp: Date.now(),
  });
}

/**
 * Clear all cache entries (brute force — iterate known patterns).
 */
export async function clearCache() {
  // Forge storage doesn't support prefix deletion,
  // so we clear known cache keys when config changes.
  const knownCacheKeys = ["project-details", "subscriptions", "recent-alerts"];
  for (const key of knownCacheKeys) {
    await storage.delete(`${STORAGE_KEYS.CACHE_PREFIX}${key}`);
  }
}
