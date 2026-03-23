/**
 * Forge app storage utilities.
 *
 * Uses @forge/kvs to persist configuration (API token, project ID)
 * at the Jira site level. All values are encrypted at rest by Forge.
 *
 * Multi-project key scheme:
 *   cvefeed:config                        — global config (secret)
 *   cvefeed:projects                      — project registry (plain)
 *   cvefeed:project:<id>:token            — API token per project (secret)
 *   cvefeed:project:<id>:issue-config     — Jira mapping config (plain)
 *   cvefeed:project:<id>:webhook-secret   — Signing secret (secret)
 *   cvefeed:cache:<id>:<key>              — Cached data per project (plain)
 */

import { storage } from "@forge/api";

const STORAGE_KEYS = {
  CONFIG: "cvefeed:config",
  PROJECTS: "cvefeed:projects",
  // Legacy keys (pre-migration)
  ISSUE_CONFIG: "cvefeed:issue-config",
  WEBHOOK_SIGNING_SECRET: "cvefeed:webhook-signing-secret",
  CACHE_PREFIX: "cvefeed:cache:",
};

// Cache TTL: 5 minutes (in ms)
const CACHE_TTL = 5 * 60 * 1000;

// ── Global Configuration ────────────────────────────────────

/**
 * Get the global CVEFeed.io configuration.
 * Returns: { configuredBy, configuredAt }
 */
export async function getConfig() {
  return storage.getSecret(STORAGE_KEYS.CONFIG);
}

/**
 * Save the global CVEFeed.io configuration.
 */
export async function saveConfig({ configuredBy }) {
  const config = {
    configuredBy,
    configuredAt: new Date().toISOString(),
  };
  await storage.setSecret(STORAGE_KEYS.CONFIG, config);
  return config;
}

/**
 * Delete the global CVEFeed.io configuration.
 */
export async function deleteConfig() {
  await storage.deleteSecret(STORAGE_KEYS.CONFIG);
}

/**
 * Check if the app is configured (has at least one project).
 */
export async function isConfigured() {
  const projects = await getProjects();
  return projects && Object.keys(projects).length > 0;
}

// ── Project Registry ────────────────────────────────────────

/**
 * Get all registered projects.
 * Returns: { [projectId]: { projectId, projectName, projectSlug, addedAt } }
 */
export async function getProjects() {
  return (await storage.get(STORAGE_KEYS.PROJECTS)) || {};
}

/**
 * Get a single project from the registry.
 */
export async function getProject(projectId) {
  const projects = await getProjects();
  return projects[projectId] || null;
}

/**
 * Add a project to the registry.
 */
export async function addProject({ projectId, projectName, projectSlug }) {
  const projects = await getProjects();
  projects[projectId] = {
    projectId,
    projectName,
    projectSlug,
    addedAt: new Date().toISOString(),
  };
  await storage.set(STORAGE_KEYS.PROJECTS, projects);
  return projects[projectId];
}

/**
 * Remove a project from the registry.
 */
export async function removeProject(projectId) {
  const projects = await getProjects();
  delete projects[projectId];
  await storage.set(STORAGE_KEYS.PROJECTS, projects);
}

// ── Per-Project API Token ───────────────────────────────────

export async function getProjectToken(projectId) {
  return storage.getSecret(`cvefeed:project:${projectId}:token`);
}

export async function saveProjectToken(projectId, token) {
  await storage.setSecret(`cvefeed:project:${projectId}:token`, token);
}

export async function deleteProjectToken(projectId) {
  await storage.deleteSecret(`cvefeed:project:${projectId}:token`);
}

// ── Per-Project Issue Configuration ─────────────────────────

export async function getProjectIssueConfig(projectId) {
  return storage.get(`cvefeed:project:${projectId}:issue-config`);
}

export async function saveProjectIssueConfig(projectId, config) {
  const issueConfig = {
    ...config,
    updatedAt: new Date().toISOString(),
  };
  await storage.set(`cvefeed:project:${projectId}:issue-config`, issueConfig);
  return issueConfig;
}

export async function deleteProjectIssueConfig(projectId) {
  await storage.delete(`cvefeed:project:${projectId}:issue-config`);
}

// ── Per-Project Webhook Signing Secret ──────────────────────

export async function getProjectWebhookSecret(projectId) {
  return storage.getSecret(`cvefeed:project:${projectId}:webhook-secret`);
}

export async function saveProjectWebhookSecret(projectId, secret) {
  await storage.setSecret(`cvefeed:project:${projectId}:webhook-secret`, secret);
}

export async function deleteProjectWebhookSecret(projectId) {
  await storage.deleteSecret(`cvefeed:project:${projectId}:webhook-secret`);
}

// ── Per-Project Caching ─────────────────────────────────────

/**
 * Get a cached value for a project. Returns null if expired or missing.
 */
export async function getCached(projectId, key) {
  const cacheKey = `${STORAGE_KEYS.CACHE_PREFIX}${projectId}:${key}`;
  const entry = await storage.get(cacheKey);
  if (!entry) return null;

  if (Date.now() - entry.timestamp > CACHE_TTL) {
    await storage.delete(cacheKey);
    return null;
  }
  return entry.data;
}

/**
 * Set a cached value for a project.
 */
export async function setCached(projectId, key, data) {
  const cacheKey = `${STORAGE_KEYS.CACHE_PREFIX}${projectId}:${key}`;
  await storage.set(cacheKey, {
    data,
    timestamp: Date.now(),
  });
}

/**
 * Clear all cache entries for a specific project.
 */
export async function clearProjectCache(projectId) {
  const knownCacheKeys = ["project-details", "subscriptions", "recent-alerts"];
  for (const key of knownCacheKeys) {
    await storage.delete(`${STORAGE_KEYS.CACHE_PREFIX}${projectId}:${key}`);
  }
}

/**
 * Clear all cache entries for all known projects.
 */
export async function clearAllCaches() {
  const projects = await getProjects();
  for (const projectId of Object.keys(projects)) {
    await clearProjectCache(projectId);
  }
}

// ── Migration ───────────────────────────────────────────────

/**
 * Migrate old single-project format to new multi-project format.
 * Triggered when cvefeed:config contains projectId (old format).
 */
export async function migrateIfNeeded() {
  const config = await storage.getSecret(STORAGE_KEYS.CONFIG);
  if (!config || !config.projectId) return false; // Already new format or not configured

  const { apiToken, projectId, projectName, configuredBy, configuredAt } = config;

  // 1. Save token to project-scoped secret
  if (apiToken) {
    await saveProjectToken(projectId, apiToken);
  }

  // 2. Move issue config
  const oldIssueConfig = await storage.get(STORAGE_KEYS.ISSUE_CONFIG);
  if (oldIssueConfig) {
    await saveProjectIssueConfig(projectId, oldIssueConfig);
    await storage.delete(STORAGE_KEYS.ISSUE_CONFIG);
  }

  // 3. Move webhook secret
  const oldWebhookSecret = await storage.getSecret(STORAGE_KEYS.WEBHOOK_SIGNING_SECRET);
  if (oldWebhookSecret) {
    await saveProjectWebhookSecret(projectId, oldWebhookSecret);
    await storage.deleteSecret(STORAGE_KEYS.WEBHOOK_SIGNING_SECRET);
  }

  // 4. Create projects registry
  await addProject({
    projectId,
    projectName: projectName || `Project #${projectId}`,
    projectSlug: "",
  });

  // 5. Save new config without apiToken/projectId
  await storage.setSecret(STORAGE_KEYS.CONFIG, {
    configuredBy,
    configuredAt,
  });

  // 6. Migrate old cache keys to project-scoped keys
  const knownCacheKeys = ["project-details", "subscriptions", "recent-alerts"];
  for (const key of knownCacheKeys) {
    const oldCacheKey = `${STORAGE_KEYS.CACHE_PREFIX}${key}`;
    const entry = await storage.get(oldCacheKey);
    if (entry) {
      await storage.set(`${STORAGE_KEYS.CACHE_PREFIX}${projectId}:${key}`, entry);
      await storage.delete(oldCacheKey);
    }
  }

  console.log("Migration complete: single project migrated to multi-project format.");
  return true;
}
