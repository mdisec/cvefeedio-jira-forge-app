import React, { useEffect, useState } from "react";
import { invoke, view } from "@forge/bridge";
import "./styles.css";

// ── Issue Configuration Sub-Component ───────────────────────

function IssueConfigSection({ projectId, onMessage }) {
  const [issueConfig, setIssueConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [creatingTest, setCreatingTest] = useState(false);

  // Dropdown data
  const [jiraProjects, setJiraProjects] = useState([]);
  const [issueTypes, setIssueTypes] = useState([]);
  const [loadingProjects, setLoadingProjects] = useState(false);
  const [loadingIssueTypes, setLoadingIssueTypes] = useState(false);

  // Form state
  const [selectedProject, setSelectedProject] = useState("");
  const [selectedIssueType, setSelectedIssueType] = useState("");
  const [labelsInput, setLabelsInput] = useState("");
  const [autoCreate, setAutoCreate] = useState(true);
  const [markAsReadOnSync, setMarkAsReadOnSync] = useState(true);
  const [priorityMapping, setPriorityMapping] = useState({
    critical: "Highest",
    high: "High",
    medium: "Medium",
    low: "Low",
  });

  const PRIORITY_OPTIONS = ["Highest", "High", "Medium", "Low", "Lowest"];

  useEffect(() => {
    loadIssueConfig();
  }, [projectId]);

  async function loadIssueConfig() {
    setLoading(true);
    try {
      const result = await invoke("getIssueConfig", { projectId });
      setIssueConfig(result);
      if (result.configured) {
        setSelectedProject(result.jiraProjectKey || "");
        setSelectedIssueType(result.issueTypeId || "");
        setLabelsInput((result.labels || []).join(", "));
        setAutoCreate(result.autoCreateIssues ?? true);
        setMarkAsReadOnSync(result.markAsReadOnSync ?? true);
        setPriorityMapping(result.priorityMapping || priorityMapping);
      }
    } catch (err) {
      onMessage({ type: "error", text: err.message });
    } finally {
      setLoading(false);
    }
  }

  async function loadJiraProjects() {
    setLoadingProjects(true);
    try {
      const result = await invoke("getJiraProjects");
      if (result && result.success) {
        setJiraProjects(result.projects || []);
        if ((result.projects || []).length === 0) {
          onMessage({ type: "error", text: "No Jira projects found. Check your app permissions." });
        }
      } else {
        onMessage({ type: "error", text: (result && result.error) || "Failed to load Jira projects." });
      }
    } catch (err) {
      console.error("loadJiraProjects error:", err);
      onMessage({ type: "error", text: err.message || "Failed to load Jira projects." });
    } finally {
      setLoadingProjects(false);
    }
  }

  async function loadIssueTypes(projectKey) {
    if (!projectKey) {
      setIssueTypes([]);
      return;
    }
    setLoadingIssueTypes(true);
    try {
      const result = await invoke("getJiraIssueTypes", { projectKey });
      if (result.success) {
        setIssueTypes(result.issueTypes);
      } else {
        onMessage({ type: "error", text: result.error });
      }
    } catch (err) {
      onMessage({ type: "error", text: err.message });
    } finally {
      setLoadingIssueTypes(false);
    }
  }

  function handleProjectChange(e) {
    const key = e.target.value;
    setSelectedProject(key);
    setSelectedIssueType("");
    if (key) {
      loadIssueTypes(key);
    } else {
      setIssueTypes([]);
    }
  }

  async function handleSaveIssueConfig(e) {
    e.preventDefault();
    if (!selectedProject || !selectedIssueType) {
      onMessage({ type: "error", text: "Select a Jira project and issue type." });
      return;
    }

    setSaving(true);
    try {
      const projectObj = jiraProjects.find((p) => p.key === selectedProject);
      const issueTypeObj = issueTypes.find((t) => t.id === selectedIssueType);

      const labels = labelsInput
        .split(",")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);

      const result = await invoke("saveIssueConfig", {
        projectId,
        jiraProjectKey: selectedProject,
        jiraProjectName: projectObj?.name || selectedProject,
        issueTypeId: selectedIssueType,
        issueTypeName: issueTypeObj?.name || selectedIssueType,
        labels,
        autoCreateIssues: autoCreate,
        markAsReadOnSync,
        priorityMapping,
      });

      if (result.success) {
        onMessage({ type: "success", text: "Issue creation settings saved." });
        await loadIssueConfig();
      } else {
        onMessage({ type: "error", text: result.error });
      }
    } catch (err) {
      onMessage({ type: "error", text: err.message });
    } finally {
      setSaving(false);
    }
  }

  async function handleTestIssue() {
    setCreatingTest(true);
    try {
      const result = await invoke("createTestIssue", { projectId });
      if (result.success) {
        onMessage({
          type: "success",
          text: `Test issue created: ${result.issueKey}`,
        });
      } else {
        onMessage({ type: "error", text: result.error });
      }
    } catch (err) {
      onMessage({ type: "error", text: err.message });
    } finally {
      setCreatingTest(false);
    }
  }

  async function handleResetIssueConfig() {
    if (!window.confirm("Reset issue creation settings?")) return;
    try {
      await invoke("deleteIssueConfig", { projectId });
      setIssueConfig({ configured: false });
      setSelectedProject("");
      setSelectedIssueType("");
      setLabelsInput("");
      setAutoCreate(false);
      setMarkAsReadOnSync(true);
      setJiraProjects([]);
      setIssueTypes([]);
      onMessage({ type: "success", text: "Issue creation settings reset." });
    } catch (err) {
      onMessage({ type: "error", text: err.message });
    }
  }

  if (loading) {
    return <div className="loading-state">Loading issue settings…</div>;
  }

  // ── Configured: show summary + edit ──
  if (issueConfig?.configured) {
    return (
      <div className="config-card">
        <div className="config-status">
          <div className="status-dot green" />
          <span>Issue Creation Configured</span>
        </div>

        <table className="config-table">
          <tbody>
            <tr>
              <th>Jira Project</th>
              <td>{issueConfig.jiraProjectName} ({issueConfig.jiraProjectKey})</td>
            </tr>
            <tr>
              <th>Issue Type</th>
              <td>{issueConfig.issueTypeName}</td>
            </tr>
            <tr>
              <th>Labels</th>
              <td>
                {issueConfig.labels?.length > 0
                  ? issueConfig.labels.map((l) => (
                      <span key={l} className="label-chip">{l}</span>
                    ))
                  : "None"}
              </td>
            </tr>
            <tr>
              <th>Auto-Create</th>
              <td>{issueConfig.autoCreateIssues ? "Enabled" : "Disabled"}</td>
            </tr>
            <tr>
              <th>Mark as Read</th>
              <td>{issueConfig.markAsReadOnSync !== false ? "Enabled" : "Disabled"}</td>
            </tr>
          </tbody>
        </table>

        <div className="priority-map-display">
          <h4>Severity to Priority Mapping</h4>
          <table className="config-table">
            <thead>
              <tr>
                <th>CVE Severity</th>
                <th>Jira Priority</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(issueConfig.priorityMapping || {}).map(([sev, pri]) => (
                <tr key={sev}>
                  <td>
                    <span className={`severity-tag ${sev}`}>
                      {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </span>
                  </td>
                  <td>{pri}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="config-actions">
          <button
            className="btn btn-primary"
            onClick={handleTestIssue}
            disabled={creatingTest}
          >
            {creatingTest ? "Creating…" : "Send Test Issue"}
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => {
              setIssueConfig({ configured: false });
              loadJiraProjects();
              // Pre-select current values
              setSelectedProject(issueConfig.jiraProjectKey);
              setLabelsInput((issueConfig.labels || []).join(", "));
              setAutoCreate(issueConfig.autoCreateIssues ?? true);
              setMarkAsReadOnSync(issueConfig.markAsReadOnSync ?? true);
              setPriorityMapping(issueConfig.priorityMapping || priorityMapping);
              loadIssueTypes(issueConfig.jiraProjectKey);
            }}
          >
            Edit Settings
          </button>
          <button className="btn btn-danger" onClick={handleResetIssueConfig}>
            Reset
          </button>
        </div>
      </div>
    );
  }

  // ── Setup form ──
  return (
    <div className="config-card">
      <div className="config-status">
        <div className="status-dot red" />
        <span>Issue Creation Not Configured</span>
      </div>
      <p className="setup-description">
        Configure how CVEFeed.io vulnerability alerts are created as Jira issues.
        Select the target project, issue type, and labels to apply.
      </p>

      <form onSubmit={handleSaveIssueConfig} className="config-form">
        {/* Step 1: Jira Project */}
        <div className="form-group">
          <label>Jira Project</label>
          {jiraProjects.length === 0 ? (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={loadJiraProjects}
              disabled={loadingProjects}
            >
              {loadingProjects ? "Loading projects…" : "Load Jira Projects"}
            </button>
          ) : (
            <select
              value={selectedProject}
              onChange={handleProjectChange}
              className="form-select"
            >
              <option value="">Select a project…</option>
              {jiraProjects.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.name} ({p.key})
                </option>
              ))}
            </select>
          )}
          <span className="help-text">
            The Jira project where vulnerability issues will be created.
          </span>
        </div>

        {/* Step 2: Issue Type */}
        {selectedProject && (
          <div className="form-group">
            <label>Issue Type</label>
            {loadingIssueTypes ? (
              <span className="help-text">Loading issue types…</span>
            ) : (
              <select
                value={selectedIssueType}
                onChange={(e) => setSelectedIssueType(e.target.value)}
                className="form-select"
              >
                <option value="">Select an issue type…</option>
                {issueTypes.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            )}
            <span className="help-text">
              Typical choices: Bug, Task, or a custom "Vulnerability" type.
            </span>
          </div>
        )}

        {/* Step 3: Labels */}
        {selectedIssueType && (
          <>
            <div className="form-group">
              <label>Labels</label>
              <input
                type="text"
                value={labelsInput}
                onChange={(e) => setLabelsInput(e.target.value)}
                placeholder="cvefeed, vulnerability, security"
                className="form-input"
              />
              <span className="help-text">
                Comma-separated labels to apply to created issues.
              </span>
            </div>

            {/* Step 4: Priority Mapping */}
            <div className="form-group">
              <label>Severity to Priority Mapping</label>
              <div className="priority-map-edit">
                {Object.entries(priorityMapping).map(([sev, pri]) => (
                  <div key={sev} className="priority-row">
                    <span className={`severity-tag ${sev}`}>
                      {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </span>
                    <select
                      value={pri}
                      onChange={(e) =>
                        setPriorityMapping({ ...priorityMapping, [sev]: e.target.value })
                      }
                      className="form-select priority-select"
                    >
                      {PRIORITY_OPTIONS.map((opt) => (
                        <option key={opt} value={opt}>{opt}</option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>
              <span className="help-text">
                Map CVE severity levels to Jira issue priorities.
              </span>
            </div>

            {/* Step 5: Auto-create toggle */}
            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={autoCreate}
                  onChange={(e) => setAutoCreate(e.target.checked)}
                />
                <span>Automatically create Jira issues from CVEFeed alerts</span>
              </label>
              <span className="help-text">
                When enabled, new vulnerability alerts will automatically create Jira issues
                using the configured settings.
              </span>
            </div>

            {/* Step 6: Mark as read toggle */}
            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={markAsReadOnSync}
                  onChange={(e) => setMarkAsReadOnSync(e.target.checked)}
                />
                <span>Mark alerts as read on CVEFeed.io after sync</span>
              </label>
              <span className="help-text">
                When enabled, alerts are marked as read on CVEFeed.io after Jira issues are created.
                When disabled, alerts remain unread but duplicate issues will not be created.
              </span>
            </div>

            <button className="btn btn-primary" type="submit" disabled={saving}>
              {saving ? "Saving…" : "Save Issue Settings"}
            </button>
          </>
        )}
      </form>
    </div>
  );
}

// ── Main App ────────────────────────────────────────────────

function App() {
  const [loading, setLoading] = useState(true);
  const [config, setConfig] = useState(null);
  const [testing, setTesting] = useState(null); // projectId being tested
  const [syncing, setSyncing] = useState(null); // projectId being synced
  const [syncResult, setSyncResult] = useState(null);
  const [message, setMessage] = useState(null);
  const [isGlobalPage, setIsGlobalPage] = useState(false);

  // Sync preview/confirm state
  const [syncPreview, setSyncPreview] = useState(null);
  const [creating, setCreating] = useState(false);

  // Selected project for detail view
  const [selectedProjectId, setSelectedProjectId] = useState(null);

  // Add project form
  const [showAddForm, setShowAddForm] = useState(false);
  const [addingProject, setAddingProject] = useState(false);
  const [newApiToken, setNewApiToken] = useState("");
  const [newProjectId, setNewProjectId] = useState("");

  // Vulnerability browser state (for global page)
  const [vulnData, setVulnData] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    view.getContext().then((ctx) => {
      const moduleKey = ctx?.extension?.moduleKey || "";
      setIsGlobalPage(moduleKey.includes("global"));
    });
    loadConfig();
  }, []);

  async function loadConfig() {
    setLoading(true);
    try {
      const result = await invoke("getAdminConfig");
      setConfig(result);
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    } finally {
      setLoading(false);
    }
  }

  async function handleAddProject(e) {
    e.preventDefault();
    if (!newApiToken.trim() || !newProjectId.trim()) {
      setMessage({ type: "error", text: "Both fields are required." });
      return;
    }

    setAddingProject(true);
    setMessage(null);
    try {
      const result = await invoke("addProject", {
        apiToken: newApiToken.trim(),
        projectId: newProjectId.trim(),
      });
      if (result.success) {
        const syncInfo = result.sync
          ? ` Synced ${result.sync.alertCount} alerts, ${result.sync.subscriptionCount} subscriptions.`
          : "";
        setMessage({
          type: "success",
          text: `Project "${result.projectName}" added successfully.${syncInfo}`,
        });
        setNewApiToken("");
        setNewProjectId("");
        setShowAddForm(false);
        await loadConfig();
      } else {
        setMessage({ type: "error", text: result.error });
      }
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    } finally {
      setAddingProject(false);
    }
  }

  async function handleRemoveProject(projectId, projectName) {
    if (!window.confirm(`Remove project "${projectName}" (ID: ${projectId})? This will delete all associated configuration.`)) return;
    try {
      await invoke("removeProject", { projectId });
      setMessage({ type: "success", text: `Project "${projectName}" removed.` });
      if (selectedProjectId === projectId) setSelectedProjectId(null);
      await loadConfig();
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    }
  }

  async function handleTest(projectId) {
    setTesting(projectId);
    setMessage(null);
    try {
      const result = await invoke("testConnection", { projectId });
      if (result.success) {
        const subs = result.subscriptions;
        setMessage({
          type: "success",
          text: `Connection OK — Project "${result.projectName}" (${subs.current_usage}/${subs.max_limit} subscriptions).`,
        });
      } else {
        setMessage({ type: "error", text: `Connection failed: ${result.error}` });
      }
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    } finally {
      setTesting(null);
    }
  }

  async function handleSync(projectId) {
    setSyncing(projectId);
    setMessage(null);
    setSyncResult(null);
    setSyncPreview(null);
    try {
      // Step 1: Refresh data cache
      const syncResult = await invoke("syncNow", { projectId });
      if (!syncResult.success) {
        setMessage({ type: "error", text: `Sync failed: ${syncResult.error}` });
        return;
      }
      setSyncResult(syncResult);

      // Step 2: Preview issues to create
      const preview = await invoke("previewSyncIssues", { projectId });
      if (preview.success) {
        setSyncPreview({ ...preview, projectId });
        if (preview.toCreate === 0) {
          setMessage({
            type: "success",
            text: `Synced ${syncResult.alertCount} alerts, ${syncResult.subscriptionCount} subscriptions. No new issues to create.${preview.duplicates > 0 ? ` ${preview.duplicates} alert(s) already have Jira issues.` : ""}`,
          });
        } else {
          setMessage({
            type: "success",
            text: `Synced ${syncResult.alertCount} alerts, ${syncResult.subscriptionCount} subscriptions. ${preview.toCreate} new issue(s) ready to create — review below.`,
          });
        }
      } else {
        setMessage({
          type: "success",
          text: `Synced ${syncResult.alertCount} alerts, ${syncResult.subscriptionCount} subscriptions.${preview.error ? ` ${preview.error}` : ""}`,
        });
      }
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    } finally {
      setSyncing(null);
    }
  }

  async function handleConfirmCreateIssues() {
    if (!syncPreview?.projectId) return;
    setCreating(true);
    setMessage(null);

    let totalCreated = 0;
    let totalSkipped = 0;
    let totalErrors = 0;
    const allCreated = [];
    let hasMore = true;
    let totalProcessed = 0;
    let total = syncPreview?.toCreate || 0;
    let page = 1;

    try {
      while (hasMore) {
        setMessage({
          type: "info",
          text: `Creating issues… ${totalCreated} created, ${totalProcessed} / ${total} processed.`,
        });

        const result = await invoke("createIssuesBatch", { projectId: syncPreview.projectId, page });
        if (!result.success) {
          setMessage({ type: "error", text: result.error });
          return;
        }

        totalCreated += result.issuesCreated;
        totalSkipped += result.issuesSkipped;
        totalErrors += result.issueErrors;
        allCreated.push(...result.created);
        totalProcessed += result.processed;
        hasMore = result.hasMore;
        if (result.nextPage) page = result.nextPage;
        if (result.total) total = result.total;
      }

      const createdList = allCreated.length > 0
        ? allCreated.slice(0, 20).map((c) => c.issueKey).join(", ") + (allCreated.length > 20 ? ` and ${allCreated.length - 20} more` : "")
        : "none";
      setMessage({
        type: "success",
        text: `Done! Created ${totalCreated} issue(s): ${createdList}. Skipped ${totalSkipped} duplicate(s).${totalErrors > 0 ? ` ${totalErrors} error(s).` : ""}`,
      });
      setSyncPreview(null);
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    } finally {
      setCreating(false);
    }
  }

  // ── Global page: vulnerability browser ──
  async function handleVulnSearch() {
    if (!searchQuery.trim()) return;
    setSearching(true);
    try {
      const result = await invoke("searchVulnerabilities", {
        query: searchQuery.trim(),
      });
      if (result.success) {
        setVulnData(result.data);
      } else {
        setMessage({ type: "error", text: result.error });
      }
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    } finally {
      setSearching(false);
    }
  }

  async function handleProjectVulns() {
    setSearching(true);
    try {
      const result = await invoke("getProjectVulnerabilities", {
        params: { page_size: 25 },
      });
      if (result.success) {
        setVulnData(result.data);
      } else {
        setMessage({ type: "error", text: result.error });
      }
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    } finally {
      setSearching(false);
    }
  }

  if (loading) {
    return (
      <div className="admin-container">
        <div className="loading-state">Loading configuration…</div>
      </div>
    );
  }

  const projects = config?.projects || [];
  const selectedProject = projects.find((p) => p.projectId === selectedProjectId);

  return (
    <div className="admin-container">
      {/* ── Header ── */}
      <div className="admin-header">
        <h1>
          {isGlobalPage
            ? "CVEFeed.io Vulnerability Browser"
            : "CVEFeed.io Configuration"}
        </h1>
        <p className="subtitle">
          {isGlobalPage
            ? "Search and browse vulnerabilities from your CVEFeed.io projects."
            : "Connect your Jira site to CVEFeed.io for vulnerability intelligence."}
        </p>
      </div>

      {/* ── Messages ── */}
      {message && (
        <div className={`message ${message.type}`}>
          {message.text}
          <button className="message-close" onClick={() => setMessage(null)}>
            ×
          </button>
        </div>
      )}

      {/* ── Admin Configuration ── */}
      {(!isGlobalPage || projects.length === 0) && (
        <>
          {/* ── Projects Section ── */}
          <div className="projects-section">
            <div className="projects-header">
              <h2>Projects</h2>
              <button
                className="btn btn-primary btn-small"
                onClick={() => setShowAddForm(!showAddForm)}
              >
                {showAddForm ? "Cancel" : "+ Add Project"}
              </button>
            </div>

            {/* ── Add Project Form ── */}
            {showAddForm && (
              <div className="config-card add-project-card">
                <h3>Add CVEFeed.io Project</h3>
                <div className="setup-instructions">
                  <ol>
                    <li>
                      Log in to{" "}
                      <a
                        href="https://cvefeed.io"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        CVEFeed.io
                      </a>{" "}
                      and open your project settings.
                    </li>
                    <li>
                      Navigate to <strong>Settings &rarr; API Tokens</strong> and create a
                      new token with the following scopes:
                    </li>
                  </ol>

                  <div className="scope-requirements">
                    <table className="config-table">
                      <thead>
                        <tr>
                          <th>Resource</th>
                          <th>Required Scope</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td><code>integrations</code></td>
                          <td><span className="scope-badge write">write</span></td>
                        </tr>
                        <tr>
                          <td><code>project</code></td>
                          <td><span className="scope-badge read">read</span></td>
                        </tr>
                        <tr>
                          <td><code>alerts</code></td>
                          <td><span className="scope-badge read">read</span></td>
                        </tr>
                        <tr>
                          <td><code>subscriptions</code></td>
                          <td><span className="scope-badge read">read</span></td>
                        </tr>
                        <tr>
                          <td><code>vulnerabilities</code></td>
                          <td><span className="scope-badge read">read</span></td>
                        </tr>
                      </tbody>
                    </table>
                    <p className="help-text">
                      The <code>integrations: write</code> scope is required for webhook
                      registration and configuration sync. Other scopes enable fetching
                      project data, alerts, and vulnerability details.
                    </p>
                  </div>

                  <ol start="3">
                    <li>Copy the API token and your project ID below.</li>
                  </ol>
                </div>

                <form onSubmit={handleAddProject} className="config-form">
                  <div className="form-group">
                    <label htmlFor="newApiToken">API Token</label>
                    <input
                      id="newApiToken"
                      type="password"
                      value={newApiToken}
                      onChange={(e) => setNewApiToken(e.target.value)}
                      placeholder="cvefeed_aBcD1234_..."
                      required
                    />
                    <span className="help-text">
                      Your CVEFeed.io project API token (starts with{" "}
                      <code>cvefeed_</code>).
                    </span>
                  </div>

                  <div className="form-group">
                    <label htmlFor="newProjectId">Project ID</label>
                    <input
                      id="newProjectId"
                      type="text"
                      value={newProjectId}
                      onChange={(e) => setNewProjectId(e.target.value)}
                      placeholder="42"
                      required
                    />
                    <span className="help-text">
                      Your numeric project ID from CVEFeed.io (visible in project
                      settings or URL).
                    </span>
                  </div>

                  <button className="btn btn-primary" type="submit" disabled={addingProject}>
                    {addingProject ? "Adding…" : "Add Project"}
                  </button>
                </form>
              </div>
            )}

            {/* ── Project Cards ── */}
            {projects.length === 0 && !showAddForm ? (
              <div className="config-card">
                <div className="config-status disconnected">
                  <div className="status-dot red" />
                  <span>No Projects Connected</span>
                </div>
                <p className="setup-description">
                  Click "Add Project" above to connect your first CVEFeed.io project.
                </p>
              </div>
            ) : (
              <div className="project-list">
                {projects.map((proj) => (
                  <div
                    key={proj.projectId}
                    className={`project-card ${selectedProjectId === proj.projectId ? "selected" : ""}`}
                    onClick={() => setSelectedProjectId(
                      selectedProjectId === proj.projectId ? null : proj.projectId
                    )}
                  >
                    <div className="project-card-header">
                      <div className="project-card-title">
                        <strong>{proj.projectName}</strong>
                        <span className="project-id">ID: {proj.projectId}</span>
                      </div>
                      <div className="project-card-status">
                        {proj.issueConfigured ? (
                          <span className="status-badge configured">
                            {proj.jiraProjectKey} ({proj.issueTypeName})
                          </span>
                        ) : (
                          <span className="status-badge not-configured">Not configured</span>
                        )}
                      </div>
                    </div>
                    <div className="project-card-meta">
                      {proj.issueConfigured && (
                        <span className="meta-item">
                          Auto-create: {proj.autoCreateIssues ? "ON" : "OFF"}
                        </span>
                      )}
                    </div>
                    <div className="project-card-actions" onClick={(e) => e.stopPropagation()}>
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => setSelectedProjectId(proj.projectId)}
                      >
                        Configure
                      </button>
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => handleSync(proj.projectId)}
                        disabled={syncing === proj.projectId}
                      >
                        {syncing === proj.projectId ? "Syncing…" : "Sync"}
                      </button>
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => handleTest(proj.projectId)}
                        disabled={testing === proj.projectId}
                      >
                        {testing === proj.projectId ? "Testing…" : "Test"}
                      </button>
                      <button
                        className="btn btn-danger btn-small"
                        onClick={() => handleRemoveProject(proj.projectId, proj.projectName)}
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ── Selected Project Detail ── */}
          {selectedProject && (
            <>
              <div className="section-divider">
                <h2>Issue Creation Settings — {selectedProject.projectName}</h2>
                <p className="subtitle">
                  Configure how vulnerability alerts for this project are created as Jira issues.
                </p>
              </div>
              <IssueConfigSection
                projectId={selectedProject.projectId}
                onMessage={setMessage}
              />

              {/* ── Sync & Issue Creation Actions ── */}
              <div className="section-divider">
                <h2>Sync & Issue Creation — {selectedProject.projectName}</h2>
                <p className="subtitle">
                  Refresh vulnerability data from CVEFeed.io and create Jira issues from unread alerts.
                </p>
              </div>
              <div className="config-card">
                <div className="config-actions">
                  <button
                    className="btn btn-primary"
                    onClick={() => handleSync(selectedProject.projectId)}
                    disabled={syncing === selectedProject.projectId}
                  >
                    {syncing === selectedProject.projectId ? "Syncing…" : "Sync Now"}
                  </button>
                </div>

                {syncResult && (
                  <div className="sync-result">
                    <table className="config-table">
                      <tbody>
                        <tr>
                          <th>Last Sync</th>
                          <td>{new Date(syncResult.syncedAt).toLocaleString()}</td>
                        </tr>
                        <tr>
                          <th>Alerts</th>
                          <td>{syncResult.alertCount} recent alerts cached</td>
                        </tr>
                        <tr>
                          <th>Subscriptions</th>
                          <td>{syncResult.subscriptionCount} monitored products</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                )}

                {/* ── Issue Creation Preview ── */}
                {syncPreview && syncPreview.toCreate > 0 && (
                  <div className="sync-preview">
                    <h3>Issue Creation Preview</h3>
                    <p className="preview-summary">
                      <strong>{syncPreview.toCreate}</strong> new issue(s) will be created in{" "}
                      <strong>{syncPreview.projectKey}</strong>.
                      {syncPreview.duplicates > 0 && (
                        <> {syncPreview.duplicates} alert(s) already have Jira issues and will be skipped.</>
                      )}
                    </p>
                    {syncPreview.markAsReadOnSync === false && (
                      <p className="help-text">
                        "Mark as Read" is disabled — alerts will remain unread on CVEFeed.io.
                        Some alerts may be skipped if matching Jira issues already exist.
                      </p>
                    )}

                    <table className="config-table preview-table">
                      <thead>
                        <tr>
                          <th>CVE ID</th>
                          <th>Severity</th>
                          <th>Title</th>
                          <th>Product</th>
                        </tr>
                      </thead>
                      <tbody>
                        {syncPreview.preview.map((item) => (
                          <tr key={item.cveId}>
                            <td>
                              <a
                                href={`https://cvefeed.io/vuln/detail/${item.cveId}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="cve-link"
                              >
                                {item.cveId}
                              </a>
                            </td>
                            <td>
                              <span className={`severity-tag ${(item.severity || "").toLowerCase()}`}>
                                {item.severity}
                              </span>
                            </td>
                            <td className="title-cell">{item.title}</td>
                            <td>{item.product}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>

                    <div className="preview-actions">
                      <button
                        className="btn btn-primary"
                        onClick={handleConfirmCreateIssues}
                        disabled={creating}
                      >
                        {creating ? "Creating Issues…" : `Confirm — Create ${syncPreview.toCreate} Issue(s)`}
                      </button>
                      <button
                        className="btn btn-secondary"
                        onClick={() => setSyncPreview(null)}
                        disabled={creating}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </>
      )}

      {/* ── Global Page: Vulnerability Browser ── */}
      {isGlobalPage && projects.length > 0 && (
        <div className="vuln-browser">
          <div className="browser-actions">
            <div className="search-bar">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleVulnSearch()}
                placeholder="Search CVEs by ID, product, or keyword…"
                className="search-input"
              />
              <button
                className="btn btn-primary"
                onClick={handleVulnSearch}
                disabled={searching}
              >
                {searching ? "Searching…" : "Search"}
              </button>
            </div>
            <button
              className="btn btn-secondary"
              onClick={handleProjectVulns}
              disabled={searching}
            >
              Show My Project Vulnerabilities
            </button>
          </div>

          {vulnData && (
            <div className="vuln-results">
              <h3>
                Results{" "}
                {vulnData.count !== undefined && (
                  <span className="count">({vulnData.count} total)</span>
                )}
              </h3>
              <table className="vuln-table">
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Title</th>
                    <th>Published</th>
                  </tr>
                </thead>
                <tbody>
                  {(vulnData.results || vulnData || []).map((v) => (
                    <tr key={v.id}>
                      <td>
                        <a
                          href={v.url || `https://cvefeed.io/vuln/detail/${v.id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="cve-link"
                        >
                          {v.id}
                        </a>
                      </td>
                      <td>
                        <span
                          className={`severity-tag ${(v.severity || "").toLowerCase()}`}
                        >
                          {v.severity || "N/A"}
                        </span>
                      </td>
                      <td>{v.cvss_score ?? "N/A"}</td>
                      <td className="title-cell">
                        {v.title || v.description?.slice(0, 100)}
                      </td>
                      <td>
                        {v.published
                          ? new Date(v.published).toLocaleDateString()
                          : "N/A"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Help section ── */}
      <div className="help-section">
        <h3>Need Help?</h3>
        <ul>
          <li>
            <a
              href="https://cvefeed.io/docs"
              target="_blank"
              rel="noopener noreferrer"
            >
              CVEFeed.io Documentation
            </a>
          </li>
          <li>
            <a href="mailto:hey@cvefeed.io">Contact Support: hey@cvefeed.io</a>
          </li>
        </ul>
      </div>
    </div>
  );
}

export default App;
