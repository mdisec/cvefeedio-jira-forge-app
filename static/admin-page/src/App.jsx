import React, { useEffect, useState, useCallback } from "react";
import { invoke, view } from "@forge/bridge";
import "./styles.css";

// ── Issue Configuration Sub-Component ───────────────────────

function IssueConfigSection({ onMessage }) {
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
  const [autoCreate, setAutoCreate] = useState(false);
  const [priorityMapping, setPriorityMapping] = useState({
    critical: "Highest",
    high: "High",
    medium: "Medium",
    low: "Low",
  });

  const PRIORITY_OPTIONS = ["Highest", "High", "Medium", "Low", "Lowest"];

  useEffect(() => {
    loadIssueConfig();
  }, []);

  async function loadIssueConfig() {
    setLoading(true);
    try {
      const result = await invoke("getIssueConfig");
      setIssueConfig(result);
      if (result.configured) {
        setSelectedProject(result.jiraProjectKey || "");
        setSelectedIssueType(result.issueTypeId || "");
        setLabelsInput((result.labels || []).join(", "));
        setAutoCreate(result.autoCreateIssues || false);
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
      console.log("getJiraProjects result:", JSON.stringify(result));
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
        jiraProjectKey: selectedProject,
        jiraProjectName: projectObj?.name || selectedProject,
        issueTypeId: selectedIssueType,
        issueTypeName: issueTypeObj?.name || selectedIssueType,
        labels,
        autoCreateIssues: autoCreate,
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
      const result = await invoke("createTestIssue");
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
      await invoke("deleteIssueConfig");
      setIssueConfig({ configured: false });
      setSelectedProject("");
      setSelectedIssueType("");
      setLabelsInput("");
      setAutoCreate(false);
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
              setAutoCreate(issueConfig.autoCreateIssues || false);
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
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState(null);
  const [message, setMessage] = useState(null);
  const [isGlobalPage, setIsGlobalPage] = useState(false);

  // Form state
  const [apiToken, setApiToken] = useState("");
  const [projectId, setProjectId] = useState("");

  // Vulnerability browser state (for global page)
  const [vulnData, setVulnData] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searching, setSearching] = useState(false);

  const setMsg = useCallback((msg) => setMessage(msg), []);

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

  async function handleSave(e) {
    e.preventDefault();
    if (!apiToken.trim() || !projectId.trim()) {
      setMessage({ type: "error", text: "Both fields are required." });
      return;
    }

    setSaving(true);
    setMessage(null);
    try {
      const result = await invoke("saveAdminConfig", {
        apiToken: apiToken.trim(),
        projectId: projectId.trim(),
      });
      if (result.success) {
        const syncInfo = result.sync
          ? ` Synced ${result.sync.alertCount} alerts, ${result.sync.subscriptionCount} subscriptions.`
          : "";
        setMessage({
          type: "success",
          text: `Connected to "${result.projectName}" successfully.${syncInfo}`,
        });
        if (result.sync) setSyncResult(result.sync);
        setApiToken("");
        setProjectId("");
        await loadConfig();
      } else {
        setMessage({ type: "error", text: result.error });
      }
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    } finally {
      setSaving(false);
    }
  }

  async function handleDisconnect() {
    if (!window.confirm("Disconnect CVEFeed.io from this Jira site?")) return;
    try {
      await invoke("deleteAdminConfig");
      setMessage({ type: "success", text: "Disconnected successfully." });
      setConfig({ configured: false });
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    }
  }

  async function handleTest() {
    setTesting(true);
    setMessage(null);
    try {
      const result = await invoke("testConnection");
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
      setTesting(false);
    }
  }

  async function handleSync() {
    setSyncing(true);
    setMessage(null);
    setSyncResult(null);
    try {
      const result = await invoke("syncNow");
      if (result.success) {
        setSyncResult(result);
        setMessage({
          type: "success",
          text: `Sync complete — ${result.alertCount} alerts, ${result.subscriptionCount} subscriptions fetched.`,
        });
      } else {
        setMessage({ type: "error", text: `Sync failed: ${result.error}` });
      }
    } catch (err) {
      setMessage({ type: "error", text: err.message });
    } finally {
      setSyncing(false);
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
            ? "Search and browse vulnerabilities from your CVEFeed.io project."
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
      {(!isGlobalPage || !config?.configured) && (
        <>
          {config?.configured ? (
            <div className="config-card">
              <div className="config-status connected">
                <div className="status-dot green" />
                <span>Connected to CVEFeed.io</span>
              </div>
              <table className="config-table">
                <tbody>
                  <tr>
                    <th>Project</th>
                    <td>{config.projectName}</td>
                  </tr>
                  <tr>
                    <th>Project ID</th>
                    <td>{config.projectId}</td>
                  </tr>
                  <tr>
                    <th>Connected</th>
                    <td>
                      {config.configuredAt
                        ? new Date(config.configuredAt).toLocaleString()
                        : "N/A"}
                    </td>
                  </tr>
                  <tr>
                    <th>API Token</th>
                    <td>{config.tokenConfigured ? "••••••••••••" : "Not set"}</td>
                  </tr>
                </tbody>
              </table>

              <div className="config-actions">
                <button
                  className="btn btn-primary"
                  onClick={handleTest}
                  disabled={testing || syncing}
                >
                  {testing ? "Testing…" : "Test Connection"}
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={handleSync}
                  disabled={syncing || testing}
                >
                  {syncing ? "Syncing…" : "Sync Now"}
                </button>
                <button className="btn btn-danger" onClick={handleDisconnect}>
                  Disconnect
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
            </div>
          ) : (
            <div className="config-card">
              <div className="config-status disconnected">
                <div className="status-dot red" />
                <span>Not Connected</span>
              </div>

              <div className="setup-instructions">
                <h3>Setup Instructions</h3>
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
                    Navigate to <strong>Settings → API Tokens</strong> and create a
                    new token with <code>read</code> access to vulnerabilities, alerts,
                    and subscriptions.
                  </li>
                  <li>Copy the API token and your project ID below.</li>
                </ol>
              </div>

              <form onSubmit={handleSave} className="config-form">
                <div className="form-group">
                  <label htmlFor="apiToken">API Token</label>
                  <input
                    id="apiToken"
                    type="password"
                    value={apiToken}
                    onChange={(e) => setApiToken(e.target.value)}
                    placeholder="cvefeed_aBcD1234_..."
                    required
                  />
                  <span className="help-text">
                    Your CVEFeed.io project API token (starts with{" "}
                    <code>cvefeed_</code>).
                  </span>
                </div>

                <div className="form-group">
                  <label htmlFor="projectId">Project ID</label>
                  <input
                    id="projectId"
                    type="text"
                    value={projectId}
                    onChange={(e) => setProjectId(e.target.value)}
                    placeholder="42"
                    required
                  />
                  <span className="help-text">
                    Your numeric project ID from CVEFeed.io (visible in project
                    settings or URL).
                  </span>
                </div>

                <button className="btn btn-primary" type="submit" disabled={saving}>
                  {saving ? "Connecting…" : "Connect to CVEFeed.io"}
                </button>
              </form>
            </div>
          )}

          {/* ── Issue Creation Settings (only when CVEFeed is connected) ── */}
          {config?.configured && (
            <>
              <div className="section-divider">
                <h2>Issue Creation Settings</h2>
                <p className="subtitle">
                  Configure how vulnerability alerts are created as Jira issues.
                </p>
              </div>
              <IssueConfigSection onMessage={setMsg} />
            </>
          )}
        </>
      )}

      {/* ── Global Page: Vulnerability Browser ── */}
      {isGlobalPage && config?.configured && (
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
