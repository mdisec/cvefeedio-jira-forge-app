import React, { useEffect, useState, useCallback } from "react";
import { invoke } from "@forge/bridge";
import "./styles.css";

function App() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [selectedProjectId, setSelectedProjectId] = useState(null);

  const loadData = useCallback(async (projectId) => {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke("getDashboardData", {
        projectId: projectId || selectedProjectId,
      });
      setData(result);
      // Auto-select first project if none selected
      if (!projectId && !selectedProjectId && result?.projects?.length > 0) {
        setSelectedProjectId(result.projects[0].projectId);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId]);

  useEffect(() => {
    loadData();
  }, []);

  const handleProjectChange = (e) => {
    const pid = e.target.value;
    setSelectedProjectId(pid);
    loadData(pid);
  };

  const handleMarkRead = async (alertId) => {
    if (!data?.projectId) return;
    try {
      await invoke("markAlertRead", { projectId: data.projectId, alertId });
      loadData(data.projectId);
    } catch (err) {
      // Silently handle
    }
  };

  if (loading) {
    return (
      <div className="gadget">
        <div className="loading">Loading vulnerability data…</div>
      </div>
    );
  }

  if (!data?.configured) {
    return (
      <div className="gadget">
        <div className="empty-state">
          <h3>CVEFeed.io Not Configured</h3>
          <p>Go to Apps → CVEFeed.io Configuration to connect.</p>
        </div>
      </div>
    );
  }

  if (error || data?.error) {
    return (
      <div className="gadget">
        <div className="error">{error || data.error}</div>
        <button className="btn-retry" onClick={() => loadData()}>
          Retry
        </button>
      </div>
    );
  }

  const { severityDistribution, alerts, totalAlerts, subscriptions, subscriptionUsage, projectName, projects } = data;

  return (
    <div className="gadget">
      {/* ── Header ── */}
      <div className="gadget-header">
        <h2>CVEFeed.io</h2>
        {projects && projects.length > 1 ? (
          <select
            className="project-selector"
            value={selectedProjectId || data.projectId || ""}
            onChange={handleProjectChange}
          >
            {projects.map((p) => (
              <option key={p.projectId} value={p.projectId}>
                {p.projectName}
              </option>
            ))}
          </select>
        ) : (
          <span className="project-name">{projectName}</span>
        )}
      </div>

      {/* ── Severity Distribution ── */}
      <div className="severity-grid">
        <div className="severity-card critical">
          <span className="sev-count">{severityDistribution.CRITICAL}</span>
          <span className="sev-label">Critical</span>
        </div>
        <div className="severity-card high">
          <span className="sev-count">{severityDistribution.HIGH}</span>
          <span className="sev-label">High</span>
        </div>
        <div className="severity-card medium">
          <span className="sev-count">{severityDistribution.MEDIUM}</span>
          <span className="sev-label">Medium</span>
        </div>
        <div className="severity-card low">
          <span className="sev-count">{severityDistribution.LOW}</span>
          <span className="sev-label">Low</span>
        </div>
      </div>

      {/* ── Subscription Usage ── */}
      {subscriptionUsage && (
        <div className="usage-bar-container">
          <div className="usage-header">
            <span>Monitored Products</span>
            <span>
              {subscriptionUsage.current_usage} / {subscriptionUsage.max_limit}
            </span>
          </div>
          <div className="usage-bar">
            <div
              className="usage-fill"
              style={{
                width: `${Math.min(
                  (subscriptionUsage.current_usage / subscriptionUsage.max_limit) * 100,
                  100
                )}%`,
              }}
            />
          </div>
        </div>
      )}

      {/* ── Recent Alerts ── */}
      <div className="alerts-section">
        <h3>
          Recent Alerts{" "}
          <span className="alert-count">({totalAlerts} total)</span>
        </h3>
        {alerts && alerts.length > 0 ? (
          <div className="alert-list">
            {alerts.map((alert) => (
              <div
                key={alert.id}
                className={`alert-item ${alert.is_read ? "read" : "unread"}`}
              >
                <div className="alert-header">
                  <a
                    href={
                      alert.vulnerability?.url ||
                      `https://cvefeed.io/vuln/detail/${alert.vulnerability?.id}`
                    }
                    target="_blank"
                    rel="noopener noreferrer"
                    className="alert-cve"
                  >
                    {alert.vulnerability?.id}
                  </a>
                  <span
                    className={`sev-tag ${(
                      alert.vulnerability?.severity || ""
                    ).toLowerCase()}`}
                  >
                    {alert.vulnerability?.severity}
                  </span>
                </div>
                <div className="alert-product">
                  {alert.affected_products?.vendor?.name} /{" "}
                  {alert.affected_products?.name}
                </div>
                <div className="alert-meta">
                  <span>
                    CVSS: {alert.vulnerability?.cvss_score ?? "N/A"}
                  </span>
                  <span>
                    {new Date(alert.created_at).toLocaleDateString()}
                  </span>
                  {!alert.is_read && (
                    <button
                      className="btn-mark-read"
                      onClick={() => handleMarkRead(alert.id)}
                    >
                      Mark Read
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="no-alerts">No recent alerts.</p>
        )}
      </div>

      {/* ── Subscriptions Preview ── */}
      {subscriptions && subscriptions.length > 0 && (
        <div className="subs-section">
          <h3>Monitored Products</h3>
          <div className="subs-list">
            {subscriptions.slice(0, 8).map((sub) => (
              <span key={sub.product?.id || sub.id} className="sub-chip">
                {sub.product?.name}
                <span className="sub-cve-count">
                  {sub.number_of_cve || 0} CVEs
                </span>
              </span>
            ))}
            {subscriptions.length > 8 && (
              <span className="sub-chip more">
                +{subscriptions.length - 8} more
              </span>
            )}
          </div>
        </div>
      )}

      {/* ── Footer ── */}
      <div className="gadget-footer">
        <a
          href="https://cvefeed.io"
          target="_blank"
          rel="noopener noreferrer"
        >
          Open CVEFeed.io
        </a>
      </div>
    </div>
  );
}

export default App;
