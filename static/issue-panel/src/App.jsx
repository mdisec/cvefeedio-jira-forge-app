import React, { useEffect, useState, useCallback } from "react";
import { invoke, view } from "@forge/bridge";
import SeverityBadge from "./components/SeverityBadge";
import VulnerabilityCard from "./components/VulnerabilityCard";
import VulnerabilityDetail from "./components/VulnerabilityDetail";
import SearchPanel from "./components/SearchPanel";
import "./styles.css";

function App() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [selectedCve, setSelectedCve] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [searching, setSearching] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const context = await view.getContext();
      const issueKey = context?.extension?.issue?.key;
      if (!issueKey) {
        setError("Could not determine issue key.");
        return;
      }

      const result = await invoke("getIssueVulnerabilities", { issueKey });
      setData(result);
    } catch (err) {
      setError(err.message || "Failed to load vulnerability data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSearch = async (query) => {
    if (!query.trim()) return;
    setSearching(true);
    setSearchResults(null);
    try {
      const result = await invoke("searchVulnerabilities", { query: query.trim() });
      if (result.success) {
        setSearchResults(result.data);
      } else {
        setError(result.error);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setSearching(false);
    }
  };

  const handleViewDetail = async (cveId) => {
    try {
      const result = await invoke("getVulnerabilityDetail", { cveId });
      if (result.success) {
        setSelectedCve(result.data);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  // ── Not configured state ──
  if (!loading && data && !data.configured) {
    return (
      <div className="panel-container">
        <div className="empty-state">
          <div className="empty-icon">🔧</div>
          <h3>CVEFeed.io Not Configured</h3>
          <p>
            An administrator needs to connect this Jira site to CVEFeed.io.
            Go to <strong>Apps → CVEFeed.io Configuration</strong> to set up.
          </p>
        </div>
      </div>
    );
  }

  // ── Loading state ──
  if (loading) {
    return (
      <div className="panel-container">
        <div className="loading">
          <div className="spinner" />
          <span>Scanning for vulnerabilities…</span>
        </div>
      </div>
    );
  }

  // ── Error state ──
  if (error) {
    return (
      <div className="panel-container">
        <div className="error-banner">
          <span>⚠️ {error}</span>
          <button className="btn-link" onClick={loadData}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  // ── CVE Detail view ──
  if (selectedCve) {
    return (
      <div className="panel-container">
        <VulnerabilityDetail
          vulnerability={selectedCve}
          onBack={() => setSelectedCve(null)}
        />
      </div>
    );
  }

  const vulnerabilities = data?.vulnerabilities || [];
  const cveIds = data?.cveIds || [];

  return (
    <div className="panel-container">
      {/* ── Header ── */}
      <div className="panel-header">
        <div className="header-left">
          <img
            src="https://cvefeed.io/static/img/cvefeed-icon.png"
            alt="CVEFeed.io"
            className="header-logo"
            onError={(e) => { e.target.style.display = "none"; }}
          />
          <h2>CVEFeed.io</h2>
        </div>
        {cveIds.length > 0 && (
          <div className="header-badge">
            <SeverityBadge
              severity={getMaxSeverity(vulnerabilities)}
              count={cveIds.length}
            />
          </div>
        )}
      </div>

      {/* ── Detected CVEs ── */}
      {vulnerabilities.length > 0 && (
        <div className="section">
          <h3 className="section-title">
            Detected Vulnerabilities ({vulnerabilities.length})
          </h3>
          <div className="vuln-list">
            {vulnerabilities.map((vuln) => (
              <VulnerabilityCard
                key={vuln.id}
                vulnerability={vuln}
                onViewDetail={() => handleViewDetail(vuln.id)}
              />
            ))}
          </div>
        </div>
      )}

      {/* ── No CVEs found — show search ── */}
      {vulnerabilities.length === 0 && (
        <div className="section">
          {cveIds.length === 0 ? (
            <div className="empty-state small">
              <p>No CVE IDs detected in this issue.</p>
              <p className="hint">
                Add CVE IDs (e.g., CVE-2024-12345) to the summary, description,
                labels, or comments to see vulnerability data here.
              </p>
            </div>
          ) : (
            <div className="empty-state small">
              <p>
                Found {cveIds.length} CVE ID(s) but could not fetch details.
              </p>
            </div>
          )}
        </div>
      )}

      {/* ── Search ── */}
      <SearchPanel
        query={searchQuery}
        onQueryChange={setSearchQuery}
        onSearch={handleSearch}
        results={searchResults}
        searching={searching}
        onViewDetail={handleViewDetail}
      />

      {/* ── Footer ── */}
      <div className="panel-footer">
        <a
          href="https://cvefeed.io"
          target="_blank"
          rel="noopener noreferrer"
          className="footer-link"
        >
          Powered by CVEFeed.io
        </a>
      </div>
    </div>
  );
}

function getMaxSeverity(vulns) {
  const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  let max = 0;
  let label = "LOW";
  vulns.forEach((v) => {
    const sev = (v.severity || "").toUpperCase();
    if ((order[sev] || 0) > max) {
      max = order[sev];
      label = sev;
    }
  });
  return label;
}

export default App;
