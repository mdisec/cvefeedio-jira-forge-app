import React from "react";
import VulnerabilityCard from "./VulnerabilityCard";

export default function SearchPanel({
  query,
  onQueryChange,
  onSearch,
  results,
  searching,
  onViewDetail,
}) {
  const handleKeyDown = (e) => {
    if (e.key === "Enter") {
      onSearch(query);
    }
  };

  const resultList = results?.results || (Array.isArray(results) ? results : []);

  return (
    <div className="search-section">
      <h3 className="section-title">Search Vulnerabilities</h3>
      <div className="search-bar">
        <input
          type="text"
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Search by CVE ID, product, or keyword…"
          className="search-input"
        />
        <button
          className="btn-search"
          onClick={() => onSearch(query)}
          disabled={searching || !query.trim()}
        >
          {searching ? "Searching…" : "Search"}
        </button>
      </div>

      {results && resultList.length === 0 && (
        <p className="no-results">No vulnerabilities found for "{query}"</p>
      )}

      {resultList.length > 0 && (
        <div className="vuln-list">
          {resultList.map((vuln) => (
            <VulnerabilityCard
              key={vuln.id}
              vulnerability={vuln}
              onViewDetail={() => onViewDetail(vuln.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
