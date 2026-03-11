import React from "react";

const SEVERITY_LABELS = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};

export default function SeverityBadge({ severity, count, compact }) {
  const sev = (severity || "").toUpperCase();
  const label = SEVERITY_LABELS[sev] || SEVERITY_LABELS.LOW;
  const className = sev.toLowerCase() || "low";

  return (
    <span
      className={`severity-badge sev-badge-${className}`}
      style={{
        padding: compact ? "1px 6px" : "2px 8px",
        borderRadius: "4px",
        fontSize: compact ? "11px" : "12px",
        fontWeight: 600,
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
      }}
    >
      {label}
      {count !== undefined && <span>({count})</span>}
    </span>
  );
}
