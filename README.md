# CVEFeed.io for Jira — Forge App

Atlassian Forge app that brings CVEFeed.io vulnerability intelligence directly into Jira.

## Modules

| Module | Description |
|--------|-------------|
| **Issue Panel** | Shows CVE data for vulnerabilities mentioned in a Jira issue |
| **Issue Glance** | Compact severity badge in the issue sidebar |
| **Dashboard Gadget** | Project-wide vulnerability summary with severity distribution and recent alerts |
| **Admin Page** | Configuration page to connect CVEFeed.io API token |
| **Global Page** | Full-page vulnerability browser accessible from Apps menu |
| **Web Trigger** | Incoming webhook endpoint for real-time alert pushes from CVEFeed.io |
| **Scheduled Trigger** | Hourly sync of vulnerability data |

## Quick Start

### Prerequisites

- Node.js 22+
- [Atlassian Forge CLI](https://developer.atlassian.com/platform/forge/getting-started/)
- A CVEFeed.io account with API token (Pro tier or above)

### Setup

```bash
# Install Forge CLI
npm install -g @forge/cli

# Login to Atlassian
forge login

# Register the app (first time only — updates manifest.yml with real app ID)
forge register

# Install dependencies
npm install
cd static/issue-panel && npm install && cd ../..
cd static/admin-page && npm install && cd ../..
cd static/dashboard-gadget && npm install && cd ../..

# Build all Custom UI frontends
npm run build:all

# Deploy
forge deploy

# Install on your Jira site
forge install
```

### Development

```bash
# Start tunnel for live development
npm run start

# Build individual modules
npm run build:issue-panel
npm run build:admin-page
npm run build:dashboard-gadget
```

## Architecture

```
jira-forge/
├── manifest.yml                 # Forge app manifest
├── package.json                 # Root dependencies
├── src/
│   ├── index.js                 # Resolver functions (Forge backend)
│   ├── api.js                   # CVEFeed.io API client
│   └── storage.js               # Forge storage utilities
├── static/
│   ├── issue-panel/             # Issue Panel Custom UI (React)
│   ├── admin-page/              # Admin + Global Page Custom UI (React)
│   └── dashboard-gadget/        # Dashboard Gadget Custom UI (React)
└── resources/
    └── images/icon.svg          # App icon
```

## How It Works

1. **Admin configures** the app via Apps → CVEFeed.io Configuration, entering their API token and project ID
2. **Issue Panel** automatically scans issue summary, description, labels, and comments for CVE IDs (e.g., CVE-2024-12345) and fetches vulnerability details from CVEFeed.io
3. **Dashboard Gadget** shows severity distribution, recent alerts, and monitored products
4. **Web Trigger** receives real-time pushes from CVEFeed.io when new vulnerabilities are detected
5. **Scheduled Trigger** refreshes cached data hourly

## CVEFeed.io API Integration

The app calls these CVEFeed.io API endpoints:

- `GET /api/vulnerability/{cve_id}/` — Vulnerability details
- `GET /api/vulnerability/quick-search?q=...` — Search vulnerabilities
- `GET /api/projects/{id}/alerts/` — Project alerts
- `GET /api/projects/{id}/vulns/` — Project vulnerabilities
- `GET /api/projects/{id}/products/` — Product subscriptions
- `GET /api/projects/{id}/` — Project details

Authentication uses `Bearer` token in the `Authorization` header.

## Marketplace Publishing

1. Ensure all modules build successfully: `npm run build:all`
2. Deploy to production: `forge deploy -e production`
3. Submit via [Atlassian Marketplace](https://developer.atlassian.com/platform/marketplace/)
4. Required: privacy policy, support URL, app description, screenshots
de