# Hermes Control Interface


A self-hosted web dashboard for the Hermes AI agent stack. Provides a browser-based terminal, file explorer, session overview, cron management, system metrics, and an agent status panel — all behind a single password gate.

**Designed for:** Single-user local networks or reverse-proxied VPS deployments. Not a multi-tenant product.

---
![Hermes Control Interface Demo](https://github.com/user-attachments/assets/9fb518c0-7990-4fc8-a681-8d2e87b10116)

## Features

- **Terminal** — Real PTY shell (node-pty) in the browser via xterm.js. Full ANSI colour, persistent session. Mobile-optimized (reduced scrollback, touch scroll).
- **File Explorer** — Browse and edit files across configurable root directories. No upload/download friction.
- **Agent List** — View all Hermes profiles with status, model, and gateway controls. Start/stop gateway and activate profiles directly from the sidebar.
- **Gateway Service Management** — Install and manage systemd gateway services per profile from the dashboard.
- **Session Monitor** — Live view of Hermes sessions and cron jobs.
- **Real-time Logs** — Stream agent, error, and gateway logs with level filtering.
- **Token Usage** — Interactive token usage stats with time/source filters.
- **System Metrics** — CPU, memory, uptime. Event-driven updates via WebSocket (no polling).
- **Rate-Limited Auth** — 5 failed login attempts in 15 minutes → 15-minute lockout. Timing-safe password comparison. HMAC-signed session cookies.
- **Layout Persistence** — Dashboard panel arrangement saved to `~/.hermes/control-interface-layout.json`.

---

## Requirements

- **Node.js 20+**
- **npm**
- A Hermes installation on the same machine (optional — the dashboard works without it, some panels just show placeholder data)
- `hermes` on PATH (optional, for in-terminal command shortcuts)

---

## Quick Start

```bash
git clone https://github.com/xaspx/hermes-control-interface.git hermes-control-interface
cd hermes-control-interface
npm install          # or: bash install.sh (interactive setup)
cp .env.example .env
# Edit .env — set HERMES_CONTROL_PASSWORD and HERMES_CONTROL_SECRET
npm start
```

Open `http://localhost:10272`.

---

## First-Run Setup

Run the interactive setup script for guided configuration:

```bash
bash install.sh
```

This will:
1. Check Node.js version
2. Install npm dependencies
3. Generate a random password and secret (or reuse existing `.env`)
4. Optionally configure nginx HTTPS reverse-proxy
5. Optionally install a systemd service for auto-start

---

## Configuration

All settings are environment variables. See [docs/CONFIG.md](docs/CONFIG.md) for the full reference.

**Required:**
| Variable | Description |
|---|---|
| `HERMES_CONTROL_PASSWORD` | Login password |
| `HERMES_CONTROL_SECRET` | HMAC secret for auth tokens (generate with `openssl rand -hex 32`) |

**Optional:**
| Variable | Default | Description |
|---|---|---|
| `PORT` | `10272` | HTTP listen port |
| `HERMES_CONTROL_HOME` | `~/.hermes` | Hermes root directory (file explorer root) |
| `HERMES_PROJECTS_ROOT` | parent of repo | Explorer projects root |
| `HERMES_CONTROL_ROOTS` | `HERMES_PROJECTS_ROOT` + `HERMES_CONTROL_HOME` | Explorer root overrides |

---

## Deployment

### Option A — Behind nginx reverse-proxy (recommended for VPS)

```bash
# In install.sh, answer Yes to the nginx prompt, or create manually:
# Proxy to http://127.0.0.1:10272 from your HTTPS server block.
# See docs/DEPLOY.md for a full example nginx config.
```

The dashboard must be served over HTTPS. The `Secure` cookie flag is always set.

### Option B — Direct on LAN (home network only)

Bind to `0.0.0.0` (default) and password-protect. Do not expose directly to the public internet without a reverse-proxy and TLS.

### Option C — systemd service

```bash
# After running install.sh:
sudo systemctl start hermes-control
sudo systemctl status hermes-control  # verify it's running
```

Auto-start on boot is enabled automatically if you installed via `install.sh`.

---

## Security Notes

- The password is compared using `crypto.timingSafeEqual` — no timing oracle.
- Auth cookies are HMAC-signed with a per-deployment secret. They expire after 24 hours.
- Rate limiting blocks an IP after 5 failed attempts in 15 minutes.
- The `Secure` cookie flag is always set. Access over HTTP only works on `localhost` — use HTTPS in production.
- File operations are scoped to configured explorer roots — path traversal out of allowed directories is blocked.
- No multi-user support. All browser sessions share the same password.

See [docs/SECURITY.md](docs/SECURITY.md) for the full security analysis.

---

## API Reference

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | No | Health check |
| `GET` | `/api/session` | No | Auth status |
| `POST` | `/api/login` | No | Login (rate-limited) |
| `POST` | `/api/logout` | No | Clear session |
| `GET` | `/api/dashboard-state` | Yes | Full dashboard snapshot |
| `GET` | `/api/profiles` | Yes | List Hermes profiles |
| `POST` | `/api/profiles/use` | Yes | Set active profile |
| `GET` | `/api/gateway/:profile` | Yes | Gateway service status |
| `POST` | `/api/gateway/:profile/:action` | Yes | Start/stop/restart gateway |
| `GET` | `/api/gateway/:profile/logs` | Yes | Gateway journal logs |
| `GET` | `/api/explorer` | Yes | Directory tree |
| `GET` | `/api/file` | Yes | Read file |
| `POST` | `/api/file` | Yes | Write file |
| `POST` | `/api/terminal/exec` | Yes | Run terminal command |
| `POST` | `/api/cron/:action` | Yes | Manage cron jobs |
| `GET` | `/api/usage` | Yes | System metrics |
| `GET` | `/api/layout` | Yes | Get layout |
| `POST` | `/api/layout` | Yes | Save layout |
| `GET` | `/api/avatar` | Yes | Get avatar metadata (url + custom flag) |
| `GET` | `/api/avatar/image` | Yes | Get avatar image (raw binary, cacheable) |
| `POST` | `/api/avatar` | Yes | Upload avatar |
| `DELETE` | `/api/avatar` | Yes | Reset avatar |
| `WS` | `/ws` | Yes | Live dashboard updates + terminal I/O |

All authenticated endpoints require a valid session cookie (`hermes...auth`).

Internal endpoints (`/internal/cron/:action`) require the `x-hermes-control-secret` header matching `HERMES_CONTROL_SECRET`.

---

## Repo Layout

```
hermes-control-interface/
├── server.js          # Express server, auth, PTY, WebSocket, APIs
├── website/           # Frontend (vanilla JS, xterm.js)
├── scripts/           # Setup scripts
│   └── setup-gateway-service.sh  # systemd gateway service installer
├── docs/              # Detailed documentation
│   ├── API.md         # API endpoint details
│   ├── CONFIG.md      # Environment variable reference
│   ├── DEPLOY.md      # Production deployment guide
│   ├── INSTALL.md     # Installation guide
│   ├── PASSWORD.md    # Password management
│   ├── SECURITY.md    # Security analysis
│   └── TROUBLESHOOTING.md
├── .env.example       # Template — copy to .env
├── .env               # Runtime config (gitignored)
├── install.sh         # Interactive first-run setup
└── package.json
```

---

## Changelog

### v2.0.0 — Agent Management + Gateway Services + UX Polish
- **Agent List panel** — sidebar showing all Hermes profiles with status, model, gateway controls
- **Activate profile** — set default profile via `hermes profile use` from dashboard
- **Gateway service management** — install/start/stop/restart systemd services per profile
  - `scripts/setup-gateway-service.sh` — one-command service installer
  - API: `GET/POST /api/gateway/:profile/*` — status, start, stop, restart, logs
- **Real-time logs panel** — stream agent/error/gateway logs with level filter
- **Token usage panel** — interactive filters by time period and source
- **Terminal UX** — mobile-optimized (reduced scrollback, touch scroll, larger font)
- **File explorer root fix** — `HERMES_CONTROL_HOME` (always `~/.hermes`, not profile subdirectory)
- **Security fixes** — CSP-safe event delegation, CSRF on gateway endpoints, Python log buffering fix

### v1.11.0 — Real-time Logs Panel
- Streaming logs via `hermes logs` (Agent/Errors/Gateway tabs)
- Log level filter (DEBUG/INFO/WARN/ERROR)
- Pause/resume log stream

### v1.10.0 — Token Usage
- Interactive token usage filters (time period + source)
- Model breakdown per provider

### v1.9.0 — UI Layout
- Sidebar reorder, responsive panels, mobile fix

### v1.8.0 — Password System
- bcrypt auth, rate limiting, CSRF

### v1.7.0 — Architecture
- Async CLI execution, YAML parser, panel cleanup

### v1.6.0 — Code Cleanup
- Dead code removal, timing-safe comparison, graceful shutdown

### v1.5.0 — Open Source Readiness
- MIT LICENSE, CONTRIBUTING.md, CODE_OF_CONDUCT.md
- GitHub issue templates (bug report, feature request)
- `engines` field (Node.js >= 20.0.0)
- All repo URLs updated to https://github.com/xaspx/hermes-control-interface

### v1.4.0 — CSRF Protection + Security
- CSRF token on all POST/PUT/DELETE endpoints
- Helmet security headers (CSP, X-Frame-Options, nosniff)
- bcrypt password hashing + reset-password script

### v1.3.0 — Helmet + Animated GIF
- Helmet middleware with safe CSP config
- Animated GIF avatar support (`<img>` element)
- Real-time system monitor via WebSocket (3s interval)

### v1.2.0 — UI Cleanup + Real Insights
- Remove state pill and Signal section from sidebar
- Toast notifications (avatar, file save, layout)
- Real token data from `hermes insights --days 7`
- Auto-refresh toggle button (10s interval)

### v1.1.0 — Stability Fixes
- Avatar served via `/api/avatar/image` endpoint
- Event-driven refresh (removed 15s broadcast + 10s polling)
- Smart rendering with change detection
- File explorer scroll position preserved

---

## Troubleshooting

**502 Bad Gateway**
The Node.js process isn't running. Check that `.env` exists and has valid `HERMES_CONTROL_PASSWORD` / `HERMES_CONTROL_SECRET` values.

```bash
cd hermes-control-interface
node server.js
# Look for startup errors
```

**"authentication required" after login**
The cookie wasn't accepted. Check that you're accessing the dashboard over HTTPS (required for `Secure` cookies), or that your reverse-proxy is forwarding cookies correctly.

**Port already in use**
Change the port: `PORT=10702 npm start` or set `PORT=10702` in `.env`.

**Terminal not connecting**
Make sure `node-pty` compiled successfully. On some systems you may need `make` and a C++ compiler.

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for more.
