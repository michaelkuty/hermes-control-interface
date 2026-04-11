# HCI Revamp v2 — Progress

Branch: `revamp/v2`
Last updated: 2026-04-12 by david

## Phase 1: Foundation ✅
- [x] Module 1.1: Project setup (Vite + vanilla JS init)
- [x] Module 1.2: Theme system (dark/light CSS + toggle)
- [x] Module 1.3: Layout skeleton (nav + content area + routing)
- [x] Module 1.4: Login page + auth frontend
- [x] Module 1.5: User Menu + notifications shell

## Phase 4: Backend API ✅
- [x] Module 4.1: Auth API (login, logout, setup, change-password, users CRUD)
- [x] Module 4.2: System API (health, agents, sessions, gateway, config)
- [x] Module 4.3: Notifications API
- [x] Module 4.4: Audit log API
- [x] All 40+ endpoints implemented and tested

## Phase 2: Core Pages ← IN PROGRESS
- [ ] Module 2.1: Home page (system health + hermes overview) ← NEXT
- [ ] Module 2.2: Agents page (profile list + CRUD)
- [ ] Module 2.3: Agent Detail — Dashboard tab
- [ ] Module 2.4: Agent Detail — Sessions tab
- [ ] Module 2.5: Agent Detail — Gateway tab
- [ ] Module 2.6: Agent Detail — Config tab (13 categories)
- [ ] Module 2.7: Agent Detail — Memory tab (dynamic)

## Phase 3: Supporting Pages
- [ ] Module 3.1: System Monitor
- [ ] Module 3.2: Skills Marketplace
- [ ] Module 3.3: Maintenance

## Phase 5: Polish
- [ ] Module 5.1: Responsive + edge cases
- [ ] Module 5.2: Error handling + loading states

## Phase 6: Release
- [ ] QA testing (browser auto-test)
- [ ] Sync staging → prod
- [ ] Major version commit + GitHub release

## API Endpoints Available
Auth: /api/auth/me, /api/auth/login, /api/auth/setup, /api/auth/logout, /api/auth/change-password
Users: /api/users (GET/POST), /api/users/:username (DELETE), /api/users/:username/reset-password
Audit: /api/audit
Notifications: /api/notifications, /api/notifications/:id/dismiss, /api/notifications/clear
System: /api/system/health, /api/dashboard-state
Sessions: /api/sessions, /api/all-sessions
Profiles: /api/profiles, /api/profiles/use
Gateway: /api/gateway/:profile, /api/gateway/:profile/:action, /api/gateway/:profile/logs
Insights: /api/insights
Cron: /api/cron/:action
Files: /api/explorer, /api/file
Terminal: /api/terminal/exec
Chat: /api/chat
