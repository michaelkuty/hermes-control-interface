const state = {
  snapshot: null,
  socket: null,
  pollTimer: null,
  clockTimer: null,
  sessionsPoller: null,
  lastLogId: null,
  currentFile: null,
  currentTree: [],
  expandedRoots: new Set(['hermes']),
  expandedDirs: new Set(),
  dirty: false,
  terminalLineCount: 0,
  lastTerminalBufferLength: 0,
  terminal: null,
  terminalFit: null,
  terminalInitRetry: null,
  pendingTerminalBuffer: '',
  terminalFullscreen: false,
  explorerFullscreen: false,
  avatarSource: '',
  avatarImage: null,
  avatarCanvas: null,
  avatarCtx: null,
  avatarState: 'idle',
  spriteTick: 0,
  widgetLayoutReady: false,
  layoutEditMode: false,
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const els = {
  shell: $('#shell'),
  topbar: $('#topbar'),
  overlay: $('#login-overlay'),
  loginForm: $('#login-form'),
  passwordInput: $('#password-input'),
  loginError: $('#login-error'),
  statusPill: $('#status-pill'),
  modelPill: $('#model-pill'),
  statePill: $('#state-pill'),
  clock: $('#clock'),
  busState: $('#bus-state'),
  refreshBtn: $('#refresh-btn'),
  layoutEditBtn: $('#layout-edit-btn'),
  layoutSaveBtn: $('#layout-save-btn'),
  logoutBtn: $('#logout-btn'),
  projectsList: null, // removed - projects sidebar gone
  sessionsList: $('#sessions-list'),
  quickActions: $('#quick-actions'),
  terminalOutput: $('#terminal-output'),
  terminalForm: $('#terminal-form'),
  terminalInput: $('#terminal-input'),
  terminalPrompt: $('#terminal-prompt'),
  terminalLabel: $('#terminal-label'),
  terminalFullscreenBtn: $('#terminal-fullscreen-btn'),
  fileStatus: $('#file-status'),
  explorerRoots: $('#explorer-roots'),
  projectsTree: $('#projects-tree'),
  hermesTree: $('#hermes-tree'),
  editorPath: $('#editor-path'),
  editorMeta: $('#editor-meta'),
  editor: $('#file-editor'),
  saveBtn: $('#save-file-btn'),
  explorerFullscreenBtn: $('#explorer-fullscreen-btn'),
  sidebarAgentSprite: $('#sidebar-agent-sprite'),
  sidebarAgentState: $('#sidebar-agent-state'),
  sidebarAgentDetails: $('#sidebar-agent-details'),
  systemPanel: $('#system-panel'),
  cronPanel: $('#cron-panel'),
  tokensPanel: $('#tokens-panel'),
  backgroundPanel: $('#background-panel'),
  sprite: $('#agent-sprite'),
  agentStateLabel: $('#agent-state-label'),
  agentDetails: $('#agent-details'),
  markdownView: $('#markdown-view'),
  eventsCount: $('#events-count'),
  tokenProvider: $('#token-provider'),
  loadLabel: $('#load-label'),
  avatarUploadBtn: $('#avatar-upload-btn'),
  avatarResetBtn: $('#avatar-reset-btn'),
  avatarFileInput: $('#avatar-file-input'),
};

const spriteFrames = {
  idle: [
    [
      '................',
      '.....oooooo.....',
      '....oohhhhhho....',
      '...ohhhsssshhho..',
      '..ohhhsseeesshh..',
      '.ohhsseoomoessh..',
      '.ohhsseessssesh..',
      '.ohhssssssssshh..',
      '..ohhsssssssshh..',
      '...ohhhhhhhhhho..',
      '.....ojjjjjjo....',
      '....ojbbbbbbj....',
      '...ojbbttttbbjo..',
      '..ojbbbbbbbbbbjo.',
      '..ojbbbbbbbbbbjo.',
      '...ojppppppppjo..',
      '....ohppppppho...',
      '......ohhhho.....',
    ],
    [
      '................',
      '.....oooooo.....',
      '....oohhhhhho....',
      '...ohhhsssshhho..',
      '..ohhhsseeesshh..',
      '.ohhsseoxxoeessh.',
      '.ohhsseessssesh..',
      '.ohhssssssssshh..',
      '..ohhsssssssshh..',
      '...ohhhhhhhhhho..',
      '.....ojjjjjjo....',
      '....ojbbbbbbj....',
      '...ojbbttttbbjo..',
      '..ojbbbbbbbbbbjo.',
      '..ojbbbbbbbbbbjo.',
      '...ojppppppppjo..',
      '....ohppppppho...',
      '......ohhhho.....',
    ],
  ],
  thinking: [
    [
      '................',
      '.....oooooo.....',
      '....oohhhhhho....',
      '...ohhhsssshhho..',
      '..ohhhsseeesshh..',
      '.ohhsseo--oeessh.',
      '.ohhsseessssesh..',
      '.ohhssssssssshh..',
      '..ohhsssssssshh..',
      '...ohhhhhhhhhho..',
      '.....ojjjjjjo....',
      '....ojbbbbbbj....',
      '...ojbbttttbbjo..',
      '..ojbbbbbbbbbbjo.',
      '..ojbbbbbbbbbbjo.',
      '...ojppppppppjo..',
      '....ohppppppho...',
      '......ohhhho.....',
    ],
    [
      '................',
      '.....oooooo.....',
      '....oohhhhhho....',
      '...ohhhsssshhho..',
      '..ohhhsseeesshh..',
      '.ohhsseoxxoeessh.',
      '.ohhsseessssesh..',
      '.ohhssssssssshh..',
      '..ohhsssssssshh..',
      '...ohhhhhhhhhho..',
      '.....ojjjjjjo....',
      '....ojbbbbbbj....',
      '...ojbbttttbbjo..',
      '..ojbbbbbbbbbbjo.',
      '..ojbbbbbbbbbbjo.',
      '...ojppppppppjo..',
      '....ohppppppho...',
      '......ohhhho.....',
    ],
  ],
  coding: [
    [
      '................',
      '.....oooooo.....',
      '....oohhhhhho....',
      '...ohhhsssshhho..',
      '..ohhhsseeesshh..',
      '.ohhsseoomoessh..',
      '.ohhsseessssesh..',
      '.ohhssssssssshh..',
      '..ohhsssssssshh..',
      '...ohhhhhhhhhho..',
      '.....ojjjjjjo....',
      '....ojbbbbbbj....',
      '...ojbbttttbbjo..',
      '..ojbbbbbbbbbbjo.',
      '..ojbbbbbbbbbbjo.',
      '...ojppppppppjo..',
      '....ohppppppho...',
      '......ohhhho.....',
    ],
    [
      '................',
      '.....oooooo.....',
      '....oohhhhhho....',
      '...ohhhsssshhho..',
      '..ohhhsseeesshh..',
      '.ohhsseoxxoeessh.',
      '.ohhsseessssesh..',
      '.ohhssssssssshh..',
      '..ohhsssssssshh..',
      '...ohhhhhhhhhho..',
      '.....ojjjjjjo....',
      '....ojbbbbbbj....',
      '...ojbbttttbbjo..',
      '..ojbbbbbbbbbbjo.',
      '..ojbbbbbbbbbbjo.',
      '...ojppppppppjo..',
      '....ohppppppho...',
      '......ohhhho.....',
    ],
  ],
  executing: [
    [
      '................',
      '.....oooooo.....',
      '....oohhhhhho....',
      '...ohhhsssshhho..',
      '..ohhhsseeesshh..',
      '.ohhsseoomoessh..',
      '.ohhsseessssesh..',
      '.ohhssssssssshh..',
      '..ohhsssssssshh..',
      '...ohhhhhhhhhho..',
      '.....ojjjjjjo....',
      '....ojbbbbbbj....',
      '...ojbbttttbbjo..',
      '..ojbbbbbbbbbbjo.',
      '..ojbbbbbbbbbbjo.',
      '...ojppppppppjo..',
      '....ohppppppho...',
      '......ohhhho.....',
    ],
    [
      '................',
      '.....oooooo.....',
      '....oohhhhhho....',
      '...ohhhsssshhho..',
      '..ohhhsseeesshh..',
      '.ohhsseoxxoeessh.',
      '.ohhsseessssesh..',
      '.ohhssssssssshh..',
      '..ohhsssssssshh..',
      '...ohhhhhhhhhho..',
      '.....ojjjjjjo....',
      '....ojbbbbbbj....',
      '...ojbbttttbbjo..',
      '..ojbbbbbbbbbbjo.',
      '..ojbbbbbbbbbbjo.',
      '...ojppppppppjo..',
      '....ohppppppho...',
      '......ohhhho.....',
    ],
  ],
};

const palette = {
  o: '#1d1526',
  h: '#4a321f',
  s: '#f0c7a1',
  b: '#356df5',
  p: '#2e3548',
  l: '#fff4d6',
  g: '#9ad7ff',
  x: '#ff8b7a',
};

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function fmtBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n || 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function fmtTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function addLine(text, cls = 'dim') {
  const line = document.createElement('div');
  line.className = `terminal-line ${cls}`;
  line.textContent = text;
  els.terminalOutput.appendChild(line);
  els.terminalOutput.scrollTop = els.terminalOutput.scrollHeight;
}

function bootTerminal() {
  if (!els.terminalOutput) return;
  if (state.terminal) return;
  if (!window.Terminal || !window.FitAddon) {
    if (!state.terminalInitRetry) {
      state.terminalInitRetry = setTimeout(() => {
        state.terminalInitRetry = null;
        bootTerminal();
      }, 120);
    }
    return;
  }

  els.terminalOutput.innerHTML = '';
  if (!state.terminal) {
    state.terminal = new window.Terminal({
      cursorBlink: true,
      fontFamily: 'JetBrains Mono, monospace',
      fontSize: 13,
      theme: {
        background: '#000000',
        foreground: '#ede6d4',
        cursor: '#f4c75c',
        selectionBackground: 'rgba(244, 199, 92, 0.25)',
      },
      scrollback: 5000,
      allowTransparency: true,
    });
    state.terminalFit = new window.FitAddon.FitAddon();
    state.terminal.loadAddon(state.terminalFit);
    state.terminal.open(els.terminalOutput);
    els.terminalOutput.addEventListener('click', () => state.terminal?.focus());
    window.visualViewport?.addEventListener('resize', () => setTimeout(syncTerminalSize, 50));
    state.terminal.onData((data) => {
      if (state.socket?.readyState === WebSocket.OPEN) {
        state.socket.send(JSON.stringify({ type: 'terminal-input', data }));
      } else {
        fetch('/api/terminal/exec', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: data }),
        }).catch(() => {});
      }
    });
    window.addEventListener('resize', () => syncTerminalSize());
  }

  state.terminal.writeln('\x1b[1;33mHermes terminal connected.\x1b[0m');
  state.terminal.writeln('\x1b[2mroot@hermes session ready. Type: hermes\x1b[0m');
  if (state.pendingTerminalBuffer) {
    state.terminal.write(state.pendingTerminalBuffer);
    state.pendingTerminalBuffer = '';
  }
  syncTerminalSize();
}

function syncTopbarOffset() {
  if (!els.topbar) return;
  const height = Math.ceil(els.topbar.getBoundingClientRect().height || 68);
  document.documentElement.style.setProperty('--topbar-offset', `${height}px`);
}

function syncTerminalSize() {
  if (!state.terminal || !state.terminalFit) return;
  try {
    state.terminalFit.fit();
    const cols = state.terminal.cols;
    const rows = state.terminal.rows;
    if (state.socket?.readyState === WebSocket.OPEN) {
      state.socket.send(JSON.stringify({ type: 'terminal-resize', cols, rows }));
    }
  } catch {}
}

function setTerminalFullscreen(enabled) {
  state.terminalFullscreen = Boolean(enabled);
  if (state.terminalFullscreen && window.matchMedia('(max-width: 1200px)').matches) {
    state.terminalFullscreen = false;
  }
  document.body.classList.toggle('terminal-fullscreen', state.terminalFullscreen);
  els.shell.classList.toggle('terminal-fullscreen', state.terminalFullscreen);
  const panel = document.querySelector('[data-panel-id="terminal"]');
  if (panel) panel.classList.toggle('is-fullscreen', state.terminalFullscreen);
  if (els.terminalFullscreenBtn) {
    els.terminalFullscreenBtn.textContent = state.terminalFullscreen ? 'exit fullscreen' : 'fullscreen';
  }
  syncTopbarOffset();
  requestAnimationFrame(() => {
    syncTopbarOffset();
    syncTerminalSize();
  });
}

function setExplorerFullscreen(enabled) {
  state.explorerFullscreen = Boolean(enabled);
  if (state.explorerFullscreen && window.matchMedia('(max-width: 1200px)').matches) {
    state.explorerFullscreen = false;
  }
  document.body.classList.toggle('explorer-fullscreen', state.explorerFullscreen);
  els.shell.classList.toggle('explorer-fullscreen', state.explorerFullscreen);
  const panel = document.querySelector('[data-panel-id="explorer"]');
  if (panel) panel.classList.toggle('is-fullscreen', state.explorerFullscreen);
  if (els.explorerFullscreenBtn) {
    els.explorerFullscreenBtn.textContent = state.explorerFullscreen ? 'exit fullscreen' : 'fullscreen';
  }
  syncTopbarOffset();
  requestAnimationFrame(() => {
    syncTopbarOffset();
  });
}

function writeTerminalRaw(chunk) {
  const raw = String(chunk || '');
  if (!raw) return;
  if (state.terminal) {
    state.terminal.write(raw);
  } else {
    state.pendingTerminalBuffer += raw;
  }
}

function renderTerminalBuffer(snapshotTerminal) {
  if (!snapshotTerminal) return;
  const text = String(snapshotTerminal.buffer || '');
  state.lastTerminalBufferLength = text.length;
  if (text) {
    if (state.terminal) state.terminal.write(text);
    else state.pendingTerminalBuffer += text;
  }
  bootTerminal();
}

function appendTerminalChunk(chunk) {
  writeTerminalRaw(chunk);
}

function renderList(container, items, formatter) {
  const tpl = $('#list-item-template');
  container.innerHTML = '';
  items.forEach((item) => {
    const node = tpl.content.firstElementChild.cloneNode(true);
    node.querySelector('.item-text').innerHTML = formatter(item);
    container.appendChild(node);
  });
}

function renderSidebarAgent(snapshot) {
  const a = snapshot.agent || {};
  const normalized = normalizeAgentState(a.state, a.details);
  const sessionCount = snapshot.sessionCount ?? (a.details || normalized);
  const label = a.label || 'David';
  const stateText = a.state || normalized;
  const detailsText = `${label} • ${sessionCount} sessions`;
  if (els.sidebarAgentState) els.sidebarAgentState.textContent = stateText;
  if (els.sidebarAgentDetails) els.sidebarAgentDetails.textContent = detailsText;
  drawSidebarSprite(normalized, a.frame || 0);
}

const SIDEBAR_COLORS = {
  o: '#f4c75c', h: '#ede6d4', s: '#b0a98c', e: '#7a6f5a',
  m: '#f4c75c', x: '#ede6d4', j: '#c9a96e', b: '#4a5568',
  t: '#ede6d4', p: '#3a5a40', g: '#67fb7f', r: '#ff7171',
  w: '#ffffff', d: '#9ca3af', '-': 'transparent',
};

function drawSidebarSprite(stateName, frameIdx) {
  const canvas = els.sidebarAgentSprite;
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  ctx.imageSmoothingEnabled = false;
  const frames = spriteFrames[stateName] || spriteFrames.idle;
  const frame = frames[frameIdx % frames.length];
  const pw = 18, ph = 18, scale = 3;
  canvas.width = pw * scale;
  canvas.height = ph * scale;
  ctx.fillStyle = '#0e121b';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  for (let row = 0; row < frame.length; row++) {
    const line = frame[row] || '';
    for (let col = 0; col < line.length; col++) {
      const ch = line[col];
      const color = SIDEBAR_COLORS[ch] || null;
      if (!color) continue;
      ctx.fillStyle = color;
      ctx.fillRect(col * scale, row * scale, scale, scale);
    }
  }
}

function renderSessions(snapshot) {
  // Sessions rendered from /api/sessions polling (limit 10)
  if (!els.sessionsList) return;
  const sessions = Array.isArray(snapshot.sessions) ? snapshot.sessions : [];
  if (!sessions.length) {
    els.sessionsList.innerHTML = '<div class="list-item"><span class="bullet" style="background: var(--amber);"></span><div class="item-text">No sessions found<span class="meta">run hermes sessions list</span></div></div>';
    return;
  }
  els.sessionsList.innerHTML = sessions.map((item) => {
    const title = escapeHtml(item.title || '—');
    const preview = escapeHtml(item.preview || '—');
    const lastActive = escapeHtml(item.lastActive || '—');
    const id = escapeHtml(item.id || '—');
    return `<div class="list-item">
      <span class="bullet"></span>
      <div class="item-text">${title}<span class="meta">${preview} • ${lastActive} • ${id}</span></div>
    </div>`;
  }).join('');
}

async function pollSidebarSessions() {
  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) return;
    const data = await res.json();
    // Merge sessions into current snapshot without replacing the whole thing
    if (state.snapshot) {
      state.snapshot.sessions = data.sessions;
    }
    renderSessions(state.snapshot || { sessions: data.sessions });
  } catch {}
}

function startSessionsPoller(intervalMs = 10_000) {
  stopSessionsPoller();
  pollSidebarSessions();
  state.sessionsPoller = setInterval(pollSidebarSessions, intervalMs);
}

function stopSessionsPoller() {
  if (state.sessionsPoller) {
    clearInterval(state.sessionsPoller);
    state.sessionsPoller = null;
  }
}

function renderQuickActions(snapshot) {
  els.quickActions.innerHTML = '';
  (snapshot.quickActions || []).forEach((action) => {
    const btn = document.createElement('button');
    btn.className = 'chip';
    btn.textContent = action.cmd;
    btn.title = action.desc;
    btn.addEventListener('click', () => {
      els.terminalInput.value = action.cmd;
      els.terminalInput.focus();
    });
    els.quickActions.appendChild(btn);
  });
}

function renderSystem(snapshot) {
  const s = snapshot.system;
  const memPct = s.memory?.percent ?? 0;
  const diskPct = s.disk?.percent ?? 0;
  els.systemPanel.innerHTML = `
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-label">CPU load</div><div class="stat-value">${(s.load?.[0] || 0).toFixed(2)}</div><div class="stat-note">${s.cpuCores} cores • ${snapshot.agent.state}</div></div>
      <div class="stat-card"><div class="stat-label">Memory</div><div class="stat-value">${memPct}%</div><div class="stat-note">${fmtBytes(s.memory?.used || 0)} / ${fmtBytes(s.memory?.total || 0)}</div><div class="progress"><span style="width:${memPct}%"></span></div></div>
      <div class="stat-card"><div class="stat-label">Disk</div><div class="stat-value">${diskPct}%</div><div class="stat-note">${fmtBytes(s.disk?.used || 0)} used</div><div class="progress"><span style="width:${diskPct}%"></span></div></div>
      <div class="stat-card"><div class="stat-label">Uptime</div><div class="stat-value">${formatUptime(s.uptime || 0)}</div><div class="stat-note">${escapeHtml(s.host)}</div></div>
      <div class="stat-card full-span"><div class="stat-label">Runtime</div><div class="stat-note">${escapeHtml(s.platform || '')}</div></div>
    </div>`;
  els.loadLabel.textContent = `${(s.load?.[0] || 0).toFixed(2)} load`;
}

function formatUptime(seconds) {
  const s = Math.floor(seconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return `${h}h ${m}m ${sec}s`;
}

function renderCron(snapshot) {
  const jobs = Array.isArray(snapshot.cronJobs) ? snapshot.cronJobs : [];
  if (!jobs.length) {
    els.cronPanel.innerHTML = '<div class="list-item"><span class="bullet" style="background: var(--amber);"></span><div class="item-text">No scheduled jobs<span class="meta">run hermes cron list</span></div></div>';
    return;
  }
  els.cronPanel.innerHTML = `<div class="job-list">${jobs.map((job) => `
    <div class="job-row">
      <div class="left">
        <div class="title">${escapeHtml(job.name)}</div>
        <div class="sub">schedule: ${escapeHtml(job.schedule || 'n/a')} • next: ${fmtTime(job.nextRun)} • last: ${job.lastRun ? fmtTime(job.lastRun) : 'never'}</div>
        <div class="sub">${escapeHtml(job.source || 'local')}</div>
      </div>
      <div class="value"><span class="badge ${job.status === 'ACTIVE' ? 'green' : 'amber'}">${job.status}</span></div>
    </div>
  `).join('')}</div>`;
}

function renderTokens(snapshot) {
  const t = snapshot.tokens || {};
  const u = snapshot.usage || {};
  const recentKinds = u.recentKinds || {};
  const kindLine = Object.entries(recentKinds).slice(0, 4).map(([kind, count]) => `${kind}:${count}`).join(' • ') || 'none';
  els.tokensPanel.innerHTML = `<div class="metric-list">
    <div class="metric-row"><div class="left"><div class="title">Total tokens</div><div class="sub">estimated from live sessions</div></div><div class="value">${t.totalTokens ?? 0}</div></div>
    <div class="metric-row"><div class="left"><div class="title">Prompt / completion</div><div class="sub">current mix</div></div><div class="value">${t.promptTokens ?? 0} / ${t.completionTokens ?? 0}</div></div>
    <div class="metric-row"><div class="left"><div class="title">Sessions / messages</div><div class="sub">active dashboard state</div></div><div class="value">${u.sessionCount ?? 0} / ${u.messageCount ?? 0}</div></div>
    <div class="metric-row"><div class="left"><div class="title">Events / cron / roots</div><div class="sub">usage snapshot</div></div><div class="value">${u.eventCount ?? 0} / ${u.cronCount ?? 0} / ${u.rootCount ?? 0}</div></div>
    <div class="metric-row full-span"><div class="left"><div class="title">Recent activity</div><div class="sub">${escapeHtml(kindLine)}</div></div><div class="value">${escapeHtml(u.lastEvent?.kind || 'none')}</div></div>
    ${(t.modelBreakdown || []).map((m) => `<div class="metric-row"><div class="left"><div class="title">${escapeHtml(m.model)}</div><div class="sub">model bucket</div></div><div class="value">${m.tokens}</div></div>`).join('')}
  </div>`;
  els.tokenProvider.textContent = u.generatedAt ? 'usage' : 'router';
}

function renderBackground() {
  els.backgroundPanel.innerHTML = `<div class="process-list">
    ${[
      { name: 'hermes-control', status: 'running', cpu: '3.1%', mem: '184 MB', note: 'dashboard runtime' },
      { name: 'ws-bus', status: 'running', cpu: '0.8%', mem: '24 MB', note: 'live snapshot bus' },
      { name: 'cron-worker', status: 'active', cpu: '0.5%', mem: '18 MB', note: 'scheduler loop' },
    ].map((p) => `<div class="process-row"><div class="left"><div class="title">${escapeHtml(p.name)}</div><div class="sub">${escapeHtml(p.note)}</div></div><div class="value">${p.status} • ${p.mem} • ${p.cpu} cpu</div></div>`).join('')}
  </div>`;
}

function markdownToHtml(md) {
  const lines = String(md || '').split('\n');
  let html = '';
  let inPre = false;
  for (const line of lines) {
    if (line.startsWith('```')) {
      inPre = !inPre;
      html += inPre ? '<pre>' : '</pre>';
      continue;
    }
    if (inPre) {
      html += escapeHtml(line) + '\n';
      continue;
    }
    if (/^#\s+/.test(line)) html += `<h1>${escapeHtml(line.slice(2))}</h1>`;
    else if (/^##\s+/.test(line)) html += `<h2>${escapeHtml(line.slice(3))}</h2>`;
    else if (/^###\s+/.test(line)) html += `<h3>${escapeHtml(line.slice(4))}</h3>`;
    else if (/^-\s+/.test(line)) html += `<ul><li>${escapeHtml(line.slice(2))}</li></ul>`;
    else if (!line.trim()) html += '<p></p>';
    else html += `<p>${escapeHtml(line)}</p>`;
  }
  return html.replace(/<\/ul><ul>/g, '');
}

const asciiDavidFrames = {
  idle: [
    [
      `      .-^^^^-.      `,
      `     /  .--.  \     `,
      `    /  (o  o)  \    `,
      `   |     __     |    `,
      `   |    (__)    |    `,
      `    \   .--.   /    `,
      `     \__/  \__/     `,
      `      /|    |\      `,
      `     /_|____|_\     `,
      `        ||||         `,
      `      __||||__       `,
      `     /_/    \_\      `,
    ],
    [
      `      .-^^^^-.      `,
      `     /  .--.  \     `,
      `    /  (o  o)  \    `,
      `   |     __     |    `,
      `   |    (__)    |    `,
      `    \   '--'   /    `,
      `     \__/  \__/     `,
      `      /|    |\      `,
      `     /_|____|_\     `,
      `        ||||         `,
      `      __||||__       `,
      `     /_/    \_\      `,
    ],
  ],
  thinking: [
    [
      `      .-^^^^-.      `,
      `     /  .--.  \     `,
      `    /  (o  o)  \    `,
      `   |     __     |    `,
      `   |   __(  )__ |    `,
      `    \   /____\  /   `,
      `     \__/  __\__/   `,
      `      /|  /\  |\    `,
      `     /_|_/  \_|_\   `,
      `        ||  ||       `,
      `      __||||__       `,
      `     /_/    \_\      `,
    ],
    [
      `      .-^^^^-.      `,
      `     /  .--.  \     `,
      `    /  (o  o)  \    `,
      `   |     __     |    `,
      `   |   __(  )__ |    `,
      `    \   \____/  /   `,
      `     \__/  __\__/   `,
      `      /| /\  |\    `,
      `     /_|____|_\     `,
      `        ||  ||       `,
      `      __||||__       `,
      `     /_/    \_\      `,
    ],
  ],
  error: [
    [
      `      .-^^^^-.      `,
      `     /  xx xx  \     `,
      `    /  (  !!  )  \   `,
      `   |    .----.    |  `,
      `   |   / FAIL \   |  `,
      `    \  | ERROR |  /  `,
      `     \_\______/__/   `,
      `      /| /\  /\ |\   `,
      `     /_|_\__/__\_|_\  `,
      `        ||!!||        `,
      `      __||!!||__      `,
      `     /_/  !!  \_\     `,
    ],
    [
      `      .-^^^^-.      `,
      `     /  xx xx  \     `,
      `    /  (  !!  )  \   `,
      `   |    .----.    |  `,
      `   |   / FAIL \   |  `,
      `    \  |  !   |  /  `,
      `     \_\______/__/   `,
      `      /| /\  /\ |\   `,
      `     /_|_\__/__\_|_\  `,
      `        ||!!||        `,
      `      __||!!||__      `,
      `     /_/  !!  \_\     `,
    ],
  ],
};

function ensureAvatarCanvas() {
  if (state.avatarCanvas) return state.avatarCanvas;
  const canvas = document.createElement('canvas');
  canvas.className = 'avatar-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  els.sprite.innerHTML = '';
  els.sprite.appendChild(canvas);
  state.avatarCanvas = canvas;
  state.avatarCtx = canvas.getContext('2d', { alpha: false });
  return canvas;
}

function loadAvatarImage(src) {
  if (!src) return;
  if (state.avatarSource === src && state.avatarImage) return;
  state.avatarSource = src;
  const img = new Image();
  img.decoding = 'async';
  img.onload = () => {
    state.avatarImage = img;
    paintSprite(state.avatarState || 'idle', state.spriteTick);
  };
  img.onerror = () => {
    state.avatarImage = null;
  };
  img.src = src;
}

function paintSprite(stateName, frameIndex) {
  state.avatarState = stateName || 'idle';
  const src = state.snapshot?.avatar?.src || state.avatarSource;
  if (src) loadAvatarImage(src);
  const canvas = ensureAvatarCanvas();
  const ctx = state.avatarCtx || canvas.getContext('2d', { alpha: false });
  state.avatarCtx = ctx;

  const image = state.avatarImage;
  const baseWidth = state.avatarState === 'error' ? 34 : state.avatarState === 'thinking' ? 38 : 42;
  const wobble = frameIndex % 2;
  const lowW = baseWidth + wobble;

  if (!image) {
    canvas.width = 42;
    canvas.height = 42;
    canvas.style.width = 'min(100%, 220px)';
    canvas.style.height = 'auto';
    ctx.imageSmoothingEnabled = false;
    ctx.fillStyle = '#0e121b';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#f4c75c';
    ctx.fillRect(9, 10, 24, 22);
    ctx.fillStyle = '#ede6d4';
    ctx.fillRect(13, 16, 4, 4);
    ctx.fillRect(25, 16, 4, 4);
    ctx.fillStyle = '#000';
    ctx.fillRect(12, 24, 18, 2);
    return;
  }

  const ratio = image.height / image.width || 1;
  const lowH = Math.max(1, Math.round(lowW * ratio));
  canvas.width = lowW;
  canvas.height = lowH;
  canvas.style.width = 'min(100%, 220px)';
  canvas.style.height = 'auto';
  ctx.imageSmoothingEnabled = false;
  ctx.clearRect(0, 0, lowW, lowH);
  ctx.drawImage(image, 0, 0, lowW, lowH);

  if (state.avatarState === 'thinking') {
    ctx.fillStyle = 'rgba(244, 199, 92, 0.06)';
    ctx.fillRect(0, 0, lowW, lowH);
  } else if (state.avatarState === 'error') {
    ctx.fillStyle = 'rgba(255, 113, 113, 0.08)';
    ctx.fillRect(0, 0, lowW, lowH);
  }
}

function normalizeAgentState(rawState, details = '') {
  const state = String(rawState || details || 'idle').toLowerCase();
  if (state.includes('error') || state.includes('fail') || state.includes('halt') || state.includes('panic')) return 'error';
  if (state.includes('think') || state.includes('exec') || state.includes('run') || state.includes('work') || state.includes('busy') || state.includes('coding')) return 'thinking';
  return 'idle';
}

function renderKnowledge(snapshot) {
  els.markdownView.innerHTML = markdownToHtml(snapshot.knowledge || '');
  els.eventsCount.textContent = `${snapshot.logs?.length || 0} events`;
}

function renderAgent(snapshot) {
  const a = snapshot.agent || {};
  const normalized = normalizeAgentState(a.state, a.details);
  const sessionCount = snapshot.sessionCount ?? (a.details || normalized);
  els.agentStateLabel.textContent = a.state || normalized;
  els.agentDetails.textContent = `${a.label || 'David'} • ${sessionCount} sessions`;
  paintSprite(normalized, a.frame || 0);
}

function renderTreeRoots(snapshot) {
  const roots = Array.isArray(snapshot.explorerRoots) ? snapshot.explorerRoots : [];
  if (!els.explorerRoots) return;
  if (!roots.some((root) => state.expandedRoots.has(root.key))) {
    state.expandedRoots = new Set(roots.map((root) => root.key));
  }
  els.explorerRoots.innerHTML = '';

  if (!roots.length) {
    els.explorerRoots.innerHTML = '<div class="small-meta">No explorer roots configured</div>';
    return;
  }

  roots.forEach((root) => {
    const block = document.createElement('section');
    block.className = `root-block${state.expandedRoots.has(root.key) ? '' : ' collapsed'}`;
    block.dataset.rootKey = root.key;

    const head = document.createElement('button');
    head.type = 'button';
    head.className = 'root-head';
    head.innerHTML = `<span>${escapeHtml(root.label || root.root || root.key)}</span><span class="root-state">${state.expandedRoots.has(root.key) ? 'collapse' : 'expand'}</span>`;
    head.addEventListener('click', () => {
      if (state.expandedRoots.has(root.key)) state.expandedRoots.delete(root.key);
      else state.expandedRoots.add(root.key);
      renderTreeRoots(state.snapshot || snapshot);
    });

    const tree = document.createElement('div');
    tree.className = 'tree';
    tree.dataset.rootKey = root.key;

    const renderNode = (node, depth = 0) => {
      const isDir = node.type === 'dir';
      const row = document.createElement('button');
      row.type = 'button';
      row.className = `tree-row ${isDir ? 'dir' : 'file'}${state.currentFile === node.path ? ' active' : ''}`;
      row.style.marginLeft = `${depth * 12}px`;
      row.dataset.path = node.path;
      row.innerHTML = isDir
        ? `<span class="tree-chevron">${state.expandedDirs.has(node.path) ? '▾' : '▸'}</span><span>${escapeHtml(node.name)}</span>`
        : `<span class="tree-chevron">•</span><span>${escapeHtml(node.name)}</span>`;
      row.addEventListener('click', async () => {
        if (isDir) {
          if (state.expandedDirs.has(node.path)) state.expandedDirs.delete(node.path);
          else state.expandedDirs.add(node.path);
          renderTreeRoots(state.snapshot || snapshot);
          return;
        }
        await openFile(node.path);
      });

      const frag = document.createDocumentFragment();
      frag.appendChild(row);
      if (isDir && state.expandedDirs.has(node.path) && Array.isArray(node.children) && node.children.length) {
        const childWrap = document.createElement('div');
        childWrap.className = 'tree-children';
        node.children.forEach((child) => childWrap.appendChild(renderNode(child, depth + 1)));
        frag.appendChild(childWrap);
      }
      return frag;
    };

    (root.children || []).forEach((child) => tree.appendChild(renderNode(child, 0)));
    block.appendChild(head);
    block.appendChild(tree);
    els.explorerRoots.appendChild(block);
  });
}

async function openFile(filePath) {

  state.currentFile = filePath;
  state.dirty = false;
  els.fileStatus.textContent = 'loading';
  els.editorMeta.textContent = 'reading file';
  els.editorPath.textContent = filePath;
  try {
    const res = await fetch(`/api/file?path=${encodeURIComponent(filePath)}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'file read failed');
    els.editor.value = data.content || '';
    els.fileStatus.textContent = 'ready';
    els.editorMeta.textContent = `${(data.content || '').split('\n').length} lines`;
  } catch (error) {
    els.fileStatus.textContent = 'error';
    els.editorMeta.textContent = error.message;
    els.editor.value = '';
  }
}

async function saveCurrentFile() {
  if (!state.currentFile) return;
  try {
    const res = await fetch('/api/file', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: state.currentFile, content: els.editor.value }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'save failed');
    state.dirty = false;
    els.fileStatus.textContent = 'saved';
    els.editorMeta.textContent = `${(els.editor.value || '').split('\n').length} lines`;
  } catch (error) {
    els.fileStatus.textContent = 'error';
    els.editorMeta.textContent = error.message;
  }
}

async function fetchSession() {
  const res = await fetch('/api/session');
  return res.json();
}

async function login(password) {
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'login failed');
  return data;
}

async function logout() {
  stopSessionsPoller();
  await fetch('/api/logout', { method: 'POST' }).catch(() => {});
  if (state.socket) {
    try { state.socket.close(); } catch {}
    state.socket = null;
  }
  setLocked(true);
}

function setLocked(locked) {
  els.overlay.classList.toggle('hidden', !locked);
  els.shell.classList.toggle('locked', locked);
}

function renderSnapshot(snapshot) {
  if (!els.topbar?.textContent) return; // Defensive: DOM not ready
  state.snapshot = snapshot;
  document.title = `Hermes Control Interface • ${snapshot.agent?.state || 'idle'}`;
  if (els.statusPill) {
    els.statusPill.textContent = snapshot.authed ? 'LIVE' : 'LOCKED';
    els.statusPill.className = `pill ${snapshot.authed ? 'good' : 'warn'}`;
  }
  if (els.modelPill) els.modelPill.textContent = snapshot.configSummary?.defaultModel || snapshot.models?.[0]?.value || 'model';
  if (els.statePill) {
    els.statePill.textContent = snapshot.agent?.state || 'idle';
    els.statePill.className = 'pill warn';
  }
  if (els.busState) {
    els.busState.textContent = snapshot.authed ? 'ws' : 'locked';
    els.busState.style.color = snapshot.authed ? 'var(--green)' : 'var(--amber)';
  }
  if (els.terminalLabel) els.terminalLabel.textContent = snapshot.loginIdentity || 'root@hermes';
  if (els.terminalPrompt) els.terminalPrompt.textContent = snapshot.terminal?.prompt || `${snapshot.loginIdentity || 'root@hermes'}:${snapshot.terminal?.cwd || snapshot.workingDir || '/'}#`;

  renderSidebarAgent(snapshot);
  renderQuickActions(snapshot);
  renderSystem(snapshot);
  renderCron(snapshot);
  renderTokens(snapshot);
  renderBackground(snapshot);
  renderAgent(snapshot);
  renderKnowledge(snapshot);
  renderTreeRoots(snapshot);
  if (!state.terminal) renderTerminalBuffer(snapshot.terminal);
}

async function fetchSnapshot() {
  const res = await fetch('/api/dashboard-state');
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'snapshot failed');
  renderSnapshot(data);
  return data;
}

function connectWs() {
  if (state.socket && (state.socket.readyState === WebSocket.OPEN || state.socket.readyState === WebSocket.CONNECTING)) return;
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${protocol}//${location.host}/ws`);
  state.socket = socket;
  socket.addEventListener('message', (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'snapshot') renderSnapshot(data.payload);
      if (data.type === 'terminal-transcript') {
        renderTerminalBuffer(data);
        state.lastTerminalBufferLength = String(data.buffer || '').length;
      }
      if (data.type === 'terminal-output') {
        appendTerminalChunk(data.chunk || '');
        state.lastTerminalBufferLength = String(data.buffer || '').length || state.lastTerminalBufferLength;
      }
    } catch {}
  });
  socket.addEventListener('close', () => {
    if (state.socket === socket) state.socket = null;
  });
}

function normalizeQuotedText(text) {
  const value = String(text || '').trim();
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

async function postJson(url, body, method = 'POST') {
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `request failed: ${url}`);
  return data;
}

const LAYOUT_STORAGE_KEY = 'hermes-control-layout-v1';

function getPanelLayout() {
  return $$('.panel').map((panel) => ({
    id: panel.dataset.panelId,
    x: Number(panel.dataset.x || '0'),
    y: Number(panel.dataset.y || '0'),
    w: Number(panel.dataset.w || '0'),
    h: Number(panel.dataset.h || '0'),
  })).filter((item) => item.id);
}

function applySavedLayout(layout) {
  const byId = new Map($$('.panel').map((panel) => [panel.dataset.panelId, panel]));
  const panels = Array.isArray(layout) ? layout : layout?.panels;
  if (!Array.isArray(panels) || !panels.length) return false;
  let applied = false;
  panels.forEach((item) => {
    const panel = byId.get(item.id);
    if (!panel) return;
    const x = Number(item.x);
    const y = Number(item.y);
    const w = Number(item.w);
    const h = Number(item.h);
    if (![x, y, w, h].every((n) => Number.isFinite(n))) return;
    panel.dataset.x = String(x);
    panel.dataset.y = String(y);
    panel.dataset.w = String(w);
    panel.dataset.h = String(h);
    applied = true;
  });
  return applied;
}

async function loadLayoutState() {
  try {
    const stored = localStorage.getItem(LAYOUT_STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      applySavedLayout(parsed);
    }
  } catch {}

  try {
    const res = await fetch('/api/layout');
    const data = await res.json();
    if (res.ok && data?.layout) {
      applySavedLayout(data.layout);
      try { localStorage.setItem(LAYOUT_STORAGE_KEY, JSON.stringify(data.layout)); } catch {}
      window.dispatchEvent(new Event('resize'));
    }
  } catch {}
}

async function saveLayoutState() {
  const layout = { panels: getPanelLayout() };
  const res = await fetch('/api/layout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(layout),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'layout save failed');
  try { localStorage.setItem(LAYOUT_STORAGE_KEY, JSON.stringify(data.layout || layout)); } catch {}
  return data.layout || layout;
}

function setLayoutEditMode(enabled) {
  state.layoutEditMode = Boolean(enabled);
  document.body.classList.toggle('layout-edit-mode', state.layoutEditMode);
  if (els.layoutEditBtn) {
    els.layoutEditBtn.textContent = state.layoutEditMode ? 'done editing' : 'edit layout';
  }
  if (els.layoutSaveBtn) {
    els.layoutSaveBtn.disabled = !state.layoutEditMode;
  }
}

async function handleCronSlashCommand(trimmed) {
  const match = trimmed.match(/^\/cron\s+(\w+)\s*(.*)$/i);
  if (!match) return false;
  const action = match[1].toLowerCase();
  const tail = match[2] || '';

  if (action === 'add') {
    const addMatch = tail.match(/^(\S+)\s+(.+)$/);
    if (!addMatch) throw new Error('usage: /cron add <schedule> <note>');
    const schedule = addMatch[1];
    const note = normalizeQuotedText(addMatch[2]);
    await postJson('/api/cron/add', { schedule, note, source: '/cron add' });
    addLine(`cron added: ${schedule} ${note}`, 'green');
    await fetchSnapshot();
    return true;
  }

  if (action === 'list') {
    await fetchSnapshot();
    addLine('cron list refreshed', 'system');
    return true;
  }

  if (action === 'remove' || action === 'pause' || action === 'resume') {
    const id = normalizeQuotedText(tail);
    if (!id) throw new Error(`usage: /cron ${action} <id>`);
    await postJson(`/api/cron/${action}`, { id });
    addLine(`cron ${action}d: ${id}`, 'green');
    await fetchSnapshot();
    return true;
  }

  throw new Error(`unsupported cron action: ${action}`);
}

async function runTerminalCommand(command) {
  const trimmed = String(command || '').trim();
  if (!trimmed) return;
  try {
    if (trimmed.startsWith('/cron ')) {
      await handleCronSlashCommand(trimmed);
      return;
    }
    if (state.socket?.readyState === WebSocket.OPEN) {
      state.socket.send(JSON.stringify({ type: 'terminal-input', data: `${trimmed}\r` }));
      return;
    }
    const res = await fetch('/api/terminal/exec', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: trimmed }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'terminal input failed');
    if (data.buffer && data.buffer.length > state.lastTerminalBufferLength) {
      appendTerminalChunk(data.buffer.slice(state.lastTerminalBufferLength));
      state.lastTerminalBufferLength = data.buffer.length;
    }
  } catch (error) {
    addLine(`error: ${error.message}`, 'red');
  }
}

async function uploadAvatarFile(file) {
  if (!file) return;
  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(new Error('failed to read image'));
    reader.readAsDataURL(file);
  });
  await postJson('/api/avatar', { dataUrl });
  await fetchSnapshot();
}


function initDragResize() {
  const panels = Array.from(document.querySelectorAll('.panel'));
  const workspace = $('#workspace');

  const applyLayout = () => {
    if (window.matchMedia('(max-width: 1200px)').matches || state.terminalFullscreen || state.explorerFullscreen || !workspace) return;
    const rect = workspace.getBoundingClientRect();
    panels.forEach((panel) => {
      const x = Number(panel.dataset.x || '0');
      const y = Number(panel.dataset.y || '0');
      const w = Number(panel.dataset.w || '30');
      const h = Number(panel.dataset.h || '30');
      panel.style.position = 'absolute';
      panel.style.left = `${Math.max(0, (x / 100) * rect.width)}px`;
      panel.style.top = `${Math.max(0, (y / 100) * rect.height)}px`;
      panel.style.width = `${Math.max(260, (w / 100) * rect.width)}px`;
      panel.style.height = `${Math.max(190, (h / 100) * rect.height)}px`;
    });
  };

  const updateFromPixels = (panel) => {
    const rect = workspace.getBoundingClientRect();
    panel.dataset.x = ((parseFloat(panel.style.left || '0') / rect.width) * 100).toFixed(2);
    panel.dataset.y = ((parseFloat(panel.style.top || '0') / rect.height) * 100).toFixed(2);
    panel.dataset.w = ((parseFloat(panel.style.width || '0') / rect.width) * 100).toFixed(2);
    panel.dataset.h = ((parseFloat(panel.style.height || '0') / rect.height) * 100).toFixed(2);
  };

  panels.forEach((panel) => {
    const handle = panel.querySelector('.drag-handle');
    const resize = panel.querySelector('.resize-handle');

    handle?.addEventListener('pointerdown', (ev) => {
      if (!state.layoutEditMode || window.matchMedia('(max-width: 1200px)').matches || state.terminalFullscreen || state.explorerFullscreen) return;
      ev.preventDefault();
      panel.classList.add('dragging');
      const startX = ev.clientX;
      const startY = ev.clientY;
      const startLeft = parseFloat(panel.style.left || '0');
      const startTop = parseFloat(panel.style.top || '0');
      const onMove = (move) => {
        panel.style.left = `${Math.max(0, startLeft + (move.clientX - startX))}px`;
        panel.style.top = `${Math.max(0, startTop + (move.clientY - startY))}px`;
      };
      const onUp = () => {
        document.removeEventListener('pointermove', onMove);
        document.removeEventListener('pointerup', onUp);
        panel.classList.remove('dragging');
        updateFromPixels(panel);
      };
      document.addEventListener('pointermove', onMove);
      document.addEventListener('pointerup', onUp);
    });

    resize?.addEventListener('pointerdown', (ev) => {
      if (!state.layoutEditMode || window.matchMedia('(max-width: 1200px)').matches || state.terminalFullscreen || state.explorerFullscreen) return;
      ev.preventDefault();
      ev.stopPropagation();
      panel.classList.add('resizing');
      const startX = ev.clientX;
      const startY = ev.clientY;
      const startWidth = parseFloat(panel.style.width || '0');
      const startHeight = parseFloat(panel.style.height || '0');
      const onMove = (move) => {
        panel.style.width = `${Math.max(260, startWidth + (move.clientX - startX))}px`;
        panel.style.height = `${Math.max(190, startHeight + (move.clientY - startY))}px`;
      };
      const onUp = () => {
        document.removeEventListener('pointermove', onMove);
        document.removeEventListener('pointerup', onUp);
        panel.classList.remove('resizing');
        updateFromPixels(panel);
      };
      document.addEventListener('pointermove', onMove);
      document.addEventListener('pointerup', onUp);
    });
  });

  window.addEventListener('resize', applyLayout);
  applyLayout();
}

function bindUi() {



  els.refreshBtn.addEventListener('click', fetchSnapshot);
  els.layoutEditBtn?.addEventListener('click', () => setLayoutEditMode(!state.layoutEditMode));
  els.layoutSaveBtn?.addEventListener('click', async () => {
    try {
      await saveLayoutState();
      addLine('layout saved', 'green');
      setLayoutEditMode(false);
    } catch (error) {
      addLine(`layout save failed: ${error.message}`, 'red');
    }
  });
  els.logoutBtn.addEventListener('click', logout);
  els.terminalFullscreenBtn?.addEventListener('click', () => setTerminalFullscreen(!state.terminalFullscreen));
  els.explorerFullscreenBtn?.addEventListener('click', () => setExplorerFullscreen(!state.explorerFullscreen));
  window.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') {
      if (state.terminalFullscreen) setTerminalFullscreen(false);
      if (state.explorerFullscreen) setExplorerFullscreen(false);
    }
  });
  window.addEventListener('resize', syncTopbarOffset);
  window.visualViewport?.addEventListener('resize', syncTopbarOffset);

  els.loginForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    els.loginError.textContent = '';
    try {
      await login(els.passwordInput.value.trim());
      els.passwordInput.value = '';
      setLocked(false);
      connectWs();
      await loadLayoutState();
      await fetchSnapshot();
    } catch (error) {
      els.loginError.textContent = error.message;
    }
  });

  els.terminalForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const command = els.terminalInput.value.trim();
    if (!command) return;
    els.terminalInput.value = '';
    await runTerminalCommand(command);
  });

  els.saveBtn.addEventListener('click', saveCurrentFile);
  els.avatarUploadBtn?.addEventListener('click', () => els.avatarFileInput?.click());
  els.avatarResetBtn?.addEventListener('click', async () => {
    await postJson('/api/avatar', {}, 'DELETE');
    await fetchSnapshot();
  });
  els.avatarFileInput?.addEventListener('change', async () => {
    const file = els.avatarFileInput.files?.[0];
    if (!file) return;
    try {
      await uploadAvatarFile(file);
      els.avatarFileInput.value = '';
    } catch (error) {
      addLine(`avatar upload failed: ${error.message}`, 'red');
    }
  });
  els.editor.addEventListener('input', () => {
    if (!state.currentFile) return;
    state.dirty = true;
    els.fileStatus.textContent = 'edited';
    els.editorMeta.textContent = 'unsaved changes';
  });

  els.editor.addEventListener('keydown', (ev) => {
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 's') {
      ev.preventDefault();
      saveCurrentFile();
    }
  });

  $$('[data-root-toggle]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const rootKey = btn.dataset.rootToggle;
      if (state.expandedRoots.has(rootKey)) state.expandedRoots.delete(rootKey);
      else state.expandedRoots.add(rootKey);
      const block = btn.closest('.root-block');
      block.classList.toggle('collapsed', !state.expandedRoots.has(rootKey));
      btn.querySelector('.root-state').textContent = state.expandedRoots.has(rootKey) ? 'collapse' : 'expand';
    });
  });
}

function startClock() {
  const tick = () => {
    const now = new Date();
    els.clock.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };
  tick();
  state.clockTimer = setInterval(tick, 1000);
}

function startSpriteLoop() {
  setInterval(() => {
    if (!state.snapshot) return;
    paintSprite(normalizeAgentState(state.snapshot.agent?.state, state.snapshot.agent?.details), state.spriteTick++ % 2);
  }, 520);
}

async function boot() {
  syncTopbarOffset();
  setLayoutEditMode(false);
  bootTerminal();
  bindUi();
  initDragResize();
  startClock();
  startSpriteLoop();

  const session = await fetchSession();
  if (session.authenticated) {
    setLocked(false);
    connectWs();
    await loadLayoutState();
    await fetchSnapshot();
    startSessionsPoller();
  } else {
    setLocked(true);
  }
}

boot();
