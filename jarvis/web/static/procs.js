// ARGUS-INSTINCT live process map: the page. It wires three modules together:
//
//   procs-state.js  the live table from /api/procs/stream (web/procview.py):
//                   births, exits, short-lived starts, verdicts, missing
//   procs-model.js  the lens rules: name against the scan baseline
//                   (/api/procs/baseline), image identity from the daemon
//                   (web/procidentity.py), combined into alarm and notice
//   procs-scene.js  the three.js scene
//
// This file owns the DOM: the sources and tallies, the change list, the top
// CPU and memory lists, the hover card, search, and the render loop.
import { CHANGE_TEXT, REASONS, describeIdent, hostReady, norm } from '/static/procs-model.js';
import { HOSTS, ProcState } from '/static/procs-state.js';
import { ProcScene, esc } from '/static/procs-scene.js';

const STALE_MS = 3000;                 // no frame for this long: the page itself says stale
const BASELINE_MS = 5 * 60 * 1000;     // the server caches it for as long
const PANEL_MS = 1000;                 // lists and tallies: once a second, or on change
const PANEL_MIN_MS = 250;              // and never more than four times a second
const LIST_N = 8;
const HOST_NAME = { win: 'Windows', lin: 'Linux (WSL)' };

const $ = (id) => document.getElementById(id);
const state = new ProcState();
const scene = new ProcScene($('scene'), $('labels'), state);
let lastFrame = 0, panelsAt = 0, baselineAt = 0;

// ---- feed ------------------------------------------------------------------------

function connect() {
  const es = new EventSource('/api/procs/stream');
  es.onmessage = (m) => {
    let f;
    try { f = JSON.parse(m.data); } catch { return; }
    lastFrame = performance.now();
    state.apply(f);
    if (f.k === 'status') renderSources();
    scene.wake();
  };
  es.onerror = () => setSync('down', 'The live stream is closed; reconnecting.');
}

async function loadBaseline() {
  baselineAt = performance.now();
  let doc;
  try {
    const r = await fetch('/api/procs/baseline', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    doc = await r.json();
  } catch (e) {
    doc = { ok: false, reason: 'baseline not reachable (' + (e.message || e) + ')', hosts: {}, watch: {} };
  }
  state.setBaseline(doc);
  scene.wake();
  renderLensState();
}

// ---- sync state ------------------------------------------------------------------

function renderSources() {
  const html = [];
  let live = 0, down = 0, present = 0;
  for (const h of HOSTS) {
    const s = state.sources[h];
    if (!s || s.state === 'absent') continue;
    present++;
    if (s.state === 'live') live++;
    if (s.state === 'stale' || s.state === 'unavailable') down++;
    const age = s.age_s == null ? '' : s.age_s < 1 ? '<1 s' : s.age_s.toFixed(1) + ' s';
    const detail = s.state === 'live' ? startsText(s.events) : esc(s.reason || '');
    html.push(`<div class="src" data-state="${esc(s.state)}"><i></i><span>${HOST_NAME[h]}</span>`
      + `<b class="num">${esc(s.state)}${age ? ' · ' + age : ''}</b>${detail ? `<small>${detail}</small>` : ''}</div>`);
  }
  $('sources').innerHTML = html.join('');
  const sync = !present ? 'connecting' : down && !live ? 'down' : down ? 'stale' : live === present ? 'live' : 'connecting';
  setSync(sync, down ? 'A process feed is not current; what you see is frozen at its last report.' : '');
  renderLensState();
}

function startsText(events) {
  if (events === 'sysmon') return 'Every start seen as it happens (Sysmon)';
  if (!events) return 'Starts seen every 500 ms only';
  return 'Short-lived starts: ' + esc(events);
}

function setSync(sync, text) {
  if (document.body.dataset.sync === sync) return;
  document.body.dataset.sync = sync;
  $('banner-title').textContent = sync === 'down' ? 'Not live' : 'Connecting…';
  $('banner-text').textContent = text || '';
  scene.wake();
}

function renderLensState() {
  const b = state.baseline;
  const label = (h) => (h === 'win' ? 'Windows' : 'Linux');
  const parts = [];
  if (!b) parts.push('Loading the baseline…');
  else if (!b.ok) parts.push(`${b.reason || 'Baseline unavailable'}. Names are shown as unknown, never as new.`);
  else parts.push('Compared with what ARGUS-INSTINCT has recorded: ' + HOSTS.map((h) => (hostReady(b, h)
    ? `${label(h)} ${b.hosts[h].rows} names` : `${label(h)}: no baseline yet`)).join(' · ') + '.');
  const id = state.identity;
  if (!id || !id.on) parts.push('Image identity is not checked.');
  else if (id.baseline === 'unavailable') parts.push(`Image identity unavailable: ${id.reason || 'no baseline'}.`);
  else if (id.queued) parts.push(`Checking ${id.queued} image${id.queued === 1 ? '' : 's'}…`);
  else parts.push('Paths and binaries checked against their history.');
  $('lens-state').textContent = parts.join(' ');
}

// ---- panels ----------------------------------------------------------------------

function renderPanels(now) {
  const since = now - panelsAt;
  if (since < PANEL_MIN_MS || (since < PANEL_MS && !state.changed)) return;
  panelsAt = now;
  state.changed = false;
  const t = state.tally();
  const shown = (h) => state.sources[h] && state.sources[h].state !== 'absent';
  $('n-win').textContent = shown('win') ? t.win : '–';
  $('n-lin').textContent = shown('lin') ? t.lin : '–';
  const short = state.shortLived;
  $('n-short').textContent = short.win + short.lin;
  $('n-short').title = `Windows ${short.win} · Linux ${short.lin}: started and ended between two 500 ms looks`;
  const judged = HOSTS.some((h) => hostReady(state.baseline, h)) || !!(state.identity && state.identity.on);
  $('n-alarm').textContent = judged ? t.alarm : '–';
  $('n-notice').textContent = judged ? t.notice : '–';
  $('n-missing').textContent = t.missing;
  const alive = state.alive();
  const row = (p, v) => `<button class="row" data-id="${esc(p.id)}" data-level="${p.level}">`
    + `<span>${esc(p.name)} <small class="num">${p.pid}</small></span><em class="num">${v}</em></button>`;
  $('top-cpu').innerHTML = alive.sort((a, b) => b.cpu - a.cpu).slice(0, LIST_N).map((p) => row(p, p.cpu.toFixed(1) + '%')).join('');
  $('top-mem').innerHTML = alive.sort((a, b) => b.rss - a.rss).slice(0, LIST_N).map((p) => row(p, fmtMem(p.rss))).join('');
  renderChanges();
}

function renderChanges() {
  const time = (ms) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  $('changes').innerHTML = state.changes.length ? state.changes.slice(0, 40).map((c) => {
    const why = c.reason ? REASONS[c.reason] + ' · ' : '';
    return `<button class="row change" data-k="${c.k}"${c.id ? ` data-id="${esc(c.id)}"` : ''}>`
      + `<span>${esc(c.name)}${c.count > 1 ? ` <small class="num">×${c.count}</small>` : ''}</span><em class="num">${time(c.at)}</em>`
      + `<small>${why}${CHANGE_TEXT[c.k]} · ${c.h === 'win' ? 'Windows' : 'Linux'}</small></button>`;
  }).join('') : '<div class="empty">Nothing has changed since you opened this view.</div>';
}

function showCard(p, x, y) {
  const card = $('card');
  if (!p) { card.style.display = 'none'; return; }
  const parent = scene.parentOf(p);
  const rows = [
    ['Domain', HOST_NAME[p.h]],
    ['PID', `<span class="num">${p.pid}</span>`],
    ['Parent', parent ? `${esc(parent.name)} <span class="num">${parent.pid}</span>` : `<span class="num">${p.ppid}</span> (exited)`],
    ...(p.h === 'win' ? [['Session', `<span class="num">${esc(p.session)}</span>`]] : []),
    ['CPU', `<span class="num">${p.cpu.toFixed(1)}%</span> of machine`],
    ['Memory', `<span class="num">${fmtMem(p.rss)}</span>`],
    ['Started', fmtAge(p.created) + ' ago'],
    ['Name', baselineText(p)],
    ...describeIdent(p.h, p.ident).map(([k, v]) => [k, esc(v)]),
  ];
  const why = p.reason ? `<div class="why" data-level="${p.level}">${esc(REASONS[p.reason])}</div>` : '';
  card.innerHTML = `<b>${esc(p.name)}</b>${why}<dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  card.style.display = 'block';
  card.style.left = Math.min(innerWidth - card.offsetWidth - 12, x + 16) + 'px';
  card.style.top = Math.min(innerHeight - card.offsetHeight - 12, y + 16) + 'px';
}

function baselineText(p) {
  const b = state.baseline;
  if (!hostReady(b, p.h)) return 'no baseline for this host';
  const row = b.hosts[p.h].names[norm(p.name)];
  if (!row) return 'never seen on this machine';
  const first = new Date(row[0] * 1000).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' });
  return `first seen ${esc(first)}${row[3] ? ' · approved' : ''}`;
}

const fmtMem = (kb) => (kb >= 1048576 ? (kb / 1048576).toFixed(1) + ' GB' : kb >= 1024 ? Math.round(kb / 1024) + ' MB' : kb + ' KB');
function fmtAge(ms) {
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 90) return Math.round(s) + ' s';
  if (s < 5400) return Math.round(s / 60) + ' min';
  return s < 172800 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + ' d';
}

// ---- input -----------------------------------------------------------------------

scene.bindInput((p) => { scene.focused = p; if (p) scene.focus(p); }, showCard);
$('lists').addEventListener('click', (e) => {
  const b = e.target.closest('.row');
  const p = b && state.procs.get(b.dataset.id);
  if (p) scene.focus(p);
});
$('find').addEventListener('input', (e) => { scene.query = e.target.value.trim().toLowerCase(); scene.wake(); });
$('only-changes').addEventListener('change', (e) => { scene.onlyChanges = e.target.checked; scene.wake(); });
addEventListener('keydown', (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || '');
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === 'f' || e.key === 'F') scene.fit();
  else if (e.key === 'Escape') { scene.focused = null; scene.wake(); }
  else if (!scene.key(e)) return;
  e.preventDefault();
});
// The scene is centred between the side panels when they are shown.
function fitPanels() {
  const shown = (el) => el && getComputedStyle(el).display !== 'none';
  const left = shown($('head')) ? $('head').getBoundingClientRect().right : 0;
  const right = shown($('lists')) ? innerWidth - $('lists').getBoundingClientRect().left : 0;
  scene.setInsets(left, right);
}
addEventListener('resize', fitPanels);
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => scene.readPalette());

// ---- theme: the dashboard's switch (same key), system setting by default -------------

const THEME_KEY = 'jarvis.theme', THEMES = ['auto', 'light', 'dark'];
function readTheme() {
  const forced = new URLSearchParams(location.hash.slice(1)).get('theme');
  if (THEMES.includes(forced)) return forced;
  try { return localStorage.getItem(THEME_KEY) || 'auto'; } catch { return 'auto'; }
}
function applyTheme(t) {
  if (!THEMES.includes(t)) t = 'auto';
  if (t === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
  $('theme').textContent = t === 'auto' ? 'Auto theme' : t === 'light' ? 'Light' : 'Dark';
  $('theme').dataset.t = t;
  scene.readPalette();
}
$('theme').addEventListener('click', () => {
  const t = THEMES[(THEMES.indexOf($('theme').dataset.t) + 1) % THEMES.length];
  try { localStorage.setItem(THEME_KEY, t); } catch { /* storage may be blocked */ }
  applyTheme(t);
});
applyTheme(readTheme());
// Capture and measurement only: the scene's draw-call and frame-time readout.
if (/(^|[#&])debug(=|&|$)/.test(location.hash)) window.procsDebug = { scene, state };

// ---- loop: render only when something moved ------------------------------------------

let last = performance.now();
function loop(now) {
  const dt = Math.min(0.1, (now - last) / 1000);
  last = now;
  state.settleStarts(now);
  if (lastFrame && now - lastFrame > STALE_MS) {
    setSync(document.body.dataset.sync === 'connecting' ? 'connecting' : 'stale',
      `No update from ARGUS-INSTINCT for ${Math.round((now - lastFrame) / 1000)} s; the map is frozen.`);
  }
  const live = document.body.dataset.sync === 'live';
  scene.pulses(now, live);
  scene.frame(now, dt, live);
  renderPanels(now);
  if (now - baselineAt > BASELINE_MS) loadBaseline();
  requestAnimationFrame(loop);
}

fitPanels();
loadBaseline();
connect();
requestAnimationFrame(loop);
