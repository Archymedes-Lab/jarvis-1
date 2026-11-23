// Application state. The daemon owns the truth; this holds the last copy the
// shell fetched and refreshes it when the pulse stream says something changed.
import { api, inApp, onDaemon, type Coverage, type UpdateInfo, type AppStatus, type PAGES } from "./api";
import { tr } from "./i18n";

export type View = "overview" | "findings" | "collectors" | "review" | "assistant" | "geo" | "coverage" | "world" | "procs" | "phone" | "pricing" | "licence" | "settings";
export type Mode = "simple" | "expert";
export type Theme = "auto" | "light" | "dark";

const THEME_KEY = "jarvis.theme";
const MODE_KEY = "jarvis.mode";
const LANG_KEY = "jarvis.lang";
const LANG_CODES = ["en", "fr", "de", "es", "zh", "ja", "ko", "pt", "hi", "ru", "ar"];
const RTL = ["ar"];

/** Language and reading direction go on <html>, so the whole page follows. */
function applyLang() {
  document.documentElement.setAttribute("lang", app.lang);
  document.documentElement.setAttribute("dir", RTL.includes(app.lang) ? "rtl" : "ltr");
}
const MIN_GAP_MS = 4000;       // pulses can arrive in bursts; one refetch covers them
const FALLBACK_MS = 60000;     // if the stream is quiet, still refresh once a minute

export const app = $state({
  data: null as any,
  coverage: null as Coverage | null,   // shared by the sidebar and the Coverage view
  casesWaiting: 0,                     // grouped cases that need a decision (sidebar badge)
  loading: false,
  error: "",
  daemon: "connecting" as "connecting" | "live" | "down",
  status: { phase: "starting", message: "Starting ARGUS-INSTINCT", detail: "" } as AppStatus,
  updatedAt: 0,
  update: null as UpdateInfo | null,
  updateChecking: false,
  view: "overview" as View,
  query: "",
  severity: null as string | null,
  host: "",
  job: "",
  selected: null as any,
  palette: false,
  theme: readTheme(),
  mode: readMode(),
  lang: readLang(),
  toasts: [] as Toast[],
});

function readTheme(): Theme {
  try { const t = localStorage.getItem(THEME_KEY); return t === "light" || t === "dark" ? t : "auto"; }
  catch { return "auto"; }
}

function readLang(): string {
  try {
    const saved = localStorage.getItem(LANG_KEY);
    if (saved && LANG_CODES.includes(saved)) return saved;
    // First run: follow the system language when it is one we have.
    const sys = (navigator.language || "en").slice(0, 2).toLowerCase();
    return LANG_CODES.includes(sys) ? sys : "en";
  } catch { return "en"; }
}

export function setLang(code: string) {
  if (!LANG_CODES.includes(code)) return;
  app.lang = code;
  try { localStorage.setItem(LANG_KEY, code); } catch { /* per-viewer convenience only */ }
  applyLang();
}

function readMode(): Mode {
  try { return localStorage.getItem(MODE_KEY) === "expert" ? "expert" : "simple"; }
  catch { return "simple"; }
}

export function applyMode() {
  document.documentElement.setAttribute("data-mode", app.mode);
}

export function setMode(m: Mode) {
  app.mode = m;
  applyMode();
  try { localStorage.setItem(MODE_KEY, m); } catch { /* per-viewer convenience only */ }
}

export function setTheme(t: Theme) {
  app.theme = t;
  try { localStorage.setItem(THEME_KEY, t); } catch { /* per-viewer convenience only */ }
  applyTheme();
}

export function applyTheme() {
  const root = document.documentElement;
  if (app.theme === "auto") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", app.theme);
}

/** The shell's own account of the daemon: running, degraded, stopped, not installed. */
export async function refreshStatus() {
  if (!inApp) {
    // Served by the daemon in a browser there is no shell to ask: the last state
    // call is the status. Without this the footer said "Starting" forever.
    app.status = app.daemon === "live"
      ? { phase: "live", message: "Watching", detail: "" }
      : { phase: "stopped", message: "Not answering", detail: app.error };
    return;
  }
  try { app.status = await api.status(); } catch { /* the shell is the source; keep the last */ }
}

let inFlight = false, last = 0, queued = 0 as any;

export async function refresh() {
  if (inFlight) return;
  inFlight = true; app.loading = true; last = Date.now();
  try {
    app.data = await api.state();
    app.error = ""; app.daemon = "live"; app.updatedAt = Date.now();
    await refreshStatus();
  } catch (e) {
    app.error = String((e as Error)?.message ?? e);
    app.daemon = "down";
    await refreshStatus();
  } finally {
    inFlight = false; app.loading = false;
  }
}

const COVERAGE_EVERY_MS = 120000;   // coverage moves slowly; the map costs the daemon a build
let coverageInFlight = false;

/** Coverage for the sidebar and the Coverage view; keeps the last answer on failure. */
export async function refreshCoverage() {
  if (coverageInFlight) return;
  coverageInFlight = true;
  try { app.coverage = await api.coverage(); }
  catch { /* keep the last map; the view says when it cannot read */ }
  try { app.casesWaiting = (await api.autopilot()).needs_me?.length ?? 0; }
  catch { /* older daemons have no cases */ }
  finally { coverageInFlight = false; }
}

const UPDATE_EVERY_MS = 6 * 3600 * 1000;       // the service caches its answer for as long

/** Ask whether a newer release is published. `loud` (a click) says the result; the quiet check does not. */
export async function checkUpdate(loud = false) {
  if (!inApp || app.updateChecking) return;
  app.updateChecking = true;
  try {
    app.update = await api.checkUpdate();
    if (loud) {
      const u = app.update;
      if (!u.enabled) toast(tr("Update checks are turned off on this computer."), "info");
      else if (u.error && !u.latest) toast(tr("Could not check for updates."), "bad");
      else if (u.newer) toast(tr("Version {v} is available.", { v: u.latest ?? "" }), "ok");
      else toast(tr("You have the latest version."), "ok");
    }
  } catch {
    if (loud) toast(tr("Could not check for updates."), "bad");
  } finally {
    app.updateChecking = false;
  }
}

function schedule() {
  const wait = Math.max(0, MIN_GAP_MS - (Date.now() - last));
  clearTimeout(queued);
  queued = setTimeout(refresh, wait);
}

export async function start() {
  applyLang();
  applyTheme();
  applyMode();
  await refresh();
  void refreshCoverage();
  setInterval(() => void refreshCoverage(), COVERAGE_EVERY_MS);
  void checkUpdate();
  setInterval(() => void checkUpdate(), UPDATE_EVERY_MS);
  await onDaemon(() => { refreshStatus(); schedule(); }, () => { app.daemon = "down"; refreshStatus(); });
  setInterval(() => { if (Date.now() - last > FALLBACK_MS) refresh(); }, 10000);
}

export type Toast = {
  id: number; text: string; tone: "ok" | "bad" | "info";
  /** Optional second line, quieter than the headline. */
  detail?: string;
  /** Optional single action, shown as a text button on the right. */
  action?: { label: string; run: () => void };
};
type ToastOpts = { detail?: string; action?: Toast["action"] };

let toastId = 0;
/** Show a small banner. The headline is one plain sentence; auto-dismiss is handled by the banner itself. */
export function toast(text: string, tone: Toast["tone"] = "info", opts: ToastOpts = {}) {
  const id = ++toastId;
  // Same message already showing: don't stack a duplicate.
  if (app.toasts.some((t) => t.text === text && t.tone === tone)) return;
  app.toasts = [...app.toasts.slice(-2), { id, text, tone, ...opts }];
}
export function dismissToast(id: number) {
  app.toasts = app.toasts.filter((t) => t.id !== id);
}

export function go(view: View, filters: Partial<{ severity: string | null; query: string; host: string; job: string }> = {}) {
  app.view = view;
  if ("severity" in filters) app.severity = filters.severity ?? null;
  if ("query" in filters) app.query = filters.query ?? "";
  if ("host" in filters) app.host = filters.host ?? "";
  if ("job" in filters) app.job = filters.job ?? "";
  app.selected = null;
}

/** Open a daemon page in the default browser. From the app the browser gets a
 *  one-time pairing link (desktop/src/api.rs open_page), so it never asks for a token. */
export async function openInBrowser(page: keyof typeof PAGES = "dashboard") {
  try {
    const r = await api.openPage(page);
    if (inApp) toast(r?.paired_link ? tr("Opening in your browser. It pairs by itself the first time.") : tr("Opening in your browser."), "ok");
  } catch (e) {
    toast(String((e as Error)?.message ?? e), "bad");
  }
}
