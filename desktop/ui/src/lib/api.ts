// The one place the interface reaches ARGUS-INSTINCT.
//
// Inside the desktop app every call is a typed Tauri command (desktop/src/api.rs):
// the page has no network permission of its own and never sees the API token.
// Served by the daemon itself (http://127.0.0.1:PORT/) the same calls go to the
// daemon's own routes with fetch, same origin; the browser sends the token
// cookie the daemon issued with the page. Either way the screens are identical.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { shapeCoverage, shapeGeo, shapePhoneDevices, shapeProcs, shapeState, shapeWorld } from "./shape";
import { brandDeep } from "./brand";
import { validLicencePage } from "./licence";

export const inApp = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

type Args = Record<string, any>;
type Route = { method: "GET" | "POST"; path: string; body?: unknown };

/** Tauri command -> daemon route, for the browser. */
export const ROUTES: Record<string, (a: Args) => Route> = {
  daemon_state: () => ({ method: "GET", path: "/api/state" }),
  run_collector: (a) => ({ method: "POST", path: `/api/run?job=${encodeURIComponent(a.job)}`, body: {} }),
  answer_question: (a) => ({ method: "POST", path: "/api/answer", body: { id: a.id, choice: a.choice } }),
  ask_jarvis: (a) => ({ method: "POST", path: "/api/ask", body: { question: a.question, level: a.level, lang: a.lang } }),
  score_coach: () => ({ method: "POST", path: "/api/score-coach", body: {} }),
  decide_fix: (a) => ({ method: "POST", path: `/api/fix/${a.decision}`, body: { id: a.id, reason: a.reason ?? "" } }),
  // Licences and purchases: the hosted claim flow (jarvis/web/licenceapi.py), the same in the
  // app and in a browser. No route here ever carries a payment secret.
  licence_state: () => ({ method: "GET", path: "/api/licence" }),
  licence_action: (a) => ({ method: "POST", path: `/api/licence/${encodeURIComponent(String(a.action))}`,
                            body: { key: a.key ?? "", plan: a.plan, ...(a.promo ? { promo: a.promo } : {}) } }),
  autopilot_status: () => ({ method: "GET", path: "/api/autopilot" }),
  autopilot_decide: (a) => ({ method: "POST", path: "/api/autopilot/decide", body: { key: a.key, choice: a.choice } }),
  autopilot_policy: (a) => ({ method: "POST", path: "/api/autopilot/policy", body: { auto_handle: a.autoHandle } }),
  pause_monitoring: (a) => ({ method: "POST", path: "/api/pause", body: { minutes: a.minutes } }),
  resume_monitoring: () => ({ method: "POST", path: "/api/resume", body: {} }),
  protection_status: () => ({ method: "GET", path: "/api/protection" }),
  protection_scan: () => ({ method: "POST", path: "/api/protection/scan", body: {} }),
  geo_state: () => ({ method: "GET", path: "/api/geo" }),
  coverage_state: () => ({ method: "GET", path: "/api/coverage" }),
  world_state: () => ({ method: "GET", path: "/api/world" }),
  procs_baseline: () => ({ method: "GET", path: "/api/procs/baseline" }),
  phone_status: () => ({ method: "GET", path: "/api/phone/status" }),
  phone_devices: () => ({ method: "GET", path: "/api/phone/devices" }),
  phone_pair_current: () => ({ method: "GET", path: "/api/phone/pair" }),
  phone_pair_start: () => ({ method: "POST", path: "/api/phone/pair/start", body: {} }),
  phone_pair_poll: (a) => ({ method: "POST", path: "/api/phone/pair/poll", body: { session: a.session } }),
  phone_pair_confirm: (a) => ({ method: "POST", path: "/api/phone/pair/confirm", body: { session: a.session, sas: a.sas, same: a.same } }),
  phone_pair_cancel: (a) => ({ method: "POST", path: "/api/phone/pair/cancel", body: { session: a.session } }),
  phone_revoke: (a) => ({ method: "POST", path: "/api/phone/revoke", body: { device: a.device } }),
  phone_test: () => ({ method: "POST", path: "/api/phone/test", body: {} }),
};

/** The daemon pages that open as their own full views. A fixed list. */
export const PAGES: Record<string, string> = { dashboard: "/ui/", coverage: "/coverage", world: "/world", procs: "/procs", geo: "/geo", classic: "/classic" };

async function http<T>(cmd: string, args: Args = {}): Promise<T> {
  if (cmd === "open_page") { window.open(PAGES[args.page] ?? "/", "_blank", "noopener"); return { ok: true } as T; }
  if (cmd === "procs_snapshot") return procsSnapshotHttp() as Promise<T>;
  if (cmd === "open_licence_page") return openLicencePageHttp(args.url) as Promise<T>;
  const route = ROUTES[cmd]?.(args);
  if (!route) throw new Error("This action is only available in the ARGUS-INSTINCT app.");
  const res = await fetch(route.path, {
    method: route.method,
    credentials: "same-origin",
    headers: route.body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: route.body !== undefined ? JSON.stringify(route.body) : undefined,
  });
  const data = await res.json().catch(() => null);
  // An unpaired browser gets 403 naming the token: pair it, then come back here.
  if (res.status === 403 && /token/i.test(String(data?.error ?? ""))) {
    window.location.assign("/pair?next=" + encodeURIComponent(window.location.pathname + window.location.search));
  }
  if (!res.ok) throw new Error(data?.message ?? data?.error ?? `HTTP ${res.status}`);
  return data as T;
}

/** In a browser: the same allow-list as the app (desktop/src/api.rs), then a new tab. */
async function openLicencePageHttp(url: unknown): Promise<void> {
  if (typeof url !== "string" || !validLicencePage(url)) throw new Error("that page is not an Archymedes licence page");
  window.open(url, "_blank", "noopener");
}

async function call<T>(cmd: string, args?: Args): Promise<T> {
  // What is shown says ARGUS-INSTINCT (brand.ts); identity fields are kept.
  return brandDeep(await (inApp ? invoke<T>(cmd, args) : http<T>(cmd, args)));
}

/** One full picture of the process table: the first `snap` per host plus the latest status. */
async function procsSnapshotHttp(): Promise<ProcsSnapshot> {
  const out: ProcsSnapshot = { snaps: {}, status: null };
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 8000);
  try {
    const res = await fetch("/api/procs/stream", { signal: ctl.signal, credentials: "same-origin" });
    if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i: number;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const frame = buf.slice(0, i);
        buf = buf.slice(i + 2);
        const line = frame.split("\n").find((l) => l.startsWith("data:"));
        if (!line) continue;
        try {
          const v = JSON.parse(line.slice(5));
          if (v.k === "snap" && Array.isArray(v.p)) out.snaps[v.h] = v.p;
          else if (v.k === "status") out.status = v;
        } catch { /* a damaged frame is skipped */ }
      }
      if (out.snaps.win && out.status) { ctl.abort(); break; }
    }
  } catch (e) {
    if (!Object.keys(out.snaps).length) throw e;      // nothing read: a real failure
  } finally { clearTimeout(timer); }
  return out;
}

/** What the app knows about the daemon (desktop/src/lifecycle.rs): never "healthy" unless it is. */
export type BlindKind = "admin_sensor" | "failed" | "stale" | "other";
/** A collector the daemon reported blind, with its cause (desktop/src/lifecycle.rs Blind). */
export type BlindItem = { job: string; label: string; reason: string; kind: BlindKind };

export type AppStatus = {
  phase: "starting" | "live" | "degraded" | "not_installed" | "not_authorised" | "stopped";
  message: string;
  detail: string;
  /** Every blind collector, grouped by the interface; absent when none. */
  blind?: BlindItem[];
};

export type Reply = { ok?: boolean; message?: string; answer?: string; source?: string; queued?: boolean; paired_link?: boolean };

export type Protection = { available: boolean; level: "on" | "off" | "stale" | "unknown"; summary: string; signature_age_days?: number | null; last_quick_scan?: string };
export type AppSettings = { notify_findings: boolean; notify_health: boolean; notify_outage: boolean };
export type Case = { key: string; title: string; severity: string; count: number; what_happened: string; recommended: string; ai_note?: string; established: string[]; uncertain: string[] };
export type Autopilot = { needs_me: Case[]; policy?: { auto_handle: boolean; min_age_days: number }; handled: { investigated: number } };

export type Geo = {
  location?: { ts: number; status: string; lat?: number; lon?: number; accuracy_m?: number; source?: string; zone?: string };
  confidence?: { score: number; signals: any[] };
  zones: { id?: string; name: string; radius_m?: number; lat?: number; lon?: number }[];
  devices: { name: string; kind: string; trust: string; located: boolean; zone?: string }[];
  anomalies: any[];
  generated_at: number;
};
export type Technique = { tid: string; name: string; tactics: string[]; level: "validated" | "claimed" | "blind" | "regressed" | string; evidence?: any; ways?: any; sources?: any; uptime?: any };
export type Coverage = {
  at: number;
  totals: { validated: number; claimed: number; blind: number; regressed: number; total: number };
  tactics: Record<string, Record<string, number>>;
  techniques: Technique[];
  uptime?: { pct24: number; buckets: number[]; tracked: number; of: number };
  /** Argus's own detection gaps against current intel (the gaps job): about the tool, not this machine. */
  intel_gaps?: { state: string; ts: number | null; total: number;
                 items: { tid: string; name: string; kind: string; priority: string; detail: string }[] };
};
export type WorldItem = { id?: string; kind: string; src: string; source: string; title: string; summary?: string; url?: string; ts: number; lat?: number; lon?: number; place?: string; country?: string };
export type WorldZone = { id: string; name: string; country?: string; lat: number; lon: number; radius_km?: number; reports: number; sources: number; places?: string[]; last_24h: number; prior_24h: number };
export type World = {
  generated_at: number; age_s: number; stale: boolean; window_s: number;
  items: WorldItem[]; zones: WorldZone[];
  counts: { reports: number; mapped: number; unmapped: number; country_level: number };
  sources: { key: string; name: string; ok: number; reports: number; error?: string }[];
  rules?: { zone: string; note: string };
};
export type PhoneStatus = { relay: string; relay_error: string; crypto: boolean; crypto_error: string; identity: boolean; devices: number; pending: number; last_ok: number | null; last_error: string };
export type PhoneDevice = { dev: string; name: string; paired_at: number | null; revoked_at: number | null; pending: boolean };
export type PairState = "waiting" | "claimed" | "confirming" | "paired" | "rejected" | "expired" | "cancelled" | "error";
export type Pairing = { session: string; state: PairState; code: string; relay: string; expires: number; remaining: number; device?: string; name?: string; sas?: string; message?: string; notice?: string; warning?: boolean };
export type ProcsSnapshot = { snaps: Record<string, any[][]>; status: any };

export type UpdateInfo = { current: string; latest: string | null; newer: boolean; enabled: boolean; checked: number; error: string };

export const api = {
  state: () => call<unknown>("daemon_state").then(shapeState),
  status: () => call<AppStatus>("app_status"),
  runCollector: (job: string) => call<Reply>("run_collector", { job }),
  answer: (id: string, choice: "yes" | "no") => call<Reply>("answer_question", { id, choice }),
  ask: (question: string, level: "simple" | "expert" = "expert", lang = "en") => call<Reply>("ask_jarvis", { question, level, lang }),
  pause: (minutes: number) => call<Reply & { paused_until?: number }>("pause_monitoring", { minutes }),
  resume: () => call<Reply>("resume_monitoring"),
  protection: () => call<Protection>("protection_status"),
  scan: () => call<Reply & { started?: boolean }>("protection_scan"),
  getSettings: () => call<AppSettings>("get_settings"),
  setSettings: (settings: AppSettings) => call<AppSettings>("set_settings", { settings }),
  scoreCoach: () => call<Reply>("score_coach"),
  autopilot: () => call<Autopilot>("autopilot_status"),
  decideCase: (key: string, choice: "recognise" | "not_recognise" | "investigate_further") =>
    call<Reply>("autopilot_decide", { key, choice }),
  setAutoHandle: (on: boolean) => call<Reply>("autopilot_policy", { autoHandle: on }),
  decideFix: (id: string, decision: "approve" | "retry" | "reject", reason?: string) =>
    call<Reply>("decide_fix", { id, decision, reason }),
  geo: () => call<unknown>("geo_state").then(shapeGeo),
  coverage: () => call<unknown>("coverage_state").then(shapeCoverage),
  world: () => call<unknown>("world_state").then(shapeWorld),
  procsBaseline: () => call<any>("procs_baseline"),
  procsSnapshot: () => call<unknown>("procs_snapshot").then(shapeProcs),
  openPage: (page: keyof typeof PAGES) => call<Reply>("open_page", { page }),
  phoneStatus: () => call<PhoneStatus>("phone_status"),
  phoneDevices: () => call<unknown>("phone_devices").then(shapePhoneDevices),
  pairCurrent: () => call<{ pairing: Pairing | null }>("phone_pair_current"),
  pairStart: () => call<Pairing>("phone_pair_start"),
  pairPoll: (session: string) => call<Pairing>("phone_pair_poll", { session }),
  pairConfirm: (session: string, sas: string, same: boolean) => call<Pairing>("phone_pair_confirm", { session, sas, same }),
  pairCancel: (session: string) => call<Pairing>("phone_pair_cancel", { session }),
  phoneRevoke: (device: string) => call<Reply>("phone_revoke", { device }),
  phoneTest: () => call<Reply>("phone_test"),
  // Only inside the app: the page itself never reaches the network, and a browser has no build version to compare.
  checkUpdate: () => call<UpdateInfo>("check_update"),
  openDownloadPage: () => call<void>("open_download_page"),
  licence: () => call<LicenceState>("licence_state"),
  licenceAction: (action: "activate" | "deactivate" | "refresh" | "upgrade" | "poll", key?: string, plan?: "server" | "desktop" | "desktop-monthly",
                  promo?: string) =>
    call<LicenceReply>("licence_action", { action, key, plan, promo }),
  openLicencePage: (url: string) => call<void>("open_licence_page", { url }),
};

export type LicenceState = {
  licensed: boolean; reason: string; product?: string; plan?: "server" | "desktop"; label?: string; key_hint?: string;
  expires_at?: number | null; lease_until?: number; renew_after?: number; auto_renew?: boolean; renew_error?: string | null;
  needs_key?: boolean; needs_check?: boolean; purchase_waiting?: boolean;
  links: { buy_server: string; buy_desktop: string; manage: string; recover: string };
};
export type LicenceReply = { ok: boolean; code?: string; error?: string; open?: string; active?: boolean; state?: LicenceState;
  promo_sent?: boolean };

/** Pulses: from the shell's stream thread in the app, from the daemon's own
 *  stream in the browser. `down` when the daemon cannot be reached. */
export async function onDaemon(pulse: (p: unknown) => void, down: () => void): Promise<UnlistenFn> {
  if (inApp) {
    const a = await listen("pulse", (e) => pulse(brandDeep(e.payload)));
    const b = await listen("daemon-down", () => down());
    return () => { a(); b(); };
  }
  if (typeof EventSource === "undefined") return () => {};
  const es = new EventSource("/api/stream");
  es.addEventListener("pulse", (e) => { try { pulse(brandDeep(JSON.parse((e as MessageEvent).data))); } catch { pulse({}); } });
  es.onerror = () => down();
  return () => es.close();
}
