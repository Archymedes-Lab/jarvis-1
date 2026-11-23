"use strict";
const SEV = ["critical", "high", "medium", "low"];
let state = null, sevFilter = null, jobFilter = "", hostFilter = "",
    query = "", grouped = false, paused = false, tab = "peers",
    open = new Set(), timer = null, showHealthy = false, showAllQuestions = false,
    findingLimit = 80, lastFindingRender = "", tickPending = false;
const FINDING_BATCH = 80;

/* ---------- theme: explicit switch, system setting as the default ---------- */
const THEME_KEY = "jarvis.theme", THEMES = ["auto", "light", "dark"];
function readTheme() { try { return localStorage.getItem(THEME_KEY) || "auto"; } catch (_) { return "auto"; } }
function applyTheme(t) {
  if (!THEMES.includes(t)) t = "auto";
  if (t === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
  for (const b of document.querySelectorAll("#theme button"))
    b.className = b.dataset.t === t ? "on" : "";
}
function setTheme(t) {
  try { localStorage.setItem(THEME_KEY, t); } catch (_) {}
  applyTheme(t);
}
applyTheme(readTheme());

/* ---------- desktop notifications from this page ----------
   The daemon raises Windows toasts on its own for new criticals; this is the
   browser's channel, for the screen the dashboard is open on. Only criticals
   that are new since the page last saw them; the first render seeds the set. */
const SEEN_KEY = "jarvis.seenCriticals";
let seenCriticals = null;
function critKey(f) { return `${f.job}|${f.title}|${f.where || ""}`; }
function notifyOn() { return typeof Notification !== "undefined" && Notification.permission === "granted"; }
function renderNotifyButton() {
  const b = document.getElementById("notify");
  if (!b) return;
  if (typeof Notification === "undefined") { b.hidden = true; return; }
  b.className = "notify" + (notifyOn() ? " on" : "");
  b.textContent = notifyOn() ? "Notifications on" : Notification.permission === "denied" ? "Notifications blocked" : "Notify me";
}
async function toggleNotify() {
  if (typeof Notification === "undefined") return;
  if (Notification.permission !== "granted") {
    const p = await Notification.requestPermission();
    if (p === "granted") { toast("Critical findings will pop up on this computer while this page is open.", "good"); }
  } else {
    toast("Notifications stay on for this site; turn them off in the browser's site settings.", "");
  }
  renderNotifyButton();
}
function notifyCriticals(s) {
  const crit = (s.findings || []).filter(f => f.severity === "critical");
  const keys = new Set(crit.map(critKey));
  if (seenCriticals === null) {
    try { seenCriticals = new Set(JSON.parse(localStorage.getItem(SEEN_KEY) || "[]")); } catch (_) { seenCriticals = new Set(); }
    if (!seenCriticals.size) { seenCriticals = keys; }           // first visit: seed, never spam
  }
  const fresh = crit.filter(f => !seenCriticals.has(critKey(f)));
  for (const f of fresh.slice(0, 3)) {
    toast(`Critical: ${f.title}`, "warn", `${f.job} · ${f.host || ""}`);
    if (notifyOn()) {
      try { const n = new Notification("ARGUS-INSTINCT: " + brand(f.title).slice(0, 90),
              { body: `${f.job}: ${String(f.detail || "").slice(0, 160)}`, tag: critKey(f).slice(0, 120) });
            n.onclick = () => { window.focus(); setSev("critical"); jump("findings-section"); }; } catch (_) {}
    }
  }
  if (fresh.length > 3) toast(`${fresh.length - 3} more new critical findings`, "warn");
  if (fresh.length) {
    for (const k of keys) seenCriticals.add(k);
    try { localStorage.setItem(SEEN_KEY, JSON.stringify([...seenCriticals].slice(-500))); } catch (_) {}
  }
}
renderNotifyButton();


// brand:begin -- identical in every page; tests/test_ui_brand.py keeps the copies equal.
// The product is ARGUS-INSTINCT. Server text can still say JARVIS (finding titles keep their
// identity for acknowledgements and history), so it is re-branded at display time.
// Real Windows objects keep their spelling so they can be found in Task Scheduler
// and Services; lowercase commands (jarvis ..., jarvis.service) are never touched.
// Idempotent: a name already followed by -1 is left alone, so text that went
// through the rule twice, or a build that renames JARVIS to ARGUS, never reads ARGUS-INSTINCT-1.
const BRAND = "ARGUS-INSTINCT";
const BRAND_KEEP = /^ (input hook|independent health monitor|connectivity guard|native sensor|Jarvis)/;
const brand = (s) => String(s ?? "").replace(/\bJARVIS\b(?!-(?:1|INSTINCT)\b)/g,
  (m, i, all) => (BRAND_KEEP.test(all.slice(i + m.length)) ? m : BRAND));
// brand:end
// plain:begin -- pure helpers behind the beginner-facing views. No DOM access: tests/test_dashboard_shell.py
// runs exactly this block in node. Plain-language text is derived from the real finding (its title, detail and
// category); the category guidance below is general background and is always labelled as such.
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g, /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bAKIA[0-9A-Z]{12,}/g, /\bAIza[0-9A-Za-z_-]{20,}/g, /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]{8,}/gi,
];
const SECRET_ASSIGN = /\b([\w-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|recovery[_-]?code)[\w-]*)(\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;}]+)/gi;
const URL_CREDENTIAL = /\b([a-z][a-z0-9+.-]*:\/\/[^\s:\/@]+:)[^\s@\/]+@/gi;
function redact(text) {
  let t = String(text ?? "");
  for (const p of SECRET_PATTERNS) t = t.replace(p, "[hidden]");
  t = t.replace(URL_CREDENTIAL, "$1[hidden]@");
  return t.replace(SECRET_ASSIGN, (m, key, sep) => key + sep + "[hidden]");
}
function clip(text, n) { const t = redact(text).replace(/\s+/g, " ").trim(); return t.length > n ? t.slice(0, n - 1) + "…" : t; }
const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + "s"}`;

// Monitoring problems are about ARGUS-INSTINCT's own checks, not about the computer.
const MON_CATEGORIES = new Set(["daemon", "collectors", "visibility", "coverage", "model"]);
const MON_JOBS = new Set(["coverage", "watchdogs", "bridge", "model", "report"]);
// Categories where ARGUS-INSTINCT reads a setting or exposure directly (a fact, whose importance depends on the user).
const CONFIG_CATEGORIES = new Set(["rules", "remote", "internet", "posture", "malware defense", "defense",
                                   "mitigations", "byovd", "boot integrity", "extension"]);
function kindOf(f) { return MON_CATEGORIES.has(f.category) || MON_JOBS.has(f.job) ? "monitoring" : "security"; }

// -> {key, label, note}. ARGUS-INSTINCT never labels a finding a confirmed attack; it says what was observed.
function stateOf(f) {
  if (kindOf(f) === "monitoring")
    return { key: "monitoring", label: "A problem with ARGUS-INSTINCT",
             note: "This is about ARGUS-INSTINCT itself, not your computer. It does not mean anything bad has happened." };
  const sev = f.severity;
  if (sev !== "critical" && sev !== "high" && sev !== "medium")
    return { key: "info", label: "Just so you know", note: "Saved for your information. It does not lower your score." };
  if (CONFIG_CATEGORIES.has(f.category))
    return { key: "confirmed", label: "A setting on your computer",
             note: "ARGUS-INSTINCT looked at this setting directly. Whether it is a problem depends on how you use your computer." };
  return { key: "suspicious", label: "Worth a closer look",
           note: "ARGUS-INSTINCT noticed something unusual. It is not proven to be harmful, and it may be perfectly normal." };
}
// How a person should read each severity. Severity is potential impact, never a verdict or a likelihood.
const SEVERITY_WORDS = { critical: "Serious", high: "Serious", medium: "Worth a look", low: "Just so you know" };
const severityWord = sev => SEVERITY_WORDS[sev] || "Not rated";

// GUIDE[category] = [what it usually means, why it may matter, a safe next step]. General background only.
const GUIDE = {
  "data at rest": ["A file on your computer seems to have a password or secret key written inside it in plain text.",
    "If anyone else can open that file, they could use that password or key as if they were you.",
    "Open the file and see if you put it there on purpose. If it is a real password you still use, change it on the website or service it belongs to."],
  persistence: ["A program is set up to start by itself, for example every time you turn on your computer.",
    "Many normal apps do this, like updaters. But harmful programs also do this so they come back after a restart.",
    "Look at the name. If you recognise the app, you can ignore this. If you do not, do not delete anything yet. Ask someone you trust to check it."],
  staging: ["A new program file was just saved on your computer, and the computer cannot tell who made it.",
    "Programs you download or build yourself do this too. Bad programs can arrive the same way.",
    "Did you just download or install something? Then this is probably it. If not, ask someone you trust to take a look."],
  rules: ["Your computer has a rule that lets other devices talk to one of its programs.",
    "The more open the rule is, the easier it is for other devices on your network to reach that program.",
    "Look at which program it is. If you do not use it, ask someone you trust if the rule can be removed."],
  remote: ["Your computer is set up so someone can connect to it from far away and use it.",
    "If you did not turn this on, someone else could possibly get in.",
    "If you set this up yourself, you can ignore this. If not, ask someone you trust to check it soon."],
  access: ["An app is using, or is allowed to use, your camera or microphone.",
    "That is normal during a video call. It is unexpected if you are not on a call or recording.",
    "Check which app it is. If you did not start it, close it and ask someone you trust to look."],
  internet: ["A program on your computer is waiting for other devices to connect to it, or ARGUS-INSTINCT cannot fully watch your internet traffic.",
    "Programs that can be reached from outside are an easier target if they have a mistake in them.",
    "If you know this program and want it open, there is nothing to do. If not, ask someone you trust."],
  impersonation: ["Sign-ins you saved on this computer, like passwords kept in your browser, could be used to log in as you.",
    "Any program that runs on your account could use them.",
    "Remove saved sign-ins for accounts you no longer use."],
  accounts: ["A user account on this computer is hidden from the sign-in screen or looks unusual.",
    "Hidden accounts are sometimes used to keep access to a computer. Some apps also make them for normal reasons.",
    "Do not delete it. First find out which app made it, or ask someone you trust."],
  interception: ["Your computer trusts a security certificate that does not come from the usual list.",
    "A certificate like this can let its owner read private web traffic, such as sign-ins.",
    "Companies and some developer tools add these on purpose. If you do not know where it came from, ask someone you trust."],
  "injected code": ["A program has hidden instructions running in its memory that are not from a file on your computer.",
    "Browsers and game tools do this for normal reasons. Harmful programs also use it to hide.",
    "Check whether it is a program you know and use. If it is not, ask someone you trust."],
  clickfix: ["Your computer's history shows commands that look like they were copied from a website and pasted in.",
    "Fake \"fix this problem\" pages trick people into running a harmful command themselves.",
    "Think: did you paste a command from a website lately? If you did not, tell someone you trust right away."],
  av: ["Windows' built-in protection, called Defender, found something it did not like.",
    "Defender has already raised a flag, so it is worth a look.",
    "Open Windows Security to see what it found and what it already did about it."],
  posture: ["A protection feature in Windows is turned off, or ARGUS-INSTINCT could not read whether it is on.",
    "A protection that is off gives you less cover.",
    "Open the details to see which one. If you did not switch it off, turn it back on."],
  "malware defense": ["A feature that helps stop harmful programs is switched off.",
    "With it off, your computer has one fewer guard.",
    "Decide if you want it on. Most people do."],
  defense: ["ARGUS-INSTINCT could not check one of Windows' protection settings.",
    "ARGUS-INSTINCT cannot say whether that protection is working if it cannot read it.",
    "Open the details to see which one."],
  mitigations: ["A program is running without an extra safety feature that makes it harder to attack.",
    "If that program has a mistake in it, it would be easier to break into.",
    "You usually do not need to do anything. Keep the program up to date."],
  screen: ["An app may be able to record what is on your screen without showing you.",
    "A screen recording can capture anything you have open, like messages or passwords.",
    "Check whether you use a screen-sharing or recording app. If you do not, ask someone you trust."],
  extension: ["An add-on is installed in your web browser.",
    "Add-ons can see the web pages you visit, so each one has to be trusted.",
    "Keep only the add-ons you know. Remove the rest from your browser's add-ons page."],
  daemon: ["The part of ARGUS-INSTINCT that watches your computer is not running the way it should.",
    "ARGUS-INSTINCT cannot watch that part of your computer until it is fixed.",
    "Open the Monitoring page. It tells you why and how to fix it."],
  collectors: ["One of ARGUS-INSTINCT's checks could not finish.",
    "Until it does, ARGUS-INSTINCT cannot tell you whether that part of your computer is okay.",
    "Open the Monitoring page to see why."],
  visibility: ["ARGUS-INSTINCT can only see part of what is going on in one area of your computer.",
    "It cannot tell you about anything it cannot see.",
    "Open the Monitoring page to see what is hidden from it, and why."],
};
// Ordinary reasons the same observation can appear on a healthy computer. Offered as possibilities, never as a finding.
const BENIGN = {
  "data at rest": ["The text is an example, a placeholder or an expired key", "You stored it on purpose in a private project"],
  persistence: ["A program you installed (an updater, a driver tool) set it up", "Windows or a device maker created it for maintenance"],
  staging: ["An installer or developer tool just wrote it", "You built or downloaded something recently"],
  rules: ["Software you installed asked for network access", "A game, server or remote tool you use needs it"],
  remote: ["You turned on remote desktop, file sharing or a similar feature"],
  access: ["You are in a call, recording or using an app that needs the camera or microphone"],
  internet: ["A local server or development tool you run is listening"],
  impersonation: ["You saved sign-ins in Windows or a browser"],
  accounts: ["A service or sandbox tool created the account"],
  interception: ["Security, company or developer software installed the certificate"],
  "injected code": ["Browsers, game tools and developer tools legitimately create such memory"],
  clickfix: ["You ran those commands yourself"],
  av: ["It could be a false positive for a program you trust"],
  posture: ["The setting may be off by choice, or not supported on this computer"],
  extension: ["You installed it yourself"],
};
const DEFAULT_BENIGN = ["It may be software you installed, or a change you made yourself"];
const SEVERITY_WHY = {
  critical: "ARGUS-INSTINCT thinks this is very serious: if it is real, it could badly harm your computer or your files.",
  high: "ARGUS-INSTINCT thinks this is serious: it is worth looking at soon.",
  medium: "ARGUS-INSTINCT thinks this is worth a look, but it is rarely urgent.",
  low: "ARGUS-INSTINCT thinks this is minor. It is just so you know.",
};
// Short definitions shown on hover or keyboard focus. Terms are matched in static guidance text only.
const GLOSSARY = {
  WMI: "A built-in part of Windows that lets programs run things automatically when something happens.",
  persistence: "When a program is set up to start again by itself after a restart. Normal apps do this, and so do harmful ones.",
  "scheduled task": "A job that Windows runs by itself at set times.",
  "firewall rule": "A setting that decides which programs may talk to other devices over the network.",
  unsigned: "Missing the maker's digital signature, which is like a stamp showing who made it. Many tools you download have none, so it is a reason to look, not proof of harm.",
  collector: "One of ARGUS-INSTINCT's checks. Each one looks at one part of your computer.",
  credential: "A password or secret key that proves to a service that you are you.",
  certificate: "A digital ID card that a computer uses to prove who it is.",
  "process injection": "When one program hides instructions inside another program. Some normal software does this, and harmful programs use it to hide.",
  "privilege escalation": "When a program gets more power on your computer than it was given.",
};
// -> {means, why, next, general}. `general` is true when the wording is category background, not the finding itself.
function guideFor(f) {
  const g = GUIDE[f.category];
  if (g) return { means: g[0], why: g[1], next: g[2], general: true };
  if (kindOf(f) === "monitoring") return { means: GUIDE.collectors[0], why: GUIDE.collectors[1], next: GUIDE.collectors[2], general: true };
  return { means: "ARGUS-INSTINCT noticed something and wants you to know.", why: SEVERITY_WHY[f.severity] || "ARGUS-INSTINCT has not said how serious this is.",
           next: "Open the details and think about whether you expect this on your computer.", general: true };
}

// One sentence saying what ARGUS-INSTINCT found, in plain words, from the real title and category.
function whatWasFound(f) {
  const t = String(f.title || "").trim();
  if (/scheduled task/i.test(t)) return "ARGUS-INSTINCT found a program that is set to run by itself at certain times.";
  if (/WMI event subscription/i.test(t)) return "ARGUS-INSTINCT found a Windows rule that runs something automatically when a certain thing happens.";
  if (/unsigned executable/i.test(t)) return "ARGUS-INSTINCT found a new program with no maker's signature to prove who made it.";
  if (/api key|credential|password|secret|token/i.test(t) && f.category === "data at rest")
    return "ARGUS-INSTINCT found a file that seems to have a password or secret key inside it.";
  const by = { persistence: "something that starts by itself", rules: "a setting that lets other devices connect",
    remote: "a setting that lets someone connect to this computer from far away", access: "an app using your camera or microphone",
    internet: "a program that other devices can reach", accounts: "an unusual account", interception: "a security certificate your computer trusts that is not a usual one",
    "injected code": "a program running hidden instructions that are not from a file", posture: "a protection setting that is off or could not be checked" };
  return by[f.category] ? `ARGUS-INSTINCT found ${by[f.category]}.` : `ARGUS-INSTINCT reported “${clip(t, 90)}”.`;
}

// Qualitative evidence basis. ARGUS-INSTINCT has no per-finding confidence score, so none is invented: this lists what
// supports the finding on hand. `others` is the full findings list, used to count independent reporters.
function evidenceBasis(f, others) {
  const same = (others || []).filter(o => o.title === f.title && o.where === f.where && o.job !== f.job);
  const collectors = 1 + new Set(same.map(o => o.job)).size;
  const forensics = (f.forensics || []).length;
  const points = [`noticed by ${plural(collectors, "check")}`,
    forensics ? `${plural(forensics, "extra piece", "extra pieces")} of proof saved` : "no extra proof saved",
    f.where ? "ARGUS-INSTINCT saved where it was" : "ARGUS-INSTINCT did not save where it was"];
  const strength = collectors > 1 || forensics ? "More than one sign" : "Only one sign";
  return { level: "unscored", strength, points, collectors, forensics,
    text: `ARGUS-INSTINCT cannot say how sure it is about this kind of finding. What it has: ${points.join("; ")}. ` +
      "How serious it is shows how much harm it could do, not how likely it is to be real." };
}

// The seven-part explanation, from real fields only. Unknowns are listed, not filled in.
function explainFinding(f, others) {
  const gd = guideFor(f), st = stateOf(f), basis = evidenceBasis(f, others);
  const facts = [`Found by: ${f.job}`, f.host ? `Host: ${f.host}` : null, f.where ? `Location: ${clip(f.where, 140)}` : null,
                 f.detail ? `Detail: ${clip(f.detail, 200)}` : null].filter(Boolean);
  const unknown = ["Whether you installed it yourself or expected it", "Whether it is doing anything harmful right now"];
  if (!f.where) unknown.push("Exactly where it is (ARGUS-INSTINCT did not save a location)");
  return {
    what: whatWasFound(f), where: f.where ? clip(f.where, 300) : "", whereRaw: f.where ? redact(f.where) : "",
    why: gd.why, whyFlagged: `${gd.means} ARGUS-INSTINCT points this out because ${gd.why.charAt(0).toLowerCase() + gd.why.slice(1)}`,
    facts, risks: [gd.why], benign: BENIGN[f.category] || DEFAULT_BENIGN, unknown,
    confidence: basis, severity: severityWord(f.severity), state: st, next: gd.next,
    steps: ["Read what ARGUS-INSTINCT saw, and where.", "Ask the assistant to explain it, or think about whether it matches an app you know.",
            gd.next, "Do not delete or turn off anything until you understand what it is."],
  };
}

// One entry per distinct (collector, title); sorted most severe first, then most frequent.
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, ok: 4 };
function groupFindings(list) {
  const by = new Map();
  for (const f of list || []) {
    const k = f.job + "|" + f.title;
    const g = by.get(k) || { key: k, sample: f, count: 0, items: [] };
    g.count += 1; g.items.push(f);
    by.set(k, g);
  }
  return [...by.values()].sort((a, b) => (SEV_RANK[a.sample.severity] ?? 9) - (SEV_RANK[b.sample.severity] ?? 9) || b.count - a.count);
}

const DETECTOR_WORDS = {
  never_ran: "has not produced a result yet", stale: "has not reported fresh results", failing: "failed on its last run",
  malformed: "returned a result that could not be read", permission_restricted: "is not allowed to read something it needs",
  missing_dependency: "is missing a component it depends on", unsupported: "is not supported on this computer",
  late: "is running behind schedule",
};
// Monitoring health problems from the server's detector report, or from the collector list on older servers.
function monitoringProblems(s) {
  const dh = s.detector_health;
  if (dh && Array.isArray(dh.detectors)) {
    return dh.detectors.filter(d => d.state !== "healthy" && d.state !== "not_applicable").map(d => ({
      id: d.id, label: d.label || d.id, state: d.state, coverage: d.coverage, reason: d.reason, impact: d.impact,
      next: d.next_action, error: d.error || "", last: d.last_success, criticality: d.criticality || "medium",
      what: d.what || d.label || d.id, affects: d.affects_status || "", command: d.command || "" }));
  }
  return (s.jobs || []).filter(j => j.stale || j.error).map(j => ({
    id: j.name, label: j.label || j.name, state: j.error ? "failing" : "stale", coverage: "blind",
    reason: j.error ? "Its last run failed." : "It has not reported recently.",
    impact: "ARGUS-INSTINCT may be missing activity in this area.", next: "Open Monitoring for the reason.", error: j.error || "", last: j.ts,
    criticality: "medium", what: j.label || j.name, affects: "", command: "" }));
}
function monitoringTotals(s) {
  const dh = s.detector_health;
  if (dh && Array.isArray(dh.detectors)) {
    const c = dh.counts || {};
    return { total: dh.total || 0, verified: c.verified || 0, partial: c.partial || 0, blind: c.blind || 0,
             notApplicable: dh.detectors.filter(d => d.state === "not_applicable").length };
  }
  const jobs = s.jobs || [], bad = jobs.filter(j => j.stale || j.error).length;
  return { total: jobs.length, verified: jobs.length - bad, partial: 0, blind: bad, notApplicable: 0 };
}
// Plain explanation of one monitoring problem, from the detector report. Nothing is claimed beyond its fields.
function explainMonitor(p) {
  const said = `${p.what} ${DETECTOR_WORDS[p.state] || "is not reporting"}.`;
  return {
    headline: `${p.label} ${DETECTOR_WORDS[p.state] || "is not reporting"}`,
    checks: `${p.what}`, working: p.state === "healthy" ? "Yes" : "No",
    lastGood: p.last ? new Date(p.last * 1000).toLocaleString() : "never",
    unavailable: `${said} ARGUS-INSTINCT cannot confirm this area right now.`,
    caution: "The absence of alerts from this check does not mean that nothing suspicious is happening.",
    affects: p.affects || "Unknown: this server did not report how much the overall status depends on it.",
    next: [p.next, p.command ? `To audit the same area by hand, run: jarvis ${p.command}` : null].filter(Boolean),
  };
}

// Newest successful result across the detectors (or the collector list), and whether it is too old to trust.
const STALE_AFTER_S = 300;
function lastCheck(s, now) {
  now = now ?? Date.now() / 1000;
  const times = [];
  const dh = s.detector_health;
  if (dh && Array.isArray(dh.detectors)) for (const d of dh.detectors) if (d.last_success) times.push(d.last_success);
  if (!times.length) for (const j of s.jobs || []) if (j.ts && !j.error) times.push(j.ts);
  if (!times.length) return { ts: null, ageS: null, stale: true };
  const ts = Math.max(...times), ageS = Math.max(0, Math.round(now - ts));
  return { ts, ageS, stale: ageS > STALE_AFTER_S };
}
function ageWords(sec) {
  if (sec == null) return "never";
  if (sec < 60) return `${sec} seconds ago`;
  if (sec < 3600) return plural(Math.floor(sec / 60), "minute") + " ago";
  if (sec < 86400) return plural(Math.floor(sec / 3600), "hour") + " ago";
  return plural(Math.floor(sec / 86400), "day") + " ago";
}

// The Overview's headline. Every sentence is supported by the counts it carries; with no data it says so.
function overviewModel(s, now) {
  const sec = s.security || null, all = s.findings || [];
  const secGroups = groupFindings(all.filter(f => kindOf(f) === "security" && stateOf(f).key !== "info"));
  const infoGroups = groupFindings(all.filter(f => kindOf(f) === "security" && stateOf(f).key === "info"));
  const review = secGroups.filter(g => g.sample.severity === "critical" || g.sample.severity === "high");
  const problems = monitoringProblems(s), tot = monitoringTotals(s);
  const monFindings = groupFindings(all.filter(f => kindOf(f) === "monitoring" && f.severity !== "ok"));
  const unverified = problems.filter(p => p.state === "never_ran" || p.state === "stale" || p.state === "malformed").length;
  const counts = {
    confirmed: secGroups.filter(g => stateOf(g.sample).key === "confirmed").length,
    suspicious: secGroups.filter(g => stateOf(g.sample).key === "suspicious").length,
    monitoring: problems.length + monFindings.length,
    unverified, expected: (sec && sec.acknowledged) || 0,
    toReview: secGroups.length, serious: review.length, info: infoGroups.length,
    notReporting: problems.length, monitoringFindings: monFindings.length,
    total: secGroups.length + infoGroups.length,
  };
  const notReporting = problems.length, last = lastCheck(s, now);
  const changes = s.assistant && s.assistant.changes && s.assistant.changes.text ? s.assistant.changes.text : "";
  const monitoring = !tot.total ? "unknown" : tot.verified === 0 ? "down" : notReporting ? "partial" : "working";
  let level, headline, parts = [];
  if (!sec && !all.length && !tot.total) {
    level = "unknown"; headline = "Status not available yet";
    parts = ["ARGUS-INSTINCT has not received enough results to describe this computer. Wait a moment, or open Monitoring."];
  } else if (sec && sec.state === "verifying") {
    const pg = sec.progress || {};
    level = "info"; headline = "ARGUS-INSTINCT is re-checking its monitors";
    parts = [`It is re-checking after a gap (${pg.checked ?? "?"} of ${pg.total ?? "?"} reporting). The last fully verified score was ${sec.score}%.`];
  } else if (secGroups.length) {
    level = review.length ? "attention" : "review";
    headline = review.length ? "Needs attention" : "Review recommended";
    parts = [`ARGUS-INSTINCT found ${plural(secGroups.length, "item")} to review, including ${review.length} marked as serious. ` +
      "Some items may have legitimate explanations. These are observations, not confirmed attacks." +
      (infoGroups.length ? ` It also recorded ${plural(infoGroups.length, "informational observation")}.` : "")];
    if (notReporting) parts.push(`${plural(notReporting, "check")} ${notReporting === 1 ? "is" : "are"} also not reporting, so this picture may be incomplete.`);
  } else if (notReporting) {
    level = "incomplete"; headline = "Monitoring issue";
    parts = [`${tot.verified} of ${tot.total} checks are reporting. ARGUS-INSTINCT cannot confirm the other ${notReporting}, so having nothing to review does not mean those areas are fine.`];
  } else {
    level = "ok"; headline = "No issues found in the checks performed";
    parts = [`All ${tot.total} checks are reporting and none produced an item to review. This reflects only what ARGUS-INSTINCT can check.` +
      (infoGroups.length ? ` It recorded ${plural(infoGroups.length, "informational observation")}.` : "")];
  }
  if (changes && level !== "unknown" && level !== "info") parts.push(changes);
  const detail = parts.join(" ");
  let scoreLine = "";
  if (sec && sec.score != null) {
    scoreLine = `Security score ${sec.score}% (${sec.grade}).`;
    if (notReporting && !review.length) scoreLine += " Part of this reflects checks that are not reporting, not known problems.";
    else scoreLine += " Findings lower it; checks that are not reporting are never counted as safe.";
  }
  const lastLine = last.ts ? `Last successful check: ${ageWords(last.ageS)}.` + (last.stale ? " That is older than expected, so these results may be out of date." : "")
                           : "No check has completed yet.";
  const monLine = { working: "Monitoring is working: every check is reporting.",
    partial: `Monitoring is partly working: ${tot.verified} of ${tot.total} checks are reporting.`,
    down: "Monitoring is not working: no check is reporting a fresh result.", unknown: "Monitoring status is not available yet." }[monitoring];
  return { level, headline, detail, parts, scoreLine, counts, review, secGroups, infoGroups, problems, monFindings, totals: tot,
           last, lastLine, monitoring, monLine, changes };
}

// What to put under "What needs your attention": serious security items first, then monitoring problems.
function attentionItems(s, limit = 5) {
  const m = overviewModel(s), out = [];
  for (const g of m.secGroups) out.push({ kind: "finding", group: g, state: stateOf(g.sample) });
  const sev = out.filter(i => i.group.sample.severity === "critical" || i.group.sample.severity === "high");
  const rest = out.filter(i => !sev.includes(i));
  const mon = m.problems.slice().sort((a, b) => (a.coverage === "blind" ? 0 : 1) - (b.coverage === "blind" ? 0 : 1))
    .map(p => ({ kind: "monitor", problem: p, state: { key: p.state === "never_ran" || p.state === "stale" ? "unverified" : "monitoring",
      label: p.state === "never_ran" || p.state === "stale" ? "Not verified" : "A problem with ARGUS-INSTINCT",
      note: "This is about ARGUS-INSTINCT itself, not your computer. It does not mean anything bad has happened." } }));
  const items = [...sev.slice(0, limit), ...mon.slice(0, 2), ...rest];
  return { items: items.slice(0, limit), total: out.length + mon.length, model: m };
}

// The single next step, always pointing at a destination that exists.
function nextStep(s) {
  const m = overviewModel(s), q = (s.questions || []).length;
  const pend = (s.assistant && s.assistant.pending) || [];
  if (pend.length) return { text: "ARGUS-INSTINCT is waiting for your decision on a proposal. Nothing has happened yet, and you can decline.",
                            label: "Review the proposal", go: "assistant", act: "openproposal" };
  if (m.review.length) {
    const t = clip(m.review[0].sample.title, 80);
    return { text: `Start with "${t}". Open the details to see what ARGUS-INSTINCT observed, then decide whether you expect it.`,
             label: "Investigate", go: "security", act: "investigate", query: m.review[0].sample.title,
             id: m.review[0].sample.id || "", job: m.review[0].sample.job || "" };
  }
  if (m.problems.length)
    return { text: "Some checks are not reporting correctly. Open Monitoring to see which checks need attention and why.",
             label: "View monitoring status", go: "monitoring" };
  if (q) return { text: `ARGUS-INSTINCT has ${plural(q, "question")} waiting for you. Your answers help it judge what is normal here.`,
                  label: "Open review queue", go: "reviewqueue" };
  return { text: "Nothing needs you right now. ARGUS-INSTINCT keeps watching. You can ask the assistant anything.",
           label: "Ask the assistant", go: "assistant" };
}

// ---- approvals ------------------------------------------------------------
// The states a proposal can be in, in the words shown to people. "Completed" is only ever claimed from a result.
const LIFECYCLE = {
  awaiting_approval: ["Awaiting your approval", "Nothing has happened yet."],
  approved_queued: ["Approved and queued", "It has not run yet, so nothing is confirmed."],
  completed: ["Completed", "Confirmed by a fresh, valid result."],
  failed: ["Failed", "It did not produce a valid result. See the reason."],
  cancelled: ["Cancelled", "Nothing was changed."],
  expired: ["Expired", "Nothing was changed."],
  denied: ["Not accepted", "Nothing was changed."],
  already_used: ["Already used", "Each proposal works once. Nothing was changed."],
};
function lifecycleInfo(key) { const v = LIFECYCLE[key]; return v ? { key, label: v[0], note: v[1] } : null; }
// Fix-proposal statuses (response/selffix.py) in plain words. Applying a patch is never done from the page.
function fixStateOf(status) {
  const m = { proposed: ["awaiting_approval", "Awaiting your approval", "Nothing has happened yet."],
    approved: ["approved_queued", "Approved: draft being generated", "A draft is written; nothing is applied."],
    drafting: ["approved_queued", "Approved: draft being generated", "A draft is written; nothing is applied."],
    review: ["awaiting_approval", "Draft ready: awaiting your authorization", "Authorizing records intent only."],
    draft_failed: ["failed", "Draft failed", "No draft was produced. Nothing was changed."],
    apply_approved: ["approved_queued", "Authorized: not yet applied", "Applying needs the terminal command."],
    applied: ["completed", "Applied from the terminal", "Check the result before relying on it."],
    rejected: ["cancelled", "Rejected", "Nothing was applied."], expired: ["expired", "Expired", "Nothing was applied."],
    failed: ["failed", "Failed", "See the reason."], rolled_back: ["cancelled", "Rolled back", "The patch was reversed."] }[status];
  return m ? { key: m[0], label: m[1], note: m[2] } : { key: "denied", label: String(status || "unknown"), note: "State not recognised." };
}
const FIX_EXPIRY_DAYS = 14;
// -> the ten things a person needs before deciding. Built from the real proposal, never from defaults that could mislead.
function approvalSpecFromDetails(d) {
  return { id: d.token, kind: "assistant", title: d.title, proposes: d.proposes, why: d.why,
    target: d.target && d.target.label ? `${d.target.label} (${d.target.kind}: ${d.target.id})` : "",
    expected: d.expected, risks: d.risks, reversible: d.reversible, ifNothing: d.if_nothing, elevated: d.elevated,
    exact: d.exact, evidence: d.evidence || [], confirmLabel: d.confirm_label, token: d.token, expiresAt: d.expires_at || null,
    destructive: false };
}
function approvalSpecForFix(f, choice) {
  const base = { id: f.id, kind: "fix", target: "ARGUS-INSTINCT's own source code in this checkout (a draft only)",
    evidence: [f.problem ? `Problem: ${clip(f.problem, 200)}` : "No problem text was recorded.",
               f.directive_objective ? `Model directive: ${clip(f.directive_objective, 200)}` : null].filter(Boolean),
    elevated: "No elevated permissions. It does not touch the system.", destructive: false,
    ifNothing: `The proposal stays open and expires after ${FIX_EXPIRY_DAYS} days. Nothing is applied.` };
  if (choice === "approve") return { ...base, title: `Approve the investigation for ${f.title}`,
    proposes: "Start generating a draft patch with the local model. It is text only.",
    why: f.problem || "ARGUS-INSTINCT raised this proposal from its own findings.",
    expected: "A drafted patch you can read. Nothing is applied.",
    risks: "Uses local model time. The draft may be wrong, and the model is advisory only.",
    reversible: "Yes. This step changes nothing, so there is nothing to undo.",
    exact: "Records your approval and starts draft generation. It applies no patch.",
    confirmLabel: `Approve the investigation: ${f.id}` };
  return { ...base, title: `Authorize the patch for ${f.title}`,
    proposes: "Record that you authorize applying the reviewed patch. The page does not apply it.",
    why: f.problem || "ARGUS-INSTINCT raised this proposal from its own findings.",
    expected: "A recorded authorization. Applying still needs `jarvis fix apply " + f.id + "` in a terminal, where its tests run first.",
    risks: "The patch changes ARGUS-INSTINCT's source when you later apply it. A wrong patch could break a check.",
    reversible: `Yes. \`jarvis fix rollback ${f.id}\` reverse-applies the stored patch.`,
    exact: "Records your authorization only. No file is changed by this click.",
    confirmLabel: `Authorize the patch: ${f.id}` };
}

// ---- notifications --------------------------------------------------------
// Derived from the same state the page already polls; nothing here talks to the server. A key is notified once:
// an unchanged finding or monitoring problem never produces a second notification. The first time the page is
// opened, what is already there is recorded as known, not announced.
const NOTIF_TYPES = { finding: "Security finding", monitoring: "A problem with ARGUS-INSTINCT", approval: "Needs your approval",
                      investigation: "Investigation update", result: "Action result", info: "Information" };
const NOTIF_MAX = 100;
function emptyNotifStore() { return { seen: {}, items: [], baseline: false }; }
function candidateNotifications(s) {
  const out = [];
  const m = overviewModel(s);
  for (const g of m.secGroups) {
    const f = g.sample;
    if (f.severity !== "critical" && f.severity !== "high") continue;
    out.push({ key: `f:${f.job}|${clip(f.title, 160)}`, type: "finding", sev: f.severity, title: clip(f.title, 120),
      text: `${severityWord(f.severity)}: ${whatWasFound(f)}${g.count > 1 ? ` (${g.count} found)` : ""} It has not been confirmed as harmful.`,
      link: { go: "security", q: clip(f.title, 120) } });
  }
  const crit = new Set(["critical", "high"]);
  let other = 0;
  for (const p of m.problems) {
    if (crit.has(p.criticality)) {
      out.push({ key: `m:${p.id}:${p.state}`, type: "monitoring", sev: "warning", title: `${p.label} ${DETECTOR_WORDS[p.state] || "is not reporting"}`,
        text: "ARGUS-INSTINCT cannot confirm this area right now. This does not mean your computer has been attacked.", link: { go: "monitoring" }, important: true });
    } else other += 1;
  }
  if (other) out.push({ key: `m:other:${other}`, type: "monitoring", sev: "info", title: `${plural(other, "other check")} not reporting`,
    text: "These checks matter less to the overall status. Open Monitoring for the reasons.", link: { go: "monitoring" } });
  const a = s.assistant || {};
  for (const d of a.pending || [])
    out.push({ key: `a:${d.token}`, type: "approval", sev: "action", title: clip(d.title, 120),
      text: "ARGUS-INSTINCT proposes this. No change has been made, and you can decline.", link: { go: "assistant", act: "openproposal", token: d.token }, important: true });
  for (const f of s.fix || []) {
    if (f.status === "proposed" || f.status === "review")
      out.push({ key: `a:${f.id}:${f.status}`, type: "approval", sev: "action", title: clip(f.title || f.id, 120),
        text: (f.status === "review" ? "A draft patch is ready. " : "A fix proposal is waiting. ") + "No change has been made.",
        link: { go: "reviewqueue" }, important: true });
    if (f.generation_state === "done" || f.status === "draft_failed" || f.generation_error)
      out.push({ key: `i:${f.id}:${f.status}:${f.generation_state || ""}`, type: "investigation", sev: f.status === "draft_failed" ? "warning" : "info",
        title: clip(f.title || f.id, 120), text: f.status === "draft_failed" ? "The draft did not complete, so this investigation is incomplete." : "The draft is ready for you to read. Nothing was applied.",
        link: { go: "reviewqueue" } });
  }
  for (const e of a.audit || []) {
    let text = null, sev = "info";
    if (e.op === "approve" && e.outcome === "queued") text = "You approved it and it was queued. It is not confirmed until a fresh result arrives.";
    else if (e.outcome === "verified") text = "Confirmed by a fresh, valid result.";
    else if (e.op === "approve" && e.outcome === "failed") { text = "It could not be queued, so nothing happened."; sev = "warning"; }
    if (text) {
      const job = (s.jobs || []).find(j => j.name === (e.target || {}).job), what = job ? `“${job.label || job.name}”` : "a check";
      const title = e.action === "rerun_monitor" ? `Re-run of ${what}` : e.action === "verify_monitor" ? `Verification of ${what}`
        : e.action === "verify_finding" ? "Verification of a finding" : (e.action || "Action").replace(/_/g, " ");
      out.push({ key: `r:${e.ts}:${e.action}:${e.outcome}`, type: "result", sev, title: clip(title, 120), text, link: { go: "assistant" } });
    }
  }
  return out;
}
// -> {store, fresh}. `store` is the new persisted state; `fresh` are items to announce now.
function deriveNotifications(s, store, now) {
  now = now ?? Math.floor(Date.now() / 1000);
  const st = store && store.items ? { seen: { ...store.seen }, items: store.items.map(i => ({ ...i })), baseline: store.baseline } : emptyNotifStore();
  const cands = candidateNotifications(s), live = new Set(cands.map(c => c.key)), fresh = [];
  for (const c of cands) {
    if (st.seen[c.key]) continue;
    st.seen[c.key] = now;
    // First visit: what is already present is known, not news. Anything needing a decision still counts as unread.
    const seeded = !st.baseline && c.type !== "approval";
    const item = { ...c, ts: now, read: seeded, known: seeded, dismissed: false, active: true };
    st.items.unshift(item);
    if (!seeded) fresh.push(item);
  }
  for (const i of st.items) i.active = live.has(i.key);
  st.baseline = true;
  st.items = st.items.slice(0, NOTIF_MAX);
  const keep = new Set(st.items.map(i => i.key));
  for (const k of Object.keys(st.seen)) if (!keep.has(k) && !live.has(k)) delete st.seen[k];
  return { store: st, fresh };
}
// Critical findings and important monitoring failures stay put while the condition is true; the rest can be dismissed.
function canDismiss(item) {
  if (item.type === "finding" && item.sev === "critical") return !item.active;
  if (item.important) return !item.active;
  return true;
}
function dismissNotification(store, key) {
  const st = { ...store, items: store.items.map(i => ({ ...i })) };
  const it = st.items.find(i => i.key === key);
  if (it && canDismiss(it)) { it.dismissed = true; it.read = true; }
  return st;
}
function markRead(store, key) {
  const st = { ...store, items: store.items.map(i => ({ ...i })) };
  for (const i of st.items) if (key == null || i.key === key) i.read = true;
  return st;
}
const visibleNotifications = store => (store.items || []).filter(i => !i.dismissed);
const unreadCount = store => visibleNotifications(store).filter(i => !i.read).length;

// ---- investigation reports (assistant checks, ARGUS-INSTINCT and coding-agent output) --------------------
// Fixed order and wording; "what I have not done" is always present, so a report never hides or implies an action.
const REPORT_SECTIONS = [["checked", "What I checked"], ["found", "What I found"], ["meaning", "What this might mean"],
  ["certainty", "How certain I am"], ["recommendation", "What I recommend"], ["not_done", "What I have not done"]];
function reportSections(r) {
  const out = [];
  for (const [k, label] of REPORT_SECTIONS) {
    const v = r[k]; const lines = Array.isArray(v) ? v : (v ? [v] : []);
    if (lines.length) out.push({ key: k, label, lines: lines.map(l => redact(l)) });
  }
  return out;
}
// plain:end
const esc = s => redact(brand(s)).replace(/[&<>"']/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function ago(ts) {
  if (!ts) return "never";
  const d = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (d < 60) return d + "s ago";
  if (d < 3600) return Math.floor(d / 60) + "m ago";
  if (d < 86400) return Math.floor(d / 3600) + "h ago";
  return Math.floor(d / 86400) + "d ago";
}
function dur(s) {
  if (s < 60) return Math.round(s) + "s";
  if (s < 3600) return Math.round(s / 60) + "m";
  return Math.round(s / 3600) + "h";
}

/* ---------- filtering ---------- */
function visible() {
  if (!state) return [];
  const q = query.trim().toLowerCase();
  return (state.findings || []).filter(f =>
    (!sevFilter || f.severity === sevFilter) &&
    (!jobFilter || f.job === jobFilter) &&
    (!hostFilter || f.host === hostFilter) &&
    (!q || (f.title + " " + f.detail + " " + (f.where || "") + " " + f.category)
             .toLowerCase().includes(q)));
}

/* ---------- progress ----------
   Measured, not guessed: the score against its oldest recorded point in the
   last 24h. The score already refuses to reward blindness, so a rise is real.
   (The findings chart sums every snapshot per bucket, so it cannot say what
   was cleared.) */
function progress(s) {
  const h = ((s.security && s.security.history) || [])
    .filter(p => p[0] >= Date.now() / 1000 - 86400);
  return { score: h.length > 1 ? h[h.length - 1][1] - h[0][1] : null };
}

/* ---------- rendering ---------- */
/* ---------- priorities and the alert bar ---------- */
function dedupe(list, limit) {
  const seen = new Set(), out = [];
  for (const f of list) { const k = `${f.job}|${f.title}`; if (seen.has(k)) continue; seen.add(k); out.push(f); if (out.length >= limit) break; }
  return out;
}
function prioList(items, empty) {
  if (!items.length) return `<ul><li><small>${esc(empty)}</small></li></ul>`;
  return `<ul>` + items.map(x => `<li><span class="t">${esc(x.title)}</span><small>${esc(x.sub || "")}</small></li>`).join("") + `</ul>`;
}
function renderPriorities(s) {
  const el = document.getElementById("prio");
  if (!el) return;
  const all = s.findings || [];
  const crit = all.filter(f => f.severity === "critical"), high = all.filter(f => f.severity === "high");
  const qs = s.questions || [], fx = Array.isArray(s.fix) ? s.fix : [];
  const questions = qs.length, fixes = fx.length;
  const youCount = questions + fixes;
  const blind = (s.jobs || []).filter(j => j.stale || j.error);
  const live = (s.jobs || []).length - blind.length;
  const sub = f => `${f.job}${f.host ? " · " + f.host : ""}${f.where ? " · " + f.where : ""}`;
  el.innerHTML = `
    <div class="card crit"><div class="big c-critical">${crit.length}</div><div class="lbl">Critical · act now</div>
      ${prioList(dedupe(crit, 4).map(f => ({ title: f.title, sub: sub(f) })), "None open")}
      <div class="act"><button data-click="showsev" data-arg="critical">Show all critical</button></div></div>
    <div class="card high"><div class="big c-high">${high.length}</div><div class="lbl">High · fix soon</div>
      ${prioList(dedupe(high, 4).map(f => ({ title: f.title, sub: sub(f) })), "None open")}
      <div class="act"><button data-click="showsev" data-arg="high">Show all high</button></div></div>
    <div class="card you"><div class="big">${youCount}</div><div class="lbl">Needs your decision</div>
      ${prioList([...(() => {
                    const by = new Map();
                    for (const q of qs) { const k = q.prompt || "A question from ARGUS-INSTINCT"; by.set(k, (by.get(k) || 0) + 1); }
                    return [...by].slice(0, 3).map(([k, n]) => ({ title: k, sub: n > 1 ? `Question · ${n} of them` : "Question" }));
                  })(),
                  ...fx.slice(0, 2).map(f => ({ title: f.title || f.id, sub: "Proposed fix · " + (f.status || "waiting") }))], "Nothing is waiting on you")}
      <div class="act"><button data-click="reviewqueue">Open review queue</button></div></div>
    <div class="card ${blind.length ? "blind" : "clean"}"><div class="big ${blind.length ? "c-medium" : "c-ok"}">${monitoringTotals(s).verified}/${monitoringTotals(s).total}</div><div class="lbl">Checks reporting</div>
      ${prioList(blind.slice(0, 4).map(j => ({ title: j.label || j.name, sub: j.error ? "Error" : "Not reporting" })), "All collectors are fresh")}
      <div class="act"><button data-click="jump" data-arg="monitoring">Open monitoring</button></div></div>`;
  const nav = document.getElementById("nav-prio"); if (nav) { nav.textContent = crit.length + high.length + youCount ? crit.length + high.length + youCount : ""; nav.className = "n " + (crit.length ? "c-critical" : high.length ? "c-high" : ""); }
  const nf = document.getElementById("nav-find"); if (nf) nf.textContent = s.findings_total || "";
}
function renderAlertBar(s) {
  const bar = document.getElementById("alertbar");
  if (!bar) return;
  const all = s.findings || [];
  const live = all.filter(urgent), crit = all.filter(f => f.severity === "critical");
  const n = live.length || crit.length;
  if (!n) { bar.hidden = true; return; }
  bar.hidden = false;
  document.getElementById("alertcount").textContent = n;
  document.getElementById("alerttext").textContent = live.length
    ? `live alert${live.length > 1 ? "s" : ""}: ${brand(live[0].title)}`
    : `critical finding${crit.length > 1 ? "s" : ""} need attention: ${brand(crit[0].title)}`;
  document.getElementById("alertsub").textContent = live.length
    ? "something is happening on this machine right now"
    : "these lower the score most and can mean an active problem";
}

function render(s) {
  state = s;
  renderPriorities(s);
  renderOverview(s);
  renderViewLists(s);
  renderDetectors(s);
  renderLinks(s);
  updateNotifications(s);
  renderAlertBar(s);
  notifyCriticals(s);

  const st = document.getElementById("status");
  const liveThreats = (s.findings || []).filter(urgent).length;
  if (liveThreats) {
    st.textContent = liveThreats + " live alert" + (liveThreats > 1 ? "s" : "");
    st.className = "status s-critical";
  } else if (s.security) {
    const sc = s.security.score, pg = s.security.progress || {};
    st.textContent = s.security.state === "verifying"
      ? `${sc}% last verified · ${s.security.phase === "waking" ? "waking up" : "re-checking"} ${pg.checked ?? "?"}/${pg.total ?? "?"}`
      : `${sc}% · ${s.security.grade}`;
    st.className = "status s-" + (sc >= 75 ? "ok" : sc >= 50 ? "medium" : "high");
  } else {
    st.textContent = s.worst === "ok" ? "all clear" : s.worst;
    st.className = "status s-" + s.worst;
  }

  document.getElementById("meta").textContent =
    `updated ${new Date().toLocaleTimeString()}`;

  renderHealth(s);
  renderTiles(s);
  renderPerformance(s);
  renderContinuity(s);
  renderActivity(s);
  renderJobs(s);
  renderTrend(s);
  renderChart(s);
  renderCats(s);
  renderFilters(s);
  renderFindings();
  renderResults();
  renderChecks(s);
  renderSide(s);
  renderReviewQueue(s);
  renderAttack(s);
  voiceBrief(s, false);
  refreshGreeting(s);

  const b = s.baseline_at ? ago(Number(s.baseline_at)) : "never";
  document.getElementById("dbinfo").innerHTML =
    `${esc(s.db)} &nbsp;·&nbsp; baseline learned ${esc(b)} &nbsp;·&nbsp; ` +
    `${s.stats.procs} fingerprints (${s.stats.approved} approved) &nbsp;·&nbsp; ` +
    `${s.stats.peers} peers seen (${s.stats.peers_public} public) &nbsp;·&nbsp; ` +
    `${s.stats.events} alerts recorded` +
    `<br><span class="faint">shortcuts: ` +
    `<kbd>/</kbd> search &nbsp; <kbd>r</kbd> refresh &nbsp; <kbd>space</kbd> pause ` +
    `&nbsp; <kbd>v</kbd> speak briefing &nbsp; <kbd>esc</kbd> clear filters</span>`;
}

function renderQuestions(s) {
  const el = document.getElementById("jarvisquestions");
  const qs = s.questions || [];
  if (!qs.length) { el.innerHTML = ""; return; }
  const shown = showAllQuestions ? qs : qs.slice(0, 2);
  el.innerHTML = shown.map(q => `<div class="question">
    <div>${pill(q.severity)} ${esc(q.prompt)}</div>
    <div class="question-actions">
      <button data-act="answer" data-id="${esc(q.id)}" data-choice="yes">Yes · ${esc(q.yes)}</button>
      <button data-act="answer" data-id="${esc(q.id)}" data-choice="no">No · ${esc(q.no)}</button>
    </div></div>`).join("") + (qs.length > 2 ? `<div class="quick">
      <button class="showmore" data-click="morequestions">${
      showAllQuestions ? "Show fewer" : `${qs.length - 2} more question${qs.length > 3 ? "s" : ""}`}</button></div>` : "");
}

function renderReviewQueue(s) {
  const questions = (s.questions || []).length;
  const fixes = (s.fix || []).length;
  // Collapsed must not mean unnoticed: waiting decisions are named and flagged.
  document.getElementById("reviewcount").textContent = (questions
    ? `${questions} need${questions === 1 ? "s" : ""} your answer`
    : "no questions waiting") + ` · ${fixes} fix proposal${fixes === 1 ? "" : "s"}`;
  document.getElementById("reviewqueue").classList.toggle("needs", questions > 0);
  if (!document.getElementById("reviewqueue").open) return;
  renderQuestions(s);
  renderFix(s);
}
document.getElementById("reviewqueue").addEventListener("toggle", () => {
  if (state) renderReviewQueue(state);
});

async function decideFix(id, choice) {
  try {
    const response = await fetch("/api/fix/" + choice, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({id})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || data.error || response.status);
    toast(data.message, "good", "fix proposal " + choice + "d");
    await tick();
  } catch (error) {
    toast("Could not record decision: " + error.message, "bad", "fix proposal");
  }
}

function scoreColor(v) {
  if (v === null || v === undefined) return "var(--low)";
  return v >= 75 ? "var(--ok)" : v >= 50 ? "var(--med)" : "var(--crit)";
}

const ICON = { critical: "◆", high: "▲", medium: "●", low: "○", ok: "✓" };
const pill = sev => `<span class="pill ${esc(sev)}"><span aria-hidden="true">${ICON[sev] || ""}</span>${esc(sev)}</span>`;

function wakeHTML(h, now = Date.now() / 1000) {
  // While ARGUS-INSTINCT re-checks after a wake or restart, the held figure is the last
  // verified result, labelled as such; progress replaces the partial live score.
  const pr = h.progress || {checked: (h.live || {}).observed || 0, total: (h.live || {}).jobs || 0,
                            pending: [], retrying: [], running: []};
  const pct = pr.total ? Math.round(pr.checked / pr.total * 100) : 0;
  const at = h.verified_at ? new Date(h.verified_at * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}) : "—";
  const left = h.warmup_ends ? Math.max(0, Math.ceil((h.warmup_ends - now) / 60)) : null;
  const names = xs => (xs || []).slice(0, 6).map(esc).join(", ") + ((xs || []).length > 6 ? ` +${xs.length - 6}` : "");
  return `<div class="wake" role="status">
      <div class="wakebar" aria-label="${pr.checked} of ${pr.total} collectors re-checked"><i style="width:${pct}%"></i></div>
      <div>re-checking collectors · <b>${pr.checked}/${pr.total}</b> current</div>
      ${(pr.running || []).length ? `<div>now running: ${names(pr.running)}</div>` : ""}
      ${(pr.retrying || []).length ? `<div class="c-high">failed since waking, retrying: ${names(pr.retrying)}</div>` : ""}
      <div class="dim">score held from last full verification at ${esc(at)}${left !== null ? ` · live score applies in ≤${left} min` : ""}</div>
    </div>`;
}

function renderHealth(s) {
  const h = s.security;
  const el = document.getElementById("health");
  if (!h) { el.textContent = "no score yet"; return; }
  const verifying = h.state === "verifying";
  const waking = verifying && h.phase === "waking";
  const meter = (v, cls) =>
    `<div class="meter ${cls || ""}"><i style="width:${v ?? 0}%;background:${scoreColor(v)}"></i></div>`;

  // Ring: the one hero figure on the page. While re-checking it holds the last
  // verified score, never a partial sweep.
  const C = 2 * Math.PI * 52, off = C * (1 - Math.max(0, Math.min(100, h.score)) / 100);
  const ring = `<div class="ring${verifying ? " held" : ""}" role="img" aria-label="${verifying ? "Last verified" : "Security"} score ${h.score} percent">
      <svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="58" fill="none" stroke="var(--line2)" stroke-width="3"
        stroke-dasharray="0.6 ${(2 * Math.PI * 58 / 50 - 0.6).toFixed(3)}"/>
      <circle class="track" cx="60" cy="60" r="52" fill="none" stroke-width="3"/>
      <circle class="fill" cx="60" cy="60" r="52" fill="none" stroke-width="3"
        stroke="${scoreColor(h.score)}" stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"/></svg>
      <div class="num"><b>${h.score}</b><span>${verifying ? "last verified" : "security"}</span></div></div>`;

  const pr = progress(s);
  const chip = verifying || pr.score === null ? "" : pr.score > 0
    ? `<span class="delta up">▲ ${pr.score} in 24h</span>`
    : pr.score < 0 ? `<span class="delta down">▼ ${-pr.score} in 24h</span>`
    : `<span class="delta flat">steady over 24h</span>`;

  // Sparkline of verified history; warm-up points are never recorded there.
  const hist = (h.history || []).filter(p => p[0] >= Date.now() / 1000 - 86400);
  let spark = "";
  if (hist.length > 1) {
    const x0 = hist[0][0], span = Math.max(1, hist[hist.length - 1][0] - x0);
    const X = p => (p[0] - x0) / span * 100, Y = p => 32 - p[1] / 100 * 30 - 1;
    const pts = hist.map(p => `${X(p).toFixed(2)},${Y(p).toFixed(2)}`).join(" ");
    const w = 100 / hist.length;
    spark = `<svg class="spark" viewBox="0 0 100 34" preserveAspectRatio="none">
      <polyline fill="none" stroke="${scoreColor(h.score)}" stroke-width="2"
        vector-effect="non-scaling-stroke" points="${pts}"/>` +
      hist.map(p => `<rect x="${Math.max(0, X(p) - w / 2).toFixed(2)}" y="0" width="${w.toFixed(2)}" height="34"
        fill="transparent" data-tip="${esc(new Date(p[0] * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}))} · score ${p[1]}"/>`).join("") +
      `</svg>`;
  }

  // Areas show their verified figures; an area still being re-checked says so.
  const liveBlind = {};
  for (const a of ((h.live || {}).areas || [])) liveBlind[a.name] = a.blind || [];
  const areas = (h.areas || []).map(a => {
    const open = SEV.filter(k => k !== "low" && (a.open || {})[k])
      .map(k => `<span class="c-${k}">${a.open[k]}${k[0]}</span>`).join(" ");
    const pct = a.score === null ? "unverified" : `${a.score}%`;
    const pending = verifying ? liveBlind[a.name] || [] : a.blind || [];
    const mark = !pending.length ? ""
      : verifying ? ` <span class="rechk" data-tip="re-checking: ${esc(pending.map(b => b.job).join(", "))}">re-checking</span>`
      : ` <span class="c-high" data-tip="not reporting: ${esc(pending.map(b => b.job + " " + b.state).join(", "))}">⚠</span>`;
    return `<span class="nm">${esc(a.name)}${mark}</span>${meter(a.score, "sm")}<span class="pc">${pct} ${open}</span>`;
  }).join("");

  el.innerHTML =
    `<div class="scorebox">${ring}<div class="scoremeta">
       <div class="grade" style="color:${scoreColor(h.score)}">${waking ? "Waking up" : verifying ? "Re-verifying" : esc(h.grade)}</div>
       <div>${chip}</div>
       ${verifying ? wakeHTML(h) : `<div class="cov">monitoring coverage ${h.coverage}%${h.acknowledged ? ` · ${h.acknowledged} confirmed as expected` : ""}</div>`}
       ${spark}
     </div></div>
     <div class="areas">${areas}</div>`;

  if (s.posture) {
    const p = s.posture, d = p.debt_counts;
    const sh = p.sustained_health || {}, ar = p.automatic_remediation || {};
    el.innerHTML += `<details><summary>Security convergence · ${esc(p.readiness)}</summary>
      <p>${d.security} security findings · ${d.coverage} coverage gaps · ${d.accepted} accepted risks</p>
      <p>Sustained health: ${esc(sh.status || 'unverified')}${sh.duration_s ? ` · ${Math.floor(sh.duration_s / 60)} min · ${sh.samples} samples` : ''}.</p>
      <p>Bounded automatic repairs: ${ar.verified || 0} verified · ${ar.failed || 0} failed · ${ar.blocked || 0} blocked.</p>
      <p>Projected after verified remediation: ${p.projected_after_verified_remediation}%.
      Verification pending; individual gains overlap.</p>
      ${(p.candidates || []).slice(0, 6).map(c => `<p>${esc(c.title)} · +${c.projected_recovery} projected
      <br>Requires review and fresh checks: ${esc(c.verification_jobs.join(', '))}</p>`).join('')}
    </details>`;
  }

  const top = (h.next_steps || [])[0];
  document.getElementById("healthsub").textContent =
    waking ? "ARGUS-INSTINCT is waking up and re-checking every collector"
    : verifying ? "re-checking collectors before updating the score"
    : pr.score > 0 ? "climbing, nicely done"
    : h.score >= 90 ? "in fine shape"
    : top ? "each gain fills the ring" : "";
  renderWins(verifying ? {next_steps: [], verifying: true} : h);
}

function renderWins(h) {
  const steps = [];
  for (const g of h.next_steps || []) {
    const same = steps.find(x => x.title === g.title && x.job === g.job);
    if (same) same.count++; else steps.push({ ...g, count: 1 });
  }
  document.getElementById("winscnt").textContent = steps.length ? `${steps.length} to go` : "";
  document.getElementById("wins").innerHTML = steps.length
    ? steps.map((g, i) => `<li tabindex="0" role="button" data-title="${esc(g.title)}"
          data-click="findtitle" data-enter="findtitle">
          <span class="rank">${i + 1}</span>
          <span class="t">${pill(g.severity)} ${esc(g.title)}${g.count > 1 ? ` <span class="loc">× ${g.count} places</span>` : ""}</span>
          <span class="a">${esc(g.area)} · ${esc(g.job)}</span></li>`).join("")
    : h.verifying ? `<li class="static"><span class="rank">…</span><span class="t">Re-verifying collectors.</span>
         <span class="a">Next steps will return with fresh evidence.</span></li>`
    : `<li class="static"><span class="rank">✓</span><span class="t">Nothing left to gain here.</span>
         <span class="a">Splendid. ARGUS-INSTINCT keeps watching.</span></li>`;
  document.getElementById("winsfoot").textContent = steps.length
    ? "Click one to see its evidence below. The first is worth the most." : "";
}

function renderAttack(s) {
  const a = s.attack, el = document.getElementById("attack");
  if (!a || !a.totals || !a.totals.total) {
    el.innerHTML = `<div class="empty">the ATT&amp;CK catalogue has not been loaded yet</div>`;
    return;
  }
  const t = a.totals, pct = n => Math.round(n / t.total * 100);
  document.getElementById("attackcnt").textContent =
    `${t.total} techniques · measured ${ago(a.at)}`;
  const head = [["validated", t.validated, "detector proven by probe, collector live"],
                ["claimed", t.claimed, "mapped, not proven"],
                ["blind", t.blind, "nothing looks for it"]]
    .concat(t.regressed ? [["regressed", t.regressed, "a detector stopped firing"]] : [])
    .map(([k, n, tip]) => `<div data-tip="${tip}"><b class="${k === "regressed" ? "c-critical" : ""}">${n}</b>
        <span><i class="sw lv-${k}"></i>${k} · ${pct(n)}%</span></div>`).join("");
  const rows = Object.entries(a.tactics).filter(([, v]) => v.total).map(([name, v]) => {
    const seg = ["validated", "claimed", "regressed", "blind"].filter(k => v[k]).map(k =>
      `<i class="lv-${k}" style="flex:${v[k]}" data-tip="${esc(name.replace(/-/g, " "))}: ${v[k]} ${k}"></i>`).join("");
    return `<span class="tn">${esc(name.replace(/-/g, " "))}</span><span class="tb">${seg}</span>
            <span class="tc">${v.validated + v.claimed}/${v.total}</span>`;
  }).join("");
  el.innerHTML = `<div class="attackhead">${head}</div><div class="attack">${rows}</div>`;
}

function findTitle(title) {
  const q = document.getElementById("q");
  q.value = title; query = title; sevFilter = null; open.clear(); findingLimit = FINDING_BATCH;
  if (state) render(state);
  document.getElementById("findings").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderTiles(s) {
  const hostBits = h => {
    const t = s.by_host[h];
    if (!t) return "";
    return SEV.filter(k => t[k]).map(k => `<span class="c-${k}" data-tip="${t[k]} ${k}">${t[k]} ${{critical: "crit", high: "high", medium: "med", low: "low"}[k]}</span>`).join("")
      || `<span class="c-ok">clean</span>`;
  };
  const live = s.jobs.filter(j => j.ts && !j.error && !j.stale).length;
  document.getElementById("tiles").innerHTML = `
    <div class="tile good" data-tip="Checks that ran and came back clean">
      <div class="n c-ok">${(s.checks || []).length}</div>
      <div class="k"><span class="ic">✓</span>Verified clean</div>
    </div>
    <div class="tile ${monitoringTotals(s).verified === monitoringTotals(s).total ? "good" : ""}" data-tip="Checks that apply to this computer and returned a fresh, valid result">
      <div class="n ${monitoringTotals(s).verified === monitoringTotals(s).total ? "c-ok" : "c-high"}">${monitoringTotals(s).verified}/${monitoringTotals(s).total}</div>
      <div class="k">Checks reporting</div>
    </div>` +
    SEV.map(k => `
      <div class="tile ${sevFilter === k ? "on" : ""}" data-click="sev" data-arg="${k}" role="button" tabindex="0"
           data-enter="sev" data-tip="Show only ${k} findings">
        <div class="n c-${k}">${s.totals[k] || 0}</div>
        <div class="k"><span class="ic c-${k}" aria-hidden="true">${ICON[k]}</span>${k[0].toUpperCase() + k.slice(1)}</div>
      </div>`).join("") + `
    <div class="tile ${sevFilter === null ? "on" : ""}" data-click="sev" data-arg="" role="button" tabindex="0"
         data-enter="sev">
      <div class="n">${s.findings_total}</div><div class="k">All findings</div>
    </div>
    <div class="tile hosttile ${hostFilter === "win" ? "on" : ""}" data-click="host" data-arg="win" role="button" tabindex="0">
      <div class="n">${hostBits("win")}</div>
      <div class="k">Windows</div>
    </div>
    <div class="tile hosttile ${hostFilter === "wsl" ? "on" : ""}" data-click="host" data-arg="wsl" role="button" tabindex="0">
      <div class="n">${hostBits("wsl")}</div>
      <div class="k">WSL</div>
    </div>`;
}

function renderJobs(s) {
  document.getElementById("jobcnt").textContent =
    `${s.jobs.length} · one at a time`;
  const rank = j => j.running ? 1 : (j.error || !j.ts || j.stale) ? 0 : 2;
  const sorted = [...s.jobs].sort((a, b) => rank(a) - rank(b));
  const healthy = sorted.filter(j => rank(j) === 2).length;
  const shown = showHealthy ? sorted : sorted.filter(j => rank(j) < 2);
  document.getElementById("jobs").innerHTML = (shown.length ? "" :
    `<div class="empty">All ${healthy} collectors are healthy. Splendid.</div>`) + shown.map(j => {
    const cls = j.running ? "run" : j.error ? "err"
              : !j.ts ? "never" : j.stale ? "stale" : "";
    const counts = SEV.filter(k => j.counts[k])
      .map(k => `<span class="c-${k}">${j.counts[k]}${k[0]}</span>`).join(" ");
    const okb = j.ok ? `<span class="c-ok">${j.ok}✓</span>` : "";
    // progress toward the next scheduled run
    const pct = j.interval
      ? Math.max(0, Math.min(100, 100 - (j.next / j.interval) * 100)) : 0;
    return `<div class="job">
      <span class="dot ${cls}" title="${esc(cls || "healthy")}"></span>
      <span class="name">
        <b>${esc(j.label)}</b> ${counts} ${okb}
        <div class="bar"><i style="width:${pct.toFixed(0)}%"></i></div>
      </span>
      <span class="age">${j.running ? "running…"
        : ago(j.ts) + (j.duration ? " · " + j.duration + "s" : "")}
        <br><span class="faint">every ${dur(j.interval)}${
          j.next > 0 && !j.running ? " · next " + dur(j.next) : ""}</span></span>
      <button class="small" data-act="runjob" data-job="${esc(j.name)}">Run</button>
    </div>` + (j.error
      ? `<div class="errbox">${esc(j.error.trim().split("\n").pop())}</div>` : "");
  }).join("") + (healthy ? `<button class="showmore" data-click="morejobs">${
    showHealthy ? "Hide healthy collectors" : `Show ${healthy} healthy collector${healthy > 1 ? "s" : ""}`}</button>` : "");
}

function renderPerformance(s) {
  const p = s.performance || {}, cpu = p.cpu_pct;
  const io = p.write_mib_s == null ? "I/O warming up" : Number(p.write_mib_s).toFixed(3) + " MiB/s writes";
  const running = (p.running || []).length ? ` · running ${p.running.map(esc).join(", ")}` : "";
  document.getElementById("perfcnt").textContent =
    `${cpu == null ? "warming up" : cpu.toFixed(1) + "% CPU"} · ${Number(p.service_memory_mib || p.rss_mib || 0).toFixed(0)} MiB service · ${io}${running}`;
  const duty = Number(p.scheduled_duty_pct || 0);
  const cls = duty >= 100 ? "c-critical" : duty >= 70 ? "c-high" : duty >= 45 ? "c-medium" : "c-ok";
  const rows = (p.top || []).map(j => `<div class="job">
    <span class="dot ${j.duty_pct >= 70 ? "err" : j.duty_pct >= 30 ? "stale" : ""}"></span>
    <span class="name"><b>${esc(j.label || j.name)}</b><div class="bar"><i style="width:${Math.min(100, j.duty_pct)}%"></i></div></span>
    <span class="age">${Number(j.duration).toFixed(1)}s/run<br><span class="faint">${Number(j.duty_pct).toFixed(1)}% duty</span></span>
  </div>`).join("");
  const profile = p.subsystems || {}, owners = profile.owners || {};
  const ownerRows = Object.entries(owners).filter(([name]) => name !== "other").map(([name, v]) =>
    `<div class="job"><span class="name"><b>${esc(name)}</b></span><span class="age">${(Number(v.rss_bytes || 0)/1048576).toFixed(0)} MiB<br>${Number(v.cpu_pct || 0).toFixed(1)}% CPU · ${Number(v.processes || 0)} proc</span></div>`).join("");
  const db = profile.database || {}, dbRows = (db.tables || []).slice(0, 5).map(t =>
    `${esc(t.name)} ${(Number(t.bytes || 0)/1048576).toFixed(0)} MiB`).join(" · ");
  const acc = p.accelerator || {}, gpuNames = (acc.gpus || []).map(g => g.name).filter(Boolean);
  const ov = acc.openvino || {}, ovDevices = (ov.devices || []).join(", ") || "none";
  const accel = gpuNames.length ? `<div class="stat"><b>accelerator</b> · ${esc(gpuNames.join(", "))} · OpenVINO ${ov.installed ? esc(ovDevices) : "not installed"} · Ollama ${((acc.ollama || {}).reachable) ? "reachable" : "not loaded/reachable"}</div>` : "";
  document.getElementById("performance").innerHTML = `<div class="stat head">
    <b class="${cls}">${duty.toFixed(1)}%</b> scheduled duty · sum of each collector's last duration ÷ cadence
  </div>${rows || '<div class="empty">waiting for collector timings…</div>'}${ownerRows}
  ${db.bytes ? `<div class="stat"><b>database ${(Number(db.bytes)/1048576).toFixed(0)} MiB</b> · ${dbRows}</div>` : ""}${accel}`;
}

/* ---------- continuity + activity ----------
   Pure view functions (no DOM): continuityHTML/activityHTML take state
   slices and return HTML strings. Thin render* wrappers mount them. */
function continuityHTML(cont) {
  if (!cont) return `<div class="empty">continuity systems not reporting yet</div>`;
  const inv = cont.invariants || {}, names = Object.keys(inv).filter(k => k !== "ok");
  const rows = names.map(k => {
    const v = inv[k] || {};
    return `<div class="job"><span class="dot ${v.ok ? "" : "err"}" title="${v.ok ? "holding" : "violated"}"></span>` +
      `<span class="name"><b>${esc(k)}</b><div class="note">${esc(v.reason || "")}</div></span>` +
      `<span class="age">${v.ok ? "Holding" : "Violated"}</span></div>`;
  }).join("");
  const gov = cont.governor || {};
  const govRow = `<div class="job"><span class="dot ${gov.pressured ? "stale" : ""}"></span>` +
    `<span class="name"><b>governor</b><div class="note">${esc(gov.reason || "unknown")}</div></span>` +
    `<span class="age">${gov.pressured ? "deferring noncritical" : "all tiers"}</span></div>`;
  const p = cont.perception;
  const percRow = p ? `<div class="job"><span class="name"><b>perception</b>` +
    `<div class="note">${p.verified || 0} verified · ${p.unreconciled || 0} unreconciled · ${p.unknown || 0} unknown` +
    `${p.windows_processes != null ? ` across ${p.windows_processes} windows processes` : ""}</div></span></div>` : "";
  return rows + govRow + percRow;
}

function activityHTML(chains) {
  if (!chains || !chains.length) return `<div class="empty">no correlated activity — single observations stay in Findings.</div>`;
  return chains.map(c => {
    const over = c.member_overflow ? ` · +${c.member_overflow} more` : "";
    const causal = c.causal ? ` · causal edge` : ` · grouped, causality unverified`;
    return `<div class="job"><span class="name">${pill(c.worst_severity)} <b>${esc(c.headline || "")}</b>` +
      `<div class="note">${c.count} observation${c.count === 1 ? "" : "s"} · ${(c.jobs || []).map(esc).join(", ")} · ${esc(c.host || "")}${causal}${over}</div></span>` +
      `<span class="age">${c.last ? ago(c.last) : ""}</span></div>`;
  }).join("");
}

function renderContinuity(s) {
  const cont = s.continuity;
  const bad = cont && cont.invariants
    ? Object.keys(cont.invariants).filter(k => k !== "ok" && !((cont.invariants[k] || {}).ok)) : [];
  document.getElementById("contcnt").textContent = !cont ? "not reporting"
    : bad.length ? `${bad.length} invariant${bad.length === 1 ? "" : "s"} violated` : "all invariants holding";
  document.getElementById("continuity").innerHTML = continuityHTML(cont);
}

function renderActivity(s) {
  const chains = (s.continuity && s.continuity.activity) || [];
  document.getElementById("actcnt").textContent =
    chains.length ? `${chains.length} ${chains.length === 1 ? "story" : "stories"}` : "no stories";
  document.getElementById("activity").innerHTML = activityHTML(chains);
}

function scoreTrendHTML(history, currentTime = Date.now() / 1000) {
  const points = (history || []).filter(p => Array.isArray(p) &&
    Number.isFinite(p[0]) && Number.isFinite(p[1]) && p[1] >= 0 && p[1] <= 100 &&
    p[0] >= currentTime - 86400 && p[0] <= currentTime).sort((a, b) => a[0] - b[0]);
  if (points.length < 2) return {count: points.length,
    html: `<div class="empty">Not enough verified score samples for a 24-hour trend.</div>`};
  const first = points[0][0], last = points[points.length - 1][0];
  const x = p => 32 + (p[0] - first) / Math.max(1, last - first) * 554;
  const y = p => 112 - p[1];
  const line = points.map(p => `${x(p).toFixed(1)},${y(p).toFixed(1)}`).join(" ");
  const tip = points.map(p => `<circle cx="${x(p).toFixed(1)}" cy="${y(p).toFixed(1)}"
    r="7" fill="transparent"><title>${esc(new Date(p[0] * 1000).toLocaleString())} · verified score ${p[1]}%</title></circle>`).join("");
  return {count: points.length, latest: points[points.length - 1][1], html:
    `<svg class="scoretrend" viewBox="0 0 600 140" preserveAspectRatio="none" role="img"
      aria-label="Verified host score from ${points[0][1]} to ${points[points.length - 1][1]} percent over the last 24 hours">
      <line x1="32" y1="12" x2="586" y2="12" stroke="var(--line)"/>
      <line x1="32" y1="62" x2="586" y2="62" stroke="var(--line)"/>
      <line x1="32" y1="112" x2="586" y2="112" stroke="var(--line)"/>
      <text x="0" y="15" fill="var(--faint)" font-size="10">100</text>
      <text x="6" y="65" fill="var(--faint)" font-size="10">50</text>
      <text x="12" y="115" fill="var(--faint)" font-size="10">0</text>
      <polyline points="${line}" fill="none" stroke="var(--accent)" stroke-width="2.5"
        vector-effect="non-scaling-stroke"/>
      <circle cx="${x(points[points.length - 1]).toFixed(1)}" cy="${y(points[points.length - 1]).toFixed(1)}"
        r="4" fill="var(--accent)"/>${tip}</svg>
    <div class="trendmeta"><span>${esc(new Date(first * 1000).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}))}</span>
      <span>Verified score history · current protection is shown above</span>
      <span>${esc(new Date(last * 1000).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}))}</span></div>`};
}

function renderTrend(s) {
  const trend = scoreTrendHTML((s.security || {}).history);
  document.getElementById("trendcnt").textContent = trend.count < 2
    ? "waiting for samples" : `${trend.count} samples · latest ${trend.latest}%`;
  document.getElementById("trend").innerHTML = trend.html;
}

function renderChart(s) {
  const h = s.history || [];
  const max = Math.max(1, ...h.map(p => p.critical + p.high + p.medium + p.low));
  document.getElementById("chart").innerHTML = h.length
    ? h.map(p => {
        const seg = SEV.map(k => {
          const v = p[k] || 0;
          return v ? `<i style="height:${Math.max(2, v / max * 76).toFixed(1)}px;
                       background:var(--${k === "critical" ? "crit"
                         : k === "high" ? "high" : k === "medium" ? "med" : "low"})"></i>` : "";
        }).join("");
        const tot = p.critical + p.high + p.medium + p.low;
        return `<div class="col" data-tip="${new Date(p.ts * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"})} · ${
          tot} findings: ${p.critical} critical, ${p.high} high, ${p.medium} medium, ${p.low} low">${seg}</div>`;
      }).join("")
    : `<div class="empty">no history yet</div>`;
  document.getElementById("chartmeta").textContent =
    h.length ? `${h.length} samples · 15-minute buckets` : "";
}

function renderCats(s) {
  const c = s.by_category || {};
  const keys = Object.keys(c).sort((a, b) => c[b] - c[a]).slice(0, 12);
  document.getElementById("cats").innerHTML = keys.map(k =>
    `<div><span>${esc(k)}</span><b>${c[k]}</b></div>`).join("");
}

function renderFilters(s) {
  document.getElementById("filters").innerHTML =
    [["all", null], ...SEV.map(k => [k, k])].map(([label, k]) =>
      `<button class="${sevFilter === k ? "on" : ""}" data-click="sev" data-arg="${k || ""}">${label[0].toUpperCase() + label.slice(1)}</button>`).join("");

  const sel = document.getElementById("jobsel");
  const want = s.jobs.map(j => j.name);
  if (sel.options.length !== want.length + 1) {
    sel.innerHTML = `<option value="">All collectors</option>` +
      s.jobs.map(j => `<option value="${esc(j.name)}">${esc(j.label)}</option>`).join("");
  }
  sel.value = jobFilter;
  document.getElementById("hostsel").value = hostFilter;
  document.getElementById("grp").className = grouped ? "on" : "";
}

function findingRow(f, i) {
  const id = "f" + i;
  const isOpen = open.has(id);
  return `<tr class="clickable sevrow" style="--sevc:var(--${{critical: "crit", high: "high", medium: "med", low: "low"}[f.severity] || "low"})"
        data-click="toggle" data-arg="${id}">
      <td>${pill(f.severity)}</td>
      <td><span class="tag">${esc(f.job)}</span></td>
      <td><span class="tag">${esc(f.host || "?")}</span></td>
      <td>
        <div class="title">${esc(f.title)}</div>
        <div class="detail">${esc(f.detail)}</div>
        ${f.where && !isOpen ? `<div class="where">${esc(f.where)}</div>` : ""}
      </td>
    </tr>` + (isOpen ? `<tr class="expand"><td colspan="4"><dl class="kv">
        <dt>in simple terms</dt><dd>${esc(guideFor(f).means)} <span class="faint">(general background)</span></dd>
        <dt>category</dt><dd>${esc(f.category || "—")}</dd>
        <dt>collector</dt><dd>${esc(f.job)}</dd>
        <dt>host</dt><dd>${esc(f.host || "—")}</dd>
        <dt>location</dt><dd>${esc(f.where || "—")}</dd>
        <dt>detail</dt><dd>${esc(f.detail)}</dd>
        ${(f.forensics || []).length ? `<dt>forensics</dt><dd><pre class="pre">${esc(f.forensics.join("\n"))}</pre></dd>` : ""}
      </dl></td></tr>` : "");
}

function renderFindings() {
  const rows = visible();
  document.getElementById("findcnt").textContent =
    `${rows.length}${rows.length !== state.findings_total ? " of " + state.findings_total : ""}`;
  document.getElementById("filtermeta").textContent =
    (sevFilter || jobFilter || hostFilter || query)
      ? "filtered — press esc to clear" : "click any row for full detail";

  const head = `<table><thead><tr>
      <th style="width:96px">Severity</th><th style="width:92px">Collector</th>
      <th style="width:52px">Host</th><th>What was found</th>
    </tr></thead><tbody>`;

  if (!rows.length) {
    document.getElementById("findings").innerHTML =
      `<div class="empty">nothing matches these filters</div>`;
    return;
  }
  // Render a bounded batch: hundreds of rows rebuilt every refresh can stall slower engines.
  const shown = rows.slice(0, findingLimit);
  let html;
  if (grouped) {
    const by = {};
    shown.forEach((f, i) => (by[f.job] = by[f.job] || []).push([f, i]));
    html = Object.keys(by).sort().map(job =>
      head + `<tr><td colspan="4" class="grouprow">
        ${esc(job)} <span class="cnt">${by[job].length}</span>
        </td></tr>` +
      by[job].map(([f, i]) => findingRow(f, i)).join("") + `</tbody></table>`).join("");
  } else {
    html = head + shown.map((f, i) => findingRow(f, i)).join("") + `</tbody></table>`;
  }
  if (rows.length > shown.length) {
    const more = Math.min(FINDING_BATCH, rows.length - shown.length);
    html += `<div class="empty"><button data-click="morefindings">show ${more} more · ${rows.length - shown.length} hidden</button></div>`;
  }
  if (html === lastFindingRender) return;
  lastFindingRender = html;
  document.getElementById("findings").innerHTML = html;
}

function showMoreFindings() {
  findingLimit += FINDING_BATCH;
  renderFindings();
}

function renderChecks(s) {
  const c = s.checks || [];
  document.getElementById("checkcnt").textContent = `${c.length} checks passed`;
  document.getElementById("checks").innerHTML = c.length ? `
    <table><thead><tr>
      <th style="width:92px">Collector</th><th style="width:46px">Host</th><th>Confirmed</th>
    </tr></thead><tbody>${c.map(f => `
      <tr>
        <td><span class="tag">${esc(f.job)}</span></td>
        <td><span class="tag">${esc(f.host || "?")}</span></td>
        <td>
          <div class="title c-ok">${esc(f.title)}</div>
          <div class="detail">${esc(f.detail)}</div>
        </td>
      </tr>`).join("")}</tbody></table>`
    : `<div class="empty">no checks have reported a clean result yet</div>`;
}

function renderIntel(s) {
  const it = s.intel || { total: 0, kinds: {}, feeds: [], hits: [] };
  const kinds = Object.entries(it.kinds || {});
  // A hunt that finds nothing only means something if the knowledge base
  // behind it is current, so freshness is shown next to the counts.
  const stale = f => !f.last_run ? "never"
    : (s.now - f.last_run > 172800 ? "stale" : ago(f.last_run));
  document.getElementById("side").innerHTML = `
    <div class="intel-head">
      <b>${it.total.toLocaleString()}</b> live indicators
      from <b>${(it.docs || 0).toLocaleString()}</b> writeups
      &nbsp;·&nbsp; hunted ${it.last_hunt ? ago(it.last_hunt) : "never"}
      &nbsp;·&nbsp; refreshed ${it.last_refresh ? ago(it.last_refresh) : "never"}
      &nbsp;·&nbsp; api spend $${(it.spend_total || 0).toFixed(2)}
      (today $${(it.spend_today || 0).toFixed(2)})
    </div>
    <div class="kindrow">${kinds.map(([k, n]) =>
      `<span class="tag">${esc(k)} <b>${n.toLocaleString()}</b></span>`).join("")}</div>
    ${(it.hits || []).length ? `
      <h3 class="sub">recent indicator matches</h3>
      <table><thead><tr>
        <th style="width:74px">Severity</th><th style="width:92px">When</th>
        <th>Match</th>
      </tr></thead><tbody>${it.hits.map(h => `
        <tr>
          <td class="sev c-${esc(h.severity)}">${esc(String(h.severity).toUpperCase())}</td>
          <td class="detail">${ago(h.ts)}</td>
          <td><div class="title">${esc(h.value)}</div>
              <div class="where">${esc(h.evidence || "")}</div></td>
        </tr>`).join("")}</tbody></table>`
      : `<div class="empty">no indicator has matched this machine</div>`}
    <h3 class="sub">feeds</h3>
    <table><thead><tr>
      <th>Feed</th><th style="width:80px">Records</th><th style="width:90px">Updated</th>
    </tr></thead><tbody>${(it.feeds || []).map(f => `
      <tr>
        <td>${esc(f.name)}${f.error
          ? `<div class="where c-high">${esc(f.error)}</div>` : ""}</td>
        <td class="detail">${(f.kept || 0).toLocaleString()}</td>
        <td class="detail">${stale(f)}</td>
      </tr>`).join("")}</tbody></table>`;
}

function renderSide(s) {
  if (tab === "internet") {
    const samples = s.internet || {};
    document.getElementById("side").innerHTML = `<div class="panelnote">Socket samples, not packet capture. Direction is inferred only when a matching listener exists. Short connections can be missed.</div>` +
      ["wsl", "win"].map(host => {
        const sample = samples[host];
        if (!sample) return `<div class="empty">${esc(host)}: no traffic sample available</div>`;
        const rows = sample.connections || [];
        return `<div class="panelnote">${esc(host)} · ${esc(sample.status || 'saved')} · saved sample ${ago(sample.ts)} · ${rows.length} endpoints${sample.truncated ? " · truncated" : ""}<div>${esc((sample.errors || []).join('; '))}</div></div>
          <div class="scroll"><table><thead><tr><th>App</th><th>Local</th><th>Remote</th><th>State / direction</th></tr></thead><tbody>` +
          rows.map(r => `<tr><td title="${esc(r.exe || '')}">${esc(r.name)} <span class="detail">${esc(r.pid)}</span></td>
            <td>${esc(r.local_ip)}:${esc(r.local_port)}</td><td>${esc(r.remote_ip || '—')}:${esc(r.remote_port || '—')}</td>
            <td>${esc(r.proto)} ${esc(r.state)}<div class="detail">${esc(r.direction)}</div></td></tr>`).join("") + `</tbody></table></div>`;
      }).join("");
    return;
  }
  if (tab === "intel") { renderIntel(s); return; }
  if (tab === "ops") { renderOps(s); return; }
  if (tab === "peers") {
    const p = s.peers || [];
    document.getElementById("side").innerHTML = p.length ? `
      <table><thead><tr>
        <th>Remote</th><th style="width:46px">Host</th><th style="width:48px">Seen</th>
        <th style="width:92px">Last</th><th>Process</th>
      </tr></thead><tbody>${p.map(x => `
        <tr>
          <td>${esc(x.remote_ip)}:${esc(x.remote_port)}${
            x.rdns ? `<div class="where">${esc(x.rdns)}</div>` : ""}</td>
          <td><span class="tag">${esc(x.host)}</span></td>
          <td class="detail">${esc(x.seen_count)}</td>
          <td class="detail">${ago(x.last_seen)}</td>
          <td class="detail">${esc(x.pname || "—")}</td>
        </tr>`).join("")}</tbody></table>`
      : `<div class="empty">no public peers recorded yet</div>`;
  } else {
    const e = s.events || [];
    document.getElementById("side").innerHTML = e.length ? `
      <table><thead><tr>
        <th style="width:74px">Severity</th><th style="width:92px">When</th>
        <th style="width:46px">Host</th><th>Process</th>
      </tr></thead><tbody>${e.map(x => `
        <tr>
          <td class="sev c-${esc(x.severity)}">${esc(String(x.severity).toUpperCase())}</td>
          <td class="detail">${ago(x.ts)}</td>
          <td><span class="tag">${esc(x.host)}</span></td>
          <td>
            <div class="title">${esc(x.name)} <span class="detail">[${esc(x.pid)}]</span></div>
            <div class="where">${esc(x.cmdline || x.exe || "")}</div>
          </td>
        </tr>`).join("")}</tbody></table>`
      : `<div class="empty">no alerts recorded yet</div>`;
  }
}

/* ---------- tooltip ---------- */
(function () {
  const tip = document.getElementById("tip");
  const place = e => {
    const x = Math.max(8, Math.min(e.clientX + 12, innerWidth - tip.offsetWidth - 8));
    const y = e.clientY + 16 + tip.offsetHeight > innerHeight ? e.clientY - tip.offsetHeight - 10 : e.clientY + 16;
    tip.style.left = x + "px"; tip.style.top = y + "px";
  };
  document.addEventListener("mouseover", e => {
    const t = e.target.closest && e.target.closest("[data-tip]");
    if (!t) { tip.className = ""; return; }
    tip.textContent = t.getAttribute("data-tip"); tip.className = "on"; place(e);
  });
  document.addEventListener("mousemove", e => { if (tip.className) place(e); });
})();

/* ---------- interaction ---------- */
function setSev(k) { sevFilter = k; open.clear(); findingLimit = FINDING_BATCH; if (state) render(state); }
function setHost(h) { hostFilter = hostFilter === h ? "" : h; open.clear(); findingLimit = FINDING_BATCH; if (state) render(state); }
function onFilter() {
  jobFilter = document.getElementById("jobsel").value;
  hostFilter = document.getElementById("hostsel").value; findingLimit = FINDING_BATCH;
  open.clear(); if (state) render(state);
}
function onSearch() {
  query = document.getElementById("q").value; open.clear(); findingLimit = FINDING_BATCH;
  if (state) { renderFindings(); renderResults(); }
}
/* The results panel sits under the search box: a search must visibly do
   something where the user is looking, not only in a table far below. */
function renderResults() {
  const panel = document.getElementById("results");
  if (!panel || !state) return;
  const q = query.trim().toLowerCase();
  if (!q) { panel.hidden = true; return; }
  const has = (...parts) => parts.join(" ").toLowerCase().includes(q);
  const findings = visible();
  const checks = (state.checks || []).filter(c => has(c.title, c.detail, c.job, c.where));
  const jobs = (state.jobs || []).filter(j => has(j.name, j.label));
  document.getElementById("resulthead").textContent =
    `${findings.length} finding${findings.length === 1 ? "" : "s"} · ${checks.length} verified-clean check${checks.length === 1 ? "" : "s"} · ${jobs.length} collector${jobs.length === 1 ? "" : "s"} match “${query.trim()}”`;
  const row = (sev, job, title, detail, act) =>
    `<li data-click="jump" data-arg="${act}"><span>${pill(sev)}</span><span class="tag">${esc(job)}</span><span><span class="t">${esc(title)}</span> <span class="d">${esc(String(detail || "").slice(0, 120))}</span></span></li>`;
  document.getElementById("resultlist").innerHTML =
    findings.slice(0, 8).map(f => row(f.severity, f.job, f.title, f.detail, "findings-section")).join("") +
    checks.slice(0, 4).map(c => row("ok", c.job, c.title, c.detail, "checks")).join("") +
    jobs.slice(0, 4).map(j => row(j.error ? "high" : j.stale ? "medium" : "ok", j.name, j.label || j.name, j.error || (j.stale ? "stale" : "fresh"), "monitoring")).join("") ||
    `<li><span></span><span></span><span class="d">nothing matches</span></li>`;
  panel.hidden = false;
}
function toggleGroup() { grouped = !grouped; open.clear(); if (state) render(state); }
function toggle(id) {
  open.has(id) ? open.delete(id) : open.add(id);
  renderFindings();
}
function setTab(t) {
  tab = t;
  for (const id of ["peers", "internet", "events", "intel", "ops"]) {
    document.getElementById("tab-" + id).className = t === id ? "on" : "";
  }
  if (state) renderSide(state);
}

/* ---------- ops & setup: copy-paste command reference ---------- */
function cp(el, text) {
  navigator.clipboard.writeText(text).then(() => {
    const was = el.textContent; el.textContent = "copied"; el.className = "on";
    setTimeout(() => { el.textContent = was; el.className = ""; }, 1200);
  }).catch(() => {});
}
function renderOps() {
  const port = location.port || "8787";
  const url = location.origin;
  const groups = [
    ["Quickstart — one command (run in WSL)", [
      ["Everything: service, seal, cleanup, browser + firewall + ASR (pops one UAC)", "./quickstart.sh"],
      ["Linux side only, no Windows bridge calls", "./quickstart.sh --no-windows"],
      ["Skip the sudo hardening", "./quickstart.sh --no-priority"],
      ["Health summary only", "./quickstart.sh --check"],
    ]],
    ["Windows hardening (if you skipped the UAC prompt)", [
      ["Firewall logging + ASR rules — elevated PowerShell", "powershell -ExecutionPolicy Bypass -File \"%LOCALAPPDATA%\\Jarvis\\harden-elevated.ps1\""],
      ["Flip ASR from audit to enforce", "powershell -ExecutionPolicy Bypass -File \"%LOCALAPPDATA%\\Jarvis\\harden-elevated.ps1\" -Enforce"],
      ["Undo firewall + ASR", "powershell -ExecutionPolicy Bypass -File \"%LOCALAPPDATA%\\Jarvis\\harden-elevated.ps1\" -Undo"],
      ["Keep WSL alive across reboot (already done by quickstart)", "powershell -ExecutionPolicy Bypass -File .\\quickstart.ps1"],
    ]],
    ["Service control", [
      ["Status", "systemctl status jarvis.service --no-pager"],
      ["Restart", "sudo systemctl restart jarvis.service"],
      ["Reload changed unit files", "sudo systemctl daemon-reload"],
      ["Live logs", "journalctl -u jarvis.service -f -o cat"],
      ["Self-check timer", "systemctl --user list-timers jarvis-selfcheck.timer"],
    ]],
    ["Run a collector now", [
      ["One job", `curl -fsS -X POST '${url}/api/run?job=controls' -H 'Origin: ${url}'`],
      ["Every job (or use “run all” above)", "for j in $(jarvis status --jobs); do jarvis $j; done"],
      ["From the CLI, print result", "jarvis coverage"],
    ]],
    ["Health check", [
      ["Are all collectors current?", `curl -fsS ${url}/api/state | python3 -c 'import json,sys,time; d=json.load(sys.stdin); j=d["jobs"]; print("stale:", [x["name"] for x in j if x.get("stale")] or "none"); print("errored:", [x["name"] for x in j if x.get("error")] or "none")'`],
      ["Dashboard URL", url],
      ["Port in use by", `ss -ltnp | grep ${port}`],
    ]],
  ];
  document.getElementById("side").innerHTML =
    `<div class="panelnote">Commands run on the host, not in the browser. Click a row to copy. Paths are relative to the checkout (~/jarvis).</div>` +
    groups.map(([name, rows]) => `
      <div class="groupname">${esc(name)}</div>
      <table><tbody>${rows.map(([label, cmd]) => `
        <tr>
          <td style="width:38%">${esc(label)}</td>
          <td><code class="pre">${esc(cmd)}</code></td>
          <td style="width:56px"><button data-act="copy" data-copy="${esc(cmd)}">copy</button></td>
        </tr>`).join("")}</tbody></table>`).join("");
}
function clearAll() {
  sevFilter = null; jobFilter = ""; hostFilter = ""; query = ""; findingLimit = FINDING_BATCH;
  document.getElementById("q").value = ""; open.clear();
  if (state) render(state);
}
function togglePause() {
  paused = !paused;
  document.getElementById("pause").textContent = paused ? "Resume" : "Pause";
  document.getElementById("pause").className = paused ? "on" : "";
  document.getElementById("beat").className = "beat " + (paused ? "off" : "on");
  document.getElementById("livetxt").textContent = paused ? "paused" : "live";
  if (!paused) tick();
}
async function runJob(n) {
  await fetch("/api/run?job=" + encodeURIComponent(n), { method: "POST" });
  setTimeout(tick, 400);
}
async function runAll() {
  if (!state) return;
  for (const j of state.jobs) {
    await fetch("/api/run?job=" + encodeURIComponent(j.name), { method: "POST" });
  }
  setTimeout(tick, 400);
}

/* The score coach: the same projection the protocols engine uses, rendered
   into the chat box. Deterministic — no model call, so it is instant. */
async function scoreCoach() {
  const output = document.getElementById("askanswer");
  output.textContent = "Computing the plan from live data…";
  try {
    const response = await fetch("/api/score-coach", { method: "POST" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || response.status);
    output.dataset.kind = "answer";
    output.innerHTML = esc(data.answer) +
      `<div class="chat-source">score coach · computed from the real scoring code · no model</div>`;
  } catch (error) {
    output.textContent = "Could not compute the plan: " + error.message;
  }
}

/* ---------- ARGUS-INSTINCT speaks first ----------
   The chat opens with a briefing built from live data on the server (no model,
   so it is instant and cannot invent a status), and any question ARGUS-INSTINCT is
   waiting on comes with its answer buttons. */
function showJarvis(text, pending, source) {
  const buttons = pending ? `
    <div class="question-actions">${["yes", "no"].map(choice =>
      `<button data-protocol="${esc(pending.protocol)}" data-choice="${choice}"
               data-click="protocol">${choice === "yes" ? "Yes" : "No"}</button>`).join("")}
    </div>` : "";
  const lines = String(text || "").split("\n").filter(Boolean).map(l =>
    `<p class="${/^First, a quick heads-up/.test(l) ? "warn" : ""}">${esc(l)}</p>`).join("");
  const box = document.getElementById("askanswer");
  box.innerHTML = `<div class="greet">${lines}</div>` + buttons +
    `<div class="chat-source">${esc(source)}</div>`;
}

let greetedScore = null, greetedAt = 0;
function refreshGreeting(s) {
  if (!s.security || !greetedAt) return;
  if (greetedScore === null) { greetedScore = s.security.score; return; }
  const moved = s.security.score !== greetedScore;
  if (moved || Date.now() - greetedAt > 300000) greet(false);
}

async function greet(speak = true) {
  greetedAt = Date.now();
  if (state && state.security) greetedScore = state.security.score;
  try {
    const response = await fetch("/api/greeting", { cache: "no-store" });
    if (!response.ok) throw new Error(response.status);
    const data = await response.json();
    // Do not overwrite an answer the user is reading.
    const box = document.getElementById("askanswer");
    if (!speak && box.dataset.kind === "answer") return;
    showJarvis(data.text, data.pending, "briefing from live data · " +
               new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
    box.dataset.kind = "greeting";
    if (greetedScore === null && state && state.security) greetedScore = state.security.score;
    if (speak && voice) briefAloud(data.text.split("\n").slice(0, 3));
  } catch (error) {
    document.getElementById("askanswer").textContent =
      "ARGUS-INSTINCT could not brief you yet: " + error.message;
  }
}

async function answerProtocol(button) {
  const {protocol, choice} = button.dataset;
  button.parentElement.querySelectorAll("button").forEach(b => b.disabled = true);
  try {
    const response = await fetch("/api/brief", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({protocol, choice})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || data.error || response.status);
    const next = data.pending ? "\n\n" + data.pending.question : "";
    showJarvis(data.message + next, data.pending, "answer recorded by ARGUS-INSTINCT");
    document.getElementById("askanswer").dataset.kind = "answer";
    say(data.message);
  } catch (error) {
    document.getElementById("askanswer").textContent = "Could not record answer: " + error.message;
  }
}

async function answerQuestion(id, choice) {
  const output = document.getElementById("askanswer");
  try {
    const response = await fetch("/api/answer", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({id, choice})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || data.error || response.status);
    output.dataset.kind = "answer";
    output.innerHTML = esc(data.message) +
      `<div class="chat-source">explicit answer recorded by ARGUS-INSTINCT</div>`;
    toast(data.message, "good", "answer recorded");
    await tick();
  } catch (error) {
    output.textContent = "Could not record answer: " + error.message;
  }
}

/* ---------- spoken security briefing ----------
   Speaks what a person watching this dashboard would want to hear without
   reading it: threats that need action now, monitoring that broke, and new
   high findings. Diffed against what was already said, so it stays quiet
   until something changes. Press v to re-brief the full status on demand. */
let voice = false, voicePrimed = false, spokenKeys = new Set(), lostConn = false;
let voiceName = "", briefToken = 0;
try { voice = localStorage.getItem("jarvis.voice") === "1"; } catch (e) {}
try { voiceName = localStorage.getItem("jarvis.voiceName") || ""; } catch (e) {}

/* A butler should sound like one: prefer a British English voice, male if the
   system names one, and remember whatever the user picks instead. */
function voices() { return window.speechSynthesis ? speechSynthesis.getVoices() : []; }
function chosenVoice() {
  const all = voices();
  return all.find(v => v.name === voiceName)
    || all.find(v => /en[-_]GB/i.test(v.lang) && /ryan|george|daniel|arthur|male|thomas|oliver/i.test(v.name))
    || all.find(v => /en[-_]GB/i.test(v.lang))
    || all.find(v => /^en/i.test(v.lang)) || null;
}
function fillVoices() {
  const sel = document.getElementById("voicesel");
  const all = voices().filter(v => /^en/i.test(v.lang));
  if (!sel || !all.length) { if (sel) sel.style.display = "none"; return; }
  const cur = chosenVoice();
  sel.style.display = "";
  sel.innerHTML = all.map(v => `<option value="${esc(v.name)}" ${cur && cur.name === v.name ? "selected" : ""}>${
    esc(v.name.replace(/^Microsoft |^Google /, "").replace(/ Online \(Natural\)/, " ✦"))} · ${esc(v.lang)}</option>`).join("");
}
function pickVoice() {
  voiceName = document.getElementById("voicesel").value;
  try { localStorage.setItem("jarvis.voiceName", voiceName); } catch (e) {}
  if (voice) { speechSynthesis.cancel(); say("Very good. I shall sound like this from now on."); }
}
if (window.speechSynthesis) { fillVoices(); speechSynthesis.onvoiceschanged = fillVoices; }

function setOrb(mode) {
  document.getElementById("orb").className = "orb " + (mode || (voice ? "on" : ""));
}
function caption(text, note) {
  document.getElementById("caption").innerHTML = esc(text) + (note ? `<small>${esc(note)}</small>` : "");
}
function idleCaption() {
  if (voice) caption("Listening for changes.", "Press v or “brief me” for a spoken briefing.");
  else caption("Voice is off.", "Press v for a spoken briefing.");
  setOrb();
}

function say(text) {
  if (!voice || !text || !window.speechSynthesis) return;
  // Spoken, the name is "Argus One": voices read "ARGUS-INSTINCT" as letters or "minus one".
  const u = new SpeechSynthesisUtterance(brand(text).replace(/\bARGUS-INSTINCT\b/g, "Argus One"));
  const v = chosenVoice();
  if (v) u.voice = v;
  u.lang = v ? v.lang : "en-GB"; u.rate = 1.02; u.pitch = 0.95;
  u.onstart = () => { setOrb("speak"); caption(text, "speaking"); };
  u.onend = u.onerror = () => { if (!speechSynthesis.pending && !speechSynthesis.speaking) idleCaption(); };
  speechSynthesis.speak(u);
}

/* Visible twin of every spoken event, so a muted tab still hears the news. */
function toast(text, kind, note) {
  const box = document.getElementById("toasts");
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.innerHTML = esc(text) + (note ? `<small>${esc(note)}</small>` : "");
  box.appendChild(el);
  while (box.children.length > 3) box.firstChild.remove();
  setTimeout(() => el.remove(), 9000);
}
function announce(text, kind, note) { text = brand(text); toast(text, kind, note); say(text); }

/* The model writes only the opening line. It is fetched first, then the
   deterministic lines follow, so facts never wait on or come from the model;
   a slow model is dropped after 20 seconds and the facts are spoken plain. */
async function briefAloud(lines) {
  if (!voice || !window.speechSynthesis) return;
  const token = ++briefToken;
  speechSynthesis.cancel();
  setOrb("think"); caption("Composing a briefing…", "local model");
  let opener = "", byModel = false;
  const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 20000);
  try {
    const live = state ? (state.findings || []).filter(urgent).length : 0;
    const r = await fetch("/api/voice", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ live_alerts: live }), signal: ctl.signal });
    if (r.ok) { const d = await r.json(); opener = d.line || ""; byModel = !!d.by_model; }
  } catch (e) { /* timed out or offline: speak the facts alone */ }
  clearTimeout(timer);
  if (token !== briefToken || !voice) return;
  const op = document.getElementById("opener");
  op.textContent = brand(opener);
  op.title = byModel ? "written by the local model, checked against the facts" : "ARGUS-INSTINCT's written-in line";
  if (opener) say(opener);
  lines.filter(Boolean).forEach(say);
  if (!opener && !lines.length) idleCaption();
}
function briefNow() {
  if (!voice) { toggleVoice(); return; }
  if (state) voiceBrief(state, true);
}
function firstClause(s) {
  return String(s || "").split(/[—;]| - /)[0].trim().slice(0, 150);
}
/* Never voiced: coverage-gap accounting and standing config issues belong on
   the screen, not read aloud every time the tab opens. */
function isNoise(f) {
  const c = (f.category || "").toLowerCase();
  return f.job === "gaps" || f.job === "scan" ||
    c === "coverage gap" || c === "not observable" || c === "visibility" || c === "limits" ||
    /named in threat intelligence exists|deprecated or unrecognised/i.test(f.title || "");
}
/* Live, host-local, do-something-now. Matched by explicit job+pattern, not by
   severity alone (a critical plaintext-secret finding is real but not urgent). */
/* Live items worth a red badge and "needs you now": tier 1 at critical or
   high. Medium tier-1 events stay on the board and are counted separately. */
function urgent(f) {
  return (f.severity === "critical" || f.severity === "high") && !isNoise(f) && !!tier1(f);
}
function tier1(f) {
  const t = (f.title || "").toLowerCase(), c = (f.category || "").toLowerCase();
  if (f.job === "input" && /inject|synthetic/.test(t) && f.severity !== "ok" && f.severity !== "low")
    return "Synthetic input detected. " + firstClause(f.detail);
  if (f.job === "controls" && /in use right now/.test(t))
    return f.title + ". " + firstClause(f.detail);
  if (c === "intel match" && f.severity === "critical")
    return "Known-attacker indicator. " + f.title;
  if (/\bspawned a shell\b|connect-back argument|reverse shell/.test(t))
    return "Possible post-exploitation. " + f.title;
  if (/owned by an invisible process|process is hidden from|invisible from the process/.test(t))
    return "Hidden process. " + f.title + ". " + firstClause(f.detail);
  if (c === "credential access")
    return "Credential access. " + f.title;
  if (/defender detected a threat/.test(t) && !/not active/i.test(f.detail || ""))
    return "Active malware detection. " + firstClause(f.detail);
  return null;
}

function voiceItems(s) {
  const out = [], F = (s.findings || []).filter(f => !isNoise(f));
  for (const f of F) {
    const key = (f.job || "") + "|" + (f.title || "") + "|" + (f.where || "");
    const a = tier1(f);
    if (a) { out.push({ key, tier: 1, text: a }); continue; }
    const t = (f.title || "").toLowerCase();
    if (f.job === "controls" && /(changed|appeared|removed)/.test(t))
      out.push({ key, tier: 3, text: "Control surface. " + f.title + ". " + firstClause(f.detail) });
    else if (f.severity === "critical")
      out.push({ key, tier: 3, kind: "crit", text: f.title || "" });
    else if (f.severity === "high")
      out.push({ key, tier: 3, kind: "high", text: f.title || "" });
  }
  for (const j of (s.jobs || [])) {
    if (j.error) out.push({ key: "err|" + j.name, tier: 2,
      text: "The " + j.name + " collector errored and is not reporting." });
    else if (j.stale) out.push({ key: "stale|" + j.name, tier: 2,
      text: "The " + j.name + " collector went stale and stopped producing results." });
  }
  const bridge = (s.jobs || []).find(j => j.name === "bridge");
  if (bridge && (bridge.stale || bridge.error))
    out.push({ key: "bridge-down", tier: 2, text: "Windows monitoring is offline. The bridge is down." });
  if ((s.findings || []).some(f => /injected-input monitor (is|has gone) (down|not running|quiet)/i.test(f.title || "")))
    out.push({ key: "hook-down", tier: 2, text: "The keystroke monitor is down. Synthetic input is not being watched." });
  return out;
}

function statusLine(s) {
  const jobs = s.jobs || [], F = (s.findings || []).filter(f => !isNoise(f));
  const cur = jobs.filter(j => j.ts && !j.stale && !j.error).length;
  const bad = jobs.filter(j => j.stale || j.error).map(j => j.name);
  const crit = F.filter(f => f.severity === "critical").length;
  const high = F.filter(f => f.severity === "high").length;
  const acts = F.filter(urgent).length;
  const minor = F.filter(f => tier1(f) && !urgent(f)).length;
  const bridge = jobs.some(j => j.name === "bridge" && !j.stale && !j.error) ? "up" : "down";
  const hook = F.some(f => /injected-input monitor (is|has gone) (down|not running|quiet)/i.test(f.title || "")) ? "down"
             : (s.checks || []).some(f => /injected-input monitor is healthy/i.test(f.title || "")) ? "healthy" : "unknown";
  const live = F.filter(f => /in use right now/i.test(f.title || ""))
                .map(f => (f.title || "").replace(/ in use right now/i, "").trim());
  const sec = s.security, pr = progress(s);
  let out = "";
  if (sec) {
    out += "Security health " + sec.score + " percent, " + sec.grade + ". ";
    if (pr.score > 0) out += "Up " + pr.score + " points today. Nicely done. ";
    else if (pr.score < 0) out += "Down " + (-pr.score) + " points today, very recoverable. ";
  }
  if ((s.checks || []).length) out += (s.checks || []).length + " checks verified clean. ";
  out += acts ? (acts + " live item" + (acts > 1 ? "s" : "") + " need" + (acts > 1 ? "" : "s") + " you now. ")
              : "No urgent live alerts right now. ";
  if (minor) out += minor + " smaller live event" + (minor > 1 ? "s" : "") + " on the board to glance at. ";
  const next = sec && (sec.next_steps || [])[0];
  if (next) out += "Best next win: " + next.title + ". ";
  else if (crit + high) out += (crit + high) + " important findings are waiting on the board. ";
  out += cur + " of " + jobs.length + " collectors current";
  if (bad.length) out += ", " + bad.length + " not reporting, so the picture is partial";
  out += ". Windows bridge " + bridge + ". Keystroke monitor " + hook + ".";
  if (live.length) out += " In use now: " + live.join(", ") + ".";
  return out;
}

function voiceBrief(s, force) {
  if (!s) return;
  const items = voiceItems(s);
  const present = new Set(items.map(i => i.key));
  const watching = new Set((s.jobs || []).filter(j => j.ts && !j.stale && !j.error).map(j => j.name));
  const gone = [];
  for (const k of [...spokenKeys]) if (!present.has(k)) {
    spokenKeys.delete(k);
    const [job, title] = k.split("|");
    if (title && watching.has(job)) gone.push(title);   // blind is not fixed
  }

  if (!voicePrimed && !force) {           // first data after opening: learn, don't announce
    items.forEach(i => spokenKeys.add(i.key));
    voicePrimed = true;
    return;
  }
  voicePrimed = true;
  const out = [];                          // [text, toast kind]
  if (!force && gone.length) {
    out.push([gone.length === 1 ? "Good news. " + gone[0] + " is no longer showing."
      : "Good news. " + gone.length + " findings are no longer showing, including " + gone[0] + ".", "good"]);
  }

  const fresh = items.filter(i => !spokenKeys.has(i.key)).sort((a, b) => a.tier - b.tier);
  fresh.filter(i => i.tier < 3).forEach(i => out.push([i.text, i.tier === 1 ? "alert" : "warn"]));

  const ctl = fresh.filter(i => i.tier === 3 && !i.kind);
  ctl.slice(0, 3).forEach(i => out.push([i.text, "warn"]));
  if (ctl.length > 3) out.push([(ctl.length - 3) + " more control-surface changes.", "warn"]);

  const nc = fresh.filter(i => i.kind === "crit").length;
  const nh = fresh.filter(i => i.kind === "high").length;
  const firstNew = fresh.find(i => i.kind === "crit") || fresh.find(i => i.kind === "high");
  if (!force && nc + nh === 1) out.push(["Something new worth a look: " + firstNew.text + ".", "warn"]);
  else if (!force && nc + nh) out.push([(nc + nh) + " new findings worth a look, starting with " + firstNew.text +
                                        ". Caught early, which is the whole idea.", "warn"]);
  fresh.forEach(i => spokenKeys.add(i.key));

  if (force) {
    briefAloud([statusLine(s), ...out.map(o => o[0])]);
  } else {
    out.forEach(([text, kind]) => announce(text, kind, "just now"));
  }
}

function toggleVoice() {
  voice = !voice;
  try { localStorage.setItem("jarvis.voice", voice ? "1" : "0"); } catch (e) {}
  const b = document.getElementById("voice");
  b.className = voice ? "on" : "";
  b.textContent = voice ? "voice on" : "voice";
  if (!voice) { briefToken++; window.speechSynthesis && speechSynthesis.cancel(); idleCaption(); return; }
  fillVoices();
  if (state) voiceBrief(state, true);
  else say("Voice briefing on. Waiting for data.");
}
(function () {
  const b = document.getElementById("voice");
  if (b && voice) { b.className = "on"; b.textContent = "voice on"; }
  idleCaption();
})();

document.addEventListener("keydown", e => {
  if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT") {
    if (e.key === "Escape") { e.target.blur(); clearAll(); }
    if (e.key === "Enter" && e.target.id === "q" && query.trim()) jump("findings-section");
    return;
  }
  if (e.key === "/") { e.preventDefault(); document.getElementById("q").focus(); }
  else if (e.key === "r") tick();
  else if (e.key === "v") { if (!voice) toggleVoice(); else voiceBrief(state, true); }
  else if (e.key === " ") { e.preventDefault(); togglePause(); }
  else if (e.key === "Escape") clearAll();
});

const STATE_TIMEOUT_MS = 15000;
function loadNotice(message) {
  const el = document.getElementById("loadnotice");
  document.getElementById("loadmessage").textContent = message || "";
  el.hidden = !message;
}

/* ---------- application shell: views, sidebar drawer ----------
   One page, several views. The location hash names the view, so the back and
   forward buttons, bookmarks and the old anchors (#priorities, #findings-section,
   #monitoring ...) all still land somewhere sensible. Filters, search text and
   expanded rows live in page state, so they survive switching views. */
const VIEWS = { overview: "Overview", security: "Security", accounts: "Accounts", network: "Network",
                monitoring: "Monitoring", assistant: "Assistant", pricing: "Pricing", settings: "Settings" };
const LEGACY = { priorities: "security", "findings-section": "security", findings: "security", reviewqueue: "security",
                 checks: "security", more: "network", geocard: "network", "score-details": "overview" };
let currentView = "overview", assistantChecked = false;
const $ = id => document.getElementById(id);

function viewOf(id) {
  if (VIEWS[id]) return id;
  if (LEGACY[id]) return LEGACY[id];
  const el = $(id), host = el && el.closest("[data-views]");
  return host ? host.dataset.views.split(" ")[0] : null;
}
function showView(v, opts = {}) {
  if (!VIEWS[v]) v = "overview";
  currentView = v;
  document.body.dataset.view = v;
  for (const a of document.querySelectorAll("#sidenav a[data-view]")) {
    if (a.dataset.view === v) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  document.title = `${VIEWS[v]} · ${BRAND}`;
  if (v === "network" && !["peers", "internet"].includes(tab)) setTab("peers");
  if (v === "settings" && !["ops", "events", "intel"].includes(tab)) setTab("ops");
  closeDrawer(false);
  if (v === "assistant" && !assistantChecked) { assistantChecked = true; refreshModelStatus(); }
  if (opts.focus) { window.scrollTo(0, 0); const h = $("h-" + v); if (h) h.focus({ preventScroll: true }); }
}
function routeFromHash(initial) {
  const id = decodeURIComponent(location.hash.slice(1));
  // Focus moves to the new heading only when the user navigates. On first load it stays at the
  // top of the page, so the first Tab reaches the skip link and the sidebar.
  showView(id ? (viewOf(id) || "overview") : "overview", { focus: initial !== true });
  if (id && !VIEWS[id]) {
    const el = $(id);
    if (el) { const d = el.closest("details"); if (d) d.open = true; requestAnimationFrame(() => el.scrollIntoView({ block: "start" })); }
  }
}
function go(v) { if (location.hash.slice(1) === v) routeFromHash(); else location.hash = v; }
function jump(id) {
  const v = viewOf(id);
  if (v && v !== currentView) go(v);
  const el = $(id);
  if (el && !VIEWS[id]) { const d = el.closest("details"); if (d) d.open = true; setTimeout(() => el.scrollIntoView({ behavior: "smooth", block: "start" }), 60); }
}
window.addEventListener("hashchange", routeFromHash);

/* narrow screens: the sidebar is a drawer. While it is open the page behind it is inert,
   so focus stays inside the drawer; Escape, the scrim and choosing a destination close it. */
function drawerOpen() { return $("sidebar").classList.contains("open"); }
function openDrawer() {
  $("sidebar").classList.add("open"); $("scrim").hidden = false; $("content").inert = true;
  $("menu").setAttribute("aria-expanded", "true");
  const first = document.querySelector("#sidenav a"); if (first) first.focus();
}
function closeDrawer(restoreFocus = true) {
  if (!drawerOpen()) return;
  $("sidebar").classList.remove("open"); $("scrim").hidden = true; $("content").inert = false;
  $("menu").setAttribute("aria-expanded", "false");
  if (restoreFocus) $("menu").focus();
}
$("menu").addEventListener("click", () => (drawerOpen() ? closeDrawer() : openDrawer()));
$("scrim").addEventListener("click", () => closeDrawer());
document.addEventListener("keydown", e => { if (e.key === "Escape" && drawerOpen()) { e.preventDefault(); closeDrawer(); } });
window.matchMedia("(min-width: 1101px)").addEventListener("change", e => { if (e.matches) closeDrawer(false); });

/* ---------- level of detail: Simple (default) or Advanced ----------
   One set of components with two depths, not two interfaces. Advanced opens the technical sections and shows
   identifiers; Simple keeps plain language first. The choice is remembered in this browser only. */
const DETAIL_KEY = "jarvis.detail";
let detailLevel = "simple";
function applyDetail(d) {
  detailLevel = d === "advanced" ? "advanced" : "simple";
  document.body.dataset.detail = detailLevel;
  for (const b of document.querySelectorAll("#detaillevel button")) {
    b.setAttribute("aria-pressed", String(b.dataset.d === detailLevel));
    b.className = b.dataset.d === detailLevel ? "on" : "";
  }
}
function setDetail(d) {
  try { localStorage.setItem(DETAIL_KEY, d); } catch (_) {}
  applyDetail(d);
  if (state) render(state);
}
applyDetail((() => { try { return localStorage.getItem(DETAIL_KEY); } catch (_) { return "simple"; } })());

/* ---------- plain-language pieces ---------- */
const KIND_ICON = { suspicious: "alert", confirmed: "sliders", monitoring: "monitoring", info: "info", unverified: "help" };
const ico = name => `<svg class="ico" aria-hidden="true"><use href="#i-${name}"/></svg>`;
function jobLabel(job) { const j = (state && state.jobs || []).find(x => x.name === job); return j ? (j.label || j.name) : job; }
const GLOSS_KEYS = Object.keys(GLOSSARY);
const GLOSS_RE = new RegExp("\\b(" + GLOSS_KEYS.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")\\b", "gi");
/* Wrap known terms in already-escaped static text so a definition is one hover or keyboard focus away. */
function gloss(escaped) {
  return escaped.replace(GLOSS_RE, m => {
    const key = GLOSS_KEYS.find(k => k.toLowerCase() === m.toLowerCase());
    return `<span class="gl" tabindex="0" role="note" data-def="${esc(GLOSSARY[key])}">${m}</span>`;
  });
}
const liHTML = items => `<ul>${items.map(i => `<li>${gloss(esc(i))}</li>`).join("")}</ul>`;
const copyBtn = (text, label) => text ? `<button class="quiet copy" data-act="copy" data-copy="${esc(text)}" aria-label="Copy ${esc(label)}">Copy</button>` : "";
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied to the clipboard.", "good"); }
  catch (_) { toast("Could not copy automatically. Select the text and copy it yourself.", "warn"); }
}

/* One finding, one explanation: what, where, why flagged, what it could mean, how sure, what to do, the evidence. */
function findingCardHTML(g, compact) {
  const f = g.sample, ex = explainFinding(f, state && state.findings), st = ex.state, adv = detailLevel === "advanced";
  const j = (state && state.jobs || []).find(x => x.name === f.job) || {};
  const where = [...new Set(g.items.map(x => x.where).filter(Boolean))].slice(0, 5);
  const row = (k, v) => `<dt>${esc(k)}</dt><dd>${v}</dd>`;
  const sec = (title, body) => `<section class="fxs"><h4>${esc(title)}</h4>${body}</section>`;
  const meaning = compact ? "" : sec("What it could mean", `
      <div class="fxcols"><div><h5>What ARGUS-INSTINCT observed</h5>${liHTML(ex.facts)}</div>
      <div><h5>Possible risk</h5>${liHTML(ex.risks)}</div>
      <div><h5>Ordinary explanations</h5>${liHTML(ex.benign)}</div>
      <div><h5>Not known</h5>${liHTML(ex.unknown)}</div></div>`);
  const confidence = compact ? "" : sec("How confident is ARGUS-INSTINCT?", `<p><b>${esc(ex.confidence.strength)}.</b> ${esc(ex.confidence.text)}</p>`);
  const actions = compact ? sec("What you can do first", `<p>${gloss(esc(ex.next))}</p>`)
    : sec("What you can do", `<ol>${ex.steps.map(x => `<li>${gloss(esc(x))}</li>`).join("")}${f.id
        ? `<li>To mark it as expected, run <code>jarvis ack ${esc(f.id)} --reason "..."</code> in a terminal. That is not available from this page.</li>` : ""}</ol>`);
  return `<article class="fx k-${st.key}">
    <div class="fxh"><span class="kind k-${st.key}">${ico(KIND_ICON[st.key])}${esc(st.label)}</span>
      <span class="sev">${esc(ex.severity)}${adv ? ` (${esc(f.severity)})` : ""}</span>${g.count > 1 ? `<span class="sev">· ${g.count} found</span>` : ""}</div>
    <h3>${esc(f.title)}</h3>
    ${sec("What was found", `<p>${gloss(esc(ex.what))} ${esc(clip(f.detail || "", 160))}</p>`)}
    ${sec("Where", where.length ? `<ul class="where">${where.map(w => `<li><code>${esc(clip(w, 300))}</code> ${copyBtn(redact(w), "location")}</li>`).join("")}</ul>`
        : `<p>ARGUS-INSTINCT did not record a location for this finding.</p>`)}
    ${sec("Why ARGUS-INSTINCT flagged it", `<p>${gloss(esc(ex.whyFlagged))}</p>`)}
    ${meaning}${confidence}
    <p class="unc"><b>Still uncertain:</b> ${esc(st.note)}</p>
    ${actions}
    <div class="fxa">
      <button data-act="tech">View evidence and details</button>
      ${f.id ? `<button data-act="explain" data-id="${esc(f.id)}">Ask the assistant to explain</button>` : ""}
      <button data-act="investigate" data-q="${esc(f.title)}" data-id="${esc(f.id || "")}" data-job="${esc(f.job || "")}">Investigate</button>
    </div>
    <details class="tech" ${adv ? "open" : ""}><summary>Technical details</summary><dl class="kv">
      ${row("severity", esc(f.severity))}${row("category", esc(f.category || "-"))}
      ${row("collector", `${esc(jobLabel(f.job))} <span class="faint">(${esc(f.job)})</span>`)}
      ${row("host", esc(f.host || "-"))}${row("last checked", esc(ago(j.ts)))}
      ${row("location", where.length ? where.map(esc).join("<br>") : "-")}
      ${row("detail", esc(clip(f.detail || "-", 600)))}
      ${row("evidence basis", esc(ex.confidence.points.join("; ")))}
      ${row("verification", "Observed by the collector. Not independently verified.")}
      ${f.id ? row("finding id", `<code>${esc(f.id)}</code> ${copyBtn(f.id, "finding id")}`) : ""}
      ${(f.forensics || []).length ? row("forensics", `<pre class="pre">${esc(f.forensics.join("\n"))}</pre>`) : ""}
    </dl></details>
  </article>`;
}
function monitorCardHTML(p) {
  const st = (p.state === "never_ran" || p.state === "stale") ? { key: "unverified", label: "Not verified" } : { key: "monitoring", label: "A problem with ARGUS-INSTINCT" };
  const ex = explainMonitor(p), sec = (t, b) => `<section class="fxs"><h4>${esc(t)}</h4>${b}</section>`;
  return `<article class="fx k-${st.key}">
    <div class="fxh"><span class="kind k-${st.key}">${ico(KIND_ICON[st.key])}${esc(st.label)}</span>
      <span class="sev">coverage: ${esc(p.coverage || "blind")}</span></div>
    <h3>${esc(ex.headline)}</h3>
    ${sec("What this check looks at", `<p>${esc(ex.checks)}</p>`)}
    ${sec("Is it working?", `<p><b>${ex.working}.</b> Last successful result: ${esc(ex.lastGood)}.${p.error ? ` Recorded error: ${esc(clip(p.error, 160))}.` : ""}</p>`)}
    ${sec("What is unavailable", `<p>${esc(ex.unavailable)}</p><p>${esc(ex.caution)}</p>`)}
    ${sec("Does it affect the overall status?", `<p>${esc(ex.affects)}</p>`)}
    ${sec("What you can do", liHTML(ex.next.length ? ex.next : ["Open Monitoring for the reason."]))}
    <div class="fxa">
      <button data-act="go" data-go="monitoring">View monitoring status</button>
      <button data-act="checkmon" data-job="${esc(p.id)}">Ask the assistant to check</button>
      <button data-act="rerun" data-job="${esc(p.id)}">Re-run this check</button>
    </div></article>`;
}

/* ---------- the Overview ---------- */
function renderOverview(s) {
  const m = overviewModel(s), tot = m.totals, att = attentionItems(s, 5), nx = nextStep(s), c = m.counts;
  const pend = (s.assistant && s.assistant.pending) || [];
  const icon = { attention: "alert", review: "info", incomplete: "help", ok: "check", info: "monitoring", unknown: "help" }[m.level];
  const st = $("ov-status");
  st.dataset.level = m.level;
  st.innerHTML = `<h2>${ico(icon)}${esc(m.headline)}</h2>${m.parts.map(t => `<p>${esc(t)}</p>`).join("")}
    <p class="lastline"><b>${esc(m.lastLine)}</b> ${esc(m.monLine)}</p>
    ${m.scoreLine ? `<p class="score">${esc(m.scoreLine)} <button data-act="go" data-go="how-score">How is this calculated?</button></p>` : ""}
    <ul class="ovcounts" aria-label="Counts">
      <li><b>${c.total}</b> findings in total</li><li><b>${c.serious}</b> marked serious</li>
      <li><b>${c.notReporting}</b> checks not reporting</li><li><b>${c.unverified}</b> not yet verified</li>
      <li class="adv"><b>${c.monitoringFindings}</b> monitoring findings</li>
      <li class="adv"><b>${c.suspicious}</b> suspicious activity</li><li class="adv"><b>${c.confirmed}</b> confirmed settings</li>
      <li class="adv"><b>${c.expected}</b> marked as expected</li></ul>
    <p class="ovfoot">ARGUS-INSTINCT reports what it observed. It never declares an attack confirmed on its own.</p>`;
  $("ov-pending").innerHTML = pend.length ? `<div class="ovpend" role="group" aria-label="Waiting for your decision">
      <span class="kind k-confirmed">${ico("help")}${esc(LIFECYCLE.awaiting_approval[0])}</span>
      <span>${esc(pend[0].title)}. ${esc(LIFECYCLE.awaiting_approval[1])} You can decline.</span>
      <button data-act="openproposal">Review and decide</button></div>` : "";
  $("ov-attn-cnt").textContent = att.total ? `showing ${att.items.length} of ${att.total}` : "";
  $("ov-attn").innerHTML = att.items.length
    ? att.items.map(i => i.kind === "finding" ? findingCardHTML(i.group, true) : monitorCardHTML(i.problem)).join("") +
      (att.total > att.items.length ? `<div class="ovactions"><button data-act="go" data-go="security">See all ${att.total} in Security</button></div>` : "")
    : `<p class="empty-good">Nothing in the current results needs your attention.</p>`;
  const pct = tot.total ? Math.round(100 * tot.verified / tot.total) : 0;
  $("ov-chk-cnt").textContent = tot.total ? `${tot.verified} of ${tot.total} reporting` : "";
  $("ov-checked").innerHTML = tot.total
    ? `<p><b>${tot.verified} of ${tot.total}</b> checks are reporting fresh, valid results.</p>
       <div class="ovmeter" role="img" aria-label="${pct} percent of checks reporting"><i style="width:${pct}%"></i></div>
       ${m.problems.length ? `<p>These are <b>not</b> counted as checked:</p><ul class="ovlist">${m.problems.slice(0, 5).map(p =>
          `<li><b>${esc(p.label)}</b><span class="kind k-${p.state === "never_ran" || p.state === "stale" ? "unverified" : "monitoring"}">${esc(p.state.replace(/_/g, " "))}</span><span class="why">${esc(p.reason || "")}</span></li>`).join("")}</ul>
          ${m.problems.length > 5 ? `<p class="faint">…and ${m.problems.length - 5} more.</p>` : ""}` : ""}
       ${tot.notApplicable ? `<p class="faint">${tot.notApplicable} more do not apply to this computer and are not counted.</p>` : ""}
       <p class="faint">${(s.checks || []).length} individual checks completed and found nothing.</p>
       <div class="ovactions"><button data-act="go" data-go="monitoring">View monitoring status</button>
         <a class="linkbtn" href="/coverage">Coverage map</a></div>`
    : `<p class="empty-good">No check results have arrived yet.</p>`;
  $("ov-next").innerHTML = `<p>${esc(nx.text)}</p><button data-act="${nx.act || "go"}" data-go="${esc(nx.go)}" ${nx.query ? `data-q="${esc(nx.query)}" data-id="${esc(nx.id || "")}" data-job="${esc(nx.job || "")}"` : ""}>${esc(nx.label)}</button>`;
  const mon = $("nav-mon");
  if (mon) { mon.textContent = m.problems.length || ""; mon.className = "n " + (m.problems.some(p => p.coverage === "blind") ? "bad" : "warn"); }
  $("side-foot").innerHTML = tot.total ? `<strong>${tot.verified} of ${tot.total} checks reporting</strong>${esc(m.headline)}` : "Waiting for results…";
}
function renderViewLists(s) {
  const fill = (listId, cntId, test, empty) => {
    const groups = groupFindings((s.findings || []).filter(f => kindOf(f) === "security" && test(f)));
    $(cntId).textContent = groups.length ? `${groups.length} item${groups.length === 1 ? "" : "s"}` : "";
    $(listId).innerHTML = groups.length
      ? groups.slice(0, 12).map(g => findingCardHTML(g, false)).join("") +
        (groups.length > 12 ? `<p class="faint">${groups.length - 12} more are in the Security view.</p>` : "")
      : `<p class="empty-good">${esc(empty)}</p>`;
  };
  const ACCOUNTS = new Set(["accounts", "impersonation", "data at rest"]), ACCOUNT_JOBS = new Set(["identity", "bruteforce", "secrets", "backdoor"]);
  const NETWORK = new Set(["peer", "network", "internet", "rules", "remote", "interception"]), NETWORK_JOBS = new Set(["firewall", "netwatch", "internet", "sniffing"]);
  fill("acc-list", "acc-cnt", f => ACCOUNTS.has(f.category) || ACCOUNT_JOBS.has(f.job),
       "Nothing about accounts or stored credentials is in the current results. That only covers the checks that are reporting.");
  fill("net-list", "net-cnt", f => NETWORK.has(f.category) || NETWORK_JOBS.has(f.job),
       "Nothing about the network is in the current results. That only covers the checks that are reporting.");
}
function renderDetectors(s) {
  const d = s.detector_health, el = $("detectors");
  if (!el) return;
  if (!d || !Array.isArray(d.detectors)) { el.innerHTML = `<p class="empty-good">Detector health is not available from this server.</p>`; return; }
  $("detectorsub").textContent = d.total ? `${(d.counts || {}).verified || 0} of ${d.total} verified` : "";
  const probs = new Map(monitoringProblems(s).map(p => [p.id, p]));
  const na = d.detectors.filter(x => x.state === "not_applicable");
  const row = x => {
    const ex = explainMonitor(probs.get(x.id) || { id: x.id, label: x.label, what: x.what || x.label, state: x.state, reason: x.reason, next: x.next_action, last: x.last_success, affects: x.affects_status, command: x.command });
    return `<details class="dhrow" ${detailLevel === "advanced" ? "open" : ""}><summary><span class="kind k-${x.coverage === "blind" ? "monitoring" : "unverified"}">${esc((x.state || "").replace(/_/g, " "))}</span>
      <b>${esc(x.label || x.id)}</b> <small>coverage: ${esc(x.coverage)}</small></summary>
      <dl class="kv more">
        <dt>What it checks</dt><dd>${esc(ex.checks)}</dd>
        <dt>Is it working?</dt><dd>${ex.working}. Last good result: ${esc(ex.lastGood)}</dd>
        <dt>What is unavailable</dt><dd>${esc(ex.unavailable)} ${esc(ex.caution)}</dd>
        <dt>Affects the overall status?</dt><dd>${esc(ex.affects)}</dd>
        <dt>What you can do</dt><dd>${esc(ex.next.join(" ")) || "Nothing further."}</dd>
        <dt class="adv">Diagnostics</dt><dd class="adv">${x.error ? "recorded error: " + esc(x.error) + " · " : ""}failures in a row: ${x.failure_count || 0} · recovery: ${esc(x.recovery_state)}${x.recovery_confirmed ? " (confirmed by a fresh result)" : ""}</dd>
      </dl>
      <div class="fxa"><button data-act="checkmon" data-job="${esc(x.id)}">Ask the assistant to check</button>
        <button data-act="rerun" data-job="${esc(x.id)}">Re-run this check</button></div></details>`;
  };
  const bad = d.detectors.filter(x => x.state !== "healthy" && x.state !== "not_applicable");
  el.innerHTML = `<p>${esc(d.summary)}</p>` + bad.map(row).join("") +
    (na.length ? `<details class="dhrow"><summary><small>${na.length} not applicable on this computer</small></summary><div class="more">${na.map(x => `<small>${esc(x.id)}: ${esc(x.reason)}</small>`).join("")}</div></details>` : "");
}

/* ---------- connections: the Link Plane (service/links.py) ---------- */
function renderLinks(s) {
  const el = $("links");
  if (!el) return;
  const L = (s.reliability || {}).links;
  if (!L || !L.links) { el.innerHTML = `<p class="empty-good">Connection status is not available from this server.</p>`; return; }
  const rows = Object.values(L.links).filter(x => x.state !== "not_applicable");
  const c = L.counts || {};
  $("linkssub").textContent = rows.length ? `${c.up || 0} of ${rows.length} up` : "";
  const when = t => t ? new Date(t * 1000).toLocaleTimeString() : "never";
  const word = { up: "connected", silent: "silent", degraded: "degraded" };
  const row = x => {
    const bad = x.state !== "up";
    const next = x.exhausted ? `Automatic reconnect used its budget. Next step: ${x.owner_cmd}.`
      : x.state === "silent" && !x.action ? `No automatic reconnect exists for this link. Next step: ${x.owner_cmd}.`
      : x.state === "silent" ? (x.last_attempt ? `Reconnect attempted at ${when(x.last_attempt.at)}${x.last_attempt.error ? ": " + x.last_attempt.error : ""}.` : "A reconnect is scheduled.")
      : x.state === "degraded" ? `Still running; if it persists: ${x.owner_cmd}.` : "";
    return `<details class="dhrow" ${bad && detailLevel === "advanced" ? "open" : ""}><summary><span class="${bad ? "kind k-monitoring" : "kind"}">${esc(word[x.state] || x.state)}</span>
      <b>${esc(x.link)}</b> <small>${esc(x.what || "")}</small></summary>
      <dl class="kv more">
        <dt>Last verified</dt><dd>${esc(when(x.last_ok))}</dd>
        ${x.reason ? `<dt>Why</dt><dd>${esc(x.reason)}</dd>` : ""}${x.note ? `<dt>Note</dt><dd>${esc(x.note)}</dd>` : ""}
        ${next ? `<dt>What happens next</dt><dd>${esc(next)}</dd>` : ""}
        <dt class="adv">Diagnostics</dt><dd class="adv">attempts this hour: ${x.attempts || 0} · action: ${esc(x.action || "owner only")} · importance: ${esc(x.criticality)}</dd>
      </dl></details>`;
  };
  const order = { silent: 0, degraded: 1, up: 2 };
  rows.sort((a, b) => (order[a.state] ?? 3) - (order[b.state] ?? 3) || a.link.localeCompare(b.link));
  const viol = (L.violations || []).length ? `<p class="empty-bad">${L.violations.length} connection(s) silent with nothing reconnecting them: ${esc(L.violations.join(", "))}.</p>` : "";
  el.innerHTML = viol + (rows.length ? rows.map(row).join("") : `<p class="empty-good">No connections to supervise on this computer.</p>`);
}

/* ---------- investigation reports (assistant checks, fix proposals) ---------- */
function agentReportHTML(r, open) {
  if (!r) return "";
  const secs = reportSections(r);
  return `<details class="rep" ${open ? "open" : ""}><summary><b>${esc(r.title)}</b>
      <span class="kind">${esc(r.mode_label)}</span><span class="kind">${esc(r.status)}</span></summary>
    ${secs.map(x => `<section class="fxs"><h4>${esc(x.label)}</h4><ul>${x.lines.map(l => `<li>${esc(l)}</li>`).join("")}</ul></section>`).join("")}
    <details class="tech" ${detailLevel === "advanced" ? "open" : ""}><summary>Technical evidence</summary><pre class="pre">${esc(r.technical || "(none recorded)")}</pre></details></details>`;
}
function lifecycleHTML(key) {
  const l = lifecycleInfo(key);
  return l ? `<p class="lc" role="status"><span class="kind k-lc">${esc(l.label)}</span> ${esc(l.note)}</p>` : "";
}

/* ---------- fix proposals (the coding agent's drafts) ---------- */
function renderFix(s) {
  const el = document.getElementById("fix");
  const items = s.fix || [];
  if (!items.length) { el.innerHTML = ""; return; }
  el.innerHTML = items.map(f => {
    const ls = fixStateOf(f.status);
    const action = f.status === "proposed"
      ? `<button data-act="fixconfirm" data-choice="approve" data-id="${esc(f.id)}">Review and approve the investigation…</button>`
      : f.status === "review"
      ? `<button data-act="fixconfirm" data-choice="authorize" data-id="${esc(f.id)}">Review and authorize the patch…</button>`
      : f.status === "draft_failed"
      ? `<button data-act="fixdecide" data-id="${esc(f.id)}" data-choice="retry">Retry draft</button>` : "";
    return `<div class="question" id="fix-${esc(f.id)}">
    <div><b>${esc(f.title)}</b> <span class="kind k-lc">${esc(ls.label)}</span> <span class="faint">${esc(ls.note)}</span></div>
    <div class="note">${esc(f.problem || "")}</div>
    ${f.generation_error ? `<div class="crit">The draft did not complete: ${esc(f.generation_error)}</div>` : ""}
    ${agentReportHTML(f.report, false)}
    <div class="question-actions">${action}<button class="quiet" data-act="fixdecide" data-id="${esc(f.id)}" data-choice="reject">Reject</button></div>
    <div class="fine">Approving the investigation generates a draft only. Applying a patch needs a separate authorization and
    <kbd>jarvis fix apply ${esc(f.id)}</kbd>; nothing is applied from this page. Proposal ${esc(f.id)}.</div>
  </div>`;
  }).join("");
}

/* ---------- the approval confirmation ----------
   One component for every action that could change something. It states the ten things a person needs, defaults
   focus to the safe choice, and never calls the backend on dismissal. Closing it, pressing Escape, or letting the
   proposal expire changes nothing. The backend still enforces the token, the 10-minute expiry and single use. */
let approvalSpec = null, approvalOpener = null, lastProposal = null;
function openApproval(spec) {
  if (!spec) return;
  approvalSpec = spec; approvalOpener = document.activeElement;
  const row = (k, v) => v ? `<div class="aprow"><dt>${esc(k)}</dt><dd>${gloss(esc(v))}</dd></div>` : "";
  const first = LIFECYCLE.awaiting_approval;
  $("ap-body").innerHTML = `<h2 id="ap-title">${esc(spec.title)}</h2>
    <p class="apstate"><span class="kind k-lc">${esc(first[0])}</span> ${esc(first[1])} Closing this box or letting it expire changes nothing.</p>
    <dl class="apl">${row("What ARGUS-INSTINCT proposes", spec.proposes)}${row("Why", spec.why)}${row("Exactly what it affects", spec.target)}
      ${row("Expected result", spec.expected)}${row("Possible side effects and risks", spec.risks)}${row("Can it be undone?", spec.reversible)}
      ${row("If you do nothing", spec.ifNothing)}${row("Permissions needed", spec.elevated)}${row("The exact action after you approve", spec.exact)}</dl>
    <details class="apev" id="ap-evidence"><summary>Evidence supporting this proposal</summary>${liHTML(spec.evidence && spec.evidence.length ? spec.evidence : ["No further evidence was recorded."])}</details>
    ${spec.expiresAt ? `<p class="faint">This proposal expires at ${esc(new Date(spec.expiresAt * 1000).toLocaleTimeString())}. Each proposal works once.</p>` : ""}
    <p class="apresult" id="ap-result" role="status" aria-live="polite"></p>`;
  $("ap-actions").innerHTML = `<button id="ap-return" data-ap="return">Return without making changes</button>
    <button data-ap="review">Review details</button>
    ${spec.kind === "assistant" ? `<button data-ap="cancel">Cancel this proposal</button>` : ""}
    <button class="apapprove" data-ap="approve">${esc(spec.confirmLabel || "Approve this action")}</button>`;
  const dlg = $("approval");
  if (typeof dlg.showModal === "function") dlg.showModal(); else dlg.setAttribute("open", "");
  $("ap-return").focus();
}
function closeApproval() {
  const dlg = $("approval");
  if (dlg.open) { if (typeof dlg.close === "function") dlg.close(); else dlg.removeAttribute("open"); }
  if (approvalOpener && approvalOpener.focus && document.contains(approvalOpener)) approvalOpener.focus();
  approvalSpec = null;
}
async function approvalResult(promise, spec, verb) {
  const out = $("ap-result");
  for (const b of $("ap-actions").querySelectorAll("button")) b.disabled = true;
  out.textContent = "Working…";
  try {
    const r = await promise;
    const d = r.data;
    if (spec.kind === "assistant") {
      const l = lifecycleInfo(d.lifecycle || (d.ok ? "approved_queued" : "failed"));
      out.innerHTML = `<span class="kind k-lc">${esc(l ? l.label : "Done")}</span> ${esc((d.sections || []).map(x => x.text).join(" ") || d.answer || "")}`;
      renderAssistant(d);
    } else {
      out.innerHTML = r.ok ? `<span class="kind k-lc">${esc(verb === "approve" ? "Approved: draft being generated" : "Authorized: not yet applied")}</span> ${esc(d.message || "")} Nothing was applied from this page.`
                           : `<span class="kind k-lc">Failed</span> ${esc(d.message || d.error || "The decision could not be recorded.")} Nothing was changed.`;
    }
    tick();
  } catch (e) { out.innerHTML = `<span class="kind k-lc">Failed</span> The request did not complete, so nothing was changed.`; }
  $("ap-actions").innerHTML = `<button id="ap-return" data-ap="return">Close</button>`;
  $("ap-return").focus();
}
async function postJSON(url, body) {
  const resp = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return { ok: resp.ok, data: await resp.json() };
}
document.addEventListener("click", ev => {
  const b = ev.target.closest("[data-ap]");
  if (!b || !approvalSpec) return;
  const spec = approvalSpec, a = b.dataset.ap;
  if (a === "return") closeApproval();
  else if (a === "review") { const d = $("ap-evidence"); d.open = true; d.querySelector("summary").focus(); }
  else if (a === "cancel") approvalResult(postJSON("/api/assistant/action", { op: "cancel", token: spec.token }), spec, "cancel");
  else if (a === "approve") {
    if (spec.kind === "assistant") approvalResult(postJSON("/api/assistant/action", { op: "approve", token: spec.token }), spec, "approve");
    else approvalResult(postJSON("/api/fix/" + spec.choice, { id: spec.id }), spec, spec.choice);
  }
});
$("approval").addEventListener("cancel", () => { approvalSpec = null; });   // Escape: no request is made
$("approval").addEventListener("close", () => { if (approvalOpener && approvalOpener.focus && document.contains(approvalOpener)) approvalOpener.focus(); });

/* ---------- notification center ----------
   Built on the state the page already polls. In-app only: OS pop-ups remain the existing "Notify me" button, which
   works only while this page is open. Dismissing a notification never changes a finding. */
const NOTIF_KEY = "jarvis.notifications";
let notifStore = (() => { try { const v = JSON.parse(localStorage.getItem(NOTIF_KEY) || "null"); return v && Array.isArray(v.items) ? v : emptyNotifStore(); } catch (_) { return emptyNotifStore(); } })();
function saveNotifs() { try { localStorage.setItem(NOTIF_KEY, JSON.stringify(notifStore)); } catch (_) {} }
function updateNotifications(s) {
  const r = deriveNotifications(s, notifStore);
  notifStore = r.store; saveNotifs();
  // Critical findings already get a toast and an optional OS pop-up from notifyCriticals; do not announce them twice.
  for (const f of r.fresh.filter(x => !(x.type === "finding" && x.sev === "critical")).slice(0, 2))
    toast(`${NOTIF_TYPES[f.type]}: ${f.title}`, f.type === "monitoring" || f.sev === "warning" ? "warn" : "", f.text);
  renderBell();
  if (!$("notifs").hidden) renderNotifPanel();
}
function renderBell() {
  const n = unreadCount(notifStore);
  $("bellcount").textContent = n || "";
  $("bell").setAttribute("aria-label", n ? `Notifications, ${n} unread` : "Notifications");
}
function renderNotifPanel() {
  const items = visibleNotifications(notifStore);
  $("notif-list").innerHTML = items.length ? items.map(i => `<li class="nt ${i.read ? "" : "unread"}" data-key="${esc(i.key)}">
      <div class="nth"><span class="kind k-${i.type === "monitoring" ? "monitoring" : i.type === "finding" ? "suspicious" : "lc"}">${esc(NOTIF_TYPES[i.type] || "Notice")}</span>
        ${i.sev && i.sev !== "info" && i.sev !== "action" ? `<span class="sev">${esc(i.sev === "warning" ? "warning" : severityWord(i.sev))}</span>` : ""}
        ${i.known ? `<span class="sev">already present when you first opened ARGUS-INSTINCT</span>` : ""}
        ${i.active ? "" : `<span class="sev">no longer reported</span>`}${i.read ? "" : `<span class="sev">new</span>`}</div>
      <p class="ntt"><b>${esc(i.title)}</b></p><p>${esc(i.text)}</p>
      <div class="fxa"><button data-act="notiview" data-key="${esc(i.key)}">View</button>
        ${canDismiss(i) ? `<button class="quiet" data-act="notidismiss" data-key="${esc(i.key)}">Dismiss</button>` : `<span class="faint">Stays until resolved</span>`}</div></li>`).join("")
    : `<li class="empty-good">No notifications yet. ARGUS-INSTINCT will list new serious findings, monitoring problems, proposals and results here.</li>`;
}
function openNotifs() {
  $("notifs").hidden = false; $("bell").setAttribute("aria-expanded", "true"); renderNotifPanel();
  $("notif-title").focus();
}
function closeNotifs(restore = true) {
  if ($("notifs").hidden) return;
  $("notifs").hidden = true; $("bell").setAttribute("aria-expanded", "false");
  if (restore) $("bell").focus();
}
$("bell").addEventListener("click", () => ($("notifs").hidden ? openNotifs() : closeNotifs()));
document.addEventListener("keydown", e => { if (e.key === "Escape" && !$("notifs").hidden) { e.preventDefault(); closeNotifs(); } });
document.addEventListener("click", e => { if (!$("notifs").hidden && !e.target.closest("#notifs") && !e.target.closest("#bell")) closeNotifs(false); });
function openLink(link) {
  if (!link) return;
  if (link.act === "openproposal") return openFirstProposal(link.token);
  go(viewOf(link.go) || link.go);
  if (!VIEWS[link.go]) jump(link.go);
  if (link.q) setSearch(link.q);
}
function openFirstProposal(token) {
  const list = (state && state.assistant && state.assistant.pending) || [];
  const d = list.find(x => x.token === token) || (lastProposal && lastProposal.token === token ? lastProposal : null) || list[0];
  if (d) openApproval(approvalSpecFromDetails(d)); else toast("That proposal is no longer open.", "warn");
}

/* one place for every button the new views add; each maps to an existing page function or endpoint */
document.addEventListener("click", ev => {
  const b = ev.target.closest("[data-act]");
  if (!b) return;
  const act = b.dataset.act;
  if (act === "go") { go(viewOf(b.dataset.go) || b.dataset.go); if (!VIEWS[b.dataset.go]) jump(b.dataset.go); if (b.dataset.q) setSearch(b.dataset.q); }
  else if (act === "investigate") investigate(b.dataset);
  else if (act === "tech") { const d = b.closest("article").querySelector("details.tech"); d.open = true; d.querySelector("summary").focus(); }
  else if (act === "explain") assistantRun({ op: "run", action: "explain_finding", target: { id: b.dataset.id } });
  else if (act === "checkmon") assistantRun({ op: "run", action: "check_monitor", target: { job: b.dataset.job } });
  else if (act === "rerun") { runJob(b.dataset.job); toast("Queued. ARGUS-INSTINCT will show the result when the check finishes.", ""); }
  else if (act === "copy") copyText(b.dataset.copy);
  // Server values (ids, job names) travel in data-* attributes, never inside an
  // inline handler's JavaScript string, where HTML escaping does not protect them.
  else if (act === "answer") answerQuestion(b.dataset.id, b.dataset.choice);
  else if (act === "runjob") runJob(b.dataset.job);
  else if (act === "fixdecide") decideFix(b.dataset.id, b.dataset.choice);
  else if (act === "openproposal") { go("assistant"); openFirstProposal(b.dataset.token); }
  else if (act === "fixconfirm") {
    const f = ((state && state.fix) || []).find(x => x.id === b.dataset.id);
    if (f) openApproval({ ...approvalSpecForFix(f, b.dataset.choice), choice: b.dataset.choice });
  }
  else if (act === "notiview") { const k = b.dataset.key, it = notifStore.items.find(i => i.key === k); notifStore = markRead(notifStore, k); saveNotifs(); renderBell(); closeNotifs(false); if (it) openLink(it.link); }
  else if (act === "notidismiss") { notifStore = dismissNotification(notifStore, b.dataset.key); saveNotifs(); renderBell(); renderNotifPanel(); }
  else if (act === "notiall") { notifStore = markRead(notifStore, null); saveNotifs(); renderBell(); renderNotifPanel(); }
});
function setSearch(text) {
  query = String(text || ""); $("q").value = query; findingLimit = FINDING_BATCH; open.clear();
  if (state) renderFindings();
}

/* ---------- assistant: suggested questions, honest model status, guided actions ---------- */
let chatOffer = null, chatActions = [];
const SECTION_TAG = { verified: "verified", recommend: "recommended", assumption: "assumption", simple: "In short",
                      observed: "What we observed", why: "Why it matters", next: "What to do next" };
function renderModelStatus(model) {
  const el = $("modelstatus");
  if (!el) return;
  el.textContent = model && model.label ? model.label : "Local AI has not been checked yet. Basic assistance is working.";
}
async function refreshModelStatus() {
  try {
    const r = await postJSON("/api/assistant/action", { op: "run", action: "check_model" });
    if (r.ok && r.data.model) renderModelStatus(r.data.model);
  } catch (_) { renderModelStatus(null); }
}
function renderAssistant(data) {
  const out = $("askanswer");
  out.dataset.kind = "answer";
  chatOffer = data.offer || null;
  const proposal = data.details && data.lifecycle === "awaiting_approval" ? data.details : null;
  // A proposal is decided in the confirmation box, never by a bare Approve button in the chat.
  chatActions = (data.actions || []).filter(a => !(proposal && (a.action === "approve" || a.action === "cancel")));
  const secs = data.sections || [];
  const body = secs.length
    ? secs.filter(x => x.kind !== "technical").map(sec => `<div class="sec">${SECTION_TAG[sec.kind] ? `<b class="tag">${SECTION_TAG[sec.kind]}:</b> ` : ""}${esc(sec.text).replace(/\n/g, "<br>")}</div>`).join("")
    : esc(data.answer);
  const tech = secs.filter(x => x.kind === "technical");
  const techHTML = tech.length ? `<details class="tech" ${detailLevel === "advanced" ? "open" : ""}><summary>Technical details</summary>${tech.map(x => `<div class="sec">${esc(x.text)}</div>`).join("")}</details>` : "";
  const buttons = chatActions.length ? `<div class="chat-actions">${chatActions.map((a, i) =>
    `<button data-chat-action="${i}">${esc(a.label)}</button>`).join("")}</div>` : "";
  const propBtn = proposal ? `<div class="chat-actions"><button data-act="openproposal" data-token="${esc(proposal.token)}">Review and decide…</button></div>` : "";
  const chips = (data.suggestions || []).length ? `<div class="chat-chips">${data.suggestions.map(q =>
    `<button class="showmore" data-ask="${esc(q)}">${esc(q)}</button>`).join("")}</div>` : "";
  if (data.model) renderModelStatus(data.model);
  out.innerHTML = body + techHTML + lifecycleHTML(data.lifecycle) + propBtn + buttons + agentReportHTML(data.report, true) + chips + `<div class="chat-source">${
    data.source === "ollama" ? "local AI explanation · no action taken" :
    data.source === "builtin" ? "answered from ARGUS-INSTINCT data · basic assistance" :
    data.source === "busy" ? "local model busy" : "local model unavailable"}</div>`;
  if (proposal) lastProposal = proposal;
}
async function assistantRun(body) {
  go("assistant");
  const out = $("askanswer");
  out.textContent = "Working…";
  try {
    const r = await postJSON("/api/assistant/action", body);
    if (!r.ok) throw new Error(r.data.error || "request failed");
    renderAssistant(r.data); tick();
  } catch (e) { out.textContent = "That didn't work. Please try again in a moment."; }
}
function assistantAction(i) {
  const a = chatActions[i];
  if (!a) return;
  if (a.action === "approve" || a.action === "cancel") return assistantRun({ op: a.action, token: a.token });
  return assistantRun({ op: a.action === "rerun_monitor" ? "propose" : "run", action: a.action, target: a.target });
}
function assistantCheckModel() { return assistantRun({ op: "run", action: "check_model" }); }
document.addEventListener("click", ev => {
  const act = ev.target.closest("[data-chat-action]"), ask = ev.target.closest("[data-ask]");
  if (act) assistantAction(Number(act.dataset.chatAction));
  else if (ask) askText(ask.dataset.ask);
});
function askText(text) { $("askq").value = text; askJarvis(new Event("submit", { cancelable: true })); }
async function askJarvis(event) {
  event.preventDefault();
  const input = $("askq"), button = $("askbtn"), output = $("askanswer"), question = input.value.trim();
  if (!question) return;
  button.disabled = true; button.textContent = "Thinking…";
  output.textContent = "Reading current ARGUS-INSTINCT state…";
  try {
    const r = await postJSON("/api/ask", { question, offer: chatOffer });
    if (!r.ok) throw new Error(r.data.error || "request failed");
    input.value = ""; renderAssistant(r.data);
  } catch (e) {
    output.textContent = /token|licen[cs]e/i.test(String(e && e.message))
      ? (/licen[cs]e/i.test(e.message) ? "An ARGUS-INSTINCT licence is needed to ask questions. Open the Pricing page."
                                       : "ARGUS-INSTINCT was restarted since this page was opened. Reload the page (Ctrl+R) and ask again.")
      : "I couldn't get an answer just now. Please try again in a moment.";
  }
  finally { button.disabled = false; button.textContent = "Ask"; }
}

/* Investigate: re-run the check that raised the finding, then have the assistant explain
   the evidence. The re-run only reads; nothing on the computer is changed. */
async function investigate(d) {
  go("assistant");
  const out = $("askanswer");
  out.textContent = "Investigating… ARGUS-INSTINCT is re-checking this and reading the evidence.";
  if (d.job) {
    try { await postJSON("/api/run?job=" + encodeURIComponent(d.job), {}); } catch (e) { /* the explanation still works from stored evidence */ }
  }
  if (d.id) return assistantRun({ op: "run", action: "explain_finding", target: { id: d.id } });
  askText("Explain this finding in simple language: " + (d.q || ""));
}

/* Security Autopilot: ARGUS-INSTINCT investigates on its own; this shows the result and asks only what it must */
let apData = null;
const AP_CHOICE = { recognise: "I recognise this", not_recognise: "I don't recognise this",
                    investigate_further: "Investigate further", review_individually: "Review individually" };
async function loadAutopilot() {
  try { apData = await (await fetch("/api/autopilot", { cache: "no-store" })).json(); } catch (e) { return; }
  renderAutopilot(apData);
  try {
    const n = (await (await fetch("/api/autopilot/notices", { cache: "no-store" })).json()).notices || [];
    for (const x of n) {
      toast(x.text, x.severity === "critical" || x.severity === "high" ? "warn" : "");
      try { if (window.Notification && Notification.permission === "granted") new Notification("ARGUS-INSTINCT", { body: x.text }); } catch (e) { /* optional */ }
    }
  } catch (e) { /* notices are optional */ }
}
function apCase(c) {
  const li = a => a.map(x => `<li>${esc(x)}</li>`).join("");
  const obs = c.observations.map(o => `<li><b>${esc(o.title)}</b> <span class="faint">(${esc(o.severity)}, ${esc(o.job)})</span><br>
      <code>${esc(clip(o.where || "no location recorded", 200))}</code></li>`).join("");
  const btns = c.options.map(o => `<button data-apd="${esc(c.key)}" data-choice="${esc(o.choice)}" title="${esc(o.consequence)}">${esc(AP_CHOICE[o.choice])}</button>`).join("");
  return `<article class="apcase sev-${esc(c.severity)}">
    <h4>${esc(c.title)}</h4>
    <p><b>What happened.</b> ${esc(c.what_happened)}</p>
    <p><b>Why it matters.</b> ${esc(c.why_it_matters)}</p>
    <p><b>What ARGUS-INSTINCT established.</b></p><ul>${li(c.established)}</ul>
    <p><b>What is still uncertain.</b></p><ul>${li(c.uncertain)}</ul>
    <p><b>Recommended next step.</b> ${esc(c.recommended || "Check whether you recognise it.")}</p>
    ${c.ai_note ? `<p class="faint"><b>Plain-language note (local AI):</b> ${esc(c.ai_note)}</p>` : ""}
    <details><summary>The ${plural(c.count, "observation")} in this case</summary><ul>${obs}</ul></details>
    <div class="apbtns">${btns}</div>
    <p class="cons">Hover a button to see what it does. None of these change anything on your computer.</p>
  </article>`;
}
function renderAutopilot(a) {
  const h = a.health, m = h.monitoring, s = a.summary, q = a.queue;
  const working = q.queued + q.investigating;
  $("ap-body").innerHTML = `
    <div class="ap3">
      <div><b>Is my computer okay?</b>${esc(h.headline)}. ARGUS-INSTINCT reports what it has observed; it cannot prove a computer is clean.</div>
      <div><b>What needs my attention?</b>${esc(h.okay)}</div>
      <div><b>Is ARGUS-INSTINCT monitoring?</b>${esc(h.monitoring_line)}${m.not_reporting ? ` ${plural(m.not_reporting, "check")} not reporting.` : ""}</div>
    </div>
    <h3>What needs me</h3>
    ${a.needs_me.length ? a.needs_me.slice(0, 5).map(apCase).join("") + (a.needs_me.length > 5
      ? `<details><summary>${a.needs_me.length - 5} more case(s), less serious first</summary>${a.needs_me.slice(5).map(apCase).join("")}</details>` : "")
      : "<p>Nothing right now. ARGUS-INSTINCT will tell you if that changes.</p>"}
    <h3>What ARGUS-INSTINCT handled</h3>
    ${a.handled.groups.length || working ? `<ul class="aplist">${a.handled.groups.map(g => `<li>${esc(g.title)} <span class="faint">· investigated</span></li>`).join("")}
      ${working ? `<li>${plural(working, "investigation")} in progress or queued</li>` : ""}
      ${q.failed ? `<li>${plural(q.failed, "investigation")} failed and will be retried; failures are never shown as done</li>` : ""}</ul>` : "<p>No investigations yet.</p>"}
    <h3>Monitoring health</h3>
    <p>${esc(m.definition)} <b>${m.reporting} of ${m.total}</b> reporting${m.partial ? `, ${m.partial} partly` : ""}. A monitoring problem is a gap in what ARGUS-INSTINCT can see, not a security finding.</p>
    ${a.recovery.length ? `<ul class="aplist">${a.recovery.map(r => `<li><b>${esc(r.job)}</b>: ${esc(r.note)} <span class="faint">(${esc(r.status)}${r.status === "retrying" ? `, attempt ${r.retries}` : ""})</span></li>`).join("")}</ul>` : ""}
    <h3>Daily summary <span class="faint">(last ${s.window_hours} hours)</span></h3>
    <ul class="aplist">
      <li>${plural(s.new_findings, "new finding")}; ${plural(s.investigations_completed, "investigation")} completed</li>
      <li>${plural(s.needs_attention, "case")} need your attention</li>
      <li>Actions you authorised: ${s.actions_authorized}; performed: ${s.actions_performed}</li>
      ${s.limitations.map(x => `<li class="faint">Limit: ${esc(x)}</li>`).join("")}
    </ul>`;
}
document.addEventListener("click", async ev => {
  const b = ev.target.closest("[data-apd]");
  if (!b) return;
  b.disabled = true;
  const r = await postJSON("/api/autopilot/decide", { key: b.dataset.apd, choice: b.dataset.choice });
  if (!r.ok) toast((r.data && r.data.error) || "That did not work.", "warn");
  else if (b.dataset.choice === "review_individually") toast("Open the case's observation list to review each one.", "");
  loadAutopilot();
});
loadAutopilot(); setInterval(loadAutopilot, 15000);

/* licence: state and purchase through the Archymedes licence service (the hosted claim flow).
   This computer opens a claim, the browser pays at pay.archymedes.xyz, and the daemon activates
   by itself when the claim is paid. No payment key is ever on this computer, and a licence never
   gates protection (tests/test_licence_never_gates_core.py). Prices: desktop/ui/src/lib/prices.ts
   (tests/test_no_seller_payment_key.py keeps the amounts on this page equal to it). */
let licence = null, licPoll = null;
const PAY_ORIGIN = "https://pay.archymedes.xyz";
// The same allow-list as the app (desktop/src/api.rs valid_licence_page, desktop/ui/src/lib/licence.ts).
function licencePageOk(url) {
  if (typeof url !== "string" || !url.startsWith(PAY_ORIGIN + "/")) return false;
  const rest = url.slice(PAY_ORIGIN.length + 1);
  return ["manage", "recover", "buy/argus-server", "buy/argus-desktop", "buy/argus-desktop-monthly"].includes(rest)
    || /^buy\/argus-(server|desktop|desktop-monthly)\?claim=clm_[0-9A-Z]{32}(&promo=[A-Za-z0-9_-]{1,40})?$/.test(rest)
    || /^buy\/argus-(server|desktop|desktop-monthly)\?promo=[A-Za-z0-9_-]{1,40}$/.test(rest);
}
// Optional promo code (the same pattern as jarvis/web/licenceapi.py PROMO). Discounts live in Stripe;
// the licence service checks the code when checkout opens and says there if it was not applied.
const PROMO = /^[A-Za-z0-9_-]{1,40}$/;
const BAD_PROMO = "A promo code is up to 40 letters, digits, - or _.";
function promoCode() {
  const el = $("lic-promo"), code = el ? el.value.trim() : "";
  return code === "" ? "" : PROMO.test(code) ? code : null;    // null: malformed
}
async function loadLicence() {
  try {
    const r = await fetch("/api/licence", { cache: "no-store" });
    if (!r.ok) return;
    licence = await r.json();
  } catch (e) { return; }
  const on = !!licence.licensed, until = on && licence.expires_at ? new Date(licence.expires_at * 1000).toLocaleDateString() : "";
  $("lic-state").textContent = on ? (until ? `active until ${until}` : "active") : "not active";
  $("lic-state").className = "lic" + (on ? " on" : "");
  $("nav-lic").textContent = on ? "" : "!";
  for (const id of ["lic-buy-month", "lic-buy-year"]) $(id).hidden = on;
  const bar = $("licbar");
  bar.hidden = on;
  // A licence never gates protection (tests/test_licence_never_gates_core.py): no locked wording.
  $("licbar-text").textContent = "No active licence. Protection works the same without one; ARGUS-INSTINCT is $15/month or $79/year.";
  if (!on && licence.purchase_waiting) waitForPayment();
}
function waitForPayment() {
  $("lic-msg").textContent = "Waiting for payment to complete in your browser…";
  if (licPoll) return;
  licPoll = setInterval(async () => {
    try {
      const r = await postJSON("/api/licence/poll", {});
      if (r.ok && r.data.active) {
        clearInterval(licPoll); licPoll = null;
        $("lic-msg").textContent = "Thank you. Your licence is active.";
        loadLicence();
      }
    } catch (e) { /* keep waiting; the daemon may be busy */ }
  }, 5000);
}
async function subscribe(plan) {
  const msg = $("lic-msg"), promo = promoCode();
  if (promo === null) { msg.textContent = BAD_PROMO; return; }
  msg.textContent = "Opening secure checkout…";
  try {
    const r = await postJSON("/api/licence/upgrade", { plan: plan === "month" ? "desktop-monthly" : "desktop", ...(promo ? { promo } : {}) });
    const link = r.ok && r.data && r.data.ok ? r.data.open : "";
    if (!licencePageOk(link)) { msg.textContent = (r.data && r.data.error) || "Could not start checkout."; return; }
    window.open(link, "_blank", "noopener");
    waitForPayment();
  } catch (e) { msg.textContent = "Could not start checkout. Please try again."; }
}
loadLicence();

routeFromHash(true);

async function tick() {
  // One request at a time, each bounded: a stalled connection must surface, not spin forever.
  if (paused || tickPending) return;
  tickPending = true;
  const ctl = new AbortController(), guard = setTimeout(() => ctl.abort(), STATE_TIMEOUT_MS);
  try {
    const r = await fetch("/api/state", { cache: "no-store", signal: ctl.signal });
    if (!r.ok) throw new Error(r.status);
    render(await r.json());
    loadNotice("");
    if (lostConn) { lostConn = false; announce("Reconnected to the ARGUS-INSTINCT daemon. Back on watch.", "good"); }
  } catch (e) {
    loadNotice(e && e.name === "AbortError"
      ? `ARGUS-INSTINCT did not answer within ${STATE_TIMEOUT_MS / 1000} seconds. Retrying automatically.`
      : "Could not load ARGUS-INSTINCT state. Retrying automatically.");
    document.getElementById("meta").textContent = "daemon unreachable — retrying";
    document.getElementById("beat").className = "beat off";
    if (!lostConn) { lostConn = true; announce("Lost connection to the ARGUS-INSTINCT daemon. Retrying.", "warn"); }
  } finally {
    clearTimeout(guard);
    tickPending = false;
  }
}
tick();
greet();
timer = setInterval(tick, 5000);

// Live pulse (/api/stream, web/stream.py): refresh the moment the daemon's
// summary changes, and relax the poll while the stream is up. Polling stays
// as the floor: a dropped or refused stream (503 once every slot is taken)
// must never leave the page frozen on old state.
const POLL_MS = 5000, POLL_STREAMING_MS = 30000, STREAM_RETRY_MS = 60000;
let pulseVersion = null, streamUp = false;
function setPoll(ms) { clearInterval(timer); timer = setInterval(tick, ms); }
function startStream() {
  if (typeof EventSource === "undefined") return null;
  const es = new EventSource("/api/stream");
  es.addEventListener("pulse", e => {
    let p;
    try { p = JSON.parse(e.data); } catch (_) { return; }
    if (!streamUp) { streamUp = true; setPoll(POLL_STREAMING_MS); }
    const first = pulseVersion === null;
    if (p.version !== pulseVersion) { pulseVersion = p.version; if (!first) tick(); }
  });
  es.onerror = () => {
    if (streamUp) { streamUp = false; setPoll(POLL_MS); tick(); }
    // EventSource reconnects by itself after a drop; after a refusal it closes.
    if (es.readyState === 2) setTimeout(startStream, STREAM_RETRY_MS);
  };
  return es;
}
startStream();

/* ---------- event wiring: no inline handlers (CSP script-src 'self') ----------
   Elements name what they do with data-click / data-input / data-change /
   data-submit / data-enter and an optional data-arg; this table is the only
   way from markup to code. Server values travel as data, never as code. */
const UI_CALLS = {
  search: () => onSearch(),
  notify: () => toggleNotify(),
  theme: el => setTheme(el.dataset.arg),
  detail: el => setDetail(el.dataset.arg),
  pause: () => togglePause(),
  closenotifs: () => closeNotifs(),
  showsev: el => { setSev(el.dataset.arg); jump("findings-section"); },
  jump: el => jump(el.dataset.arg),
  clear: () => clearAll(),
  tick: () => tick(),
  filter: () => onFilter(),
  group: () => toggleGroup(),
  voicepick: () => pickVoice(),
  voice: () => toggleVoice(),
  runall: () => runAll(),
  brief: () => briefNow(),
  ask: (el, ev) => askJarvis(ev),
  checkmodel: () => assistantCheckModel(),
  coach: () => scoreCoach(),
  tab: el => setTab(el.dataset.arg),
  reviewqueue: () => { document.getElementById("reviewqueue").open = true; jump("reviewqueue"); },
  morequestions: () => { showAllQuestions = !showAllQuestions; renderQuestions(state); },
  findtitle: el => findTitle(el.dataset.title),
  sev: el => setSev(el.dataset.arg || null),
  host: el => setHost(el.dataset.arg),
  morejobs: () => { showHealthy = !showHealthy; renderJobs(state); },
  toggle: el => toggle(el.dataset.arg),
  morefindings: () => showMoreFindings(),
  protocol: el => answerProtocol(el),
  go: el => go(el.dataset.arg),
  subscribe: el => subscribe(el.dataset.arg),
  licpage: el => {
    const promo = el.dataset.arg.startsWith("buy/") ? promoCode() : "";
    if (promo === null) { toast(BAD_PROMO, "warn"); return; }
    const u = PAY_ORIGIN + "/" + el.dataset.arg + (promo ? "?promo=" + promo : "");
    if (licencePageOk(u)) window.open(u, "_blank", "noopener");
  },
};
function uiDispatch(attr, ev) {
  // Every matching ancestor, innermost first: the order inline handlers ran in.
  for (let el = ev.target && ev.target.closest && ev.target.closest(`[${attr}]`); el;
       el = el.parentElement && el.parentElement.closest(`[${attr}]`)) {
    const fn = UI_CALLS[el.getAttribute(attr)];
    if (fn) fn(el, ev);
  }
}
// Capture phase, so these run before the delegated data-act handler, as the
// inline handlers they replace did.
document.addEventListener("click", ev => uiDispatch("data-click", ev), true);
document.addEventListener("input", ev => uiDispatch("data-input", ev), true);
document.addEventListener("change", ev => uiDispatch("data-change", ev), true);
document.addEventListener("submit", ev => uiDispatch("data-submit", ev), true);
document.addEventListener("keydown", ev => { if (ev.key === "Enter") uiDispatch("data-enter", ev); }, true);

/* ---------- GeoSecurity card summary ---------- */
function geoSummary(){
  fetch("/api/geo").then(r=>r.json()).then(g=>{
    const s=(g.location||{}).status||"unknown", z=(g.zones||[]).length, a=(g.anomalies||[]).length;
    const el=document.getElementById("geocnt");
    if(el) el.textContent = `${s} · ${z} zone${z===1?"":"s"} · ${a} anomal${a===1?"y":"ies"}`;
  }).catch(()=>{});
}
geoSummary(); setInterval(geoSummary, 60000);

