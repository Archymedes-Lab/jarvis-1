// Argus on the phone: inbox, servers, pairing, approvals, settings. Alert text is untrusted data
// from a server: it is only ever placed with textContent, never parsed as HTML.
import { approvalChallenge, b64u, generateDevice, keyId, normalizeCode, qrProof, sas, sealReply, supported, unb64u, validCode } from "./lib/protocol.js";
import { messages, servers, settings } from "./lib/store.js";
import { CATEGORIES, signedFetch, syncAll } from "./lib/sync.js";
import { assertPasskey, createPasskey, platformAuthenticator } from "./lib/passkey.js";
import { parsePairing, startScanner } from "./lib/qr.js";

const view = document.getElementById("view");
const status = document.getElementById("status");

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return el;
}

const ago = (t) => {
  const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(t * 1000).toLocaleDateString();
};
const sevClass = (s) => `sev sev-${["critical", "high", "medium", "low", "ok"].includes(s) ? s : "info"}`;
const isIos = () => /iPhone|iPad|iPod/.test(navigator.userAgent);
const standalone = () => matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
const needsApproval = (m) => m.kind === "approval" && m.approval === "approve";

let stopScan = null;
function show(...nodes) {
  if (stopScan) { stopScan(); stopScan = null; }
  view.replaceChildren(...nodes);
  view.focus({ preventScroll: true });
  const tab = location.hash.startsWith("#/servers") || location.hash.startsWith("#/add") || location.hash.startsWith("#/pair") ? "servers"
    : location.hash.startsWith("#/settings") ? "settings" : "inbox";
  for (const a of document.querySelectorAll(".tabs a")) a.toggleAttribute("aria-current", a.dataset.tab === tab);
}

// Android/Chrome offers its own install prompt; keep it for the Install button.
let installEvent = null;
addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); installEvent = e; });

// --- inbox -----------------------------------------------------------------------
let inflight = null;

async function inbox() {
  // Opening the inbox checks for new alerts first: push only wakes the service
  // worker, and a phone without push still gets its alerts.
  await sync();
  const [list, paired] = [await messages.all(), await servers.all()];
  if (!paired.length) {
    return show(h("section", { class: "empty" },
      h("h1", {}, "No servers yet"),
      h("p", {}, "Pair a server running Argus to receive its alerts here, end-to-end encrypted."),
      h("a", { class: "button", href: "#/add" }, "Add a server")));
  }
  if (!list.length) {
    return show(h("section", { class: "empty" }, h("h1", {}, "All quiet"),
      h("p", {}, `${paired.length} server${paired.length > 1 ? "s" : ""} paired. New alerts appear here.`),
      h("button", { class: "button ghost", onclick: refresh }, "Check now")));
  }
  // Filter by category; the choice is kept in the hash so Back keeps it.
  const want = new URLSearchParams(location.hash.split("?")[1] || "").get("c");
  const present = Object.keys(CATEGORIES).filter((c) => list.some((m) => (m.category || "system") === c));
  const shown = want ? list.filter((m) => (m.category || "system") === want) : list;
  const chip = (c, text) => h("a", { class: `chip ${(c || "") === (want || "") ? "on" : ""}`,
    href: c ? `#/?c=${c}` : "#/", "aria-current": (c || "") === (want || "") ? "true" : false }, text);
  show(h("nav", { class: "chips", "aria-label": "Filter by kind" },
      chip("", `All ${list.length}`),
      present.map((c) => chip(c, `${CATEGORIES[c]} ${list.filter((m) => (m.category || "system") === c).length}`))),
    h("ul", { class: "list" }, shown.map((m) =>
    h("li", {}, h("a", { class: `row ${m.read ? "" : "unread"}`, href: `#/m/${m.id}` },
      h("span", { class: sevClass(m.severity) }, needsApproval(m) && !m.answered && m.expires > Date.now() / 1000 ? "approve" : m.severity),
      h("span", { class: "row-main" }, h("span", { class: "row-title" }, m.title),
        h("span", { class: "row-meta" }, `${CATEGORIES[m.category] || CATEGORIES.system} · ${m.label || m.host} · ${ago(m.at)}`)))))));
}

async function message(id) {
  const m = await messages.get(id);
  if (!m) return show(h("p", { class: "pad" }, "This alert is no longer on this phone."), h("a", { class: "button ghost", href: "#/" }, "Back"));
  if (!m.read) { m.read = true; await messages.put(m); }
  if (m.approval && m.approval_id) return approvalView(m);
  show(h("article", { class: "detail" },
    h("a", { class: "back", href: "#/" }, "‹ Alerts"),
    h("span", { class: sevClass(m.severity) }, m.severity),
    h("span", { class: "kindtag" }, CATEGORIES[m.category] || CATEGORIES.system),
    h("h1", {}, m.title),
    h("p", { class: "row-meta" }, `${m.label || m.host} · ${new Date(m.at * 1000).toLocaleString()}`),
    h("pre", { class: "body" }, m.body),
    h("button", { class: "button ghost danger", onclick: async () => { await messages.remove(id); location.hash = "#/"; } }, "Delete from this phone")));
}

// --- approvals -----------------------------------------------------------------------
// An approval is a request from a paired server to apply ONE reversible action (or to undo one a phone
// approved). The phone recomputes the challenge from what it shows, so the Face ID / fingerprint check
// signs exactly this action; the server verifies it and applies nothing otherwise.
async function approvalView(m) {
  const server = (await servers.all()).find((s) => s.mb === m.mb);
  const undo = m.approval === "undo";
  let challenge = null;
  try { challenge = await approvalChallenge(m.approval_id, m.eid, m.action, m.target, m.expires); } catch {}
  const honest = challenge && b64u(challenge) === m.challenge;
  const expired = Date.now() / 1000 >= m.expires;
  const error = h("p", { class: "error", role: "alert" });
  const body = [
    h("a", { class: "back", href: "#/" }, "‹ Alerts"),
    h("span", { class: sevClass(undo ? "ok" : m.severity) }, undo ? "undo" : "approve"),
    h("h1", {}, m.title),
    h("p", { class: "row-meta" }, `${m.label || m.host} · ${new Date(m.at * 1000).toLocaleString()}`),
    undo ? h("p", {}, "This takes back the action you approved from this phone.")
      : h("p", {}, "This server wants to do the following. You can undo it afterwards."),
    h("pre", { class: "body" }, m.preview || m.body),
    h("p", { class: "fine" }, `Action: ${m.action}. ${expired ? "This request has expired." : `Open until ${new Date(m.expires * 1000).toLocaleTimeString()}.`}`),
  ];
  if (m.answered) {
    body.push(h("p", { class: "row-meta" }, m.answered === "deny" ? "You dismissed this." : "Sent. You will get a notification when it is done."));
  } else if (!honest) {
    body.push(h("p", { class: "error" }, "This request does not check out, so nothing can be approved from it."));
  } else if (expired) {
    body.push(h("p", { class: "row-meta" }, "Ask the server to offer it again, or approve it on the computer."));
  } else if (!server || !server.passkeyId) {
    body.push(h("p", { class: "error" }, "This phone is not set up to approve. Pair it again with the QR code and turn on Face ID or fingerprint."));
  } else {
    const approve = h("button", { class: "button", onclick: () => answer(m, server, "approve", challenge, error, approve, deny) },
      undo ? "Undo with Face ID" : "Approve with Face ID");
    const deny = h("button", { class: "button ghost", onclick: () => answer(m, server, "deny", challenge, error, approve, deny) }, "Not now");
    body.push(error, approve, deny);
  }
  show(h("article", { class: "detail stack" }, body));
}

async function answer(m, server, decision, challenge, error, ...buttons) {
  error.textContent = "";
  for (const b of buttons) b.disabled = true;
  try {
    // The biometric prompt must be the first thing awaited: Safari needs the tap's user gesture for it.
    const assertion = decision === "approve" ? await assertPasskey(server.passkeyId, challenge) : undefined;
    const now = Date.now() / 1000;
    // Strictly increasing per server; never reuses a number even if this phone's storage was reset.
    server.replyCounter = Math.max((server.replyCounter || 0) + 1, Math.floor(now));
    await servers.put(server);
    const payload = { type: "approval", approval_id: m.approval_id, decision, counter: server.replyCounter, at: Math.floor(now) };
    if (assertion) payload.assertion = assertion;
    const reply = await sealReply(server.keys.sigPriv, server.dev, server.mb, unb64u(server.s_enc), payload, now);
    await signedFetch(server, "POST", `/v1/device/${server.dev}/replies?mb=${server.mb}`, reply);
    m.answered = decision;
    await messages.put(m);
    approvalView(m);
  } catch (err) {
    const name = err && err.name;
    error.textContent = name === "NotAllowedError" ? "The Face ID / fingerprint check was cancelled or failed. Nothing was sent."
      : `Could not send: ${err.message || err}`;
    for (const b of buttons) b.disabled = false;
  }
}

// --- servers -------------------------------------------------------------------------
async function serverList() {
  const list = await servers.all();
  const pending = await settings.get(PENDING, null);
  show(h("section", { class: "pad" },
    h("h1", {}, "Servers"),
    pending && Date.now() < pending.deadline ? h("p", { class: "card" }, `Pairing with ${pending.server.label} is in progress. `,
      h("a", { href: "#/pending" }, "Continue")) : null,
    list.length ? h("ul", { class: "list" }, list.map((s) => h("li", { class: "server" },
      h("div", {}, h("strong", {}, s.label), h("span", { class: "row-meta" },
        s.lastError ? `Problem: ${s.lastError}` : s.lastSync ? `Checked ${ago(s.lastSync)}` : `Paired ${ago(s.pairedAt)}`),
        h("span", { class: "row-meta" }, s.passkeyId ? "Can approve with Face ID / fingerprint" : "Alerts only")),
      h("button", { class: "button ghost danger small", onclick: () => removeServer(s) }, "Remove"))))
      : h("p", {}, "No server is paired with this phone."),
    h("a", { class: "button", href: "#/add" }, "Add a server")));
}

async function removeServer(s) {
  if (!confirm(`Stop receiving alerts from ${s.label} on this phone?`)) return;
  try { await signedFetch(s, "DELETE", `/v1/mailbox/${s.mb}/devices/${s.dev}`); } catch {}
  await messages.removeServer(s.mb);
  await servers.remove(s.mb);
  serverList();
}

// --- pairing: install, scan, set up ------------------------------------------------------
async function addServer() {
  if (!(await supported())) {
    return show(h("section", { class: "pad" }, h("h1", {}, "Update your browser"),
      h("p", {}, "This browser lacks the encryption Argus uses (X25519 and Ed25519). Use a current Safari, Chrome or Firefox.")));
  }
  // iPhone only delivers notifications to a Home-Screen app, and keeps that app's storage apart from
  // Safari's: so the app must be added first and pairing done inside it.
  if (isIos() && !standalone()) return installGuide();
  scanView();
}

function installGuide() {
  show(h("section", { class: "pad stack" },
    h("h1", {}, "Add Argus to your Home Screen"),
    h("p", {}, "Notifications on iPhone only work from the Home Screen. It takes ten seconds:"),
    h("ol", { class: "steps" },
      h("li", {}, "Tap the Share button ", h("strong", {}, "⬆︎"), " at the bottom of Safari."),
      h("li", {}, "Scroll down and tap ", h("strong", {}, "Add to Home Screen"), ", then ", h("strong", {}, "Add"), "."),
      h("li", {}, "Open ", h("strong", {}, "Argus"), " from your Home Screen and tap ", h("strong", {}, "Add a server"), ".")),
    h("p", { class: "fine" }, "You do not download anything from the App Store. Argus stays a web page that lives on your Home Screen."),
    h("a", { class: "button ghost", href: "#/add-typed" }, "Pair with a typed code anyway (alerts only)")));
}

function scanView() {
  const video = h("video", { class: "scanner", muted: true, playsinline: true });
  const error = h("p", { class: "error", role: "alert" });
  const installNote = !isIos() && !standalone() && installEvent
    ? h("button", { class: "button ghost", onclick: async () => { installEvent.prompt(); installEvent = null; } }, "Install Argus on this phone") : null;
  show(h("section", { class: "pad stack center" },
    h("h1", {}, "Scan the QR code"),
    h("p", {}, "On your computer or server, run ", h("code", {}, "argus notify pair"), ", then point this camera at the QR code it shows."),
    video, error, installNote,
    h("a", { class: "button ghost", href: "#/add-typed" }, "Type the code instead")));
  startScanner(video, (text) => {
    try {
      const p = parsePairing(text);
      location.hash = `#/pair?c=${p.code}&k=${b64u(p.secret)}&mb=${p.mb}`;
    } catch (err) { error.textContent = String(err.message || err); }
  }).then((stop) => { if (video.isConnected) stopScan = stop; else stop(); }).catch(() => {
    error.textContent = "The camera is not available. Allow camera access for Argus in Settings, or type the code instead.";
  });
}

// QR pairing, step 2: notifications and the passkey each need their own tap, so they are a checklist.
async function setupPhone(pairing) {
  const state = { notifications: "Notification" in window && Notification.permission === "granted", passkey: null, skippedPasskey: false };
  const hasAuthenticator = await platformAuthenticator();
  const name = h("input", { id: "name", maxlength: "40", value: defaultName() });
  const error = h("p", { class: "error", role: "alert" });
  const go = h("button", { class: "button", disabled: true }, "Pair this phone");
  const rows = h("div", { class: "stack" });
  // Alerts still arrive when the app is open without notifications, so a refusal does not block pairing.
  const notifOk = () => state.notifications || !("PushManager" in window) || Notification.permission === "denied";
  const refreshUi = () => {
    const notifRow = h("div", { class: "card" },
      h("strong", {}, state.notifications ? "✓ Notifications are on" : "1. Allow notifications"),
      !state.notifications ? h("p", { class: "row-meta" }, ("PushManager" in window)
        ? "So Argus can tell you when it needs you." : "This browser cannot show background notifications. Alerts appear when you open Argus.") : null,
      !state.notifications && "PushManager" in window ? h("button", { class: "button", onclick: async () => {
        if ((await Notification.requestPermission()) === "granted") state.notifications = true;
        refreshUi();
      } }, "Allow notifications") : null);
    const keyRow = h("div", { class: "card" },
      h("strong", {}, state.passkey ? "✓ Face ID / fingerprint is set up" : "2. Use Face ID or fingerprint to approve"),
      !state.passkey ? h("p", { class: "row-meta" }, hasAuthenticator
        ? "So only you can approve an action from this phone. Alerts work without it."
        : "This phone has no Face ID or fingerprint set up, so it can receive alerts but not approve actions.") : null,
      !state.passkey && hasAuthenticator ? h("button", { class: "button", onclick: async () => {
        try { state.passkey = await createPasskey(name.value.trim() || "Phone"); error.textContent = ""; }
        catch (err) { error.textContent = err && err.name === "NotAllowedError" ? "That was cancelled. You can pair without it." : String(err.message || err); }
        refreshUi();
      } }, "Set up Face ID / fingerprint") : null);
    rows.replaceChildren(notifRow, keyRow);
    go.disabled = !notifOk();
  };
  go.addEventListener("click", async () => {
    error.textContent = "";
    go.disabled = true;
    try { await pairWithQr(pairing, name.value.trim() || "Phone", state.passkey); }
    catch (err) { error.textContent = String(err.message || err); go.disabled = false; }
  });
  refreshUi();
  show(h("section", { class: "pad stack" },
    h("h1", {}, "Set up this phone"),
    h("label", { for: "name" }, "Name for this phone"), name, rows, error, go));
}

// QR pairing, step 3. The QR carries the server's mailbox id (the hash of its key) and a secret the
// relay never sees: the phone pins the server from the camera, and its claim carries a proof made with
// that secret, so the relay cannot slip a device of its own in. No digits to compare.
async function pairWithQr(pairing, name, passkey) {
  const offerRes = await fetch(`/v1/pair/${pairing.code}`, { cache: "no-store" });
  if (!offerRes.ok) throw new Error("That code is unknown or has expired. Run the pairing again on the server.");
  const offer = await offerRes.json();
  const sSig = unb64u(offer.s_sig), sEnc = unb64u(offer.s_enc);
  if ((await keyId(sSig)) !== offer.mb || offer.mb !== pairing.mb || sEnc.length !== 32)
    throw new Error("This is not the server the QR code was made by. Nothing was paired.");
  const keys = await generateDevice();
  const server = { mb: offer.mb, label: String(offer.label || "server").slice(0, 40), s_sig: offer.s_sig, s_enc: offer.s_enc,
    dev: keys.dev, keys, pairedAt: Math.floor(Date.now() / 1000), name, passkeyId: passkey ? passkey.id : "", replyCounter: 0 };
  const push = await subscription().catch(() => null);
  const proof = await qrProof(pairing.secret, keys.sigPub, keys.encPub, passkey ? unb64u(passkey.spki) : new Uint8Array());
  // Kept before claiming, like a typed pairing, so a reload resumes with the same keys. The QR's
  // secret is not kept: once the claim is sent it is no longer needed.
  const pending = { code: pairing.code, server, push, deadline: Date.now() + 10 * 60_000, qr: true };
  await settings.set(PENDING, pending);
  try {
    await signedFetch(server, "POST", `/v1/pair/${pairing.code}/claim`,
      { dev: keys.dev, d_sig: b64u(keys.sigPub), d_enc: b64u(keys.encPub), name, push, proof, passkey: passkey ? passkey.spki : undefined });
  } catch (err) {
    await settings.set(PENDING, null);
    throw err;
  }
  history.replaceState(null, "", "#/pending");        // the pairing secret leaves the address bar
  return awaitConfirmation(pending);
}

// The older way: type the code and compare six digits. Alerts only: without the QR there is nothing
// binding a passkey to this phone, so the server will not let it approve anything.
async function addTyped() {
  if (!(await supported())) return addServer();
  const code = h("input", { id: "code", inputmode: "text", autocapitalize: "characters", autocomplete: "off",
    spellcheck: "false", maxlength: "11", placeholder: "XXXXX-XXXXX", "aria-describedby": "code-help", required: true });
  code.addEventListener("input", () => {
    const n = normalizeCode(code.value).slice(0, 10);
    code.value = n.length > 5 ? `${n.slice(0, 5)}-${n.slice(5)}` : n;
  });
  const name = h("input", { id: "name", maxlength: "40", value: defaultName() });
  const error = h("p", { class: "error", role: "alert" });
  const form = h("form", { class: "pad stack", onsubmit: async (e) => {
    e.preventDefault();
    error.textContent = "";
    const c = normalizeCode(code.value);
    if (!validCode(c)) { error.textContent = "The code has 10 letters and digits, as your server shows it."; return; }
    form.querySelector("button").disabled = true;
    try { await pairTyped(c, name.value.trim() || "Phone"); }
    catch (err) { error.textContent = String(err.message || err); form.querySelector("button").disabled = false; }
  } },
    h("h1", {}, "Type the code"),
    h("p", { id: "code-help" }, "On the server, run ", h("code", {}, "argus notify pair"), " and type the code it shows. Alerts only: to approve actions from this phone, scan the QR code instead."),
    h("label", { for: "code" }, "Pairing code"), code,
    h("label", { for: "name" }, "Name for this phone"), name,
    error,
    h("button", { class: "button", type: "submit" }, "Continue"),
    h("a", { class: "button ghost", href: "#/add" }, "Scan the QR code instead"));
  show(form);
  code.focus();
}

function defaultName() {
  const ua = navigator.userAgent;
  return /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android phone" : "Browser";
}

const PENDING = "pendingPairing";

async function pairTyped(code, name) {
  const offerRes = await fetch(`/v1/pair/${code}`, { cache: "no-store" });
  if (!offerRes.ok) throw new Error("That code is unknown or has expired. Run the pairing again on the server.");
  const offer = await offerRes.json();
  const sSig = unb64u(offer.s_sig), sEnc = unb64u(offer.s_enc);
  // The mailbox id is the hash of the server's key: the relay cannot substitute another.
  if ((await keyId(sSig)) !== offer.mb || sEnc.length !== 32) throw new Error("The relay returned an offer that does not check out.");
  const keys = await generateDevice();
  const server = { mb: offer.mb, label: String(offer.label || "server").slice(0, 40), s_sig: offer.s_sig, s_enc: offer.s_enc,
    dev: keys.dev, keys, pairedAt: Math.floor(Date.now() / 1000), name, passkeyId: "", replyCounter: 0 };
  const push = await subscription().catch(() => null);
  // Keep the pairing (with this phone's keys) before claiming: a reload or a
  // switch to another app mid-pairing used to lose the keys, and the server
  // then "paired" a phone that could never read anything.
  const pending = { code, server, push, deadline: Date.now() + 10 * 60_000, qr: false };
  await settings.set(PENDING, pending);
  try {
    await signedFetch(server, "POST", `/v1/pair/${code}/claim`,
      { dev: keys.dev, d_sig: b64u(keys.sigPub), d_enc: b64u(keys.encPub), name, push });
  } catch (err) {
    await settings.set(PENDING, null);
    throw err;
  }
  return awaitConfirmation(pending);
}

// Both ways of pairing wait here. Typed code: the six digits to compare. QR: nothing to compare (the
// claim carries the proof), only "confirm on the server". Resumed after a reload with the same keys.
async function awaitConfirmation(pending) {
  const { code, server, push, deadline, qr } = pending;
  const waiting = h("p", { class: "row-meta" }, "Waiting for the server…");
  const cancel = h("button", { class: "button ghost small", onclick: async () => { await settings.set(PENDING, null); location.hash = "#/servers"; } }, "Cancel");
  if (qr) {
    show(h("section", { class: "pad stack center" }, h("h1", {}, "Almost there"),
      h("p", {}, `Confirm on ${server.label} that this is your phone.`), waiting, cancel));
  } else {
    const digits = await sas(unb64u(server.s_sig), unb64u(server.s_enc), server.keys.sigPub, server.keys.encPub);
    show(h("section", { class: "pad stack center" },
      h("h1", {}, "Compare this code"),
      h("p", {}, `On ${server.label}, answer yes only if it shows exactly:`),
      h("p", { class: "sas", "aria-label": digits.split("").join(" ") }, `${digits.slice(0, 3)} ${digits.slice(3)}`),
      h("p", { class: "fine" }, "If the codes differ, answer no on the server: someone may be interfering."),
      waiting, cancel));
  }
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 2500));
    if ((await settings.get(PENDING, null))?.code !== code) return;        // cancelled elsewhere
    const st = await fetch(`/v1/pair/${code}/status?dev=${server.dev}`, { cache: "no-store" }).then((r) => r.json()).catch(() => ({}));
    if (st.active) {
      await servers.put(server);
      await settings.set(PENDING, null);
      if (push) await signedFetch(server, "PUT", `/v1/device/${server.dev}/push?mb=${server.mb}`, push).catch(() => {});
      await syncAll();
      return show(h("section", { class: "pad stack center" }, h("h1", {}, "Paired"),
        h("p", {}, `Alerts from ${server.label} now arrive on this phone.` + (server.passkeyId ? " You can approve reversible actions here." : "")),
        push ? h("a", { class: "button", href: "#/" }, "See alerts")
          : h("button", { class: "button", onclick: enableNotifications }, "Turn on notifications")));
    }
  }
  await settings.set(PENDING, null);
  throw new Error("The server did not confirm within 10 minutes. Nothing was paired.");
}

// A pairing interrupted by a reload resumes where it was, with the same keys.
async function resumePending() {
  const pending = await settings.get(PENDING, null);
  if (!pending) return false;
  if (Date.now() >= pending.deadline || !pending.server?.keys) { await settings.set(PENDING, null); return false; }
  try { await awaitConfirmation(pending); }
  catch (err) { show(h("section", { class: "pad stack" }, h("p", { class: "error", role: "alert" }, String(err.message || err)),
    h("a", { class: "button", href: "#/add" }, "Try again"))); }
  return true;
}

// --- notifications -------------------------------------------------------------------
async function registration() {
  if (!("serviceWorker" in navigator)) return null;
  return navigator.serviceWorker.ready;
}

async function subscription() {
  if (!("PushManager" in window) || Notification.permission !== "granted") return null;
  const reg = await registration();
  const existing = await reg.pushManager.getSubscription();
  if (existing) return existing.toJSON();
  const { key } = await fetch("/v1/vapid").then((r) => r.json());
  return (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: unb64u(key) })).toJSON();
}

async function enableNotifications() {
  if (!("Notification" in window) || !("PushManager" in window)) {
    status.textContent = isIos() && !standalone() ? "Add Argus to your Home Screen first." : "Notifications are not available in this browser.";
    return;
  }
  if ((await Notification.requestPermission()) !== "granted") { status.textContent = "Notifications are off."; return; }
  const sub = await subscription();
  for (const s of await servers.all()) await signedFetch(s, "PUT", `/v1/device/${s.dev}/push?mb=${s.mb}`, sub).catch(() => {});
  status.textContent = "Notifications on.";
  route();
}

async function settingsView() {
  const detail = await settings.get("lockscreenDetail", false);
  const perm = "Notification" in window ? Notification.permission : "unavailable";
  const toggle = h("input", { type: "checkbox", id: "detail", checked: detail,
    onchange: (e) => settings.set("lockscreenDetail", e.target.checked) });
  show(h("section", { class: "pad stack" },
    h("h1", {}, "Settings"),
    h("div", { class: "card" }, h("strong", {}, "Notifications"),
      h("p", { class: "row-meta" }, perm === "granted" ? "On for this phone." : perm === "denied"
        ? "Blocked in the browser's site settings." : "Off."),
      perm !== "granted" && perm !== "denied" ? h("button", { class: "button", onclick: enableNotifications }, "Turn on notifications") : null,
      isIos() && !standalone() ? h("p", { class: "fine" }, "On iPhone, add Argus to the Home Screen (Share › Add to Home Screen) to receive notifications.") : null),
    await categoryCard(),
    h("div", { class: "card" }, h("label", { class: "switch", for: "detail" }, toggle,
      h("span", {}, h("strong", {}, "Show alert titles on the lock screen"),
        h("span", { class: "row-meta" }, "Off: the lock screen shows only the severity and the server; the text stays inside the app.")))),
    h("div", { class: "card" }, h("strong", {}, "Privacy"),
      h("p", { class: "row-meta" }, "Alerts are encrypted on your server for this phone only. The relay and the push services see sizes and times, never the text. There is no account."))));
}

// Which kinds of news buzz the phone. Everything still reaches the inbox, and a
// security threat always notifies: it is the reason this app exists.
async function categoryCard() {
  const muted = new Set(await settings.get("mutedCategories", []));
  const rows = Object.entries(CATEGORIES).filter(([c]) => c !== "test").map(([c, text]) => {
    const locked = c === "threat";
    const box = h("input", { type: "checkbox", id: `cat-${c}`, checked: locked || !muted.has(c), disabled: locked,
      onchange: async (e) => {
        const now = new Set(await settings.get("mutedCategories", []));
        if (e.target.checked) now.delete(c); else now.add(c);
        await settings.set("mutedCategories", [...now]);
      } });
    return h("label", { class: "switch", for: `cat-${c}` }, box,
      h("span", {}, h("strong", {}, text), locked ? h("span", { class: "row-meta" }, "Always on.") : null));
  });
  return h("div", { class: "card" }, h("strong", {}, "Notify me about"),
    h("p", { class: "row-meta" }, "Turned-off kinds still arrive in the inbox, without a notification."), rows);
}

// --- routing -------------------------------------------------------------------------
async function route() {
  const hash = location.hash || "#/";
  if (hash.startsWith("#/m/")) return message(decodeURIComponent(hash.slice(4)));
  if (hash === "#/servers") return serverList();
  if (hash === "#/add") return addServer();
  if (hash === "#/pending") return (await resumePending()) || addServer();
  if (hash === "#/add-typed") return addTyped();
  if (hash.startsWith("#/pair")) {
    // A QR opened as a link (for example from the system camera) lands here.
    if (isIos() && !standalone()) return installGuide();
    try { return setupPhone(parsePairing(`${location.origin}/${hash}`)); }
    catch (err) { return show(h("section", { class: "pad stack" }, h("h1", {}, "Pairing"), h("p", { class: "error" }, String(err.message || err)),
      h("a", { class: "button", href: "#/add" }, "Scan again"))); }
  }
  if (hash === "#/settings") return settingsView();
  return inbox();         // "#/" and "#/?c=<category>"
}

// One check at a time; callers arriving meanwhile share it.
function sync() {
  inflight = inflight || runSync().finally(() => { inflight = null; });
  return inflight;
}

async function runSync() {
  status.textContent = "Checking…";
  try {
    const { fresh, dropped } = await syncAll();
    const problems = (await servers.all()).filter((s) => s.lastError);
    status.textContent = problems.length ? `${problems[0].label}: ${problems[0].lastError}`
      : dropped ? `${dropped} message${dropped > 1 ? "s" : ""} failed verification and were dropped`
      : fresh.length ? `${fresh.length} new` : "";
  } catch (err) {
    status.textContent = `Could not check: ${err.message || err}`;
  }
}

async function refresh() {
  route();          // the inbox syncs as it renders
}

addEventListener("hashchange", route);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") refresh(); });
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js", { type: "module", scope: "/" }).catch(() => {
    status.textContent = "Background notifications are not supported in this browser.";
  });
}
// First paint: an interrupted pairing takes precedence over the inbox.
(async () => { if (!(location.hash && location.hash !== "#/") && (await resumePending())) return; route(); })();
