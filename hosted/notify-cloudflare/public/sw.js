// Service worker: the shell offline, and on an (empty) push: fetch, verify, decrypt,
// notify. What a lock screen shows is the owner's choice (Settings); by default only
// the severity and the server, never the alert's text.
import { CATEGORIES, syncAll } from "./lib/sync.js";
import { settings } from "./lib/store.js";

const SHELL = "argus-shell-v2";
const FILES = ["/", "/index.html", "/app.js", "/style.css", "/lib/protocol.js", "/lib/store.js", "/lib/sync.js",
  "/lib/passkey.js", "/lib/qr.js",
  "/manifest.webmanifest", "/icons/icon-192.png", "/icons/icon-512.png", "/icons/badge-72.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(SHELL).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== SHELL).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || url.pathname.startsWith("/v1/") || e.request.method !== "GET") return;
  e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request).catch(() => caches.match("/index.html"))));
});

const RANK = { critical: 0, high: 1, medium: 2, low: 3, ok: 4, info: 5 };

self.addEventListener("push", (e) => {
  e.waitUntil((async () => {
    const { fresh } = await syncAll();
    const detail = await settings.get("lockscreenDetail", false);
    // Muted categories still reach the inbox; they just do not buzz the phone.
    // A security threat cannot be muted.
    const muted = new Set((await settings.get("mutedCategories", [])).filter((c) => c !== "threat"));
    const alerts = [...fresh].filter((m) => !muted.has(m.category))
      .sort((a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9));
    if (!alerts.length) {
      // Browsers (and iOS, which drops a subscription that stays silent) require a visible notification
      // for every push. A push with nothing new is rare now: the relay only wakes a phone for a message.
      // Replace, never stack: one quiet entry under a fixed tag.
      return self.registration.showNotification("Argus", { body: "Nothing new.", tag: "argus-sync",
        icon: "/icons/icon-192.png", badge: "/icons/badge-72.png", silent: true });
    }
    const shown = alerts.length > 3 ? [summary(alerts)] : alerts.map((m) => single(m, detail));
    for (const n of shown) await self.registration.showNotification(n.title, n.options);
  })());
});

function single(m, detail) {
  const where = m.label || m.host || "your server";
  if (m.kind === "approval") {
    // Needs a person: always visible, and it stays until acted on. iOS web push has no action buttons,
    // so the tap opens the app on the request.
    return { title: `Argus · ${where}`, options: { body: "Approval needed. Tap to review.", tag: m.id,
      icon: "/icons/icon-192.png", badge: "/icons/badge-72.png", data: { url: `/#/m/${m.id}` }, requireInteraction: true } };
  }
  const kind = CATEGORIES[m.category] || CATEGORIES.system;
  return {
    title: detail ? `${kind} · ${m.severity.toUpperCase()} · ${where}` : `${kind} · ${where}`,
    options: { body: detail ? m.title : `${article(m.severity)} ${m.severity} alert. Open to read it.`,
      tag: m.id, icon: "/icons/icon-192.png", badge: "/icons/badge-72.png",
      data: { url: `/#/m/${m.id}` }, requireInteraction: m.severity === "critical" },
  };
}

function summary(alerts) {
  const servers = new Set(alerts.map((m) => m.label || m.host));
  const kinds = [...new Set(alerts.map((m) => CATEGORIES[m.category] || CATEGORIES.system))].join(", ");
  return { title: "Argus", options: { body: `${alerts.length} new alerts from ${servers.size} server${servers.size > 1 ? "s" : ""}: ${kinds}.`,
    tag: "argus-summary", icon: "/icons/icon-192.png", badge: "/icons/badge-72.png", data: { url: "/#/" } } };
}

const article = (s) => (/^[aeiou]/.test(s) ? "An" : "A");

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const target = (e.notification.data && e.notification.data.url) || "/#/";
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((wins) => {
    for (const w of wins) if ("focus" in w) { w.navigate(target); return w.focus(); }
    return self.clients.openWindow(target);
  }));
});
