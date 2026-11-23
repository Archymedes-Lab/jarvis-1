// IndexedDB for the app and its service worker: paired servers (with this phone's
// non-extractable keys for each), decrypted messages and settings. Nothing here
// leaves the phone.
const DB = "argus-notify";
const RANK = { critical: 0, high: 1, medium: 2, low: 3, ok: 4, info: 5 };
const VERSION = 1;

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      db.createObjectStore("servers", { keyPath: "mb" });
      const m = db.createObjectStore("messages", { keyPath: "id" });
      m.createIndex("at", "at");
      db.createObjectStore("settings");
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx(store, mode, fn) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const result = fn(t.objectStore(store));
    t.oncomplete = () => resolve(result && "result" in result ? result.result : result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

export const servers = {
  all: () => tx("servers", "readonly", (s) => s.getAll()),
  get: (mb) => tx("servers", "readonly", (s) => s.get(mb)),
  put: (server) => tx("servers", "readwrite", (s) => s.put(server)),
  remove: (mb) => tx("servers", "readwrite", (s) => s.delete(mb)),
};

export const messages = {
  // Newest first; within the same second the most severe first.
  all: async () => (await tx("messages", "readonly", (s) => s.getAll()))
    .sort((a, b) => b.at - a.at || (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9)),
  get: (id) => tx("messages", "readonly", (s) => s.get(id)),
  put: (m) => tx("messages", "readwrite", (s) => s.put(m)),
  remove: (id) => tx("messages", "readwrite", (s) => s.delete(id)),
  removeServer: async (mb) => {
    for (const m of await messages.all()) if (m.mb === mb) await messages.remove(m.id);
  },
  // Keep the inbox bounded on the phone too.
  prune: async (keep = 500) => {
    const all = await messages.all();
    for (const m of all.slice(keep)) await messages.remove(m.id);
  },
};

export const settings = {
  get: (k, fallback) => tx("settings", "readonly", (s) => s.get(k)).then((v) => (v === undefined ? fallback : v)),
  set: (k, v) => tx("settings", "readwrite", (s) => s.put(v, k)),
};
