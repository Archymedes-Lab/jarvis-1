// The product is ARGUS-INSTINCT. Same rule as the web pages (brand:begin in jarvis/web/static)
// and the daemon (jarvis/core/brand.py); tests/test_ui_brand.py keeps the copies equal.
// Daemon text can say JARVIS where the word is an identity (finding titles match
// acknowledgements), so it is re-branded here, where it is shown.
const BRAND = "ARGUS-INSTINCT";
const BRAND_KEEP = /^ (input hook|independent health monitor|connectivity guard|native sensor|Jarvis)/;

export const brand = (s: unknown): string => String(s ?? "").replace(/\bJARVIS\b(?!-(?:1|INSTINCT)\b)/g,
  (m: string, i: number, all: string) => (BRAND_KEEP.test(all.slice(i + m.length)) ? m : BRAND));

// Fields the app sends back to the daemon to act on one thing: never rewritten,
// or an action would name something that does not exist.
const IDENTITY = new Set(["key", "id", "fp", "guid", "job", "name", "where", "host", "kind",
  "command", "category", "token", "path", "exe", "url"]);

/** A copy of `value` with every displayed string branded; identity fields kept. */
export function brandDeep<T>(value: T, field = ""): T {
  if (typeof value === "string") return (IDENTITY.has(field) ? value : brand(value)) as T;
  if (Array.isArray(value)) return value.map((v) => brandDeep(v, field)) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = brandDeep(v, k);
    return out as T;
  }
  return value;
}
