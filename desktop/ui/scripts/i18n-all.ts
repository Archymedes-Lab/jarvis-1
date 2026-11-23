// Every string that must have an entry in each locale: tr() literals, the
// vocabulary table in words.ts (both registers), and the few strings that reach
// tr() through variables (see i18n-keys.ts).
import { readFileSync } from "node:fs";
import { collectKeys } from "./i18n-keys";

export function allKeys(root = "src"): string[] {
  const keys = new Set(collectKeys(root));
  const w = readFileSync(`${root}/lib/words.ts`, "utf8");
  const block = w.slice(w.indexOf("export const W = {"), w.indexOf("} as const;"));
  const re = /\[\s*"((?:\\.|[^"\\])*)"\s*,\s*"((?:\\.|[^"\\])*)"\s*\]/g;
  for (const m of block.matchAll(re)) {
    for (const s of [m[1], m[2]]) if (s) keys.add(JSON.parse(`"${s}"`));
  }
  // The category guidance shown in Simple mode (lib/guide.json) reaches tr() through plainFinding().
  const guide = JSON.parse(readFileSync(`${root}/lib/guide.json`, "utf8")) as Record<string, string[]>;
  for (const lines of Object.values(guide)) for (const s of lines) keys.add(s);
  return [...keys].sort();
}

if (import.meta.main) {
  const keys = allKeys();
  console.error(`${keys.length} keys`);
  console.log(JSON.stringify(keys, null, 1));
}
