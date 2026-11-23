import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { NAV } from "./nav";

// 2026-11-07: the Licence item had no "nav.licence" wording; t() threw while the
// sidebar rendered and the whole app came up blank. The cast in the template hid it.
// words.ts needs the Svelte runtime, so its keys are read from the source.
const words = readFileSync(new URL("./words.ts", import.meta.url), "utf8");

test("every navigation item has its wording in both modes", () => {
  for (const n of NAV) {
    const m = words.match(new RegExp(`"nav\\.${n.view}":\\s*\\["([^"]+)",\\s*"([^"]+)"\\]`));
    expect(m, n.view).not.toBeNull();
  }
});
