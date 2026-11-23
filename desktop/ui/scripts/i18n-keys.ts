// Lists every English string the interface asks tr() to translate.
// Used by the locale test and to produce a worklist for translators.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) { if (n !== "locales") walk(p, out); }
    else if (/\.(svelte|ts)$/.test(n) && !/\.test\.ts$/.test(n)) out.push(p);
  }
  return out;
}

/** Every status sentence the desktop shell can send (desktop/src/lifecycle.rs): the
 *  interface shows them through tr(), so each needs a translation like any other string.
 *  Literal messages are read from Status::new(Phase::X, "…") and the messages built for
 *  blind collectors; counted ones ({n}) are matched by lib/blind.ts statusKey. */
export function shellStatusKeys(root = "src"): string[] {
  const rs = readFileSync(join(root, "..", "..", "src", "lifecycle.rs"), "utf8");
  const code = rs.slice(0, rs.indexOf("#[cfg(test)]"));
  const out = new Set<string>();
  for (const m of code.matchAll(/Status::new\(\s*Phase::\w+,\s*"((?:\\.|[^"\\])*)"/g)) out.add(JSON.parse(`"${m[1]}"`));
  for (const m of code.matchAll(/(?:format!\(|^\s*)"(ARGUS-INSTINCT (?:is running, but|can't fully check)[^"]*)"/gm)) out.add(m[1]);
  return [...out];
}

export function collectKeys(root = "src"): string[] {
  const keys = new Set<string>();
  const re = /\btr\(\s*"((?:\\.|[^"\\])*)"/g;
  for (const f of walk(root)) {
    const text = readFileSync(f, "utf8");
    for (const m of text.matchAll(re)) keys.add(JSON.parse(`"${m[1]}"`));
  }
  // Strings that reach tr() through a variable.
  const extra = [
    "Automatic", "Light", "Dark", "15 minutes", "1 hour", "4 hours", "24 hours",
    "Critical", "High", "Medium", "Low", "Ok", "never",
    // plain.ts CATEGORY_LABEL
    "Passwords and keys in plain text, already reported",
    "Activity on the Linux side",
    "Attacker techniques ARGUS-INSTINCT cannot see yet",
    "Attacker techniques that do not apply here",
    "Connections to listed attacker addresses",
    "Container settings and versions",
    "Earlier items that came back or are still open",
    "Gaps in what is watched",
    "Known flaws in your code's dependencies",
    "Passwords and keys stored in plain text",
    "Possible tampering",
    "Programs launched from startup places",
    "Programs named like known malware",
    "Programs that ran at startup",
    "Things ARGUS-INSTINCT could not fully see",
    "ARGUS-INSTINCT is still getting a look at your computer", "Check back in a minute.",
    "1 thing needs your attention", "{n} things need your attention",
    "Start with the most urgent one below. This is not proof that something is wrong, only that it is worth a look.",
    "Nothing urgent, but a few things are worth a look",
    "1 item could use your attention when you have a minute.", "{n} items could use your attention when you have a minute.",
    "No signs of trouble right now", "Nothing needs you right now.",
    "Some of ARGUS-INSTINCT's checks are not reporting right now, so this picture may be incomplete.",
    // Pricing plan features reach tr() through a list.
    "Continuous monitoring of this computer", "Plain-language assistant", "Investigate any finding with one click",
    "Approvals, reports and daily briefing",
    // lib/blind.ts GROUPS reach tr() through the status banner.
    "Failed last run", "Run one again, or open Collectors to see the error.",
    "Not reporting", "These usually catch up by themselves after the computer wakes up or ARGUS-INSTINCT restarts.",
    "Administrator sensor", "This edition runs without administrator rights, so these checks see less. It is a limit of this edition, not a fault.",
    "Other",
  ];
  for (const k of extra) keys.add(k);
  for (const k of shellStatusKeys(root)) keys.add(k);
  return [...keys].sort();
}

if (import.meta.main) console.log(JSON.stringify(collectKeys(), null, 1));
