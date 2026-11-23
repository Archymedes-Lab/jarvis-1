// Plain-language wording for the Simple mode. The category guidance is the
// dashboard's own (lib/guide.json, kept in step with the GUIDE in jarvis/web/static/dashboard.js),
// so both interfaces tell the same story. General background, never a verdict.
import guide from "./guide.json";
import type { Finding } from "./model";

const G = guide as Record<string, string[]>;
const SEVERITY_WHY: Record<string, string> = {
  critical: "If it is real, it can seriously harm this computer or your data.",
  high: "Worth looking at soon.",
  medium: "Worth a look, rarely urgent.",
  low: "For your information.",
};

export interface Plain { means: string; why: string; next: string }

/** True when the category has plain wording of its own; otherwise show the finding's own title. */
export function hasGuide(f: Finding): boolean { return Boolean(G[f.category ?? ""]); }

export function plainFinding(f: Finding): Plain {
  const g = G[f.category ?? ""];
  if (g) return { means: g[0], why: g[1], next: g[2] };
  return {
    means: "ARGUS-INSTINCT noticed something it wants you to know about.",
    why: SEVERITY_WHY[f.severity] ?? "ARGUS-INSTINCT has not rated this.",
    next: "Open it and decide whether you expect this on your computer.",
  };
}

export interface Headline { tone: "ok" | "warn" | "bad" | "unknown"; title: string; body: string; vars: Record<string, number>; partial?: string }

export const PARTIAL = "Some of ARGUS-INSTINCT's checks are not reporting right now, so this picture may be incomplete.";

/** One calm sentence about the whole computer, from the numbers the daemon reports.
 *  With nothing found it never says the computer is fine or safe: the absence of alerts
 *  does not prove safety (honesty rule carried over from the Normal/Pro views, d50ac10).
 *  `title` and `body` are English keys with {n} placeholders; the view translates them. */
export function headline(score: number | null | undefined, critical: number, high: number, notReporting: number): Headline {
  if (score === null || score === undefined) {
    return { tone: "unknown", title: "ARGUS-INSTINCT is still getting a look at your computer", body: "Check back in a minute.", vars: {} };
  }
  const partial = notReporting ? PARTIAL : undefined;
  if (critical) {
    return { tone: "bad", title: critical === 1 ? "1 thing needs your attention" : "{n} things need your attention",
      body: "Start with the most urgent one below. This is not proof that something is wrong, only that it is worth a look.", vars: { n: critical }, partial };
  }
  if (high) {
    return { tone: "warn", title: "Nothing urgent, but a few things are worth a look",
      body: high === 1 ? "1 item could use your attention when you have a minute." : "{n} items could use your attention when you have a minute.", vars: { n: high }, partial };
  }
  return { tone: "ok", title: "No signs of trouble right now", body: "Nothing needs you right now.", vars: {}, partial };
}


/** A short name for categories the guide does not cover, so a group never reads as
 *  "noticed something". Labels follow what the findings in that category say. */
export const CATEGORY_LABEL: Record<string, string> = {
  "not observable": "Attacker techniques ARGUS-INSTINCT cannot see yet",
  "not applicable": "Attacker techniques that do not apply here",
  "coverage gap": "Gaps in what is watched",
  "appcode": "Known flaws in your code's dependencies",
  "containers": "Container settings and versions",
  "ledger": "Earlier items that came back or are still open",
  "ran": "Programs that ran at startup",
  "present": "Passwords and keys stored in plain text",
  "tampering": "Possible tampering",
  "": "Things ARGUS-INSTINCT could not fully see",
  "sysmon-linux": "Activity on the Linux side",
  "history": "Programs launched from startup places",
  "named process": "Programs named like known malware",
  "c2 match": "Connections to listed attacker addresses",
  "tracked": "Passwords and keys in plain text, already reported",
};

/** The group's name: its plain sentence when the guide has one, else its label or category. */
export function groupLabel(category: string | null | undefined): string {
  const c = category ?? "";
  return CATEGORY_LABEL[c] ?? (c ? c.charAt(0).toUpperCase() + c.slice(1) : CATEGORY_LABEL[""]);
}
