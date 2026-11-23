// Groups the collectors the daemon reports blind by cause, so the status banner
// can say "Administrator sensor · 9, Not reporting · 7" instead of one long
// sentence. Grouping only: every item stays in exactly one group.
import type { BlindItem, BlindKind } from "./api";

export type BlindGroup = { kind: BlindKind; title: string; help: string; items: BlindItem[] };

/** Display order and wording. Short titles double as the chip labels. */
export const GROUPS: { kind: BlindKind; title: string; help: string }[] = [
  { kind: "failed", title: "Failed last run", help: "Run one again, or open Collectors to see the error." },
  { kind: "stale", title: "Not reporting", help: "These usually catch up by themselves after the computer wakes up or ARGUS-INSTINCT restarts." },
  { kind: "admin_sensor", title: "Administrator sensor", help: "This edition runs without administrator rights, so these checks see less. It is a limit of this edition, not a fault." },
  { kind: "other", title: "Other", help: "" },
];

const KINDS = new Set<BlindKind>(GROUPS.map((g) => g.kind));

/** Non-empty groups in display order; an unknown kind from a newer shell counts as "other". */
export function groupBlind(items: BlindItem[] | undefined): BlindGroup[] {
  const by = new Map<BlindKind, BlindItem[]>();
  for (const it of items ?? []) {
    const kind = KINDS.has(it.kind) ? it.kind : "other";
    by.set(kind, [...(by.get(kind) ?? []), it]);
  }
  return GROUPS.filter((g) => by.has(g.kind)).map((g) => ({ ...g, items: by.get(g.kind)! }));
}

/** True when the only thing missing is the edition's administrator sensor: a known
 *  limit, shown calmly rather than as a warning. */
export function onlyEditionLimits(items: BlindItem[] | undefined): boolean {
  return !!items?.length && items.every((i) => i.kind === "admin_sensor");
}

/** The shell's status sentences that carry a count (desktop/src/lifecycle.rs classify_pulse),
 *  as a translation key plus its number, so they can be translated like any other string.
 *  Anything else is returned as is, for tr() to look up whole. */
const COUNTED: [RegExp, string][] = [
  [/^ARGUS-INSTINCT is running, but (\d+) of its checks are not working$/, "ARGUS-INSTINCT is running, but {n} of its checks are not working"],
  [/^ARGUS-INSTINCT can't fully check (\d+) parts of your computer right now$/, "ARGUS-INSTINCT can't fully check {n} parts of your computer right now"],
];
export function statusKey(message: string): { key: string; n?: number } {
  for (const [re, key] of COUNTED) {
    const m = re.exec(message);
    if (m) return { key, n: Number(m[1]) };
  }
  return { key: message };
}
