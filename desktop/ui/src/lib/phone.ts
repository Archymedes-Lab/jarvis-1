// Pure helpers for the phone pairing screens (tested in phone.test.ts).
import type { PairState } from "./api";

/** "123456" -> "123 456", the way the phone shows it. */
export function spacedSas(sas: string | undefined): string {
  return sas && /^\d{6}$/.test(sas) ? `${sas.slice(0, 3)} ${sas.slice(3)}` : "";
}

/** Seconds -> "9:05". */
export function clock(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** Still in progress: the page keeps polling only in "waiting". */
export const live = (s: PairState | undefined): boolean => s === "waiting" || s === "claimed" || s === "confirming";

export function tone(s: PairState | undefined): "ok" | "bad" | "run" {
  if (s === "paired") return "ok";
  if (s === "rejected" || s === "expired" || s === "error" || s === "cancelled") return "bad";
  return "run";
}

/** Relay URL without the scheme, for reading aloud or typing on a phone. */
export function bareUrl(url: string): string {
  return url.replace(/^https?:\/\//, "").replace(/\/$/, "");
}
