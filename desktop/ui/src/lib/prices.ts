// Argus prices, as decided in the price book: archymedes-gtm catalog/stripe.ts and
// docs/PRICE-BOOK.md (owner decisions 2026-11-04 to 2026-11-06). The licence service
// (hosted/licence-cloudflare) sells them by Stripe lookup key; prices.test.ts checks the
// Desktop amounts against those keys. Change both places together.

export const DESKTOP = { yearCents: 7900, monthCents: 1500, teamMax: 100 } as const;

/** Server: one fleet licence, graduated per server per year. */
export const SERVER_TIERS: { upTo: number; usdCents: number }[] = [
  { upTo: 10, usdCents: 5000 }, { upTo: 50, usdCents: 4000 }, { upTo: 250, usdCents: 3000 }, { upTo: 1000, usdCents: 2000 },
];
export const FLEET_MAX = 1000;   // above it: enterprise terms by contact

/** Yearly cost in cents of `n` servers on the graduated tiers; null above FLEET_MAX or for a bad count. */
export function fleetCents(n: number): number | null {
  if (!Number.isInteger(n) || n < 1 || n > FLEET_MAX) return null;
  let total = 0, from = 0;
  for (const t of SERVER_TIERS) {
    const to = Math.min(n, t.upTo);
    if (to > from) total += (to - from) * t.usdCents;
    from = t.upTo;
    if (from >= n) break;
  }
  return total;
}

/** What a year of monthly payments costs over the yearly price, in cents. */
export const yearlySavingCents = DESKTOP.monthCents * 12 - DESKTOP.yearCents;

/** "$79" or "$1,234.50" in the interface language. */
export function usd(cents: number, lang = "en"): string {
  const whole = cents % 100 === 0;
  return new Intl.NumberFormat(lang, { style: "currency", currency: "USD", minimumFractionDigits: whole ? 0 : 2, maximumFractionDigits: 2 }).format(cents / 100);
}
