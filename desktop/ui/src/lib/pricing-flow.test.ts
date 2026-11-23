// The web dashboard and the app buy the same way: through the hosted licence claim flow at
// pay.archymedes.xyz, at the prices in prices.ts. No seller payment key or local checkout route.
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { ROUTES } from "./api";
import { buyPage, checkPromo, PAY_ORIGIN, PROMO, validLicencePage } from "./licence";

const src = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");
const CLAIM = "clm_0123456789ABCDEFGHJKMNPQRSTVWXYZ";

test("in a browser, licence state and purchases go to the daemon's licence routes", () => {
  expect(ROUTES.licence_state({})).toEqual({ method: "GET", path: "/api/licence" });
  expect(ROUTES.licence_action({ action: "upgrade", plan: "desktop-monthly" }))
    .toEqual({ method: "POST", path: "/api/licence/upgrade", body: { key: "", plan: "desktop-monthly" } });
  expect(ROUTES.licence_action({ action: "poll" }).path).toBe("/api/licence/poll");
  // a crafted action stays inside /api/licence/
  expect(ROUTES.licence_action({ action: "../billing/checkout" }).path).toBe("/api/licence/..%2Fbilling%2Fcheckout");
});

test("no browser route reaches a local Stripe checkout", () => {
  for (const [cmd, route] of Object.entries(ROUTES)) {
    const r = route({ action: "upgrade", job: "x", page: "x", decision: "approve" });
    expect(`${cmd} ${r.path}`).not.toMatch(/billing|stripe|checkout/i);
  }
  const api = src("./api.ts");
  expect(api).not.toMatch(/billing|checkout\.stripe\.com|session_id/i);
});

test("only Archymedes licence pages open, the same list as the app", () => {
  for (const ok of ["manage", "recover", "buy/argus-server", "buy/argus-desktop", "buy/argus-desktop-monthly",
                    `buy/argus-desktop?claim=${CLAIM}`, `buy/argus-desktop-monthly?claim=${CLAIM}`, `buy/argus-server?claim=${CLAIM}`]) {
    expect(validLicencePage(`${PAY_ORIGIN}/${ok}`)).toBe(true);
  }
  for (const bad of ["https://checkout.stripe.com/c/pay/cs_live_abc", "http://pay.archymedes.xyz/manage",
                     "https://pay.archymedes.xyz.evil/manage", "https://pay.archymedes.xyz/buy/argus-server?claim=clm_short",
                     `https://pay.archymedes.xyz/buy/argus-server?claim=${CLAIM}&x=1`, "https://pay.archymedes.xyz/",
                     `https://pay.archymedes.xyz/buy/argus-watch?claim=${CLAIM}`, "javascript:alert(1)", ""]) {
    expect(validLicencePage(bad)).toBe(false);
  }
  // The Rust allow-list says the same.
  const rust = src("../../../src/api.rs");
  expect(rust).toContain('const BASE: &str = "https://pay.archymedes.xyz/";');
  expect(rust).not.toMatch(/checkout\.stripe\.com|\/api\/billing/);
});

test("the Pricing view buys through the claim flow at the price-book prices", () => {
  const view = src("../views/Pricing.svelte");
  expect(view).toContain('api.licenceAction("upgrade"');
  expect(view).toContain("api.openLicencePage(");
  expect(view).toContain('from "../lib/prices"');
  expect(view).not.toMatch(/\$\d/);            // no amount written outside prices.ts
  expect(view).not.toMatch(/billing(Status|Checkout|Confirm)/);
});

test("a promo code rides along to the daemon only when there is one", () => {
  expect(ROUTES.licence_action({ action: "upgrade", plan: "desktop", promo: "LAUNCH20" }).body)
    .toEqual({ key: "", plan: "desktop", promo: "LAUNCH20" });
  expect("promo" in (ROUTES.licence_action({ action: "upgrade", plan: "desktop" }).body as object)).toBe(false);
  expect("promo" in (ROUTES.licence_action({ action: "upgrade", plan: "desktop", promo: "" }).body as object)).toBe(false);
});

test("promo codes: shape check, and the checkout pages that may carry one", () => {
  expect(checkPromo("")).toEqual({ state: "empty" });
  expect(checkPromo("   ")).toEqual({ state: "empty" });
  expect(checkPromo(" Launch_20-x ")).toEqual({ state: "ok", code: "Launch_20-x" });
  expect(checkPromo("A".repeat(40)).state).toBe("ok");
  for (const bad of ["A".repeat(41), "SAVE 20", "a&b", "a.b", "été", "<b>", "%41", "a?b", "a#b"]) expect(checkPromo(bad)).toEqual({ state: "bad" });
  expect(PROMO.source).toBe("^[A-Za-z0-9_-]{1,40}$");
  expect(buyPage("argus-server", checkPromo("FLEET10"))).toBe("buy/argus-server?promo=FLEET10");
  expect(buyPage("argus-desktop", checkPromo(""))).toBe("buy/argus-desktop");
  expect(buyPage("argus-desktop-monthly", checkPromo("bad code"))).toBe("buy/argus-desktop-monthly");
  for (const ok of [`buy/argus-desktop?claim=${CLAIM}&promo=LAUNCH_20-x`, "buy/argus-server?promo=FLEET10",
                    `buy/argus-desktop-monthly?claim=${CLAIM}&promo=${"A".repeat(40)}`]) {
    expect(validLicencePage(`${PAY_ORIGIN}/${ok}`)).toBe(true);
  }
  for (const bad of [`buy/argus-desktop?claim=${CLAIM}&promo=`, `buy/argus-desktop?claim=${CLAIM}&promo=${"A".repeat(41)}`,
                     `buy/argus-desktop?claim=${CLAIM}&promo=A&x=1`, `buy/argus-desktop?claim=${CLAIM}&promo=A%20B`,
                     "buy/argus-desktop?promo=", "buy/argus-desktop?promo=A&claim=x", "manage?promo=A", "buy/argus-watch?promo=A",
                     `buy/argus-desktop?promo=A&claim=${CLAIM}`, "buy/argus-desktop?promo=a&allow_promotion_codes=false"]) {
    expect(validLicencePage(`${PAY_ORIGIN}/${bad}`)).toBe(false);
  }
});

test("the Pricing view passes the promo code through the claim, and shows list prices only", () => {
  const view = src("../views/Pricing.svelte");
  expect(view).toContain("checkPromo(promoText)");
  expect(view).toMatch(/api\.licenceAction\("upgrade", undefined, [^)]*promo\.state === "ok" \? promo\.code : undefined\)/s);
  expect(view).toContain('tr("Promo code (optional)")');
  // a malformed code stops before the daemon is asked
  expect(view.indexOf('if (promo.state === "bad")')).toBeLessThan(view.indexOf('api.licenceAction("upgrade"'));
  expect(view).not.toMatch(/discount|percent_off|amount_off/i);
});
