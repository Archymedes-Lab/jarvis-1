// Grant a complimentary licence through the deployed Worker (src/admin.ts), without knowing KEY_PEPPER.
// docs/STRIPE-HANDOFF.md, "Complimentary licences".
//
//   read -rsp 'ADMIN_GRANT_SECRET: ' ADMIN_GRANT_SECRET; echo; export ADMIN_GRANT_SECRET
//   bun scripts/admin-grant.ts argus-desktop someone@example.com 3 365 cofounder
//   unset ADMIN_GRANT_SECRET
//
// The secret is used to sign the request and is never sent. Each secret makes one grant.
// PAY_ORIGIN overrides the endpoint (default https://pay.archymedes.xyz), e.g. a local `bun run dev`.
import { hmacHex } from "../src/stripe";

const secret = process.env.ADMIN_GRANT_SECRET || "";
if (secret.length < 32) { console.error("set ADMIN_GRANT_SECRET (the same value as the Worker secret) in the environment"); process.exit(2); }
const [offer, email, seats = "1", days = "365", note = "complimentary"] = process.argv.slice(2);
if (!offer || !email) { console.error("usage: admin-grant.ts <offer> <email> [seats] [days] [role]"); process.exit(2); }
const origin = process.env.PAY_ORIGIN || "https://pay.archymedes.xyz";
const body = JSON.stringify({ offer, email, seats: Number(seats), days: Number(days), note });
const t = Math.floor(Date.now() / 1000);
const res = await fetch(`${origin}/admin/grant`, {
  method: "POST", body,
  headers: { "Content-Type": "application/json", "X-Admin-Signature": `t=${t},v1=${await hmacHex(secret, `${t}.${body}`)}` },
});
const out = (await res.json().catch(() => ({}))) as any;
if (!res.ok) { console.error(`refused (${res.status} ${out.code ?? ""}): ${out.error ?? "no detail"}`); process.exit(1); }
console.log(`key (hand it over in person or by a private channel; it is not stored): ${out.key}`);
console.log(`licence ${out.licence_id}, ends ${out.ends}. This admin secret is now spent.`);
