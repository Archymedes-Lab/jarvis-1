// Support helper for docs/STRIPE-HANDOFF.md runbooks. Needs KEY_PEPPER in the environment (the same value as
// the Worker secret; read it from your password manager, never from a file in the repo). Prints SQL to run with
// `npx wrangler d1 execute argus-licence --remote --command "<sql>"`. It never connects to anything.
//
//   KEY_PEPPER=… bun scripts/support.ts key ARGUS-SRV-…        find the licence for a key
//   KEY_PEPPER=… bun scripts/support.ts email someone@x.com     find licences for a purchase email
//   KEY_PEPPER=… bun scripts/support.ts reissue <cs_…> <current key_gen> <server|desktop>
//                                                              a new key for a leaked one (the old key stops working)
//   KEY_PEPPER=… bun scripts/support.ts grant argus-desktop someone@x.com [seats] [days] [role]
//                                                              a complimentary licence, no Stripe (src/grant.ts)
import { deriveKey, emailHash, keyHash, parseKey } from "../src/keys";

const pepper = process.env.KEY_PEPPER || "";
if (pepper.length < 32) { console.error("set KEY_PEPPER (the Worker secret) in the environment"); process.exit(2); }
const [cmd, a, b, c] = process.argv.slice(2);
const q = (s: string) => `'${s.replace(/'/g, "''")}'`;

if (cmd === "key") {
  const p = parseKey(a);
  if (!p.ok) { console.error(`not a valid key (${p.reason})`); process.exit(2); }
  console.log(`SELECT id, offer, status, lic_exp, key_last4 FROM licences_v2 WHERE key_hash = ${q(await keyHash(pepper, p.key))};`);
} else if (cmd === "email") {
  console.log(`SELECT id, offer, status, lic_exp, key_last4 FROM licences_v2 WHERE email_hash = ${q(await emailHash(pepper, a || ""))};`);
} else if (cmd === "reissue") {
  const gen = Number(b) + 1;
  if (!/^cs_(test|live)_/.test(a || "") || !Number.isInteger(gen) || !["server", "desktop"].includes(c)) {
    console.error("usage: reissue <checkout session id> <current key_gen> <server|desktop>"); process.exit(2);
  }
  const key = await deriveKey(pepper, a, gen, c === "server" ? "SERVER" : "DESKTOP");
  console.log(`new key (send it to the customer; it is not stored): ${key}`);
  console.log(`UPDATE licences_v2 SET key_gen = ${gen}, key_hash = ${q(await keyHash(pepper, key))}, key_last4 = ${q(key.slice(-4))}, ` +
              `emailed_at = NULL WHERE session_id = ${q(a)} AND key_gen = ${gen - 1};`);
  console.log("Machines already activated keep working (they renew with their device key, not the key). If the key leaked, release the strangers' machines too: UPDATE activations_v2 SET released_at = unixepoch(), released_by = 'support' WHERE licence_id = 'lic_…' AND id <> 'act_… (the owner's)';");
} else if (cmd === "grant") {
  // grant <offer> <email> [seats] [days] [note]   e.g. grant argus-desktop someone@x.com 3 365 cofounder
  const { grant, asSql } = await import("../src/grant");
  const g = await grant(pepper, { offer: a, email: b || "", seats: Number(c ?? 1), days: Number(process.argv[6] ?? 365),
                                  note: process.argv[7] ?? "complimentary", livemode: true }, Math.floor(Date.now() / 1000));
  console.log(`key (hand it over in person or by a private channel; it is not stored): ${g.key}`);
  console.log(`licence ${g.licenceId}, ends ${new Date(g.licExp * 1000).toISOString().slice(0, 10)}`);
  console.log(asSql(g.statements));
  console.log(`Extend later: UPDATE licences_v2 SET lic_exp = <unix time>, updated_at = unixepoch() WHERE id = '${g.licenceId}'; ` +
              `INSERT INTO audit (at, licence_id, action, actor) VALUES (unixepoch(), '${g.licenceId}', 'grant extended', 'support');`);
} else {
  console.error("commands: key <key> | email <address> | reissue <session> <gen> <server|desktop> | grant <offer> <email> [seats] [days] [note]"); process.exit(2);
}
