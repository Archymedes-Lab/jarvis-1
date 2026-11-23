// Make a licence signing key pair. docs/STRIPE-HANDOFF.md, "Signing keys".
//
//   bun scripts/licence-keygen.ts [--kid 2026-11-a] [--out ~/.config/archymedes] [--client ../../jarvis/licensing/trust.py]
//
// - The private key goes to <out>/argus-licence-<kid>.secret (mode 0600), outside the repository, in the
//   form the Worker reads: "<kid>.<base64url PKCS#8>". It is never printed.
// - The public key is added to the client's PUBLIC_KEYS (jarvis/licensing/trust.py); keys already there stay,
//   so leases signed by the previous kid keep verifying during a rotation.
// - Then it prints the `wrangler secret put` commands to run (test and live are separate Workers/keys).
import { chmodSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { b64url } from "../src/cert";

const args = process.argv.slice(2);
const opt = (name: string, dflt: string) => { const i = args.indexOf(`--${name}`); return i >= 0 && args[i + 1] ? args[i + 1] : dflt; };
const month = new Date().toISOString().slice(0, 7);
const kid = opt("kid", `${month}-a`);
if (!/^[A-Za-z0-9-]{1,32}$/.test(kid)) throw new Error("kid: letters, digits and dashes, at most 32");
const outDir = resolve(opt("out", join(homedir(), ".config", "archymedes")).replace(/^~/, homedir()));
const client = resolve(opt("client", join(import.meta.dir, "..", "..", "..", "jarvis", "licensing", "trust.py")));

const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey) as ArrayBuffer);
const pub = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey) as ArrayBuffer));

mkdirSync(outDir, { recursive: true, mode: 0o700 });
const secretPath = join(outDir, `argus-licence-${kid}.secret`);
if (existsSync(secretPath)) throw new Error(`${secretPath} exists; choose another --kid`);
writeFileSync(secretPath, `${kid}.${b64url(pkcs8)}`, { mode: 0o600 });
chmodSync(secretPath, 0o600);

const src = readFileSync(client, "utf8");
const begin = src.indexOf("PUBLIC_KEYS = {"), end = src.indexOf("}", begin);
if (begin < 0 || end < 0) throw new Error(`no PUBLIC_KEYS block in ${client}`);
const entry = `    '${kid}': '${pub}',\n`;
writeFileSync(client, src.slice(0, end) + entry + src.slice(end));

console.log(`kid:          ${kid}`);
console.log(`public key:   ${pub}  (added to ${client})`);
console.log(`private key:  ${secretPath}  (0600; keep it out of git; back it up in your password manager)`);
console.log("\nNext:");
console.log(`  npx wrangler secret put LICENCE_SIGNING_KEY < ${secretPath}`);
console.log("  openssl rand -base64 48 | tr -d '\\n' | npx wrangler secret put KEY_PEPPER   # once, never rotate casually");
console.log("  commit trust.py, ship that Argus release, then deploy the Worker.");
