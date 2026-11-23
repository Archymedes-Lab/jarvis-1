// A scripted phone for the local end-to-end test: the same protocol.js the app uses.
// Usage: bun tests/e2e_phone.js BASE CODE  — prints JSON lines on stdout.
import { b64u, generateDevice, keyId, openEnvelope, sas, signRequest, unb64u } from "../public/lib/protocol.js";

const [base, code] = process.argv.slice(2);
const say = (o) => console.log(JSON.stringify(o));
const enc = new TextEncoder();

async function signed(dev, method, path, body) {
  const bytes = body === undefined ? new Uint8Array() : enc.encode(JSON.stringify(body));
  const headers = await signRequest(dev.sigPriv, dev.sigPub, method, path, bytes, Date.now() / 1000);
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : bytes });
  return { status: res.status, json: await res.json().catch(() => null), headers };
}

const offer = await (await fetch(`${base}/v1/pair/${code}`)).json();
if ((await keyId(unb64u(offer.s_sig))) !== offer.mb) { say({ error: "offer does not check out" }); process.exit(1); }
const dev = await generateDevice();
const claim = await signed(dev, "POST", `/v1/pair/${code}/claim`,
  { dev: dev.dev, d_sig: b64u(dev.sigPub), d_enc: b64u(dev.encPub), name: "e2e phone", push: null });
say({ step: "claimed", status: claim.status });
// A second phone racing for the same code must be refused.
const intruder = await generateDevice();
const second = await signed(intruder, "POST", `/v1/pair/${code}/claim`,
  { dev: intruder.dev, d_sig: b64u(intruder.sigPub), d_enc: b64u(intruder.encPub), name: "intruder", push: null });
say({ step: "second_claim", status: second.status });
say({ step: "sas", sas: await sas(unb64u(offer.s_sig), unb64u(offer.s_enc), dev.sigPub, dev.encPub), dev: dev.dev });

for (let i = 0; i < 60; i++) {
  const st = await (await fetch(`${base}/v1/pair/${code}/status?dev=${dev.dev}`)).json();
  if (st.active) { say({ step: "active" }); break; }
  await new Promise((r) => setTimeout(r, 500));
}

const path = `/v1/device/${dev.dev}/inbox?mb=${offer.mb}`;
const deadline = Date.now() + 30_000;
let got = 0;
while (Date.now() < deadline && got < 1) {
  const r = await signed(dev, "GET", path);
  if (r.status !== 200) { say({ step: "inbox", status: r.status }); break; }
  for (const env of r.json) {
    const p = await openEnvelope(env, dev.encPriv, unb64u(offer.s_sig));
    say({ step: "message", payload: p, relay_saw: Object.keys(env).sort() });
    got += 1;
  }
  if (r.json.length) {
    const ack = await signed(dev, "POST", `/v1/device/${dev.dev}/ack?mb=${offer.mb}`, { ids: r.json.map((e) => e.id) });
    say({ step: "ack", status: ack.status });
    // Replaying the exact signed request must be refused.
    const replay = await fetch(base + path, { headers: r.headers });
    say({ step: "replay", status: replay.status });
  }
  await new Promise((res) => setTimeout(res, 500));
}
// Two identical requests in the same second are distinct (signed nonce), never a "replay".
const [a, b] = await Promise.all([signed(dev, "GET", path), signed(dev, "GET", path)]);
say({ step: "same_second", status: [a.status, b.status] });
// Reading someone else's inbox, a forged signature, a push endpoint outside the push services.
const other = await signed(intruder, "GET", path);
say({ step: "other_device_inbox", status: other.status });
const forged = await signed(dev, "GET", path);
forged.headers["X-Notify-Sig"] = b64u(new Uint8Array(64));
say({ step: "forged", status: (await fetch(base + path, { headers: forged.headers })).status });
const evilPush = await signed(dev, "PUT", `/v1/device/${dev.dev}/push?mb=${offer.mb}`, { endpoint: "https://169.254.169.254/latest" });
say({ step: "evil_push", status: evilPush.status });
// After the server revokes this phone it can read nothing more.
await new Promise((r) => setTimeout(r, 4000));
say({ step: "after_revoke", status: (await signed(dev, "GET", path)).status });
