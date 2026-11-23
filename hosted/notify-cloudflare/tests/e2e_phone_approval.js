// A scripted phone for the approval end-to-end test: the app's own protocol.js (sealing, signing, challenge,
// QR proof) plus a software passkey that builds WebAuthn assertions exactly as a platform authenticator does.
// Usage: bun tests/e2e_phone_approval.js BASE CODE SECRET_B64U   then JSON commands, one per line, on stdin.
import { approvalChallenge, b64u, generateDevice, openEnvelope, qrProof, sealReply, sha256, signRequest, unb64u }
  from "../public/lib/protocol.js";

const [base, code, secretB64] = process.argv.slice(2);
const enc = new TextEncoder();
const say = (o) => console.log(JSON.stringify(o));
const origin = new URL(base).origin, rpId = new URL(base).hostname;

async function signed(dev, method, path, body) {
  const bytes = body === undefined ? new Uint8Array() : enc.encode(JSON.stringify(body));
  const headers = await signRequest(dev.sigPriv, dev.sigPub, method, path, bytes, Date.now() / 1000);
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : bytes });
  return { status: res.status, json: await res.json().catch(() => null) };
}

// WebCrypto signs ECDSA as raw r||s; WebAuthn authenticators return DER.
function der(raw) {
  const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); if (b[0] & 0x80) b = new Uint8Array([0, ...b]); return [0x02, b.length, ...b]; };
  const r = int(raw.slice(0, 32)), s = int(raw.slice(32));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}

const passkey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const spki = new Uint8Array(await crypto.subtle.exportKey("spki", passkey.publicKey));
let uses = 0;
async function assertion(challenge, { flags = 0x05 } = {}) {
  const auth = new Uint8Array([...(await sha256(enc.encode(rpId))), flags, 0, 0, 0, ++uses]);
  const client = enc.encode(JSON.stringify({ type: "webauthn.get", challenge: b64u(challenge), origin, crossOrigin: false }));
  const msg = new Uint8Array([...auth, ...(await sha256(client))]);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, passkey.privateKey, msg));
  return { id: "software-passkey", authenticatorData: b64u(auth), clientDataJSON: b64u(client), signature: b64u(der(sig)) };
}

let offer = null;                      // fetched when told to pair: the server publishes it first
const dev = await generateDevice();
let counter = 0;
const server = () => ({ keys: dev });

async function inbox() {
  const r = await signed(dev, "GET", `/v1/device/${dev.dev}/inbox?mb=${offer.mb}`);
  const items = [];
  if (!Array.isArray(r.json)) return { status: r.status, items, error: r.json && r.json.error };
  for (const env of r.json) items.push(await openEnvelope(env, dev.encPriv, unb64u(offer.s_sig)));
  if (r.json.length) await signed(dev, "POST", `/v1/device/${dev.dev}/ack?mb=${offer.mb}`, { ids: r.json.map((e) => e.id) });
  return { status: r.status, items };
}

for await (const line of console) {
  if (!line.trim()) continue;
  const cmd = JSON.parse(line);
  if (cmd.cmd === "pair") {
    offer = await (await fetch(`${base}/v1/pair/${code}`)).json();
    const proof = await qrProof(unb64u(secretB64), dev.sigPub, dev.encPub, cmd.nopasskey ? new Uint8Array() : spki);
    const body = { dev: dev.dev, d_sig: b64u(dev.sigPub), d_enc: b64u(dev.encPub), name: "e2e iPhone", push: null, proof };
    if (!cmd.nopasskey) body.passkey = b64u(spki);
    say({ step: "claimed", status: (await signed(dev, "POST", `/v1/pair/${code}/claim`, body)).status });
    for (let i = 0; i < 80; i++) {
      const st = await (await fetch(`${base}/v1/pair/${code}/status?dev=${dev.dev}`)).json();
      if (st.active) { say({ step: "active", dev: dev.dev }); break; }
      await new Promise((r) => setTimeout(r, 300));
    }
  } else if (cmd.cmd === "inbox") {
    say({ step: "inbox", ...(await inbox()) });
  } else if (cmd.cmd === "answer") {
    const a = cmd.request;
    const ch = await approvalChallenge(a.approval_id, a.eid, a.action, a.target, a.expires);
    const challengeOk = b64u(ch) === a.challenge;       // the phone recomputes it from what it shows
    const payload = { type: "approval", approval_id: a.approval_id, decision: cmd.decision, counter: ++counter, at: Math.floor(Date.now() / 1000) };
    if (cmd.decision === "approve") payload.assertion = await assertion(cmd.wrongChallenge ? crypto.getRandomValues(new Uint8Array(32)) : ch, { flags: cmd.flags });
    const reply = await sealReply(dev.sigPriv, dev.dev, offer.mb, unb64u(offer.s_enc), payload, Date.now() / 1000);
    const r = await signed(dev, "POST", `/v1/device/${dev.dev}/replies?mb=${offer.mb}`, reply);
    say({ step: "answered", status: r.status, challengeOk, relay_saw: Object.keys(reply).sort() });
  } else if (cmd.cmd === "quit") {
    break;
  }
}
