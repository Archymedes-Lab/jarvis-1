import { describe, expect, it } from "bun:test";
import vec from "./vectors.json";
import * as p from "../public/lib/protocol.js";

// WebCrypto cannot import raw private keys; wrap the test seeds in PKCS#8.
const PKCS8 = { X25519: "302e020100300506032b656e04220420", Ed25519: "302e020100300506032b657004220420" };
const fromHex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
async function priv(alg, seedB64, usages) {
  const der = new Uint8Array([...fromHex(PKCS8[alg]), ...p.unb64u(seedB64)]);
  return crypto.subtle.importKey("pkcs8", der, { name: alg }, false, usages);
}

describe("protocol matches the server's Python implementation", () => {
  it("opens and verifies the Python-sealed envelope", async () => {
    const encPriv = await priv("X25519", vec.device.d_enc_priv, ["deriveBits"]);
    const payload = await p.openEnvelope(vec.envelope, encPriv, p.unb64u(vec.server.s_sig));
    expect(payload).toEqual(vec.payload);
  });

  it("rejects a tampered ciphertext, header or signature", async () => {
    const encPriv = await priv("X25519", vec.device.d_enc_priv, ["deriveBits"]);
    const sSig = p.unb64u(vec.server.s_sig);
    for (const field of ["ct", "sig", "dev", "expires"]) {
      const bad = { ...vec.envelope };
      bad[field] = field === "expires" ? bad.expires + 1 : bad[field].slice(0, -2) + (bad[field].endsWith("A") ? "BB" : "AA");
      await expect(p.openEnvelope(bad, encPriv, sSig)).rejects.toThrow();
    }
    const other = await p.generateDevice();
    await expect(p.openEnvelope(vec.envelope, encPriv, other.sigPub)).rejects.toThrow();
  });

  it("derives the same ids, SAS and request signature", async () => {
    expect(await p.keyId(p.unb64u(vec.server.s_sig))).toBe(vec.server.mailbox);
    expect(await p.keyId(p.unb64u(vec.device.d_sig))).toBe(vec.device.dev);
    const s = await p.sas(p.unb64u(vec.server.s_sig), p.unb64u(vec.server.s_enc),
                          p.unb64u(vec.device.d_sig), p.unb64u(vec.device.d_enc));
    expect(s).toBe(vec.sas);
    const r = vec.request, h = r.headers;
    const body = new TextEncoder().encode(r.body);
    const ok = await p.verifyRequest((k) => h[k], r.method, r.path, body, Number(h["X-Notify-Time"]));
    expect(ok.ok).toBe(true);
    expect(ok.id).toBe(vec.server.mailbox);
    const late = await p.verifyRequest((k) => h[k], r.method, r.path, body, Number(h["X-Notify-Time"]) + 301);
    expect(late.reason).toBe("stale");
    const other = await p.verifyRequest((k) => h[k], r.method, r.path + "x", body, Number(h["X-Notify-Time"]));
    expect(other.ok).toBe(false);
  });

  it("canonical JSON equals Python's sorted, compact, non-ASCII form", () => {
    expect(p.canonical({ b: 1, a: [true, null, "é ✓"], c: { z: 0, y: "x" } }))
      .toBe('{"a":[true,null,"é ✓"],"b":1,"c":{"y":"x","z":0}}');
  });

  it("a device signs requests the relay accepts", async () => {
    const d = await p.generateDevice();
    const body = new TextEncoder().encode("{}");
    const h = await p.signRequest(d.sigPriv, d.sigPub, "GET", "/v1/device/x/inbox", body, 1000);
    const ok = await p.verifyRequest((k) => h[k], "GET", "/v1/device/x/inbox", body, 1000);
    expect([ok.ok, ok.id]).toEqual([true, d.dev]);
  });

  it("normalises typed codes the way the server does", () => {
    expect(p.normalizeCode("ab0io-l23x9")).toBe("AB010123X9");   // Python: crypto.normalize_code
    expect(p.validCode(p.normalizeCode("7K2QM-9XWFH"))).toBe(true);
    expect(p.validCode("7K2QM9XWFU")).toBe(false);
  });
});

describe("approvals match the server's Python implementation", () => {
  it("computes the same action-bound challenge", async () => {
    const a = vec.approval;
    const ch = await p.approvalChallenge(a.approval_id, a.eid, a.action, a.target, a.expires);
    expect(p.b64u(ch)).toBe(a.challenge);
  });

  it("changing any shown field changes the challenge", async () => {
    const a = vec.approval;
    const base = p.b64u(await p.approvalChallenge(a.approval_id, a.eid, a.action, a.target, a.expires));
    for (const alt of [[a.approval_id.replace("A", "B"), a.eid, a.action, a.target, a.expires],
                       [a.approval_id, "e2", a.action, a.target, a.expires],
                       [a.approval_id, a.eid, "wipe", a.target, a.expires],
                       [a.approval_id, a.eid, a.action, "other", a.expires],
                       [a.approval_id, a.eid, a.action, a.target, a.expires + 1]])
      expect(p.b64u(await p.approvalChallenge(...alt))).not.toBe(base);
  });

  it("computes the same QR proof, and a different secret gives a different proof", async () => {
    const q = vec.qr_proof;
    const proof = await p.qrProof(p.unb64u(q.secret), p.unb64u(q.d_sig), p.unb64u(q.d_enc), p.unb64u(q.passkey));
    expect(proof).toBe(q.proof);
    expect(await p.qrProof(new Uint8Array(16), p.unb64u(q.d_sig), p.unb64u(q.d_enc), p.unb64u(q.passkey))).not.toBe(q.proof);
  });
});
