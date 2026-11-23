// The phone's passkey: Face ID / fingerprint, through WebAuthn. It is what makes "Approve" more than
// a tap: the server only accepts an approval that carries an assertion from this passkey, made with the
// user verified, over a challenge bound to the exact action (protocol.js approvalChallenge).
//
// Both calls need a user gesture in Safari, so they are only ever called from a button handler.
import { b64u, unb64u } from "./protocol.js";

const RP_NAME = "Argus";

export function passkeysAvailable() {
  return typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;
}

// True when this device has a built-in authenticator (Face ID, Touch ID, fingerprint, Windows Hello).
export async function platformAuthenticator() {
  try {
    return passkeysAvailable() && (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
  } catch { return false; }
}

// Make the passkey. Returns { id, spki }: the credential id and its ES256 public key (DER, base64url).
export async function createPasskey(name) {
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { id: location.hostname, name: RP_NAME },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: name || "phone", displayName: name || "phone" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" },
    attestation: "none",
    timeout: 60000,
  } });
  const spki = cred.response.getPublicKey && cred.response.getPublicKey();
  if (!spki) throw new Error("This browser cannot export the passkey's public key. Update it and try again.");
  return { id: b64u(new Uint8Array(cred.rawId)), spki: b64u(new Uint8Array(spki)) };
}

// Ask for the biometric check over `challenge` (32 bytes). Returns the assertion the server verifies.
export async function assertPasskey(credId, challenge) {
  const a = await navigator.credentials.get({ publicKey: {
    challenge,
    rpId: location.hostname,
    allowCredentials: [{ type: "public-key", id: unb64u(credId) }],
    userVerification: "required",
    timeout: 60000,
  } });
  const r = a.response;
  return {
    id: b64u(new Uint8Array(a.rawId)),
    authenticatorData: b64u(new Uint8Array(r.authenticatorData)),
    clientDataJSON: b64u(new Uint8Array(r.clientDataJSON)),
    signature: b64u(new Uint8Array(r.signature)),
  };
}

