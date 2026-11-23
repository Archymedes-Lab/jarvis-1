// Reading the pairing QR inside the installed app (the camera app would open Safari, whose storage is
// separate from the Home-Screen app's on iPhone, so pairing has to happen in here).
import jsQR from "./jsqr.js";
import { normalizeCode, unb64u, validCode } from "./protocol.js";

const ID = /^[A-Za-z0-9_-]{22}$/;

// What a pairing QR / link says: { code, secret (16 bytes), mb }. Throws a sentence a person can act on.
// Only this app's own origin is accepted: a QR for another relay is not this app's to trust.
export function parsePairing(text) {
  let url;
  try { url = new URL(String(text).trim()); } catch { throw new Error("That is not an Argus pairing code."); }
  if (url.origin !== location.origin) throw new Error("That QR code is for a different Argus address.");
  const params = new URLSearchParams(url.hash.replace(/^#\/?pair\??/, ""));
  const code = normalizeCode(params.get("c") || "");
  const mb = params.get("mb") || "";
  let secret;
  try { secret = unb64u(params.get("k") || ""); } catch { secret = new Uint8Array(); }
  if (!validCode(code) || !ID.test(mb) || secret.length !== 16) throw new Error("That is not an Argus pairing code.");
  return { code, secret, mb };
}

// Open the camera in `video` and call onText(text) once per distinct QR seen. Returns stop().
export async function startScanner(video, onText) {
  const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
  video.srcObject = stream;
  video.setAttribute("playsinline", "");
  await video.play();
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  let stopped = false, last = "";
  const tick = () => {
    if (stopped) return;
    const w = video.videoWidth, h = video.videoHeight;
    if (w && h) {
      const scale = Math.min(1, 640 / Math.max(w, h));
      canvas.width = Math.round(w * scale);
      canvas.height = Math.round(h * scale);
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const hit = jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
      if (hit && hit.binaryData && hit.binaryData.length) {
        const text = new TextDecoder().decode(Uint8Array.from(hit.binaryData));
        if (text !== last) { last = text; onText(text); }
      }
    }
    setTimeout(tick, 150);
  };
  tick();
  return () => {
    stopped = true;
    for (const t of stream.getTracks()) t.stop();
    video.srcObject = null;
  };
}
