// Decode a QR matrix (JSON rows of 0/1 on stdin) with the phone app's own scanner library.
// Prints the decoded text, or an empty line when the code cannot be read.
import jsQR from "../public/lib/jsqr.js";

const rows = JSON.parse(await Bun.stdin.text());
const scale = 8, quiet = 4, n = rows.length, size = (n + 2 * quiet) * scale;
const data = new Uint8ClampedArray(size * size * 4).fill(255);
for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) {
  if (!rows[y][x]) continue;
  for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) {
    const i = (((y + quiet) * scale + dy) * size + (x + quiet) * scale + dx) * 4;
    data[i] = data[i + 1] = data[i + 2] = 0;
  }
}
const hit = jsQR(data, size, size, { inversionAttempts: "dontInvert" });
console.log(hit ? new TextDecoder().decode(Uint8Array.from(hit.binaryData)) : "");
