"""Draw the JARVIS desktop icons with the standard library alone.

    python3 desktop/scripts/icons.py

Writes desktop/icons/{32x32,128x128,128x128@2x}.png and icon.ico (PNG-in-ICO,
16-256 px). Generated rather than downloaded so the app carries no third-party
artwork and the icons can be rebuilt and reviewed from this one file.
"""

import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "icons"
BG = (11, 18, 32)          # dashboard background
RING = (56, 189, 248)      # dashboard accent
CORE = (226, 232, 240)
SS = 4                     # supersamples per axis


def _coverage(x, y, size):
    """Colour at pixel centre (x, y) for a rounded-square badge with a ring and a core."""
    c = size / 2
    r = size * 0.5
    corner = size * 0.22
    # rounded square
    dx = max(abs(x - c) - (r - corner), 0)
    dy = max(abs(y - c) - (r - corner), 0)
    if math.hypot(dx, dy) > corner:
        return None
    d = math.hypot(x - c, y - c)
    if size * 0.26 <= d <= size * 0.34:
        return RING
    if d <= size * 0.12:
        return CORE
    # three HUD ticks on the ring's outside
    angle = math.degrees(math.atan2(y - c, x - c)) % 120
    if size * 0.37 <= d <= size * 0.42 and (angle < 12 or angle > 108):
        return RING
    return BG


def render(size):
    rows = []
    for py in range(size):
        row = bytearray([0])                       # PNG filter: none
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(SS):
                for sx in range(SS):
                    col = _coverage(px + (sx + 0.5) / SS, py + (sy + 0.5) / SS, size)
                    if col:
                        acc[0] += col[0]
                        acc[1] += col[1]
                        acc[2] += col[2]
                        acc[3] += 255
            n = SS * SS
            a = acc[3] // n
            if a:
                cov = acc[3] / 255
                row += bytes((round(acc[0] / cov), round(acc[1] / cov), round(acc[2] / cov), a))
            else:
                row += b"\0\0\0\0"
        rows.append(bytes(row))
    return png(size, b"".join(rows))


def png(size, raw):
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def ico(images):
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    return header + entries + blobs


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    made = {s: render(s) for s in (16, 32, 48, 128, 256)}
    (OUT / "32x32.png").write_bytes(made[32])
    (OUT / "128x128.png").write_bytes(made[128])
    (OUT / "128x128@2x.png").write_bytes(made[256])
    (OUT / "icon.png").write_bytes(made[256])
    (OUT / "icon.ico").write_bytes(ico([(s, made[s]) for s in (16, 32, 48, 256)]))
    print("wrote", ", ".join(sorted(p.name for p in OUT.iterdir())))


if __name__ == "__main__":
    main()
