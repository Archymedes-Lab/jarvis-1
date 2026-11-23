"""A small QR code encoder, so `argus notify pair` can show a pairing QR with no third-party package.

Byte mode, error correction level M, versions 1-10 (up to 214 bytes): a pairing link is about 100.
The algorithm is the standard one (ISO/IEC 18004); the layout follows the public-domain description by
Project Nayuki. tests/test_notify_qr.py checks the output by decoding it with the phone app's own scanner
library (jsQR) and by structural invariants.
"""

# (error-correction codewords per block, number of blocks) for level M, versions 1..10
_M = {1: (10, 1), 2: (16, 1), 3: (26, 1), 4: (18, 2), 5: (24, 2), 6: (16, 4), 7: (18, 4), 8: (22, 4), 9: (22, 5), 10: (26, 5)}
MAX_VERSION = 10


class TooLong(ValueError):
    pass


def _raw_modules(ver):
    n = (16 * ver + 128) * ver + 64
    if ver >= 2:
        align = ver // 7 + 2
        n -= (25 * align - 10) * align - 55
        if ver >= 7:
            n -= 36
    return n


def _data_capacity(ver):
    ecc, blocks = _M[ver]
    return _raw_modules(ver) // 8 - ecc * blocks


def _gf_mul(x, y):
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 2)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, c in enumerate(divisor):
            result[i] ^= _gf_mul(c, factor)
    return result


def _bit(x, i):
    return (x >> i) & 1


class _Grid:
    def __init__(self, ver):
        self.ver = ver
        self.size = ver * 4 + 17
        self.m = [[False] * self.size for _ in range(self.size)]
        self.fn = [[False] * self.size for _ in range(self.size)]

    def set(self, x, y, dark, function=True):
        self.m[y][x] = bool(dark)
        if function:
            self.fn[y][x] = True

    def function_patterns(self):
        s = self.size
        for i in range(s):
            self.set(6, i, i % 2 == 0)
            self.set(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (s - 4, 3), (3, s - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < s and 0 <= y < s:
                        self.set(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = self.alignment_positions()
        n = len(pos)
        for i in range(n):
            for j in range(n):
                if (i == 0 and j == 0) or (i == 0 and j == n - 1) or (i == n - 1 and j == 0):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.set(pos[i] + dx, pos[j] + dy, max(abs(dx), abs(dy)) != 1)
        self.format_bits(0)                      # reserve the format area
        self.version_bits()

    def alignment_positions(self):
        if self.ver == 1:
            return []
        n = self.ver // 7 + 2
        step = (self.ver * 4 + n * 2 + 1) // (n * 2 - 2) * 2
        return list(reversed([self.size - 7 - i * step for i in range(n - 1)] + [6]))

    def format_bits(self, mask):
        data = (0 << 3) | mask                   # level M = 0b00
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = ((data << 10) | rem) ^ 0x5412
        s = self.size
        for i in range(0, 6):
            self.set(8, i, _bit(bits, i))
        self.set(8, 7, _bit(bits, 6))
        self.set(8, 8, _bit(bits, 7))
        self.set(7, 8, _bit(bits, 8))
        for i in range(9, 15):
            self.set(14 - i, 8, _bit(bits, i))
        for i in range(0, 8):
            self.set(s - 1 - i, 8, _bit(bits, i))
        for i in range(8, 15):
            self.set(8, s - 15 + i, _bit(bits, i))
        self.set(8, s - 8, True)

    def version_bits(self):
        if self.ver < 7:
            return
        rem = self.ver
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = (self.ver << 12) | rem
        for i in range(18):
            a, b = self.size - 11 + i % 3, i // 3
            self.set(a, b, _bit(bits, i))
            self.set(b, a, _bit(bits, i))

    def place(self, codewords):
        s, i = self.size, 0
        total = len(codewords) * 8
        for right in range(s - 1, 0, -2):
            if right <= 6:
                right -= 1
            for vert in range(s):
                for j in range(2):
                    x = right - j
                    y = (s - 1 - vert) if ((right + 1) & 2) == 0 else vert
                    if not self.fn[y][x] and i < total:
                        self.m[y][x] = bool(_bit(codewords[i >> 3], 7 - (i & 7)))
                        i += 1

    def mask(self, k):
        for y in range(self.size):
            for x in range(self.size):
                inv = (
                    (x + y) % 2 == 0, y % 2 == 0, x % 3 == 0, (x + y) % 3 == 0,
                    (x // 3 + y // 2) % 2 == 0, x * y % 2 + x * y % 3 == 0,
                    (x * y % 2 + x * y % 3) % 2 == 0, ((x + y) % 2 + x * y % 3) % 2 == 0,
                )[k]
                if inv and not self.fn[y][x]:
                    self.m[y][x] = not self.m[y][x]

    def penalty(self):
        s, m = self.size, self.m
        score = 0
        for lines in (m, [list(col) for col in zip(*m)]):
            for row in lines:
                run, prev = 0, None
                for v in row + [None]:
                    if v == prev:
                        run += 1
                    else:
                        if run >= 5:
                            score += 3 + run - 5
                        run, prev = 1, v
                text = "".join("1" if v else "0" for v in row)
                score += 40 * (text.count("10111010000") + text.count("00001011101"))
        for y in range(s - 1):
            for x in range(s - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    score += 3
        dark = sum(v for row in m for v in row)
        k = -(-abs(dark * 20 - s * s * 10) // (s * s)) - 1
        return score + max(k, 0) * 10


def _codewords(data, ver):
    ecc_len, blocks = _M[ver]
    cap = _data_capacity(ver)
    bits = [0, 1, 0, 0]
    count_bits = 8 if ver < 10 else 16
    bits += [(len(data) >> i) & 1 for i in range(count_bits - 1, -1, -1)]
    for b in data:
        bits += [(b >> i) & 1 for i in range(7, -1, -1)]
    bits += [0] * min(4, cap * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    out = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(out) < cap:
        out.append(pad)
        pad ^= 0xEC ^ 0x11
    raw = _raw_modules(ver) // 8
    short_len, n_short = raw // blocks, blocks - raw % blocks
    divisor = _rs_divisor(ecc_len)
    parts, k = [], 0
    for i in range(blocks):
        chunk = out[k:k + short_len - ecc_len + (0 if i < n_short else 1)]
        k += len(chunk)
        ecc = _rs_remainder(chunk, divisor)
        if i < n_short:
            chunk = chunk + [0]
        parts.append(chunk + ecc)
    result = []
    for i in range(len(parts[0])):
        for j, blk in enumerate(parts):
            if i != short_len - ecc_len or j >= n_short:
                result.append(blk[i])
    return result


def encode(text):
    """The QR code for `text` (UTF-8, byte mode, level M) as a square list of rows of booleans."""
    data = text.encode("utf-8")
    ver = next((v for v in range(1, MAX_VERSION + 1)
                if len(data) <= (_data_capacity(v) * 8 - 4 - (8 if v < 10 else 16)) // 8), None)
    if ver is None:
        raise TooLong(f"{len(data)} bytes does not fit in a version {MAX_VERSION} QR code")
    grid = _Grid(ver)
    grid.function_patterns()
    grid.place(_codewords(data, ver))
    best = None
    for k in range(8):
        grid.mask(k)
        grid.format_bits(k)
        score = grid.penalty()
        if best is None or score < best[0]:
            best = (score, k)
        grid.mask(k)                              # XOR again: undo
    grid.mask(best[1])
    grid.format_bits(best[1])
    return [row[:] for row in grid.m]


def render_ansi(matrix, border=2):
    """Terminal text: black modules on a white quiet zone, two rows per line (half blocks)."""
    n = len(matrix)
    full = [[False] * (n + 2 * border) for _ in range(border)]
    rows = full + [[False] * border + r + [False] * border for r in matrix] + full
    if len(rows) % 2:
        rows.append([False] * len(rows[0]))
    lines = []
    for y in range(0, len(rows), 2):
        cells = []
        for x in range(len(rows[0])):
            fg = 30 if rows[y][x] else 97
            bg = 40 if rows[y + 1][x] else 107
            cells.append(f"\x1b[{fg};{bg}m▀")
        lines.append("".join(cells) + "\x1b[0m")
    return "\n".join(lines)
