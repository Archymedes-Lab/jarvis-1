"""Bounded decompression: no archive can make JARVIS allocate or work without limit.

A decompression bomb is a few kilobytes that inflate to gigabytes. Fed to the
daemon - a hostile or hijacked threat feed, or a planted event-log segment - it
exhausts memory (the server edition runs under MemoryMax 1G) or keeps a worker
inflating for hours, and either way the monitor stops watching. That is evasion.

Every limit here counts bytes actually produced, never a size an archive
declares about itself. Exceeding a limit raises InflateLimit, a ValueError, so
callers that already treat unreadable input as "not observed" keep doing so:
an oversized input is reported, never silently truncated into a clean result.
"""

import io
import zipfile
import zlib

GZIP_MAGIC = b"\x1f\x8b"


class InflateLimit(ValueError):
    """Decompressed data exceeded its bound."""


def gunzip(data, limit):
    """Decompress gzip `data` (one or more members) to at most `limit` bytes."""
    out, size = [], 0
    while True:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        buf = data
        while not d.eof:
            # +1 so that reaching exactly `limit` is allowed and one more byte is not.
            chunk = d.decompress(buf, limit - size + 1)
            if chunk:
                size += len(chunk)
                if size > limit:
                    raise InflateLimit(f"gzip data inflates beyond {limit} bytes")
                out.append(chunk)
            buf = d.unconsumed_tail
            if not chunk and not buf:
                break
        if not d.eof:
            raise EOFError("gzip data ends before the end-of-stream marker")
        data = d.unused_data
        # Concatenated members are valid gzip; anything else after is ignored,
        # as gzip.decompress does with trailing zero padding.
        if not data.startswith(GZIP_MAGIC):
            return b"".join(out)


def zip_first_member(data, limit, max_entries=64):
    """The first file of a zip archive, at most `limit` bytes once inflated.

    The declared size is checked first as a cheap early refusal, then the
    bytes are counted as they are produced, so a header that lies about its
    size still cannot get past the bound."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        entries = zf.infolist()
        if len(entries) > max_entries:
            raise InflateLimit(f"zip archive has {len(entries)} entries, over {max_entries}")
        files = [i for i in entries if not i.is_dir()]
        if not files:
            raise ValueError("empty zip archive")
        info = files[0]
        if info.file_size > limit:
            raise InflateLimit(f"zip member declares {info.file_size} bytes, over {limit}")
        with zf.open(info) as fh:
            payload = fh.read(limit + 1)
        if len(payload) > limit:
            raise InflateLimit(f"zip member inflates beyond {limit} bytes")
        return payload


def readline(fh, limit):
    """One line from a (decompressing) binary stream, at most `limit` bytes."""
    line = fh.readline(limit + 1)
    if len(line) > limit:
        raise InflateLimit(f"line longer than {limit} bytes")
    return line


def lines(fh, limit):
    """Iterate a stream's lines, refusing any line longer than `limit` bytes."""
    while True:
        line = readline(fh, limit)
        if not line:
            return
        yield line


def chunks(fh, limit, size=1024 * 1024):
    """Iterate a stream in blocks, refusing to produce more than `limit` bytes in total."""
    total = 0
    while True:
        block = fh.read(size)
        if not block:
            return
        total += len(block)
        if total > limit:
            raise InflateLimit(f"stream inflates beyond {limit} bytes")
        yield block


class Bounded:
    """A read-only stream that refuses to produce more than `limit` bytes.

    Wraps a decompressing stream (bz2.open, gzip.open) so a consumer that
    parses as it reads (xml iterparse) holds one block at a time, and a bomb
    stops at the bound instead of after the whole archive inflated."""

    def __init__(self, stream, limit):
        self.stream, self.limit, self.total = stream, limit, 0

    def read(self, size=-1):
        if size is None or size < 0:
            size = 1024 * 1024
        block = self.stream.read(min(size, self.limit - self.total + 1))
        self.total += len(block)
        if self.total > self.limit:
            raise InflateLimit(f"stream inflates beyond {self.limit} bytes")
        return block
