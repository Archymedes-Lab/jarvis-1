import gzip
import io
import struct
import tempfile
import tracemalloc
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from jarvis.core import event, eventlog, inflate
from jarvis.core.eventlog import EventLog
from jarvis.intel import feeds

MB = 1024 * 1024


def bomb(size):
    """`size` zero bytes, gzip-compressed: about a thousandth of that on disk."""
    return gzip.compress(b"\0" * size, compresslevel=9)


def zip_of(name, payload, lie_size=None):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, payload)
    data = bytearray(raw.getvalue())
    if lie_size is not None:
        # Understate the uncompressed size in both the local and central headers.
        local = data.find(b"PK\x03\x04")
        struct.pack_into("<I", data, local + 22, lie_size)
        central = data.find(b"PK\x01\x02")
        struct.pack_into("<I", data, central + 24, lie_size)
    return bytes(data)


class GunzipTests(unittest.TestCase):
    def test_round_trip_and_concatenated_members(self):
        self.assertEqual(inflate.gunzip(gzip.compress(b"abc"), 3), b"abc")
        two = gzip.compress(b"ab") + gzip.compress(b"cd")
        self.assertEqual(inflate.gunzip(two, 10), gzip.decompress(two))

    def test_exact_limit_is_allowed_one_more_byte_is_not(self):
        data = gzip.compress(b"x" * 100)
        self.assertEqual(len(inflate.gunzip(data, 100)), 100)
        with self.assertRaises(inflate.InflateLimit):
            inflate.gunzip(data, 99)

    def test_bomb_is_refused_without_inflating_it(self):
        data = bomb(64 * MB)
        self.assertLess(len(data), 128 * 1024)
        tracemalloc.start()
        try:
            with self.assertRaises(inflate.InflateLimit):
                inflate.gunzip(data, 1 * MB)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 8 * MB, "the refusal must not hold the inflated data")

    def test_bomb_hidden_in_a_second_member_is_refused(self):
        with self.assertRaises(inflate.InflateLimit):
            inflate.gunzip(gzip.compress(b"ok") + bomb(8 * MB), 1 * MB)

    def test_truncated_stream_is_an_error_not_a_short_result(self):
        with self.assertRaises(EOFError):
            inflate.gunzip(gzip.compress(b"x" * 1000)[:-12], 10_000)

    def test_limit_error_is_a_value_error_for_existing_handlers(self):
        self.assertTrue(issubclass(inflate.InflateLimit, ValueError))


class ZipTests(unittest.TestCase):
    def test_first_member(self):
        self.assertEqual(inflate.zip_first_member(zip_of("a.csv", b"1,2\n"), 100), b"1,2\n")

    def test_declared_size_over_limit_is_refused_early(self):
        with self.assertRaises(inflate.InflateLimit):
            inflate.zip_first_member(zip_of("a.csv", b"\0" * (2 * MB)), 1 * MB)

    def test_header_that_understates_its_size_cannot_pass_the_bound(self):
        data = zip_of("a.csv", b"\0" * (8 * MB), lie_size=100)
        with self.assertRaises((inflate.InflateLimit, zipfile.BadZipFile)):
            out = inflate.zip_first_member(data, 1 * MB)
            # If zipfile trusted the lie and stopped early, the result is still bounded.
            self.assertLessEqual(len(out), 1 * MB)
            raise zipfile.BadZipFile("short read accepted")

    def test_too_many_entries_and_empty_archives(self):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as zf:
            for i in range(70):
                zf.writestr(f"f{i}", b"x")
        with self.assertRaises(inflate.InflateLimit):
            inflate.zip_first_member(raw.getvalue(), 100)
        empty = io.BytesIO()
        with zipfile.ZipFile(empty, "w"):
            pass
        with self.assertRaises(ValueError):
            inflate.zip_first_member(empty.getvalue(), 100)


class StreamTests(unittest.TestCase):
    def test_line_and_chunk_bounds(self):
        fh = io.BytesIO(b"short\n" + b"y" * 50 + b"\n")
        self.assertEqual(inflate.readline(fh, 10), b"short\n")
        with self.assertRaises(inflate.InflateLimit):
            inflate.readline(fh, 10)
        self.assertEqual(list(inflate.lines(io.BytesIO(b"a\nb\n"), 5)), [b"a\n", b"b\n"])
        self.assertEqual(b"".join(inflate.chunks(io.BytesIO(b"z" * 10), 10, size=3)), b"z" * 10)
        with self.assertRaises(inflate.InflateLimit):
            list(inflate.chunks(io.BytesIO(b"z" * 11), 10, size=3))

    def test_newline_free_gzip_line_is_refused(self):
        with gzip.open(io.BytesIO(bomb(16 * MB)), "rb") as fh:
            with self.assertRaises(inflate.InflateLimit):
                inflate.readline(fh, 64 * 1024)


class _Resp(io.BytesIO):
    def __init__(self, body, encoding=None):
        super().__init__(body)
        self.headers = {"Content-Encoding": encoding} if encoding else {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FeedFetchTests(unittest.TestCase):
    def fetch(self, body, encoding=None, **kw):
        with mock.patch.object(feeds.urllib.request, "urlopen", return_value=_Resp(body, encoding)):
            return feeds.fetch("https://feed.example/x", max_bytes=8 * MB, **kw)

    def test_plain_gzip_and_zip_feeds_still_parse(self):
        csv = b"# comment\n1.2.3.4,c2\n"
        self.assertEqual(self.fetch(csv), csv)
        self.assertEqual(self.fetch(gzip.compress(csv), "gzip"), csv)
        self.assertEqual(self.fetch(zip_of("f.csv", csv)), csv)
        self.assertEqual(self.fetch(gzip.compress(zip_of("f.csv", csv))), csv)

    def test_gzip_bomb_feed_is_refused(self):
        with self.assertRaises(inflate.InflateLimit):
            self.fetch(bomb(32 * MB), "gzip", max_inflated=1 * MB)

    def test_zip_bomb_feed_is_refused(self):
        with self.assertRaises((inflate.InflateLimit, zipfile.BadZipFile)):
            self.fetch(zip_of("f.csv", b"\0" * (8 * MB), lie_size=10), max_inflated=1 * MB)

    def test_default_cap_fits_the_server_memory_budget(self):
        # MemoryHigh is 768 MB on the server edition; parsing roughly doubles the bytes.
        self.assertLessEqual(feeds.MAX_INFLATED * 2, 512 * MB)


def ev(record):
    return event.make(
        host="WINBOX", sensor="sensor", device="device", boot="b", channel="c",
        generation="g", record=record, source="sysmon", source_event=1,
        time="2026-09-23T10:00:00Z", received="2026-09-23T10:00:01Z",
        category="process", action="start",
        process={"pid": record, "guid": f"{{g{record}}}", "image": r"C:\x.exe"})


class EventLogBombTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.log = EventLog(Path(tmp.name) / "eventlog", writer=True)
        self.addCleanup(self.log.close)
        self.log.append([ev(n) for n in range(1, 4)], {"sensor": "sensor", "channel": "c"})
        self.log.seal(force=True)
        self.segment = self.log._segment_path(self.log.chain[0]["segment"])

    def plant(self, tail):
        with gzip.open(self.segment, "rb") as fh:
            header = fh.readline()
        with gzip.open(self.segment, "wb") as fh:
            fh.write(header)
            fh.write(tail)

    def test_sealed_segments_still_read_and_verify(self):
        self.assertEqual([e["seq"] for e in self.log.iter_events()], [1, 2, 3])

    def test_planted_newline_free_line_is_refused_by_the_reader(self):
        self.plant(b"{" + b" " * (2 * MB))
        with mock.patch.object(eventlog, "MAX_EVENT_LINE", 64 * 1024):
            with self.assertRaises(inflate.InflateLimit):
                list(self.log.iter_events())

    def test_planted_oversized_segment_is_reported_unreadable_by_verify(self):
        self.plant(b"\n" * (4 * MB))
        with mock.patch.object(eventlog, "MAX_SEGMENT_PLAIN", 1 * MB):
            problems = self.log.verify()["problems"]
        self.assertTrue(any("unreadable" in p and "beyond" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
