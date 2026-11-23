"""A small, standard-library, coverage-guided mutation fuzzer.

Why not hypothesis or atheris: neither is installed on the release or CI
machines, and the gate code (release/) is standard library only by design. This
engine needs nothing but CPython 3.12+ (it uses sys.monitoring for line
coverage when available and falls back to blind mutation otherwise).

A target is a plain function taking one input (bytes or str). It reports:
  * nothing                -> the input was handled;
  * an exception listed in Target.expected -> a documented refusal, not a finding;
  * AssertionError         -> an oracle (property) failed: a blind spot or misreport;
  * any other exception    -> a crash;
  * running past the per-input deadline -> a hang (SIGALRM interrupts it).

Findings are deduplicated by (kind, exception type, innermost project frame) so
a run reports each distinct flaw once, with the smallest reproducer seen.
"""

import os
import random
import signal
import sys
import time
import traceback
from dataclasses import dataclass, field

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROJECT_DIRS = (os.path.join(ROOT, "jarvis") + os.sep, os.path.join(ROOT, "release") + os.sep)


class Hang(Exception):
    """Raised by the alarm when one input runs past its deadline."""


@dataclass
class Target:
    name: str
    run: object                      # callable(input) -> None
    seeds: list
    kind: str = "text"               # "text" or "bytes"
    expected: tuple = ()             # exception types that are documented refusals
    tokens: tuple = ()               # dictionary of interesting fragments
    max_len: int = 4096
    timeout_s: float = 2.0           # one input longer than this is a hang
    slow_s: float = 0.5              # one input longer than this is recorded as slow
    note: str = ""


@dataclass
class Finding:
    kind: str                        # crash | hang | oracle | slow
    target: str
    signature: str
    detail: str
    reproducer: object
    seconds: float = 0.0
    count: int = 1


@dataclass
class Result:
    target: str
    executions: int = 0
    seconds: float = 0.0
    corpus: int = 0
    coverage: int = 0
    findings: dict = field(default_factory=dict)


# --- mutation ---------------------------------------------------------------

TEXT_SPECIAL = ["\x00", "\n", "\r\n", "\r", "\t", " ", "  ", "\u2028", "\u0085", "\ufeff", "\u2026",
                "\u0663", "\uff11", "\"", "'", "\\", "=", ",", ";", ":", "|", "#", "/", "..", "%",
                "-1", "0", "4294967295", "99999999999999999999", "\u202e", "[", "{",
                "]", "}", "<", ">", "&", "&amp;", "]]>", "${x}", "*", "?"]
BYTES_SPECIAL = [b"\x00", b"\xff", b"\x7f", b"\x80", b"\xff\xff\xff\xff", b"\x00\x00\x00\x00",
                 b"\xfe\xff\xff\xff", b"\x00\x00\x00\x80", b"PK\x01\x02", b"PK\x03\x04", b"PK\x05\x06",
                 b"PK\x06\x06", b"-1", b"-60       ", b"\n", b"/", b"..", b"\xc0\xaf"]


def _as(kind, piece):
    if kind == "bytes":
        return piece if isinstance(piece, bytes) else piece.encode("utf-8", "surrogatepass")
    return piece if isinstance(piece, str) else piece.decode("latin-1")


def mutate(rng, data, target, corpus):
    kind = target.kind
    specials = BYTES_SPECIAL if kind == "bytes" else TEXT_SPECIAL
    pool = list(target.tokens) + specials
    for _ in range(rng.randint(1, 4)):
        n = len(data)
        op = rng.randrange(10)
        i = rng.randint(0, n)
        if op == 0 and n:                                    # delete a span
            j = min(n, i + rng.randint(1, 16))
            data = data[:i] + data[j:]
        elif op == 1:                                        # insert a token
            data = data[:i] + _as(kind, rng.choice(pool)) + data[i:]
        elif op == 2 and n:                                  # replace a span with a token
            j = min(n, i + rng.randint(1, 8))
            data = data[:i] + _as(kind, rng.choice(pool)) + data[j:]
        elif op == 3 and n:                                  # duplicate a span (repetition)
            j = min(n, i + rng.randint(1, 64))
            data = data[:i] + data[i:j] * rng.randint(2, 64) + data[j:]
        elif op == 4 and n:                                  # flip one unit
            k = rng.randrange(n)
            if kind == "bytes":
                data = data[:k] + bytes([data[k] ^ (1 << rng.randrange(8))]) + data[k + 1:]
            else:
                data = data[:k] + chr(rng.randrange(0x20, 0x250)) + data[k + 1:]
        elif op == 5 and corpus:                             # splice with another input
            other = rng.choice(corpus)
            j = rng.randint(0, len(other))
            data = data[:i] + other[j:]
        elif op == 6 and n >= 4 and kind == "bytes":          # overwrite an integer field
            k = rng.randrange(n - 3)
            val = rng.choice([0, 1, 0xFFFF, 0xFFFFFFFF, 0x7FFFFFFF, n, rng.randrange(1 << 32)])
            data = data[:k] + val.to_bytes(4, rng.choice(["little", "big"])) + data[k + 4:]
        elif op == 7 and n:                                  # truncate
            data = data[:i]
        elif op == 8:                                        # swap two lines
            sep = b"\n" if kind == "bytes" else "\n"
            lines = data.split(sep)
            if len(lines) > 2:
                a, b = rng.randrange(len(lines)), rng.randrange(len(lines))
                lines[a], lines[b] = lines[b], lines[a]
                data = sep.join(lines)
        else:                                                # insert a long run
            data = data[:i] + _as(kind, rng.choice(pool)) * rng.choice([16, 64, 512, 2048, 8192]) + data[i:]
    return data[:target.max_len]


# --- coverage ---------------------------------------------------------------

class Coverage:
    """New (code, line) locations in project files, via sys.monitoring.

    Each location fires once (the callback returns DISABLE), so the steady-state
    cost is close to zero; `fresh` counts locations first reached by the last input."""

    TOOL = 4  # sys.monitoring.PROFILER_ID is 2, OPTIMIZER_ID 5; 4 is free for tools

    def __init__(self):
        self.mon = getattr(sys, "monitoring", None)
        self.seen = 0
        self.fresh = 0
        self.active = False

    def __enter__(self):
        if self.mon is None:
            return self
        try:
            self.mon.use_tool_id(self.TOOL, "argus-fuzz")
        except ValueError:
            return self
        disable = self.mon.DISABLE

        def on_line(code, _line):
            if code.co_filename.startswith(PROJECT_DIRS):
                self.fresh += 1
            return disable

        self.mon.register_callback(self.TOOL, self.mon.events.LINE, on_line)
        self.mon.set_events(self.TOOL, self.mon.events.LINE)
        self.active = True
        return self

    def take(self):
        n, self.fresh = self.fresh, 0
        self.seen += n
        return n

    def __exit__(self, *exc):
        if self.active:
            self.mon.set_events(self.TOOL, 0)
            self.mon.register_callback(self.TOOL, self.mon.events.LINE, None)
            self.mon.free_tool_id(self.TOOL)
        return False


# --- running ----------------------------------------------------------------

def _alarm(_sig, _frame):
    raise Hang()


def _innermost_project_frame(tb):
    where = "?"
    for fs in traceback.extract_tb(tb):
        if fs.filename.startswith(PROJECT_DIRS) or "/tests/fuzz/" in fs.filename:
            where = f"{os.path.relpath(fs.filename, ROOT)}:{fs.lineno}"
    return where


def execute(target, data, _retry=False):
    """(kind or None, signature, detail, seconds) for one input."""
    old = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, target.timeout_s)
    t0 = time.perf_counter()
    try:
        target.run(data)
        kind, sig, detail = None, "", ""
    except Hang:
        kind, sig, detail = "hang", "timeout", f"did not return within {target.timeout_s:.1f} s"
    except target.expected:
        kind, sig, detail = None, "", ""
    except AssertionError as exc:
        kind = "oracle"
        sig = str(exc).split(":", 1)[0][:80]
        detail = str(exc)[:500]
    except RecursionError as exc:
        kind, sig, detail = "crash", "RecursionError", str(exc)[:300]
    except Exception as exc:  # noqa: BLE001 - every unexpected exception is a finding
        kind = "crash"
        sig = f"{type(exc).__name__}@{_innermost_project_frame(exc.__traceback__)}"
        detail = f"{type(exc).__name__}: {str(exc)[:300]}"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
    seconds = time.perf_counter() - t0
    if kind is None and seconds > target.slow_s and not _retry:
        # A loaded machine stalls now and then: slow only when it is slow twice.
        again = execute(target, data, _retry=True)[3]
        if again > target.slow_s:
            kind, sig, detail = "slow", "slow", f"{min(seconds, again):.2f} s for {len(data)} units"
    return kind, sig, detail, seconds


def fuzz(target, budget_s, seed=0, max_execs=None, log=None):
    rng = random.Random(f"{target.name}:{seed}")
    corpus = [_as(target.kind, s) for s in target.seeds] or [_as(target.kind, "")]
    res = Result(target.name)
    start = time.monotonic()
    with Coverage() as cov:
        # Seeds first: a seed that already fails is a finding too.
        queue = list(corpus)
        while time.monotonic() - start < budget_s and (max_execs is None or res.executions < max_execs):
            if queue:
                data = queue.pop(0)
            else:
                data = mutate(rng, rng.choice(corpus), target, corpus)
            cov.take()
            kind, sig, detail, secs = execute(target, data)
            res.executions += 1
            if cov.take() and data not in corpus and kind is None:
                corpus.append(data)
            if kind:
                key = f"{kind}:{sig}"
                prev = res.findings.get(key)
                if prev is None:
                    res.findings[key] = Finding(kind, target.name, sig, detail, data, secs)
                    if log:
                        log(f"  [{target.name}] {kind} {sig}: {detail[:160]}")
                else:
                    prev.count += 1
                    if len(data) < len(prev.reproducer):
                        prev.reproducer, prev.detail, prev.seconds = data, detail, secs
        res.coverage = cov.seen
    res.seconds = time.monotonic() - start
    res.corpus = len(corpus)
    return res
