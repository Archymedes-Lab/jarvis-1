"""One authoritative provider per expensive system state.

Phase 3 groundwork: six consumers must not perform six expensive reads.
Collectors consume shared states instead of independently executing
PowerShell, /proc walks, WMI, socket enumeration or filesystem scans.

Current scope is deliberately narrow: a TTL-cached process snapshot shared
between the process scan and the resource profiler (the two hottest
collectors). The cache key includes hosts and socket attribution so a
caller that needs sockets never silently receives a socket-less snapshot.

  ONE expensive read
          ↓
  many cheap consumers

instead of six consumers → six expensive reads. Event-first telemetry
remains the long-term direction; this removes the duplicate polling cost
without changing any finding semantics.
"""

import threading
import time

_TTL_DEFAULT = 30.0
_SOCKET_TTL = 5.0

_CACHE = {}
_SOCKET_CACHE = {"at": 0.0, "table": None}
_HITS = {"hits": 0, "misses": 0}
_SOCKET_HITS = {"hits": 0, "misses": 0}
_LOCK = threading.RLock()


def _key(hosts, with_sockets):
    return (tuple(sorted(hosts)), bool(with_sockets))


def get_processes(hosts, collect_fn, with_sockets=True, ttl=_TTL_DEFAULT,
                  now=None):
    """Return cached processes or call collect_fn() once and cache the result.

    `collect_fn` is a zero-argument callable performing the expensive read.
    Pure caching layer: never mutates the list, never fabricates processes.
    """
    now = time.monotonic() if now is None else now
    key = _key(hosts, with_sockets)
    with _LOCK:
        entry = _CACHE.get(key)
        if entry is not None and now - entry["at"] <= ttl:
            _HITS["hits"] += 1
            return entry["processes"]
        # Collect while holding the lock so simultaneous consumers cannot
        # both perform the same expensive system read on a cold cache.
        processes = collect_fn()
        _CACHE[key] = {"at": now, "processes": processes}
        _HITS["misses"] += 1
        return processes


def clear():
    with _LOCK:
        _CACHE.clear()
        _HITS["hits"] = 0
        _HITS["misses"] = 0
        _SOCKET_CACHE["at"] = 0.0
        _SOCKET_CACHE["table"] = None
        _SOCKET_HITS["hits"] = 0
        _SOCKET_HITS["misses"] = 0


def stats():
    with _LOCK:
        return {"entries": len(_CACHE), "hits": _HITS["hits"],
                "misses": _HITS["misses"],
                "socket_hits": _SOCKET_HITS["hits"],
                "socket_misses": _SOCKET_HITS["misses"]}


def get(key, collect_fn, ttl=_TTL_DEFAULT, now=None):
    """Generic authoritative provider: one expensive read, many consumers.

    `key` names the system state (e.g. "processes:wsl+win:sockets").
    Pure caching layer: never mutates the value, never fabricates state.
    """
    now = time.monotonic() if now is None else now
    with _LOCK:
        entry = _CACHE.get(key)
        if entry is not None and now - entry["at"] <= ttl:
            _HITS["hits"] += 1
            return entry["processes"]
        value = collect_fn()
        _CACHE[key] = {"at": now, "processes": value}
        _HITS["misses"] += 1
        return value


def get_socket_table(collect_fn, ttl=_SOCKET_TTL, now=None):
    """One /proc/net read per interval, shared by process, firewall and
    hidden-socket consumers. `collect_fn` performs the expensive read."""
    now = time.monotonic() if now is None else now
    with _LOCK:
        if (_SOCKET_CACHE["table"] is not None
                and now - _SOCKET_CACHE["at"] <= ttl):
            _SOCKET_HITS["hits"] += 1
            return _SOCKET_CACHE["table"]
        table = collect_fn()
        _SOCKET_CACHE["at"] = now
        _SOCKET_CACHE["table"] = table
        _SOCKET_HITS["misses"] += 1
        return table
