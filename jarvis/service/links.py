"""The Link Plane: every connection JARVIS depends on, kept or visibly lost.

The reliability plane (reliability.py) keeps scheduled *jobs* from going stale
silently. This keeps the *links* those jobs stand on: the Windows interop
bridge, the input hook, the native sensor spool, the Sysmon feeds, the
elevated broker, the Windows supervisor tasks, the dead-man heartbeat, the
alert channels and the sealed phone relay. Each has had its own check with its
own words; none had a common reconnect policy, so a stuck task or a dead socket
was described in a finding and then waited for a human.

Design (docs/architecture/LINK-PLANE-PROMPT.md): one table (LINKS) declares,
per link, the evidence that proves it alive, its maximum silence, the bounded
reconnect action and the owner's command. ``LinkPlane`` is pure policy with
small persisted state; the scheduler ticks it from the 20 s reliability
watchdog pass, gathers the evidence other jobs already produced, and performs
the actions it decides on one short worker thread. No new process, no new
timer.

Invariants (tests/test_links.py):

    L2 a link past its maximum silence always has a recorded reconnect attempt
       inside its budget or an `exhausted` state that names the owner command;
       `violations()` is empty under every modelled failure sequence.
    L3 at most BUDGET attempts per WINDOW_S per link, backoff BACKOFF between
       attempts; an action never restarts the daemon, never elevates, never
       changes policy, never deletes, never sends content.
    L4 state comes from stored evidence, never from a component's own claim;
       `last_ok` only moves forward on fresh good evidence.
    L6 no action during the cold-start hold or the resume grace.
    L7 nothing about the machine leaves it; the relay probe is one bodiless
       GET of a public key, the device list is metadata.

Collector health is never a compromise verdict: a silent link is a blind spot,
not an attack.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from jarvis.core.finding import LOCAL_HOST

META = "link_state"
UP, SILENT, DEGRADED, NA = "up", "silent", "degraded", "not_applicable"

BUDGET = 3                     # attempts per link per window
WINDOW_S = 3600.0
BACKOFF = (30.0, 120.0, 600.0)  # before attempt 1, 2, 3 (after silence began)
PENDING_GRACE_S = 120.0        # a decided action not yet reported back counts this long
RESUME_GRACE_S = 300.0
RELAY_PROBE_EVERY_S = 300.0
TASK_CACHE_S = 60.0            # Windows state files are re-read at most this often
RELAY_PROBE_TIMEOUT_S = 5
PHONE_DEAF_AFTER_S = 48 * 3600.0
STATE_MAX_BYTES = 8192
RELAY_UA = "notify-client/1"

# Actions, by name. The scheduler maps each to one bounded primitive an
# operator could run by hand. None = only the owner may act.
QUEUE, INTEROP, TASK = "queue", "interop", "task"


@dataclass(frozen=True)
class Link:
    name: str
    kind: str            # lane | job | task | broker | meta | channels | relay
    max_silence: float
    criticality: str
    action: str | None
    owner_cmd: str
    job: str = ""        # kind=job: the snapshot that is the evidence
    lane: str = ""       # kind=lane
    task: str = ""       # kind=task: the Windows scheduled task name
    windows: bool = False  # exists only when a Windows host is attached
    what: str = ""


LINKS: tuple[Link, ...] = (
    Link("lane:fast", "lane", 300, "critical", None, "systemctl restart jarvis", lane="fast",
         what="the one-minute lane (scan, bridge, native, hook, heartbeat)"),
    Link("lane:main", "lane", 900, "high", None, "systemctl restart jarvis", lane="main",
         what="the main collector lane"),
    Link("lane:frequent", "lane", 900, "high", None, "systemctl restart jarvis", lane="frequent",
         what="the five-minute collector lane (audio, hidden, resources, netwatch, ...)"),
    Link("lane:bulk", "lane", 1800, "medium", None, "systemctl restart jarvis", lane="bulk",
         what="the bulk lane (feeds, evidence, deep audits)"),
    Link("windows-bridge", "job", 135, "critical", INTEROP, "wsl --shutdown (from Windows), then wait",
         job="bridge", windows=True, what="PowerShell through the WSL interop socket"),
    Link("input-hook", "job", 135, "high", QUEUE, "jarvis inputwatch --start (from a desktop terminal)",
         job="input_hook", windows=True, what="the injected-input hook on the desktop"),
    Link("native-sensor", "job", 180, "critical", QUEUE, "Restart-Service JarvisNativeSensor (elevated)",
         job="native", windows=True, what="the native sensor spool (Sysmon, Defender, security log)"),
    Link("sysmon-windows", "job", 1200, "critical", QUEUE, "check the Sysmon service and its configuration",
         job="sysmon", windows=True, what="Windows Sysmon ingestion"),
    Link("sysmon-linux", "job", 1200, "critical", QUEUE, "journalctl -u sysmon; check journald retention",
         job="sysmon_linux", what="Linux Sysmon journal ingestion"),
    Link("elevated-broker", "broker", 45 * 60, "medium", TASK, "jarvis broker install",
         task="jarvis elevated broker", windows=True, what="privileged read-only evidence"),
    Link("health-monitor", "task", 300, "high", TASK,
         "powershell.exe -File jarvis-health-monitor.ps1 -Install",
         task="JARVIS independent health monitor", windows=True,
         what="the Windows monitor that reports JARVIS missing"),
    Link("reviver", "task", 60, "high", TASK, "powershell.exe -File jarvis-reviver.ps1 -Install",
         task="jarvis reviver", windows=True, what="the instant reviver"),
    Link("connectivity-guard", "task", 300, "medium", TASK,
         "powershell.exe -File jarvis-connectivity-guard.ps1 -Install",
         task="JARVIS connectivity guard", windows=True, what="the connectivity guard"),
    Link("dead-man", "meta", 0, "medium", None, "fix heartbeat_url in the alert config",
         what="the off-box dead-man heartbeat"),
    Link("alert-channels", "channels", 0, "critical", None,
         "jarvis notify pair (phone) or restore the mail configuration",
         what="a way to reach the owner"),
    Link("phone-relay", "relay", RELAY_PROBE_EVERY_S, "high", None, "jarvis notify pair",
         what="the sealed phone relay and the paired phones"),
)
BY_NAME = {link.name: link for link in LINKS}
TASK_LINKS = {link.name: link.task for link in LINKS if link.task}


# --- evidence ---------------------------------------------------------------

def _age(now, ts):
    try:
        ts = float(ts or 0)
    except (TypeError, ValueError):
        return None
    return max(0.0, now - ts) if ts > 0 else None


def relay_probe(base_url, opener=urllib.request.urlopen):
    """'' when the relay answers its public-key route, else a short reason.
    Unauthenticated, bodiless, five seconds: proves reachability only."""
    req = urllib.request.Request(base_url.rstrip("/") + "/v1/vapid", method="GET",
                                 headers={"User-Agent": RELAY_UA})
    try:
        with opener(req, timeout=RELAY_PROBE_TIMEOUT_S) as resp:
            resp.read(2048)
            code = getattr(resp, "status", 200)
            return "" if 200 <= code < 300 else f"HTTP {code}"
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return type(exc).__name__


def phone_evidence(now, probe=relay_probe, devices_call=None):
    """The relay side of the phone link, bounded and metadata-only.

    `devices_call(ident)` fetches the relay's device list (None when the
    route is not deployed or the call fails); injected for tests."""
    try:
        from jarvis.response import alert
        from jarvis.response.notify import crypto, devices, relay
    except Exception as exc:  # noqa: BLE001 - optional dependency
        return {"applicable": False, "reason": type(exc).__name__}
    conf = alert.load_conf()
    out = {"applicable": True, "paired": 0, "pending": 0, "relay_ok": None,
           "relay_error": "", "phones": []}
    try:
        active = devices.active()
    except Exception:
        active = []
    out["paired"] = len(active)
    out["pending"] = sum(1 for d in active if d.get("relay_pending"))
    try:
        base = relay.base_url(conf)
    except Exception as exc:  # noqa: BLE001
        out["relay_error"] = str(exc)[:80]
        return out
    err = probe(base)
    out["relay_ok"] = not err
    out["relay_error"] = err
    if err or not active:
        return out
    try:
        ident = crypto.Identity.load()
    except Exception:
        ident = None
    if ident is None:
        return out
    call = devices_call
    if call is None:
        def call(ident):
            try:
                return relay.call(conf, ident, "GET", f"/v1/mailbox/{ident.mailbox}/devices")
            except relay.RelayError:
                return None
    listed = call(ident)
    if isinstance(listed, list):
        known = {d["dev"] for d in active}
        for row in listed:
            if isinstance(row, dict) and row.get("dev") in known:
                out["phones"].append({"dev": str(row["dev"])[:10], "name": str(row.get("name") or "")[:40],
                                      "state": row.get("state"), "push": bool(row.get("push")),
                                      "last_seen": row.get("last_seen")})
    return out


# --- evaluation ----------------------------------------------------------------

def evaluate(link, evidence, now):
    """One link's state from gathered evidence: {state, age, since, reason}."""
    windows = bool(evidence.get("windows"))
    if link.windows and not windows:
        return {"state": NA, "reason": "no Windows host attached"}
    if link.kind == "lane":
        age = (evidence.get("lanes") or {}).get(link.lane)
        if age is None:
            return {"state": NA, "reason": "lane not running here"}
        if age == float("inf"):
            return {"state": SILENT, "age": None, "reason": "lane thread died"}
        if age > link.max_silence:
            return {"state": SILENT, "age": age, "reason": f"no loop for {int(age)} s"}
        return {"state": UP, "age": age}
    if link.kind == "job":
        snap = (evidence.get("snapshots") or {}).get(link.job) or {}
        age = _age(now, snap.get("ts"))
        if age is None:
            return {"state": SILENT, "age": None, "reason": "no result on record"}
        err = (snap.get("error") or "").strip()
        # Only a rotation seen by the latest pass counts: the collector keeps
        # remembered hits on view for a day, and one from yesterday says
        # nothing about the stream now. No seen_at (older collectors): current.
        last = float(snap.get("ts") or 0)
        rotated = any("rotated past the last read position" in (f.get("title") or "")
                      and (f.get("seen_at") is None or last - float(f["seen_at"]) < link.max_silence)
                      for f in (snap.get("findings") or ()) if isinstance(f, dict))
        if age > link.max_silence:
            return {"state": SILENT, "age": age, "since": now - age,
                    "reason": f"last result {int(age)} s ago" + (f"; {err[:80]}" if err else "")}
        if err:
            return {"state": DEGRADED, "age": age, "reason": err.splitlines()[-1][:120]}
        if rotated:
            return {"state": DEGRADED, "age": age, "reason": "journal rotated past the read position",
                    "tighten": True}
        return {"state": UP, "age": age}
    if link.kind in ("task", "broker"):
        checked = (evidence.get("tasks") or {}).get(link.name)
        if checked is None:
            return {"state": NA, "reason": "not installed"}
        age = _age(now, checked)
        if age is None or age > link.max_silence:
            return {"state": SILENT, "age": age, "since": (now - age) if age else None,
                    "reason": "state file unreadable or without a check time" if age is None
                    else f"last check {int(age)} s ago"}
        return {"state": UP, "age": age}
    if link.kind == "meta":
        hb = evidence.get("dead_man") or {}
        if not hb.get("configured"):
            return {"state": NA, "reason": "no heartbeat_url"}
        failures = int(hb.get("failures") or 0)
        if failures >= 5:
            return {"state": SILENT, "reason": f"{failures} pings failed in a row ({hb.get('last_error') or '?'})",
                    "since": hb.get("last_ok")}
        return {"state": UP, "age": _age(now, hb.get("last_ok"))}
    if link.kind == "channels":
        names = list(evidence.get("channels") or [])
        if not names:
            return {"state": SILENT, "reason": "no alert channel is configured"}
        return {"state": UP, "channels": names}
    if link.kind == "relay":
        ph = evidence.get("phone") or {}
        if not ph.get("applicable"):
            return {"state": NA, "reason": ph.get("reason") or "notify unavailable"}
        if not ph.get("paired"):
            return {"state": DEGRADED, "reason": "no phone is paired"}
        if ph.get("relay_ok") is False:
            return {"state": SILENT, "reason": f"relay unreachable: {ph.get('relay_error')}",
                    "since": ph.get("relay_since")}
        deaf = [p for p in ph.get("phones") or ()
                if p.get("last_seen") and _age(now, p["last_seen"]) is not None
                and _age(now, p["last_seen"]) > PHONE_DEAF_AFTER_S]
        pending = int(ph.get("pending") or 0)
        if pending:
            return {"state": DEGRADED, "reason": f"{pending} phone(s) paired here but not activated on the relay"}
        if deaf:
            names = ", ".join(p.get("name") or p.get("dev") for p in deaf)
            return {"state": DEGRADED, "reason": f"not heard from the relay for 48 h: {names}"}
        nopush = [p for p in ph.get("phones") or () if p.get("state") == "active" and not p.get("push")]
        if nopush:
            return {"state": UP, "note": f"{len(nopush)} phone(s) without push: alerts wait until the app is opened"}
        return {"state": UP, "phones": len(ph.get("phones") or ())}
    return {"state": NA, "reason": "unknown link kind"}


# --- the plane -------------------------------------------------------------------

class LinkPlane:
    """Policy + small state. `tick` decides; the caller performs actions and
    reports outcomes with `attempted`. Everything here is synchronous and
    thread-free, so it can be tested with a fake clock."""

    def __init__(self, links=LINKS):
        self.links = tuple(links)
        self.state = {"links": {}, "relay": {}}
        self.statuses = {}
        self.dirty = False

    # persistence ------------------------------------------------------------
    def load(self, raw):
        try:
            doc = json.loads(raw or "{}")
        except (TypeError, ValueError):
            doc = {}
        if isinstance(doc, dict) and isinstance(doc.get("links"), dict):
            self.state = {"links": doc["links"], "relay": doc.get("relay") or {},
                          "lanes": doc.get("lanes") or {}}
        return self

    def dump(self):
        raw = json.dumps(self.state, sort_keys=True, separators=(",", ":"))
        if len(raw) > STATE_MAX_BYTES:
            # Bound the record: keep the newest attempts only.
            for entry in self.state["links"].values():
                entry["attempts"] = entry.get("attempts", [])[-BUDGET:]
            raw = json.dumps(self.state, sort_keys=True, separators=(",", ":"))
        return raw

    def _entry(self, name):
        return self.state["links"].setdefault(name, {"state": UP, "attempts": []})

    # decisions ----------------------------------------------------------------
    def tick(self, evidence, now, hold=False):
        """Evaluate every link. Returns {"actions": [(link, action)],
        "transitions": [(name, old, new, reason)]}. `hold` (cold start,
        resume grace, owner pause) suppresses actions, never evaluation."""
        actions, transitions = [], []
        for link in self.links:
            st = evaluate(link, evidence, now)
            entry = self._entry(link.name)
            old = entry.get("state", UP)
            if st["state"] == UP:
                # The newest good evidence, never the clock: L4.
                seen = now - st["age"] if st.get("age") is not None else now
                entry["last_ok"] = max(float(entry.get("last_ok") or 0), seen)
                entry["attempts"] = []
                entry.pop("pending", None)
                entry.pop("exhausted", None)
                entry.pop("since", None)
            elif st["state"] == SILENT and "since" not in entry:
                since = st.get("since") or entry.get("last_ok") or now
                entry["since"] = float(since)
            if old != st["state"]:
                transitions.append((link.name, old, st["state"], st.get("reason", "")))
                entry["state"] = st["state"]
                entry["reason"] = st.get("reason", "")
                self.dirty = True
            if st["state"] == SILENT and link.action and not hold:
                if self._attempt_due(entry, now):
                    actions.append((link, link.action))
                    # First decision time: refreshing it would hide a worker
                    # that never reports back (the violation this detects).
                    entry.setdefault("pending", now)
            if st["state"] == SILENT and link.action and self._exhausted(entry, now) \
                    and not entry.get("exhausted"):
                entry["exhausted"] = now
                self.dirty = True
            self.statuses[link.name] = {**st, "link": link.name, "criticality": link.criticality,
                                        "what": link.what, "owner_cmd": link.owner_cmd,
                                        "action": link.action, "attempts": len(entry.get("attempts") or []),
                                        "last_attempt": entry.get("last_attempt"),
                                        "exhausted": bool(entry.get("exhausted")),
                                        "since": entry.get("since"), "last_ok": entry.get("last_ok")}
        return {"actions": actions, "transitions": transitions}

    def _recent(self, entry, now):
        return [t for t in entry.get("attempts") or [] if now - float(t) < WINDOW_S]

    def _exhausted(self, entry, now):
        return len(self._recent(entry, now)) >= BUDGET

    def _attempt_due(self, entry, now):
        recent = self._recent(entry, now)
        if len(recent) >= BUDGET:
            return False
        since = float(entry.get("since") or now)
        basis = max([since] + [float(t) for t in recent])
        return now - basis >= BACKOFF[len(recent)]

    def attempted(self, name, action, error, now):
        """Record one performed action and its outcome (L3)."""
        entry = self._entry(name)
        entry.setdefault("attempts", []).append(now)
        entry["attempts"] = entry["attempts"][-BUDGET:]
        entry["last_attempt"] = {"at": now, "action": action, "error": (error or "")[:160]}
        entry.pop("pending", None)
        self.dirty = True

    # reports --------------------------------------------------------------------
    def violations(self, now):
        """Silent links with an action that was neither attempted inside the
        window nor marked exhausted: the state L2 forbids. Pure; for tests
        and the health endpoint."""
        out = []
        for link in self.links:
            st = self.statuses.get(link.name) or {}
            if st.get("state") != SILENT or not link.action:
                continue
            entry = self._entry(link.name)
            since = float(entry.get("since") or now)
            if now - since < BACKOFF[0]:
                continue           # inside the first backoff: not yet due
            if self._recent(entry, now) or entry.get("exhausted"):
                continue
            pending = entry.get("pending")
            if pending and now - float(pending) < PENDING_GRACE_S:
                continue           # decided this tick; the worker has not reported yet
            out.append(link.name)
        return out

    def summary(self, now=None):
        now = time.time() if now is None else now
        counts = {UP: 0, SILENT: 0, DEGRADED: 0, NA: 0}
        for st in self.statuses.values():
            counts[st.get("state", NA)] = counts.get(st.get("state", NA), 0) + 1
        silent = sorted(n for n, s in self.statuses.items() if s.get("state") == SILENT)
        exhausted = sorted(n for n, s in self.statuses.items() if s.get("exhausted"))
        return {"counts": counts, "silent": silent, "exhausted": exhausted,
                "violations": self.violations(now), "links": self.statuses}

    def findings(self, now=None):
        """Findings for the watchdogs job: silence (medium), attempts (low),
        exhausted budgets (high, naming the owner command). The components'
        own findings stay the primary pages; nothing is suppressed."""
        now = time.time() if now is None else now
        out = []
        for link in self.links:
            st = self.statuses.get(link.name)
            if not st or st.get("state") in (UP, NA):
                continue
            where = link.task or link.job or link.name
            if st.get("state") == DEGRADED:
                out.append(_f("low", f"connection degraded: {link.name}",
                              f"{link.what}: {st.get('reason', '')}. Next step if it persists: {link.owner_cmd}.",
                              where, link.job or f"link:{link.name}"))
                continue
            la = st.get("last_attempt") or {}
            if st.get("exhausted"):
                out.append(_f("high", f"connection lost: {link.name} (reconnect budget used)",
                              f"{link.what}: {st.get('reason', '')}. {BUDGET} reconnect attempts in the last hour "
                              f"did not bring it back (last: {la.get('action')}, "
                              f"{'ok' if not la.get('error') else la.get('error')}). Owner action: {link.owner_cmd}.",
                              where, link.job or f"link:{link.name}"))
            elif link.action is None:
                out.append(_f("medium" if link.criticality in ("medium", "low") else "high",
                              f"connection lost: {link.name}",
                              f"{link.what}: {st.get('reason', '')}. No automatic reconnect exists for this link. "
                              f"Owner action: {link.owner_cmd}.", where, link.job or f"link:{link.name}"))
            else:
                detail = f"{link.what}: {st.get('reason', '')}."
                if la:
                    detail += (f" Reconnect attempted ({la.get('action')}) at "
                               f"{time.strftime('%H:%M:%S', time.localtime(float(la.get('at') or now)))}"
                               + (f": {la['error']}" if la.get("error") else "") + ".")
                else:
                    detail += " A reconnect is scheduled."
                out.append(_f("medium", f"connection silent: {link.name}", detail, where,
                              link.job or f"link:{link.name}"))
        if not out:
            out.append(_f("ok", "every connection is up",
                          f"{sum(1 for s in self.statuses.values() if s.get('state') == UP)} links verified "
                          "from stored evidence; nothing silent, nothing exhausted", "links"))
        return out


def _f(severity, title, detail, where, about=""):
    """A finding about another component. `about_collector` says so: without
    it the watchdogs job's own run would count as a blind spot (incidents.
    coverage_status), and the score could not drop a verdict that newer clean
    evidence from that collector has contradicted."""
    out = {"category": "collectors", "severity": severity, "title": title, "detail": detail,
           "where": where, "host": LOCAL_HOST}
    if about:
        out["about_collector"] = about
    return out


def findings_from_meta(raw, evidence, now=None):
    """The watchdogs job's view: rebuild the plane from persisted state and
    current evidence (it runs in a lane, not in the supervisor thread)."""
    now = time.time() if now is None else now
    plane = LinkPlane().load(raw)
    plane.tick(evidence, now, hold=True)
    return plane.findings(now)


# --- evidence gathering ----------------------------------------------------------

def gather_evidence(snapshots, now, store=None, scheduler=None, plane=None, windows=None,
                    phone=phone_evidence):
    """Everything `evaluate` needs, from state other jobs already produced.

    Reads three small state files, the broker status, the alert config and
    the store's heartbeat meta; the relay probe runs at most every
    RELAY_PROBE_EVERY_S and its result is kept in the plane's state so the
    watchdogs job can reuse it instead of probing again. Never raises."""
    from jarvis.platform import host
    ev = {"snapshots": snapshots or {}, "lanes": {}, "tasks": {}, "dead_man": {},
          "channels": [], "phone": {"applicable": False, "reason": "not gathered"}}
    ev["windows"] = host.has_windows() if windows is None else bool(windows)
    if scheduler is not None:
        for lane in ("fast", "frequent", "main", "bulk"):
            thread = getattr(scheduler, f"{lane}_thread", None) if lane != "main" else scheduler
            if thread is None:
                continue                      # never started here: not applicable
            if not getattr(thread, "is_alive", lambda: False)():
                ev["lanes"][lane] = float("inf")   # started and died: silent, never "not running here"
                continue
            try:
                ev["lanes"][lane] = float(scheduler.lane_age(lane))
            except Exception:
                pass
        if plane is not None:
            plane.state["lanes"] = {"at": now, **{k: (v if v != float("inf") else -1) for k, v in ev["lanes"].items()}}
    elif plane is not None:
        # A lane only (the watchdogs job): the supervisor thread persisted the
        # lane ages on its last tick. A stale stamp means the supervisor itself
        # stopped, which every lane then reports as silence (L2).
        seen = plane.state.get("lanes") or {}
        at = float(seen.get("at") or 0)
        if at:
            late = max(0.0, now - at - 60.0)
            for k, v in seen.items():
                if k != "at":
                    ev["lanes"][k] = float("inf") if v == -1 else float(v) + late
    cache = getattr(plane, "_cache", None) if plane is not None else None
    if ev["windows"] and cache and now - float(cache.get("at") or 0) < TASK_CACHE_S:
        # The state files live on the Windows drive (9p): about 40 ms per
        # read set. Once a minute is plenty for links whose budgets are
        # measured in minutes; the lanes and snapshots above stay live.
        ev["tasks"] = dict(cache["tasks"])
    elif ev["windows"]:
        try:
            from jarvis.platform import broker
            from jarvis.service import connectivity, supervisors
            paths = {"health-monitor": supervisors.health_monitor_state_path(),
                     "reviver": supervisors.REVIVER_STATE,
                     "connectivity-guard": connectivity.STATE}
            for name, path in paths.items():
                state = supervisors.read_state(path)
                if state is None:
                    import os
                    if os.path.exists(path):
                        # Present but unreadable (a truncated write, a stale
                        # Windows drive, or tampering): silent, so a bounded
                        # restart rewrites it; the supervisors audit already
                        # reports the unreadable file itself. Never "absent".
                        ev["tasks"][name] = 0
                    continue
                ev["tasks"][name] = state.get("checkedAt") or 0
            if broker.installed():
                ev["tasks"]["elevated-broker"] = (broker.status() or {}).get("finished") or 0
        except Exception:
            pass
        if plane is not None:
            plane._cache = {"at": now, "tasks": dict(ev["tasks"])}
    try:
        from jarvis.response import alert
        conf = alert.load_conf()
        ev["channels"] = alert.channels(conf)
        if (conf.get("heartbeat_url") or "").strip() and store is not None:
            hb = json.loads(store.get_meta("heartbeat_state", "{}") or "{}")
            ev["dead_man"] = {"configured": True, **(hb if isinstance(hb, dict) else {})}
    except Exception:
        pass
    relay = (plane.state.get("relay") if plane is not None else None) or {}
    fresh = relay.get("at") and now - float(relay["at"]) < RELAY_PROBE_EVERY_S
    if not fresh and plane is not None:
        try:
            probe = phone(now)
        except Exception as exc:  # noqa: BLE001
            probe = {"applicable": False, "reason": type(exc).__name__}
        since = relay.get("relay_since")
        if probe.get("relay_ok") is False:
            since = since or now
        else:
            since = None
        relay = {"at": now, **probe, "relay_since": since}
        plane.state["relay"] = relay
        plane.dirty = True
    ev["phone"] = {k: v for k, v in relay.items() if k != "at"}
    return ev
