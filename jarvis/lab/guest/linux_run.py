"""Runs inside the disposable guest: start each emulator, then measure whether the
real reader (jarvis.platform.spy_linux) sees it, and how fast. Prints its result as
base64 between markers plus a sha256, and never touches a network or the host."""

import base64
import glob
import hashlib
import json
import os
import platform
import resource
import signal
import subprocess
import sys
import time

sys.path.insert(0, "/opt/lab")
from jarvis.platform import spy_linux  # noqa: E402

LAB = "/opt/lab"
SETTLE_S = 3.0          # how long a "should stay quiet" control is observed
POLL_S = 0.25
READY_TIMEOUT_S = 30


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _dump(subject):
    return {"key": subject.key, "host": "wsl", "label": subject.label, "signature": subject.signature,
            "path_class": subject.path_class,
            "observations": [{"kind": o.kind, "source": o.source, "fresh": o.fresh, "complete": o.complete}
                             for o in subject.observations]}


def _offers():
    keyboard = any(spy_linux.keyboard_event(p[len("/dev/input/event"):]) is True
                   for p in glob.glob("/dev/input/event*"))
    return {"keyboard": keyboard, "sound": bool(glob.glob("/dev/snd/pcmC*D*c")),
            "uinput": os.path.exists("/dev/uinput")}


def _scan():
    t0, c0 = time.monotonic(), time.process_time()
    subs, cov = spy_linux.subjects()
    return subs, cov, {"wall_s": round(time.monotonic() - t0, 4), "cpu_s": round(time.process_time() - c0, 4),
                       "maxrss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}


def _target(subs, pid):
    for s in subs:
        if s.key.split(":")[-2] == str(pid):
            return s
    return None


def _run_one(sc, offers):
    if sc.get("needs") and not offers.get(sc["needs"]):
        return {"id": sc["id"], "status": "skipped", "reason": f"guest offers no {sc['needs']} device"}
    proc = subprocess.Popen([sys.executable, f"{LAB}/lab/emu_linux.py", sc["emulator"]],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                            errors="replace", start_new_session=True)
    try:
        signal.alarm(READY_TIMEOUT_S)
        line = proc.stdout.readline().strip()
        signal.alarm(0)
    except Exception:
        line = ""
    if not line.startswith("READY "):
        _stop(proc, None)
        return {"id": sc["id"], "status": "error", "reason": "emulator did not become ready"}
    target_pid = int(line.split()[1])
    t_ready = time.monotonic()
    want = set(sc.get("expect_kinds") or ())
    quiet = not want
    found, cost, latency = None, None, None
    end = t_ready + max(SETTLE_S, float(sc.get("max_latency_s", 10)) * 2)
    while time.monotonic() < end:
        subs, _cov, cost = _scan()
        s = _target(subs, target_pid)
        if s is not None:
            found = s
            kinds = {o.kind for o in s.observations}
            if want and want <= kinds:
                latency = round(time.monotonic() - t_ready, 3)
                break
        if quiet and time.monotonic() - t_ready >= SETTLE_S:
            latency = round(time.monotonic() - t_ready, 3)
            break
        time.sleep(POLL_S)
    cleaned = _stop(proc, target_pid)
    return {"id": sc["id"], "status": "ran", "subject": _dump(found) if found else None,
            "latency_s": latency, "scan_cost": cost, "cleaned": cleaned}


def _stop(proc, target_pid):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
    if target_pid is None:
        return True
    for _ in range(40):
        try:
            os.kill(target_pid, 0)
        except OSError:
            return True
        time.sleep(0.1)
    return False


def main():
    with open(f"{LAB}/scenarios.json", encoding="utf-8", errors="replace") as fh:
        scenarios = json.load(fh)
    files = {p: _sha(p) for p in sorted(glob.glob(f"{LAB}/**/*.py", recursive=True))}
    offers = _offers()
    subs, cov, cost = _scan()
    baseline = [_dump(s) for s in subs if s.observations]
    results = [_run_one(sc, offers) for sc in scenarios]
    out = {"kernel": platform.release(), "python": platform.python_version(), "offers": offers,
           "files_sha256": files, "baseline": {"processes": len(subs), "coverage": cov["status"],
                                              "with_observations": baseline, "scan_cost": cost},
           "results": results,
           "uptime_s": float(open("/proc/uptime", encoding="utf-8", errors="replace")
                            .read().split()[0])}
    raw = json.dumps(out, separators=(",", ":"), sort_keys=True).encode()
    print("JVLAB-DATA-BEGIN")
    b64 = base64.b64encode(raw).decode()
    for i in range(0, len(b64), 76):
        print(b64[i:i + 76])
    print("JVLAB-DATA-END")
    print("JVLAB-SHA256 " + hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    main()
