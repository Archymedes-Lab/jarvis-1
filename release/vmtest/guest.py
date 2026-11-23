#!/usr/bin/env python3
"""Runs inside a disposable guest (root, no network): the clean-machine matrix for the
ARGUS-1 server edition (docs/commercial/VM-INSTALL-MATRIX.md).

Phase 1 (cloud-init, first boot):
  S1 the packages in the payload are the signed bytes (re-hashed here)
  S7 optional upgrade: install the older release, let it run, install the candidate
  S2 first run: unit active as argus, health answers, native CLI, no Python installed
  S3 planted scenario (16 checks), S4 idle footprint, S5 `argus review`
  then reboot into phase 2 (a one-shot unit that runs at most once)
Phase 2 (after the reboot):
  S6 service back, scheduler receipts resume; S8 remove; S9 purge
Prints one base64 JSON result between markers on the serial console, then powers off.
Any exception reports itself and powers off: the guest never hangs or reboot-loops.
"""
import base64
import glob
import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

LAB = "/opt/lab"
WORK = "/var/lib/vmtest"
CONF = json.load(open(f"{LAB}/config.json"))
OBSERVE_S = int(CONF.get("idle_s", 3600))
SETTLE_S = int(CONF.get("settle_s", 600))
SAMPLE_S = 60
PORT = 8787
STATE = "/var/lib/argus/.argus"
PHASE2_UNIT = "/etc/systemd/system/vmtest-phase2.service"
R = {"results": [], "timeline": [], "config": CONF}
T0 = time.time()


def mark(what):
    R["timeline"].append([round(time.time() - T0, 1), what])
    print(f"[vmtest {time.time() - T0:6.1f}s] {what}", flush=True)


def sh(cmd, timeout=600):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, errors="replace", timeout=timeout)
        return r.returncode, (r.stdout + r.stderr)
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"


AUTH = {"token": None}     # the release requires a credential on every API route (read too)


def http(path, method="GET", token=None, timeout=20, anonymous=False):
    token = None if anonymous else (token or AUTH["token"])
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method,
                                 headers={"X-ARGUS-Token": token} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(4 * 1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def unit(prop):
    _, out = sh(f"systemctl show argus.service -p {prop} --value", 20)
    return out.strip()


def rss_mb(pid):
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS"):
                return int(line.split()[1]) // 1024
    except OSError:
        return None


def meminfo(key):
    for line in open("/proc/meminfo"):
        if line.startswith(key + ":"):
            return int(line.split()[1]) // 1024


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def token():
    for p in [f"{STATE}/api.token"] + glob.glob("/var/lib/argus/**/api.token", recursive=True):
        try:
            return open(p).read().strip()
        except OSError:
            continue
    return None


def wait_live(limit=180):
    end = time.time() + limit
    while time.time() < end:
        status, _ = http("/api/live")
        if status in (200, 503):
            return round(time.time() - T0, 1)
        time.sleep(2)
    return None


def job_ts(name):
    _, body = http("/api/state")
    try:
        for j in json.loads(body).get("jobs", []):
            if j.get("name") == name:
                return j.get("ts") or 0
    except ValueError:
        pass
    return 0


def run_jobs(token, names, timeout=420):
    """Force jobs and wait until each has a result newer than the request."""
    before = {n: job_ts(n) for n in names}
    for n in names:
        http(f"/api/run?job={n}", "POST", token)
    end, done = time.time() + timeout, set()
    while time.time() < end and len(done) < len(names):
        for n in names:
            if n not in done and job_ts(n) > before[n]:
                done.add(n)
        time.sleep(3)
    return {n: n in done for n in names}


def findings_of(jobs):
    _, body = http("/api/state")
    try:
        return [{"job": f.get("job"), "severity": f.get("severity"), "title": (f.get("title") or "")[:200],
                 "detail": (f.get("detail") or "")[:400], "where": (f.get("where") or "")[:200]}
                for f in json.loads(body).get("findings", []) if f.get("job") in jobs]
    except ValueError:
        return []


# A codebase an attacker or a careless deploy leaves on a server: a dependency
# with a published advisory, code that evaluates input, and a secret in .env.
DEMO_LOCK = {"name": "demoapp", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
             "packages": {"": {"name": "demoapp", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
                          "node_modules/lodash": {"version": "4.17.15",
                                                  "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"}}}
DEMO_PY = (
    "import subprocess\n"
    "from flask import request\n\n"
    "def run():\n"
    "    subprocess.call('ping -c1 ' + request.args['h'], shell=True)\n"
    "    return eval(request.args['expr'])\n")
# The one advisory the guest can know without network: OSV GHSA-p6mc-m468-83gw
# (CVE-2020-8203, lodash prototype pollution, fixed in 4.17.19), in the index
# shape core/osvindex.py documents. The daily osv job would download it.
OSV_SEED = {"ecosystems": {"npm": {"fetched_at": None, "source": "vmtest seed (no network in the guest)",
                                   "packages": {"lodash": [{
                                       "id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"],
                                       "severity": "HIGH", "summary": "Prototype Pollution in lodash",
                                       "malicious": False, "ranges": [["3.7.0", "4.17.19", None]],
                                       "versions": []}]}}}}


def expect(found, label, test):
    hit = [f for f in found if test(f)]
    return {"check": label, "ok": bool(hit), "evidence": hit[:2]}


def scenario(token):
    """Real sshd, real keys, a real reverse tunnel, a real codebase: plant them
    after a baseline and check each one is reported (results in R["scenario"])."""
    S = R["scenario"] = {"steps": {}}
    S["sshd"] = sh("sshd -V 2>&1; systemctl is-active ssh.socket ssh.service 2>&1", 20)[1].strip()[-300:]
    # Baseline: let sshwatch and logins learn the server as installed.
    S["baseline_runs"] = run_jobs(token, ["sshwatch", "logins", "opshealth"])
    S["baseline"] = findings_of({"sshwatch"})
    mark(f"scenario baseline: {S['baseline_runs']} {len(S['baseline'])} sshwatch findings")

    steps = [
        ("key", "install -d -m700 /root/.ssh && ssh-keygen -q -t ed25519 -N '' -C vmtest-intruder -f /root/.ssh/vmtest"
                " && install -d -m700 -o vmuser -g vmuser /home/vmuser/.ssh"
                " && cat /root/.ssh/vmtest.pub >> /home/vmuser/.ssh/authorized_keys"
                " && chown vmuser:vmuser /home/vmuser/.ssh/authorized_keys && chmod 600 /home/vmuser/.ssh/authorized_keys"),
        ("service_key", "install -d -m700 -o www-data -g www-data /var/www/.ssh"
                        " && ssh-keygen -q -t ed25519 -N '' -C vmtest-svc -f /root/.ssh/svc"
                        " && install -m600 -o www-data -g www-data /root/.ssh/svc.pub /var/www/.ssh/authorized_keys"),
        ("config", "printf 'PermitUserEnvironment yes\\n' > /etc/ssh/sshd_config.d/00-vmtest.conf"
                   " && (systemctl reload ssh 2>/dev/null || true)"),
        ("tunnel", "ssh -i /root/.ssh/vmtest -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                   " -o BatchMode=yes -o ExitOnForwardFailure=yes -f -N -R 9000:localhost:22 vmuser@127.0.0.1"),
        ("hostkey", "cp /etc/ssh/ssh_host_ed25519_key.pub /root/hostkey.before"
                    " && rm -f /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub && ssh-keygen -A"),
        ("codebase", "mkdir -p /srv/demoapp && cd /srv/demoapp && git init -q 2>/dev/null; true"),
        # opshealth: a unit that fails, a certificate 3 days from expiry named by an
        # nginx site, and a real cgroup OOM kill (a unit over its MemoryMax).
        ("failed_unit", "systemd-run --unit=vmtest-fail -p Restart=no /bin/false; sleep 2; "
                        "systemctl is-failed vmtest-fail"),
        ("cert", "mkdir -p /etc/ssl/vmtest /etc/nginx/sites-enabled && openssl req -x509 -newkey ec"
                 " -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /etc/ssl/vmtest/site.key"
                 " -out /etc/ssl/vmtest/site.pem -subj /CN=vmtest.example -days 3 2>&1 | tail -1"
                 " && printf 'server {\\n listen 443 ssl;\\n ssl_certificate /etc/ssl/vmtest/site.pem;\\n"
                 " ssl_certificate_key /etc/ssl/vmtest/site.key;\\n}\\n' > /etc/nginx/sites-enabled/vmtest"),
        ("oom", "systemd-run --unit=vmtest-oom --wait -p MemoryMax=40M -p MemorySwapMax=0 "
                "python3 -c 'b = bytearray(400 * 1024 * 1024)'; journalctl -k -n 5 -o cat | grep -i 'killed process' | tail -1"),
    ]
    for name, cmd in steps:
        code, out = sh(cmd, 60)
        S["steps"][name] = {"code": code, "out": out.strip()[-300:]}
    with open("/srv/demoapp/package.json", "w") as fh:
        json.dump({"name": "demoapp", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}}, fh)
    with open("/srv/demoapp/package-lock.json", "w") as fh:
        json.dump(DEMO_LOCK, fh)
    with open("/srv/demoapp/app.py", "w") as fh:
        fh.write(DEMO_PY)
    with open("/srv/demoapp/.env", "w") as fh:
        fh.write("DATABASE_URL=postgres://app:Vmtest-Plant3d-Passw0rd@db.internal/app\n")
    osv = f"{STATE}/osv"
    os.makedirs(osv, exist_ok=True)
    seed = json.loads(json.dumps(OSV_SEED))
    seed["ecosystems"]["npm"]["fetched_at"] = time.time()
    with open(f"{osv}/index.json", "w") as fh:
        json.dump(seed, fh)
    sh(f"chown -R argus:argus {osv}; chmod 700 {osv}", 20)
    S["tunnel_listen"] = sh("ss -tlnp 2>/dev/null | grep -E ':9000\\b' || true", 20)[1].strip()[-300:]
    mark(f"scenario planted: { {k: v['code'] for k, v in S['steps'].items()} }")

    S["runs"] = run_jobs(token, ["sshwatch", "logins", "opshealth"], timeout=300)
    # appcode alone, timed: it must finish well inside its 300 s job timeout.
    t0 = time.time()
    S["runs"].update(run_jobs(token, ["appcode"], timeout=600))
    S["appcode_wall_s"] = round(time.time() - t0, 1)
    _, body = http("/api/state")
    try:
        S["job_durations"] = {j["name"]: j.get("duration") for j in json.loads(body).get("jobs", [])
                              if j.get("name") in ("appcode", "sshwatch", "logins", "opshealth")}
    except ValueError:
        S["job_durations"] = {}
    # The job snapshot records no duration, so time appcode directly: one full
    # run as the argus account with the service's capabilities, beside the
    # running daemon on this 1-vCPU guest.
    t0 = time.time()
    # /usr/local/bin/argus drops to the argus account with the service's capabilities.
    code, out = sh("/usr/local/bin/argus appcode --json > /run/appcode-timed.json", 900)
    S["appcode_timed"] = {"seconds": round(time.time() - t0, 1), "code": code, "out": out.strip()[-300:]}
    try:
        timed = json.load(open("/run/appcode-timed.json"))
        S["appcode_timed"]["findings"] = len(timed)
        S["appcode_timed"]["demoapp"] = any("/srv/demoapp" in json.dumps(f) for f in timed)
    except (OSError, ValueError) as exc:
        S["appcode_timed"]["read_error"] = type(exc).__name__
    found = findings_of({"sshwatch", "logins", "appcode", "opshealth"})
    S["findings"] = found[:120]
    t = lambda f: f["title"].lower()  # noqa: E731
    checks = [
        expect(found, "new key on vmuser reported", lambda f: t(f) == "new ssh key for vmuser"),
        expect(found, "service-account key reported", lambda f: t(f) == "ssh key on service account www-data"),
        expect(found, "PermitUserEnvironment reported", lambda f: "set their login environment" in t(f)),
        expect(found, "reverse tunnel client reported", lambda f: t(f).startswith("reverse ssh tunnel from this host")),
        expect(found, "sshd remote-forward listener reported", lambda f: "forwards port 9000" in t(f)),
        expect(found, "open session reported", lambda f: "ssh session(s) open now" in t(f)),
        expect(found, "host key change reported", lambda f: t(f) == "ssh host key changed"),
        {"check": "sshwatch fully observed (no visibility gap)",
         "ok": not any(f["job"] == "sshwatch" and t(f) == "ssh not fully observed" for f in found),
         "evidence": [f for f in found if f["job"] == "sshwatch" and t(f) == "ssh not fully observed"][:1]},
        expect(found, "codebase /srv/demoapp detected",
               lambda f: f["job"] == "appcode" and "/srv/demoapp" in (f["detail"] + f["where"] + f["title"])),
        expect(found, "lodash advisory matched",
               lambda f: f["job"] == "appcode" and ("lodash" in (f["title"] + f["detail"]).lower())
               and ("GHSA-p6mc-m468-83gw" in f["title"] + f["detail"] or "CVE-2020-8203" in f["title"] + f["detail"])),
        expect(found, "eval / shell=True code reported",
               lambda f: f["job"] == "appcode" and "app.py" in (f["detail"] + f["where"])
               and any(w in (f["title"] + f["detail"]).lower() for w in ("eval", "shell"))),
        expect(found, ".env secret reported",
               lambda f: f["job"] == "appcode" and ".env" in (f["detail"] + f["where"] + f["title"])),
        expect(found, "failed unit reported", lambda f: t(f) == "service vmtest-fail.service has failed"),
        expect(found, "expiring certificate reported (high)",
               lambda f: t(f).startswith("tls certificate for vmtest.example expires in") and f["severity"] == "high"),
        expect(found, "cgroup OOM kill reported", lambda f: f["job"] == "opshealth" and "killed" in t(f)
               and "python3" in f["detail"]),
        {"check": "appcode alone finishes within 240 s on 1 vCPU (timed directly)",
         "ok": S["appcode_timed"]["code"] == 0 and S["appcode_timed"]["seconds"] <= 240
               and S["appcode_timed"].get("demoapp") is True,
         "evidence": [S["appcode_timed"]]},
    ]
    for c in checks:
        c["evidence"] = c["evidence"][:2]
    S["checks"] = checks
    S["passed"] = sum(c["ok"] for c in checks)
    S["total"] = len(checks)
    leak = [f for f in found if "Vmtest-Plant3d-Passw0rd" in json.dumps(f)]
    S["secret_value_in_findings"] = bool(leak)
    mark(f"scenario: {S['passed']}/{S['total']} checks passed; secret value shown: {bool(leak)}")
    sh("pkill -f 'ssh -i /root/.ssh/vmtest' || true", 10)


# -- packages ------------------------------------------------------------------

def package_path(which):
    return CONF["files"][which]["guest_path"]


def install(which):
    """Install the old or candidate package the way a user would. {code, seconds, tail}."""
    path = package_path(which)
    t = time.time()
    if CONF["package"] == "deb":
        code, out = sh(f"DEBIAN_FRONTEND=noninteractive dpkg -i {path}", 900)
    else:
        dest = f"{LAB}/{which}"
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest)
        code, out = sh(f"tar -xzf {path} -C {dest} && {dest}/argus-server/install.sh", 900)
    return {"code": code, "seconds": round(time.time() - t, 1), "tail": out[-3000:]}


def last_receipt():
    """Newest run receipt in the daemon store (read-only), or None."""
    try:
        conn = sqlite3.connect(f"file:{STATE}/argus.db?mode=ro", uri=True, timeout=5)
        try:
            return conn.execute("SELECT MAX(observed_at) FROM defender_runs").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error:
        return None


def store_counts():
    """Row counts of the daemon store, read-only (S7 history kept)."""
    db = f"{STATE}/argus.db"
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        try:
            return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    for t in ("snapshots", "defender_runs")}
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return {"error": type(exc).__name__}


def baseline_digest():
    files = sorted(glob.glob(f"{STATE}/baseline*")) + sorted(glob.glob(f"{STATE}/*baseline*.json"))
    return {os.path.basename(p): sha256(p) for p in dict.fromkeys(files) if os.path.isfile(p)}


def accounts():
    return sh("getent passwd | grep -c '^argus:'", 10)[1].strip()


def first_run():
    """S2: the installed copy runs as designed."""
    AUTH["token"] = token()
    s2 = {"active": sh("systemctl is-active argus", 10)[1].strip(), "user": unit("User"),
          "api_first_answer_s": wait_live()}
    # What an outside probe sees (no credential), as release/install_test.sh checks it.
    status, body = http("/api/health", anonymous=True)
    s2["health_status"] = status
    s2["health_names_argus"] = '"ARGUS"' in body.replace(" ", "")
    s2["health_head"] = body[:300]
    code, out = sh("/usr/local/bin/argus --help", 120)
    s2["cli_ok"] = code == 0
    code, out = sh("/usr/local/bin/argus welcome server", 120)
    s2["welcome"] = {"code": code, "head": out[:600]}
    s2["python_installed"] = sh("find /opt/argus -name '*.py' -o -name '*.pyc' | head -n 3", 60)[1].strip()
    try:
        s2["verification_ok"] = json.load(open("/opt/argus/verification.json")).get("ok", True)
    except (OSError, ValueError) as exc:
        s2["verification_ok"] = f"unreadable: {type(exc).__name__}"
    s2["version"] = sh("head -c 200 /opt/argus/VERSION", 10)[1].strip()
    return s2


def idle_samples(seconds):
    samples, end = [], time.time() + seconds
    while True:
        pid = unit("MainPID")
        mem, cpu = unit("MemoryCurrent"), unit("CPUUsageNSec")
        samples.append({"t": round(time.time() - T0), "cgroup_mb": int(mem) // 1048576 if mem.isdigit() else None,
                        "rss_mb": rss_mb(pid) if pid and pid != "0" else None,
                        "cpu_s": round(int(cpu) / 1e9, 1) if cpu.isdigit() else None,
                        "load1": float(open("/proc/loadavg").read().split()[0]),
                        "avail_mb": meminfo("MemAvailable"), "restarts": unit("NRestarts"),
                        "active": unit("ActiveState")})
        if time.time() >= end:
            return samples
        time.sleep(min(SAMPLE_S, max(1, end - time.time())))


def review():
    """S5: `argus review` writes an owner-only file with a state per area and no secret."""
    out_path = "/tmp/vmtest-review.txt"
    code, out = sh(f"/usr/local/bin/argus review --days 1 --out {out_path}", 300)
    s5 = {"code": code, "out": out.strip()[-400:]}
    if code != 0 and ("invalid choice" in out or "unrecognized" in out or "usage:" in out):
        s5["available"] = False
        return s5
    s5["available"] = True
    try:
        st = os.stat(out_path)
        text = open(out_path, encoding="utf-8", errors="replace").read()
        s5.update({"mode": oct(st.st_mode & 0o777), "lines": text.count("\n"),
                   "sections": text.count("\n## "), "states": text.count("   State: "),
                   "not_an_audit": "It is not a security audit" in text,
                   "secret_value_shown": "Vmtest-Plant3d-Passw0rd" in text})
    except OSError as exc:
        s5["read_error"] = type(exc).__name__
    return s5


def boot_id():
    return open("/proc/sys/kernel/random/boot_id").read().strip()


def save():
    os.makedirs(WORK, exist_ok=True)
    with open(f"{WORK}/r.json", "w") as fh:
        json.dump({"R": R, "t0": T0}, fh)


# -- phases --------------------------------------------------------------------

def phase1():
    os_release = dict(line.rstrip().split("=", 1) for line in open("/etc/os-release") if "=" in line)
    R["guest"] = {"os": os_release.get("PRETTY_NAME", "").strip('"'), "mem_total_mb": meminfo("MemTotal"),
                  "cpus": os.cpu_count(), "kernel": os.uname().release,
                  "glibc": sh("ldd --version | head -n 1", 10)[1].strip(),
                  "systemd": sh("systemctl --version | head -n 1", 10)[1].strip(),
                  "mem_available_before_mb": meminfo("MemAvailable")}
    R["files_sha256"] = {f"{LAB}/guest.py": sha256(f"{LAB}/guest.py")}
    if CONF.get('security_probes'):
        R['files_sha256'][f'{LAB}/security_guest.py'] = sha256(f'{LAB}/security_guest.py')
    # S1 (guest half): the bytes delivered are the bytes the host verified against SHA256SUMS.
    R["S1"] = {w: {"expected": f["sha256"], "got": sha256(f["guest_path"])} for w, f in CONF["files"].items()}
    if any(v["expected"] != v["got"] for v in R["S1"].values()):
        raise RuntimeError("a package in the payload does not match its verified digest")
    sh("id vmuser >/dev/null 2>&1 || useradd -m -s /bin/bash vmuser", 30)

    if "old" in CONF["files"]:
        mark("S7: installing the older release")
        old = install("old")
        R["S7"] = {"old_install": old, "old_live_s": wait_live()}
        mark(f"S7: old release installed (exit {old['code']}); settling {SETTLE_S}s")
        time.sleep(SETTLE_S)
        R["S7"]["before"] = {"counts": store_counts(), "baseline": baseline_digest(), "accounts": accounts(),
                             "version": sh("head -c 200 /opt/argus/VERSION", 10)[1].strip()}
    mark("installing the candidate")
    R["install"] = install("candidate")
    mark(f"install exit {R['install']['code']} in {R['install']['seconds']}s")
    if "S7" in R:
        R["S7"]["after"] = {"counts": store_counts(), "baseline": baseline_digest(), "accounts": accounts(),
                            "active": sh("systemctl is-active argus", 10)[1].strip(),
                            "version": sh("head -c 200 /opt/argus/VERSION", 10)[1].strip()}
    R["S2"] = first_run()
    mark(f"S2: {R['S2']['active']} as {R['S2']['user']}, health {R['S2']['health_status']}")

    for src in glob.glob(f"{LAB}/seed/*.json"):
        os.makedirs(f"{STATE}/distrovuln", exist_ok=True)
        shutil.copy(src, f"{STATE}/distrovuln/{os.path.basename(src)}")
    sh(f"chown -R argus:argus {STATE}/distrovuln 2>/dev/null; chmod 700 {STATE}/distrovuln 2>/dev/null", 20)
    tok = token()
    AUTH["token"] = tok
    R["token_found"] = bool(tok)
    R["state_status"] = http("/api/state")[0]
    if CONF.get('security_probes'):
        from security_guest import probes
        R['security_probes'] = probes(PORT, tok)
    R["forced"] = {j: http(f"/api/run?job={j}", "POST", tok)[0]
                   for j in ("patches", "heartbeat", "distrovuln", "firewall", "backdoor", "logins")}
    if CONF.get("scenario", True):
        try:
            scenario(tok)
        except Exception as exc:  # noqa: BLE001 - report it, keep measuring
            R["scenario_error"] = f"{type(exc).__name__}: {exc}"[:500]

    mark(f"S4: idle observation for {OBSERVE_S}s")
    R["samples"] = idle_samples(OBSERVE_S)
    R["disk_state_mb"] = sh("du -sm /var/lib/argus | cut -f1", 60)[1].strip()
    R["S5"] = review()
    mark(f"S5: review {R['S5']}")
    R["S6"] = {"boot_before": boot_id(), "reboot_at": time.time()}
    with open(PHASE2_UNIT, "w") as fh:
        fh.write("[Unit]\nDescription=vmtest phase 2\nAfter=argus.service\n"
                 f"ConditionPathExists=!{WORK}/phase2.started\n\n"
                 "[Service]\nType=oneshot\n"
                 f"ExecStart=/usr/bin/python3 {LAB}/guest.py --phase 2\n"
                 "StandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\nTimeoutStartSec=infinity\n\n"
                 "[Install]\nWantedBy=multi-user.target\n")
    sh("systemctl daemon-reload && systemctl enable vmtest-phase2.service", 60)
    save()
    mark("S6: rebooting")
    sh("systemctl reboot", 30)
    time.sleep(600)            # the reboot normally ends this process first
    raise RuntimeError("the guest did not reboot")


def phase2():
    open(f"{WORK}/phase2.started", "w").close()        # never run twice, even if this crashes
    saved = json.load(open(f"{WORK}/r.json"))
    R.clear()
    R.update(saved["R"])
    mark("S6: back after reboot")
    AUTH["token"] = token()
    s6 = R["S6"]
    s6["boot_after"] = boot_id()
    s6["api_answer_s_after_boot"] = wait_live(300)
    s6["active"] = sh("systemctl is-active argus", 10)[1].strip()
    s6["restarts"] = unit("NRestarts")
    s6["health_status"] = http("/api/health")[0]
    boot_t = time.time() - float(open("/proc/uptime").read().split()[0])
    # Receipts resumed: the store's newest run receipt is from this boot (read-only), or the
    # API reports a job newer than the boot. Both are recorded; either is evidence.
    end, api_ok, db_ok = time.time() + 600, False, False
    while time.time() < end and not (api_ok or db_ok):
        status, body = http("/api/state")
        try:
            state = json.loads(body)
            api_ok = any((j.get("ts") or 0) > boot_t for j in state.get("jobs", []))
            s6["state_probe"] = {"status": status, "keys": sorted(state)[:30], "jobs": len(state.get("jobs", []))}
        except (ValueError, AttributeError):
            s6["state_probe"] = {"status": status, "head": body[:200]}
        last = last_receipt()
        db_ok = last is not None and last > boot_t
        s6["last_receipt_after_boot_s"] = round(last - boot_t, 1) if last else None
        if not (api_ok or db_ok):
            time.sleep(10)
    s6["receipts_resumed"] = api_ok or db_ok
    s6["receipts_via"] = {"api": api_ok, "store": db_ok}
    s6["live"] = http("/api/live")[1][:300]
    s6["journal_this_boot"] = sh("journalctl -b -u argus.service --no-pager -o cat | tail -n 25", 60)[1][-2500:]
    s6["tracebacks_this_boot"] = sh("journalctl -b -u argus.service --no-pager -o cat | grep -c Traceback", 60)[1].strip()

    status, body = http("/api/state")
    try:
        state = json.loads(body)
        R["jobs"] = [{"name": j["name"], "error": (j.get("error") or "")[:200], "freshness": j.get("freshness")}
                     for j in state.get("jobs", [])]
        R["totals"] = state.get("totals")
    except ValueError:
        R["state_error"] = f"{status} {body[:200]}"
    R["journal_tracebacks"] = sh("journalctl -u argus.service --no-pager -o cat | grep -c Traceback", 60)[1].strip()
    R["journal_errors"] = sh("journalctl -u argus.service -p err --no-pager -o cat | tail -n 30", 60)[1][-2500:]

    mark("S8: removing")
    if CONF["package"] == "deb":
        code, out = sh("DEBIAN_FRONTEND=noninteractive dpkg -r argus-server", 300)
    else:
        code, out = sh("/opt/argus/uninstall.sh", 300)
    R["S8"] = {"code": code, "tail": out[-1200:], "unit_gone": sh("systemctl cat argus.service", 20)[0] != 0,
               "opt_gone": not os.path.exists("/opt/argus"), "history_kept": os.path.isdir("/var/lib/argus"),
               "cli_gone": not os.path.exists("/usr/local/bin/argus")}
    mark("S9: purging")
    if CONF["package"] == "deb":
        code, out = sh("DEBIAN_FRONTEND=noninteractive dpkg -P argus-server", 300)
    else:
        code, out = sh(f"{LAB}/candidate/argus-server/uninstall.sh --purge", 300)
    R["S9"] = {"code": code, "tail": out[-800:], "state_gone": not os.path.exists("/var/lib/argus"),
               "etc_gone": not os.path.exists("/etc/argus"), "user_gone": sh("id argus", 10)[0] != 0,
               "procs_left": sh("ps -o pid= -u argus 2>/dev/null | wc -l", 10)[1].strip()}
    R["results"] = [{"ok": True}]
    mark("done")


def emit():
    raw = json.dumps(R).encode()
    b64 = base64.b64encode(raw).decode()
    print("JVLAB-DATA-BEGIN", flush=True)
    for i in range(0, len(b64), 76):
        print(b64[i:i + 76], flush=True)
    print("JVLAB-DATA-END", flush=True)
    print("JVLAB-SHA256 " + hashlib.sha256(raw).hexdigest(), flush=True)


if __name__ == "__main__":
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    phase = "2" if sys.argv[1:] == ["--phase", "2"] else "1"
    try:
        phase1() if phase == "1" else phase2()
    except Exception as exc:  # noqa: BLE001 - report, never hang or loop
        R["harness_error"] = f"phase {phase}: {type(exc).__name__}: {exc}"[:500]
        R.setdefault("results", [])
    emit()
    subprocess.run(["poweroff", "-f"])
