#!/usr/bin/env python3
"""Clean-machine matrix for the ARGUS-1 server edition, one disposable guest per cell.

    python3 release/vmtest/vmtest.py --release DIR --distro debian-12 --package tarball
            [--upgrade-from OLDDIR] [--idle 3600] [--settle 600] [--out DIR]

DIR holds a signed release as published (SHA256SUMS, SHA256SUMS.sig and the server
tarball or .deb). Plan and scenarios: docs/commercial/VM-INSTALL-MATRIX.md.

Invariants (tests/test_vmtest.py):
- Signed bytes only: SHA256SUMS must verify against a releaser key that is both in
  release/allowed_signers and pinned by the owner (ARGUS_RELEASE_SIGNERS or
  ~/.config/argus-release/trusted_signers); the package must be listed and match. The
  guest re-hashes what it installs and the host compares (S1). Anything else is refused
  before a guest starts.
- Isolation and disposal come from jarvis/lab/vmlab.py: network-less container, only
  /dev/kvm, copy-on-write overlay over a verified base image that is re-verified after
  the run; the container and run directory are removed on every path, including Ctrl-C.
- The guest reboots once (S6) inside the same container; the run timeout bounds it.
- Guest output is data: size-capped, hash-checked, and the harness file the guest ran
  must hash to the one shipped. A missing or rejected result is reported, never filled in.
- One guest at a time, refused under host pressure (vmlab.blockers); run serially.
"""

import argparse
import glob
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "release"))
import signers  # noqa: E402

from jarvis.lab import vmlab  # noqa: E402

TRUSTED = Path("~/.config/argus-release/trusted_signers").expanduser()
OUT = Path("~/.cache/argus-vmtest/results").expanduser()
PACKAGES = {"tarball": "argus-server-linux-x86_64.tar.gz", "deb": "argus-server_*_amd64.deb"}
# Footprint budget proposed in VM-INSTALL-MATRIX.md (owner may change). Idle = after the
# planted scenario, sampled each minute for the idle window.
BUDGET = {"rss_mb": 150, "cgroup_mb": 300, "cpu_s_per_h": 60, "state_mb": 50}
USER_DATA = """#cloud-config
bootcmd:
  - [ systemctl, mask, --now, serial-getty@ttyS0.service ]
runcmd:
  - [ sh, -c, "trap '' HUP; exec >/dev/ttyS0 2>&1; mkdir -p /opt/lab; tar xf /dev/disk/by-id/virtio-jvpayload -C /opt/lab; python3 /opt/lab/guest.py" ]
"""


class RefuseError(Exception):
    """The run must not start: unverified release, unknown image, missing package."""


def pinned_text():
    env = os.environ.get("ARGUS_RELEASE_SIGNERS", "")
    if env.strip():
        return env
    try:
        return TRUSTED.read_text()
    except OSError:
        return ""


def verify_release(release_dir, kind, pinned=None, allowed_text=None, verify=signers.verify):
    """{principal, file, sha256, version} for the package of `kind` in a signed release dir."""
    d = Path(release_dir)
    if kind not in PACKAGES:
        raise RefuseError(f"package must be one of {', '.join(PACKAGES)}")
    sums, sig = d / "SHA256SUMS", d / "SHA256SUMS.sig"
    if not sums.is_file():
        raise RefuseError(f"{sums} is missing")
    pins = signers.pinned_from(pinned if pinned is not None else pinned_text())
    try:
        principal, _fp = verify(sums, sig, allowed_text if allowed_text is not None else signers.ALLOWED.read_text(),
                                pins)
    except signers.SignatureError as exc:
        raise RefuseError(f"release signature: {exc}") from exc
    matches = sorted(glob.glob(str(d / PACKAGES[kind])))
    if len(matches) != 1:
        raise RefuseError(f"expected one {PACKAGES[kind]} in {d}, found {len(matches)}")
    pkg = Path(matches[0])
    listed = None
    for line in sums.read_text().splitlines():
        digest, _, name = line.partition(" ")
        if name.strip().lstrip("*") == pkg.name:
            listed = digest.strip().lower()
    if not listed:
        raise RefuseError(f"{pkg.name} is not listed in the signed SHA256SUMS")
    got = vmlab._hex(pkg)
    if got != listed:
        raise RefuseError(f"{pkg.name} does not match the signed SHA256SUMS")
    return {"principal": principal, "file": str(pkg), "name": pkg.name, "sha256": got, "dir": str(d)}


def _add(tar, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.uid, info.gid, info.mtime = len(data), mode, 0, 0, 0
    tar.addfile(info, fileobj=io.BytesIO(data))


def build_payload(run_dir, kind, candidate, old=None, idle_s=3600, settle_s=600, scenario=True, seeds=(), security=False):
    """payload.tar for the guest; returns {guest path: sha256} the guest must report."""
    files = {"candidate": candidate, **({"old": old} if old else {})}
    conf = {"package": kind, "idle_s": int(idle_s), "settle_s": int(settle_s), "scenario": bool(scenario),
            "files": {}}
    guest = (HERE / "guest.py").read_bytes()
    security_guest = (HERE / 'security_guest.py').read_bytes() if security else None
    with tarfile.open(Path(run_dir) / "payload.tar", "w", format=tarfile.PAX_FORMAT) as tar:
        _add(tar, "guest.py", guest, 0o755)
        if security_guest is not None:
            _add(tar, 'security_guest.py', security_guest)
            conf['security_probes'] = True
        for which, rel in files.items():
            ext = ".tar.gz" if kind == "tarball" else ".deb"
            name = f"{which}{ext}"
            data = Path(rel["file"]).read_bytes()
            _add(tar, name, data)
            conf["files"][which] = {"guest_path": f"/opt/lab/{name}", "sha256": rel["sha256"], "name": rel["name"]}
        for seed in seeds:
            _add(tar, f"seed/{Path(seed).name}", Path(seed).read_bytes())
        _add(tar, "config.json", json.dumps(conf).encode())
    expected = {"/opt/lab/guest.py": hashlib.sha256(guest).hexdigest()}
    if security_guest is not None:
        expected['/opt/lab/security_guest.py'] = hashlib.sha256(security_guest).hexdigest()
    return expected, conf


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def summarize(guest, report, conf, budget=BUDGET):
    """Per-scenario verdicts: True passed, False failed, None not run or not measurable. Pure."""
    g = guest or {}
    out = {"problems": list(report.get("problems", [])) + list(report.get("blocked", []))}
    if g.get("harness_error"):
        out["problems"].append(g["harness_error"])
    s1 = g.get("S1") or {}
    out["S1"] = bool(s1) and all(v.get("expected") == v.get("got") for v in s1.values()) \
        and all((conf.get("files") or {}).get(w, {}).get("sha256") == v.get("got") for w, v in s1.items()) \
        and (g.get("install") or {}).get("code") == 0
    s2 = g.get("S2") or {}
    out["S2"] = (s2.get("active") == "active" and s2.get("user") == "argus" and s2.get("health_names_argus") is True
                 and s2.get("cli_ok") is True and not s2.get("python_installed")
                 and s2.get("verification_ok") is True) if s2 else None
    sc = g.get("scenario") or {}
    out["S3"] = (sc.get("passed") == sc.get("total") and not sc.get("secret_value_in_findings")) if sc else None
    out["S3_count"] = f"{sc.get('passed')}/{sc.get('total')}" if sc else None
    samples = [s for s in g.get("samples") or [] if s.get("active") == "active"]
    fp = {}
    if len(samples) >= 2:
        span_h = (samples[-1]["t"] - samples[0]["t"]) / 3600
        rss = [s["rss_mb"] for s in samples if s.get("rss_mb") is not None]
        cg = [s["cgroup_mb"] for s in samples if s.get("cgroup_mb") is not None]
        cpu0, cpu1 = _num(samples[0].get("cpu_s")), _num(samples[-1].get("cpu_s"))
        fp = {"idle_hours": round(span_h, 2), "rss_mb_max": max(rss) if rss else None,
              "cgroup_mb_max": max(cg) if cg else None,
              "cpu_s_per_h": round((cpu1 - cpu0) / span_h, 1) if span_h > 0 and None not in (cpu0, cpu1) else None,
              "state_mb": _num(g.get("disk_state_mb")),
              "restarts": samples[-1].get("restarts")}
        checks = {"rss_mb": fp["rss_mb_max"], "cgroup_mb": fp["cgroup_mb_max"], "cpu_s_per_h": fp["cpu_s_per_h"],
                  "state_mb": fp["state_mb"]}
        fp["within_budget"] = {k: (v <= budget[k] if v is not None else None) for k, v in checks.items()}
        out["S4"] = all(v is True for v in fp["within_budget"].values()) and str(fp["restarts"]) in ("0", "None")
    else:
        out["S4"] = None
    out["footprint"] = fp
    s5 = g.get("S5") or {}
    if not s5 or s5.get("available") is False:
        out["S5"] = None
    else:
        out["S5"] = (s5.get("code") == 0 and s5.get("mode") == "0o600" and s5.get("sections", 0) > 0
                     and s5.get("sections") == s5.get("states") and s5.get("not_an_audit") is True
                     and s5.get("secret_value_shown") is False)
    s6 = g.get("S6") or {}
    out["S6"] = (s6.get("boot_after") not in (None, s6.get("boot_before")) and s6.get("active") == "active"
                 and s6.get("receipts_resumed") is True and str(s6.get("tracebacks_this_boot")) == "0") \
        if "boot_after" in s6 else None
    s7 = g.get("S7")
    if not s7:
        out["S7"] = None
    else:
        before, after = s7.get("before") or {}, s7.get("after") or {}
        kept = all(after.get("counts", {}).get(k, -1) >= v for k, v in (before.get("counts") or {}).items()
                   if isinstance(v, int))
        out["S7"] = ((s7.get("old_install") or {}).get("code") == 0 and after.get("active") == "active"
                     and after.get("accounts") == "1" and kept and after.get("baseline") == before.get("baseline")
                     and after.get("version") != before.get("version"))
    s8, s9 = g.get("S8") or {}, g.get("S9") or {}
    out["S8"] = (s8.get("code") == 0 and s8.get("unit_gone") and s8.get("opt_gone") and s8.get("cli_gone")
                 and s8.get("history_kept")) if s8 else None
    out["S9"] = (s9.get("code") == 0 and s9.get("state_gone") and s9.get("etc_gone") and s9.get("user_gone")
                 and str(s9.get("procs_left")) == "0") if s9 else None
    iso = report.get("isolation") or {}
    out["isolation_ok"] = bool(iso) and all(iso.get(k) is True for k in
                                            ("container_removed", "run_dir_removed", "base_image_unchanged"))
    out["passed"] = sorted(k for k in ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9") if out.get(k) is True)
    out["failed"] = sorted(k for k in ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9") if out.get(k) is False)
    out["not_run"] = sorted(k for k in ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9") if out.get(k) is None)
    return out


RUN_ID = __import__("re").compile(r"^[0-9a-f]{10}$")


def sweep_stale(root, runner=subprocess.run, now=None, min_age_s=3600):
    """Remove run folders a killed run left behind (host crash, power loss: no `finally`).

    Only folders named like a run id, older than min_age_s, with no container of either
    harness still present are removed. Returns the removed ids. Never touches images/."""
    runs = Path(root) / "runs"
    now = time.time() if now is None else now
    removed = []
    for d in sorted(runs.iterdir()) if runs.is_dir() else []:
        if not d.is_dir() or d.is_symlink() or not RUN_ID.match(d.name):
            continue
        if now - d.stat().st_mtime < min_age_s:
            continue
        alive = runner(["docker", "ps", "-aq", "--filter", f"name=argus-vmtest-{d.name}",
                        "--filter", f"name=jvlab-{d.name}"], capture_output=True, timeout=30)
        if alive.returncode != 0 or alive.stdout.strip():
            continue                     # unknown or still present: leave it
        shutil.rmtree(d, ignore_errors=True)
        removed.append(d.name)
    return removed


def run_cell(cfg, kind, candidate, old=None, idle_s=3600, settle_s=600, seeds=(), *, runner=subprocess.run,
             popen=subprocess.Popen, sleep=time.sleep, clock=time.monotonic, load=None,
             verify=vmlab.verify_base_image, echo=print, security=False):
    """Boot one guest for one matrix cell. Returns (guest result or None, lab report, config)."""
    report = {"started": int(time.time()), "image": cfg.image, "package": kind, "candidate": candidate["name"],
              "old": old["name"] if old else None, "problems": [], "blocked": []}
    load = load if load is not None else vmlab.pressure()
    report["host_load"] = load

    def ok(argv):
        try:
            return runner(argv, capture_output=True, timeout=30).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    stop = vmlab.blockers(cfg, load, docker_ok=ok(["docker", "version"]),
                          container_ok=ok(["docker", "image", "inspect", cfg.container_image]),
                          image_ok=verify(cfg), kvm=os.path.exists("/dev/kvm"))
    if stop:
        report["blocked"] = stop
        return None, report, None
    report["stale_runs_removed"] = sweep_stale(cfg.root, runner)
    run_id = uuid.uuid4().hex[:10]
    run_dir = Path(cfg.root) / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    name = f"argus-vmtest-{run_id}"
    data, conf = None, None
    try:
        expected, conf = build_payload(run_dir, kind, candidate, old, idle_s, settle_s, seeds=seeds, security=security)
        (run_dir / "user-data").write_text(USER_DATA)
        (run_dir / "meta-data").write_text(f"instance-id: argus-{run_id}\nlocal-hostname: argus-test\n")
        for argv in (("sh", "-c", "cd /work && xorriso -as mkisofs -quiet -o seed.iso -V cidata -J -r user-data meta-data"),
                     vmlab.overlay_argv(cfg, "12G")):
            r = runner(vmlab.helper_command(cfg, run_dir, *argv), capture_output=True, timeout=120)
            if r.returncode:
                raise vmlab.LabError("helper failed: " + r.stderr.decode("utf-8", "replace")[-300:])
        gid = cfg.kvm_gid if cfg.kvm_gid is not None else os.stat("/dev/kvm").st_gid
        proc = popen(vmlab.docker_command(cfg, run_dir, name, gid), stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
        serial, end, seen = run_dir / "serial.log", clock() + cfg.timeout_s, 0
        text = ""
        while clock() < end:
            sleep(5)
            try:
                text = serial.read_text(errors="replace")
            except OSError:
                text = ""
            lines = text.splitlines()
            for line in lines[seen:]:
                if line.startswith("[vmtest"):
                    echo(line)
            seen = len(lines)
            if vmlab.SHA + " " in text or proc.poll() is not None:
                break
        else:
            report["problems"].append(f"guest did not finish within {cfg.timeout_s}s")
        try:
            text = serial.read_text(errors="replace")
        except OSError:
            pass
        data, problems = vmlab.parse_serial(text, expected)
        report["problems"] += problems
    except vmlab.LabError as exc:
        report["problems"].append(str(exc))
    finally:
        runner(["docker", "rm", "-f", name], capture_output=True, timeout=60)
        shutil.rmtree(run_dir, ignore_errors=True)
    gone = runner(["docker", "ps", "-aq", "--filter", f"name={name}"], capture_output=True, timeout=30)
    report["isolation"] = {"container_removed": gone.returncode == 0 and not gone.stdout.strip(),
                           "run_dir_removed": not run_dir.exists(), "base_image_unchanged": bool(verify(cfg))}
    return data, report, conf


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--release", required=True, help="signed release directory (candidate)")
    ap.add_argument("--distro", default=vmlab.DEFAULT_IMAGE, choices=sorted(vmlab.IMAGES))
    ap.add_argument("--package", required=True, choices=sorted(PACKAGES))
    ap.add_argument("--upgrade-from", help="older signed release directory (S7)")
    ap.add_argument("--idle", type=int, default=3600, help="idle observation seconds (S4)")
    ap.add_argument("--settle", type=int, default=600, help="seconds the older release runs before S7")
    ap.add_argument("--guest-mb", type=int, default=1536)
    ap.add_argument("--seed", action="append", default=[], help="distrovuln index to seed (no guest network)")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args(argv)
    if not 60 <= args.idle <= 6 * 3600 or not 0 <= args.settle <= 3600:
        sys.exit("idle must be 60 s to 6 h and settle 0 to 3600 s")
    try:
        candidate = verify_release(args.release, args.package)
        old = verify_release(args.upgrade_from, args.package) if args.upgrade_from else None
    except RefuseError as exc:
        sys.exit(f"not starting: {exc}")
    if old and old["sha256"] == candidate["sha256"]:
        sys.exit("not starting: the upgrade source is the same package as the candidate")
    sys.path.insert(0, str(HERE))
    import fetch_image
    trust = fetch_image.read_trust(vmlab.ROOT, args.distro)
    # One vCPU: a small VPS, and gentle on this host (QEMU load has degraded WSL interop before).
    cfg = vmlab.Config(guest_mb=args.guest_mb, cpus=1, image=args.distro, allow_reboot=True,
                       timeout_s=args.idle + args.settle + 3600)
    data, report, conf = run_cell(cfg, args.package, candidate, old, args.idle, args.settle, seeds=args.seed,
                                  echo=lambda line: print(line, flush=True))
    report["image_trust"] = trust
    report["release"] = {"candidate": {k: candidate[k] for k in ("name", "sha256", "principal", "dir")},
                         "old": {k: old[k] for k in ("name", "sha256", "principal", "dir")} if old else None}
    summary = summarize(data, report, conf or {"files": {}}) if conf else {"problems": report["blocked"] or
                                                                            report["problems"]}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = out / f"vmtest-{args.distro}-{args.package}-{stamp}.json"
    path.write_text(json.dumps({"summary": summary, "report": report, "guest": data}, indent=1))
    print(json.dumps({"summary": summary, "written": str(path)}, indent=1))
    if data is None:
        sys.exit("no guest result")


if __name__ == "__main__":
    main()
