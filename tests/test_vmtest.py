"""Clean-machine matrix harness (release/vmtest/, jarvis/lab/vmlab.py images and reboot).

Each test names the invariant it guards (module docstrings of vmtest.py and fetch_image.py).
No guest is booted: docker and QEMU are replaced by recorders, so the cleanup and refusal
paths are exercised exactly as the real run takes them.
"""

import base64
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
sys.path.insert(0, str(ROOT / "release" / "vmtest"))

import fetch_image  # noqa: E402
import signers  # noqa: E402
import vmtest  # noqa: E402

from jarvis.lab import vmlab  # noqa: E402


def lab(tmp, image="ubuntu-24.04", **kw):
    return vmlab.Config(root=Path(tmp), image=image, **kw)


def put_image(tmp, key, data=b"image-bytes", digest=None):
    img = vmlab.IMAGES[key]
    images = Path(tmp) / "images"
    (images / img.file).parent.mkdir(parents=True, exist_ok=True)
    (images / img.file).write_bytes(data)
    d = digest or hashlib.new(img.algo, data).hexdigest()
    (images / img.sums).write_text(f"{d} *{Path(img.file).name}\n")
    return img


class Images(unittest.TestCase):
    def test_each_registered_image_verifies_with_its_own_hash(self):
        for key in vmlab.IMAGES:
            with tempfile.TemporaryDirectory() as tmp:
                put_image(tmp, key)
                self.assertTrue(vmlab.verify_base_image(lab(tmp, key)), key)

    def test_unknown_image_missing_list_and_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(vmlab.verify_base_image(lab(tmp, "debian-12")))       # nothing there
            put_image(tmp, "debian-12", digest="0" * 128)
            self.assertFalse(vmlab.verify_base_image(lab(tmp, "debian-12")))       # mismatch
            self.assertFalse(vmlab.verify_base_image(lab(tmp, "windows-11")))      # unknown name
            with self.assertRaises(vmlab.LabError):
                vmlab.overlay_argv(lab(tmp, "windows-11"))

    def test_a_sha256_list_cannot_vouch_for_a_sha512_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            img = put_image(tmp, "debian-12")
            data = (Path(tmp) / "images" / img.file).read_bytes()
            (Path(tmp) / "images" / img.sums).write_text(
                f"{hashlib.sha256(data).hexdigest()}  {Path(img.file).name}\n")
            self.assertFalse(vmlab.verify_base_image(lab(tmp, "debian-12")))

    def test_overlay_backs_onto_the_configured_image_read_only_mount(self):
        argv = vmlab.overlay_argv(lab("/x", "debian-12"), "12G")
        self.assertIn("/img/debian-12/debian-12-genericcloud-amd64-20261026-2643.qcow2", argv)
        self.assertEqual(argv[-1], "12G")

    def test_reboot_is_off_unless_asked_and_isolation_is_unchanged_when_on(self):
        off = vmlab.docker_command(lab("/x"), Path("/x/run"), "n", 993)
        on = vmlab.docker_command(lab("/x", allow_reboot=True), Path("/x/run"), "n", 993)
        self.assertIn("-no-reboot", off)
        self.assertNotIn("-no-reboot", on)
        self.assertEqual([a for a in off if a != "-no-reboot"], on)
        for flag in ("--network", "--cap-drop", "--read-only", "restrict=on"):
            self.assertTrue(any(flag in a for a in on), flag)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_for(files):
    def opener(url, timeout):
        name = url.rsplit("/", 1)[1]
        if name not in files:
            raise OSError("404")
        return FakeResponse(files[name])
    return opener


class Fetch(unittest.TestCase):
    def test_only_a_pinned_primary_fingerprint_is_trusted(self):
        pin = fetch_image.UBUNTU_CLOUD_KEY
        good = f"[GNUPG:] GOODSIG X\n[GNUPG:] VALIDSIG SUBKEY 2026-01-01 0 4 0 1 10 00 {pin}\n"
        self.assertEqual(fetch_image.valid_signer(good, [pin]), pin)
        self.assertIsNone(fetch_image.valid_signer(good.replace(pin, "A" * 40), [pin]))
        self.assertIsNone(fetch_image.valid_signer("[GNUPG:] GOODSIG X\n", [pin]))
        self.assertIsNone(fetch_image.valid_signer("[GNUPG:] BADSIG X\n", [pin]))

    def test_non_https_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(fetch_image.FetchError):
                fetch_image._get("http://example.org/x", Path(tmp) / "x", 10, opener_for({"x": b"1"}))

    def test_https_only_image_is_written_only_when_its_hash_matches_and_says_so(self):
        img = vmlab.IMAGES["debian-12"]
        name = Path(img.file).name
        data = b"debian-image"
        good = {"SHA512SUMS": f"{hashlib.sha512(data).hexdigest()}  {name}\n".encode(), name: data}
        with tempfile.TemporaryDirectory() as tmp:
            trust = fetch_image.fetch("debian-12", root=tmp, opener=opener_for(good))
            self.assertEqual(trust["trust"], "https-only")
            self.assertTrue(vmlab.verify_base_image(lab(tmp, "debian-12")))
            self.assertEqual(fetch_image.read_trust(tmp, "debian-12")["trust"], "https-only")

    def test_hash_mismatch_or_cap_leaves_no_image_and_no_part_file(self):
        img = vmlab.IMAGES["debian-12"]
        name = Path(img.file).name
        bad = {"SHA512SUMS": f"{'0' * 128}  {name}\n".encode(), name: b"tampered"}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(fetch_image.FetchError):
                fetch_image.fetch("debian-12", root=tmp, opener=opener_for(bad))
            left = [p.name for p in (Path(tmp) / "images").rglob("*")]
            self.assertFalse([n for n in left if n.endswith(".part") or n == name or n == "TRUST.json"], left)

    def test_signed_image_with_unpinned_signer_is_refused_and_nothing_written(self):
        img = vmlab.IMAGES["ubuntu-22.04"]
        name = Path(img.file).name
        data = b"jammy"
        files = {"SHA256SUMS": f"{hashlib.sha256(data).hexdigest()} *{name}\n".encode(),
                 "SHA256SUMS.gpg": b"sig", name: data}

        def gpg(argv, **kw):
            out = "[GNUPG:] VALIDSIG X 0 0 4 0 1 10 00 " + "B" * 40 + "\n" if "--verify" in argv else ""
            return SimpleNamespace(returncode=0, stdout=out, stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(fetch_image.FetchError):
                fetch_image.fetch("ubuntu-22.04", root=tmp, opener=opener_for(files), run=gpg)
            self.assertFalse((Path(tmp) / "images" / img.file).exists())

    def test_signed_image_with_pinned_signer_is_recorded_as_signature(self):
        img = vmlab.IMAGES["ubuntu-22.04"]
        name = Path(img.file).name
        data = b"jammy"
        files = {"SHA256SUMS": f"{hashlib.sha256(data).hexdigest()} *{name}\n".encode(),
                 "SHA256SUMS.gpg": b"sig", name: data}
        calls = []

        def gpg(argv, **kw):
            calls.append((argv, kw.get("env", {}).get("GNUPGHOME")))
            out = ("[GNUPG:] VALIDSIG X 0 0 4 0 1 10 00 " + fetch_image.UBUNTU_CLOUD_KEY + "\n"
                   if "--verify" in argv else "")
            return SimpleNamespace(returncode=0, stdout=out, stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            trust = fetch_image.fetch("ubuntu-22.04", root=tmp, opener=opener_for(files), run=gpg)
            self.assertEqual(trust["trust"], "signature")
            self.assertTrue(vmlab.verify_base_image(lab(tmp, "ubuntu-22.04")))
            # gpg only ever ran against the lab-only keyring
            self.assertTrue(all(home == str(Path(tmp) / "gnupg") for _a, home in calls))

    def test_existing_image_is_not_replaced_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            put_image(tmp, "debian-12")
            with self.assertRaises(fetch_image.FetchError):
                fetch_image.fetch("debian-12", root=tmp, opener=opener_for({}))


def release_dir(tmp, pkg_bytes=b"tarball", listed=None, extra_tar=False):
    d = Path(tmp) / "rel"
    d.mkdir()
    (d / "argus-server-linux-x86_64.tar.gz").write_bytes(pkg_bytes)
    digest = listed or hashlib.sha256(pkg_bytes).hexdigest()
    (d / "SHA256SUMS").write_text(f"{digest}  argus-server-linux-x86_64.tar.gz\n")
    (d / "SHA256SUMS.sig").write_text("sig")
    return d


def ok_verify(*a):
    return ("chrisnkuno", "SHA256:x")


def bad_verify(*a):
    raise signers.SignatureError("not made by a pinned releaser key")


class Release(unittest.TestCase):
    def test_signed_listed_matching_package_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = release_dir(tmp)
            got = vmtest.verify_release(d, "tarball", pinned="", allowed_text="", verify=ok_verify)
            self.assertEqual(got["sha256"], hashlib.sha256(b"tarball").hexdigest())
            self.assertEqual(got["principal"], "chrisnkuno")

    def test_unsigned_release_is_refused_before_anything_starts(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(vmtest.RefuseError):
                vmtest.verify_release(release_dir(tmp), "tarball", pinned="", allowed_text="", verify=bad_verify)

    def test_package_that_differs_from_the_signed_list_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = release_dir(tmp, listed="1" * 64)
            with self.assertRaises(vmtest.RefuseError):
                vmtest.verify_release(d, "tarball", pinned="", allowed_text="", verify=ok_verify)

    def test_missing_or_unlisted_package_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = release_dir(tmp)
            with self.assertRaises(vmtest.RefuseError):
                vmtest.verify_release(d, "deb", pinned="", allowed_text="", verify=ok_verify)
            (d / "SHA256SUMS").write_text("")
            with self.assertRaises(vmtest.RefuseError):
                vmtest.verify_release(d, "tarball", pinned="", allowed_text="", verify=ok_verify)

    def test_real_signature_check_refuses_with_no_pinned_signer(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(vmtest.RefuseError):
                vmtest.verify_release(release_dir(tmp), "tarball", pinned="", allowed_text="")


def candidate(tmp, data=b"pkg"):
    p = Path(tmp) / "argus-server-linux-x86_64.tar.gz"
    p.write_bytes(data)
    return {"file": str(p), "name": p.name, "sha256": hashlib.sha256(data).hexdigest()}


class Payload(unittest.TestCase):
    def test_payload_carries_the_harness_the_signed_bytes_and_their_digests(self):
        with tempfile.TemporaryDirectory() as tmp:
            cand = candidate(tmp)
            expected, conf = vmtest.build_payload(tmp, "tarball", cand, idle_s=120)
            with tarfile.open(Path(tmp) / "payload.tar") as tar:
                names = tar.getnames()
                guest = tar.extractfile("guest.py").read()
                packed = tar.extractfile("candidate.tar.gz").read()
                shipped = json.loads(tar.extractfile("config.json").read())
            self.assertEqual(sorted(names), ["candidate.tar.gz", "config.json", "guest.py"])
            self.assertEqual(packed, b"pkg")
            self.assertEqual(shipped["files"]["candidate"]["sha256"], cand["sha256"])
            self.assertEqual(expected, {"/opt/lab/guest.py": hashlib.sha256(guest).hexdigest()})
            self.assertEqual(conf, shipped)

    def test_guest_never_runs_phase_two_twice_and_never_hangs(self):
        src = (ROOT / "release" / "vmtest" / "guest.py").read_text()
        compile(src, "guest.py", "exec")
        self.assertIn("ConditionPathExists=!", src)
        # the marker is written before any other phase-two work
        body = src[src.index("def phase2():"):]
        self.assertLess(body.index("phase2.started"), body.index("json.load"))
        self.assertIn('subprocess.run(["poweroff", "-f"])', src)
        self.assertNotIn("ubuntu@", src)      # distro-neutral login user


def good_guest(conf, **over):
    g = {
        "S1": {"candidate": {"expected": conf["files"]["candidate"]["sha256"],
                             "got": conf["files"]["candidate"]["sha256"]}},
        "install": {"code": 0},
        "S2": {"active": "active", "user": "argus", "health_names_argus": True, "cli_ok": True,
               "python_installed": "", "verification_ok": True},
        "scenario": {"passed": 16, "total": 16, "secret_value_in_findings": False},
        "samples": [{"t": 0, "active": "active", "rss_mb": 70, "cgroup_mb": 170, "cpu_s": 100.0, "restarts": "0"},
                    {"t": 3600, "active": "active", "rss_mb": 80, "cgroup_mb": 180, "cpu_s": 130.0, "restarts": "0"}],
        "disk_state_mb": "6",
        "S5": {"available": True, "code": 0, "mode": "0o600", "sections": 15, "states": 15, "not_an_audit": True,
               "secret_value_shown": False},
        "S6": {"boot_before": "a", "boot_after": "b", "active": "active", "receipts_resumed": True,
               "tracebacks_this_boot": "0"},
        "S8": {"code": 0, "unit_gone": True, "opt_gone": True, "cli_gone": True, "history_kept": True},
        "S9": {"code": 0, "state_gone": True, "etc_gone": True, "user_gone": True, "procs_left": "0"},
    }
    g.update(over)
    return g


ISO = {"isolation": {"container_removed": True, "run_dir_removed": True, "base_image_unchanged": True}}


class Summary(unittest.TestCase):
    conf = {"files": {"candidate": {"sha256": "c" * 64}}}

    def test_a_clean_run_passes_every_scenario_it_ran(self):
        s = vmtest.summarize(good_guest(self.conf), ISO, self.conf)
        self.assertEqual(s["passed"], ["S1", "S2", "S3", "S4", "S5", "S6", "S8", "S9"])
        self.assertEqual(s["not_run"], ["S7"])
        self.assertEqual(s["footprint"]["cpu_s_per_h"], 30.0)
        self.assertTrue(s["isolation_ok"])

    def test_bytes_that_differ_from_the_signed_digest_fail_s1(self):
        g = good_guest(self.conf, S1={"candidate": {"expected": "c" * 64, "got": "d" * 64}})
        self.assertFalse(vmtest.summarize(g, ISO, self.conf)["S1"])

    def test_over_budget_footprint_fails_s4_and_names_the_metric(self):
        g = good_guest(self.conf)
        g["samples"][-1]["rss_mb"] = 400
        s = vmtest.summarize(g, ISO, self.conf)
        self.assertFalse(s["S4"])
        self.assertFalse(s["footprint"]["within_budget"]["rss_mb"])

    def test_too_few_samples_is_not_measured_not_passed(self):
        g = good_guest(self.conf, samples=[{"t": 0, "active": "active"}])
        self.assertIsNone(vmtest.summarize(g, ISO, self.conf)["S4"])

    def test_release_without_review_is_not_run_and_a_leak_fails(self):
        self.assertIsNone(vmtest.summarize(good_guest(self.conf, S5={"available": False}), ISO, self.conf)["S5"])
        leak = good_guest(self.conf)
        leak["S5"]["secret_value_shown"] = True
        self.assertFalse(vmtest.summarize(leak, ISO, self.conf)["S5"])

    def test_no_reboot_or_no_resumed_receipts_fails_s6(self):
        same = good_guest(self.conf)
        same["S6"]["boot_after"] = "a"
        self.assertFalse(vmtest.summarize(same, ISO, self.conf)["S6"])
        stuck = good_guest(self.conf)
        stuck["S6"]["receipts_resumed"] = False
        self.assertFalse(vmtest.summarize(stuck, ISO, self.conf)["S6"])

    def test_upgrade_that_loses_history_or_duplicates_the_account_fails_s7(self):
        s7 = {"old_install": {"code": 0},
              "before": {"counts": {"snapshots": 40, "defender_runs": 90}, "baseline": {"b": "1"}, "version": "1"},
              "after": {"counts": {"snapshots": 41, "defender_runs": 95}, "baseline": {"b": "1"}, "version": "2",
                        "active": "active", "accounts": "1"}}
        self.assertTrue(vmtest.summarize(good_guest(self.conf, S7=s7), ISO, self.conf)["S7"])
        lost = json.loads(json.dumps(s7))
        lost["after"]["counts"]["defender_runs"] = 3
        self.assertFalse(vmtest.summarize(good_guest(self.conf, S7=lost), ISO, self.conf)["S7"])
        dup = json.loads(json.dumps(s7))
        dup["after"]["accounts"] = "2"
        self.assertFalse(vmtest.summarize(good_guest(self.conf, S7=dup), ISO, self.conf)["S7"])

    def test_purge_that_leaves_the_account_fails_s9(self):
        g = good_guest(self.conf)
        g["S9"]["user_gone"] = False
        self.assertFalse(vmtest.summarize(g, ISO, self.conf)["S9"])

    def test_no_guest_result_claims_nothing(self):
        s = vmtest.summarize(None, {"problems": ["guest did not finish"]}, self.conf)
        self.assertEqual(s["passed"], [])
        self.assertIn("guest did not finish", s["problems"])
        self.assertFalse(s["isolation_ok"])


def serial_for(data):
    raw = json.dumps(data).encode()
    b64 = base64.b64encode(raw).decode()
    return f"[vmtest   1.0s] hello\nJVLAB-DATA-BEGIN\n{b64}\nJVLAB-DATA-END\nJVLAB-SHA256 {hashlib.sha256(raw).hexdigest()}\n"


class Recorder:
    """Stands in for docker: helpers succeed, the guest writes `serial` to the run dir."""

    def __init__(self, serial=None, helper_rc=0, raise_in_wait=None):
        self.calls, self.serial, self.helper_rc, self.raise_in_wait = [], serial, helper_rc, raise_in_wait
        self.run_dir = None

    def runner(self, argv, **kw):
        self.calls.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            self.run_dir = Path(next(a for a in argv if a.endswith(":/work")).split(":")[0])
            return SimpleNamespace(returncode=self.helper_rc, stdout=b"", stderr=b"helper broke")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    def popen(self, argv, **kw):
        self.calls.append(list(argv))
        if self.serial is not None:
            (self.run_dir / "serial.log").write_text(self.serial)
        return SimpleNamespace(poll=lambda: 0 if self.serial is not None else None)

    def sleep(self, s):
        if self.raise_in_wait:
            raise self.raise_in_wait


IDLE = {"cpu_avg60": 1.0, "mem_avail_mb": 9000, "free_gb": 100.0}


class RunCell(unittest.TestCase):
    def cell(self, tmp, rec, **kw):
        cfg = lab(tmp, kvm_gid=993, timeout_s=kw.pop("timeout_s", 60), allow_reboot=True)
        with unittest.mock.patch("os.path.exists", return_value=True):
            return vmtest.run_cell(cfg, "tarball", candidate(tmp), idle_s=60, runner=rec.runner, popen=rec.popen,
                                   sleep=rec.sleep, clock=kw.pop("clock", iter(range(0, 10**6, 10)).__next__),
                                   load=IDLE, verify=lambda c: True, echo=lambda line: None, **kw)

    def test_blocked_host_starts_nothing_and_says_why(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder()
            cfg = lab(tmp)
            data, report, conf = vmtest.run_cell(cfg, "tarball", candidate(tmp), runner=rec.runner,
                                                 popen=rec.popen, load={"cpu_avg60": 95, "mem_avail_mb": 100},
                                                 verify=lambda c: True)
            self.assertIsNone(data)
            self.assertTrue(report["blocked"])
            self.assertFalse([c for c in rec.calls if c[:2] == ["docker", "run"]])

    def test_successful_cell_returns_the_hash_checked_result_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            guest_sha = hashlib.sha256((ROOT / "release" / "vmtest" / "guest.py").read_bytes()).hexdigest()
            rec = Recorder(serial_for({"results": [{"ok": True}], "files_sha256": {"/opt/lab/guest.py": guest_sha}}))
            data, report, conf = self.cell(tmp, rec)
            self.assertEqual(data["results"], [{"ok": True}])
            self.assertEqual(report["problems"], [])
            self.assertTrue(all(report["isolation"].values()))
            self.assertIn(["docker", "rm", "-f", next(c for c in rec.calls if "--name" in c)[4]], rec.calls)
            self.assertFalse(list((Path(tmp) / "runs").iterdir()))
            self.assertNotIn("-no-reboot", next(c for c in rec.calls if "--name" in c))

    def test_guest_running_other_code_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder(serial_for({"results": [], "files_sha256": {"/opt/lab/guest.py": "0" * 64}}))
            _data, report, _conf = self.cell(tmp, rec)
            self.assertIn("guest ran code that differs from the code under test", report["problems"])

    def test_helper_failure_still_removes_container_and_run_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder(helper_rc=1)
            data, report, _conf = self.cell(tmp, rec)
            self.assertIsNone(data)
            self.assertTrue(any("helper failed" in p for p in report["problems"]))
            self.assertTrue(any(c[:3] == ["docker", "rm", "-f"] for c in rec.calls))
            self.assertFalse(list((Path(tmp) / "runs").iterdir()))

    def test_guest_that_never_finishes_is_reported_not_filled_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder(serial=None)
            data, report, _conf = self.cell(tmp, rec, timeout_s=30)
            self.assertIsNone(data)
            self.assertTrue(any("did not finish" in p for p in report["problems"]))

    def test_interrupted_run_still_removes_container_and_run_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder(serial=None, raise_in_wait=KeyboardInterrupt())
            with self.assertRaises(KeyboardInterrupt):
                self.cell(tmp, rec)
            self.assertTrue(any(c[:3] == ["docker", "rm", "-f"] for c in rec.calls))
            self.assertFalse(list((Path(tmp) / "runs").iterdir()))


class Sweep(unittest.TestCase):
    def test_only_old_orphaned_run_folders_are_removed(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp) / "runs"
            for name in ("aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc", "not-a-run"):
                (runs / name).mkdir(parents=True)
            (Path(tmp) / "images").mkdir()
            for name in ("aaaaaaaaaa", "bbbbbbbbbb", "not-a-run"):
                os.utime(runs / name, (1000, 1000))           # old
            def docker(argv, **kw):
                live = any("bbbbbbbbbb" in a for a in argv)  # b's container still exists
                return SimpleNamespace(returncode=0, stdout=b"id\n" if live else b"", stderr=b"")
            removed = vmtest.sweep_stale(tmp, docker, now=1000 + 7200)
            self.assertEqual(removed, ["aaaaaaaaaa"])
            self.assertEqual(sorted(p.name for p in runs.iterdir()), ["bbbbbbbbbb", "cccccccccc", "not-a-run"])
            self.assertTrue((Path(tmp) / "images").is_dir())

    def test_unknown_docker_state_keeps_the_folder(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "runs" / "aaaaaaaaaa").mkdir(parents=True)
            os.utime(Path(tmp) / "runs" / "aaaaaaaaaa", (1000, 1000))
            broken = lambda argv, **kw: SimpleNamespace(returncode=1, stdout=b"", stderr=b"")  # noqa: E731
            self.assertEqual(vmtest.sweep_stale(tmp, broken, now=99999), [])


class Cli(unittest.TestCase):
    def test_bounds_and_unsigned_release_stop_before_any_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = release_dir(tmp)
            for argv in (["--release", str(d), "--package", "tarball", "--idle", "5"],
                         ["--release", str(d), "--package", "tarball"]):
                with unittest.mock.patch.dict("os.environ", {"ARGUS_RELEASE_SIGNERS": "none"}), \
                        unittest.mock.patch.object(vmtest, "run_cell") as run, \
                        self.assertRaises(SystemExit):
                    vmtest.main(argv)
                run.assert_not_called()


import unittest.mock  # noqa: E402

if __name__ == "__main__":
    unittest.main()
