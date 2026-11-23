"""The native Windows edition: compiled payloads, per-user install, build and Setup.

Invariants (docs/architecture/WINDOWS-EDITION.md):
- The download carries no .ps1/.py: payloads are compiled in, the gate refuses
  any script or source file, home or build paths, and anything not allowed.
- The compiled copy of a payload wins over a file of the same name; a payload
  the edition lacks still throws (never an empty clean result); files that a
  task or the broker runs are written byte for byte, atomically, into a folder
  named by the payload set, and an unwritable profile never stops an import.
- The control audit fingerprints the compiled copy, so the installed
  supervisor is not reported as changed.
- `native` refuses off Windows, keeps its port on reinstall, never shares a
  port, refuses beside another JARVIS install, keeps a valid desktop token,
  writes a new one owner-only, and uninstall revokes only its own client.
- The Setup is built only from inputs whose commit, version and digests match
  their build records, and gated like every other download.
"""

import hashlib
import importlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))

import build_setup  # noqa: E402
import build_windows  # noqa: E402
import gate  # noqa: E402

from jarvis.cli.commands import native  # noqa: E402
from jarvis.core import paths  # noqa: E402
from jarvis.platform.provenance import persistence  # noqa: E402

PAYLOAD = b"\xef\xbb\xbf# compiled\r\nWrite-Output 'compiled'\r\n"


class Compiled:
    """Install a fake compiled payload module for the duration of a test."""

    def __init__(self, scripts, digest="d" * 64):
        self.mod = types.ModuleType(paths.PAYLOAD_MODULE)
        self.mod.SCRIPTS, self.mod.DIGEST = scripts, digest

    def __enter__(self):
        sys.modules[paths.PAYLOAD_MODULE] = self.mod
        return self.mod

    def __exit__(self, *exc):
        sys.modules.pop(paths.PAYLOAD_MODULE, None)


class PayloadSeam(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="payload-home-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        patcher = mock.patch.dict(os.environ, {"HOME": str(self.home), "LOCALAPPDATA": str(self.home / "L")})
        patcher.start()
        self.addCleanup(patcher.stop)
        sys.modules.pop(paths.PAYLOAD_MODULE, None)

    def test_source_tree_reads_the_file_and_names_absence(self):
        self.assertIsNone(paths._embedded()[0])
        real = paths.load_win_script("startup.ps1")
        self.assertEqual(real, (paths.WIN_SCRIPTS_DIR / "startup.ps1").read_text(encoding="utf-8", errors="replace"))
        self.assertTrue(paths.load_win_script("no-such.ps1").startswith('throw "no-such.ps1 is not part'))
        self.assertEqual(paths.win_script("startup.ps1"), paths.WIN_SCRIPTS_DIR / "startup.ps1")

    def test_compiled_copy_wins_over_a_planted_file(self):
        # startup.ps1 exists as a file in this tree: the compiled bytes must win.
        with Compiled({"startup.ps1": PAYLOAD}):
            self.assertEqual(paths.load_win_script("startup.ps1"), PAYLOAD.decode("utf-8"))
            # A name the edition lacks throws even though a file of that name exists.
            self.assertTrue(paths.load_win_script("asep.ps1").startswith('throw "asep.ps1 is not part'))

    def test_written_out_byte_for_byte_once_and_repaired(self):
        with Compiled({"inputhook.ps1": PAYLOAD}, digest="a" * 64):
            p = paths.win_script("inputhook.ps1")
            self.assertEqual(p.read_bytes(), PAYLOAD)
            self.assertIn("a" * 16, str(p))
            ino = p.stat().st_ino
            self.assertEqual(paths.win_script("inputhook.ps1").stat().st_ino, ino)  # not rewritten
            p.write_bytes(b"tampered")
            self.assertEqual(paths.win_script("inputhook.ps1").read_bytes(), PAYLOAD)
            self.assertEqual([x.name for x in p.parent.iterdir()], ["inputhook.ps1"])  # no temp left
        with Compiled({"inputhook.ps1": PAYLOAD}, digest="b" * 64):
            self.assertNotEqual(paths.win_script("inputhook.ps1").parent, p.parent)

    def test_unwritable_profile_does_not_raise(self):
        with Compiled({"memscan.ps1": PAYLOAD}, digest="c" * 64):
            root = paths.payload_root("c" * 64)
            root.parent.mkdir(parents=True)
            root.write_text("a file where the folder should be")
            p = paths.win_script("memscan.ps1")
            self.assertEqual(p, root / "memscan.ps1")
            self.assertFalse(p.exists())

    def test_control_audit_fingerprints_the_compiled_copy(self):
        task = next(t for t in persistence.MANAGED_TASKS if t.name == "jarvis native service")
        missing_root = self.home / "no-checkout"
        with Compiled({"jarvis-native-service.ps1": PAYLOAD}):
            got = persistence.expected_hash(task, missing_root)
            want = persistence.normalized_text_hash(str(paths.win_script("jarvis-native-service.ps1")))
            self.assertEqual(got, want)
        # Source tree: the file in the code root, as before.
        self.assertEqual(persistence.expected_hash(task, ROOT),
                         persistence.normalized_text_hash(str(ROOT / "jarvis-native-service.ps1")))


class ProgramPath(unittest.TestCase):
    """Run 41646681752: the compiled engine registered <dist>\\python.exe (Nuitka's
    sys.executable), a file that does not exist, as the service program."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="dist-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        (self.d / "argus-instinct.exe").write_bytes(b"MZ")
        self.fake_python = str(self.d / "python.exe")          # does not exist

    def test_source_tree_uses_the_interpreter(self):
        self.assertEqual(paths.program(compiled=False, executable="/usr/bin/python3"), "/usr/bin/python3")

    def test_compiled_uses_the_program_it_was_started_as(self):
        exe = str(self.d / "argus-instinct.exe")
        self.assertEqual(paths.program(compiled=True, argv0=exe, executable=self.fake_python), exe)
        # Started without the extension (from a shell): the .exe is still found.
        self.assertEqual(paths.program(compiled=True, argv0=exe[:-4], executable=self.fake_python), exe)

    def test_compiled_falls_back_to_the_one_program_beside_it(self):
        got = paths.program(compiled=True, argv0="argus-instinct-renamed", executable=self.fake_python)
        self.assertEqual(got, str(self.d / "argus-instinct.exe"))
        self.assertNotEqual(got, self.fake_python)

    def test_children_and_the_service_use_it(self):
        import inspect

        from jarvis.collectors.host import fridaydefender
        from jarvis.core import rulepack
        from jarvis.service import scheduler
        for mod in (scheduler, rulepack, fridaydefender, native):
            src = inspect.getsource(mod)
            self.assertNotRegex(src, r"\[sys\.executable, \"-m\"", mod.__name__)
            self.assertIn("self_executable()", src, mod.__name__)


class CliExitCode(unittest.TestCase):
    def test_a_commands_integer_result_is_the_exit_code(self):
        from jarvis.cli import parser
        home = tempfile.mkdtemp(prefix="cli-home-")
        self.addCleanup(shutil.rmtree, home, True)
        with mock.patch.dict(os.environ, {"HOME": home}), mock.patch.object(native.host, "KIND", "linux"), \
                mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(parser.main(["--db", f"{home}/t.db", "native", "install"]), 2)
        for result, code in ((None, 0), (True, 0), (1, 1), (3, 3)):
            with self.subTest(result=result), \
                    mock.patch.dict(os.environ, {"HOME": home}), \
                    mock.patch.object(native, "cmd_status", return_value=result):
                self.assertEqual(parser.main(["--db", f"{home}/t.db", "native", "status"]), code)


class NativeCli(unittest.TestCase):
    def test_refuses_off_windows_without_running_anything(self):
        with mock.patch.object(native.host, "KIND", "linux"), \
             mock.patch.object(native, "_run_service_script", side_effect=AssertionError("ran")):
            for fn in (native.cmd_install, native.cmd_status, native.cmd_stop, native.cmd_uninstall):
                self.assertEqual(fn(mock.Mock(port=0, no_desktop=False, all=False), None), 2)

    def test_port_choice(self):
        free = {8787: False, 8788: True}.get
        self.assertEqual(native.choose_port(0, 8790, free=lambda p: False), (8790, ""))  # reinstall keeps it
        port, note = native.choose_port(0, 0, free=lambda p: free(p, True))
        self.assertEqual(port, 8788)
        self.assertIn("8787 is in use", note)
        self.assertEqual(native.choose_port(0, 0, free=lambda p: True), (8787, ""))
        with self.assertRaises(ValueError):
            native.choose_port(9000, 0, free=lambda p: False)
        with self.assertRaises(ValueError):
            native.choose_port(0, 0, free=lambda p: False)

    def test_refuses_beside_another_install(self):
        ours = {"service": native.SERVICE_NAME, "live": True}
        self.assertEqual(native.other_install(0, probe=lambda p: ours), native.DEFAULT_PORT)
        self.assertEqual(native.other_install(8787, probe=lambda p: ours), 0)  # our own reinstall
        self.assertEqual(native.other_install(0, probe=lambda p: {"service": "other"}), 0)
        self.assertEqual(native.other_install(0, probe=lambda p: None), 0)
        root = tempfile.mkdtemp(prefix="svc-")
        self.addCleanup(shutil.rmtree, root, True)
        with mock.patch.object(native.host, "KIND", "windows"), \
             mock.patch.object(native, "state_root", return_value=root), \
             mock.patch.object(native, "_service_config", return_value={}), \
             mock.patch.object(native, "_health", return_value=ours), \
             mock.patch.object(native, "_run_service_script", side_effect=AssertionError("ran")), \
             mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(native.cmd_install(mock.Mock(port=0, no_desktop=False), None), 3)

    def test_install_keeps_a_transcript_even_without_a_console(self):
        # The Setup's silent install runs the engine with no console: stdout can be
        # None. What install printed must still be in install.log.
        root = tempfile.mkdtemp(prefix="svc-")
        self.addCleanup(shutil.rmtree, root, True)
        with mock.patch.object(native.host, "KIND", "windows"), \
             mock.patch.object(native, "state_root", return_value=root), \
             mock.patch.object(native, "_service_config", return_value={}), \
             mock.patch.object(native, "_health", return_value=None), \
             mock.patch.object(native, "choose_port", return_value=(8787, "")), \
             mock.patch.object(native, "_run_service_script", return_value=(1, "task refused: reason X")), \
             mock.patch("sys.stdout", None), mock.patch("sys.stderr", None):
            self.assertEqual(native.cmd_install(mock.Mock(port=0, no_desktop=False), None), 1)
            self.assertIsNone(sys.stdout)   # restored
        log = Path(root, native.INSTALL_LOG).read_text(encoding="utf-8")
        self.assertIn("task refused: reason X", log)
        self.assertIn("could not be registered", log)

    def test_wait_healthy_retries_then_gives_up(self):
        answers = iter([None, {"live": False}, {"live": True}])
        self.assertEqual(native.wait_healthy(1, wait=100, sleep=lambda s: None, probe=lambda p: next(answers)),
                         {"live": True})
        clock = iter([0, 0, 50, 200])
        with mock.patch.object(native.time, "monotonic", lambda: next(clock)):
            self.assertIsNone(native.wait_healthy(1, wait=100, sleep=lambda s: None, probe=lambda p: None))

    def test_desktop_pairing_keeps_a_valid_token_and_writes_new_ones_privately(self):
        from jarvis.web import clients
        d = Path(tempfile.mkdtemp(prefix="app-"))
        self.addCleanup(shutil.rmtree, d, True)
        token = "jc1_" + "a" * 12 + "_" + "B" * 43
        store = mock.Mock()
        with mock.patch.object(clients, "pair", return_value=("a" * 12, token)) as pair:
            self.assertEqual(native.pair_desktop(store, str(d), 8790), "paired")
            pair.assert_called_once_with(store, native.DESKTOP_CLIENT_NAME)
            self.assertEqual((d / "client.token").read_text(), token)
            self.assertEqual((d / "port").read_text(), "8790\n")
            if hasattr(os, "geteuid"):
                self.assertEqual((d / "client.token").stat().st_mode & 0o077, 0)
            self.assertEqual(native.pair_desktop(store, str(d), 8787), "kept")
            self.assertEqual(pair.call_count, 1)
        self.assertEqual(native.pair_desktop(None, str(d / "new"), 8787), "no store to pair the desktop app")

    def test_desktop_pairing_against_the_real_client_table(self):
        # The mocked test above passed while the real pairing refused the name
        # (run 41670149691: "desktop (this computer)" has parentheses).
        from jarvis.core.store import Store
        from jarvis.web import clients
        d = Path(tempfile.mkdtemp(prefix="app-"))
        self.addCleanup(shutil.rmtree, d, True)
        store = Store(str(d / "t.db"))
        self.addCleanup(store.close)
        self.assertEqual(native.pair_desktop(store, str(d / "app"), 8787), "paired")
        token = (d / "app" / "client.token").read_text()
        self.assertTrue(clients.looks_like(token))
        self.assertEqual(native.unpair_desktop(store, str(d / "app")), 1)

    def test_uninstall_revokes_only_its_own_client(self):
        from jarvis.web import clients
        d = Path(tempfile.mkdtemp(prefix="app-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "client.token").write_text("x")
        (d / "port").write_text("8787\n")
        rows = [{"id": "1", "name": native.DESKTOP_CLIENT_NAME},
                {"id": "2", "name": "cli"},
                {"id": "3", "name": native.DESKTOP_CLIENT_NAME, "revoked_at": 5}]
        with mock.patch.object(clients, "listing", return_value=rows), \
             mock.patch.object(clients, "revoke", return_value=True) as revoke:
            self.assertEqual(native.unpair_desktop(mock.Mock(), str(d)), 1)
        self.assertEqual([c.args[1] for c in revoke.call_args_list], ["1"])
        self.assertEqual(list(d.iterdir()), [])


def fake_dist(root, extra=()):
    dist = Path(root) / "dist"
    (dist / "argus" / "web" / "static").mkdir(parents=True)
    (dist / build_windows.EXE).write_bytes(b"MZ engine")
    (dist / "python312.dll").write_bytes(b"MZ dll")
    (dist / "argus" / "web" / "static" / "index.html").write_bytes(b"<html></html>")
    for rel, data in extra:
        (dist / rel).parent.mkdir(parents=True, exist_ok=True)
        (dist / rel).write_bytes(data)
    return dist


class WindowsBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="winbuild-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.policy = gate.load_policy()

    def test_file_version(self):
        self.assertEqual(build_windows.file_version("2026.11.03-2"), "2026.11.3.2")
        self.assertEqual(build_windows.file_version("2026.11.03"), "2026.11.3.0")
        with self.assertRaises(ValueError):
            build_windows.file_version("v2026.11.03")

    def _tree(self):
        tree = self.tmp / "tree"
        (tree / "argus" / "platform" / "win").mkdir(parents=True)
        (tree / "argus" / "core").mkdir(parents=True)
        (tree / "argus" / "platform" / "win" / "a.ps1").write_bytes(PAYLOAD)
        (tree / "argus" / "platform" / "win" / "b.ps1").write_bytes(b"b\n")
        (tree / "argus-native-service.ps1").write_bytes(b"loop\r\n")
        return tree

    def test_payload_module_is_exact_and_stable(self):
        tree = self._tree()
        names, digest = build_windows.payload_module(tree)
        self.assertEqual(names, ["a.ps1", "argus-native-service.ps1", "b.ps1"])
        ns = {}
        exec((tree / "argus" / "core" / "_payloads.py").read_text(encoding="utf-8"), ns)
        self.assertEqual(ns["SCRIPTS"]["a.ps1"], PAYLOAD)
        self.assertEqual(ns["DIGEST"], digest)
        self.assertEqual(build_windows.payload_module(tree)[1], digest)
        (tree / "argus" / "platform" / "win" / "b.ps1").write_bytes(b"changed\n")
        self.assertNotEqual(build_windows.payload_module(tree)[1], digest)

    def test_payload_module_refuses_a_duplicate_name(self):
        tree = self._tree()
        (tree / "argus" / "platform" / "win" / "argus-native-service.ps1").write_bytes(b"x")
        with self.assertRaises(SystemExit):
            build_windows.payload_module(tree)

    def _zip(self, extra=()):
        out = self.tmp / "out"
        out.mkdir(exist_ok=True)
        dist = fake_dist(self.tmp / f"d{len(list(self.tmp.iterdir()))}", extra)
        name = build_windows.build_zip(build_windows.entries(dist, "2026.11.03-0", "abc"), out)
        return out / name

    def _gate(self, path):
        return gate.check_artifact(path, gate.rule_for(path.name, self.policy), self.policy)[0]

    def test_clean_engine_zip_passes(self):
        self.assertEqual(self._gate(self._zip()), [])

    def test_gate_refuses_scripts_source_paths_and_strays(self):
        for extra, why in [
            ((("argus/platform/win/startup.ps1", b"x"),), "ps1"),
            ((("argus/core/paths.py", b"x"),), "py"),
            ((("python312.dll", b"MZ C:\\Users\\runneradmin\\AppData\\x"),), "home path"),
            ((("vcruntime.dll", b"MZ D:\\a\\Argus-1\\Argus-1\\x"),), "workspace path"),
            ((("notes.txt", b"x"),), "stray"),
        ]:
            with self.subTest(why):
                self.assertTrue(self._gate(self._zip(extra)), f"{why} was not refused")

    def test_upstream_build_paths_pass_only_in_their_own_files(self):
        ok = [("python312.dll", b"MZ pdb D:\\a\\1\\b\\bin\\amd64\\python312.pdb"),
              ("libssl-3.dll", b"MZ C:\\A\\_work\\1\\s\\ssl"),
              ("cryptography/hazmat/bindings/_rust.pyd",
               b"MZ D:\\a\\cryptography\\x C:\\Users\\runneradmin\\.cargo\\x")]
        self.assertEqual(self._gate(self._zip(ok)), [])
        refused = [
            ((("python312.dll", b"MZ D:\\a\\1\\ then D:\\a\\Argus-1\\Argus-1\\x"),), "our path after an exempt one"),
            ((("argus-instinct.exe", b"MZ D:\\a\\1\\x"),), "exempt text in our own program"),
            ((("python312.dll", b"MZ C:\\Users\\runneradmin\\x"),), "exempt text in the wrong file"),
            ((("libssl-3.dll", b"MZ D:\\a\\1\\x"),), "another file's exempt text"),
        ]
        for extra, why in refused:
            with self.subTest(why):
                self.assertTrue(self._gate(self._zip(extra)), f"{why} was not refused")

    def test_a_zip_signature_constant_is_not_an_archive_but_a_real_one_is(self):
        def header(name):
            return b"PK\x01\x02" + b"\x00" * 24 + len(name).to_bytes(2, "little") + b"\x00" * 16 + name
        constant = ("python312.dll", b"MZ zipimport" + header(b"\x00\x00\x00z\x19bad local header") + b"tail")
        self.assertEqual(self._gate(self._zip([constant])), [])
        # A lone directory header is not an archive (detection is structural since
        # the windows-installer merge); a real zip appended to a binary is.
        lone = ("python312.dll", b"MZ" + header(b"argus/core/main.pyc") + b"tail")
        self.assertEqual(self._gate(self._zip([lone])), [])
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as inner:
            inner.writestr("argus/core/main.pyc", b"\x00" * 16)
        planted = ("python312.dll", b"MZ" + b"\x00" * 64 + buf.getvalue())
        self.assertTrue(any("embedded archive member" in p for p in self._gate(self._zip([planted]))))

    def test_setup_stage_refuses_members_outside_the_top_folder(self):
        for bad in ("../evil.exe", "other/x.dll", "/abs.dll"):
            z = self.tmp / f"bad{abs(hash(bad))}.zip"
            with zipfile.ZipFile(z, "w") as f:
                f.writestr(bad, b"x")
            with self.subTest(bad), self.assertRaises(SystemExit):
                build_setup.stage(z, self.tmp / "nope.exe", self.tmp / "s")

    def _inputs(self, engine_commit="abc", desktop_commit="abc", tamper=False):
        eng, desk = self.tmp / "engine", self.tmp / "desktop"
        for d in (eng, desk):
            shutil.rmtree(d, ignore_errors=True)
            d.mkdir()
        z = self._zip()
        shutil.copy(z, eng / z.name)
        d = hashlib.sha256(z.read_bytes()).hexdigest()
        (eng / "windows-build.json").write_text(json.dumps(
            {"version": "2026.11.03-0", "commit": engine_commit, "files": {z.name: {"sha256": d}}}))
        exe = desk / build_setup.DESKTOP_EXE
        exe.write_bytes(b"MZ desktop")
        dd = hashlib.sha256(b"MZ desktop").hexdigest()
        (desk / "desktop-windows-build.json").write_text(json.dumps(
            {"version": "2026.11.03-0", "commit": desktop_commit, "files": {exe.name: {"sha256": dd}}}))
        if tamper:
            exe.write_bytes(b"MZ swapped")
        return eng, desk

    def _setup(self, eng, desk, makensis="false"):
        argv = ["build_setup.py", "--engine", str(eng), "--desktop", str(desk), "--version", "2026.11.03-0",
                "--out", str(self.tmp / "setup"), "--makensis", makensis]
        with mock.patch.object(sys, "argv", argv):
            build_setup.main()

    def test_setup_refuses_mismatched_or_changed_inputs(self):
        for kw in ({"desktop_commit": "def"}, {"tamper": True}):
            with self.subTest(kw), self.assertRaises(SystemExit):
                self._setup(*self._inputs(**kw))

    @unittest.skipUnless(
        (Path.home() / ".cache/argus-tools/nsis/root/usr/bin/makensis").is_file()
        and (shutil.which("7z") or (Path.home() / ".cache/argus-tools/7zip/root/usr/lib/7zip/7z").is_file()),
        "makensis and 7z are needed for the real Setup build")
    def test_real_setup_build_passes_the_gate(self):
        nsis = Path.home() / ".cache/argus-tools/nsis/root"
        env = {"NSISDIR": str(nsis / "usr/share/nsis"),
               "PATH": f"{Path.home() / '.cache/argus-tools/7zip/root/usr/lib/7zip'}{os.pathsep}{os.environ['PATH']}"}
        # Relative --out, as the workflow passes it (makensis resolves a relative
        # OutFile against the .nsi's folder: run 41629504457 failed on exactly that).
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.tmp)
        with mock.patch.dict(os.environ, env):
            eng, desk = self._inputs()
            argv = ["build_setup.py", "--engine", str(eng), "--desktop", str(desk), "--version", "2026.11.03-0",
                    "--out", "setup", "--makensis", str(nsis / "usr/bin/makensis")]
            with mock.patch.object(sys, "argv", argv):
                build_setup.main()
            setup = self.tmp / "setup" / build_setup.SETUP_NAME
            self.assertEqual(self._gate(setup), [])


class Workflow(unittest.TestCase):
    def test_draft_waits_for_the_windows_install_test(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        needs = next(line for line in text.splitlines() if line.strip().startswith("needs: [meta, verify,"))
        # Builds start beside verify; nothing is assembled unless verify, the
        # source smoke and both install tests passed.
        for job in ("verify", "windows-source-smoke", "engine-windows", "windows-setup",
                    "windows-install-test", "server-install-test"):
            self.assertIn(job, needs)
        self.assertIn("release/windows/install_test.ps1", text)
        self.assertIn(r"--work C:\argus-build ", text)

    def test_only_dry_runs_are_cancelled_or_built_warm(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        self.assertIn("cancel-in-progress: ${{ github.ref_type != 'tag' }}", text)
        # Every cache restore of build state is skipped for a tag: a release builds cold.
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if "actions/cache/restore@" in line and "Restore" in lines[i - 2]:
                self.assertIn("if: github.ref_type != 'tag'", lines[i - 1], lines[i - 2])
        self.assertIn("release/windows/source_smoke.ps1", text)
        self.assertIn("retention-days: 7", text)

    def test_a_build_cache_is_saved_only_after_a_successful_build(self):
        # Run 42066556800 compiled 556 C files with 0 cache hits: a cancelled run had saved an
        # empty cache under `if: always()`, and restore-keys returns the NEWEST prefix match,
        # so the empty entry beat the populated ones. A cancelled or failed build saves nothing.
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        always = [ln.strip() for ln in text.splitlines() if "if: always()" in ln]
        self.assertEqual(always, [], "a cancelled run must not save a cache")
        steps = re.findall(r"- name: (Save [^\n]*)\n\s+if: ([^\n]+)\n", text)
        self.assertGreaterEqual(len(steps), 4, "server, desktop-linux, desktop-windows, engine-windows")
        for name, cond in steps:
            self.assertIn("success()", cond, name)
            self.assertIn("github.ref_type != 'tag'", cond, name)

    def test_the_install_test_runs_every_scenario_on_its_own_clean_host(self):
        # The scenarios share the supervisor's restart budget (3 per 15 minutes), which is why one
        # host ran them in a fixed order with up to 16 minutes of waiting between them. A fresh host
        # per scenario has the whole budget, so the host-sharing waits go; every real wait stays.
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        script = (ROOT / "release" / "windows" / "install_test.ps1").read_text()
        declared = re.search(r"ValidateSet\(([^)]*)\)\]\[string\]\$Scenario\s*=\s*'all'", script)
        self.assertIsNotNone(declared, "the script takes -Scenario with 'all' as its default")
        names = set(re.findall(r"'([a-z-]+)'", declared.group(1)))
        self.assertIn("all", names)
        scenarios = names - {"all"}
        job = text[text.index("  windows-install-test:"):text.index("  draft:")]
        matrix = re.search(r"scenario:\s*\[([^\]]*)\]", job)
        self.assertIsNotNone(matrix, "windows-install-test shards by scenario")
        sharded = {s.strip() for s in matrix.group(1).split(",") if s.strip()}
        self.assertEqual(sharded, scenarios, "a scenario missing from the matrix would never run in CI")
        self.assertIn("fail-fast: false", job)
        self.assertIn("-Scenario ${{ matrix.scenario }}", job)
        for name in scenarios:
            self.assertIn(f"Want '{name}'", script, f"{name} selects at least one block of the script")

    def test_service_loop_requires_the_exact_engine(self):
        text = (ROOT / "jarvis-native-service.ps1").read_text(encoding="utf-8")
        self.assertIn("if (-not $p.ExecutablePath -or $p.ExecutablePath -ne $Engine) { return $null }", text)
        self.assertIn("[string]$Engine = ''", text)

    def test_stop_and_reinstall_end_the_running_loop_not_just_the_task(self):
        # Clean windows-2025 run 41801062950: the loop outlived Stop-ScheduledTask and
        # still held the single-instance lock after `native stop`.
        text = (ROOT / "jarvis-native-service.ps1").read_text(encoding="utf-8")
        block = text[text.index("if ($Install -or $Remove) {"):text.index("if ($Remove) { Say")]
        stop = block.index("Stop-ScheduledTask")
        kill = block.index("Stop-Process -Id $_.ProcessId")
        self.assertLess(stop, kill)
        self.assertIn("$_.ProcessId -ne $PID", block)            # never itself
        self.assertIn("$staged = Join-Path $StateRoot", block)   # only this service's own loop
        self.assertLess(kill, block.index("Stop-Daemon ([int]$old.pid)"))

    def test_the_repeating_trigger_can_revive_a_dead_loop_and_install_resets_the_budget(self):
        # Run 41839251050: the loop died, the task stayed "Running", IgnoreNew dropped
        # every revival trigger; and a reinstall kept a spent budget and never started.
        text = (ROOT / "jarvis-native-service.ps1").read_text(encoding="utf-8")
        self.assertIn("-MultipleInstances Parallel", text)
        self.assertNotIn("-MultipleInstances IgnoreNew", text)
        self.assertIn("$owned = $mutex.WaitOne(0)", text)            # extra instances exit
        install = text[text.index("if ($Install -or $Remove) {"):text.index("Register-ScheduledTask")]
        self.assertIn("Remove-Item -LiteralPath $statePath", install)
        self.assertLess(install.index('if ($Remove) { Say'), install.index("Remove-Item -LiteralPath $statePath"))

    def test_lifting_a_pause_lets_it_supervise_again_within_budget(self):
        text = (ROOT / "jarvis-native-service.ps1").read_text(encoding="utf-8")
        self.assertIn("if (-not $paused -and $st.gaveUp) { $st.gaveUp = $false", text)
        self.assertIn("if ($st.restarts.Count -ge $RestartBudget) {", text)   # budget unchanged

class OutputEncoding(unittest.TestCase):
    """The service's stdout is a cp1252 file on Windows; an arrow in the start-up
    line stopped the daemon (run 41663851546)."""

    def test_redirected_cp1252_output_takes_any_character(self):
        from jarvis.cli import parser
        raw = io.BytesIO()
        out = io.TextIOWrapper(raw, encoding="cp1252")
        with self.assertRaises(UnicodeEncodeError):
            out.write("\u2192"); out.flush()
        raw = io.BytesIO()
        out = io.TextIOWrapper(raw, encoding="cp1252")
        err = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        parser.safe_streams([out, err])
        print("dashboard \u2192 http://127.0.0.1:8787", file=out, flush=True)
        self.assertIn("\u2192".encode("utf-8"), raw.getvalue())
        parser.safe_streams([None, None])   # no console at all: nothing to do

    def test_windows_state_dir_is_not_judged_by_posix_modes(self):
        from jarvis.core import statedir
        d = tempfile.mkdtemp(prefix="st-")
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o777)
        self.assertEqual(statedir.private_problems(d, os_name="nt"), [f"{d}: {statedir.WINDOWS_NOTE}"])
        self.assertTrue(any("must be 0700" in p for p in statedir.private_problems(d, os_name="posix")))



if __name__ == "__main__":
    importlib.invalidate_caches()
    unittest.main()
