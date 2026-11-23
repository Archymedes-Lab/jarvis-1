"""The server installer never leaves a watched server unwatched.

The shipped release/server/install.sh is run for real, as a copy whose system
paths point into a scratch directory, with the system tools it calls (systemctl,
useradd, curl, ...) replaced by recording stand-ins. Nothing outside the scratch
directory is read or written and no service is touched.

Invariants (PRODUCTION-READINESS-2026-11-02 finding 5):

  1. A new copy that fails its own verification is not installed, and a running
     Argus is never stopped for it.
  2. After the switch, any failure before the new version answers puts the
     previous program, version file and unit back and starts it again if it was
     running; the installer exits non-zero and says which state the server is in.
  3. If the previous version cannot be started again, the installer says the
     server is not being watched; it never reports that state as recovered.
  4. A good upgrade leaves the new version running and no leftovers.
"""
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from jarvis.core.paths import REPO_ROOT

INSTALL = REPO_ROOT / "release" / "server" / "install.sh"
SYSTEM_PATHS = ("/opt/argus", "/var/lib/argus", "/etc/argus", "/etc/systemd/system",
                "/usr/local/bin/argus", "/run/systemd/system")

STUBS = {
    "id": 'if [ "${1:-}" = -u ]; then echo 0; fi; exit 0',
    "systemctl": textwrap.dedent('''\
        echo "$*" >> "$FAKE/systemctl.log"
        case "$1" in
          is-active) grep -q '^active$' "$FAKE/state" 2>/dev/null ;;
          stop) echo inactive > "$FAKE/state" ;;
          start|restart)
            if [ -e "$FAKE/start_fails" ]; then exit 1; fi
            echo active > "$FAKE/state" ;;
          *) exit 0 ;;
        esac'''),
    "install": textwrap.dedent('''\
        n=$#; i=0; skip=0
        while [ $i -lt $n ]; do
          a="$1"; shift; i=$((i+1))
          if [ $skip = 1 ]; then skip=0; continue; fi
          case "$a" in -o|-g) skip=1 ;; *) set -- "$@" "$a" ;; esac
        done
        exec /usr/bin/install "$@"'''),
    "curl": textwrap.dedent('''\
        if grep -q '^active$' "$FAKE/state" 2>/dev/null && [ -e "$FAKE/root/opt/argus/bin/healthy" ]; then
          printf '{"service": "ARGUS"}'; exit 0
        fi
        exit 7'''),
    "getent": "exit 1",
}
NOOPS = ("useradd", "usermod", "chown", "ss", "setpriv", "sudo", "sleep", "wget")

PROGRAM = textwrap.dedent('''\
    #!/bin/sh
    case "$*" in
      *argus.verify*)
        if [ -e "$(dirname "$0")/verify_ok" ]; then echo "verification passed"; exit 0; fi
        echo "verification FAILED"; exit 1 ;;
    esac
    exit 0
    ''')


def executable(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@unittest.skipUnless(shutil.which("bash") and os.path.exists("/usr/bin/install"), "needs bash and coreutils")
class Failsafe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fake = Path(self.tmp.name)
        self.root = self.fake / "root"
        for d in ("opt", "var/lib", "etc/systemd/system", "usr/local/bin", "run/systemd/system"):
            (self.root / d).mkdir(parents=True)
        stubs = self.fake / "stubs"
        stubs.mkdir()
        for name, body in STUBS.items():
            executable(stubs / name, "#!/bin/sh\n" + body + "\n")
        for name in NOOPS:
            executable(stubs / name, "#!/bin/sh\nexit 0\n")
        self.env = {"PATH": f"{stubs}:/usr/bin:/bin", "FAKE": str(self.fake), "LANG": "C.UTF-8"}

    def archive(self, version, verify_ok=True, healthy=True, unit=True):
        here = self.fake / f"archive-{version}"
        (here / "bin").mkdir(parents=True)
        (here / "units").mkdir()
        executable(here / "bin" / "argus-server", PROGRAM)
        (here / "bin" / "tag").write_text(version)
        if verify_ok:
            (here / "bin" / "verify_ok").write_text("")
        if healthy:
            (here / "bin" / "healthy").write_text("")
        (here / "VERSION").write_text(version)
        (here / "uninstall.sh").write_text("#!/bin/sh\n")
        if unit:
            (here / "units" / "argus.service").write_text(f"# unit {version}\n")
        text = INSTALL.read_text()
        for path in SYSTEM_PATHS:
            text = text.replace(path, f"{self.root}{path}")
        executable(here / "install.sh", text)
        return here

    def run_install(self, here, *args):
        return subprocess.run(["bash", str(here / "install.sh"), *args], env=self.env,
                              capture_output=True, text=True, timeout=120)

    # what the server looks like afterwards
    def tag(self):
        return (self.root / "opt/argus/bin/tag").read_text()

    def version(self):
        return (self.root / "opt/argus/VERSION").read_text()

    def unit(self):
        return (self.root / "etc/systemd/system/argus.service").read_text()

    def active(self):
        state = self.fake / "state"
        return state.exists() and state.read_text().strip() == "active"

    def calls(self):
        log = self.fake / "systemctl.log"
        return log.read_text().splitlines() if log.exists() else []

    def leftovers(self):
        return sorted(p.name for p in (self.root / "opt/argus").iterdir()
                      if p.name.endswith((".old", ".new")))

    def installed(self, version):
        res = self.run_install(self.archive(version))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        (self.fake / "systemctl.log").unlink()
        return res

    def test_fresh_install_starts_and_leaves_nothing_behind(self):
        res = self.run_install(self.archive("v1"))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual((self.tag(), self.version(), self.active()), ("v1", "v1", True))
        self.assertEqual(self.leftovers(), [])
        self.assertIn("dashboard answering", res.stdout)

    def test_good_upgrade_runs_the_new_version(self):
        self.installed("v1")
        res = self.run_install(self.archive("v2"))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual((self.tag(), self.version(), self.unit(), self.active()),
                         ("v2", "v2", "# unit v2\n", True))
        self.assertEqual(self.leftovers(), [])

    def test_a_copy_that_fails_verification_never_stops_the_running_service(self):
        self.installed("v1")
        res = self.run_install(self.archive("v2", verify_ok=False))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("not installed", res.stderr)
        self.assertEqual((self.tag(), self.version(), self.unit(), self.active()),
                         ("v1", "v1", "# unit v1\n", True))
        self.assertFalse([c for c in self.calls() if c.split()[0] in ("stop", "restart", "start")],
                         self.calls())
        self.assertEqual(self.leftovers(), [])
        # The report on disk still describes the installed copy.
        self.assertIn("passed", (self.root / "opt/argus/verification.txt").read_text())

    def test_first_install_of_a_bad_copy_installs_nothing(self):
        res = self.run_install(self.archive("v1", verify_ok=False))
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse((self.root / "opt/argus/bin").exists())
        self.assertFalse((self.root / "etc/systemd/system/argus.service").exists())

    def test_skip_verify_is_an_explicit_override(self):
        self.installed("v1")
        res = self.run_install(self.archive("v2", verify_ok=False), "--skip-verify")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("WARNING", res.stdout)
        self.assertEqual(self.tag(), "v2")

    def test_a_new_version_that_does_not_answer_is_rolled_back(self):
        self.installed("v1")
        res = self.run_install(self.archive("v2", healthy=False))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("previous version was put back and is running again", res.stderr)
        self.assertEqual((self.tag(), self.version(), self.unit(), self.active()),
                         ("v1", "v1", "# unit v1\n", True))
        self.assertEqual(self.leftovers(), [])

    def test_a_failure_after_the_switch_is_rolled_back(self):
        self.installed("v1")
        res = self.run_install(self.archive("v2", unit=False))     # the unit copy fails mid-install
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual((self.tag(), self.version(), self.unit(), self.active()),
                         ("v1", "v1", "# unit v1\n", True))
        self.assertEqual(self.leftovers(), [])

    def test_an_unwatched_server_is_reported_as_unwatched(self):
        self.installed("v1")
        here = self.archive("v2", unit=False)
        (self.fake / "start_fails").write_text("")
        res = self.run_install(here)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("not being watched", res.stderr)
        self.assertNotIn("is running again", res.stderr)
        self.assertEqual(self.tag(), "v1")                          # the old program is still put back

    def test_no_start_keeps_a_watched_server_watched(self):
        self.installed("v1")
        res = self.run_install(self.archive("v2"), "--no-start")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual((self.tag(), self.active()), ("v2", True))

    def test_a_stopped_service_is_not_started_by_a_rollback(self):
        self.installed("v1")
        (self.fake / "state").write_text("inactive\n")
        res = self.run_install(self.archive("v2", unit=False))
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual((self.tag(), self.active()), ("v1", False))
        self.assertIn("was not running before", res.stderr)


if __name__ == "__main__":
    unittest.main()
