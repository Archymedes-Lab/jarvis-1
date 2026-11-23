"""Linux system integrity (collectors/persistence/linuxguard.py).

Invariants
  1. Drift: the first pass records a baseline; later passes report new, changed and
     removed watched files and new privileged-group members; nothing is learned later.
  2. Invariants without a baseline: PAM running a program or loading a module from
     outside the system folders, LD_PRELOAD/LD_AUDIT for every session, a dangerous
     file capability outside system folders, a log cut shorter in place.
  3. Read-only and private: contents are never quoted; links are not followed.
  4. Evidence continuity: an unreadable source is a gap, never "unchanged" and never
     "removed"; a capped pass says so.
  5. Accepting a new baseline needs a person at a terminal.
"""
import argparse
import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from jarvis.cli import output
from jarvis.cli.commands import linuxguard as cli
from jarvis.collectors.persistence import linuxguard as g
from jarvis.core.finding import content_origin
from jarvis.core.store import Store

SECRET = "Hunter2-secret-value"


def caps_xattr(*bits):
    lo = 0
    for b in bits:
        lo |= 1 << b
    return struct.pack("<IIIII", 0x02000001, lo, 0, 0, 0)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        r = self.root = self.tmp.name
        for d in ("etc/pam.d", "etc/sudoers.d", "etc/udev/rules.d", "etc/apt/apt.conf.d", "etc/update-motd.d",
                  "var/log", "caps"):
            os.makedirs(os.path.join(r, d))
        self.write("etc/pam.d/common-auth", "auth [success=1 default=ignore] pam_unix.so nullok\n")
        self.write("etc/environment", 'PATH="/usr/bin:/bin"\n')
        self.write("etc/bash.bashrc", "# system bashrc\n")
        self.write("etc/apt/apt.conf.d/20auto", 'APT::Periodic::Update-Package-Lists "1";\n')
        self.write("var/log/auth.log", "x" * 500)
        self.groups = {"sudo": ["alice"], "docker": []}
        self.xattrs = {}
        self.store = Store(os.path.join(r, "t.db"))
        self.addCleanup(self.store.close)

    def p(self, rel):
        return os.path.join(self.root, rel)

    def write(self, rel, text):
        with open(self.p(rel), "w") as fh:
            fh.write(text)

    def families(self):
        return (("pam", (), (self.p("etc/pam.d"),), "high", "sign-in"),
                ("environment", (self.p("etc/environment"),), (), "high", "sessions"),
                ("shell", (self.p("etc/bash.bashrc"),), (), "medium", "shells"),
                ("udev", (), (self.p("etc/udev/rules.d"),), "medium", "devices"),
                ("apt", (), (self.p("etc/apt/apt.conf.d"),), "medium", "packages"),
                ("motd", (), (self.p("etc/update-motd.d"),), "medium", "motd"))

    def getgrnam(self, name):
        if name not in self.groups:
            raise KeyError(name)
        return SimpleNamespace(gr_mem=list(self.groups[name]))

    def getxattr(self, path, name, follow_symlinks=False):
        if path in self.xattrs:
            return self.xattrs[path]
        raise OSError(61, "no data")

    def run_pass(self, store=True):
        with mock.patch.object(g, "SEVERITY", {f[0]: f[3] for f in self.families()}), \
                mock.patch.object(g, "WHAT", {f[0]: f[4] for f in self.families()}):
            return g.audit(self.store if store else None, families=self.families(), logs=(self.p("var/log/auth.log"),),
                           cap_roots=(self.p("caps"),), getgrnam=self.getgrnam, getxattr=self.getxattr)

    def titles(self, out):
        """(severity, title) without the file-evidence mark every file finding carries."""
        return [(f["severity"], f["title"].replace(" (file evidence)", "")) for f in out if f["severity"] != "ok"]


class Drift(Base):
    def test_a_clean_machine_reports_nothing_after_the_baseline(self):
        first = self.run_pass()
        self.assertEqual([f["title"] for f in first], ["system integrity baseline recorded"])
        self.assertEqual(self.titles(self.run_pass()), [])

    def test_each_kind_of_drift_is_reported_at_its_family_weight(self):
        self.run_pass()
        self.write("etc/bash.bashrc", "# system bashrc\n(/tmp/x &)\n")
        self.write("etc/udev/rules.d/99-x.rules", 'RUN+="/usr/local/bin/x"\n')
        self.write("etc/apt/apt.conf.d/99x", 'APT::Update::Pre-Invoke {"/usr/local/bin/x";};\n')
        self.write("etc/update-motd.d/99-x", "#!/bin/sh\n/usr/local/bin/x\n")
        os.unlink(self.p("etc/apt/apt.conf.d/20auto"))
        got = dict((t, s) for s, t in self.titles(self.run_pass()))
        self.assertEqual(got[f"changed since first seen: {self.p('etc/bash.bashrc')}"], "medium")
        self.assertEqual(got[f"new since first seen: {self.p('etc/udev/rules.d/99-x.rules')}"], "medium")
        self.assertEqual(got[f"new since first seen: {self.p('etc/apt/apt.conf.d/99x')}"], "medium")
        self.assertEqual(got[f"new since first seen: {self.p('etc/update-motd.d/99-x')}"], "medium")
        self.assertEqual(got[f"removed since first seen: {self.p('etc/apt/apt.conf.d/20auto')}"], "low")

    def test_drift_is_never_learned_by_repetition(self):
        self.run_pass()
        self.write("etc/bash.bashrc", "changed\n")
        for _ in range(3):
            self.assertTrue([t for _, t in self.titles(self.run_pass()) if "changed since first seen" in t])

    def test_a_new_privileged_group_member_is_high(self):
        self.run_pass()
        self.groups["sudo"].append("mallory")
        self.groups["docker"].append("eve")
        got = self.titles(self.run_pass())
        self.assertIn(("high", "new member of the sudo group: mallory"), got)
        self.assertIn(("high", "new member of the docker group: eve"), got)

    def test_an_unreadable_file_is_a_gap_not_removed_or_unchanged(self):
        self.run_pass()
        with mock.patch.object(g.safe_files, "read_start", return_value=None):
            out = self.run_pass()
        self.assertFalse([t for _, t in self.titles(out) if "removed since" in t])
        self.assertIn("System integrity was not completely checked", [t for _, t in self.titles(out)])

    def test_a_capped_pass_says_so(self):
        with mock.patch.object(g, "MAX_FILES", 1):
            out = self.run_pass()
        self.assertTrue(any("reached its limit" in f["detail"] for f in out))


class Invariants(Base):
    def test_pam_running_a_program_is_high_without_a_baseline_and_the_line_is_not_shown(self):
        self.write("etc/pam.d/common-auth",
                   "auth required pam_unix.so\nauth optional pam_exec.so quiet /tmp/x.sh " + SECRET + "\n"
                   "auth required /home/u/evil.so\n")
        out = self.run_pass(store=False)
        f = [f for f in out if f["title"].startswith("PAM runs a program")][0]
        self.assertEqual(f["severity"], "high")
        self.assertIn("line(s) 2, 3", f["detail"])
        self.assertNotIn(SECRET, json.dumps(out))
        self.assertTrue(content_origin(f))

    def test_system_pam_modules_are_fine(self):
        self.write("etc/pam.d/common-auth", "auth required pam_unix.so\n"
                   "session optional /usr/lib/x86_64-linux-gnu/security/pam_systemd.so\n@include common-x\n")
        self.assertFalse([f for f in self.run_pass(store=False) if "PAM runs" in f["title"]])

    def test_global_ld_preload_is_high_and_its_value_is_not_shown(self):
        self.write("etc/environment", f'PATH="/usr/bin"\nLD_PRELOAD=/usr/local/lib/{SECRET}.so\n')
        f = [f for f in self.run_pass(store=False) if "LD_PRELOAD" in f["title"]][0]
        self.assertEqual(f["severity"], "high")
        self.assertNotIn(SECRET, f["detail"] + f["title"])

    def test_dangerous_file_capabilities_outside_system_folders_are_high(self):
        path = self.p("caps/python3")
        self.write("caps/python3", "x")
        self.xattrs[path] = caps_xattr(7)
        self.write("caps/ping", "x")
        self.xattrs[self.p("caps/ping")] = caps_xattr(13)             # cap_net_raw: not root-equivalent
        out = [f for f in self.run_pass(store=False) if "capabilities" in f["title"]]
        self.assertEqual(len(out), 1)
        self.assertIn("cap_setuid", out[0]["detail"])
        self.assertEqual(g.file_caps(caps_xattr(21, 1)), ["cap_dac_override", "cap_sys_admin"])
        self.assertEqual(g.file_caps(b"\x00"), [])

    def test_a_log_cut_in_place_is_high_but_rotation_is_not(self):
        self.run_pass()
        with open(self.p("var/log/auth.log"), "w"):
            pass                                                     # emptied, same file
        self.assertIn(("high", "log cut shorter in place: auth.log"), self.titles(self.run_pass()))
        with open(self.p("var/log/auth.log"), "a") as fh:
            fh.write("y" * 300)                                      # grows again on the same file
        self.run_pass()
        os.rename(self.p("var/log/auth.log"), self.p("var/log/auth.log.1"))
        self.write("var/log/auth.log", "z")                          # rotated: a new, smaller file
        self.assertNotIn(("high", "log cut shorter in place: auth.log"), self.titles(self.run_pass()))

    def test_links_are_not_followed(self):
        outside = os.path.join(self.root, "outside")
        with open(outside, "w") as fh:
            fh.write("LD_PRELOAD=/x.so\n")
        os.unlink(self.p("etc/environment"))
        os.symlink(outside, self.p("etc/environment"))
        self.assertFalse([f for f in self.run_pass(store=False) if "LD_PRELOAD" in f["title"]])


class Portability(unittest.TestCase):
    def test_the_job_table_imports_where_unix_modules_do_not_exist(self):
        # Measured 2026-11-11: an unguarded `import grp` broke every job on native Windows.
        import subprocess
        import sys
        code = ("import builtins, sys\n"
                "real = builtins.__import__\n"
                "def guard(name, *a, **k):\n"
                "    if name in ('grp', 'pwd', 'fcntl', 'termios', 'resource'):\n"
                "        raise ImportError(name)\n"
                "    return real(name, *a, **k)\n"
                "builtins.__import__ = guard\n"
                "import jarvis.collectors.persistence.linuxguard as g\n"
                "assert g.privileged_members() == {}\n"
                "print('ok')\n")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
                           cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.assertEqual(r.stdout.strip(), "ok", r.stderr[-400:])


class Accept(Base):
    def test_accept_needs_a_typed_word_at_a_terminal(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True
        args = argparse.Namespace(action="accept")
        with mock.patch.object(g, "accept", return_value=7) as accept:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.cmd_linuxguard(args, self.store), 2)   # not a terminal
            accept.assert_not_called()
            with mock.patch.object(output.sys, "stdin", Tty("accept\n")), \
                    mock.patch.object(output.sys, "stdout", Tty()):
                self.assertEqual(cli.cmd_linuxguard(args, self.store), 0)
            accept.assert_called_once()

    def test_accept_refuses_when_anything_could_not_be_read(self):
        with mock.patch.object(g, "watched_files", side_effect=lambda scan, *a: scan.denied.append("/etc/sudoers") or {}):
            with self.assertRaises(RuntimeError):
                g.accept(self.store)


if __name__ == "__main__":
    unittest.main()
