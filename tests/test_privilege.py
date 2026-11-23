import subprocess
import sys
import unittest
from unittest import mock

from jarvis.platform import privilege


class PrivilegeTests(unittest.TestCase):
    def test_missing_reads_each_capability_bit(self):
        full = sum(1 << bit for bit in privilege.CAPS.values())
        with mock.patch.object(privilege.os, "geteuid", return_value=1000):
            self.assertEqual(privilege.missing(full), [])
            self.assertEqual(sorted(privilege.missing(0)), sorted(privilege.CAPS))
            partial = full & ~(1 << privilege.CAPS["CAP_SYS_PTRACE"])
            self.assertEqual(privilege.missing(partial), ["CAP_SYS_PTRACE"])
            self.assertFalse(privilege.can_read_other_processes(partial))

    def test_root_lacks_nothing(self):
        with mock.patch.object(privilege.os, "geteuid", return_value=0):
            self.assertEqual(privilege.missing(0), [])

    def test_unreadable_status_counts_as_no_capability(self):
        self.assertEqual(privilege.effective("/nonexistent/status"), 0)

    def test_children_start_with_no_ambient_capabilities(self):
        self.assertTrue(privilege.drop_ambient())
        out = subprocess.run([sys.executable, "-c",
                              "print([l for l in open('/proc/self/status') "
                              "if l.startswith('CapAmb')][0].split()[1])"],
                             capture_output=True, text=True, check=True).stdout
        self.assertEqual(int(out, 16), 0)


class CoveragePrivilegeTests(unittest.TestCase):
    def findings(self, lacking, sealed=True):
        from jarvis.service import coverage
        with mock.patch.object(privilege, "missing", return_value=lacking), \
             mock.patch.object(privilege, "code_tree_problems",
                               return_value=[] if sealed else ["writable"]), \
             mock.patch.object(privilege.os, "geteuid", return_value=1000):
            return [f for f in coverage.visibility()
                    if f["title"] in ("running unprivileged", "least-privilege visibility")]

    def test_missing_capability_stays_a_visibility_gap(self):
        out = self.findings(["CAP_SYS_PTRACE"])
        self.assertEqual([(f["category"], f["severity"]) for f in out],
                         [("visibility", "medium")])
        self.assertIn("CAP_SYS_PTRACE", out[0]["detail"])

    def test_granted_set_is_a_stated_limit_naming_what_was_withheld(self):
        out = self.findings([])
        self.assertEqual([(f["category"], f["severity"]) for f in out], [("limits", "low")])
        self.assertIn("CAP_SYS_ADMIN", out[0]["detail"])


if __name__ == "__main__":
    unittest.main()
