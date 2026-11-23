"""Bug check parsing: only well-formed codes are named; everything else is dropped."""
import unittest

from jarvis.core import bugcheck


class BugcheckTests(unittest.TestCase):
    def test_wer_string_parses_code_and_parameters(self):
        code, params = bugcheck.from_wer("0x00020001 (0x0000000000000011, 0x3a8b1a, 0x1007, 0xffffe80000c4af00)")
        self.assertEqual(code, 0x20001)
        self.assertEqual(params[0], "0x0000000000000011")
        self.assertEqual(bugcheck.label(code), "0x20001 HYPERVISOR_ERROR")

    def test_malformed_wer_strings_are_none(self):
        for text in ("", None, "nonsense", "0x0 (0x1)", "0x123456789 (0x1)",
                     "0x20001 (0x1, 0x2, 0x3, 0x4, 0x5)", "0x20001 (zz)", "0x20001"):
            self.assertIsNone(bugcheck.from_wer(text), text)

    def test_kernel_power_code_bounds(self):
        self.assertEqual(bugcheck.from_kernel_power("131073"), 0x20001)
        for value in ("0", "-1", "x", None, str(2 ** 32)):
            self.assertIsNone(bugcheck.from_kernel_power(value), value)

    def test_every_listed_code_has_a_known_class_and_unknown_is_other(self):
        for name, kind in bugcheck.CODES.values():
            self.assertIn(kind, bugcheck.CLASSES, name)
        self.assertEqual(bugcheck.describe(0xABC), ("0xABC", "other"))
        self.assertEqual(bugcheck.label(0xABC), "0xABC")
        self.assertTrue(bugcheck.BELOW_KERNEL <= set(bugcheck.CLASSES))


if __name__ == "__main__":
    unittest.main()
