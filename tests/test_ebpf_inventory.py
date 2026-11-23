"""eBPF programs are inventoried without bpftool and judged against a baseline.

2026-10-27 coverage audit: bpftool is not installed here, so the program
inventory came back empty without a finding; an eBPF rootkit loaded after
boot was invisible. /proc/kallsyms lists every JIT-compiled program by tag.
"""
import os
import tempfile
import unittest

from jarvis.collectors.process.hidden import ebpf

KALLSYMS = """\
0000000000000000 T bpf_prog_alloc
0000000000000000 t bpf_prog_seq_show
0000000000000000 t bpf_prog_0123456789abcdef_sd_devices\t[bpf]
0000000000000000 t bpf_prog_0123456789abcdef_sd_devices\t[bpf]
0000000000000000 t bpf_prog_1111111111111111_UDPsend\t[bpf]
0000000000000000 t bpf_prog_2222222222222222\t[bpf]
0000000000000000 t bpf_prog_3333333333333333_hide_pids\t[bpf]
0000000000000000 t not_bpf_prog_4444444444444444_x\t[bpf]
"""


def fake_proc(d, kallsyms=KALLSYMS, jit="1"):
    os.makedirs(os.path.join(d, "sys/net/core"))
    with open(os.path.join(d, "sys/net/core/bpf_jit_enable"), "w") as fh:
        fh.write(jit + "\n")
    with open(os.path.join(d, "kallsyms"), "w") as fh:
        fh.write(kallsyms)
    return d


class ParseTests(unittest.TestCase):
    def test_programs_are_read_by_tag_and_kernel_functions_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            got = ebpf.kallsyms_programs(fake_proc(d))
        self.assertEqual(got, {"0123456789abcdef": "sd_devices", "1111111111111111": "UDPsend",
                               "2222222222222222": "", "3333333333333333": "hide_pids"})

    def test_jit_off_is_blind_not_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(ebpf.kallsyms_programs(fake_proc(d, jit="0")))

    def test_unreadable_kallsyms_is_blind(self):
        self.assertIsNone(ebpf.kallsyms_programs("/nonexistent-proc"))


class AssessTests(unittest.TestCase):
    BASE = {"0123456789abcdef": "sd_devices"}
    SYSMON = [{"name": "sysmon"}]

    def sev(self, programs, holders=()):
        out, _ = ebpf.assess(programs, self.BASE, list(holders))
        return {f["detail"].split(" ")[0]: f["severity"] for f in out
                if f["title"] == "new eBPF program loaded since baseline"}

    def test_blind_view_is_reported_medium(self):
        out, learned = ebpf.assess(None, self.BASE, [])
        self.assertEqual(out[0]["severity"], "medium")
        self.assertIsNone(learned)

    def test_first_run_learns(self):
        out, learned = ebpf.assess({"aa" * 8: "x"}, None, [])
        self.assertEqual(learned, {"aa" * 8: "x"})
        self.assertEqual(out[0]["title"], "eBPF program baseline learned")

    def test_new_named_program_is_medium(self):
        self.assertEqual(self.sev({**self.BASE, "33" * 8: "hide_pids"}), {"hide_pids": "medium"})

    def test_expected_churn_is_low(self):
        got = self.sev({**self.BASE, "55" * 8: "sd_fw_egress", "66" * 8: ""})
        self.assertEqual(got, {"sd_fw_egress": "low", "(unnamed)": "low"})

    def test_sysmon_names_are_trusted_only_while_sysmon_holds_ebpf(self):
        self.assertEqual(self.sev({**self.BASE, "11" * 8: "UDPsend"}, self.SYSMON),
                         {"UDPsend": "low"})
        # The same name with no Sysmon running is an impostor candidate.
        self.assertEqual(self.sev({**self.BASE, "11" * 8: "UDPsend"}), {"UDPsend": "medium"})

    def test_new_tags_are_never_learned_silently(self):
        programs = {**self.BASE, "33" * 8: "hide_pids"}
        _, learned = ebpf.assess(programs, self.BASE, [])
        self.assertIsNone(learned)
        out, _ = ebpf.assess(programs, self.BASE, [])   # next run: still reported
        self.assertTrue(any("hide_pids" in f["detail"] for f in out))

    def test_nothing_new_is_ok(self):
        out, _ = ebpf.assess(dict(self.BASE), self.BASE, [])
        self.assertEqual([f["severity"] for f in out], ["ok"])


class StoreTests(unittest.TestCase):
    def test_baseline_persists_between_runs_and_cli_never_writes(self):
        with tempfile.TemporaryDirectory() as d:
            proc = fake_proc(os.path.join(d, "proc"))
            db = os.path.join(d, "j.db")
            first = ebpf.findings([], db_path=db, proc=proc)
            self.assertEqual(first[0]["title"], "eBPF program baseline learned")
            second = ebpf.findings([], db_path=db, proc=proc)
            self.assertEqual(second[0]["title"], "no eBPF programs beyond the baseline")
            cli = ebpf.findings([], db_path=None, proc=proc)
            self.assertEqual(cli[0]["title"], "eBPF programs loaded")


if __name__ == "__main__":
    unittest.main()
