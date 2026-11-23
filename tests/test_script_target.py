"""Which file an interpreter process is really executing (platform/linux.py
_script_target). Before 2026-10-29 inline code (`bash -c ...`) was taken for a
script path, so a command that merely mentioned /tmp scored critical."""

import unittest

from jarvis.collectors.process import detect
from jarvis.platform.linux import _script_target

CLAUDE = ("source /home/u/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && "
          "eval 'ls ~/x' < /dev/null && pwd -P >| /tmp/claude-682d-cwd")


class ScriptTarget(unittest.TestCase):
    def t(self, *argv):
        return _script_target(list(argv), argv[0].rsplit("/", 1)[-1])

    def test_script_files_are_still_found(self):
        self.assertEqual(self.t("/usr/bin/python3", "/tmp/x.py"), "/tmp/x.py")
        self.assertEqual(self.t("/usr/bin/bash", "/home/u/run.sh", "a"), "/home/u/run.sh")
        self.assertEqual(self.t("/usr/bin/python3", "-u", "/srv/app/main.py"), "/srv/app/main.py")

    def test_inline_code_is_not_a_script(self):
        self.assertEqual(self.t("/bin/bash", "-c", CLAUDE), "")
        self.assertEqual(self.t("/bin/bash", "-lc", "make build > /tmp/log"), "")
        self.assertEqual(self.t("/usr/bin/python3", "-c", "open('/tmp/x').read()"), "")
        self.assertEqual(self.t("/usr/bin/python3", "-m", "http.server"), "")
        self.assertEqual(self.t("/usr/bin/node", "-e", "console.log('/tmp/a')"), "")

    def test_inline_code_that_executes_from_temp_is_still_caught(self):
        self.assertEqual(self.t("/bin/sh", "-c", "chmod +x /tmp/.k; /tmp/.k --daemon"), "/tmp/.k")
        self.assertEqual(self.t("/bin/bash", "-c", "cd / && . /dev/shm/env"), "/dev/shm/env")
        self.assertEqual(self.t("/bin/bash", "-c", "python3 /var/tmp/p.py"), "/var/tmp/p.py")
        self.assertEqual(self.t("/bin/bash", "-c", "x=1; bash /tmp/stage2"), "/tmp/stage2")
        self.assertEqual(self.t("/bin/bash", "-c", "make 2>&1 && /tmp/run"), "/tmp/run")

    def test_redirections_into_temp_are_not_execution(self):
        for code in ("pwd -P >| /tmp/cwd", "make > /tmp/log 2>&1", "sort < /tmp/in", "cmd >> /tmp/a; cat /tmp/a"):
            self.assertEqual(self.t("/bin/bash", "-c", code), "", code)

    def test_scores_end_to_end(self):
        def score(argv):
            p = {"pid": 9, "ppid": 1, "name": "bash", "exe": "/usr/bin/bash", "cmdline": " ".join(argv),
                 "script": self.t(*argv), "host": "wsl", "user": "u", "fp": "x", "conns": []}
            return detect.assess(p, known=set(), approved=set())
        self.assertIn(score(["/usr/bin/bash", "-c", CLAUDE])["severity"], ("low", "medium"))
        self.assertEqual(score(["/usr/bin/bash", "-c", "/tmp/.k"])["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
