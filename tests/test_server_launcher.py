"""The packaged server edition runs its launcher compiled (argus-release.pyc,
no source); collectors/persistence/control.py must still recognise its own unit."""

import unittest


class ServerLauncherIsRecognised(unittest.TestCase):
    """The packaged server edition runs a compiled launcher (.pyc); the control
    audit must still recognise its own unit, and nothing else by that name."""

    def check(self, argv, user="jarvis", root_only=True):
        from unittest import mock

        from jarvis.collectors.persistence import control
        with mock.patch.object(control, "_unit_show", return_value=(argv, user)), \
                mock.patch.object(control, "_root_only", return_value=root_only), \
                mock.patch("os.stat") as st, mock.patch("pwd.getpwuid") as gp:
            st.return_value.st_uid = 0
            gp.return_value.pw_name = "owner"
            return control._verified_unit("/etc/systemd/system/jarvis.service")

    def test_compiled_and_source_launchers(self):
        for launcher in ("/opt/jarvis/app/jarvis-release.pyc", "/opt/jarvis/app/jarvis-release.py"):
            self.assertIn("sealed JARVIS server release",
                          self.check(["/opt/jarvis/python/bin/python3", "-I", launcher, "serve", "--port", "8787"]))

    def test_native_binary(self):
        argv = ["/opt/jarvis/bin/jarvis-server", "serve", "--port", "8787"]
        self.assertIn("sealed native JARVIS server binary", self.check(argv))
        self.assertEqual(self.check(argv, user="www-data"), "")
        self.assertEqual(self.check(argv, root_only=False), "")
        self.assertEqual(self.check(["/tmp/jarvis-server", "serve", "--port", "8787"]), "")
        self.assertEqual(self.check(["/opt/jarvis/bin/jarvis-server", "shell"]), "")

    def test_lookalikes_are_not_recognised(self):
        argv = ["/usr/bin/python3", "-I", "/opt/jarvis/app/jarvis-release.pyc", "serve", "--port", "1"]
        self.assertEqual(self.check(argv, user="www-data"), "")
        self.assertEqual(self.check(argv, root_only=False), "")
        self.assertEqual(self.check(["/usr/bin/python3", "-I", "/tmp/jarvis-release.pyc", "serve", "--port", "1"]), "")


if __name__ == "__main__":
    unittest.main()
