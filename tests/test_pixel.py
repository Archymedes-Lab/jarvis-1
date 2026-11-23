import os
import tempfile
import unittest

from jarvis.collectors.host.pixel import mail, screen, web
from jarvis.collectors.host.pixel.run import audit


def sev(findings, title_part):
    return [f["severity"] for f in findings if title_part in f["title"]]


class ScreenPostureTests(unittest.TestCase):
    def test_rdp_without_capture_protection_outranks_rdp_with_it(self):
        without = screen.rules_windows({"rdpDenied": 0, "captureProtection": 0,
                                        "rdpNla": 1})
        with_it = screen.rules_windows({"rdpDenied": 0, "captureProtection": 1,
                                        "rdpNla": 1})

        self.assertEqual(sev(without, "Remote Desktop is enabled"), ["high"])
        self.assertEqual(sev(with_it, "Remote Desktop is enabled"), ["medium"])

    def test_disabled_rdp_is_reported_as_ok_not_silently(self):
        out = screen.rules_windows({"rdpDenied": 1})

        self.assertEqual(sev(out, "Remote Desktop is disabled"), ["ok"])

    def test_a_listening_screen_port_is_high(self):
        out = screen.rules_windows({"rdpDenied": 1, "listeners": [5900, 443]})

        hit = [f for f in out if "screen-sharing port" in f["title"]]
        self.assertEqual([f["severity"] for f in hit], ["high"])
        self.assertIn("VNC", hit[0]["detail"])

    def test_installed_capture_app_does_not_mask_the_streaming_summary(self):
        """An app that *may* capture is a different claim from an active
        stream; the reassuring summary must still be emitted."""
        out = screen.rules_windows({
            "rdpDenied": 1, "listeners": [],
            "capturePkgs": [{"name": "Teams",
                             "caps": ["graphicsCaptureWithoutBorder"]}]})

        self.assertEqual(sev(out, "no screen is being streamed"), ["ok"])

    def test_an_active_remote_tool_suppresses_the_streaming_summary(self):
        out = screen.rules_windows({
            "rdpDenied": 1, "listeners": [],
            "procs": [{"name": "AnyDesk", "path": "C:/a.exe"}]})

        self.assertEqual(sev(out, "no screen is being streamed"), [])
        self.assertEqual(sev(out, "AnyDesk is running"), ["medium"])

    def test_borderless_capture_outranks_bordered_capture(self):
        out = screen.rules_windows({"rdpDenied": 1, "capturePkgs": [
            {"name": "A", "caps": ["graphicsCapture"]},
            {"name": "B", "caps": ["graphicsCaptureWithoutBorder"]}]})

        self.assertEqual(sorted(sev(out, "may capture the screen")),
                         ["low", "medium"])

    def test_missing_windows_data_is_reported_as_unknown_not_as_clean(self):
        out = screen.rules_windows(None)

        self.assertEqual([f["severity"] for f in out], ["low"])
        self.assertIn("unknown", out[0]["detail"])

    def test_x11_is_flagged_and_wayland_is_not(self):
        x11 = screen.rules_linux({"XDG_SESSION_TYPE": "x11", "DISPLAY": ":0"})
        wl = screen.rules_linux({"XDG_SESSION_TYPE": "wayland",
                                 "WAYLAND_DISPLAY": "wayland-0"})

        self.assertEqual([f["severity"] for f in x11], ["medium"])
        self.assertEqual([f["severity"] for f in wl], ["ok"])

    def test_headless_session_claims_no_desktop_rather_than_safety(self):
        out = screen.rules_linux({}, x11_socket="/nonexistent")

        self.assertEqual([f["severity"] for f in out], ["ok"])
        self.assertIn("no desktop", out[0]["detail"])


class MailPixelTests(unittest.TestCase):
    def test_one_by_one_remote_image_is_a_beacon(self):
        hits = mail.scan_html(
            '<img src="https://cdn.example.com/x.gif" width="1" height="1">')

        self.assertEqual(len(hits), 1)
        self.assertIn("1x1", hits[0]["why"])

    def test_tracking_host_is_a_beacon_even_at_full_size(self):
        hits = mail.scan_html(
            '<img src="https://open.mailstat.example/o.png" width="600">')

        self.assertEqual(len(hits), 1)
        self.assertIn("tracking-style URL", hits[0]["why"])

    def test_ordinary_inline_image_is_not_reported(self):
        html = ('<img src="cid:logo">'
                '<img src="https://example.com/banner.png" width="600">')

        self.assertEqual(mail.scan_html(html), [])

    def test_a_message_with_no_beacon_says_so_explicitly(self):
        out = mail.rules_message("<p>hello</p>")

        self.assertEqual([f["severity"] for f in out], ["ok"])

    def test_thunderbird_remote_images_enabled_is_high(self):
        on = mail.rules_thunderbird(
            'user_pref("mailnews.message_display.disable_remote_image", false);')
        off = mail.rules_thunderbird(
            'user_pref("mailnews.message_display.disable_remote_image", true);')

        self.assertEqual([f["severity"] for f in on], ["high"])
        self.assertEqual([f["severity"] for f in off], ["ok"])

    def test_thunderbird_default_is_treated_as_blocking(self):
        """The pref is absent on a fresh profile, and the default blocks."""
        out = mail.rules_thunderbird("user_pref(\"other.pref\", 1);")

        self.assertEqual([f["severity"] for f in out], ["ok"])

    def test_outlook_auto_download_is_high_and_blocking_is_ok(self):
        on = mail.rules_outlook({"outlook": [{"version": "16.0",
                                              "blockHttp": 0}]})
        off = mail.rules_outlook({"outlook": [{"version": "16.0",
                                               "blockHttp": 1}]})

        self.assertEqual([f["severity"] for f in on], ["high"])
        self.assertEqual([f["severity"] for f in off], ["ok"])

    def test_absent_outlook_is_stated_rather_than_left_silent(self):
        out = mail.rules_outlook({"outlook": []})

        self.assertEqual([f["severity"] for f in out], ["ok"])


class WebTrackingTests(unittest.TestCase):
    def test_disabled_tracking_protection_is_reported(self):
        out = web.rules_firefox(
            'user_pref("privacy.trackingprotection.enabled", false);')

        self.assertEqual(sev(out, "tracking protection is off"), ["medium"])

    def test_absent_pref_counts_as_the_protective_default(self):
        out = web.rules_firefox("")

        self.assertEqual(sev(out, "tracking protection is on"), ["ok"])
        self.assertIn("browser default", out[0]["detail"])

    def test_permissive_cookie_behaviour_is_reported(self):
        out = web.rules_firefox('user_pref("network.cookie.cookieBehavior", 0);')

        self.assertEqual(sev(out, "accepts third-party cookies"), ["medium"])

    def test_total_cookie_protection_is_ok(self):
        out = web.rules_firefox('user_pref("network.cookie.cookieBehavior", 5);')

        self.assertEqual(sev(out, "restricts third-party cookies"), ["ok"])

    def test_chromium_cookie_modes_are_graded(self):
        allow = web.rules_chromium({"profile": {"cookie_controls_mode": 0}})
        block = web.rules_chromium({"profile": {"cookie_controls_mode": 2}})

        self.assertEqual([f["severity"] for f in allow], ["medium"])
        self.assertEqual([f["severity"] for f in block], ["ok"])

    def test_do_not_track_is_only_low_and_says_it_does_not_help(self):
        out = web.rules_chromium({"profile": {"cookie_controls_mode": 0},
                                  "enable_do_not_track": False})

        dnt = [f for f in out if "Do Not Track" in f["title"]]
        self.assertEqual([f["severity"] for f in dnt], ["low"])
        self.assertIn("most trackers ignore it", dnt[0]["detail"])

    def test_a_profile_directory_is_actually_read(self):
        with tempfile.TemporaryDirectory() as home:
            prof = os.path.join(home, ".mozilla/firefox/abc.default")
            os.makedirs(prof)
            with open(os.path.join(prof, "prefs.js"), "w") as fh:
                fh.write('user_pref("network.cookie.cookieBehavior", 0);')

            out = web.audit(hosts=("wsl",), home=home)

        self.assertEqual(sev(out, "accepts third-party cookies"), ["medium"])


class AuditTests(unittest.TestCase):
    def test_a_failing_surface_is_reported_not_read_as_clean(self):
        original = screen.audit
        screen.audit = lambda hosts: (_ for _ in ()).throw(OSError("boom"))
        try:
            out = audit(hosts=("wsl",))
        finally:
            screen.audit = original

        hit = [f for f in out if f["title"].endswith("check failed")]
        self.assertEqual(len(hit), 1)
        self.assertIn("boom", hit[0]["detail"])

    def test_every_finding_carries_the_shared_shape(self):
        for f in audit(hosts=("wsl",)):
            for key in ("category", "severity", "title", "detail", "where",
                        "host"):
                self.assertIn(key, f)


class WiringTests(unittest.TestCase):
    """The daemon job and the investigate sweep both call into this package;
    a missing import there only fails at run time, in a background thread."""

    def test_daemon_registers_and_dispatches_the_pixel_job(self):
        from jarvis.service import jobs, schedule

        self.assertIn("pixel", schedule.JOBS)
        self.assertIsInstance(jobs.run_job("pixel", ("wsl",), ":memory:"), list)

    def test_investigate_sweep_includes_the_pixel_surface(self):
        from jarvis.cli.commands import audit as audit_cmd

        self.assertIs(audit_cmd.pixel.audit, audit)


if __name__ == "__main__":
    unittest.main()
