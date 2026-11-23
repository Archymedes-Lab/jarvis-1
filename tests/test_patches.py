import bz2
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import patches
from jarvis.core import debver, inflate
from jarvis.intel import distrovuln
from jarvis.service import heartbeat

UBUNTU_OVAL = b"""<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
 xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
 xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
 <generator><oval:timestamp>2026-10-23T13:49:27</oval:timestamp></generator>
 <definitions>
  <definition id="d:100" class="inventory"><criteria><criterion test_ref="t:100"/></criteria></definition>
  <definition id="d:1" class="patch"><metadata><title>USN-1-1 -- OpenSSL</title>
   <reference source="USN" ref_id="USN-1-1"/><reference source="CVE" ref_id="CVE-2024-0001"/>
   <reference source="CVE" ref_id="CVE-2024-0002"/><advisory><severity>High</severity></advisory></metadata>
   <criteria><criterion test_ref="t:1"/></criteria></definition>
  <definition id="d:2" class="patch"><metadata><title>USN-2-1 -- ffmpeg</title>
   <reference source="CVE" ref_id="CVE-2025-0518"/></metadata>
   <criteria><criterion test_ref="t:2"/></criteria></definition>
 </definitions>
 <tests>
  <linux-def:dpkginfo_test id="t:1"><linux-def:object object_ref="o:1"/><linux-def:state state_ref="s:1"/></linux-def:dpkginfo_test>
  <linux-def:dpkginfo_test id="t:2"><linux-def:object object_ref="o:2"/><linux-def:state state_ref="s:2"/></linux-def:dpkginfo_test>
 </tests>
 <objects>
  <linux-def:dpkginfo_object id="o:1"><linux-def:name var_ref="v:1"/></linux-def:dpkginfo_object>
  <linux-def:dpkginfo_object id="o:2"><linux-def:name var_ref="v:2"/></linux-def:dpkginfo_object>
 </objects>
 <states>
  <linux-def:dpkginfo_state id="s:1"><linux-def:evr operation="less than">3.0.13-0ubuntu3.1</linux-def:evr></linux-def:dpkginfo_state>
  <linux-def:dpkginfo_state id="s:2"><linux-def:evr operation="less than">7:6.1.1-3ubuntu5+esm15</linux-def:evr></linux-def:dpkginfo_state>
 </states>
 <variables>
  <constant_variable id="v:1"><value>libssl3t64</value><value>openssl</value></constant_variable>
  <constant_variable id="v:2"><value>ffmpeg</value><value>libavcodec60</value></constant_variable>
 </variables>
</oval_definitions>"""

DEBIAN_OVAL = b"""<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
 <definitions>
  <definition id="d:1" class="vulnerability"><metadata><title>CVE-2023-4911 glibc</title>
   <reference source="CVE" ref_id="CVE-2023-4911"/></metadata>
   <criteria><criterion test_ref="tst:1"/><criteria><criterion test_ref="tst:3"/></criteria></criteria></definition>
  <definition id="d:2" class="vulnerability"><metadata><title>CVE-2099-1 sudo (unfixed)</title>
   <reference source="CVE" ref_id="CVE-2099-0001"/></metadata>
   <criteria><criterion test_ref="tst:4"/></criteria></definition>
 </definitions>
 <tests>
  <dpkginfo_test id="tst:3" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><object object_ref="obj:3"/><state state_ref="ste:3"/></dpkginfo_test>
  <dpkginfo_test id="tst:4" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><object object_ref="obj:4"/><state state_ref="ste:4"/></dpkginfo_test>
 </tests>
 <objects>
  <dpkginfo_object id="obj:3" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><name>glibc</name></dpkginfo_object>
  <dpkginfo_object id="obj:4" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><name>sudo</name></dpkginfo_object>
 </objects>
 <states>
  <dpkginfo_state id="ste:3" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><evr operation="less than">0:2.36-9+deb12u3</evr></dpkginfo_state>
  <dpkginfo_state id="ste:4" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"><evr operation="less than">0:0</evr></dpkginfo_state>
 </states>
</oval_definitions>"""


def parse(xml):
    return distrovuln.parse_oval(io.BytesIO(xml))


class DebverTests(unittest.TestCase):
    CASES = [("1.0", "1.0-1", -1), ("1:1.0", "2.0", 1), ("1.0~rc1", "1.0", -1), ("1.2~", "1.2~~", 1),
             ("1.0a", "1.0+dfsg", -1), ("2.36-9+deb12u7", "2.36-9+deb12u10", -1),
             ("3.0.13-0ubuntu3", "3.0.13-0ubuntu3.1", -1), ("1.0.00", "1.0.0", 0), ("0:2.2-1", "2.2-1", 0),
             ("7:6.1.1-3ubuntu5", "7:6.1.1-3ubuntu5+esm15", -1), ("10", "9", 1)]

    def test_documented_orderings(self):
        for a, b, want in self.CASES:
            with self.subTest(a=a, b=b):
                got = debver.compare(a, b)
                self.assertEqual((got > 0) - (got < 0), want)

    @unittest.skipUnless(shutil.which("dpkg"), "dpkg not installed")
    def test_agrees_with_dpkg(self):
        versions = sorted({v for c in self.CASES for v in c[:2]})
        for a in versions:
            for b in versions:
                lt = subprocess.run(["dpkg", "--compare-versions", a, "lt", b]).returncode == 0
                gt = subprocess.run(["dpkg", "--compare-versions", a, "gt", b]).returncode == 0
                got = debver.compare(a, b)
                self.assertEqual((got > 0) - (got < 0), -1 if lt else (1 if gt else 0), (a, b))


class OvalTests(unittest.TestCase):
    def test_ubuntu_binary_names_through_variables(self):
        idx, generated = parse(UBUNTU_OVAL)
        self.assertEqual(generated, "2026-10-23T13:49:27")
        self.assertEqual(idx["openssl"][0][:3], ["3.0.13-0ubuntu3.1", ["CVE-2024-0001", "CVE-2024-0002"], "USN-1-1 -- OpenSSL"])
        self.assertIn("libssl3t64", idx)
        self.assertNotIn("d:100", json.dumps(idx))          # inventory definitions are not fixes

    def test_debian_source_names_and_unfixed_skipped(self):
        idx, _ = parse(DEBIAN_OVAL)
        self.assertEqual(idx["glibc"][0][0], "0:2.36-9+deb12u3")
        self.assertNotIn("sudo", idx, "a 'less than 0:0' state means no fix exists")

    def test_definition_cap_and_bomb_are_refused(self):
        with mock.patch.object(distrovuln, "MAX_DEFINITIONS", 1):
            with self.assertRaises(inflate.InflateLimit):
                parse(UBUNTU_OVAL)
        bomb = bz2.compress(b"<a>" + b" " * (8 * 1024 * 1024) + b"</a>")
        with self.assertRaises(inflate.InflateLimit):
            distrovuln.parse_oval(inflate.Bounded(bz2.open(io.BytesIO(bomb)), 1024 * 1024))


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.osr = os.path.join(self.tmp, "os-release")
        with open(self.osr, "w") as fh:
            fh.write('ID=ubuntu\nVERSION_CODENAME=noble\n')

    def test_writes_index_atomically_and_reports_ok(self):
        urls = []
        def fetch(url, max_bytes, timeout):
            urls.append(url)
            return bz2.compress(UBUNTU_OVAL)
        out = distrovuln.refresh(fetch=fetch, path=self.osr, root=self.tmp, now=1000)
        self.assertEqual(out[0]["severity"], "ok")
        self.assertIn("com.ubuntu.noble.usn.oval.xml.bz2", urls[0])
        doc = distrovuln.load("ubuntu", "noble", self.tmp)
        self.assertEqual((doc["match"], doc["fetched_at"]), ("binary", 1000))

    def test_failed_download_keeps_the_old_index_and_says_so(self):
        distrovuln.refresh(fetch=lambda *a, **k: bz2.compress(UBUNTU_OVAL), path=self.osr, root=self.tmp, now=1000)
        def broken(*a, **k):
            raise OSError("timed out")
        out = distrovuln.refresh(fetch=broken, path=self.osr, root=self.tmp, now=2000)
        self.assertEqual(out[0]["severity"], "low")
        self.assertIn("last good copy", out[0]["detail"])
        self.assertEqual(distrovuln.load("ubuntu", "noble", self.tmp)["fetched_at"], 1000)

    def test_unsupported_distribution_is_stated_not_clean(self):
        with open(self.osr, "w") as fh:
            fh.write('ID=alpine\nVERSION_CODENAME=\n')
        out = distrovuln.refresh(fetch=mock.Mock(), path=self.osr, root=self.tmp)
        self.assertIn("not observed", out[0]["detail"])
        self.assertNotEqual(out[0]["severity"], "ok")


INSTALLED = {
    "openssl": ("3.0.13-0ubuntu3", "openssl", "3.0.13-0ubuntu3"),
    "libssl3t64": ("3.0.13-0ubuntu3", "openssl", "3.0.13-0ubuntu3"),
    "ffmpeg": ("7:6.1.1-3ubuntu5", "ffmpeg", "7:6.1.1-3ubuntu5"),
    "libavcodec60": ("7:6.1.1-3ubuntu5", "ffmpeg", "7:6.1.1-3ubuntu5"),
    "libc6": ("2.36-9+deb12u1", "glibc", "2.36-9+deb12u1"),
}


class PatchesTests(unittest.TestCase):
    def index(self, xml=UBUNTU_OVAL, match="binary"):
        pk, gen = parse(xml)
        return {"distro": "ubuntu", "codename": "noble", "match": match, "packages": pk,
                "generated": gen, "fetched_at": 1_000_000}

    def audit(self, installed=INSTALLED, kev=frozenset(), pending=([], []), lists_age=0.5, index=None, **kw):
        def run(argv, timeout=120):
            if argv[0] == "dpkg-query":
                if installed is None:
                    return 1, ""
                return 0, "".join(f"ii \t{b}\t{v}\t{s}\t{sv}\n" for b, (v, s, sv) in installed.items())
            if argv[0] == "apt-get":
                lines = [f"Inst {p} [1] (2 noble-updates [amd64])" for p in pending[0]]
                lines += [f"Inst {p} [1] (2 noble-security [amd64])" for p in pending[1]]
                return 0, "\n".join(lines)
            return 1, ""
        with mock.patch.object(patches, "lists_age_days", return_value=lists_age), \
                mock.patch.object(patches, "reboot_state", return_value=(None, [], "")):
            return patches.audit(None, run=run, now=1_000_100, kev=set(kev),
                                 index=self.index() if index is None else index,
                                 release=("ubuntu", "noble"), **kw)

    def titles(self, out):
        return {f["title"]: f for f in out}

    def test_binary_matching_groups_by_source_and_separates_ubuntu_pro(self):
        out = self.titles(self.audit())
        plain = out["1 packages have security fixes not installed"]
        self.assertIn("openssl 3.0.13-0ubuntu3 → 3.0.13-0ubuntu3.1 (2 CVE)", plain["detail"])
        pro = out["1 packages have security fixes only through Ubuntu Pro (ESM)"]
        self.assertIn("ffmpeg", pro["detail"])
        self.assertNotIn("libavcodec60 ", pro["detail"], "one entry per source package")

    def test_known_exploited_is_high_per_package(self):
        out = self.titles(self.audit(kev={"CVE-2025-0518"}))
        f = out["known-exploited vulnerability fixed but not installed: ffmpeg"]
        self.assertEqual(f["severity"], "high")
        self.assertIn("Ubuntu Pro", f["detail"])
        self.assertNotIn("1 packages have security fixes only through Ubuntu Pro (ESM)", out)

    def test_debian_matches_source_versions(self):
        out = self.titles(self.audit(index=self.index(DEBIAN_OVAL, match="source")))
        f = out["1 packages have security fixes not installed"]
        self.assertIn("glibc 2.36-9+deb12u1 → 0:2.36-9+deb12u3", f["detail"])
        installed = dict(INSTALLED, libc6=("2.36-9+deb12u3", "glibc", "2.36-9+deb12u10"))
        out = self.titles(self.audit(installed=installed, index=self.index(DEBIAN_OVAL, match="source")))
        self.assertIn("no published security fix is missing", out)

    def test_nothing_missing_is_ok_with_provenance(self):
        current = {k: (v[0].replace("ubuntu3", "ubuntu9"), v[1], v[2].replace("ubuntu3", "ubuntu9"))
                   for k, v in INSTALLED.items() if k in ("openssl", "libssl3t64")}
        out = self.titles(self.audit(installed=current))
        self.assertEqual(out["no published security fix is missing"]["severity"], "ok")

    def test_stale_lists_and_missing_index_are_not_clean(self):
        out = self.audit(lists_age=30, index={}, pending=([], ["openssl"]))
        titles = self.titles(out)
        self.assertEqual(titles["package lists are stale — pending updates unknown"]["severity"], "medium")
        self.assertIn("fixable CVEs not observed yet", titles)
        self.assertEqual(titles["1 security updates pending"]["severity"], "medium")
        self.assertFalse(any(f["severity"] == "ok" for f in out))

    def test_unreadable_package_database_is_not_observed(self):
        out = self.audit(installed=None)
        self.assertEqual(out[0]["title"], "installed packages could not be read")

    def test_reboot_pending_escalates_after_a_day_or_on_a_newer_kernel(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        marker = os.path.join(tmp, "reboot-required")
        open(marker, "w").close()
        with open(marker + ".pkgs", "w") as fh:
            fh.write("libc6\nlinux-image-6.8.0-50-generic\n")
        os.utime(marker, (1000, 1000))
        for k in ("6.8.0-45-generic", "6.8.0-50-generic"):
            os.makedirs(os.path.join(tmp, "modules", k, "kernel"))
        since, why, kernel = patches.reboot_state(1000 + 3600, marker, os.path.join(tmp, "modules"),
                                                  running="6.8.0-45-generic")
        self.assertEqual((since, kernel), (1000, "6.8.0-50-generic"))
        self.assertIn("libc6", why)
        with mock.patch.object(patches, "reboot_state", return_value=(1000, ["libc6"], "")):
            self.assertEqual(patches._reboot(1000 + 3600)[0]["severity"], "low")
            self.assertEqual(patches._reboot(1000 + 2 * 86400)[0]["severity"], "medium")


class HeartbeatTests(unittest.TestCase):
    URL = "https://hc-ping.com/00000000-secret-token"

    class Store:
        def __init__(self):
            self.meta = {}

        def get_meta(self, k, d=None):
            return self.meta.get(k, d)

        def set_meta(self, k, v):
            self.meta[k] = v

    def opener(self, status=200, exc=None):
        calls = []

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def open_(req, timeout):
            calls.append((req.get_method(), req.full_url, req.data, timeout))
            if exc:
                raise exc
            r = Resp(b"OK")
            r.status = status
            return r
        return open_, calls

    def test_no_url_is_a_visible_low_finding(self):
        [f] = heartbeat.run(self.Store(), conf={})
        self.assertEqual(f["severity"], "low")
        self.assertIn("nothing outside this machine notices", f["title"])

    def test_plain_http_is_refused_without_sending(self):
        opener, calls = self.opener()
        [f] = heartbeat.run(self.Store(), conf={"heartbeat_url": "http://hc-ping.com/x"}, opener=opener)
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(calls, [])

    def test_success_is_one_bodiless_get_and_the_url_never_leaks(self):
        store = self.Store()
        opener, calls = self.opener()
        [f] = heartbeat.run(store, conf={"heartbeat_url": self.URL}, now=100, opener=opener)
        self.assertEqual(f["severity"], "ok")
        self.assertEqual(calls, [("GET", self.URL, None, heartbeat.TIMEOUT_S)])
        self.assertNotIn("secret-token", json.dumps(f) + json.dumps(store.meta))

    def test_failures_escalate_after_five_and_reset_on_success(self):
        import urllib.error
        store = self.Store()
        boom = urllib.error.URLError(OSError("connection refused " + self.URL))
        bad, _ = self.opener(exc=boom)
        sev = [heartbeat.run(store, conf={"heartbeat_url": self.URL}, now=i, opener=bad)[0]["severity"]
               for i in range(heartbeat.FAILING_AFTER)]
        self.assertEqual(sev, ["low"] * (heartbeat.FAILING_AFTER - 1) + ["medium"])
        self.assertNotIn("secret-token", json.dumps(store.meta))
        good, _ = self.opener()
        self.assertEqual(heartbeat.run(store, conf={"heartbeat_url": self.URL}, now=99, opener=good)[0]["severity"], "ok")
        self.assertEqual(json.loads(store.meta[heartbeat.META])["failures"], 0)

    def test_http_error_status_is_a_failure(self):
        bad, _ = self.opener(status=503)
        [f] = heartbeat.run(self.Store(), conf={"heartbeat_url": self.URL}, opener=bad)
        self.assertIn("HTTP 503", f["detail"])


if __name__ == "__main__":
    unittest.main()
