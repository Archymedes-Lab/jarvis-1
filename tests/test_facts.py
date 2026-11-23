"""Host facts and per-collector requirements (jarvis/platform/facts.py, Collector.requires).

Each test names the invariant it guards. Hosts are built as small fixture trees,
so the same assertions hold on any machine the suite runs on.
"""

import os
import tempfile
import unittest

from jarvis.core import mechanisms
from jarvis.platform import facts, host
from jarvis.service import schedule

UBUNTU = 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n'
DEBIAN = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n'
ROCKY = 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\n'
ALPINE = 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.20.3\n'


def tree(files=(), dirs=()):
    root = tempfile.mkdtemp()
    for rel in dirs:
        os.makedirs(os.path.join(root, rel), exist_ok=True)
    for rel, text in dict(files).items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
    return root


def linux(os_release, kernel="6.1.0-25-amd64", extra=(), dirs=(), cgroup="0::/\n"):
    files = {"etc/os-release": os_release, "proc/sys/kernel/osrelease": kernel + "\n",
             "proc/1/cgroup": cgroup, **dict(extra)}
    return tree(files, dirs)


def probe(root, environ=None):
    return facts.probe(root, platform="linux", environ=environ or {}, which=lambda _name: None)


SERVER_BASE = ("run/systemd/system", "run/systemd/journal", "lib64")
LD = {"lib64/ld-linux-x86-64.so.2": ""}


class Parsers(unittest.TestCase):
    def test_os_release_is_parsed_and_families_resolve_through_id_like(self):
        self.assertEqual(facts.family_of(facts.parse_os_release(UBUNTU)), "debian")
        self.assertEqual(facts.family_of(facts.parse_os_release(ROCKY)), "rhel")
        self.assertEqual(facts.family_of(facts.parse_os_release(ALPINE)), "alpine")
        self.assertEqual(facts.parse_os_release(DEBIAN)["codename"], "bookworm")

    def test_unknown_stays_unknown(self):
        self.assertEqual(facts.parse_os_release(""), {})
        self.assertIsNone(facts.family_of(facts.parse_os_release('ID=plan9\n')))
        empty = probe(tree())
        for key in ("distro", "family", "init", "container", "libc", "kernel"):
            self.assertIsNone(empty[key], key)
        self.assertEqual(empty["package_dbs"], [])

    def test_container_needs_evidence_and_names_the_runtime(self):
        self.assertEqual(facts.container_kind(tree({".dockerenv": ""}), {}), "docker")
        self.assertEqual(facts.container_kind(tree({"run/.containerenv": ""}), {}), "podman")
        self.assertEqual(facts.container_kind(tree(), {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}), "kubernetes")
        self.assertEqual(facts.container_kind(tree(), {}, cgroup="0::/kubepods/burstable/pod1\n"), "kubernetes")
        self.assertIsNone(facts.container_kind(tree(), {}, cgroup="0::/init.scope\n"))

    def test_libc_is_read_from_the_loader_present(self):
        self.assertEqual(facts.libc_kind(tree({"lib/ld-musl-x86_64.so.1": ""})), "musl")
        self.assertEqual(facts.libc_kind(tree(LD)), "glibc")
        self.assertIsNone(facts.libc_kind(tree()))

    def test_reads_are_capped(self):
        root = tree({"etc/os-release": "ID=ubuntu\n" + "X=" + "a" * (facts.MAX_READ * 2) + "\n"})
        self.assertEqual(facts.probe(root, platform="linux", environ={}, which=lambda _n: None)["distro"], "ubuntu")

    def test_probe_is_deterministic(self):
        root = linux(UBUNTU, dirs=SERVER_BASE, extra={**LD, "var/lib/dpkg/status": "", "var/lib/rpm/x": ""})
        self.assertEqual(probe(root), probe(root))
        self.assertEqual(probe(root)["package_dbs"], ["dpkg", "rpm"])


class OtherSystems(unittest.TestCase):
    def test_macos_is_unsupported_not_linux(self):
        self.assertEqual(host._detect(os_name="posix", platform="darwin"), "unsupported")
        self.assertIn("does not support", host.unsupported_reason("unsupported"))
        self.assertEqual(facts.probe(tree(), platform="darwin")["supported"], False)

    def test_known_kinds_are_unchanged(self):
        self.assertEqual(host._detect(os_name="nt"), "windows")
        self.assertEqual(host._detect(os_name="posix", osrelease="6.6.87.2-microsoft-standard-WSL2",
                                      override="", platform="linux"), "wsl")
        self.assertEqual(host._detect(os_name="posix", osrelease="6.1.0-25-amd64", platform="linux"), "linux")
        self.assertEqual(host.unsupported_reason("linux"), "")


def absent_on(f, windows=False, linux_=True):
    _keep, absent = schedule.applicable(windows, linux_, facts=f)
    return absent


class Applicability(unittest.TestCase):
    def test_a_full_debian_server_keeps_every_declared_collector(self):
        f = probe(linux(DEBIAN, dirs=SERVER_BASE, extra={**LD, "var/lib/dpkg/status": "", "var/run/docker.sock": ""}))
        absent = absent_on(f)
        for name in ("pkgverify", "patches", "distrovuln", "opshealth", "bootchain", "keyreaders", "containers"):
            self.assertNotIn(name, absent, name)

    def test_this_shape_of_host_wsl_ubuntu_with_docker_loses_nothing(self):
        f = probe(linux(UBUNTU, kernel="6.18.54.1-microsoft-standard-WSL2", dirs=SERVER_BASE,
                        extra={**LD, "var/lib/dpkg/status": "", "var/run/docker.sock": ""}))
        with_facts = set(absent_on(f, windows=True))
        without = set(schedule.applicable(True, True)[1])
        self.assertEqual(with_facts, without)

    def test_rhel_family_has_no_oval_source_and_says_so(self):
        f = probe(linux(ROCKY, kernel="5.14.0-427.el9.x86_64", dirs=SERVER_BASE, extra={**LD, "var/lib/rpm/rpmdb.sqlite": ""}))
        absent = absent_on(f)
        self.assertIn("distrovuln", absent)
        self.assertIn("OVAL", absent["distrovuln"])
        self.assertNotIn("pkgverify", absent)          # rpm -V works there
        self.assertNotIn("patches", absent)            # dnf is handled

    def test_alpine_container_skips_what_it_cannot_have_and_names_why(self):
        f = probe(linux(ALPINE, dirs=(), extra={"lib/ld-musl-x86_64.so.1": "", "lib/apk/db/installed": "", ".dockerenv": ""}))
        self.assertEqual(f["container"], "docker")
        self.assertEqual(f["libc"], "musl")
        absent = absent_on(f)
        for name, word in (("bootchain", "container"), ("keyreaders", "container"), ("pkgverify", "dpkg or rpm"),
                           ("patches", "dpkg or rpm"), ("opshealth", "systemd"), ("containers", "container engine"),
                           ("distrovuln", "OVAL")):
            self.assertIn(name, absent, name)
            self.assertTrue(absent[name].startswith("not on this host: needs "), absent[name])
            self.assertIn(word, absent[name], name)

    def test_a_missing_sensor_is_never_a_reason_to_skip(self):
        # The collectors that exist to report an absent or broken sensor declare no
        # requirement, so even a bare container still runs them and shows the gap.
        for name in ("auditd", "sysmon_linux", "netflow", "heartbeat", "watchdogs", "gaps", "coverage", "selfguard"):
            self.assertEqual(mechanisms.BY_NAME[name].requires, (), name)
        f = probe(linux(ALPINE, extra={".dockerenv": ""}))
        absent = absent_on(f)
        for name in ("auditd", "sysmon_linux", "netflow", "heartbeat"):
            self.assertNotIn(name, absent, name)

    def test_unknown_facts_are_unmet_not_crashes(self):
        c = mechanisms.BY_NAME["pkgverify"]
        self.assertTrue(mechanisms.unmet(c, {}))
        self.assertTrue(mechanisms.unmet(c, {"package_dbs": None}))
        self.assertEqual(mechanisms.unmet(mechanisms.BY_NAME["scan"], {}), [])

    def test_every_declared_requirement_exists_and_says_what_it_needs(self):
        for c in mechanisms.COLLECTORS:
            for r in c.requires:
                self.assertIn(r, mechanisms.REQUIREMENTS, f"{c.name}: {r}")
        for name, (meaning, test) in mechanisms.REQUIREMENTS.items():
            self.assertTrue(meaning and callable(test), name)

    def test_no_facts_keeps_the_old_domain_rules(self):
        self.assertEqual(schedule.applicable(False, True), schedule.applicable(False, True, facts=None))


if __name__ == "__main__":
    unittest.main()
