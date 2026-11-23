"""Collectors that parse text an attacker can influence: sshd logs, journal JSON,
Sysmon XML, sshd_config / authorized_keys, package-manager output."""

import io
import json
import os
import tempfile

from jarvis.collectors.host import updates
from jarvis.collectors.identity import bruteforce, logins, sshwatch
from jarvis.collectors.telemetry.sysmon_linux import journal as sysmon_journal
from jarvis.platform.native import normalize
from tests.fuzz.engine import Target

TRUE_IP = "198.51.100.7"


def sshd_user(name):
    """What sshd writes for a client-chosen user name: at most 100 characters
    (%.100s), non-printable bytes as \\ooo octal (strnvis VIS_SAFE|VIS_OCTAL).
    Spaces and printable punctuation are written as they are."""
    out = []
    for ch in name[:100]:
        out.append(ch if 0x20 <= ord(ch) < 0x7f else "".join(f"\\{b:03o}" for b in ch.encode()))
    return "".join(out)


# --- sshd failed-login attribution --------------------------------------------------

def run_logins_attribution(name):
    """Oracle: a failure is charged to the address sshd itself wrote at the end of the
    line, whatever user name the remote client chose."""
    user = sshd_user(name)
    lines = [f"Invalid user {user} from {TRUE_IP} port 4242",
             f"Failed password for invalid user {user} from {TRUE_IP} port 4242 ssh2"]
    _events, _state, failures = logins.evaluate([(1000.0, ln) for ln in lines], {}, {}, 1000.0)
    wrong = sorted(ip for ip in failures if ip != TRUE_IP)
    assert not wrong, (f"logins: failures charged to {wrong} instead of {TRUE_IP} for user name {user!r}")


def run_bruteforce_attribution(name):
    user = sshd_user(name)
    lines = [f"Failed password for invalid user {user} from {TRUE_IP} port 4242 ssh2"] * 30
    findings = bruteforce._linux(lines)
    titles = " ".join(f["title"] for f in findings)
    assert TRUE_IP in titles, f"bruteforce: 30 failures from {TRUE_IP} not attributed to it (user {user!r}): {titles}"


# --- journal JSON readers -----------------------------------------------------------

class _FakePopen:
    def __init__(self, text):
        self.stdout = io.StringIO(text)
        self.returncode = 0

    def communicate(self, timeout=None):
        return "", ""

    def kill(self):
        pass


def run_logins_journal(text):
    logins.read_journal(None, run=lambda *a, **k: _FakePopen(text))


def run_bruteforce_journal(text):
    bruteforce._linux(bruteforce._journal_messages(text))


# --- Sysmon XML -----------------------------------------------------------------------

def run_sysmon_linux(text):
    sysmon_journal._parse(text)


def run_native_parse(text):
    normalize.parse(text)


# --- sshd configuration and keys --------------------------------------------------------

def run_sshd_config(text):
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "etc/ssh/sshd_config.d"))
        main = os.path.join(root, "etc/ssh/sshd_config")
        with open(main, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(text)
        cfg, matches, _files, _problems = sshwatch.parse_sshd_config(main, root=root)
        sshwatch.policy_findings(cfg, matches, main)
        sshwatch.ports_of(cfg)


def run_key_line(text):
    for line in text.splitlines() or [""]:
        parsed = sshwatch.parse_key_line(line)
        if parsed:
            sshwatch.fingerprint(parsed[2])
            sshwatch.rsa_bits(parsed[2])
    sshwatch.client_tunnels(["ssh"] + text.split())


# --- package managers -------------------------------------------------------------------

WINGET_HEAD = ("Name                                         Id                          Version        "
               "Available      Source\n" + "-" * 112 + "\n")
WINGET_ROWS = [("Example Browser", "Example.Browser", "120.0.1", "121.0.0"),
               ("Git", "Git.Git", "2.53.0", "2.56.0.4"),
               ("Plain Game", "Studio.PlainGame", "1.0", "1.1")]


def _row(name, pid, ver, avail):
    return f"{name:<45}{pid:<28}{ver:<15}{avail:<15}winget"


def run_winget_rows(name):
    """Oracle: one row with an unusual display name (installed programs name
    themselves, including user-scope ones) must not hide the rows after it."""
    name = " ".join(name.split()) or "x"
    table = WINGET_HEAD + "\n".join([_row(name, "Odd.App", "1.0", "2.0")] +
                                    [_row(*r) for r in WINGET_ROWS]) + "\n4 upgrades available.\n"
    ids = {i["id"] for i in updates.parse_winget(table)}
    missing = [r[1] for r in WINGET_ROWS if r[1] not in ids]
    assert not missing, f"winget: rows {missing} dropped after a row named {name!r}"


def run_pkg_parsers(text):
    updates.parse_apt(text)
    updates.parse_snap(text)
    updates.parse_winget(text)
    updates.parse_choco(text)


def run_brew(text):
    updates.parse_brew(text)


JOURNAL_SEED = "\n".join(json.dumps(r) for r in [
    {"__CURSOR": "s=1", "__REALTIME_TIMESTAMP": "1730000000000000", "_UID": "0",
     "MESSAGE": f"Accepted publickey for chris from {TRUE_IP} port 5 ssh2: ED25519 SHA256:abc"},
    {"__CURSOR": "s=2", "__REALTIME_TIMESTAMP": "1730000001000000", "_UID": "0",
     "MESSAGE": [70, 97, 105, 108, 101, 100]},
    {"__CURSOR": "s=3", "_UID": "1000", "MESSAGE": f"Invalid user a from {TRUE_IP} port 1"},
])
SYSMON_SEED = ("<Event><System><EventID>1</EventID><TimeCreated SystemTime=\"2026-09-04T12:07:02Z\"/>"
               "</System><EventData><Data Name=\"UtcTime\">2026-09-04 11:17:40.544</Data>"
               "<Data Name=\"Image\">/usr/bin/example</Data><Data Name=\"CommandLine\">a &lt;b&gt;</Data>"
               "</EventData></Event>")
NATIVE_SEED = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
               "<Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID></System><EventData>"
               "<Data Name='Image'>C:\\x\\a.exe</Data></EventData><UserData><A><B>t</B></A></UserData></Event>")
SSHD_SEED = ("Port 22\nPasswordAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\n"
             "Ciphers aes256-gcm@openssh.com,aes128-cbc\nSubsystem sftp /usr/lib/openssh/sftp-server\n"
             "Match User git\n  PasswordAuthentication yes\nListenAddress [::1]:2222\n")
KEY_SEED = ('command="echo hi",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl a@b\n'
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDA x\n-R 8080:localhost:22 -o RemoteForward=1 host")
APT_SEED = ("Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-security [amd64])\n"
            "Name Version Rev\nfirefox 130 4\nx|1|2|false\n")
BREW_SEED = json.dumps({"formulae": [{"name": "openssl@3", "installed_versions": ["3.3.1"],
                                      "current_version": "3.3.2", "pinned": False}], "casks": []})

TARGETS = [
    Target("logins.attribution", run_logins_attribution,
           ["admin", "bob from 203.0.113.9", "x from 10.0.0.1 port 22"],
           tokens=(" from ", "203.0.113.9", " port 22", " ssh2", "invalid user "), max_len=120,
           note="property: client-chosen user names cannot move a failure to another address"),
    Target("bruteforce.attribution", run_bruteforce_attribution,
           ["admin", "bob from 203.0.113.9", "x from 10.0.0.1 port 22 ssh2"],
           tokens=(" from ", "203.0.113.9", " port 22", " ssh2", " [preauth]"), max_len=120),
    Target("logins.read_journal", run_logins_journal, [JOURNAL_SEED],
           tokens=('"MESSAGE"', "[", "256", "-1", '"__CURSOR"', "null"), max_len=4096),
    Target("bruteforce.journal", run_bruteforce_journal, [JOURNAL_SEED],
           tokens=('"MESSAGE"', '"_UID": "0"', "[", "256"), max_len=4096),
    Target("sysmon_linux.parse", run_sysmon_linux, [SYSMON_SEED, "ProcessCreate:\n  Image: /bin/x\n\n"],
           tokens=("<Event", "</Event>", "<EventID>", "x", "<Data Name=\"", "&#", "<!DOCTYPE"), max_len=8192),
    Target("native.parse", run_native_parse, [NATIVE_SEED], expected=(normalize.NormalizeError,),
           tokens=("<!ENTITY", "&x;", "<![CDATA[", "<Data", "</Data>", "xmlns"), max_len=8192),
    Target("sshwatch.config", run_sshd_config, [SSHD_SEED],
           tokens=("Match ", "Include ", "=", "\"", "#", "Port ", "ListenAddress ", "Subsystem "),
           max_len=2048, timeout_s=3.0),
    Target("sshwatch.keys", run_key_line, [KEY_SEED],
           tokens=('"', ",", "ssh-ed25519 ", "-R", "-oRemoteForward", " "), max_len=2048),
    Target("updates.winget_rows", run_winget_rows,
           ["Example", "The following game", "Price cannot be determined", "x  y"],
           tokens=("the following", "cannot be determined", "require explicit targeting", "upgrades available",
                   "\u2026", "<", "winget"), max_len=60,
           note="property: an installed program's display name cannot hide other updates"),
    Target("updates.parsers", run_pkg_parsers, [APT_SEED, WINGET_HEAD + _row(*WINGET_ROWS[0])],
           tokens=("Inst ", "|", "---", "<", "winget", "msstore"), max_len=4096),
    Target("updates.brew", run_brew, [BREW_SEED, "[]", "null"],
           tokens=("[", "{", "null", "1", '"installed_versions"', '"formulae"'), max_len=1024),
]
