"""SSH watch: what the SSH server allows, every key that can log in, and the
tunnels open right now (ARGUS-SERVER.md, Linux servers).

The neighbours each read one slice: `logins` reads sshd's Accepted records,
`bruteforce` the failures, `backdoor` the keys in ~/.ssh/authorized_keys of
human accounts and five risky sshd_config lines. This reads the rest, the way
sshd itself would:

    policy    the effective sshd configuration: Include files followed, first
              value wins (sshd's rule), Match blocks kept apart, defaults applied
              where nothing is set. Passwords accepted, user environment
              (LD_PRELOAD through ~/.ssh/environment), logging turned down so
              logins go unrecorded, StrictModes off, weak algorithms, and
              Subsystem commands that are not an SFTP server.
    files     sshd_config and its includes writable by anyone but root, host
              private keys readable by others, /etc/ssh/sshrc and ~/.ssh/rc
              (both run on every login), and the host key fingerprints, learned
              once: a host key that changes is a replaced server identity.
    keys      every AuthorizedKeysFile path of every account, system accounts
              and the authorized_keys2 file of the default included: a key
              added since the last run, a key on a service account, a key in a
              file the backdoor audit does not read, weak keys, key files others
              can write.
    tunnels   ports sshd listens on beyond its configured ones (a client's
              remote forward, -R, landing on this host), SSH client processes
              here opening reverse (-R), SOCKS (-D) or tun (-w) tunnels, and
              the inbound sessions open now.

Invariants (tests/test_sshwatch.py holds each):
    I1  a file or process that cannot be read is reported as not observed,
        never as clean
    I2  the first run learns keys and host keys and pages only for what is
        risky in itself; drift is reported from the second run on
    I3  bounded: file sizes, accounts, keys, includes, processes and the kept
        events all have ceilings
    I4  read-only; host private keys are only stat()ed, and only public key
        fingerprints, types and comments are stored
    I5  stored state that cannot be parsed is relearned, and says so
"""

import base64
import glob
import hashlib
import ipaddress
import json
import os
import re
import shlex
import stat
import struct
import time

try:
    import pwd
except ImportError:      # native Windows: no passwd database, and no caller there
    pwd = None

from jarvis.core import safeio
from jarvis.core.finding import finding as _finding

STATE_META = "sshwatch_state_v1"     # {"learned_at", "keys": {acct: {fp: {...}}}, "hostkeys": {path: fp}}
EVENTS_META = "sshwatch_events_v1"   # [{"ts", "kind", ...}] last day of drift events

MAX_FILE = 256 * 1024
MAX_INCLUDE_DEPTH = 8
MAX_CONFIG_FILES = 64
MAX_ACCOUNTS = 5000
MAX_KEYS_PER_FILE = 1000
MAX_KEYS_STORED = 20000
MAX_PIDS = 65536
MAX_EVENTS = 500
KEEP_S = 24 * 3600
MAX_LISTED = 5

SSHD_NAMES = {"sshd", "sshd-session", "sshd-auth"}
CLIENT_NAMES = {"ssh", "autossh"}

# Upstream OpenSSH defaults for the keywords judged here (sshd_config(5)).
DEFAULTS = {
    "passwordauthentication": "yes",
    "kbdinteractiveauthentication": "yes",
    "usepam": "no",
    "permituserenvironment": "no",
    "loglevel": "INFO",
    "strictmodes": "yes",
    "authorizedkeysfile": ".ssh/authorized_keys .ssh/authorized_keys2",
    "port": "22",
}
# Keywords sshd accumulates instead of keeping the first value.
MULTI = {"port", "listenaddress", "hostkey", "include", "acceptenv", "setenv"}
ALIASES = {"challengeresponseauthentication": "kbdinteractiveauthentication"}
QUIET_LEVELS = {"quiet", "fatal", "error"}
WEAK_ALGO = re.compile(
    r"(?:^|[,+^-])(3des-cbc|aes\d+-cbc|blowfish-cbc|cast128-cbc|arcfour\w*|rijndael-cbc\S*"
    r"|hmac-md5\S*|hmac-sha1-96\S*|umac-64\S*"
    r"|diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1"
    r"|ssh-dss\S*)(?=,|$)", re.I)
ALGO_KEYWORDS = ("ciphers", "macs", "kexalgorithms", "hostkeyalgorithms",
                 "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes")
SFTP_RE = re.compile(r"(^|/)(sftp-server|internal-sftp)(\s|$)")
KEY_TYPES = re.compile(r"^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+@openssh\.com|\S+-cert-v01@openssh\.com)$")


def _split_options(opts):
    """authorized_keys options split on commas outside double quotes, in one
    pass (the lookahead regex this replaces was quadratic in the comma count)."""
    out, cur, quoted = [], [], False
    for ch in opts:
        if ch == '"':
            quoted = not quoted
        if ch == "," and not quoted:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _read(path, limit=MAX_FILE):
    """(text, problem). problem is "" when read, "missing" or a reason."""
    # authorized_keys lives in folders other users own: a FIFO there would
    # block a plain open() forever and stall the lane (safeio).
    try:
        data = safeio.read_regular(path, limit)
    except FileNotFoundError:
        return "", "missing"
    except OSError as exc:
        return "", exc.strerror or str(exc)
    if len(data) > limit:
        return data[:limit].decode("utf-8", "replace"), f"larger than {limit} bytes; the rest was not read"
    return data.decode("utf-8", "replace"), ""


# ── the effective sshd configuration ─────────────────────────────────────

def _tokens(line):
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError:
        return line.split()


def parse_sshd_config(path, root="/"):
    """(global, matches, files, problems).

    global: keyword -> (value, "file:line"), first value wins; MULTI keywords
    keep a list of values. matches: [(criteria, {keyword: (value, where)})].
    files: every config file read. Include globs resolve against /etc/ssh as
    sshd does; depth and file count are bounded (I3)."""
    glob_cfg, matches, files, problems = {}, [], [], []
    current = [glob_cfg]
    etc_ssh = os.path.join(root, "etc/ssh")

    def walk(p, depth):
        if depth > MAX_INCLUDE_DEPTH:
            problems.append(f"{p}: Include nested deeper than {MAX_INCLUDE_DEPTH}; not followed")
            return
        if len(files) >= MAX_CONFIG_FILES:
            problems.append(f"more than {MAX_CONFIG_FILES} sshd config files; {p} not read")
            return
        text, problem = _read(p)
        if problem == "missing" and depth == 0:
            return
        files.append(p)
        if problem and problem != "missing":
            problems.append(f"{p}: {problem}")
        for n, raw in enumerate(text.splitlines(), 1):
            toks = _tokens(raw)
            if not toks:
                continue
            if "=" in toks[0]:              # sshd also accepts Keyword=value
                head, _eq, rest = toks[0].partition("=")
                toks = [head] + ([rest] if rest else []) + toks[1:]
            key = ALIASES.get(toks[0].lower(), toks[0].lower())
            value = " ".join(toks[1:])
            where = f"{p}:{n}"
            if key == "match":
                block = {}
                matches.append((value, block))
                current[0] = block
                continue
            if key == "include":
                for pattern in toks[1:]:
                    if root != "/" and pattern.startswith("/"):
                        pattern = os.path.join(root, pattern.lstrip("/"))
                    elif not pattern.startswith("/"):
                        pattern = os.path.join(etc_ssh, pattern)
                    try:
                        found = sorted(glob.glob(pattern))
                    except ValueError:          # a NUL in the pattern (FZ-07)
                        problems.append(f"{where}: Include {pattern!r} is not a usable path")
                        continue
                    for inc in found:
                        walk(inc, depth + 1)
                continue
            target = current[0]
            if key in MULTI:
                target.setdefault(key, []).append((value, where))
            elif key == "subsystem":
                # "Subsystem name" without a command is refused by sshd; it used to be
                # stored as a plain value, and the next Subsystem line or the policy
                # check then crashed the whole SSH audit (FZ-07).
                if len(toks) >= 3:
                    target.setdefault("subsystem", {}).setdefault(toks[1], (" ".join(toks[2:]), where))
                else:
                    problems.append(f"{where}: Subsystem without a command; sshd refuses this line")
            elif key not in target:
                target[key] = (value, where)

    walk(path, 0)
    return glob_cfg, matches, files, problems


def effective(cfg, key):
    """(value, where) of a single-valued keyword, the default when unset."""
    if key in cfg:
        return cfg[key]
    return DEFAULTS.get(key, ""), "default"


def _yes(value):
    return value.strip().lower().split()[:1] == ["yes"]


def policy_findings(cfg, matches, main_path):
    out = []

    def risky(key, test, sev, title, why):
        value, where = effective(cfg, key)
        if test(value):
            src = "OpenSSH default, nothing sets it" if where == "default" else where
            out.append(_finding("remote access", sev, title, f"{why} ({key} {value}; {src})", main_path))
        for crit, block in matches:
            if key in block and test(block[key][0]):
                out.append(_finding("remote access", sev, f"{title} (Match {crit})",
                                    f"{why} ({key} {block[key][0]}; {block[key][1]})", main_path))

    risky("passwordauthentication", _yes, "medium", "SSH accepts passwords",
          "every account with a password can be guessed over the network; keys cannot")
    if _yes(effective(cfg, "usepam")[0]):
        risky("kbdinteractiveauthentication", _yes, "medium", "SSH accepts PAM keyboard-interactive logins",
              "with UsePAM this asks for the account password even where PasswordAuthentication is off")
    risky("permituserenvironment", lambda v: v.strip().lower() not in ("no", ""), "high",
          "SSH lets users set their login environment",
          "~/.ssh/environment and environment= key options can set LD_PRELOAD and run code in sshd's child")
    risky("loglevel", lambda v: v.strip().lower() in QUIET_LEVELS, "high",
          "SSH logins are not logged",
          "below INFO sshd writes no Accepted records: logins leave no trace and the login audit sees none")
    risky("strictmodes", lambda v: v.strip().lower() == "no", "medium",
          "SSH does not check key file permissions",
          "keys in files other accounts can write are accepted")
    for key in ALGO_KEYWORDS:
        risky(key, lambda v: bool(WEAK_ALGO.search(v.replace(" ", ""))), "medium",
              "SSH offers weak algorithms",
              "broken ciphers, MACs, key exchanges or DSA keys are enabled")
    value, where = effective(cfg, "authorizedkeysfile")
    usual = {".ssh/authorized_keys", ".ssh/authorized_keys2", "%h/.ssh/authorized_keys", "%h/.ssh/authorized_keys2"}
    if where != "default" and not set(value.split()) <= usual:
        out.append(_finding("remote access", "low", "SSH reads keys from a non-default place",
                            f"AuthorizedKeysFile {value} ({where}); the keys there are audited below",
                            main_path))
    for blocks in [cfg] + [b for _c, b in matches]:
        for name, (cmd, w) in sorted((blocks.get("subsystem") or {}).items()):
            if not SFTP_RE.search(cmd):
                out.append(_finding("remote access", "high", f"SSH subsystem {name} runs {cmd.split()[0]}",
                                    f"any account that can log in can start it on demand ({w})", main_path))
    return out


def ports_of(cfg):
    ports = {int(v) for v, _w in cfg.get("port", []) if v.isdigit()}
    for v, _w in cfg.get("listenaddress", []):
        addr = (v.split() or [""])[0]
        m = re.search(r"\]:(\d+)$", addr) if addr.startswith("[") else (
            re.search(r":(\d+)$", addr) if addr.count(":") == 1 else None)
        if m:
            ports.add(int(m.group(1)))
    return ports or {22}


# ── files: config ownership, host keys, login scripts ────────────────────

def _writable_by_others(st):
    return st.st_uid != 0 or bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def _group_name(gid):
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        return ""


def fingerprint(blob_b64):
    """OpenSSH's SHA256 fingerprint of a base64 public key blob, or ""."""
    try:
        raw = base64.b64decode(blob_b64, validate=True)
    except (ValueError, TypeError):
        return ""
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def rsa_bits(blob_b64):
    """Modulus size of an ssh-rsa public key blob, 0 when it cannot be parsed."""
    try:
        raw = base64.b64decode(blob_b64, validate=True)
        fields, pos = [], 0
        for _ in range(3):
            (n,) = struct.unpack(">I", raw[pos:pos + 4])
            fields.append(raw[pos + 4:pos + 4 + n])
            pos += 4 + n
        modulus = fields[2].lstrip(b"\0")
        return len(modulus) * 8 - (8 - modulus[0].bit_length()) if modulus else 0
    except (ValueError, TypeError, struct.error, IndexError):
        return 0


def file_findings(cfg, files, root="/"):
    out, hostkeys = [], {}
    etc_ssh = os.path.join(root, "etc/ssh")
    for p in [etc_ssh] + files:
        try:
            st = os.stat(p)
        except OSError:
            continue
        if _writable_by_others(st):
            out.append(_finding("remote access", "critical", "SSH server configuration can be changed by non-root",
                                f"{p}: owner uid {st.st_uid}, mode {oct(st.st_mode & 0o777)}; whoever can "
                                "write it decides who may log in", p))
    keys = [v for v, _w in cfg.get("hostkey", [])] or [
        f"/etc/ssh/ssh_host_{t}_key" for t in ("rsa", "ecdsa", "ed25519")]
    for key in keys:
        path = os.path.join(root, key.lstrip("/")) if root != "/" else key
        try:
            st = os.stat(path)        # I4: never opened
        except OSError:
            continue
        loose = st.st_mode & stat.S_IROTH or (st.st_mode & stat.S_IRGRP and _group_name(st.st_gid) != "ssh_keys")
        if loose or st.st_uid != 0:
            out.append(_finding("remote access", "critical", "SSH host private key readable by others",
                                f"{path}: owner uid {st.st_uid}, mode {oct(st.st_mode & 0o777)}; a copy lets "
                                "someone impersonate this server", path))
        text, _p = _read(path + ".pub", 16384)
        parts = text.split()
        if len(parts) >= 2:
            fp = fingerprint(parts[1])
            if fp:
                hostkeys[key] = fp
    sshrc = os.path.join(etc_ssh, "sshrc")
    if os.path.exists(sshrc):
        out.append(_finding("persistence", "high", "/etc/ssh/sshrc runs on every SSH login",
                            "a script sshd runs for every account at login; confirm you put it there", sshrc))
    return out, hostkeys


# ── authorised keys of every account ─────────────────────────────────────

def parse_key_line(line):
    """(options, type, blob, comment) of an authorized_keys line, or None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Options may hold quoted strings with spaces: walk to the first key type.
    toks, buf, quoted = [], "", False
    for ch in line:
        if ch == '"':
            quoted = not quoted
        if ch in " \t" and not quoted:
            if buf:
                toks.append(buf)
                buf = ""
            continue
        buf += ch
    if buf:
        toks.append(buf)
    for i, t in enumerate(toks[:3]):
        if KEY_TYPES.match(t) and i + 1 < len(toks):
            return " ".join(toks[:i]), t, toks[i + 1], " ".join(toks[i + 2:])
    return None


def _accounts(passwd=None):
    if passwd is not None:
        return passwd[:MAX_ACCOUNTS]
    try:
        return [(p.pw_name, p.pw_uid, p.pw_dir, p.pw_shell) for p in pwd.getpwall()][:MAX_ACCOUNTS]
    except Exception:
        return []


def key_files(account, home, patterns, root="/"):
    out = []
    for pat in patterns.split():
        p = pat.replace("%%", "\0").replace("%h", home).replace("%u", account).replace("%U", "")
        p = p.replace("\0", "%")
        if not p.startswith("/"):
            p = os.path.join(home, p)
        if root != "/":
            p = os.path.join(root, p.lstrip("/"))
        out.append(p)
    return out


def scan_keys(cfg, passwd=None, root="/"):
    """(inventory, findings, unreadable). inventory: acct -> fp -> record."""
    patterns = effective(cfg, "authorizedkeysfile")[0]
    if patterns.strip().lower() == "none":
        return {}, [], []
    inventory, out, unreadable = {}, [], []
    default_file = ".ssh/authorized_keys"
    for name, uid, home, shell in _accounts(passwd):
        if not home or home == "/nonexistent":
            continue
        for path in key_files(name, home, patterns, root):
            text, problem = _read(path)
            if problem == "missing":
                continue
            if problem and not text:
                unreadable.append(f"{path} ({problem})")
                continue
            try:
                st = os.stat(path)
                if st.st_uid not in (0, uid) or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    out.append(_finding("remote access", "critical", f"SSH key file of {name} writable by others",
                                        f"owner uid {st.st_uid}, mode {oct(st.st_mode & 0o777)}: someone "
                                        "else can add a key that logs in as this account", path))
            except OSError:
                pass
            n = 0
            for line in text.splitlines():
                parsed = parse_key_line(line)
                if not parsed:
                    continue
                n += 1
                if n > MAX_KEYS_PER_FILE:
                    unreadable.append(f"{path} (more than {MAX_KEYS_PER_FILE} keys; the rest not read)")
                    break
                opts, ktype, blob, comment = parsed
                fp = fingerprint(blob)
                if not fp:
                    continue
                bits = rsa_bits(blob) if ktype == "ssh-rsa" else 0
                inventory.setdefault(name, {})[fp] = {
                    "file": path, "type": ktype, "bits": bits, "comment": comment[:120],
                    "options": [o.split("=", 1)[0] for o in _split_options(opts) if o][:12]}
                label = f"{ktype} {fp} {comment[:60] or '(no comment)'}"
                nologin = (shell or "").endswith(("nologin", "false"))
                if 0 < uid < 1000:
                    out.append(_finding("remote access", "high", f"SSH key on service account {name}",
                                        f"{label} in {path}; service accounts rarely need one"
                                        + ("; its nologin shell still allows tunnels (-N)" if nologin else ""),
                                        path))
                elif not path.endswith("/" + default_file) and (uid == 0 or uid >= 1000):
                    out.append(_finding("remote access", "high", f"SSH key for {name} in {os.path.basename(path)}",
                                        f"{label}: a file sshd accepts that is easy to overlook", path))
                if ktype.startswith("ssh-dss") or (ktype == "ssh-rsa" and 0 < bits < 2048):
                    out.append(_finding("remote access", "medium", f"weak SSH key for {name}",
                                        f"{label} ({'DSA' if 'dss' in ktype else f'RSA {bits} bits'})", path))
                if "environment=" in opts:
                    out.append(_finding("remote access", "medium", f"SSH key for {name} sets environment variables",
                                        f"{label}: honoured only when PermitUserEnvironment allows it", path))
        for extra, sev, why in ((".ssh/rc", "high", "runs on every SSH login of this account"),
                                (".ssh/environment", "medium",
                                 "sets the login environment when PermitUserEnvironment allows it")):
            p = os.path.join(home, extra)
            if root != "/":
                p = os.path.join(root, p.lstrip("/"))
            if os.path.isfile(p):
                out.append(_finding("persistence", sev, f"~/{extra} for {name}", why, p))
    return inventory, out, unreadable


# ── live sessions and tunnels ────────────────────────────────────────────

def _proc_names(proc):
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()][:MAX_PIDS]
    except OSError:
        return []
    out = []
    for pid in pids:
        try:
            with open(f"{proc}/{pid}/comm", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        if comm in SSHD_NAMES or comm in CLIENT_NAMES:
            out.append((int(pid), comm))
    return out


def _cmdline(proc, pid):
    try:
        with open(f"{proc}/{pid}/cmdline", "rb") as fh:
            return [a.decode("utf-8", "replace") for a in fh.read(65536).split(b"\0") if a]
    except OSError:
        return []


def _uid(proc, pid):
    try:
        with open(f"{proc}/{pid}/status", errors="replace") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return -1


def _sock_inodes(proc, pid):
    """Socket inodes of a pid, or None when its fds cannot be read."""
    fddir = f"{proc}/{pid}/fd"
    try:
        fds = os.listdir(fddir)
    except OSError:
        return None
    out = set()
    for fd in fds[:4096]:
        try:
            target = os.readlink(f"{fddir}/{fd}")
        except OSError:
            continue
        if target.startswith("socket:["):
            out.add(int(target[8:-1]))
    return out


CLIENT_FLAGS = {"-R": ("high", "reverse SSH tunnel from this host",
                       "opens a port on {dest} that leads back into this machine"),
                "-w": ("high", "SSH tun device tunnel from this host", "routes whole networks to {dest}"),
                "-D": ("medium", "SSH SOCKS proxy on this host",
                       "anything that reaches the local port is relayed through {dest}")}
CLIENT_OPTS = {"remoteforward": "-R", "tunnel": "-w", "dynamicforward": "-D"}


def client_tunnels(argv):
    """[(flag, dest)] tunnels an ssh/autossh command line opens."""
    flags, dest, i = [], "", 1
    takes_arg = set("BbcDEeFIiJLlmOoPpQRSWw")
    while i < len(argv):
        a = argv[i]
        if a.startswith("-") and len(a) > 1 and a != "--":
            j = 1
            while j < len(a):
                ch = a[j]
                if ch in takes_arg:
                    val = a[j + 1:] or (argv[i + 1] if i + 1 < len(argv) else "")
                    if f"-{ch}" in CLIENT_FLAGS:
                        flags.append(f"-{ch}")
                    if ch == "o":
                        k = re.split(r"[ =]", val, maxsplit=1)[0].lower()
                        if k in CLIENT_OPTS:
                            flags.append(CLIENT_OPTS[k])
                    if not a[j + 1:]:
                        i += 1
                    break
                j += 1
        elif not dest:
            dest = a
        i += 1
    return [(f, dest or "?") for f in dict.fromkeys(flags)]


def _is_loopback(ip):
    """/proc/net renders ::1 in full (0:0:0:0:0:0:0:1); measured on Ubuntu 24.04."""
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def live_findings(cfg, table, proc="/proc"):
    """(findings, problems): sshd forward listeners, client tunnels, sessions."""
    out, problems = [], []
    sshd_ports = ports_of(cfg)
    sessions, blind = [], 0
    for pid, comm in _proc_names(proc):
        if comm in CLIENT_NAMES:
            argv = _cmdline(proc, pid)
            for flag, dest in client_tunnels(argv):
                sev, title, why = CLIENT_FLAGS[flag]
                out.append(_finding("remote access", sev, f"{title} to {dest}",
                                    f"pid {pid} uid {_uid(proc, pid)} ({comm} {flag}): " + why.format(dest=dest),
                                    f"pid {pid}"))
            continue
        inodes = _sock_inodes(proc, pid)
        if inodes is None:
            blind += 1
            continue
        for ino in inodes:
            c = table.get(ino)
            if not c or not c["proto"].startswith("tcp"):
                continue
            if c["state"] == "LISTEN" and c["local_port"] not in sshd_ports:
                loop = _is_loopback(c["local_ip"])
                out.append(_finding("remote access", "medium" if loop else "high",
                                    f"SSH session forwards port {c['local_port']} into this host",
                                    f"sshd pid {pid} listens on {c['local_ip']}:{c['local_port']}: a client's "
                                    "remote forward (-R)" + ("" if loop else ", reachable from the network"),
                                    f"{c['local_ip']}:{c['local_port']}"))
            elif c["state"] == "ESTABLISHED" and c["local_port"] in sshd_ports:
                sessions.append(c["remote_ip"])
    if blind:
        problems.append(f"{blind} sshd processes' sockets could not be read (needs CAP_SYS_PTRACE): "
                        "forwarded ports and sessions of those are not observed")
    if sessions:
        peers = sorted(set(sessions))
        out.append(_finding("login", "low", f"{len(sessions)} SSH session(s) open now",
                            "from " + ", ".join(peers[:MAX_LISTED]) + (" …" if len(peers) > MAX_LISTED else ""),
                            "sshd"))
    return out, problems


# ── drift against the learned state ──────────────────────────────────────

def drift(state, inventory, hostkeys, now):
    """(events, state). The first run only learns (I2)."""
    learning = not state.get("learned_at")
    events = []
    old_keys = state.get("keys") or {}
    old_host = state.get("hostkeys") or {}
    if not learning:
        for acct, keys in inventory.items():
            for fp, rec in keys.items():
                if fp not in (old_keys.get(acct) or {}):
                    events.append({"ts": now, "kind": "key_added", "user": acct, "fp": fp,
                                   "file": rec["file"], "type": rec["type"], "comment": rec["comment"][:60]})
        for acct, keys in old_keys.items():
            for fp, rec in keys.items():
                if fp not in (inventory.get(acct) or {}):
                    events.append({"ts": now, "kind": "key_removed", "user": acct, "fp": fp,
                                   "file": rec.get("file", ""), "type": rec.get("type", ""),
                                   "comment": rec.get("comment", "")[:60]})
        for path, fp in hostkeys.items():
            if path in old_host and old_host[path] != fp:
                events.append({"ts": now, "kind": "hostkey_changed", "file": path, "fp": fp,
                               "old": old_host[path]})
    stored, n = {}, 0
    for acct, keys in inventory.items():
        for fp, rec in keys.items():
            if n >= MAX_KEYS_STORED:
                break
            stored.setdefault(acct, {})[fp] = rec
            n += 1
    state = {"learned_at": state.get("learned_at") or now, "keys": stored,
             "hostkeys": {**old_host, **hostkeys}}
    return events, state


EVENT_TEXT = {
    "key_added": ("high", "new SSH key for {user}", "{type} {fp} {comment} added to {file}"),
    "key_removed": ("low", "SSH key removed for {user}", "{type} {fp} {comment} no longer in {file}"),
    "hostkey_changed": ("high", "SSH host key changed",
                        "{file} is now {fp} (was {old}); clients will warn, or a replaced server is answering"),
}


def event_findings(events, now):
    out = {}
    for e in events:
        if now - e.get("ts", 0) > KEEP_S or e.get("kind") not in EVENT_TEXT:
            continue
        sev, title, detail = EVENT_TEXT[e["kind"]]
        f = _finding("remote access", sev, title.format(**e),
                     detail.format(**e) + time.strftime(" (%Y-%m-%d %H:%M UTC)", time.gmtime(e["ts"])),
                     e.get("fp", ""))
        out[(f["title"], f["where"])] = f
    return list(out.values())


def _load(store, key, default):
    raw = store.get_meta(key, "") or ""
    if not raw:
        return default, False
    try:
        v = json.loads(raw)
    except (ValueError, TypeError):
        return default, True
    return (v, False) if isinstance(v, type(default)) else (default, True)


def audit(store, hosts=None, now=None, root="/", proc="/proc", passwd=None, table=None):
    now = time.time() if now is None else now
    out, problems = [], []
    main = os.path.join(root, "etc/ssh/sshd_config")
    cfg, matches, files, cfg_problems = parse_sshd_config(main, root)
    problems += cfg_problems
    installed = bool(files)
    if installed:
        out += policy_findings(cfg, matches, main)
    elif os.path.exists(main):
        problems.append(f"{main} could not be read")
    f_out, hostkeys = file_findings(cfg, files, root)
    out += f_out
    inventory, k_out, unreadable = scan_keys(cfg, passwd, root)
    out += k_out
    # Without an sshd configuration no key can log in, so an unreadable key file
    # is not a gap in what matters (a workstation with no SSH server).
    if unreadable and installed:
        problems.append(f"{len(unreadable)} key file(s) not read: " + "; ".join(unreadable[:MAX_LISTED]))
    if table is None:
        from jarvis.platform.linux import socket_table
        table = socket_table(fresh=True)
    l_out, l_problems = live_findings(cfg, table, proc)
    out += l_out
    problems += l_problems

    state, corrupt = _load(store, STATE_META, {})
    if corrupt:
        problems.append("stored SSH key state could not be read; learning again, so changes since the "
                        "last good run are not reported")
    events, state = drift(state, inventory, hostkeys, now)
    kept, _c = _load(store, EVENTS_META, [])
    kept = [e for e in kept if isinstance(e, dict) and now - e.get("ts", 0) <= KEEP_S]
    kept = (kept + events)[-MAX_EVENTS:]
    store.set_meta(STATE_META, json.dumps(state))
    store.set_meta(EVENTS_META, json.dumps(kept))
    out += event_findings(kept, now)
    if problems:
        out.append(_finding("visibility", "medium", "SSH not fully observed", "; ".join(problems)[:1500],
                            "sshwatch"))
    return out
