"""Web shells — T1505.003, and the reason jarvis had a web-server blind spot.

A web shell is a script dropped into a running web server's document root that
takes a command from an HTTP parameter and runs it. It is the classic foothold
after exploiting a public-facing app, and it leaves an obvious artefact: a
server-side script file, recently written, whose contents are a command
dispatcher rather than a page.

This runs only when a web server is actually listening — no server, nothing to
audit — then walks its document root (bounded) for script files that were
written recently *and* read as a dispatcher: an exec primitive next to a
request variable, an `eval` of decoded input, an ASP page that shells out.

It cannot catch a web shell that lives only in memory (a loaded module, a
patched handler) or one written in the app's own framework. Those need request
logging or file-integrity monitoring, which this is not.
"""

import os
import re
import subprocess

from jarvis.collectors import webroots
from jarvis.core.finding import file_finding
from jarvis.core.finding import finding as _finding
from jarvis.core.paths import load_win_script
from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import ps_json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

HTTP_PORTS = {80, 443, 8080, 8443, 7001}
# Real web servers: worth auditing wherever they listen. Runtimes like node,
# java and python host web servers too, but also host dev tooling, so those
# only count on a standard HTTP port.
SERVER_HINTS = ("nginx", "httpd", "apache", "apache2", "php-fpm", "php-cgi",
                "w3wp", "tomcat", "caddy", "lighttpd")

SCRIPT_EXT = (".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".pht",
              ".asp", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx", ".jspa",
              ".cfm", ".pl", ".cgi", ".py")

COMMON_ROOTS = webroots.COMMON_ROOTS

SKIP_DIRS = {"node_modules", "vendor", ".git", ".svn", "cache", "tests",
             "test", "__pycache__", "site-packages"}

# An execution primitive.
_EXEC = re.compile(
    r"\b(system|shell_exec|passthru|popen|proc_open|pcntl_exec|exec)\s*\(|"
    r"\bRuntime\.getRuntime\(\)\.exec|\bProcessBuilder\b|"
    r"WScript\.Shell|Server\.CreateObject|\bcmd(\.exe)?\s*/c|/bin/(ba)?sh\b",
    re.I)
# Input coming straight off the request.
_INPUT = re.compile(
    r"\$_(POST|GET|REQUEST|COOKIE|SERVER)\b|php://input|"
    r"Request\.(Item|Form|QueryString|Params)|getParameter\s*\(|"
    r"os\.environ|flask\.request|django", re.I)
# eval-of-decoded-input, the compact web-shell idiom.
_EVAL_DECODE = re.compile(
    r"(eval|assert|create_function|call_user_func)\s*\(\s*"
    r"(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|pack)\s*\(|"
    r"preg_replace\s*\(\s*['\"].*?/e['\"]|"
    r"\beval\s*\(\s*(request|Request|\$_)",
    re.I)


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))


# ── finding a listening web server ─────────────────────────────────────────

def _linux_servers():
    try:
        r = subprocess.run(["ss", "-ltnpH"], capture_output=True, text=True, errors="replace",
                           timeout=15)
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    port_re = re.compile(r"[:.](\d+)\s")
    proc_re = re.compile(r'users:\(\("([^"]+)"')
    for line in r.stdout.splitlines():
        pm = port_re.search(line)
        cm = proc_re.search(line)
        if not pm:
            continue
        port = int(pm.group(1))
        proc = cm.group(1) if cm else ""
        if port in HTTP_PORTS or any(h in proc.lower() for h in SERVER_HINTS):
            found.append((port, proc or "?"))
    return found


_roots_from_config = webroots.roots_from_config
_expand = webroots.expand


# ── scanning a document root ──────────────────────────────────────────────

def _scan_root(root, max_files=6000, max_bytes=1_000_000, age_days=45):
    import time
    cutoff = time.time() - age_days * 86400
    hits, n = [], 0
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if n >= max_files:
                return hits
            ext = os.path.splitext(name)[1].lower()
            if ext not in SCRIPT_EXT:
                continue
            n += 1
            path = os.path.join(dirpath, name)
            try:
                st = os.stat(path)
                if st.st_mtime < cutoff or st.st_size > max_bytes:
                    continue
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    body = fh.read(max_bytes)
            except OSError:
                continue
            score, why = 0, []
            if _EVAL_DECODE.search(body):
                score += 2
                why.append("eval of decoded request input")
            if _EXEC.search(body) and _INPUT.search(body):
                score += 2
                why.append("an exec primitive beside a request variable")
            elif _EXEC.search(body):
                score += 1
                why.append("an exec primitive")
            if re.search(r"\bpassword\b.*\bif\b|\bmd5\(\$_", body, re.I):
                score += 1
                why.append("a password gate")
            if score:
                hits.append((path, st.st_mtime, score, why))
    return hits


def _linux():
    servers = _linux_servers()
    if not servers:
        return [_finding("webshell", "ok", "no web server listening (Linux)",
                         "nothing on the usual HTTP ports, so there is no "
                         "document root to audit", "ss -ltnp")]
    out = []
    roots = _roots_from_config() or set()
    roots |= set(_expand(COMMON_ROOTS))
    roots = sorted(r for r in roots if os.path.isdir(r))
    if not roots:
        return [_finding(
            "webshell", "low",
            f"a web server is listening ({servers[0][1]}) but its root was "
            f"not found", "checked the config and the common paths; point "
            "jarvis at it if it lives elsewhere", "webshell")]

    import time
    for root in roots[:6]:
        for path, mtime, score, why in _scan_root(root):
            sev = "critical" if score >= 4 else "high" if score >= 2 else "low"
            out.append(file_finding(
                "webshell", sev, "server-side script reads as a command dispatcher",
                f"{path} (modified {time.strftime('%Y-%m-%d', time.localtime(mtime))})"
                f" — {', '.join(why)}", path))
    if not out:
        out.append(_finding(
            "webshell", "ok", "no web shell in the served roots",
            f"scanned {', '.join(roots[:6])} — no recently written script that "
            f"reads as a dispatcher", "webshell"))
    return out


# ── Windows / IIS ─────────────────────────────────────────────────────────

_WIN_PS = load_win_script("webshell.ps1")


def _windows():
    if not collect_windows.available():
        return []
    d = ps_json(_WIN_PS, timeout=180)
    if not d:
        return []
    if not d.get("listening"):
        return [_finding("webshell", "ok", "no web server listening (Windows)",
                         "nothing on the usual HTTP ports", "Get-NetTCPConnection",
                         host="win")]
    hits = d.get("hits") or []
    if isinstance(hits, dict):
        hits = [hits]
    out = []
    for h in hits:
        p = (h or {}).get("path", "?")
        w = ((h or {}).get("written") or "").replace("T", " ")[:19]
        out.append(file_finding(
            "webshell", "high",
            "IIS script reads as a command dispatcher",
            f"{p} (modified {w}) — contains eval / Request.* / a shell object",
            p, host="win"))
    if not out:
        out.append(_finding("webshell", "ok", "no web shell in the IIS roots",
                            "recently written .aspx/.asp/.jsp none matching "
                            "dispatcher shapes", "wwwroot", host="win"))
    return out


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += _linux()
    if "win" in hosts:
        out += _windows()
    return sort_findings(out)
