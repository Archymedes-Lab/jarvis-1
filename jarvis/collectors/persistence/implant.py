"""Targeted-implant forensics: interception, boundary bypass, and trust subversion.

The other audits look for malware. This one looks for the things a *targeted*
implant does that commodity malware usually does not bother with — the quiet
changes that let an operator read traffic, reach in past the firewall, and be
trusted by the machine while doing it.

Mercenary surveillance tooling is the reference case. Its desktop artefacts are
well documented — Candiru's DevilsTongue, FinFisher/FinSpy, the Intellexa and
NSO desktop chains — and they cluster in three places that no other collector
here examines:

  interception   a root certificate the operator controls, a proxy or PAC URL,
                 a rewritten hosts file, a DNS server override. None of these
                 are malware. All of them make TLS readable.

  boundary       `netsh interface portproxy` forwards a port straight through
                 the host with no firewall rule to show for it. A filtering
                 platform callout driver sees traffic below the firewall UI
                 entirely. Both are "firewall breaching" without ever touching
                 a firewall rule, which is why the firewall audit cannot see
                 them.

  trust          an unsigned or non-Microsoft driver, a PAM module no package
                 owns, a preloaded object. These do not hide the implant; they
                 make the system vouch for it.

A caveat worth stating plainly: true Pegasus indicators are iOS and Android
artefacts, and nothing here can find them — that is a phone forensics job for
Amnesty's MVT. What this module finds is the desktop equivalent class. It
reports mechanism, not attribution: it will tell you a root CA that Microsoft
did not ship is trusted by this machine, and it will not tell you who put it
there.
"""

import os
import re
import subprocess

from jarvis.core.finding import win_finding as _finding
from jarvis.core.paths import load_win_script
from jarvis.core.util import dpkg_owns
from jarvis.platform.windows import aslist, ps_json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"interception": 0, "boundary": 1, "trust": 2, "implant": 3}


def _cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return r.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


# ── Windows ───────────────────────────────────────────────────────────────

PS_IMPLANT = load_win_script("implant.ps1")

# Root CA issuers that ship with Windows or arrive through Microsoft's trusted
# root program. Anything outside this set was added by software or by a person.
STOCK_CA = re.compile(
    r"(Microsoft|DigiCert|GlobalSign|Baltimore|VeriSign|Symantec|Thawte|"
    r"GeoTrust|Go Daddy|Entrust|COMODO|Sectigo|USERTrust|AddTrust|"
    r"Let's Encrypt|ISRG|Amazon|Google Trust|Starfield|QuoVadis|SecureTrust|"
    r"Certum|Actalis|Buypass|D-TRUST|SwissSign|T-Systems|IdenTrust|"
    r"Network Solutions|Hongkong Post|TWCA|SECOM|Security Communication|"
    r"AAA Certificate|Trustwave|XRamp|Cybertrust|Verisign|Atos|E-Tugra|"
    r"Hellenic|NetLock|Autoridad|Chambers|Camerfirma|ANF|Firmaprofesional|"
    r"OISTE|WISeKey|SwissSign|TeliaSonera|Sonera|Staat der|Trust Asia|"
    r"UCA |vTrus|SHECA|CFCA|GDCA|iTrusChina|BJCA|ZeroSSL|SSL.com)", re.I)

# Local-development CAs. Present on a developer machine on purpose, and their
# private keys sit on this disk, so they are worth naming but are not a finding.
DEV_CA = re.compile(r"(localhost|mkcert|\bdev\b|charles|fiddler|burp|"
                    r"mitmproxy|vite|webpack|dotnet|ASP\.NET|IIS Express|"
                    r"Docker|Kubernetes|minikube|ngrok|Tailscale|Proton)", re.I)


def audit_windows():
    data = ps_json(PS_IMPLANT, timeout=300)
    if not data:
        return [_finding("interception", "medium",
                         "windows implant audit unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    # -- root certificates --------------------------------------------------
    seen = set()
    for c in aslist(data.get("roots")):
        subject = (c.get("subject") or "").strip()
        issuer = (c.get("issuer") or "").strip()
        thumb = c.get("thumb") or ""
        if not subject or thumb in seen:
            continue
        seen.add(thumb)
        if STOCK_CA.search(subject) or STOCK_CA.search(issuer):
            continue
        sev = "medium" if DEV_CA.search(subject) else "high"
        note = ("a local development CA — expected on a developer machine, "
                "but its private key is on this disk"
                if DEV_CA.search(subject) else
                "not a Microsoft-shipped root — this CA can mint a trusted "
                "certificate for any site, which is what TLS interception needs")
        out.append(_finding(
            "interception", sev,
            f"non-standard root certificate trusted: {subject[:90]}",
            f"{note}; valid {(c.get('nb') or '')[:10]} to {(c.get('na') or '')[:10]}",
            thumb[:40]))

    # -- proxy / PAC --------------------------------------------------------
    proxy = data.get("proxy") or {}
    if proxy.get("pac"):
        out.append(_finding(
            "interception", "high", "a proxy auto-config URL is set",
            f"AutoConfigURL = {proxy['pac']} — every request this machine makes "
            f"is routed by a script fetched from there",
            "HKCU Internet Settings"))
    if proxy.get("enable") and proxy.get("server"):
        out.append(_finding(
            "interception", "medium", "a system proxy is configured",
            f"ProxyServer = {proxy['server']}", "HKCU Internet Settings"))
    wh = proxy.get("winhttp") or ""
    if wh and "Direct access" not in wh and "DIRECT" not in wh.upper():
        squashed = " ".join(wh.split())[:160]
        out.append(_finding(
            "interception", "medium", "WinHTTP has a proxy configured",
            f"{squashed} — this is the proxy used by services, separate from "
            f"the per-user setting", "netsh winhttp"))

    # -- portproxy ----------------------------------------------------------
    pp = data.get("portproxy") or ""
    rows = [l for l in pp.splitlines()
            if re.match(r"^\s*\d+\.\d+\.\d+\.\d+\s+\d+", l)]
    for row in rows:
        out.append(_finding(
            "boundary", "critical", "a portproxy forwarding rule exists",
            f"{' '.join(row.split())} — netsh portproxy moves traffic through "
            f"this host without creating a firewall rule, so nothing in the "
            f"firewall audit would show it", "netsh interface portproxy"))

    # -- hosts file ---------------------------------------------------------
    for line in (data.get("hosts") or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        if ip.startswith(("127.", "::1", "0.0.0.0")):
            continue        # local overrides and ad-blocking, not interception
        out.append(_finding(
            "interception", "high", f"hosts file redirects {names[0]}",
            f"{ip} → {' '.join(names)} — a name this machine resolves is being "
            f"pointed somewhere by hand", "drivers/etc/hosts"))

    # -- DNS overrides ------------------------------------------------------
    for d in aslist(data.get("dns")):
        servers = [s for s in aslist(d.get("servers")) if s]
        odd = [s for s in servers
               if not s.startswith(("127.", "192.168.", "10.", "172.", "fe80"))]
        if odd:
            out.append(_finding(
                "interception", "low",
                f"external DNS server on {d.get('iface')}",
                f"{', '.join(odd)} — resolution for this interface is handled "
                f"off-network", "Get-DnsClientServerAddress"))

    # -- driver signing -----------------------------------------------------
    for drv in aslist(data.get("drivers")):
        status = (drv.get("status") or "").strip()
        signer = (drv.get("signer") or "")
        if status in ("Valid", ""):
            if signer and "Microsoft" not in signer and "Windows" not in signer:
                out.append(_finding(
                    "trust", "low",
                    f"third-party driver running: {drv.get('name')}",
                    f"signed by {signer[:100]}", drv.get("path", "")))
            continue
        out.append(_finding(
            "trust", "high",
            f"running driver is not validly signed: {drv.get('name')}",
            f"Authenticode status {status} — a driver runs in the kernel, so "
            f"this is the highest-trust code on the machine",
            drv.get("path", "")))
    return out


# ── Linux / WSL ───────────────────────────────────────────────────────────

PAM_DIRS = ("/lib/security", "/usr/lib/security",
            "/lib/x86_64-linux-gnu/security", "/usr/lib/x86_64-linux-gnu/security")


_dpkg_owns = dpkg_owns


def unowned_pam_modules(dirs=PAM_DIRS):
    """PAM modules no package owns.

    This closes the T1556 gap the intel corpus keeps raising: a PAM module is
    loaded into every authentication, so a rogue one sees every password.
    `dirs` lets the coverage map's probe point this at a directory of its own.
    """
    out = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            continue
        for fn in entries:
            if not fn.endswith(".so"):
                continue
            full = os.path.join(d, fn)
            if _dpkg_owns(full):
                continue
            out.append(_finding(
                "trust", "critical", f"PAM module not owned by any package: {fn}",
                "every authentication on this system loads the PAM stack, so a "
                "module here sees every password that is typed",
                full, "wsl"))
    return out


def audit_linux():
    out = unowned_pam_modules()

    # -- preloaded objects --------------------------------------------------
    if os.path.exists("/etc/ld.so.preload"):
        try:
            body = open("/etc/ld.so.preload", errors="replace").read().strip()
        except OSError:
            body = ""
        if body:
            out.append(_finding(
                "trust", "critical", "a global library preload is configured",
                f"{body} — this object is loaded into every dynamically linked "
                f"process on the system", "/etc/ld.so.preload", "wsl"))

    # -- locally added certificate authorities ------------------------------
    for d in ("/usr/local/share/ca-certificates", "/etc/pki/ca-trust/source/anchors"):
        if not os.path.isdir(d):
            continue
        try:
            for fn in sorted(os.listdir(d)):
                out.append(_finding(
                    "interception", "high",
                    f"locally installed certificate authority: {fn}",
                    "a CA added here is trusted by curl, apt, git and most "
                    "language runtimes on this system",
                    os.path.join(d, fn), "wsl"))
        except OSError:
            continue

    # -- proxy environment --------------------------------------------------
    for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        val = os.environ.get(var)
        if val:
            out.append(_finding(
                "interception", "low", f"{var} is set in this environment",
                f"{val}", "environment", "wsl"))

    # -- traffic redirection ------------------------------------------------
    nat = _cmd(["iptables", "-t", "nat", "-S"]) or ""
    for line in nat.splitlines():
        if "REDIRECT" in line or "DNAT" in line:
            out.append(_finding(
                "boundary", "high", "a NAT redirect rule is installed",
                f"{line.strip()[:160]} — traffic leaving this machine is being "
                f"sent somewhere other than where it was addressed",
                "iptables -t nat", "wsl"))

    # -- hosts file ---------------------------------------------------------
    try:
        for line in open("/etc/hosts", errors="replace"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith(("127.", "::1", "0.0.0.0",
                                                            "fe00", "ff00", "ff02")):
                out.append(_finding(
                    "interception", "medium",
                    f"hosts file redirects {parts[1]}",
                    f"{parts[0]} → {' '.join(parts[1:])}", "/etc/hosts", "wsl"))
    except OSError:
        pass

    # -- eBPF ---------------------------------------------------------------
    # eBPF can read and rewrite traffic and hide processes without a module.
    progs = _cmd(["bpftool", "prog", "show"]) or ""
    n = len([l for l in progs.splitlines() if re.match(r"^\d+:", l)])
    if n:
        out.append(_finding(
            "implant", "medium", f"{n} eBPF programs are loaded",
            "eBPF can inspect and rewrite traffic and hide processes without a "
            "kernel module — run `bpftool prog show` to see what they attach to",
            "bpftool", "wsl"))
    return out


def audit(hosts=("wsl", "win")):
    out = []
    if "wsl" in hosts:
        out += audit_linux()
    if "win" in hosts:
        out += audit_windows()
    return sort_findings(out)


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
