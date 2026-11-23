"""Ban a source that is guessing passwords here, inbound only and for a while.

Deterrence by cost, never by counter-attack: a Windows Firewall inbound block
rule makes this machine stop answering one public address the brute-force
detector caught hammering logons. Nothing is sent to that address — no scan,
no probe, no reply — so the action cannot become the threat it is fighting.

The ban is time-bounded and escalates for a source that comes back after it
lifts (1 h, 6 h, 24 h, then 7 days), which is what makes sustained guessing
expensive. The firewall is stateful, so an inbound rule leaves connections this
machine starts itself untouched; the damage boundary is "that one address can
no longer open a connection to this machine until the ban lifts".

Expiry is enforced by the ladder's sweep (defense.expire); if JARVIS is down
the rule stays, named and grouped so the owner can find and remove it.

Private, loopback, link-local, carrier-grade NAT, documentation and other
non-global addresses are never targets, nor anything in the owner's
`ban_allowlist`. The address is validated as a literal IP before it ever
reaches PowerShell, so nothing from a log line is interpolated into a command.
"""

import ipaddress
import re

from jarvis.platform.windows import ps_json

from .base import AUTO, Action, register

RULE_PREFIX = "JARVIS-ban-"
ESCALATION = (3600, 6 * 3600, 86400, 7 * 86400)

# bruteforce.py: "31 failed Windows logons for admin from 1.2.3.4 in 24h". The
# user name is the guesser's own text and can itself read "from 8.8.8.8 in 24h",
# so only the detector's trailing clause names the source.
_SOURCE = re.compile(r"\bfrom (\S+) in \d+h\Z")


def _public_ip(value):
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    # is_global admits multicast (224.0.0.1 is "global"); a logon source never is.
    return str(ip) if ip.is_global and not ip.is_multicast else None


def _rule_name(value):
    ip = _public_ip(value)
    return RULE_PREFIX + ip if ip else None


def _wrap(body):
    return ("$ErrorActionPreference='Stop';" + body +
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))")


@register
class BanSource(Action):
    id = "ban_source"
    title = "Ban a password-guessing source (inbound, time-bounded)"
    autonomy = AUTO
    reversible = True
    host = "win"
    enable_flag = "auto_ban_source"
    max_active = 256

    def match(self, finding, job):
        f = finding or {}
        if job != "bruteforce" or f.get("category") != "bruteforce" or f.get("host") != "win":
            return None
        m = _SOURCE.search(f.get("title", ""))
        ip = _public_ip(m.group(1)) if m else None
        return {"ip": ip} if ip else None

    def identity(self, finding, target):
        return "ip:" + target["ip"]

    def permitted(self, target, conf):
        ip = ipaddress.ip_address(target["ip"])
        for entry in (conf or {}).get("ban_allowlist") or []:
            try:
                net = ipaddress.ip_network(str(entry), strict=False)
            except ValueError:
                continue
            if ip.version == net.version and ip in net:
                return False, f"{ip} is in the owner's ban_allowlist ({net})"
        return True, ""

    def ttl(self, target, prior):
        return ESCALATION[min(max(int(prior), 0), len(ESCALATION) - 1)]

    def auto_eligible(self, finding, job, target):
        return job == "bruteforce" and finding.get("severity") == "high"

    def preview(self, target):
        return (f"Add a Windows Firewall inbound rule refusing new connections from "
                f"{target['ip']} for a limited time (longer if it returns). "
                f"Nothing is sent to that address. Reversible.")

    def _run(self, script, timeout=30):
        return ps_json(script, timeout=timeout)

    def apply(self, target, case):
        ip = _public_ip(target.get("ip"))
        if not ip:
            return False, {}, "not a public address"
        name = RULE_PREFIX + ip
        result = self._run(_wrap(
            f"$n='{name}';$ip='{ip}';"
            "try{"
            "if(-not(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)){"
            "New-NetFirewallRule -DisplayName $n -Direction Inbound -Action Block "
            "-RemoteAddress $ip -Profile Any -Group 'JARVIS' "
            "-Description 'JARVIS time-bounded ban; remove with jarvis defend undo' | Out-Null};"
            "$ok=[bool](Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)}"
            "catch{$ok=$false};$j=@{ok=$ok}|ConvertTo-Json -Compress;"))
        if isinstance(result, dict) and result.get("ok"):
            return True, {"ip": ip, "name": name}, f"banned {ip} inbound"
        return False, {}, "firewall rule could not be created (needs the Windows bridge)"

    def undo(self, target, record):
        # The name is rebuilt from a validated address, never taken verbatim
        # from a stored record, so a tampered ledger cannot reach PowerShell.
        name = _rule_name((record or {}).get("ip") or (target or {}).get("ip"))
        if not name:
            return False, "no valid address recorded"
        result = self._run(_wrap(
            f"$n='{name}';"
            "try{Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue|"
            "Remove-NetFirewallRule;"
            "$ok=-not[bool](Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)}"
            "catch{$ok=$false};$j=@{ok=$ok}|ConvertTo-Json -Compress;"))
        if isinstance(result, dict) and result.get("ok"):
            return True, f"lifted the ban on {name[len(RULE_PREFIX):]}"
        return False, "could not remove the firewall rule"

    def recover(self, target, record):
        name = _rule_name((record or {}).get("ip") or (target or {}).get("ip"))
        if not name:
            return "unknown", {}, "invalid ban recovery target"
        result = self._run(_wrap(
            f"$n='{name}';"
            "try{$ok=[bool](Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue);"
            "$j=@{available=$true;blocked=$ok}|ConvertTo-Json -Compress}"
            "catch{$j=@{available=$false;blocked=$false}|ConvertTo-Json -Compress};"))
        ip = name[len(RULE_PREFIX):]
        if not isinstance(result, dict) or not result.get("available"):
            return "unavailable", {}, "Windows firewall state could not be read"
        if result.get("blocked"):
            return "applied", {"ip": ip, "name": name}, f"verified inbound ban on {ip}"
        return "not_applied", {}, f"no JARVIS inbound ban exists for {ip}"
