"""Block traffic to a high-confidence malicious address, reversibly.

A Windows Firewall outbound block rule stops this machine reaching an address
threat intelligence has flagged, without touching the process or the file —
the least invasive way to cut a command-and-control channel. The rule is named
so it can be found and removed again; undo deletes exactly that rule.

The address is validated as a literal IP here before it ever reaches
PowerShell, so nothing from a feed is interpolated into a command.
"""

import ipaddress

from jarvis.platform.windows import ps_json

from .base import AUTO, Action, register

RULE_PREFIX = "JARVIS-block-"


def _ip(value):
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


@register
class BlockAddress(Action):
    id = "block_address"
    title = "Block a malicious address"
    autonomy = AUTO
    reversible = True
    host = "win"
    enable_flag = "auto_block_ip"

    def match(self, finding, job):
        # The hunt's C2/infrastructure matches carry the peer ip in the detail
        # as "…(1.2.3.4:443)…" or "→ 1.2.3.4:port". Pull the first literal IP.
        cat = (finding or {}).get("category", "")
        if cat not in ("c2 match",):
            return None
        blob = (finding.get("detail", "") + " " + finding.get("where", ""))
        for token in blob.replace("(", " ").replace(")", " ").replace("→", " ").split():
            ip = _ip(token.split(":")[0] if token.count(":") == 1 else token)
            if ip and not ipaddress.ip_address(ip).is_private:
                return {"ip": ip}
        return None

    def preview(self, target):
        return (f"Add a Windows Firewall outbound rule blocking all traffic to "
                f"{target['ip']}. Reversible.")

    def auto_eligible(self, finding, job, target):
        # The hunt promotes an address to critical only when a high-confidence
        # C2 listing is corroborated by an independent signal
        # (hunt.grade_ip_hit). A lone listing, a CIDR match or a shared
        # provider address remains an approval proposal.
        return job == "hunt" and finding.get("category") == "c2 match" \
            and finding.get("severity") == "critical"

    def _run(self, script):
        return ps_json(script, timeout=30)

    def apply(self, target, case):
        ip = _ip(target.get("ip"))
        if not ip:
            return False, {}, "not a valid address"
        name = RULE_PREFIX + ip
        script = (
            "$ErrorActionPreference='Stop';"
            f"$n='{name}';$ip='{ip}';"
            "try{"
            "if(-not(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)){"
            "New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block "
            "-RemoteAddress $ip -Profile Any -Group 'JARVIS' | Out-Null};"
            "$ok=[bool](Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)}"
            "catch{$ok=$false};"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
            "(@{ok=$ok}|ConvertTo-Json -Compress)))")
        result = self._run(script)
        if isinstance(result, dict) and result.get("ok"):
            return True, {"ip": ip, "name": name}, f"blocked {ip}"
        return False, {}, "firewall rule could not be created (needs the Windows bridge)"

    def undo(self, target, record):
        name = record.get("name") or (RULE_PREFIX + _ip(record.get("ip") or ""))
        if not name or name == RULE_PREFIX:
            return False, "no rule recorded"
        script = (
            "$ErrorActionPreference='Stop';"
            f"$n='{name}';"
            "try{Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue|"
            "Remove-NetFirewallRule;"
            "$gone=-not[bool](Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)}"
            "catch{$gone=$false};"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
            "(@{ok=$gone}|ConvertTo-Json -Compress)))")
        result = self._run(script)
        if isinstance(result, dict) and result.get("ok"):
            return True, f"unblocked {record.get('ip')}"
        return False, "could not remove the firewall rule"

    def recover(self, target, record):
        ip = _ip((record or {}).get("ip") or (target or {}).get("ip"))
        if not ip:
            return "unknown", {}, "invalid firewall recovery target"
        name = (record or {}).get("name") or (RULE_PREFIX + ip)
        script = (
            "$ErrorActionPreference='Stop';"
            f"$n='{name}';"
            "try{$r=Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue;"
            "$ok=[bool]$r;$j=@{available=$true;blocked=$ok}|ConvertTo-Json -Compress}"
            "catch{$j=@{available=$false;blocked=$false}|ConvertTo-Json -Compress};"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))")
        result = self._run(script)
        if not isinstance(result, dict) or not result.get("available"):
            return "unavailable", {}, "Windows firewall state could not be read"
        if result.get("blocked"):
            return "applied", {"ip": ip, "name": name}, f"verified outbound block for {ip}"
        return "not_applied", {}, f"no JARVIS outbound block exists for {ip}"
