"""Can anything on the network reach a listening port? Windows Firewall's
answer, evaluated conservatively.

A listener is proven unreachable only when every firewall profile (Domain,
Private and Public, not just the one active now, so joining another network
cannot silently expose it) is enabled, blocks inbound by default, and either
ignores all allow rules ("block all incoming connections") or has no enabled
inbound allow rule matching the listener's protocol, port and program.
Keywords such as RPC, remote-address scopes and anything unreadable count as
matching: uncertainty keeps a port exposed.
"""

import re
import time

from jarvis.platform.windows import ps_json

PROFILES = ("Domain", "Private", "Public")
CACHE_S = 600
_CACHE = {"at": 0.0, "state": None}

PS_STATE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$o.profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
    @{ name = [string]$_.Name; enabled = [string]$_.Enabled
       defaultInbound = [string]$_.DefaultInboundAction
       allowInboundRules = [string]$_.AllowInboundRules } })
$ports = @{}; Get-NetFirewallPortFilter -All -PolicyStore ActiveStore | ForEach-Object {
    $ports[$_.InstanceID] = $_ }
$apps = @{}; Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore | ForEach-Object {
    $apps[$_.InstanceID] = $_ }
$o.rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow |
    ForEach-Object {
        $p = $ports[$_.InstanceID]; $a = $apps[$_.InstanceID]
        @{ id = [string]$_.InstanceID; profile = [string]$_.Profile
           protocol = [string]$p.Protocol; localPort = @($p.LocalPort | ForEach-Object { [string]$_ })
           program = [string]$a.Program } })
$o.ok = $true
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 5 -Compress)))
"""


def state(refresh=False):
    """The current firewall state, cached for CACHE_S; None when unreadable."""
    now = time.time()
    if not refresh and _CACHE["state"] is not None and now - _CACHE["at"] < CACHE_S:
        return _CACHE["state"]
    data = ps_json(PS_STATE, timeout=120)
    if not (isinstance(data, dict) and data.get("ok") and data.get("profiles")):
        return None
    _CACHE.update(at=now, state=data)
    return data


def _list(value):
    return value if isinstance(value, list) else [value] if value not in (None, "") else []


def _profiles_of(rule):
    text = str(rule.get("profile") or "Any")
    if text in ("Any", "", "NotConfigured"):
        return set(PROFILES)
    return {p for p in PROFILES if p.lower() in text.lower()}


def _protocol_matches(rule, proto):
    p = str(rule.get("protocol") or "Any").lower()
    return p in ("any", "", proto, {"tcp": "6", "udp": "17"}.get(proto, "?"))


def _port_matches(rule, port):
    ports = [str(x) for x in _list(rule.get("localPort"))] or ["Any"]
    for spec in ports:
        s = spec.strip().lower()
        if s in ("any", ""):
            return True
        if re.fullmatch(r"\d+", s):
            if int(s) == port:
                return True
        elif re.fullmatch(r"\d+-\d+", s):
            lo, hi = (int(x) for x in s.split("-"))
            if lo <= port <= hi:
                return True
        else:
            return True     # RPC, RPCEPMap, IPHTTPSIn, ... : unknown reach, assume it
    return False


def _norm_program(path):
    p = str(path or "").strip().strip('"').lower().replace("/", "\\")
    return "c:\\windows" + p[len("%systemroot%"):] if p.startswith("%systemroot%") else p


def _program_matches(rule, exe):
    program = _norm_program(rule.get("program"))
    if program in ("any", "", "system") or not exe:
        return True
    return program == _norm_program(exe)


def _profile_blocks(profile, rules, proto, port, exe):
    if str(profile.get("enabled")).lower() not in ("true", "1"):
        return False
    if str(profile.get("defaultInbound")).lower() == "allow":
        return False
    if str(profile.get("allowInboundRules")).lower() in ("false", "0"):
        return True     # "block all incoming connections": allow rules ignored
    name = profile.get("name")
    return not any(name in _profiles_of(r) and _protocol_matches(r, proto)
                   and _port_matches(r, port) and _program_matches(r, exe)
                   for r in rules)


def blocked(proto, port, exe="", fw=None):
    """Why no profile lets this listener be reached, or "" when not proven."""
    fw = fw if fw is not None else state()
    if not fw:
        return ""
    by_name = {str(p.get("name")): p for p in _list(fw.get("profiles"))}
    if set(by_name) < set(PROFILES):
        return ""
    rules = [r for r in _list(fw.get("rules")) if isinstance(r, dict)]
    proto = str(proto or "").lower()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return ""
    if all(_profile_blocks(by_name[n], rules, proto, port, exe) for n in PROFILES):
        if all(str(by_name[n].get("allowInboundRules")).lower() in ("false", "0")
               for n in PROFILES):
            return "Windows Firewall blocks all incoming connections on every profile"
        return "no enabled inbound allow rule on any firewall profile matches it"
    return ""


def rule_inactive(fw=None):
    """True when every profile ignores inbound allow rules, so no permissive
    allow rule can admit anything."""
    fw = fw if fw is not None else state()
    if not fw:
        return False
    by_name = {str(p.get("name")): p for p in _list(fw.get("profiles"))}
    return set(PROFILES) <= set(by_name) and all(
        str(by_name[n].get("enabled")).lower() in ("true", "1")
        and str(by_name[n].get("allowInboundRules")).lower() in ("false", "0")
        for n in PROFILES)
