"""Sysmon ProcessCreate policy probe: read-only export of the active filter.

Phase 1: before claiming process-visibility coverage, JARVIS must be able
to show which classes of processes the active Sysmon configuration excludes.
This module exports the live configuration with elevated read-only access
(`Sysmon64.exe -c`, which never changes state) and classifies the
ProcessCreate (event 1) rule set. No remediation, no config writes, no
Defender exclusions — observation only.

Outcome vocabulary (conservative):
  full        event 1 present with no Exclude rules
  filtered    event 1 present with one or more Exclude rules (listed)
  missing     event 1 absent from the active configuration
  unknown     configuration could not be read (not installed / no privilege)

A reconciliation gap (snapshot present, no start event) combined with
`filtered` names the likely cause; combined with `full` it points at
log-wrap, sensor stop or tampering instead of policy. Either way the
verdict is evidence, not a coverage claim.
"""

import hashlib
import re
from collections import Counter

from jarvis.core.paths import repo_file
from jarvis.platform import broker

EVENT_CREATE = "ProcessCreate"
BASELINE = "windows-sysmon/jarvis-windows-baseline.xml"


def config_hash(dump):
    """The running configuration's SHA-256 as `Sysmon -c` reports it, or None.
    Sysmon hashes the XML file it was given, byte for byte."""
    match = re.search(r"(?im)Config hash:\s*SHA256=([0-9a-f]{64})", str(dump or ""))
    return match.group(1).lower() if match else None


def baseline_sha256(path=None):
    """SHA-256 of the checkout's reviewed Sysmon baseline, or None."""
    try:
        with open(path or repo_file(BASELINE), "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def drift(policy, baseline=None):
    """'match', 'drift' or 'unknown': running config vs reviewed baseline."""
    running = (policy or {}).get("config_hash")
    expected = baseline if baseline is not None else baseline_sha256()
    if not running or not expected:
        return "unknown"
    return "match" if running == expected else "drift"


def _rules(lines):
    rules = []
    for line in lines:
        match = re.match(
            r"(?i)^\s*([A-Za-z][A-Za-z0-9]*)\s+filter:\s*(.+?)\s+value:\s*'(.*)'\s*$",
            line)
        if match:
            rules.append({"field": match.group(1),
                          "condition": match.group(2).strip().lower(),
                          "value": match.group(3)})
    return rules


def _broker_dump(now=None):
    """Return (dump, evidence error) from the reviewed elevated broker."""
    data, why = broker.result("sysmon_policy", now=now)
    if data is None:
        return None, why
    if data.get("installed") is not True:
        return None, str(data.get("error") or "Sysmon is not installed")[:200]
    if data.get("exit_code") != 0 or data.get("error"):
        return None, str(data.get("error") or "configuration export failed")[:200]
    dump = data.get("dump")
    if not isinstance(dump, str) or not dump.strip():
        return None, "elevated Sysmon configuration export was empty"
    return dump, ""


def parse(dump):
    """Parse a `Sysmon -c` dump into a policy verdict. Pure; never executes."""
    if dump is None:
        return {"event1": "unknown", "detail": "configuration unreadable; "
                "Sysmon may be absent or this account lacks privilege"}
    text = str(dump)
    # Current Sysmon (validated with 15.21) prints sections as:
    #   - ProcessCreate  onmatch: exclude
    #       Image filter: is value: '...'
    # rather than the older `Event ProcessCreate` form. Any child filter makes
    # ProcessCreate selective: exclude rules omit the named classes, while an
    # include rule records only the named classes.
    modern = re.search(
        r"(?im)^\s*-\s*ProcessCreate\s+onmatch:\s*(include|exclude)[^\r\n]*",
        text)
    if modern:
        mode = modern.group(1).lower()
        tail = text[modern.end():]
        boundary = re.search(
            r"(?im)^\s*-\s*[A-Za-z][A-Za-z0-9]*\s+onmatch:\s*(?:include|exclude)",
            tail)
        section = tail[:boundary.start()] if boundary else tail
        filters = [line.strip()[:300] for line in section.splitlines()
                   if re.search(r"(?i)\bfilter:\s*", line)]
        rules = _rules(section.splitlines())
        if filters:
            key = "excludes" if mode == "exclude" else "includes"
            scope = ("excluded" if mode == "exclude" else
                     "limited to explicit include rules")
            return {"event1": "filtered", "mode": mode,
                    "detail": f"ProcessCreate {scope} by {len(filters)} rule(s)",
                    key: filters[:20], "rules": rules,
                    "field_counts": dict(Counter(
                        rule["field"] for rule in rules)),
                    "rule_count": len(filters)}
        if mode == "include":
            return {"event1": "missing", "mode": mode,
                    "detail": "ProcessCreate include policy contains no rules"}
        return {"event1": "full", "mode": mode,
                "detail": "ProcessCreate recorded without excludes"}

    # Split the dump into the ProcessCreate section: from its header to the
    # next event header of the form `Event ...`.
    blocks = re.split(r"(?m)^Event\s+", text)
    create = ""
    for block in blocks:
        if re.match(r"(?i)processcreate\b|event\s*id\s*[:=]?\s*1\b", block.strip()[:80]):
            create = block
            break
        if "ProcessCreate" in block[:400]:
            create = block
            break
    if not create:
        # Fall back to whole-dump search: an explicit rule mention is still
        # evidence the filter exists even if section parsing fails.
        if not re.search(r"(?i)processcreate", text):
            return {"event1": "missing", "detail": "ProcessCreate (event 1) "
                    "absent from the active configuration"}
        create = text
    excludes = re.findall(r"(?im)^\s*exclude\b[^\n]*", create)
    excludes = [e.strip()[:200] for e in excludes if e.strip()]
    if excludes:
        return {"event1": "filtered",
                "detail": f"ProcessCreate excluded by {len(excludes)} rule(s)",
                "excludes": excludes[:10]}
    return {"event1": "full", "detail": "ProcessCreate recorded without excludes"}


def audit(now=None):
    """Read the fresh, elevated broker export. Returns a verdict; never raises."""
    try:
        dump, error = _broker_dump(now=now)
        verdict = parse(dump)
        verdict["config_hash"] = config_hash(dump)
        verdict["source"] = "elevated_broker" if dump is not None else "unavailable"
        if error:
            verdict["detail"] = error
        return verdict
    except Exception as exc:
        return {"event1": "unknown",
                "detail": f"probe failed: {type(exc).__name__}",
                "source": "unavailable"}


def summary(policy):
    """Health-safe policy metadata; never expose raw paths or command rules."""
    policy = policy or {}
    return {key: policy.get(key) for key in (
        "event1", "mode", "detail", "rule_count", "field_counts", "source",
        "config_hash")
        if policy.get(key) is not None}


def matching_rule(policy, process):
    """Return the first active rule matching snapshot metadata, if supported."""
    if (policy or {}).get("event1") != "filtered" \
            or (policy or {}).get("mode") != "exclude":
        return None
    process = process or {}
    values = {
        "image": str(process.get("exe") or ""),
        "commandline": str(process.get("cmdline") or ""),
    }
    for rule in policy.get("rules") or []:
        field = str(rule.get("field") or "").lower()
        actual = values.get(field)
        expected = str(rule.get("value") or "")
        condition = str(rule.get("condition") or "").lower()
        if not actual or not expected:
            continue
        left, right = actual.casefold(), expected.casefold()
        matched = (
            (condition == "is" and left == right)
            or (condition == "is not" and left != right)
            or (condition == "contains" and right in left)
            or (condition == "begin with" and left.startswith(right))
            or (condition == "end with" and left.endswith(right))
        )
        if matched:
            return {"field": rule.get("field"), "condition": condition,
                    "value": expected}
    return None


def _condition(condition, actual, expected):
    """One Sysmon filter condition, case-insensitive as Sysmon applies it."""
    left, right = actual.casefold(), expected.casefold()
    parts = [p for p in right.split(";") if p]
    return {
        "is": lambda: left == right,
        "is not": lambda: left != right,
        "is any": lambda: left in parts,
        "contains": lambda: right in left,
        "contains any": lambda: any(p in left for p in parts),
        "contains all": lambda: all(p in left for p in parts),
        "excludes": lambda: right not in left,
        "excludes any": lambda: any(p not in left for p in parts),
        "excludes all": lambda: all(p not in left for p in parts),
        "begin with": lambda: left.startswith(right),
        "not begin with": lambda: not left.startswith(right),
        "end with": lambda: left.endswith(right),
        "not end with": lambda: not left.endswith(right),
    }.get(condition, lambda: False)()


def _filters_match(node, fields):
    """A Rule (its groupRelation) or a whole onmatch block (any child)."""
    results = []
    for child in node:
        if child.tag == "Rule":
            results.append(_filters_match(child, fields))
        else:
            results.append(_condition(child.attrib.get("condition", "is"),
                                      fields.get(child.tag, ""), child.text or ""))
    if node.tag == "Rule" and node.attrib.get("groupRelation", "or").lower() == "and":
        return bool(results) and all(results)
    return any(results)


def registry_recorded(root, event_type, target_object, image=""):
    """Would this Sysmon policy record the registry event? Pure; for replays
    and for proving the baseline still feeds the registry detectors.

    root is the parsed <Sysmon> element. Recorded means some include block
    matches and no exclude block does (Sysmon: exclude wins)."""
    fields = {"EventType": event_type, "TargetObject": target_object, "Image": image}
    blocks = [e for e in root.iter("RegistryEvent")]
    included = any(_filters_match(b, fields) for b in blocks
                   if b.attrib.get("onmatch") == "include")
    excluded = any(_filters_match(b, fields) for b in blocks
                   if b.attrib.get("onmatch") == "exclude")
    return included and not excluded


def gap_cause(policy, dropped_process_create=False, process=None):
    """Likely cause of a snapshot-without-start gap. Advisory only."""
    state = (policy or {}).get("event1", "unknown")
    if state == "filtered":
        matched = matching_rule(policy, process)
        if matched:
            return ("matched active Sysmon ProcessCreate exclusion: "
                    f"{matched['field']} {matched['condition']} "
                    f"{matched['value']!r}")
        if dropped_process_create:
            count = (dropped_process_create
                     if type(dropped_process_create) is int else None)
            suffix = f" ({count} observed this boot)" if count else ""
            return ("likely driver-queue loss: no active exclusion matched "
                    "this process and Sysmon reported dropped ProcessCreate "
                    f"events (event 255){suffix}; widen the queue or narrow "
                    "the noisiest rule")
        count = (policy or {}).get("rule_count")
        suffix = f" ({count} active rule(s))" if isinstance(count, int) else ""
        return ("likely Sysmon ProcessCreate filtering: the active policy "
                f"selects process classes{suffix}; inspect the persisted "
                "elevated policy evidence to identify matches")
    if dropped_process_create:
        count = (dropped_process_create
                 if type(dropped_process_create) is int else None)
        suffix = f" ({count} observed this boot)" if count else ""
        return ("likely driver-queue loss: Sysmon reported dropped "
                f"ProcessCreate events (event 255){suffix}; widen the queue or "
                "narrow the noisiest rule")
    if state == "full":
        return ("policy records all ProcessCreate; suspect log wrap, "
                "sensor stop, or tampering rather than filtering")
    return "unattributed gap: policy unknown; preserve evidence and re-validate"
