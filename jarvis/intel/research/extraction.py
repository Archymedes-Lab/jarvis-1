"""What the model is asked to extract from a writeup, and how its answer becomes
candidate indicators (every one still passes core.vet)."""

import json

from jarvis.core import vet
from jarvis.core.util import now

# ── The extraction prompt ─────────────────────────────────────────────────
#
# Every rule here exists because its absence produced a specific bad result in
# testing. Notably: naming the target platform in the prompt caused the model
# to echo "Windows 11 workstation with WSL2" back as extracted data, so the
# prompt now says nothing about the machine it defends.
EXTRACTION_PROMPT = """\
You are extracting host-based detection content from a security research \
article for an automated defensive agent. The output is machine-consumed. \
Precision matters far more than recall: a wrong indicator causes a false alarm \
on a production workstation, while a missing one costs nothing.

COPY, DO NOT COMPOSE. Every value must appear verbatim in the article. Do not \
infer, generalise, normalise, complete, or reconstruct any value. If you are \
recalling it from knowledge of this malware family rather than reading it in \
this text, omit it.

OMIT ANY VALUE THAT IS NOT A REAL OBSERVED ARTEFACT. Specifically omit: \
redacted or partially redacted values, anything containing angle brackets or \
ellipses, illustrative examples such as evil.com or example.com, RFC1918 and \
loopback addresses used in lab writeups, and digests of empty or placeholder \
input. An empty array is a correct and expected answer. Never fill a field to \
avoid leaving it empty.

SEPARATE ATTACKER ARTEFACTS FROM ABUSED LEGITIMATE ONES. A path, process, or \
key only belongs in an attacker_* field if the article says the attacker \
created, dropped, or controls it. If the article describes the attacker abusing \
software that is legitimately present on a normal system - a debugger, a shell, \
a signed system binary, a package manager - put its name in abused_legitimate \
and nowhere else. This distinction is critical: the consuming system treats \
attacker_* values as things that should not exist on a clean machine.

REFANG defanged notation: evil[.]com becomes evil.com, hxxp becomes http.

EXCLUDE the publishing vendor's own domains, cited reference links, social \
media links, and any infrastructure belonging to the researchers.

PREFER SPECIFICITY. A full absolute path is worth more than a bare filename. A \
full registry path is worth more than a hive name. If only a vague reference \
exists, omit it rather than guessing the rest.

If the article is not primary threat research containing concrete artefacts - \
if it is a product announcement, an opinion piece, a conference recap, or a \
listing page - set is_threat_research to false and leave every array empty.\
"""


EXTRACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "is_threat_research": {
            "type": "boolean",
            "description": "True only for primary research containing concrete artefacts.",
        },
        "threat_name": {
            "type": "string",
            "description": "Malware family, tool, or campaign name as written. Empty if unnamed.",
        },
        "platforms": {
            "type": "array", "items": {"type": "string"},
            "description": "Operating systems the article says are affected.",
        },
        "attack_technique_ids": {
            "type": "array", "items": {"type": "string"},
            "description": "MITRE ATT&CK technique IDs stated in the article, e.g. T1053.005.",
        },
        "attacker_file_paths": {
            "type": "array", "items": {"type": "string"},
            "description": "Absolute paths the attacker created or dropped.",
        },
        "attacker_process_names": {
            "type": "array", "items": {"type": "string"},
            "description": "Names of attacker-controlled binaries or services.",
        },
        "registry_keys": {
            "type": "array", "items": {"type": "string"},
            "description": "Full registry paths the attacker created or modified.",
        },
        "domains": {
            "type": "array", "items": {"type": "string"},
            "description": "Attacker-controlled domains, refanged.",
        },
        "ipv4": {
            "type": "array", "items": {"type": "string"},
            "description": "Attacker-controlled IPv4 addresses, refanged.",
        },
        "sha256": {
            "type": "array", "items": {"type": "string"},
            "description": "SHA-256 digests of attacker samples. Omit other hash lengths.",
        },
        "cves": {
            "type": "array", "items": {"type": "string"},
            "description": "CVE identifiers the article says were exploited.",
        },
        "abused_legitimate": {
            "type": "array", "items": {"type": "string"},
            "description": "Legitimate software the attacker abused rather than installed.",
        },
        "persistence_mechanisms": {
            "type": "array", "items": {"type": "string"},
            "description": "One short phrase per mechanism describing how it survives reboot.",
        },
        "detection_guidance": {
            "type": "array", "items": {"type": "string"},
            "description": "Concrete, checkable detection advice. One idea per string.",
        },
    },
    "required": ["is_threat_research"],
}


# Which schema field feeds which indicator kind in the store.
FIELD_KINDS = {
    "attacker_file_paths": "path",
    "attacker_process_names": "process",
    "registry_keys": "regkey",
    "domains": "domain",
    "ipv4": "ipv4",
    "sha256": "sha256",
    "attack_technique_ids": "attack",
    "cves": "cve",
}


def _parse_summary(raw):
    """Extraction comes back as a JSON string. Anything else is discarded."""
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def _as_list(value):
    """Fields come back as null, a string, or a list depending on the article."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str) and v.strip()]
    return []


def ingest_result(store, result, topic, query, stats):
    """Vet one article's extraction and fold the survivors into the store."""
    url = (result.get("url") or "").strip()
    if not url:
        return 0
    data = _parse_summary(result.get("summary"))
    if not data:
        stats["unparsed"] += 1
        return 0
    if not data.get("is_threat_research"):
        stats["not_research"] += 1
        return 0

    ts = now()
    threat = (data.get("threat_name") or "").strip()[:120]
    context_bits = _as_list(data.get("persistence_mechanisms"))[:2]
    context = (threat + (" — " if threat and context_bits else "")
               + "; ".join(context_bits))[:400]

    kept = 0
    for field, kind in FIELD_KINDS.items():
        for raw in _as_list(data.get(field))[:60]:
            k = kind
            # A ".so"/".ko" named as a process is really a file to hunt for,
            # not a process to match — reroute rather than discard it.
            if kind == "process" and raw.strip().lower().endswith(
                    (".so", ".ko", ".dll", ".dylib")):
                k = "filename"
            norm, why = vet.vet(k, raw)
            stats["seen"] += 1
            if not norm:
                stats["rejected"] += 1
                stats["reasons"][why] = stats["reasons"].get(why, 0) + 1
                continue
            # ATT&CK ids and CVEs describe technique, not attacker
            # infrastructure, so they are always safe to keep at high
            # confidence. Everything else starts as a lead, not a verdict.
            conf = "high" if k in ("attack", "cve", "sha256") else "medium"
            store.db.execute(
                """INSERT INTO indicators(kind,value,norm,confidence,topic,
                                          context,source_url,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(kind,norm) DO UPDATE SET
                       last_seen=excluded.last_seen,
                       doc_count=indicators.doc_count+1""",
                (k, raw[:512], norm, conf, topic, context, url, ts, ts),
            )
            kept += 1
            stats["kept"] += 1

    store.db.execute(
        """INSERT INTO intel_docs(url,title,published,topic,query,fetched_at,
                                  text_len,n_indicators)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(url) DO UPDATE SET
               fetched_at=excluded.fetched_at,
               n_indicators=excluded.n_indicators""",
        (url, (result.get("title") or "")[:300],
         (result.get("publishedDate") or "")[:32], topic, query[:300],
         ts, len(result.get("text") or ""), kept),
    )
    stats["docs"] += 1
    return kept
