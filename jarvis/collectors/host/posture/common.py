"""Finding shape and ordering for the posture audit."""


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


CAT_ORDER = {"malware defense": 0, "platform integrity": 1, "memory defense": 2,
             "data at rest": 3, "account & access": 4, "attack surface": 5,
             "visibility": 6, "licensing": 7, "operations": 8}


def _finding(category, severity, title, detail, fix="", host="win"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail + (f"  →  {fix}" if fix else ""),
            "where": fix, "host": host}


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
