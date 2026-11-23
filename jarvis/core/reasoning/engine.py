"""Deterministic spyware / covert-process assessment of one process instance.

Verdict classes name what was observed, never intent:

  NO_SIGNAL                 nothing relevant observed
  EXPECTED_DECLARED         capabilities explained by a signed, matching product
  EXPECTED_DUAL_USE         explained, but the product is also commonly abused;
                            the owner should confirm they installed it
  UNEXPLAINED_CAPABILITY    a capture capability with no explanation, one stage
  SUSPECT_CHAIN             unexplained capture plus two or more other stages
  VISIBILITY_CONTRADICTION  independent views disagree, or the process disguises
                            itself; concealment alone is enough

Invariants: missing evidence is never clean; stale or incomplete observations
are unknown, not positive; identity weakness (unsigned, temp path, brand new)
adds context only when a stage fact is already present; explanation by
category needs a valid signature and an exact publisher match, and never
authorizes anything; a mechanism JARVIS cannot see is listed as a blind spot.
"""

from jarvis.core.reasoning import knowledge, vocab

VERDICT_DEPTH = {"NO_SIGNAL": 0, "EXPECTED_DECLARED": 0, "EXPECTED_DUAL_USE": 1,
                 "UNEXPLAINED_CAPABILITY": 1, "SUSPECT_CHAIN": 2,
                 "VISIBILITY_CONTRADICTION": 2}
VERDICT_LEVEL = {"NO_SIGNAL": 0, "EXPECTED_DECLARED": 0, "EXPECTED_DUAL_USE": 1,
                 "UNEXPLAINED_CAPABILITY": 1, "SUSPECT_CHAIN": 2,
                 "VISIBILITY_CONTRADICTION": 2}     # response ladder, max 2 here
NEW_IMAGE_DAYS = 14
MAX_OBSERVATIONS = 256


def _positive(subject):
    return [o for o in subject.observations[:MAX_OBSERVATIONS] if o.positive()]


def _explained(caps, subject):
    """(explained set, category ids) for capture kinds in `caps`."""
    if subject.declared == vocab.JARVIS_COMPONENT:
        own = {"cap.keyboard.hook", "cap.input.injection"}
        return {c for c in caps if c in own}, [vocab.JARVIS_COMPONENT]
    if subject.path_class == "os" and subject.label in knowledge.LINUX_OS_COMPONENTS:
        expected = knowledge.LINUX_OS_COMPONENTS[subject.label]
        return {c for c in caps if c in expected}, ["linux_os_component"]
    if subject.signature != "valid" or subject.runs_script:
        return set(), []
    cats = knowledge.categories_for(subject.publisher, subject.path_class)
    expected = set()
    for cid in cats:
        expected.update(knowledge.CATEGORIES[cid]["expects"])
    return {c for c in caps if c in expected}, cats


def _matches(unexplained, present, blind):
    out = []
    for aid, arch in knowledge.ARCHETYPES.items():
        hit = [c for c in arch["capture"] if c in unexplained]
        if arch["capture"] and not hit:
            continue
        if not arch["capture"] and "conceal" not in present:
            continue
        missing = [s for s in arch["needs"] if s not in present]
        out.append({"archetype": aid, "title": arch["title"], "matched": hit,
                    "mechanism": arch["mechanism"], "not_yet_observed": missing,
                    "next_checks": list(arch["next_checks"]),
                    "cannot_see": [m for m in blind if m in _archetype_blind(hit, missing)]})
    return out


def _archetype_blind(hit, missing):
    names = set()
    for kind in hit:
        names.update(vocab.CAPTURE_MECHANISMS.get(kind, ()))
    for stage in missing:
        if stage in vocab.STAGE_MECHANISM:
            names.add(vocab.STAGE_MECHANISM[stage])
    return names


def _blind(caps, stages_missing):
    names = set()
    for kind in caps:
        names.update(vocab.CAPTURE_MECHANISMS.get(kind, ()))
    for stage in stages_missing:
        if stage in vocab.STAGE_MECHANISM:
            names.add(vocab.STAGE_MECHANISM[stage])
    names.add("hidden process")
    if not caps:
        # Nothing observed: absence proves nothing about any unobservable mechanism.
        names.update(n for n, (status, _) in vocab.OBSERVABILITY.items() if status == "blind")
    return sorted(n for n in names
                  if vocab.OBSERVABILITY.get(n, ("blind",))[0] in ("blind", "limited"))


def assess(subject):
    obs = _positive(subject)
    degraded = sorted({o.source for o in subject.observations[:MAX_OBSERVATIONS]
                       if not (o.fresh and o.complete)})
    by_stage = {}
    for o in obs:
        by_stage.setdefault(vocab.KINDS[o.kind][0], set()).add(o.kind)
    caps = by_stage.get("capture", set())
    explained, cats = _explained(caps, subject)
    unexplained = caps - explained
    dual_use = any(knowledge.CATEGORIES[c]["dual_use"] for c in cats
                   if c in knowledge.CATEGORIES)

    # Stage evidence that counts toward a chain. For an explained product the
    # ordinary companions (autostart, network) are part of being that product;
    # concealment and evasion still count.
    chain = {s: set(k) for s, k in by_stage.items() if s != "capture"}
    if explained and not unexplained:
        for s in ("persist", "egress", "stage"):
            chain.pop(s, None)
    strong = sorted(k for k in by_stage.get("conceal", ()) if k in vocab.STRONG_CONCEAL)
    other_stages = sorted(s for s in chain if s != "capture" and chain[s])

    weakness = []
    if subject.signature in ("none", "invalid"):
        weakness.append("unsigned or invalid signature")
    if subject.path_class in ("temp", "user_writable"):
        weakness.append("runs from a user-writable location")
    if subject.age_days is not None and subject.age_days < NEW_IMAGE_DAYS:
        weakness.append("image first seen recently")
    context = weakness if (unexplained or strong or other_stages) else []

    if strong:
        verdict = "VISIBILITY_CONTRADICTION"
    elif unexplained and len(other_stages) >= 2:
        verdict = "SUSPECT_CHAIN"
    elif unexplained:
        verdict = "UNEXPLAINED_CAPABILITY"
    elif explained:
        verdict = "EXPECTED_DUAL_USE" if dual_use else "EXPECTED_DECLARED"
    elif other_stages and by_stage.get("evade"):
        verdict = "UNEXPLAINED_CAPABILITY"
    else:
        verdict = "NO_SIGNAL"

    points = sum(min(vocab.STAGE_CAP[s], sum(vocab.KINDS[k][1] for k in kinds))
                 for s, kinds in {**{"capture": unexplained}, **chain}.items())
    stage_names = sorted(({"capture"} if unexplained else set()) | set(chain))
    missing_stages = sorted(set(vocab.STAGES) - set(stage_names) - {"evade"})
    blind = _blind(caps | set(), missing_stages)
    depth = VERDICT_DEPTH[verdict]
    if strong and unexplained:
        depth = 3       # forensic trace is proposed only; a human must authorize it
    matches = (_matches(unexplained, set(stage_names), blind)
               if verdict not in ("NO_SIGNAL", "EXPECTED_DECLARED") else [])
    reasons = []
    if subject.runs_script and caps:
        reasons.append("a signed script host: its signature says nothing about the script")
    if explained:
        anchor = ("path-verified core OS daemon" if cats == ["linux_os_component"]
                  else "valid signature, exact publisher")
        reasons.append("explained by " + "/".join(cats) + f" ({anchor})"
                       + (" - dual-use: confirm you installed it" if dual_use else ""))
    if unexplained:
        reasons.append("unexplained capture: " + ", ".join(sorted(unexplained)))
    if strong:
        reasons.append("concealment: " + ", ".join(strong))
    if other_stages:
        reasons.append("chain stages present: " + ", ".join(other_stages))
    if context:
        reasons.append("context: " + "; ".join(context))
    return {
        "key": subject.key, "host": subject.host, "label": subject.label,
        "verdict": verdict, "points": points, "stages": stage_names,
        "capture": sorted(caps), "explained": sorted(explained),
        "unexplained": sorted(unexplained), "categories": cats,
        "observation_depth": depth,
        "depth_needs_human": depth >= 3,
        "response_level": VERDICT_LEVEL[verdict],
        "reasons": reasons, "archetypes": matches,
        "missing_stages": missing_stages, "blind_mechanisms": blind,
        "degraded_sources": degraded,
        "note": "a verdict names observations and missing evidence, not intent",
    }


def assess_all(subjects, limit=200):
    rows = [assess(s) for s in subjects[:2000]]
    order = {"VISIBILITY_CONTRADICTION": 0, "SUSPECT_CHAIN": 1, "UNEXPLAINED_CAPABILITY": 2,
             "EXPECTED_DUAL_USE": 3, "EXPECTED_DECLARED": 4, "NO_SIGNAL": 5}
    rows.sort(key=lambda r: (order[r["verdict"]], -r["points"], r["key"]))
    return rows[:limit]


def jev_features(row, subject):
    """Fixed-vocabulary metadata for the advisory model. No names, paths,
    publishers, keys or free text; only enums, kind labels and booleans. The
    deterministic verdict is withheld so the advisory stays an independent opinion."""
    age = subject.age_days
    return {
        "capture_kinds": sorted(row["capture"]),
        "explained_kinds": sorted(row["explained"]),
        "stages_present": row["stages"],
        "concealment": sorted(k for k in (o.kind for o in subject.observations if o.positive())
                              if k in vocab.STRONG_CONCEAL),
        "signature": subject.signature if subject.signature in vocab.SIGNATURES else "unknown",
        "path_class": subject.path_class if subject.path_class in vocab.PATH_CLASSES else "unknown",
        "declared_category": (row["categories"] or ["none"])[0],
        "image_age_band": ("unknown" if age is None else "new" if age < NEW_IMAGE_DAYS
                           else "established"),
        "has_visible_window": subject.has_window,
        "blind_mechanism_count": len(row["blind_mechanisms"]),
    }
