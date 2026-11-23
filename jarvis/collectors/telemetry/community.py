"""Community rule matches, judged per install before they become findings.

core/sigma.py says whether a community (Sigma) rule matches one event. Raw
matches cannot be findings as they are: replayed over 18 hours of this
project's own development machine, 28 rules matched 11,578 times, nearly all on
the monitor's own PowerShell audits (measured 2026-11-10). Exempting activity by
name is the evadable kind of allowance (DETECTION-CONTENT section 2.2), so this
module learns per install instead:

  * A *shape* is (rule, program, parent program). For the first BURN_IN_S after
    community rules first run on an install, each new shape is recorded and
    reported once as low inventory: "this already happens here". It is never
    silently accepted.
  * After that, a shape seen for the first time is a finding at the rule's
    capped severity. Known shapes only count.
  * Nothing is learned after the burn-in, so an attacker cannot teach the
    monitor a shape later by repeating it.
  * Learned shapes stay on the list as one standing low finding until a person
    has reviewed them (`jarvis rules`): learning demotes, it never hides.

Invariants
  1. No lost visibility: every match is either a finding or counted against a
     shape that was itself reported when learned; a pass that could not finish
     says so (never a silent partial pass).
  2. Bounded: at most MAX_DISTINCT distinct events are evaluated per pass and
     MAX_SHAPES shapes are kept; the rule file is bounded by core/sigma.py.
  3. Content is not authority: severity is capped (sigma.LEVEL), findings carry
     origin "sigma" and are never acted on unasked.
  4. Attribution: every finding names the rule's author (DRL 1.1).
  4b. A finding never quotes the command line: a community rule has no notion of
     which part is safe to show, and command lines carry passwords and tokens.
  5. A rule file that does not validate is reported, never read as "no rules".

Limits, stated: an attacker whose activity has the same shape as something
learned (for example PowerShell started by the same parent and matching the
same rule) is not reported by this layer; anything present during the burn-in
is inventory, not an alert. Without a store (a replay) nothing is learned and
every match is returned, which is what the detection benchmark measures.
"""

import json

from jarvis.core import sigma

META = "community_rules_v1"
BURN_IN_S = 7 * 86400
MAX_SHAPES = 2000
MAX_DISTINCT = 6000
MAX_LISTED = 12


def _base(path):
    return (path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()[:64]


def shape(rule, image, parent):
    return f"{rule.id}|{_base(image)}|{_base(parent)}"


def load_state(store):
    try:
        state = json.loads(store.get_meta(META, "") or "{}")
    except (TypeError, ValueError):
        state = {}
    if not isinstance(state, dict) or not isinstance(state.get("shapes"), dict) \
            or not isinstance(state.get("since"), (int, float)):
        return None
    return state


def scan(category, rows, fields):
    """Match `rows` against the community rules of `category`.

    `fields(row)` -> (image, parent, when, quoted text) for a matching row.
    -> (matches [(rule, image, parent, when, text)], skipped events, error text)."""
    idx, error = sigma.index(category)
    if error or not idx.rules:
        return [], 0, error
    memo, out, skipped = {}, [], 0
    for row in rows:
        event = sigma.prepare(category, row)
        key = tuple(event.values())
        if key not in memo:
            if len(memo) >= MAX_DISTINCT:
                skipped += 1
                continue
            memo[key] = idx.match(event)
        for rule in memo[key]:
            image, parent, when, text = fields(row)
            out.append((rule, image, parent, when, text))
    return out, skipped, ""


def judge(store, matches, now):
    """Split matches into alerts and newly learned shapes; persist the state.

    Without a store nothing is learned: every match is an alert.
    -> (alerts {shape: [rule, image, parent, count, when, text]}, learned [same])"""
    alerts, learned = {}, {}
    state = load_state(store) if store is not None else None
    fresh = store is not None and state is None
    if fresh:
        state = {"since": int(now), "shapes": {}}
    shapes = state["shapes"] if state else None
    burning = state is not None and now - state["since"] < BURN_IN_S
    changed = fresh
    for rule, image, parent, when, text in matches:
        key = shape(rule, image, parent)
        if shapes is not None and key in shapes:
            if key in learned:
                learned[key][3] += 1
            continue
        if burning and len(shapes) < MAX_SHAPES:
            shapes[key] = {"first": int(now), "title": rule.title[:120], "author": rule.author[:120],
                           "reviewed": False}
            learned[key] = [rule, image, parent, 1, when, text]
            changed = True
            continue
        hit = alerts.setdefault(key, [rule, image, parent, 0, when, text])
        hit[3] += 1
        hit[4] = when or hit[4]
    if changed:
        store.set_meta(META, json.dumps(state, sort_keys=True))
    return alerts, list(learned.values())


def unreviewed(state):
    """[(shape key, entry)] learned shapes nobody has reviewed yet."""
    return [(k, v) for k, v in sorted((state or {}).get("shapes", {}).items())
            if isinstance(v, dict) and not v.get("reviewed")]


def review(store, keys=None):
    """Mark learned shapes as reviewed (all of them when `keys` is None). -> how many."""
    state = load_state(store)
    if not state:
        return 0
    done = 0
    for key, entry in state["shapes"].items():
        if isinstance(entry, dict) and not entry.get("reviewed") and (keys is None or key in keys):
            entry["reviewed"] = True
            done += 1
    if done:
        store.set_meta(META, json.dumps(state, sort_keys=True))
    return done


def forget(store, key):
    """Drop one learned shape, so its next occurrence is judged afresh. -> True if it existed."""
    state = load_state(store)
    if not state or key not in state["shapes"]:
        return False
    del state["shapes"][key]
    store.set_meta(META, json.dumps(state, sort_keys=True))
    return True


def findings(category, rows, fields, make, store=None, now=0.0):
    """Findings for one detector pass. `make(severity, title, detail, image)` builds one."""
    matches, skipped, error = scan(category, rows, fields)
    out = []
    if error:
        f = make("medium", "Community detection rules could not be loaded",
                 f"{error}. No community rule ran in this pass; the built-in rules are unaffected. "
                 "Reinstalling the program restores the rule file.", "")
        f["origin"] = "sigma"
        return [f]
    alerts, _learned = judge(store, matches, now)
    for rule, image, parent, count, when, text in alerts.values():
        f = make(rule.severity, f"{rule.title} (community rule)",
                 f"{_base(image)} started by {_base(parent) or 'an unknown parent'}"
                 + (f" at {when}" if when else "") + (f", {count} times" if count > 1 else "")
                 + " (command line withheld: it may carry a secret)"
                 + f". This matches a community rule and is new on this computer; whether it was "
                   f"authorised is for you to confirm. {sigma.attribution(rule)}.", image)
        f["techniques"] = list(rule.tids)
        f["origin"] = "sigma"
        out.append(f)
    # Standing, not once: what was learned stays listed until someone has looked.
    # Emitted by the process-start pass only, so two passes do not list it twice.
    waiting = unreviewed(load_state(store)) if store is not None and category != sigma.WIN_REG else []
    if waiting:
        listed = "; ".join(
            f"{v.get('title', '?')} ({k.split('|')[1] or 'unknown'} under {k.split('|')[2] or 'unknown'}, "
            f"rule by {v.get('author') or 'its Sigma author'})" for k, v in waiting[:MAX_LISTED])
        f = make("low", "Existing activity matches community rules and has not been reviewed",
                 f"{len(waiting)} kind(s) of activity were already happening on this computer during the "
                 f"first week of community rules, so they do not alert: {listed}"
                 + (f"; and {len(waiting) - MAX_LISTED} more" if len(waiting) > MAX_LISTED else "")
                 + ". Anything you do not recognise is worth a look. List them with  jarvis rules  and "
                   f"mark them reviewed with  jarvis rules reviewed . Rules: {sigma.LICENSE}.", "")
        f["origin"] = "sigma"
        out.append(f)
    if skipped:
        f = make("low", "Community rules did not finish this pass",
                 f"{skipped} events were not checked against community rules because the pass reached "
                 f"its limit of {MAX_DISTINCT} distinct events. The built-in rules checked every event.", "")
        f["origin"] = "sigma"
        out.append(f)
    return out
