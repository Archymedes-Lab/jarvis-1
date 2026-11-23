"""The property catalogue: one sentence the pure engines must keep for every
input in a generated space. Shipped inside the package so an installed copy
can re-run them (python -m jarvis.verify); tests/test_verify_props.py runs
the same catalogue under unittest. Standard library only."""

from jarvis.collectors.host.inputwatch import watchers
from jarvis.collectors.identity import bruteforce
from jarvis.core.reasoning import engine, vocab
from jarvis.response.actions import ban_source
from jarvis.response.reporting import score
from jarvis.service.schedule import JOBS
from jarvis.verify.props import PropertyFailure, forall

NOW = 2_000_000_000
CASES = 150          # per property; replayable by seed and index

# ---------------------------------------------------------------- score ----
SEVERITIES = ("critical", "high", "medium", "low", "ok")
SCORED = [j for j in JOBS if j in score.AREA_OF]


def gen_finding(g):
    return {"category": g.choice(("thing", "attack surface", "malware defense")),
            "severity": g.choice(SEVERITIES), "title": f"t{g.int(0, 6)}",
            "where": "", "host": g.choice(("win", "wsl")), "detail": f"d{g.int(0, 3)}"}


def gen_snapshots(g):
    out = {}
    for job, (interval, _label) in JOBS.items():
        state = g.choice(("current", "current", "current", "stale", "failing", "missing"))
        if state == "missing":
            continue
        ts = NOW - (interval * 3 + 600 if state == "stale" else g.int(0, interval))
        out[job] = {"ts": ts, "error": "boom" if state == "failing" else "",
                    "findings": g.list(gen_finding, 0, 4)}
    return out


def total(snaps):
    return score.compute(snaps, JOBS, NOW)["score"]



# ------------------------------------------------------------ reasoning ----
RANK = {"NO_SIGNAL": 0, "EXPECTED_DECLARED": 1, "EXPECTED_DUAL_USE": 2,
        "UNEXPLAINED_CAPABILITY": 3, "SUSPECT_CHAIN": 4, "VISIBILITY_CONTRADICTION": 5}
KINDS = sorted(vocab.KINDS)


def gen_observation(g):
    return vocab.Observation(kind=g.choice(KINDS), source=g.choice(("a", "b", "c")),
                             fresh=g.bool(0.8), complete=g.bool(0.8))


def gen_subject(g):
    return vocab.Subject(
        key=f"k{g.int(0, 9)}", host=g.choice(("win", "wsl")), label="x",
        signature=g.choice(vocab.SIGNATURES), publisher=g.choice(("", "Acme", "Microsoft")),
        path_class=g.choice(vocab.PATH_CLASSES),
        age_days=g.choice((None, 0, 7, 30, 400)), has_window=g.choice((None, True, False)),
        runs_script=g.bool(0.2), observations=g.list(gen_observation, 0, 6))


# ------------------------------------------------------------- watchers ----
SEV = {None: -1, "ok": 0, "low": 1, "medium": 2, "high": 3}


def gen_row(g):
    kind = g.choice(("hook", "hook", "rawinput", "poll", "winevent"))
    typ = {"hook": str(g.choice((13, 14, 0, 2, 3, 7, -1, 4))),
           "rawinput": f"{g.choice((1, 2))}/{g.choice((6, 2, 5))}/{g.choice((0, 256, 257, 4096))}",
           "poll": "getasynckeystate", "winevent": "any"}[kind]
    signed = g.bool()
    return {"kind": kind, "type": typ, "pid": g.int(1, 9), "start": g.int(0, 2),
            "path": g.choice(("", r"C:\Windows\explorer.exe", r"C:\Program Files\A\a.exe",
                              r"C:\Users\u\AppData\x.exe",
                              r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")),
            "via": "live", "sig": "Valid" if signed else g.choice(("NotSigned", "HashMismatch")),
            "signer": "Vendor" if signed else "", "first": 10, "last": 20, "count": 1,
            "lib": g.choice(("", "NULL", "hook.dll")), "failed": g.bool(0.1),
            "visible_windows": g.choice((None, 0, 2)), "exited": g.bool(0.2),
            "calls": g.choice((None, 500, 6000)), "ms": g.choice((None, 90, 400))}


def sev(row, own=()):
    f = watchers.classify(row, own)
    return SEV[f["severity"] if f else None]


# ---------------------------------------------------------------- score ----
def score_range(snaps):
    r = score.compute(snaps, JOBS, NOW)
    assert 0 <= r["score"] <= 100 and 0 <= r["coverage"] <= 100, r["score"]
    for a in r["areas"]:
        assert a["score"] is None or 0 <= a["score"] <= 100
        assert not (a["blind"] and a["observed"] and a["score"]), "blind area must read 0"


def _snaps_and_job(g):
    snaps = gen_snapshots(g)
    current = [j for j in SCORED if j in snaps and not snaps[j]["error"]]
    return snaps, (g.choice(current) if current else None)


def gen_snaps_job(g):
    return _snaps_and_job(g)


def gen_snaps_job_finding(g):
    snaps, job = _snaps_and_job(g)
    return snaps, job, gen_finding(g)


def losing_a_collector_never_raises_the_score(case):
    snaps, job = case
    if job is None:
        return True
    before = total(snaps)
    lost = dict(snaps)
    lost[job] = dict(snaps[job], error="collector died")
    assert total(lost) <= before, f"{job}: {before} -> {total(lost)}"


def adding_a_finding_never_raises_the_score(case):
    snaps, job, finding = case
    if job is None:
        return True
    before = total(snaps)
    more = dict(snaps)
    more[job] = dict(snaps[job], findings=snaps[job]["findings"] + [finding])
    assert total(more) <= before, f"{job}: {before} -> {total(more)}"


def the_same_fact_twice_is_one_fact(case):
    snaps, job, finding = case
    if job is None:
        return True
    once = dict(snaps)
    once[job] = dict(snaps[job], findings=snaps[job]["findings"] + [finding])
    twice = dict(snaps)
    twice[job] = dict(snaps[job], findings=snaps[job]["findings"] + [finding, dict(finding)])
    assert total(once) == total(twice)


# ------------------------------------------------------------ reasoning ----
_CAP = sum(vocab.STAGE_CAP.values())


def verdict_is_well_formed_and_points_bounded(subject):
    r = engine.assess(subject)
    assert r["verdict"] in RANK, r["verdict"]
    assert 0 <= r["points"] <= _CAP, r["points"]
    assert r["depth_needs_human"] == (r["observation_depth"] >= 3)
    assert r["response_level"] <= 2


def stale_or_incomplete_observations_never_count(subject):
    full = engine.assess(subject)
    only_positive = vocab.Subject(**{**subject.__dict__,
                                     "observations": [o for o in subject.observations
                                                      if o.positive()]})
    clean = engine.assess(only_positive)
    assert (full["verdict"], full["points"], full["stages"]) == \
           (clean["verdict"], clean["points"], clean["stages"]), (full, clean)
    degraded = {o.source for o in subject.observations if not o.positive()}
    assert set(full["degraded_sources"]) == degraded


def gen_subject_and_observation(g):
    return gen_subject(g), vocab.Observation(kind=g.choice(KINDS), source="z")


def adding_a_positive_observation_never_lowers_the_verdict(case):
    # The invariant (SPYWARE-REASONING.md #5) is about the verdict. Points are
    # not monotone in general: a capture capability explained by the
    # subject's own publisher turns its companions into "part of being that
    # product", so chain points drop while the verdict rises. Points stay
    # monotone when the added evidence is not a capture capability.
    subject, extra = case
    before = engine.assess(subject)
    more = vocab.Subject(**{**subject.__dict__,
                            "observations": subject.observations + [extra]})
    after = engine.assess(more)
    assert RANK[after["verdict"]] >= RANK[before["verdict"]], \
        (before["verdict"], after["verdict"], extra)
    if vocab.KINDS[extra.kind][0] != "capture":
        assert after["points"] >= before["points"], (before["points"], after["points"], extra)


# ------------------------------------------------------------- watchers ----
def signing_never_raises_severity(row):
    s = sev(row)
    signed = dict(row, sig="Valid", signer="Vendor")
    assert sev(signed) <= s or row["path"] == "", (row, s, sev(signed))
    unsigned = dict(row, sig="NotSigned", signer="")
    assert sev(unsigned) >= s or row["path"] == ""


def a_watcher_that_exited_keeps_its_severity(row):
    assert sev(dict(row, exited=True)) == sev(dict(row, exited=False))


def own_supervised_pid_is_always_ok_or_ignored(row):
    s = sev(row, own=[row["pid"]])
    assert s <= 0, s


def failed_registrations_never_produce_a_finding(row):
    if row["kind"] == "hook":
        assert watchers.classify(dict(row, failed=True)) is None


# --------------------------------------------------------- containment ----
# V15: the observed party writes the user name of a failed logon; Windows
# writes the source address. Only the address may become a ban target.
SOURCES = ("45.155.205.7", "2a00:1450:4001::1", "198.51.100.4", "10.0.0.5", "-")
NAME_TOKENS = ("admin", "x", "from", "in", "24h", "1h", "8.8.8.8", "1.1.1.1", "45.155.205.8",
               "local", "|", "-", "2a00:1450:4001::2")
# Whole clauses in the detector's own shape: an attack writes these, and four
# exact words in order are too rare to arise from single tokens in 150 cases.
NAME_CLAUSES = ("from 8.8.8.8 in 24h", "from 1.1.1.1 in 1h", "from 2a00:1450:4001::2 in 24h",
                "x|8.8.8.8", "from local in 24h")


def gen_guess(g):
    words = [g.choice(NAME_CLAUSES if g.bool(0.4) else NAME_TOKENS) for _ in range(g.int(0, 6))]
    name = "".join(w + g.choice((" ", "", "|")) for w in words).strip()
    return {"user": name, "source": g.choice(SOURCES)}


def a_guessed_name_never_chooses_the_target(case):
    data = {"auditing": 1, "total": 30, "lockouts": 0,
            "top": [{"key": f"{case['user']}|{case['source']}|0xc000006d|0xc0000064|", "n": 30}]}
    action = ban_source.BanSource()
    targets = [action.match(f, "bruteforce") for f in bruteforce.windows_findings(data)]
    real = ban_source._public_ip(case["source"])
    assert all(t is None or t["ip"] == real for t in targets), targets
    # The defence still works: a public source is found whatever the name says.
    if real:
        assert {"ip": real} in targets, targets


# (invariant id, name, generator, property). Ids follow VERIFICATION-LADDER.md.
PROPERTIES = (
    ("V1", "score range", gen_snapshots, score_range),
    ("V1", "blindness never improves the score", gen_snaps_job, losing_a_collector_never_raises_the_score),
    ("V2", "findings never improve the score", gen_snaps_job_finding, adding_a_finding_never_raises_the_score),
    ("V2", "duplicate findings do not double count", gen_snaps_job_finding, the_same_fact_twice_is_one_fact),
    ("V3", "assess well-formed", gen_subject, verdict_is_well_formed_and_points_bounded),
    ("V3", "missing evidence never counts", gen_subject, stale_or_incomplete_observations_never_count),
    ("V4", "evidence is monotone", gen_subject_and_observation, adding_a_positive_observation_never_lowers_the_verdict),
    ("V5", "signature only lowers severity", gen_row, signing_never_raises_severity),
    ("V5", "exit does not launder a watcher", gen_row, a_watcher_that_exited_keeps_its_severity),
    ("V5", "own hook never counts", gen_row, own_supervised_pid_is_always_ok_or_ignored),
    ("V5", "failed hooks are not watchers", gen_row, failed_registrations_never_produce_a_finding),
    ("V15", "a guessed user name never chooses the banned address", gen_guess,
     a_guessed_name_never_chooses_the_target),
)


def check(invariant, name, generate, prop, cases=CASES, seed=0):
    """One property -> {"invariant", "name", "ok", "cases", "error"}."""
    try:
        forall(name, generate, prop, cases, seed)
    except PropertyFailure as exc:
        return {"invariant": invariant, "name": name, "ok": False, "cases": cases,
                "error": str(exc)[:800]}
    except Exception as exc:  # a crash is a failure, never a pass
        return {"invariant": invariant, "name": name, "ok": False, "cases": cases,
                "error": f"{type(exc).__name__}: {exc}"[:800]}
    return {"invariant": invariant, "name": name, "ok": True, "cases": cases, "error": ""}


def run(cases=CASES, seed=0):
    return [check(i, n, g, p, cases, seed) for i, n, g, p in PROPERTIES]
