"""The daily `verify` job (service layer): re-run the verification ladder over the running
copy and record the result where the dashboard and the coverage audit read
it. Under a second of CPU; bulk lane; governor-deferrable.

A failure is reported high: the code that scores this machine no longer keeps
one of its own documented invariants, which is either a defect or a change to
the installed files. It is visibility about JARVIS itself, never a verdict
about the machine."""

import importlib
import json
import time

from jarvis.core.finding import LOCAL_HOST

META = "code_verification_v1"


def _finding(severity, title, detail, where="jarvis/verify"):
    return {"category": "visibility", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": LOCAL_HOST}


def audit(store, hosts=("wsl",)):
    # Loaded at run time, not imported: jarvis.verify sits above every layer
    # because it exercises all of them, so the service layer may not import
    # it statically (tests/test_layers.py). The job only hands the report to
    # the store; the verification itself stays a top-level concern.
    report_mod = importlib.import_module("jarvis.verify.report")
    try:
        report = report_mod.run()
    except Exception as exc:
        return [_finding("high", "Code verification could not run",
                         f"{type(exc).__name__}: {exc}"[:400])]
    try:
        store.set_meta(META, json.dumps({"at": int(time.time()), "ok": report["ok"],
                                         "summary": report_mod.summary(report),
                                         "python": report["python"],
                                         "failures": [x for x in report["properties"] + report["models"]
                                                      if not x["ok"]][:10]}))
        store.commit()
    except Exception:
        pass
    if report["ok"]:
        return [_finding("ok", "Installed code keeps its verified invariants",
                         report_mod.summary(report) + f" in {report['seconds']}s")]
    failed = [x for x in report["properties"] + report["models"] if not x["ok"]]
    if not report["lane_membership"]["ok"]:
        failed.append({"invariant": "V8", "name": "protection jobs in the fast lane",
                       "error": report["lane_membership"]["error"]})
    return [_finding(
        "high", "Installed code violates a verified invariant",
        "; ".join(f"{x['invariant']} {x['name']}: {x['error'][:160]}" for x in failed[:4])
        + ". The copy of JARVIS running here no longer keeps an invariant its tests "
        "prove (" + report_mod.summary(report) + "). Treat its scores as unverified "
        "and reinstall from a release whose manifest records a passing verification.")]
