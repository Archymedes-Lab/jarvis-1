import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import acknowledge
from jarvis.service import autopilot as ap
from jarvis.service import detectorhealth

NOW = 2_000_000_000


def f(sev="high", title="credential in config", where="C:/scratch/a/one.json",
      category="credentials", detail="key found"):
    return {"category": category, "severity": sev, "title": title, "detail": detail,
            "where": where, "host": "win"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def put(self, findings, job="creds"):
        self.store.save_snapshot(job, findings)

    def state(self, fid):
        return ap._row(self.store, fid)["state"]

    def fid(self, finding, job="creds"):
        return acknowledge.finding_id(finding, job)

    def report(self, **dets):
        d = [dict({"id": k, "state": v, "error": "", "recovery_confirmed": False}) for k, v in dets.items()]
        healthy = sum(1 for x in d if x["state"] == detectorhealth.HEALTHY)
        return {"detectors": d, "total": len(d),
                "counts": {"verified": healthy, "partial": 0, "blind": len(d) - healthy}}


class InvestigationTests(Base):
    def test_new_finding_is_queued_then_investigated_automatically(self):
        a = f()
        self.put([a])
        self.assertEqual(ap.sync(self.store, NOW), 1)
        self.assertEqual(self.state(self.fid(a)), ap.QUEUED)
        ap.run_queue(self.store, NOW, use_ai=False)
        self.assertEqual(self.state(self.fid(a)), ap.NEEDS_USER)
        rep = ap._report(ap._row(self.store, self.fid(a)))
        self.assertTrue(rep["known"] and rep["unknown"])
        self.assertEqual(rep["assessment"], "suspicious")

    def test_unchanged_finding_is_not_reinvestigated(self):
        a = f(sev="low", where="C:/x/y.txt")
        self.put([a])
        ap.sync(self.store, NOW)
        ap.run_queue(self.store, NOW, use_ai=False)
        self.assertEqual(ap.sync(self.store, NOW + 60), 0)
        self.assertEqual(ap.sync(self.store, NOW + ap.REFRESH_S + 1), 1)   # scheduled refresh
        self.put([f(sev="low", where="C:/x/y.txt", detail="key found")])

    def test_changed_evidence_reopens(self):
        a = f(sev="low")
        self.put([a])
        ap.sync(self.store, NOW)
        ap.run_queue(self.store, NOW, use_ai=False)
        fid = self.fid(a)
        before = ap._row(self.store, fid)["evidence"]
        changed = dict(a, severity="high")
        self.put([changed])
        ap.sync(self.store, NOW + 5)
        row = ap._row(self.store, self.fid(changed)) or ap._row(self.store, fid)
        self.assertNotEqual(row["evidence"], before)

    def test_failed_investigation_stays_failed_and_backs_off(self):
        a = f()
        self.put([a])
        ap.sync(self.store, NOW)
        with mock.patch.object(ap, "investigate", side_effect=RuntimeError("boom")):
            ap.run_queue(self.store, NOW, use_ai=False)
        row = ap._row(self.store, self.fid(a))
        self.assertEqual(row["state"], ap.FAILED)
        self.assertIn("boom", row["error"])
        self.assertGreater(row["next_run"], NOW)
        self.assertEqual(ap.sync(self.store, NOW + 1), 0)                  # not before the backoff

    def test_no_detail_is_insufficient_not_investigated(self):
        a = f(where="", detail="")
        self.put([a])
        ap.sync(self.store, NOW)
        ap.run_queue(self.store, NOW, use_ai=False)
        self.assertEqual(self.state(self.fid(a)), ap.INSUFFICIENT)

    def test_interrupted_investigation_resumes_after_restart(self):
        a = f()
        self.put([a])
        ap.sync(self.store, NOW)
        ap._move(self.store, self.fid(a), ap.INVESTIGATING, "started", NOW)
        self.assertEqual(ap.recover_interrupted(self.store, NOW + ap.STALE_RUN_S + 1), 1)
        self.assertEqual(self.state(self.fid(a)), ap.QUEUED)

    def test_state_changes_are_audited_and_illegal_ones_refused(self):
        a = f()
        self.put([a])
        ap.sync(self.store, NOW)
        with self.assertRaises(ValueError):
            ap._move(self.store, self.fid(a), ap.APPLIED, "skip", NOW)
        n = self.store.db.execute("SELECT COUNT(*) FROM investigation_events WHERE fid=?",
                                  (self.fid(a),)).fetchone()[0]
        self.assertGreaterEqual(n, 1)

    def test_governor_pressure_defers_all_work(self):
        self.put([f()])
        ap.sync(self.store, NOW)
        self.assertTrue(ap.run_queue(self.store, NOW, pressured=True)["deferred"])
        self.assertEqual(self.store.db.execute(
            "SELECT COUNT(*) FROM investigations WHERE state=?", (ap.QUEUED,)).fetchone()[0], 1)

    def test_batch_is_bounded(self):
        self.put([f(title=f"t{i}", where=f"C:/d{i}/x.json") for i in range(ap.BATCH + 7)])
        ap.sync(self.store, NOW)
        self.assertEqual(ap.run_queue(self.store, NOW, use_ai=False)["investigated"], ap.BATCH)

    def test_model_unavailable_changes_nothing(self):
        a = f()
        self.put([a])
        ap.sync(self.store, NOW)
        with mock.patch("jarvis.response.llm.ping", return_value=("offline", 0.1)):
            ap.run_queue(self.store, NOW, conf={})
        self.assertEqual(self.state(self.fid(a)), ap.NEEDS_USER)
        self.assertEqual(ap._report(ap._row(self.store, self.fid(a))).get("ai"), "unavailable")


class GroupingTests(Base):
    def test_same_folder_groups_and_each_member_keeps_its_evidence(self):
        items = [f(title=f"cred {i}", where=f"C:/scratch/a/f{i}.json", detail=f"d{i}") for i in range(3)]
        items[1]["severity"] = "medium"
        self.put(items)
        ap.sync(self.store, NOW)
        ap.run_queue(self.store, NOW, use_ai=False)
        keys = {ap._row(self.store, self.fid(i))["group_key"] for i in items}
        self.assertEqual(len(keys), 1)
        case = ap.decision_queue(self.store)[0]
        self.assertEqual(case["count"], 3)
        self.assertEqual({o["severity"] for o in case["observations"]}, {"high", "medium"})
        self.assertEqual(len(case["observations"]), 3)

    def test_same_title_elsewhere_is_not_merged(self):
        a = f(title="same", where="C:/one/a.json")
        b = f(title="same", where="C:/two/a.json")
        self.assertNotEqual(ap.group_key(a, "creds"), ap.group_key(b, "creds"))

    def test_one_tools_files_share_a_root_but_two_tools_do_not(self):
        r = ap.locus_root
        self.assertEqual(r("C:/Users/u/AppData/Local/Temp/claude/x/s/scratchpad/node_modules/zod/v4/a.js"),
                         r("C:/Users/u/AppData/Local/Temp/claude/y/other/b.js"))
        self.assertNotEqual(r("C:/Users/u/AppData/Local/Temp/claude/a.js"), r("C:/Users/u/AppData/Local/Temp/other/a.js"))
        self.assertNotEqual(r("C:/Users/u/AppData/Local/Programs/cursor/a.exe"), r("C:/Users/u/AppData/Local/Programs/trae/a.exe"))
        self.assertEqual(r("%SystemRoot%/system32/svchost.exe", "firewall"), "%systemroot%/system32/svchost.exe")

    def test_no_location_is_never_grouped(self):
        a, b = f(where="", detail="x"), f(where="", detail="y")
        self.assertNotEqual(ap.group_key(a, "j"), ap.group_key(b, "j"))


class DecisionTests(Base):
    def waiting(self, n=2):
        items = [f(title=f"c{i}", where=f"C:/s/a/f{i}.json", detail=f"d{i}") for i in range(n)]
        self.put(items)
        ap.sync(self.store, NOW)
        ap.run_queue(self.store, NOW, use_ai=False)
        return items, ap.decision_queue(self.store)[0]["key"]

    def test_one_case_instead_of_many_questions(self):
        _items, _key = self.waiting(5)
        self.assertEqual(len(ap.decision_queue(self.store)), 1)

    def test_recognise_is_scoped_to_exact_observations(self):
        items, key = self.waiting(2)
        out = ap.decide(self.store, key, "recognise", [self.fid(items[0])], now=NOW + 1)
        self.assertFalse(out["applies_to_future"])
        self.assertEqual(self.state(self.fid(items[0])), ap.INVESTIGATED)
        self.assertEqual(self.state(self.fid(items[1])), ap.NEEDS_USER)
        self.assertEqual(acknowledge.load(self.store), {})                 # nothing whitelisted
        # a new sibling in the same folder is still asked about
        new = f(title="new", where="C:/s/a/new.json", detail="n")
        self.put(items + [new])
        ap.sync(self.store, NOW + 2)
        ap.run_queue(self.store, NOW + 2, use_ai=False)
        self.assertEqual(self.state(self.fid(new)), ap.NEEDS_USER)

    def test_recognition_does_not_survive_changed_evidence(self):
        items, key = self.waiting(1)
        ap.decide(self.store, key, "recognise", now=NOW + 1)
        changed = dict(items[0], detail="a different secret now")
        self.put([changed])
        ap.sync(self.store, NOW + 2)
        ap.run_queue(self.store, NOW + 2, use_ai=False)
        self.assertEqual(self.state(self.fid(changed)), ap.NEEDS_USER)

    def test_not_recognised_proposes_but_does_not_authorize(self):
        items, key = self.waiting(1)
        ap.decide(self.store, key, "not_recognise", now=NOW + 1)
        fid = self.fid(items[0])
        self.assertEqual(self.state(fid), ap.PROPOSED)
        with self.assertRaises(ValueError):
            ap.mark_applied(self.store, fid, True)                         # cannot apply unauthorised
        ap.authorize(self.store, fid, NOW + 2)
        self.assertEqual(self.state(fid), ap.AUTHORIZED)
        ap.mark_applied(self.store, fid, True, now=NOW + 3)
        self.assertEqual(self.state(fid), ap.APPLIED)
        self.put([])                                                       # gone after the action
        ap.sync(self.store, NOW + 4)
        self.assertEqual(self.state(fid), ap.VERIFIED)

    def test_investigating_never_authorises_remediation(self):
        items, key = self.waiting(1)
        ap.decide(self.store, key, "investigate_further", now=NOW + 1)
        self.assertEqual(self.state(self.fid(items[0])), ap.QUEUED)
        with self.assertRaises(ValueError):
            ap.authorize(self.store, self.fid(items[0]))

    def test_authorizing_one_finding_does_not_touch_another(self):
        items, key = self.waiting(2)
        ap.decide(self.store, key, "not_recognise", now=NOW + 1)
        ap.authorize(self.store, self.fid(items[0]), NOW + 2)
        self.assertEqual(self.state(self.fid(items[1])), ap.PROPOSED)

    def test_decision_is_recorded_with_scope_and_time(self):
        items, key = self.waiting(2)
        ap.decide(self.store, key, "recognise", [self.fid(items[0])], note="mine", now=NOW + 9)
        row = self.store.db.execute("SELECT * FROM autopilot_decisions").fetchone()
        self.assertEqual(row["ts"], NOW + 9)
        self.assertEqual(list(json.loads(row["scope"])), [self.fid(items[0])])


class RecoveryTests(Base):
    def test_transient_failure_backs_off_with_jitter_and_exhausts(self):
        rep = self.report(netwatch=detectorhealth.FAILING)
        rng = lambda: 0.5
        plan = ap.plan_recovery(self.store, rep, NOW, rng)
        self.assertEqual(plan[0]["action"], "wait")
        t, sent = NOW, []
        for _ in range(ap.RECOVERY_MAX_RETRIES + 3):
            t += ap.RETRY_CAP_S + 1
            plan = ap.plan_recovery(self.store, rep, t, rng)
            sent.append(ap.run_recovery(self.store, plan, lambda j: True, t, rng=rng))
        self.assertEqual(sum(sent), ap.RECOVERY_MAX_RETRIES)               # a bounded budget
        row = self.store.db.execute("SELECT * FROM recovery").fetchone()
        self.assertEqual(row["status"], "exhausted")
        self.assertGreater(row["next_try"], t)                             # cooldown, not a storm

    def test_backoff_grows_and_is_capped(self):
        mid = lambda: 0.5
        self.assertLess(ap.backoff(0, mid), ap.backoff(3, mid))
        self.assertLessEqual(ap.backoff(30, lambda: 1.0), int(ap.RETRY_CAP_S * 1.25))

    def test_permanent_causes_are_not_retried(self):
        rep = self.report(a=detectorhealth.MISSING_DEP, b=detectorhealth.RESTRICTED)
        rep["detectors"].append({"id": "feed", "state": detectorhealth.FAILING,
                                 "error": "HTTP Error 410: Gone", "recovery_confirmed": False})
        rep["total"] = 3
        plan = ap.plan_recovery(self.store, rep, NOW)
        self.assertTrue(all(p["action"] == "none" for p in plan))
        self.assertEqual({p["klass"] for p in plan}, {"missing_dependency", "permission", "source_unavailable"})
        calls = []
        ap.run_recovery(self.store, plan, lambda j: calls.append(j), NOW)
        self.assertEqual(calls, [])

    def test_pressure_postpones_retries(self):
        rep = self.report(x=detectorhealth.FAILING)
        ap.plan_recovery(self.store, rep, NOW)
        plan = ap.plan_recovery(self.store, rep, NOW + 4000)
        calls = []
        ap.run_recovery(self.store, plan, lambda j: calls.append(j), NOW + 4000, pressured=True)
        self.assertEqual(calls, [])

    def test_retry_storm_is_limited_per_cycle(self):
        rep = self.report(**{f"j{i}": detectorhealth.FAILING for i in range(9)})
        ap.plan_recovery(self.store, rep, NOW)
        plan = ap.plan_recovery(self.store, rep, NOW + 5000)
        self.assertEqual(ap.run_recovery(self.store, plan, lambda j: True, NOW + 5000), ap.RECOVERY_PER_CYCLE)

    def test_recovery_cleared_only_when_confirmed_healthy(self):
        rep = self.report(x=detectorhealth.FAILING)
        ap.plan_recovery(self.store, rep, NOW)
        ok = self.report(x=detectorhealth.HEALTHY)
        ap.plan_recovery(self.store, ok, NOW + 1)                          # healthy but unconfirmed
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM recovery").fetchone()[0], 1)
        ok["detectors"][0]["recovery_confirmed"] = True
        ap.plan_recovery(self.store, ok, NOW + 2)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM recovery").fetchone()[0], 0)

    def test_stale_collector_is_never_healthy(self):
        snap = {"ts": NOW - 10 * 86400, "findings": [], "error": ""}
        det = detectorhealth.assess("x", snap, 300, now=NOW)
        self.assertNotEqual(det["state"], detectorhealth.HEALTHY)

    def test_missing_model_does_not_stop_deterministic_work(self):
        self.put([f(sev="low", where="C:/q/z.txt")])
        with mock.patch("jarvis.response.llm.ping", return_value=("offline", 0.1)):
            out = ap.cycle(self.store, self.report(x=detectorhealth.HEALTHY), conf={}, now=NOW)
        self.assertEqual(out["investigated"], 1)


class HealthAndNoticeTests(Base):
    def test_one_definition_of_the_health_numbers(self):
        rep = self.report(a=detectorhealth.HEALTHY, b=detectorhealth.FAILING, c=detectorhealth.HEALTHY)
        nums = ap.health_numbers(rep)
        self.assertEqual((nums["reporting"], nums["total"], nums["not_reporting"]), (2, 3, 1))
        st = ap.status(self.store, rep, NOW)
        self.assertEqual(st["health"]["monitoring"], nums)
        self.assertEqual(st["summary"]["monitoring"], nums)

    def test_notifications_are_deduplicated_and_consolidated(self):
        items = [f(title=f"c{i}", where=f"C:/s/a/f{i}.json", detail=f"d{i}") for i in range(4)]
        self.put(items)
        ap.sync(self.store, NOW)
        ap.run_queue(self.store, NOW, use_ai=False)
        first = ap.take_notices(self.store, NOW)
        self.assertEqual(len(first), 1)                                     # four items, one notice
        self.assertEqual(ap.take_notices(self.store, NOW + 60), [])         # not repeated

    def test_collector_retries_do_not_notify(self):
        ap.plan_recovery(self.store, self.report(x=detectorhealth.FAILING), NOW)
        self.assertEqual(ap.take_notices(self.store, NOW), [])

    def test_quiet_hours_hold_non_critical(self):
        self.put([f()])
        ap.sync(self.store, NOW)
        ap.run_queue(self.store, NOW, use_ai=False)
        hour = __import__("time").localtime(NOW).tm_hour
        self.store.set_meta(ap.PREFS_KEY, json.dumps({"quiet_start": hour, "quiet_end": (hour + 2) % 24}))
        self.assertEqual(ap.take_notices(self.store, NOW), [])

    def test_summary_counts_and_limitations(self):
        self.put([f()])
        ap.sync(self.store, NOW)
        ap.run_queue(self.store, NOW, use_ai=False)
        s = ap.daily_summary(self.store, self.report(a=detectorhealth.FAILING), NOW + 5)
        self.assertEqual(s["new_findings"], 1)
        self.assertEqual(s["needs_attention"], 1)
        self.assertTrue(any("not reporting" in x for x in s["limitations"]))

    def test_no_code_path_performs_remediation(self):
        src = open(ap.__file__, encoding="utf-8").read()
        for banned in ("os.remove", "os.unlink", "shutil", "subprocess", "taskkill", "netsh", "os.system"):
            self.assertNotIn(banned, src)


if __name__ == "__main__":
    unittest.main()


DAY = 86400


class AutoHandleTests(Base):
    def waiting(self, sev="high", n=2, category="accounts"):
        items = [f(sev=sev, title=f"c{i}", where=f"C:/s/a/f{i}.json", detail=f"d{i}", category=category)
                 for i in range(n)]
        self.put(items, job="accounts")
        ap.sync(self.store, NOW)
        ap.run_queue(self.store, NOW, use_ai=False)
        return items

    def test_off_by_default_decides_nothing(self):
        self.waiting()
        self.assertFalse(ap.auto_handle_enabled(self.store))
        self.assertEqual(ap.auto_handle(self.store, NOW + 9 * DAY), 0)
        self.assertEqual(len(ap.decision_queue(self.store)), 1)

    def test_enabled_recognises_standing_confirm_items_and_audits_it(self):
        items = self.waiting()
        owners = {ap._report(m).get("owner") for m in ap._members(self.store, ap.decision_queue(self.store)[0]["key"])}
        self.assertEqual(owners, {"you_confirm"}, "fixture must be an owner-confirm kind")
        ap.set_auto_handle(self.store, True)
        self.assertEqual(ap.auto_handle(self.store, NOW + 4 * DAY), 2)
        self.assertEqual(ap.decision_queue(self.store), [])
        self.assertEqual(self.state(acknowledge.finding_id(items[0], "accounts")), ap.INVESTIGATED)
        note = self.store.db.execute("SELECT note FROM autopilot_decisions ORDER BY id DESC").fetchone()["note"]
        self.assertIn("auto-handled", note)

    def test_new_items_wait_until_they_have_stood_three_days(self):
        self.waiting()
        ap.set_auto_handle(self.store, True)
        self.assertEqual(ap.auto_handle(self.store, NOW + 2 * DAY), 0)
        self.assertEqual(len(ap.decision_queue(self.store)), 1)

    def test_never_decides_for_critical(self):
        self.waiting(sev="critical", n=1)
        ap.set_auto_handle(self.store, True)
        self.assertEqual(ap.auto_handle(self.store, NOW + 30 * DAY), 0)
        self.assertEqual(len(ap.decision_queue(self.store)), 1)

    def test_only_you_do_items_always_ask(self):
        self.waiting(category="credentials", n=1)       # "rotate this credential": only the owner can act
        ap.set_auto_handle(self.store, True)
        key = ap.decision_queue(self.store)[0]["key"]
        owner = ap._report(ap._members(self.store, key)[0]).get("owner")
        if owner == "you_confirm":
            self.skipTest("this category is owner-confirm in this build")
        self.assertEqual(ap.auto_handle(self.store, NOW + 30 * DAY), 0)

    def test_changed_evidence_reopens_an_auto_handled_item(self):
        items = self.waiting(n=1)
        ap.set_auto_handle(self.store, True)
        self.assertEqual(ap.auto_handle(self.store, NOW + 4 * DAY), 1)
        changed = dict(items[0], detail="something else now")
        self.put([changed], job="accounts")
        ap.sync(self.store, NOW + 5 * DAY)
        ap.run_queue(self.store, NOW + 5 * DAY, use_ai=False)
        self.assertEqual(self.state(acknowledge.finding_id(changed, "accounts")), ap.NEEDS_USER)

    def test_per_cycle_bound(self):
        self.waiting(n=3)
        ap.set_auto_handle(self.store, True)
        self.assertEqual(ap.auto_handle(self.store, NOW + 4 * DAY, limit=2), 0)   # group larger than budget waits
