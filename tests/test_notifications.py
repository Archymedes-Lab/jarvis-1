import json
import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.core.store import Store
from jarvis.response import alert
from jarvis.response.reporting import cadence, emails
from jarvis.response.reporting import notifications as n

CONF = {'resend_api_key':'test','alert_to':'owner@example.test','alert_from':'jarvis@example.test',
        'alert_digest_interval':3600}


class NotificationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=os.path.join(self.tmp.name,'test.db')
        self.store=Store(self.path)
        self.clock=patch('time.time',return_value=1000000); self.now=self.clock.start()
        self.sender=patch.object(alert,'send_email',return_value='');self.send=self.sender.start()
        self.f={'category':'intrusion','severity':'high','title':'unknown script','detail':'check','where':'file'}

    def tearDown(self):
        self.sender.stop();self.clock.stop();self.store.close();self.tmp.cleanup()

    # A hardening job: these tests are about digest timing, and a new high
    # from a threat detector (e.g. intrusion) interrupts instead.
    def observe(self,job='posture',findings=None,error=''):
        n.dispatch(self.store,CONF,job,[self.f] if findings is None else findings,error)

    def test_multiple_jobs_coalesce_and_survive_restart(self):
        self.observe();self.observe()
        f={**self.f,'title':'other script'}
        self.observe('other',[f]);self.observe('other',[f])
        self.send.assert_not_called()
        self.store.close();self.store=Store(self.path)
        self.now.return_value+=3601
        n.flush(self.store,CONF)
        self.send.assert_called_once()
        self.assertIn('(and 1 more, ',self.send.call_args.args[1])
        self.assertEqual(json.loads(self.store.get_meta(n.QUEUE)),{})

    def test_no_still_repeat_and_each_age_tier_sends_once(self):
        # A new critical interrupts at once; its age reminders do not. They
        # wait for the next digest, and each tier arrives once.
        self.f['severity']='critical';self.observe()
        self.assertEqual(self.send.call_count,1)
        self.now.return_value+=3601;self.observe()
        self.assertEqual(self.send.call_count,1)
        self.now.return_value+=3601;n.flush(self.store,CONF)
        self.assertEqual(self.send.call_count,2)
        self.assertIn('ESCALATED',self.send.call_args.args[2])
        self.now.return_value+=100;self.observe();n.flush(self.store,CONF)
        self.assertEqual(self.send.call_count,2)
        self.now.return_value+=100000;self.observe();self.observe()
        self.now.return_value+=3601;n.flush(self.store,CONF)
        self.assertEqual(self.send.call_count,3)
        self.now.return_value+=86400*30;self.observe()
        self.now.return_value+=3601;n.flush(self.store,CONF)
        self.assertEqual(self.send.call_count,3)

    def test_critical_worsening_bypasses_digest(self):
        self.observe();self.observe()
        self.f={**self.f,'severity':'critical'};self.observe()
        self.send.assert_called_once()
        self.assertIn('[CRITICAL]',self.send.call_args.args[2])

    def test_failed_initial_send_retries_without_acknowledging(self):
        self.f['severity']='critical';self.send.return_value='offline';self.observe()
        st=json.loads(self.store.get_meta(alert.STATE_META))[alert.finding_key(self.f)]
        self.assertEqual(st['last_sent'],0)
        self.assertTrue(json.loads(self.store.get_meta(n.QUEUE)))
        self.send.return_value='';self.now.return_value+=301;self.observe()
        self.assertEqual(self.send.call_count,2)
        self.assertFalse(json.loads(self.store.get_meta(n.QUEUE)))

    def test_cap_keeps_pending_and_quick_disappearance_is_not_mailed(self):
        self.observe();self.observe()
        self.store.set_meta(alert.SENT_LOG_META,json.dumps([1000000]*12))
        self.now.return_value+=3600;n.flush(self.store,CONF)
        self.send.assert_not_called()
        self.assertTrue(json.loads(self.store.get_meta(n.QUEUE)))
        self.observe(findings=[])
        self.assertFalse(json.loads(self.store.get_meta(n.QUEUE)))
        self.send.assert_not_called()

    def test_failure_cannot_resolve_previous_security_findings(self):
        self.f['severity']='critical';self.observe()
        self.observe(findings=[],error='collector failed')
        state=json.loads(self.store.get_meta(alert.STATE_META))
        self.assertIn(alert.finding_key(self.f),state)
        self.assertEqual(self.store.ledger_rows()[0]['cleared_at'],0)

    def test_unrelated_job_does_not_clear_and_recovery_survives_mail_failure(self):
        self.f['severity']='critical';self.observe()
        self.observe(job='other',findings=[])
        self.assertIn(alert.finding_key(self.f),json.loads(self.store.get_meta(alert.STATE_META)))
        n.dispatch(self.store, {**CONF, 'alert_on_clear': True}, 'posture', [])
        self.now.return_value+=3601;self.send.return_value='offline'
        n.flush(self.store,{**CONF, 'alert_on_clear': True})
        self.assertTrue(json.loads(self.store.get_meta(n.QUEUE)))
        self.assertNotEqual(self.store.ledger_rows()[0]['cleared_at'],0)

    def test_clear_is_silent_by_default_and_not_claimed_as_remediation(self):
        self.f['severity']='critical';self.observe()
        self.observe(findings=[])
        self.now.return_value+=3601;n.flush(self.store,CONF)
        self.send.assert_called_once()
        self.assertFalse(json.loads(self.store.get_meta(n.QUEUE)))

    def test_failed_repair_is_queued_on_first_observation_with_reason(self):
        self.f['remediation']={'status':'failed','reason':'Repair lacks permission.'}
        self.observe()
        self.now.return_value+=3601;n.flush(self.store,CONF)
        self.send.assert_called_once()
        self.assertIn('Repair lacks permission.', self.send.call_args.args[2])

    def test_confirmed_outage_bypasses_ordinary_cap(self):
        down = [{'category':'daemon','severity':'high','title':'JARVIS is down'}]
        self.store.set_meta(alert.SENT_LOG_META,json.dumps([1000000]*12))
        self.observe(findings=down)
        self.send.assert_not_called()                 # not yet an outage
        self.now.return_value+=n.OUTAGE_CONFIRM_S;self.observe(findings=down)
        self.send.assert_called_once()

    def test_restart_length_outage_is_never_mailed(self):
        down = [{'category':'daemon','severity':'high','title':'JARVIS is down'}]
        self.observe(findings=down)
        self.now.return_value+=120;self.observe(findings=[])
        self.now.return_value+=n.OUTAGE_CONFIRM_S*4;self.observe(findings=[])
        n.flush(self.store,CONF)
        self.send.assert_not_called()

    def test_briefing_mode_holds_non_urgent_changes_for_the_briefing(self):
        conf = {k: v for k, v in CONF.items() if k != 'alert_digest_interval'}
        self.assertTrue(n.briefings(conf))
        n.dispatch(self.store, conf, 'posture', [self.f])
        n.dispatch(self.store, conf, 'posture', [self.f])
        self.now.return_value += 86400
        n.flush(self.store, conf)
        self.send.assert_not_called()
        held = n.pending_for_briefing(self.store, conf)
        self.assertEqual([item['finding']['title'] for _k, item in held], ['unknown script'])
        crit = {**self.f, 'severity': 'critical', 'title': 'new critical'}
        n.dispatch(self.store, conf, 'posture', [self.f, crit])
        self.send.assert_called_once()                # only the new critical
        self.assertIn('Please look at this now: new critical', self.send.call_args.args[1])
        self.assertNotIn('unknown script', self.send.call_args.args[2])

    def test_daily_is_once_per_local_day_not_every_poll(self):
        now=1000000;conf={'report_hour':0}
        self.assertTrue(cadence.daily_due(self.store,conf,now))
        self.store.set_meta('report_daily_last_ok',now)
        self.assertFalse(cadence.daily_due(self.store,conf,now+100))
        self.assertTrue(cadence.daily_due(self.store,conf,now+86400))


class DigestChainsTests(NotificationsTests):
    def test_related_findings_arrive_as_one_story(self):
        base = {**self.f, 'severity': 'critical', 'host': 'win',
                'subject_id': 'edge-1', 'title': 'browser launched helper'}
        other = {**base, 'title': 'helper reached an outside peer'}
        self.observe(findings=[base, other])
        self.send.assert_called_once()
        body = self.send.call_args.args[2]
        self.assertIn('RELATED ACTIVITY (1 story)', body)
        self.assertIn('2 related observations', body)

    def test_unrelated_findings_gain_no_story_section(self):
        one = {**self.f, 'severity': 'critical', 'host': 'win',
               'title': 'first thing', 'where': 'a'}
        two = {**self.f, 'severity': 'critical', 'host': 'wsl',
               'title': 'second thing', 'where': 'b'}
        self.observe(findings=[one, two])
        self.send.assert_called_once()
        self.assertNotIn('RELATED ACTIVITY', self.send.call_args.args[2])


class BriefingTests(NotificationsTests):
    CONF = {k: v for k, v in CONF.items() if k != 'alert_digest_interval'}

    def test_one_briefing_per_slot_and_held_changes_drain(self):
        conf = {**self.CONF, 'briefing_hours': [9, 18]}
        self.now.return_value = cadence.briefing_slot(conf, self.now.return_value)[0] + 60
        self.observe();self.observe()
        n.dispatch(self.store, conf, 'posture', [self.f])
        slot = cadence.briefing_slot(conf, self.now.return_value)
        self.assertIsNotNone(cadence.briefing_due(self.store, conf, self.now.return_value))
        err, subject = cadence.briefing_email(self.store, conf, None, self.now.return_value,
                                             cadence.part_of_day(slot[1]))
        self.assertEqual(err, '')
        self.assertIn('briefing', subject)
        self.store.set_meta('briefing_last_ok', self.now.return_value)
        self.assertIsNone(cadence.briefing_due(self.store, conf, self.now.return_value + 60))
        self.assertEqual(n.pending_for_briefing(self.store, conf), [])

    def test_a_long_missed_slot_is_skipped_not_sent_stale(self):
        conf = {'briefing_hours': [9]}
        slot = cadence.briefing_slot(conf, self.now.return_value)[0]
        self.assertIsNotNone(cadence.briefing_due(self.store, conf, slot + 60))
        self.assertIsNone(cadence.briefing_due(self.store, conf,
                                               slot + cadence.BRIEFING_GRACE_S + 60))

    def test_briefing_slots_follow_the_configured_hours(self):
        self.assertEqual(cadence.briefing_hours({}), [9, 18])
        self.assertEqual(cadence.briefing_hours({'report_hour': 7}), [7, 18])
        self.assertEqual(cadence.briefing_hours({'briefing_hours': [20, 6, 6]}), [6, 20])
        self.assertEqual(cadence.part_of_day(7), 'morning')
        self.assertEqual(cadence.part_of_day(18), 'evening')


class ThreatInterruptTests(unittest.TestCase):
    setUp = NotificationsTests.setUp
    tearDown = NotificationsTests.tearDown
    CONF = BriefingTests.CONF

    def test_new_high_from_a_threat_detector_interrupts_but_hardening_waits(self):
        conf = self.CONF
        n.dispatch(self.store, conf, 'posture', [{**self.f, 'title': 'firewall off'}])
        n.dispatch(self.store, conf, 'posture', [{**self.f, 'title': 'firewall off'}])
        self.send.assert_not_called()
        n.dispatch(self.store, conf, 'hunt', [{**self.f, 'title': 'known-bad hash running'}])
        self.send.assert_called_once()
        self.assertIn('known-bad hash running', self.send.call_args.args[2])


class BriefingContentTests(unittest.TestCase):
    def test_condition_codes_are_deterministic(self):
        self.assertEqual(emails.condition(0, 0)[0], 'GREEN')
        self.assertEqual(emails.condition(2, 0)[0], 'AMBER')
        self.assertEqual(emails.condition(2, 1)[0], 'RED')

    def test_an_open_critical_is_the_mission_before_any_protocol(self):
        crit = {'category': 'present', 'severity': 'critical', 'host': 'wsl',
                'title': 'OpenAI API key in plaintext', 'where': '/h/.env:1'}
        snaps = {'secrets': {'ts': 1000000, 'findings': [crit], 'error': ''}}
        with patch.object(emails.protocols, 'pick_next', return_value=None) as pick:
            _s, text, _h = emails.briefing([], None, None, snaps, 1000000, conf={})
        self.assertIn('MISSION OF THE DAY: OpenAI API key in plaintext', text)
        pick.assert_not_called()

    def test_briefing_names_a_mission_changes_wins_and_custody(self):
        f = {'category': 'intrusion', 'severity': 'high', 'title': 'unknown script',
             'detail': 'check', 'where': 'file', 'host': 'wsl'}
        pending = [('k', {'tag': 'ESCALATED', 'finding': f, 'job': 'intrusion',
                          'first': 1000000 - 3 * 86400, 'level': 1}),
                   ('r', {'tag': 'RESOLVED', 'finding': {**f, 'title': 'old task'},
                          'job': 'intrusion', 'first': 0, 'level': 0})]
        snaps = {'intrusion': {'ts': 1000000, 'findings': [f], 'error': ''}}
        custody = {'vault_job': {'ok': True, 'vaulted_segments': 36},
                   'anchors': {'records': 2, 'confirmed': 1, 'latest_confirmed_height': 900001},
                   'sysmon': {'state': 'drift'}}
        subject, text, html = emails.briefing(
            pending, {'score': 61, 'grade': 'fair', 'areas': [], 'coverage': 90, 'next_steps': []}, 3, snaps, 1000000,
            conf={}, custody=custody, part='evening')
        self.assertTrue(subject.startswith('[JARVIS] Evening briefing: '), subject)
        self.assertIn('security score 61% · condition AMBER', subject)
        self.assertIn('MISSION OF THE DAY: unknown script', text)
        self.assertIn('reminder · open 3d', text)
        self.assertIn('old task — no longer observed', text)
        self.assertIn('Security score up 3 points', text)
        self.assertIn('36 sealed segments', text)
        self.assertIn('NOT running the reviewed baseline', text)
        self.assertIn('Mission of the day', html)
