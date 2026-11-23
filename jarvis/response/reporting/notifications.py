"""Durable change digests and finite age-based escalation, replacing STILL spam."""
import json
import time

from jarvis.response import acknowledge, alert, fixit

from . import emails, score

QUEUE = 'alert_pending_changes'
LAST_DIGEST = 'alert_digest_last_ok'
RETRY_AT = 'alert_delivery_retry_at'
# A collector outage must last this long before it can page: restarts and
# brief interop hiccups made every daemon restart an email (measured
# 2026-09-23: nine in one hour, all "collector … is failing/stale").
OUTAGE_CONFIRM_S = 900
# Only these changes to a critical finding interrupt. Age reminders
# (ESCALATED) wait for the next briefing: known problems are the briefing's
# job, the interrupt is for something new.
INTERRUPT_TAGS = ('NEW', 'WORSENED', 'REOPENED')
# A new high from a detector of live activity interrupts too; a high from a
# hardening or posture check is a to-do, and waits for the briefing.
THREAT_AREA = "Active threats"
ESCALATIONS = {
    'critical': (3600, 21600, 86400),
    'high': (86400, 259200, 604800),
    'medium': (259200, 604800, 1209600),
}


def _load(store, key):
    try:
        value = json.loads(store.get_meta(key, '{}') or '{}')
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def deliver(store, job, findings, error=""):
    """Called by the scheduler after every job. Sends at most one email.

    Never raises: an alerting path that can crash the monitor is worse than one
    that occasionally misses. The caller still wraps this in its own guard.
    """
    try:
        # The desktop toast runs whether or not mail is configured: it is the
        # channel that needs no key, and criticals must interrupt someone.
        from jarvis.response import toast
        toast.deliver(store, job, list(findings or []))
    except Exception:
        pass
    try:
        conf = alert.load_conf()
        if not alert.enabled(conf):
            return
        dispatch(store, conf, job, list(findings or []), error)
    except Exception:
        pass


def dispatch(store, conf, job, findings, error=''):
    now = int(time.time())
    rank = alert.SEV_RANK
    state = _load(store, alert.STATE_META)
    queue = _load(store, QUEUE)
    minimum = rank.get(conf.get('alert_min_severity', 'high'), 1)
    if error:
        findings = list(findings) + [{
            'category':'collectors', 'severity':'high', 'host':'wsl',
            'title':f"collector '{job}' did not complete observation", 'detail':str(error)[-300:],
            'where':'jarvis serve'}]
    present, advisory = {}, set()
    for f in findings:
        key = alert.finding_key(f)
        if f.get('category') in alert.NOPAGE_CATEGORIES and not alert.is_outage(f):
            advisory.add(key)
        elif rank.get(f.get('severity'), 9) <= minimum or alert.is_outage(f):
            # Duplicate findings may disagree: the worst evidence wins.
            if key not in present or rank.get(f.get('severity'),9) < rank.get(present[key].get('severity'),9):
                present[key] = f

    for key, f in present.items():
        sev = f.get('severity','high')
        outage = alert.is_outage(f)
        st = state.get(key)
        first_observation = st is None
        if st is None:
            st = {'first':now, 'count':0, 'last_sent':0, 'sev':sev, 'job':job}
            state[key] = st
        was = st.get('observed_sev', st.get('sev',sev))
        st.update(finding=f, last_seen=now, observed_sev=sev)
        st['outage'] = outage
        old = queue.get(key)
        age = max(0, now - int(st.get('first',now)))
        if outage and age < OUTAGE_CONFIRM_S:
            continue            # not yet an outage worth anyone's attention
        thresholds = (900,3600,21600) if outage else ESCALATIONS.get(sev, ESCALATIONS['high'])
        level = sum(age >= t for t in thresholds)
        threat = sev == 'critical' or (
            sev == 'high' and score.AREA_OF.get(job) == THREAT_AREA)
        pageable = outage or threat
        tag = None
        if old and old['tag'] == 'RESOLVED':
            tag = 'REOPENED'
        elif not st.get('last_sent') and (pageable or not first_observation or f.get('remediation')):
            tag = 'NEW'
        elif rank.get(sev,9) < rank.get(was,9):
            tag = 'WORSENED'
        elif st.get('last_sent') and level > int(st.get('escalation',0)):
            tag = 'ESCALATED'
        urgent = (outage and not st.get('last_sent')) or (threat and tag in INTERRUPT_TAGS)
        if old and old['tag'] != 'RESOLVED':
            # Retain an unsent worsening even if no further severity change
            # occurs; severity improvements before send must remain truthful.
            old.update(finding=f, urgent=bool(old.get('urgent')) or urgent, level=level)
        elif tag:
            queue[key] = {'tag':tag, 'finding':f, 'job':job, 'queued':now,
                          'urgent':urgent, 'level':level, 'first':st['first']}

    for key in list(state):
        st = state[key]
        if error or key in present or not alert.same_domain(st.get('job',''),job):
            continue
        queue.pop(key, None)
        if st.get('last_sent'):
            # Ledger resolution is a collector fact, independent of mail.
            store.ledger_cleared(key, now)
            if key not in advisory and conf.get('alert_on_clear',False) is True:
                f = st.get('finding') or {
                    'category':key.split('|')[0], 'title':key.split('|')[1],
                    'where':key.split('|',2)[-1], 'severity':st.get('sev','high')}
                queue[key] = {'tag':'RESOLVED', 'finding':f, 'job':job,
                              'queued':now, 'urgent':bool(st.get('outage')),
                              'first':st.get('first',now), 'level':0}
        state.pop(key)
    store.set_meta(alert.STATE_META, json.dumps(state))
    store.set_meta(QUEUE, json.dumps(queue))
    return flush(store, conf)


def flush(store, conf):
    now = int(time.time())
    queue = _load(store, QUEUE)
    if conf.get('alert_on_clear', False) is not True:
        queue = {k: v for k, v in queue.items() if v.get('tag') != 'RESOLVED'}
        store.set_meta(QUEUE, json.dumps(queue))
    # A change you have since acknowledged is not worth an email.
    acks = acknowledge.load(store)
    confirmed = [k for k, v in queue.items() if v.get('tag') != 'RESOLVED'
                 and acknowledge.is_acknowledged(acks, v['finding'], v['job'], now)]
    if confirmed:
        for k in confirmed:
            queue.pop(k, None)
        store.set_meta(QUEUE, json.dumps(queue))
    if not queue or now < int(store.get_meta(RETRY_AT,0) or 0):
        return False
    if briefings(conf):
        # Non-urgent changes wait for the next scheduled briefing.
        due = False
    else:
        period = max(60, alert.parse_int(conf.get('alert_digest_interval'),3600))
        last = int(store.get_meta(LAST_DIGEST,0) or 0)
        oldest = min(item['queued'] for item in queue.values())
        due = now - (last or oldest) >= period
    batch = {k:v for k,v in queue.items() if v.get('urgent') or due}
    if not batch:
        return False
    urgent = any(v.get('urgent') for v in batch.values())
    cap = alert.OUTAGE_HOURLY_CAP if urgent else max(0,alert.parse_int(conf.get('alert_hourly_cap'),12))
    if cap and len(alert.recent_sends(store)) >= cap:
        store.set_meta('alert_capped_at',now)
        return False  # Nothing is acknowledged or discarded.
    ordered = sorted(batch.items(), key=lambda kv: alert.SEV_RANK.get(kv[1]['finding'].get('severity'),9))
    health = score.latest(store)
    subject, text, html = emails.digest(
        ordered, urgent, health, score.change_since(store, 86400, now) if health else None, now,
        conf, store=store)
    # File the digest under its most pressing category, and tell the channels
    # how many items of each kind it carries (response/categories.py).
    from jarvis.response import categories
    kinds = [categories.of_finding(v['finding'], v.get('job', '')) for _k, v in ordered]
    worst = ordered[0][1]['finding'].get('severity') if ordered else None
    err = alert.deliver(conf, subject, text, html=html, category=categories.dominant(kinds),
                        severity=worst if worst in ('critical', 'high', 'medium', 'low') else None,
                        counts=categories.counts(kinds))
    if err:
        store.set_meta('alert_last_error',f'{now}: {err}'[:300])
        store.set_meta(RETRY_AT,now + 300)
        return False
    mark_sent(store, ordered, now, digest=due)
    return True


def briefings(conf):
    """Scheduled briefings replace the rolling digest unless a fixed
    `alert_digest_interval` is configured or `briefings` is false."""
    return (conf.get('briefings', True) is not False
            and conf.get('alert_digest_interval') in (None, ''))


def pending_for_briefing(store, conf, now=None):
    """Queued, unacknowledged, non-urgent changes for the next briefing, worst first."""
    now = int(time.time() if now is None else now)
    queue = _load(store, QUEUE)
    acks = acknowledge.load(store)
    items = [(k, v) for k, v in queue.items()
             if not v.get('urgent') and (v.get('tag') != 'RESOLVED'
                                         or conf.get('alert_on_clear', False) is True)
             and not (v.get('tag') != 'RESOLVED'
                      and acknowledge.is_acknowledged(acks, v['finding'], v['job'], now))]
    return sorted(items, key=lambda kv: alert.SEV_RANK.get(kv[1]['finding'].get('severity'), 9))


def mark_sent(store, ordered, now, digest=True):
    """Record delivery of `ordered` [(key, queue item)] after a successful send."""
    queue = _load(store, QUEUE)
    state = _load(store,alert.STATE_META)
    for key, item in ordered:
        if item['tag'] != 'RESOLVED':
            st = state.get(key)
            if st:
                st.update(last_sent=now, count=int(st.get('count',0))+1,
                          sev=item['finding'].get('severity','high'), escalation=item['level'])
                st.pop('pending',None)
            store.ledger_sent(key,item['finding'],item['job'],fixit.suggest(item['finding']) or '',now)
        queue.pop(key,None)
    store.set_meta(alert.STATE_META,json.dumps(state))
    store.set_meta(QUEUE,json.dumps(queue))
    alert.record_send(store)
    if digest:
        store.set_meta(LAST_DIGEST,now)
    store.set_meta(RETRY_AT,0)
    store.set_meta('alert_last_ok',now)
    store.set_meta('alert_last_error','')
