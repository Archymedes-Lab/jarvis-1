"""Daily advisory eligibility; change digests are driven by collector results."""
import json
import time

from jarvis.response import alert, protocols

from . import advisory, emails, notifications, score


def daily_due(store, conf, now=None):
    now = int(time.time() if now is None else now)
    hour = min(23,max(0,alert.parse_int(conf.get('report_hour'),9)))
    last = int(store.get_meta('report_daily_last_ok',0) or
               store.get_meta(alert.REPORT_OK_META,0) or 0)
    current = time.localtime(now)
    if current.tm_hour < hour:
        return False
    return not last or time.strftime('%Y-%m-%d',time.localtime(last)) != time.strftime('%Y-%m-%d',current)


def health_due(store, conf, now=None):
    """Once a day at report_hour, like the advisory, on its own bookmark."""
    now = int(time.time() if now is None else now)
    hour = min(23,max(0,alert.parse_int(conf.get('report_hour'),9)))
    last = int(store.get_meta('health_email_last_ok',0) or 0)
    current = time.localtime(now)
    if current.tm_hour < hour:
        return False
    return not last or time.strftime('%Y-%m-%d',time.localtime(last)) != time.strftime('%Y-%m-%d',current)


BRIEFING_EVENING_HOUR = 18
# A slot missed by more than this (daemon down, machine asleep) is skipped:
# an "evening briefing" at breakfast helps nobody, and the next one is due soon.
BRIEFING_GRACE_S = 3 * 3600


def briefing_hours(conf):
    """Local hours at which briefings go out: `briefing_hours`, else the
    morning report hour and an evening one."""
    raw = conf.get('briefing_hours')
    if not isinstance(raw, (list, tuple)) or not raw:
        raw = [alert.parse_int(conf.get('report_hour'), 9), BRIEFING_EVENING_HOUR]
    hours = sorted({min(23, max(0, alert.parse_int(h, 9))) for h in raw})
    return hours or [9]


def briefing_slot(conf, now=None):
    """(timestamp, hour) of the latest scheduled briefing at or before `now`."""
    now = int(time.time() if now is None else now)
    best = None
    for days_back in (0, 1):
        day = time.localtime(now - days_back * 86400)
        for hour in briefing_hours(conf):
            stamp = int(time.mktime((day.tm_year, day.tm_mon, day.tm_mday, hour, 0, 0,
                                     0, 0, -1)))
            if stamp <= now and (best is None or stamp > best[0]):
                best = (stamp, hour)
    return best


def part_of_day(hour):
    return 'morning' if hour < 12 else 'afternoon' if hour < 17 else 'evening'


def briefing_due(store, conf, now=None):
    """The (slot, hour) to brief for, or None when this slot was already sent."""
    now = int(time.time() if now is None else now)
    slot = briefing_slot(conf, now)
    if slot is None or now < int(store.get_meta('briefing_retry_at', 0) or 0):
        return None
    if now - slot[0] > BRIEFING_GRACE_S:
        return None
    last = int(store.get_meta('briefing_last_ok', 0) or 0)
    return slot if last < slot[0] else None


def briefing_email(store, conf, jobs, now=None, part='morning'):
    """Build and send a briefing; drains held changes on success.

    -> (error or "", subject)."""
    now = int(time.time() if now is None else now)
    pending = notifications.pending_for_briefing(store, conf, now)
    result = score.latest(store)
    state = protocols.evaluate(store, jobs, now) if jobs else ()
    try:
        custody = json.loads(store.get_meta('evidence_v1') or 'null')
    except (TypeError, ValueError):
        custody = None
    subject, text, html = emails.briefing(
        pending, result, score.change_since(store, 86400, now) if result else None,
        store.get_snapshots(), now, store, conf, state, custody, part)
    err = alert.send_email(conf, subject, text, html=html)
    if not err:
        notifications.mark_sent(store, pending, now, digest=True)
    return err, subject


def _briefing(store, conf, jobs, now):
    due = briefing_due(store, conf, now)
    if due is None:
        return
    err, _subject = briefing_email(store, conf, jobs, now, part_of_day(due[1]))
    if err:
        store.set_meta('briefing_retry_at', now + 900)
        store.set_meta('alert_last_error', f'{now}: {err}'[:300])
    else:
        store.set_meta('briefing_last_ok', now)
        store.set_meta('briefing_retry_at', 0)


def run(store, jobs):
    # Recorded on every pass, email or not: the dashboard trend and the digest
    # header both read this history.
    score.record(store, jobs)
    conf = alert.load_conf()
    if not alert.enabled(conf):
        return advisory.advisory_report(store,jobs)
    # Alerts go out on every configured channel; the reports below are email.
    notifications.flush(store,conf)
    if not alert.email_enabled(conf):
        return advisory.advisory_report(store,jobs)
    briefed = notifications.briefings(conf)
    if briefed:
        _briefing(store, conf, jobs, int(time.time()))
    if conf.get('report_daily_enabled', False) is not True:
        # The full advisory is off, but the health bar still arrives once a
        # day unless health_email_enabled is set to false — or briefings,
        # which carry the same health panel, are on.
        now = int(time.time())
        if (not briefed and conf.get('health_email_enabled', True) is not False
                and health_due(store, conf, now)
                and now >= int(store.get_meta('health_email_retry_at',0) or 0)):
            err = emails.health_email(store, conf, now, jobs)
            if err:
                store.set_meta('health_email_retry_at', now + 900)
                store.set_meta('alert_last_error', f'{now}: {err}'[:300])
            else:
                store.set_meta('health_email_last_ok', now)
                store.set_meta('health_email_retry_at', 0)
        return [{'category':'reporting','severity':'ok','host':'wsl',
                 'title':'automatic repairs and attention alerts active',
                 'detail':('Scheduled briefings at ' + ', '.join(
                     f'{h:02d}:00' for h in briefing_hours(conf)) + '; interrupts only for '
                     'new critical threats and lasting outages.') if briefed else
                 'Routine daily email is disabled; findings remain on the dashboard.',
                 'where':'scheduler'}]
    now = int(time.time())
    if now < int(store.get_meta('report_retry_at',0) or 0) or not daily_due(store,conf,now):
        return [{'category':'reporting','severity':'ok','host':'wsl',
                 'title':'daily advisory scheduled; change digests active',
                 'detail':'Unchanged findings do not send repeat alerts.','where':'scheduler'}]
    result = advisory.advisory_report(store,jobs)
    if int(store.get_meta(alert.REPORT_OK_META,0) or 0) >= now:
        store.set_meta('report_daily_last_ok',now)
        store.set_meta('report_retry_at',0)
    else:
        store.set_meta('report_retry_at',now+900)
    return result
