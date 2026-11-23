"""Supervise the independent connectivity guard from its persisted observations."""
import time

from jarvis.platform import host

from .supervisors import read_state

STATE = host.local_appdata('Jarvis', 'Connectivity', 'state.json')


def audit(path=STATE, now=None):
    now = int(time.time() if now is None else now)
    state = read_state(path)
    title, detail, severity = 'connectivity guard is healthy', 'Recent TCP, DNS and HTTPS checks passed.', 'ok'
    try:
        checked = int((state or {}).get('checkedAt') or 0)
    except (ValueError, TypeError):
        checked = 0
    if not state or not checked or now - checked > 300 or checked > now + 60:
        title, detail, severity = ('connectivity guard observation is unavailable',
                                  'The Windows guard has no fresh valid state; inspect its scheduled task.', 'high')
    elif state.get('action') == 'paused':
        title, detail, severity = 'connectivity recovery is paused', 'User pause is active.', 'low'
    elif state.get('applicationFailures', 0) >= 3:
        title, detail, severity = ('internet application connectivity is degraded',
                                  'Three consecutive DNS/HTTPS checks failed. The guard preserves the active link and VPN; upstream diagnosis is needed.', 'high')
    elif not state.get('internetTcpReachable'):
        title, detail, severity = ('internet connectivity is unavailable',
                                  'Guard action: ' + str(state.get('action')) + '; ' + str(state.get('error', '')), 'high')
    elif not isinstance(state.get('application'), dict):
        title, detail, severity = ('application connectivity has not been verified',
                                  'TCP is reachable, but DNS/HTTPS observations are missing.', 'medium')
    elif state['application'].get('healthy') is not True:
        title, detail, severity = ('application connectivity failure is being confirmed',
                                  'TCP is reachable; waiting for repeat DNS/HTTPS checks.', 'medium')
    return [{'category':'connectivity', 'host':'win', 'severity':severity,
             'title':title, 'detail':detail, 'where':path}]
