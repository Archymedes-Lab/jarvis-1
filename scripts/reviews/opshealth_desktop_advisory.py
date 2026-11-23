"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'add the operational checks server operators most want automated, and make the desktop app '
            'the way a downloaded Windows install is used',
    'research': 'Exa web and forum research 2026-10-28: daily checks are disk/inodes, failed systemd units, '
                'error logs, backups, unexpected reboots; small-company outages are memory/OOM, disk, expired '
                'certificates, failed deploys; forums abandon tools that are heavy or noisy',
    'opshealth': {
        'interval_s': 900,
        'failed_units': 'medium per unit, first 8 named',
        'certs': 'from nginx/apache/haproxy/caddy configs and certbot live; expired critical, <7 days high, '
                 '<21 days medium; key files never opened',
        'oom': 'kernel journal behind a cursor, high, kept one day',
        'reboots': 'previous boot without a shutdown record in its last 60 journal lines, high, once per boot',
        'unreadable': 'journal or systemctl unreadable is reported as not observed',
    },
    'desktop': {
        'before': 'daemon as per-user scheduled task, browser dashboard shortcut, desktop app a separate download',
        'after': 'installer bundles the app, hash-checked, Start menu entry, tray at every logon (--hidden), '
                 'opened after install; daemon unchanged and keeps running when the app quits; browser kept as '
                 'fallback; WebView2 absence and Defender ASR blocks reported',
    },
}
QUESTIONS = {
    'cert_bands': {'type': 'choice', 'instructions':
        'Are the certificate expiry severity bands appropriate given automatic renewal at 30 days?',
        'criteria': {'good': 'Appropriate', 'too_noisy': 'Too noisy', 'too_late': 'Warns too late',
                     'uncertain': 'Insufficient information'}},
    'unit_severity': {'type': 'choice', 'instructions':
        'What severity should a failed systemd unit have on a server by default?',
        'criteria': {'low': 'Low', 'medium': 'Medium', 'high': 'High', 'uncertain': 'Insufficient information'}},
    'unclean_inference_risk': {'type': 'noul', 'instructions':
        'Could inferring an unclean shutdown from missing shutdown lines produce false alerts often enough '
        '(for example a journal that drops its last lines on a clean poweroff) to need a quieter severity '
        'until validated on real servers?',
        'criteria': {'true': 'Yes, start quieter', 'false': 'No, high is fine'}},
    'desktop_safety': {'type': 'noul', 'instructions':
        'Does keeping the monitoring daemon independent of the desktop app (quitting the app never stops '
        'monitoring) materially protect users compared with running monitoring inside the app?',
        'criteria': {'true': 'Yes, materially', 'false': 'No meaningful difference'}},
    'autostart_ok': {'type': 'noul', 'instructions':
        'Is starting the desktop app hidden in the tray at every logon an acceptable default for a security '
        'monitor, given users can disable it?',
        'criteria': {'true': 'Acceptable default', 'false': 'Should be opt-in'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
