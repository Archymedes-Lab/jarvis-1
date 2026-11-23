"""Fixed engineering metadata only; advisory, never deployment authorization.

Argus server release 2026-10-25: Prometheus /metrics, a .deb, and the desktop
client shipped beside the server packages."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'ship the Linux server edition of a self-hosted host security monitor as a public download, '
            'with the desktop client, adding what DevOps operators most ask for',
    'research': [
        'complexity and setup overhead is the top concern in observability surveys',
        'alert noise is the top incident-response barrier',
        'about three quarters of teams invest in Prometheus; a /metrics endpoint is expected',
        'operators expect an apt-installable .deb and a small footprint',
    ],
    'daemon_model': 'stdlib Python daemon as an unprivileged system account with three read-only '
                    'capabilities; dashboard and JSON API bound to 127.0.0.1 only, Host header checked '
                    'against DNS rebinding; state-changing routes need a per-start token; reads do not',
    'metrics_design': 'GET /metrics on the same loopback listener, no token, like /api/health; labels only '
                      'severity and scheduled job name; no finding text, addresses or paths; collectors '
                      'that never reported have no age sample; unreadable store returns 503; one rendering '
                      'cached 15 seconds',
    'deb_alternatives': [
        'thin .deb: payload in /usr/share, postinst runs the existing installer, which verifies the code, '
        'keeps the previous install on failure, and copies to a root-owned /opt; depends on python3 >= 3.12',
        'native .deb: dpkg owns every file under /opt directly; verification moved into postinst without '
        'rollback of the previous version',
    ],
    'desktop_alternatives': [
        'desktop client stays loopback-only and reaches a server through an SSH local port forward',
        'desktop client connects to the server over the network with TLS and a token',
    ],
    'desktop_packaging': 'no Tauri CLI on the build host; Linux binary built with cargo and packed into a '
                         'hand-written .deb; Windows binary cross-compiled; both renamed from the same source',
}
QUESTIONS = {
    'metrics_auth': {'type': 'noul', 'instructions':
        'Given the listener is loopback-only with a Host-header check, is serving the metadata-only '
        '/metrics without a token acceptable, provided it reveals no finding text, addresses or paths?',
        'criteria': {'true': 'Acceptable', 'false': 'A token should be required'}},
    'metrics_leak': {'type': 'noul', 'instructions':
        'Could per-severity open-finding counts and per-collector failing flags still help a local '
        'attacker on the same host time an action to avoid detection?',
        'criteria': {'true': 'Yes, a meaningful timing aid', 'false': 'No meaningful aid'}},
    'deb_design': {'type': 'choice', 'instructions':
        'Which .deb design best preserves install-time verification, rollback to the previous version and '
        'root-owned sealed code, while meeting operator expectations?',
        'criteria': {'thin': 'Thin .deb that runs the existing verifying installer',
                     'native': 'Native .deb with dpkg owning every file',
                     'uncertain': 'Insufficient information'}},
    'desktop_remote': {'type': 'choice', 'instructions':
        'For a server edition, which desktop client connection keeps the attack surface smallest while '
        'remaining usable for an operator?',
        'criteria': {'ssh_tunnel': 'Loopback-only client through an SSH local port forward',
                     'network_tls': 'Direct network connection with TLS and a token',
                     'uncertain': 'Insufficient information'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Is a release built and checked only by unit tests, static checks and package inspection, '
        'without installing it on a clean server, insufficient to call the server install verified?',
        'criteria': {'true': 'Insufficient; a clean-server install is still needed',
                     'false': 'Sufficient'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    if STATE['phase'] == 'implementation':
        STATE['validation'] = json.loads(sys.stdin.read() or '{}')
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
