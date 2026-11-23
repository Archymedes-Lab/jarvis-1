"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'make the Linux server edition of a host security monitor protect internet-facing servers, '
            'and add analysis of incoming packets',
    'measured_gaps': [
        'every established connection to a listening port from a public address is critical',
        'firewall posture only checks whether iptables is empty',
        'two collectors are Windows-only but scheduled on Linux and fail every run',
        'no successful-login or new-key tracking',
        'package ownership check is dpkg-only',
        'one alert channel (email)',
        'no packet or flow visibility',
        'never run end to end on plain Linux',
    ],
    'packet_alternatives': [
        'AF_PACKET with a classic BPF filter, header-only truncation in the kernel, separate unit with CAP_NET_RAW',
        'eBPF or XDP counters with CAP_BPF and CAP_PERFMON',
        'ingest Suricata or Zeek logs',
        'conntrack netlink dump with CAP_NET_ADMIN',
    ],
    'selected_packets': 'AF_PACKET header-only sampler (owner choice), with eBPF reconsidered if drops exceed 1 percent',
    'privilege_layout': 'daemon gains no capability; sampler unit has only CAP_NET_RAW; firewall reader is a '
                        'oneshot with only CAP_NET_ADMIN and fixed commands; both write data the daemon ingests',
    'noise_control': 'declared services file; inbound to declared ports is not a finding; findings aggregate per '
                     'port and per source network and page only on state change',
    'privacy': 'no payload stored; DNS features only, not names; bounded retention of remote addresses',
    'alerting': 'webhook signed with HMAC, ntfy, syslog counted as a channel only when a forwarder runs, email',
    'validation': 'unit and property tests plus a non-privileged systemd container with binfmt masked',
}
QUESTIONS = {
    'order': {'type': 'choice', 'instructions':
        'Which should be built first so that the server edition protects infrastructure soonest?',
        'criteria': {'noise_exposure': 'Declared services and the firewall view (remove false criticals)',
                     'packets': 'The packet sampler',
                     'alerts': 'More alert channels',
                     'logins': 'Successful-login and new-key tracking',
                     'uncertain': 'Insufficient information'}},
    'packet_design': {'type': 'choice', 'instructions':
        'Which packet alternative best fits least privilege, bounded cost and no payload retention?',
        'criteria': {'afpacket': 'AF_PACKET header-only sampler in its own unit',
                     'ebpf': 'eBPF or XDP counters', 'ids': 'Suricata or Zeek ingest',
                     'conntrack': 'conntrack dump', 'uncertain': 'Insufficient information'}},
    'separation': {'type': 'noul', 'instructions':
        'Does keeping CAP_NET_RAW and CAP_NET_ADMIN out of the daemon, in separate minimal units that only '
        'write data, materially reduce the impact of a compromised daemon?',
        'criteria': {'true': 'Yes, materially', 'false': 'No meaningful reduction'}},
    'declared_services_risk': {'type': 'noul', 'instructions':
        'Could a declared-services list that suppresses inbound findings on declared ports hide an attack '
        'that arrives over a declared service, so that other detections (logins, web shells, process '
        'behaviour) remain necessary?',
        'criteria': {'true': 'Yes, other detections remain necessary',
                     'false': 'No, declared-port suppression is safe on its own'}},
    'syslog_channel': {'type': 'noul', 'instructions':
        'Should a syslog line count as a working alert channel only when a log forwarder is running?',
        'criteria': {'true': 'Only with a forwarder', 'false': 'Always'}},
    'container_validation_gap': {'type': 'noul', 'instructions':
        'Is validation in a local non-internet-facing container insufficient to claim the packet detections '
        'are tuned for real internet background noise?',
        'criteria': {'true': 'Real internet traffic is still needed', 'false': 'The container is sufficient'}},
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
