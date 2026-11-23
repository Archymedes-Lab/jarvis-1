"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'protect a developer laptop (Docker Engine 29.1.3 native inside WSL2, 9 containers of one '
            'product stack reachable from the internet through a Cloudflare tunnel) against the attack '
            'classes catalogued from 2025-2026 sources: exposed API worms, supply-chain tag overwrites, '
            'container stealers reading env and ~/.docker/config.json, runtime CVEs (runc, containerd, '
            'Docker cp race), kernel Copy Fail via AF_ALG, docker-group root equivalence',
    'built': {
        'per_container': 'seccomp/apparmor unconfined (high/medium), root user (medium), hostPID+SYS_PTRACE '
                         '(critical), no-new-privileges and writable rootfs and no limits (low), mutable tag '
                         '(low), image older than a year (medium), secret-shaped env names only (medium), '
                         'decode-and-pipe or download-and-pipe start command (high), tunnel client (medium), '
                         'root + restart=always (low); existing: privileged, host namespaces, socket, '
                         'sensitive mounts, capabilities, public ports',
        'host': 'docker group members (medium), TCP 2375/2376 listener (critical/high), userns-remap off '
                '(medium), seccomp off (high), no MAC (low), live-restore off (low), insecure registries '
                '(high), defaults (low), runtime versions below vendor-stated fixes (critical/high/medium), '
                'plain registry logins (medium)',
        'events': 'docker events since a stored cursor: exec commands shaped like nsenter/chroot/mount/'
                  'insmod/base64 -d reported high, counts of execs and creates low; events live only in '
                  'daemon memory',
        'process_rules': 'docker run --privileged/--cap-add SYS_ADMIN|SYS_PTRACE|SYS_MODULE|ALL/unconfined '
                         '(high), docker exec with nsenter/chroot/mount/insmod/base64 -d (high), dockerd -H '
                         'tcp:// non-loopback (critical), existing host-mount/pid-host run rule (medium)',
    },
    'not_built': 'image content scanning, image signature verification, runtime syscall tracing inside '
                 'containers beyond Sysmon-for-Linux process creation, network policy between containers, '
                 'the Cloudflare tunnel configuration itself',
    'noise_concern': 'this is a dev machine: the owner runs docker exec and docker run daily; most posture '
                     'rows are low or medium and the only highs need an escape-shaped command or an '
                     'unconfined profile',
}
QUESTIONS = {
    'coverage': {'type': 'choice', 'instructions':
        'How completely do built.per_container, built.host, built.events and built.process_rules cover the '
        'attack classes in goal for a single-host Docker Engine (not Kubernetes, not Docker Desktop)?',
        'criteria': {'unobserved': 'most classes unobserved', 'escape_only': 'main escape paths only',
                     'escape_supply_credentials': 'escape, supply chain and credential paths with stated gaps',
                     'nearly_complete': 'nearly complete for a single host'}},
    'severity_fit': {'type': 'noul', 'instructions':
        'Given noise_concern, is the severity ladder (critical only for privileged, socket, host-root mounts, '
        'PID+ptrace and TCP API; high for unconfined seccomp, stagers, escape-shaped execs and vulnerable '
        'runc; medium/low for posture) proportionate for a developer laptop?',
        'criteria': {'true': 'Proportionate', 'false': 'Too loud or too quiet'}},
    'first_owner_action': {'type': 'choice', 'instructions':
        'Which single owner action most reduces risk on this host, where the live posture is: docker group '
        'contains the owner, userns-remap off, no AppArmor in the kernel, containerd 2.2.1 (< 2.2.4), Docker '
        '29.1.3 (< 29.5.1), runc 1.3.3 (fixed), secrets in env for 5 containers, cloudflared tunnel, images '
        'pulled by :latest and two images two years old?',
        'criteria': {'update_runtime': 'update containerd and Docker Engine',
                     'secrets_to_files': 'move env secrets to compose secrets and rotate',
                     'userns_or_rootless': 'enable userns-remap or rootless Docker',
                     'pin_and_refresh_images': 'pin digests and refresh the two-year-old images',
                     'tunnel_review': 'review what the Cloudflare tunnel exposes'}},
    'gap': {'type': 'choice', 'instructions': 'Which item in not_built matters most for this host?',
        'criteria': {'image_scanning': 'image vulnerability scanning', 'signatures': 'image signature verification',
                     'syscall_tracing': 'in-container syscall tracing', 'network_policy': 'inter-container network policy',
                     'tunnel_config': 'tunnel configuration review'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
