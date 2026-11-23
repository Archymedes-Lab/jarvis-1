"""Audience profiles: first-run text for each edition, bounded by the register.

A commercial release reaches different audiences (Linux server admins first,
then Windows/WSL desktop users; docs/commercial/RELEASE-PLAN-2026-11.md). Each
gets a first-run that says what this edition looks at and what it does not.
Every statement about a capability comes from `jarvis.core.assurance`; this
module adds plain labels and fixed facts, never a stronger status.

Invariants (tests/test_audience.py):
- A capability's status word is a pure function of its register status. Only
  the known register statuses have words; anything else, or a capability the
  register does not hold, is "unknown" and listed as not provided.
- The number of live-tested capabilities is counted from the register, never
  written into the text.
- No rendered line contains an overclaim (complete, guaranteed, fully
  protected, ...), whatever the register says, and no hand-written label or
  fact promises an outcome (protects, prevents, stops, ...).
- Scores are described as not being compromise verdicts; removal is described
  together with what has not been validated about it.
- Reads only the in-memory register: no store, no network, no files, and the
  output is bounded in lines and characters.
- An unknown profile (including a team edition that does not exist yet) is
  refused, never rendered as a guess.
"""

from jarvis.core import assurance

# Register status -> what a user is told. Nothing in today's register is stronger
# than "partial"; a stronger status needs measured evidence first (AGENTS.md), and
# would also need a reviewed word added here: until then it renders as unknown.
STATUS_WORDS = {
    'partial': 'partly built; not live-tested',
    'unverified': 'built and tested in source only; not yet verified on a real machine',
}
UNKNOWN_WORD = 'unknown; treat as not provided'
LIVE_STATUSES = frozenset({'live', 'tested', 'live_tested', 'validated', 'containment_validated'})

# Phrases no first-run line may contain, in any profile (lower-case match).
FORBIDDEN = (
    'complete protection', 'fully protected', 'full protection', 'guarantee',
    'bulletproof', 'unhackable', 'invulnerable', '100%', 'always protected',
    'nothing gets past', 'cannot be bypassed', 'stops all', 'blocks all',
    'military-grade', 'you are safe', 'you are secure', 'proves you are',
)

# Hand-written labels and facts describe what is looked at, never an outcome:
# these verbs promise one (Jev review 2026-11-01 doubted a phrase list alone,
# 0.26). Register text is not checked here: it is the source of truth.
PROMISES = (
    'protects', 'protect you', 'prevents', 'stops ', 'secures', 'blocks ', 'catches',
    'defends', 'keeps you', 'detects all', 'detects every', 'ensures', 'eliminates',
)

MAX_LABEL = 60
MAX_LIMIT = 160
MAX_LINES = 80

SCORES_NOTE = ('Health and assurance scores describe what ARGUS-INSTINCT can observe and how much '
               'evidence supports it. Neither is a verdict that this machine is or is not '
               'compromised, and an absence of alerts is not proof of safety.')

PROFILES = {
    'server': {
        'title': 'ARGUS-INSTINCT server edition',
        'audience': 'Linux server admins and self-hosters',
        'capabilities': (
            ('server_ssh_watch', 'SSH configuration, authorised keys and tunnels'),
            ('server_login_audit', 'Successful SSH logins from new networks or keys'),
            ('server_exposure_audit', 'Firewall and exposed services'),
            ('server_packet_sensor', 'Inbound packet headers (no payloads)'),
            ('server_ops_health', 'Failed services, expiring certificates, OOM kills'),
            ('linux_boot_chain', 'Boot chain and kernel images'),
            ('linux_keyboard_readers', 'Processes reading the keyboard'),
            ('package_integrity', 'Integrity of commonly replaced packages'),
            ('patch_cve_awareness', 'Pending security updates and known CVEs'),
            ('app_code_vulnerabilities', 'Vulnerable dependencies and secrets in codebases'),
            ('container_inventory', 'Docker privilege and published ports'),
            ('self_tamper_evidence', 'Changes to ARGUS-INSTINCT itself'),
            ('off_box_heartbeat', 'Off-box "host went silent" heartbeat'),
            ('alert_channels', 'Alert delivery (email, webhook, ntfy, syslog)'),
        ),
        'facts': (
            'The off-box heartbeat is off until you set a heartbeat URL; until then nobody '
            'is told if this server goes silent.',
            'Alerts go only to channels you configure or to a phone you pair.',
        ),
        'next_steps': (
            'argus sshwatch              SSH policy, keys and tunnels',
            'argus opshealth             failed services, certificates, OOM kills',
            'argus status                what ARGUS-INSTINCT knows so far',
            'argus review                one report of the last 7 days and its blind spots',
        ),
        'removal': ('.deb: sudo apt remove argus-server; tarball install: sudo '
                    '/opt/argus/uninstall.sh. Removal on a clean machine has not been '
                    'validated yet.'),
    },
    'desktop': {
        'title': 'ARGUS-INSTINCT desktop',
        'audience': 'Windows and WSL developers',
        'capabilities': (
            ('wsl_trust_boundary', 'The Windows/WSL boundary'),
            ('credential_guardian', 'Secrets and credential access'),
            ('download_provenance', 'Where downloaded programs came from'),
            ('input_surveillance', 'Keyboard and input hooks'),
            ('peripheral_privacy_seal', 'Microphone and camera consent'),
            ('online_guardian', 'Network destinations and threat intelligence'),
            ('browser_privacy_veil', 'Browser trackers (opt-in browser sensor)'),
            ('preos_boot_integrity', 'Firmware, Secure Boot and measured boot'),
            ('dotnet_assembly_defense', '.NET runtime hijacks'),
            ('live_process_view', 'Live process view'),
            ('technique_rules', 'ATT&CK technique rules'),
            ('native_host_portability', 'Windows without WSL'),
            ('in_app_notifications', 'In-app notifications'),
        ),
        'facts': (
            'Windows mode without WSL has not been installed on another machine yet.',
            'ARGUS-INSTINCT is built never to delete your files automatically.',
        ),
        'next_steps': (
            'argus status                what ARGUS-INSTINCT knows so far',
            'jarvis coverage             blind spots, stale collectors, failures',
        ),
        'removal': ('Remove ARGUS-INSTINCT from Installed apps. Removal on a clean machine has not '
                    'been validated yet.'),
    },
}


# Native Windows (no WSL), the Setup's per-user edition. Only capabilities whose
# collectors run on Windows without elevation and without WSL; what this
# edition does not install is said in `facts`, never left out silently.
PROFILES['windows'] = {
    'title': 'ARGUS-INSTINCT for Windows',
    'audience': 'Windows PCs, no WSL needed',
    'capabilities': (
        ('credential_guardian', 'Secrets and credential access'),
        ('download_provenance', 'Where downloaded programs came from'),
        ('peripheral_privacy_seal', 'Microphone and camera consent'),
        ('online_guardian', 'Network destinations and threat intelligence'),
        ('preos_boot_integrity', 'Firmware, Secure Boot and measured boot'),
        ('dotnet_assembly_defense', '.NET runtime hijacks'),
        ('native_host_portability', 'Windows without WSL'),
        ('in_app_notifications', 'In-app notifications'),
    ),
    'facts': (
        'It runs for your account only and needs no administrator.',
        'Not in this edition: the elevated event sensor, the elevated broker and the '
        'keyboard-hook watcher. Checks that need them, WSL or Linux are listed as not '
        'applicable on this PC.',
        'ARGUS-INSTINCT is built never to delete your files automatically.',
    ),
    'next_steps': (
        'jarvis native status --all  what runs here and what does not apply',
        'jarvis coverage             blind spots, stale collectors, failures',
    ),
    'removal': ('Settings, Apps, ARGUS-INSTINCT, Uninstall. Your history stays in ~/.jarvis '
                'until you delete that folder. Removal on a clean machine has not been validated yet.'),
}


class UnknownProfile(ValueError):
    pass


def _first_clause(gap):
    text = ' '.join(str(gap or '').split())
    clause = text.split(';', 1)[0].strip()
    if not clause:
        return 'limits not recorded'
    if len(clause) > MAX_LIMIT:
        clause = clause[:MAX_LIMIT - 1].rstrip() + '…'
    return clause


def _overclaims(text):
    low = text.lower()
    return [p for p in FORBIDDEN if p in low]


def _promises(text):
    low = text.lower()
    return [p for p in PROMISES if p in low]


def first_run(profile, register=None):
    """The first-run statement for `profile` as a dict. Raises UnknownProfile."""
    if profile not in PROFILES:
        raise UnknownProfile(f'unknown profile {profile!r}; choose one of: '
                             + ', '.join(sorted(PROFILES)))
    reg = assurance.CAPABILITIES if register is None else register
    spec = PROFILES[profile]
    looked_at, not_provided = [], []
    for cap, label in spec['capabilities']:
        entry = reg.get(cap)
        status = entry[0] if isinstance(entry, tuple) and entry else None
        word = STATUS_WORDS.get(status)
        row = {'capability': cap, 'label': label[:MAX_LABEL], 'register_status': status}
        if word is None:
            row.update(status=UNKNOWN_WORD, limit='not in the coverage register'
                       if entry is None else 'status not recognised')
            not_provided.append(row)
        else:
            row.update(status=word, limit=_first_clause(entry[2] if len(entry) > 2 else ''))
            looked_at.append(row)
    statuses = [v[0] for v in reg.values() if isinstance(v, tuple) and v]
    live = sum(s in LIVE_STATUSES for s in statuses)
    total = len(statuses)
    register_line = (f'{live} of {total} capabilities in the coverage register have been '
                     'live-tested.' if live else
                     f'None of the {total} capabilities in the coverage register has been '
                     'live-tested yet.')
    return {
        'profile': profile,
        'title': spec['title'],
        'audience': spec['audience'],
        'register': {'total': total, 'live_tested': live,
                     'policy_version': assurance.POLICY_VERSION},
        'register_line': register_line,
        'looks_at': looked_at,
        'not_provided': not_provided,
        'facts': list(spec['facts']),
        'scores_note': SCORES_NOTE,
        'next_steps': list(spec['next_steps']),
        'removal': spec['removal'],
    }


def render(statement):
    """Plain text for a terminal. Bounded; refuses any line with an overclaim."""
    lines = [statement['title'], f'For: {statement["audience"]}', '',
             statement['register_line'], '', 'What this edition is built to look at:']
    for row in statement['looks_at']:
        lines.append(f'  - {row["label"]}: {row["status"]}.')
        lines.append(f'      Limit: {row["limit"]}.')
    if statement['not_provided']:
        lines += ['', 'Not provided in this release:']
        lines += [f'  - {row["label"]}: {row["limit"]}.' for row in statement['not_provided']]
    lines += ['', 'Good to know:']
    lines += [f'  - {fact}' for fact in statement['facts']]
    lines += ['', statement['scores_note'], '', 'Try next:']
    lines += [f'  {step}' for step in statement['next_steps']]
    lines += ['', f'To remove: {statement["removal"]}']
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES - 1] + ['(truncated)']
    bad = [p for line in lines for p in _overclaims(line)]
    handwritten = ([statement['title'], statement['audience']] + list(statement['facts'])
                   + [r['label'] for r in statement['looks_at'] + statement['not_provided']])
    bad += [p for text in handwritten for p in _promises(text)]
    if bad:
        raise ValueError(f'first-run text would overclaim: {sorted(set(bad))}')
    return '\n'.join(lines) + '\n'
