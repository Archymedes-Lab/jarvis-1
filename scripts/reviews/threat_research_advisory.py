"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'apply 2025-2026 threat research to a Windows and Linux host monitor with explicit invariants',
    'research': 'Exa 2026-10-29: BYOVD EDR killers, ClickFix, infostealers, eBPF and io_uring rootkits, PAM '
                'backdoors (Plague), Copy Fail and DirtyFrag page-cache exploits needing user namespaces, Linux '
                'boot persistence (GRUB, initramfs hooks), Windows mandatory-profile hive persistence (NTUSER.MAN)',
    'already_covered': 'ld.so.preload, unowned PAM modules, PAM package verify, eBPF and io_uring cross-view, '
                       'RunMRU ClickFix, WMI subscriptions, Winlogon, driver blocklist, HVCI',
    'added': {
        'bootchain_linux': 'kernel/initramfs images by size+inode+ctime, GRUB config, grub.d, initramfs hooks, '
                           'dracut modules learned once; changes weighed against package logs within 20 minutes '
                           '(explained low, unexplained high for images and hooks, medium for config); unowned '
                           'hooks reported at once; absent package tool means unknown owner',
        'kernel_surface': 'unprivileged BPF enabled medium; kptr/dmesg/ptrace/userns/module signing/exploit '
                          'modules aggregated into one low finding',
        'windows_asr_byovd': 'ASR rule 56a863a9 state: block ok, audit or warn low, off medium, not configured '
                             'low, unreadable reported as not observed',
        'windows_ntuser_man': 'NTUSER.MAN in any profile high; unreadable profiles counted',
        'spyware_keyreaders': 'Linux processes holding keyboard evdev, hidraw or uinput judged by image '
                              '(root-owned, package-owned, system dir, not deleted), never by name; expected '
                              'compositors quiet when verified, other packaged readers low, keylogger packages, '
                              'writable or deleted images high, unreadable images medium unverified',
        'spyware_staging': 'dot-entries in /var/log and /run (folders and executables high, files medium), hidden '
                           'executables in /dev/shm /tmp /var/tmp high; reads at most 4 magic bytes',
        'packet_socket_identity': 'packet-socket holders exempt only when name matches and image is a root-owned '
                                  'package-owned system binary; unreadable image medium unverified (was name-only)',
        'kernel_taint': 'taint bits after the first run of each boot: forced, unsigned module or oops high, others medium',
        'udev_run': 'udev rules running programs outside system dirs high from first run; rule changes medium',
        'browser_master_key': 'command line naming Chromium Local State high (Windows and Linux)',
        'windows_ssh_tunnels': 'ssh.exe -R or -w medium, -D low (VS Code Remote-SSH uses -D)',
    },
}
QUESTIONS = {
    'pkg_window': {'type': 'choice', 'instructions':
        'Is a 20-minute window around a file change appropriate for attributing it to package-manager activity?',
        'criteria': {'good': 'Appropriate', 'too_wide': 'Too wide, an attacker can hide inside it',
                     'too_narrow': 'Too narrow, legitimate updates will page', 'uncertain': 'Insufficient information'}},
    'man_severity': {'type': 'choice', 'instructions':
        'What severity should an NTUSER.MAN file in a user profile on a non-domain Windows PC have?',
        'criteria': {'medium': 'Medium', 'high': 'High', 'critical': 'Critical', 'uncertain': 'Insufficient information'}},
    'asr_not_configured': {'type': 'choice', 'instructions':
        'With HVCI and the vulnerable driver blocklist on, what severity should a not-configured BYOVD ASR rule have?',
        'criteria': {'ok': 'Not a finding', 'low': 'Low', 'medium': 'Medium', 'uncertain': 'Insufficient information'}},
    'aggregate_low': {'type': 'noul', 'instructions':
        'Does aggregating several loose kernel settings into one low finding reduce alert fatigue without hiding '
        'the unprivileged BPF case that is reported separately at medium?',
        'criteria': {'true': 'Yes', 'false': 'No'}},
    'staging_var_log_sev': {'type': 'choice', 'instructions':
        'What severity should any hidden file (not folder, not executable) directly in /var/log have on a server?',
        'criteria': {'low': 'Low', 'medium': 'Medium', 'high': 'High', 'uncertain': 'Insufficient information'}},
    'packaged_reader_low': {'type': 'noul', 'instructions':
        'Is low the right severity for a package-installed program that is not a known compositor or hotkey daemon '
        'holding the keyboard device, given that packaged keyloggers are matched by name and reported high?',
        'criteria': {'true': 'Low is right', 'false': 'Should be higher'}},
    'ssh_d_low': {'type': 'noul', 'instructions':
        'Is low appropriate for ssh.exe -D (SOCKS) on Windows when developer tools such as VS Code Remote-SSH use it '
        'legitimately, while -R and -w stay medium?',
        'criteria': {'true': 'Yes', 'false': 'No'}},
    'next_validation': {'type': 'choice', 'instructions':
        'Which validation should come first for these additions?',
        'criteria': {'vm_plant': 'Plant an initramfs hook, a changed GRUB config and a loose sysctl in a disposable Linux VM',
                     'windows_live': 'Read the ASR rule and profiles live on a Windows PC',
                     'more_units': 'More unit tests', 'uncertain': 'Insufficient information'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
