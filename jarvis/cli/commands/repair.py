"""Unprivileged CLI front end for the root-owned repair helper."""
import os
import subprocess

HELPER='/usr/local/sbin/jarvis-repair'


def command(args, store):
    if not os.path.isfile(HELPER):
        print('Repair helper is not installed. Run sudo bash scripts/repair/install-repair-helper.sh.')
        return 1
    result=subprocess.run(['/usr/bin/sudo','-n',HELPER,args.action],timeout=150)
    return result.returncode


def add_parser(sub):
    parser=sub.add_parser('repair',help='run a named privileged JARVIS repair')
    parser.add_argument('action',choices=('status','monitor','telemetry','journal','mount','all'),default='status',nargs='?')
    parser.set_defaults(fn=command)
