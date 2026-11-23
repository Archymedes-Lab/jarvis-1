"""Semgrep fixtures only; never execute these synthetic bad examples."""
import json
import os
import sqlite3
import subprocess


def code():
    data = json.loads('{}')
    value = data['expression']
    # ruleid: argus-untrusted-code-execution
    eval(value)
    # ruleid: argus-untrusted-code-execution
    subprocess.run(value, shell=True)
    # ok: argus-untrusted-code-execution
    subprocess.run(['echo', value], shell=False)
    # ok: argus-untrusted-code-execution
    eval('1 + 1')


def sql():
    name = input()
    db = sqlite3.connect(':memory:')
    # ruleid: argus-untrusted-sql
    db.execute('SELECT * FROM users WHERE name = ' + name)
    # ok: argus-untrusted-sql
    db.execute('SELECT * FROM users WHERE name = ?', (name,))


def environment():
    value = os.environ.get('SYNTHETIC_VALUE')
    # ruleid: argus-untrusted-code-execution
    os.system(value)
