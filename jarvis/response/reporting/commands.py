"""How to inspect each part of the system by hand.

A report that names a problem but not the command that shows it makes the
reader go looking. Every scheduled job here maps to the CLI command that runs
the same collector interactively, so a line in the email is directly
actionable.

The map is validated against the real argument parser by the test suite: a job
that gains a command, or a command that gets renamed, cannot silently leave a
report pointing at something that does not run.
"""

from jarvis.core import mechanisms

# job name -> the CLI command that audits the same ground, declared on each
# collector in core/mechanisms.py.
JOB_COMMANDS = mechanisms.commands()

# Commands worth running whatever the findings say, in the order a person
# would actually work through them.
OVERVIEW = (
    ("jarvis status", "one-line health of every collector and the daemon"),
    ("jarvis outstanding", "what was reported and never resolved"),
    ("jarvis investigate", "every collector in one pass, worst first"),
    ("jarvis coverage", "what JARVIS currently cannot see"),
    ("jarvis selfcheck", "is the monitor actually monitoring?"),
    ("jarvis retention", "database size and what ages out"),
    ("jarvis evidence list", "collected investigation material"),
)


def command_for(job):
    """The full command line for a job, or "" when it has no interactive form."""
    sub = JOB_COMMANDS.get(job)
    return "jarvis %s" % sub if sub else ""


def commands_for_findings(findings):
    """Ordered, de-duplicated commands covering the jobs that reported.

    Ordered by the worst severity each job produced, so the first command in
    the list is the one worth running first.
    """
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
    worst = {}
    for f in findings:
        job = f.get("job") or ""
        cmd = command_for(job)
        if not cmd:
            continue
        r = rank.get(f.get("severity"), 9)
        if r < worst.get(cmd, (9, ""))[0]:
            worst[cmd] = (r, f.get("severity", "?"))
    return [(cmd, sev) for cmd, (r, sev) in
            sorted(worst.items(), key=lambda kv: (kv[1][0], kv[0]))]
