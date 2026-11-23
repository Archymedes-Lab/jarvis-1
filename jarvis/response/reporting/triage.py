"""Who has to act on a finding: JARVIS, or you — and what exactly to do.

Every email groups findings by this answer, because a list of problems is only
useful once it says which ones will fix themselves and which ones are waiting
on a person:

  jarvis       JARVIS repairs or retries this itself. Nothing to do unless it
               keeps coming back.
  you_do       A concrete task only you can perform (rotate a key, approve an
               elevated change, add a passphrase). The step is spelled out.
  you_confirm  A detection only you can judge: it is either something you did
               or something you did not. JARVIS cannot know which, so it will
               not guess and will not silence it.

The rules never promote a finding to "jarvis" unless an automatic action is
actually defined for it (response.remediation) or it is a monitoring outage
the daemon retries on its own. Anything unrecognised defaults to you_confirm:
an unhandled finding must never read as taken care of.
"""

import os

from jarvis.core import egress
from jarvis.response import acknowledge, alert, fixit, remediation

from .commands import command_for

JARVIS, YOU_DO, YOU_CONFIRM = "jarvis", "you_do", "you_confirm"

LABEL = {
    JARVIS: "JARVIS is handling",
    YOU_DO: "Needs you — action",
    YOU_CONFIRM: "Needs you — confirm",
}
BLURB = {
    JARVIS: "Repaired or retried automatically. No action unless it keeps coming back.",
    YOU_DO: "Only you can do these. Each one says exactly what to run or change.",
    YOU_CONFIRM: "JARVIS cannot tell whether you caused these. If you did, they are "
                 "expected; if you did not, treat them as suspicious.",
}
ORDER = (YOU_DO, YOU_CONFIRM, JARVIS)

# Posture-style categories whose finding already carries its fix in `where`.
_SETTING_CATEGORIES = {"malware defense", "platform integrity", "memory defense",
                       "data at rest", "account & access", "attack surface", "licensing"}

# Monitoring limits and upkeep: JARVIS keeps checking, restarts what it
# supervises, and retries refreshes. Nothing here is a task for you.
_MONITORING_CATEGORIES = {"visibility", "limits", "intel", "feed", "telemetry",
                          "auditd", "reporting"}

# Files a tool manages as its own credential store. The right step is to keep
# them private, not to "move the secret out" of the place the tool reads it.
_TOOL_STORES = (".claude/.credentials.json", ".config/gh/hosts.yml",
                ".config/cursor/auth.json", ".config/.wrangler/config/default.toml",
                ".config/archymedes/settings.json", ".docker/config.json", ".fly/config.yml",
                ".config/gcloud/", ".aws/credentials", ".netrc", ".npmrc")

# A suggested command that only reads (verify, list, inspect) is a way to
# confirm, not a fix.
_READ_ONLY = ("get-", "select-", "test-", "dir ", "ls ", "cat ", "type ", "verify ")

_FIREWALL_SCRIPT = ("elevated PowerShell: powershell -ExecutionPolicy Bypass -File "
                    "scripts\\repair\\repair-reported-firewall.ps1 (keeps a rollback record)")


def classify(finding, job=""):
    """{owner, action, command, id} for one finding."""
    result = _classify(finding, job)
    result["id"] = acknowledge.finding_id(finding, job)
    return result


def _classify(finding, job):
    f = finding or {}
    category = (f.get("category") or "").lower()
    title = f.get("title") or ""
    where = f.get("where") or ""
    inspect = command_for(job) if job else ""
    repair = f.get("remediation") or {}

    # The response ladder had its say first. An action JARVIS already took is
    # its to explain (with the undo); one it proposed is yours to approve.
    guard = f.get("defense") or {}
    if guard.get("status") in ("attempting", "uncertain", "not_applied"):
        return _r(YOU_DO,
                  "JARVIS cannot safely assume the outcome of a containment action. "
                  "It did not repeat or undo it. Inspect the preserved evidence, then run "
                  "the read-only recovery check.",
                  "jarvis defend reconcile")
    if guard.get("rung") == "auto" and guard.get("status") == "applied":
        return _r(JARVIS, f"JARVIS contained this automatically ({guard.get('detail', 'done')}). "
                          f"Undo if it was a false alarm.", guard.get("undo", ""))
    if guard.get("rung") == "propose":
        return _r(YOU_DO, "JARVIS can contain this for you — approve it to run the reversible "
                          f"action: {guard.get('preview', '')}", guard.get("approve", ""))

    if repair.get("status") in ("verified", "attempting"):
        return _r(JARVIS, repair.get("reason") or "Automatic repair in progress.", inspect)
    if repair.get("status") in ("failed", "blocked"):
        return _r(YOU_DO, (repair.get("reason") or "Automatic repair could not finish.")
                  + " Run the repair yourself.", fixit.suggest(f) or "jarvis repair status")
    if category in alert.NOPAGE_CATEGORIES:
        return _r(JARVIS, "Recorded on the dashboard and in the advisory; not a task.", inspect)
    if job and remediation.action_for(job, f):
        return _r(JARVIS, "An automatic repair is defined and runs before any alert.", inspect)
    if (alert.is_outage(f) or category in ("daemon", "collectors")
            or (category == "input" and "monitor" in title.lower())):
        return _r(JARVIS, "JARVIS retries or restarts this on its own. If it persists for "
                          "a day, run the command below.", "jarvis selfcheck")
    if category in _MONITORING_CATEGORIES:
        return _r(JARVIS, "A known monitoring limit; JARVIS keeps checking. Nothing to do "
                          "unless you want deeper visibility.", inspect)

    fix = fixit.suggest(f)
    if egress.program_of(title):
        return _r(YOU_CONFIRM, "Say whether this program should reach the internet. Yes "
                               "remembers it; no makes every later connection from it high.",
                  "jarvis answer <id> yes|no")
    if category == "present" or job == "secrets":
        path = where.split(":")[0]
        private = _owner_only(path)
        # Only a verified owner-only mode drops the step; unknown keeps it.
        tighten = f"chmod 600 {path}" if path and private is not True else ""
        if f.get("severity") == "low" and "private project environment file" in title:
            return _r(YOU_CONFIRM, "This is an expected local development credential "
                      "in an owner-only project environment file. Keep it private and "
                      "Git-ignored; rotate it if a copy was exposed, and remove it only "
                      "when the project no longer needs it.", "")
        if "/.claude/paste-cache/" in path:
            return _r(YOU_DO, "A pasted copy of a secret sits in the Claude paste cache. "
                              "Delete the cached file; the original is unaffected.",
                      f"rm {path}" if path else "")
        if any(marker in path for marker in _TOOL_STORES):
            if private is not True:
                return _r(YOU_DO, "This is a tool's own credential store. Keep the secret where "
                                  "the tool reads it, but make sure only you can read the file.",
                          tighten)
            return _r(YOU_CONFIRM, "This is a tool's own credential store and it is already "
                                   "readable only by you. If you still use the tool, that is the "
                                   "expected place for its token: confirm it. If not, sign out "
                                   "of the tool so the token is revoked.", "")
        if "private key" in title:
            return _r(YOU_DO, "Add a passphrase to this key (or delete it if unused)"
                              + ("; the file is also readable by others." if private is False else "."),
                      (f"{tighten} && " if tighten else "") + (f"ssh-keygen -p -f {path}" if path else ""))
        return _r(YOU_DO, "Rotate this credential at its provider, then move it out of the "
                          "plaintext file (a secret manager, or an environment variable loaded "
                          "at runtime)"
                          + (". The file is already readable only by you." if private is True
                             else " and make sure only you can read the file."),
                  tighten)
    if job == "firewall" and category == "rules":
        return _r(YOU_DO, "Remove or narrow this inbound rule. Changing the firewall needs "
                          "Windows administrator approval, which JARVIS does not have.",
                  fix or _FIREWALL_SCRIPT)
    if category == "accounts":
        return _r(YOU_CONFIRM, "Confirm you created this account (sandboxes and dev tools "
                               "sometimes do). If not, the command below reverses it.",
                  fix or inspect)
    if fix:
        verb = fix.split(":", 1)[-1].strip().lower() if fix.lower().startswith("elevated") else fix.lower()
        if verb.startswith(_READ_ONLY):
            return _r(YOU_CONFIRM, "Verify this with the command below; it only reads.", fix)
        return _r(YOU_DO, "Apply this fix.", fix)
    if category in _SETTING_CATEGORIES:
        return _r(YOU_DO, "Turn this protection on.", where or inspect)
    if category in ("agent", "editor", "vcs", "packages"):
        return _r(YOU_CONFIRM, "Confirm this developer-tool configuration is yours before "
                               "the next time the tool runs.", inspect)
    return _r(YOU_CONFIRM, "Confirm whether this was you. Inspect it first; do not delete "
                           "anything based on this alone.", inspect)


def _owner_only(path):
    """True/False for a local file's permissions; None when it cannot be checked
    (a Windows path, or a file that is gone)."""
    if not path or not path.startswith("/"):
        return None
    try:
        return os.stat(path).st_mode & 0o077 == 0
    except OSError:
        return None


def _r(owner, action, command):
    return {"owner": owner, "action": action, "command": command or ""}


def group(items):
    """items: iterable of (finding, job) -> {owner: [(finding, job, triage)]} in ORDER."""
    out = {owner: [] for owner in ORDER}
    for finding, job in items:
        t = classify(finding, job)
        out[t["owner"]].append((finding, job, t))
    for owner in out:
        out[owner].sort(key=lambda it: alert.SEV_RANK.get(it[0].get("severity"), 9))
    return out


def current(snapshots, levels=("critical", "high", "medium"), acks=None, now=None):
    """(finding, job) for every actionable finding in the latest snapshots.

    Churn and meta categories (per-process, per-peer, coverage gaps, the alert
    ledger) are left out, as they are from paging, and so is anything you have
    acknowledged while that acknowledgement holds.
    """
    out = []
    for job, snap in sorted((snapshots or {}).items()):
        for f in (snap or {}).get("findings") or ():
            if (isinstance(f, dict) and f.get("severity") in levels
                    and f.get("category") not in alert.NOPAGE_CATEGORIES
                    and not (acks and acknowledge.is_acknowledged(acks, f, job, now))):
                out.append((f, job))
    return out
