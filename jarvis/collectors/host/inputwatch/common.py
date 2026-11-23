"""Constants shared by more than one part of inputwatch."""

import hashlib

from jarvis.core.paths import win_script

HEARTBEAT_S = 60

HOOK_PS1 = str(win_script("inputhook.ps1"))

READ_CAP = 8 * 1024 * 1024   # bytes of helper output read per pass; a runaway

_M_DUPES = "input_hook_dupe_pids"       # "<local ts>:<pid,pid>" seen this drain

_M_OVERSIZE = "input_hook_oversized_at"  # local ts the output file blew READ_CAP

_M_SESSION = "input_hook_session"   # "<helper session>:<desktop session>" from the newest beat

SOUND_META = "sound_listener_v1"      # JSON: the newest beat's sound-listener counters + its ts

HOST_META = "input_hook_host"         # JSON: the newest beat's resident-host counters + its ts

STATES_META = "input_hook_states"     # JSON list: recent watchdog events [ts, state, unseen_ms, fg]

STATES_KEEP = 20

OWN_PIDS_META = "input_hook_own_pids"  # JSON {pid: last heartbeat ts}: every helper of ours in 24 h

OWN_PIDS_KEEP_S = 24 * 3600


def _sha256(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


def _mget_int(store, key, default=0):
    try:
        return int(store.get_meta(key, default) or default)
    except (TypeError, ValueError):
        return default
