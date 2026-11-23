"""Release switch with an optimistic base check, driven through the real gate.

State: the ordered list of built releases (names sort in build order, as the
real `releases/` directory does), which one is live, the base a candidate was
staged from, and what the last deploy attempt did.

The `deploy` action calls the shipped `check_expected_base` with a manifest
whose release id is computed by the real `release_id`, so the invariant "a
candidate staged on a base that is no longer live is refused" is checked
against the shipped code. `rollback` mirrors `_deploy_locked --rollback`: the
lexicographically previous release becomes live.

Abstractions: the filesystem, the lock (a second concurrent writer is modelled
as `foreign_switch`, another release switched in between stage and deploy),
the test run, pruning, and the build itself (every build succeeds).
"""

import hashlib
import importlib.util
from dataclasses import dataclass, replace
from pathlib import Path

from jarvis.platform.provenance import release as rel
from jarvis.verify.mc import Model

ROOT = Path(__file__).resolve().parents[3]
DEPLOY_SCRIPT = ROOT / "scripts" / "deploy_root_runtime.py"


class NotApplicable(RuntimeError):
    """The real code this model drives is not part of this copy (packaged
    editions ship no root deploy tool), so the model is not applicable here
    rather than failed. Absent is not applicable."""


def _deploy():
    """Load the shipped deploy gate on first use, never at import: an installed
    copy must still import this package to run the models that apply."""
    global deploy
    if deploy is not None:
        return deploy
    if not DEPLOY_SCRIPT.is_file():
        raise NotApplicable(f"{DEPLOY_SCRIPT.name} is not part of this copy")
    spec = importlib.util.spec_from_file_location("deploy_root_runtime_model", DEPLOY_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    deploy = module
    return module


deploy = None

MAX_RELEASES = 4


def manifest(name):
    digest = hashlib.sha256(name.encode()).hexdigest()      # bare hex, as manifests store it
    files = {"jarvis/x.py": digest}
    return {"files": files, "release_id": rel.release_id(files), "name": name}


@dataclass(frozen=True)
class State:
    releases: tuple = ("r1",)
    live: int = 0
    staged_base: str | None = None      # release id the candidate was staged on
    staged_live: int | None = None      # index that was live when staged (model bookkeeping)
    last: str = "none"                  # none | deployed | refused | rolled_back
    last_matched: bool = True           # the deploy that succeeded had staged_base == live

    @property
    def live_id(self):
        return manifest(self.releases[self.live])["release_id"]


def act_stage(s):
    return (replace(s, staged_base=s.live_id, staged_live=s.live, last="none"),)


def act_foreign_switch(s):
    if len(s.releases) >= MAX_RELEASES:
        return ()
    name = f"r{len(s.releases) + 1}"
    return (replace(s, releases=s.releases + (name,), live=len(s.releases), last="none"),)


def act_deploy(s):
    if s.staged_base is None or len(s.releases) >= MAX_RELEASES:
        return ()
    try:
        _deploy().check_expected_base(s.staged_base, manifest(s.releases[s.live]))
    except SystemExit:
        return (replace(s, last="refused"),)
    name = f"r{len(s.releases) + 1}"
    return (replace(s, releases=s.releases + (name,), live=len(s.releases),
                    staged_base=None, staged_live=None, last="deployed",
                    last_matched=(s.staged_live == s.live)),)


def act_rollback(s):
    if s.live == 0:
        return ()
    return (replace(s, live=s.live - 1, last="rolled_back"),)


ACTIONS = [("stage", act_stage), ("foreign_switch", act_foreign_switch),
           ("deploy", act_deploy), ("rollback", act_rollback)]

INVARIANTS = [
    ("a deploy succeeds only on the base it was staged from",
     lambda s: s.last != "deployed" or s.last_matched),
    ("the live release is always a built release",
     lambda s: 0 <= s.live < len(s.releases)),
]


def model():
    _deploy()                       # NotApplicable here when the gate is not shipped
    return Model("release_switch", State(), ACTIONS, INVARIANTS, max_states=20_000)
