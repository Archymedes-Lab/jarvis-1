"""Running every toolchain check and ordering the result."""

from .common import _finding, reset_cache

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

CAT_ORDER = {"agent": 0, "editor": 1, "vcs": 2, "packages": 3, "visibility": 4}
from .agents import check_agent_hooks
from .extensions import check_extensions
from .mcp import check_mcp
from .packaging import check_git_hooks, check_package_config


def audit(store=None, hosts=("wsl", "win")):
    # The repository walk is the expensive part and four of the five checks
    # need it. Cache it for the run, and drop it afterwards so the next run
    # sees repositories that were cloned since.
    reset_cache()
    out = []
    checks = (
        ("mcp", lambda: check_mcp(store, hosts)),
        ("agent hooks", lambda: check_agent_hooks(store, hosts)),
        ("extensions", lambda: check_extensions(store, hosts)),
        ("git hooks", lambda: check_git_hooks(hosts)),
        ("package config", lambda: check_package_config(hosts)),
    )
    for label, fn in checks:
        try:
            out += fn()  # noqa: PERF203 — one crash must not stop the rest
        except Exception as exc:
            # A check that crashed has to say so where its result would have
            # been. Dropping it would leave the section looking clean, which is
            # the failure this codebase treats as worse than the finding.
            out.append(_finding(
                "visibility", "medium", f"toolchain check '{label}' failed",
                f"{type(exc).__name__}: {exc} — that part of the developer "
                f"trust surface is unaudited this run", label))
    reset_cache()
    return sort_findings(out)


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))
