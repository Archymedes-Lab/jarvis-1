"""Is the developer toolchain still trustworthy?

Split by the surface each part inspects: `mcp` covers what an agent may
call, `agents` its hooks, instruction files and plugins, `extensions` the
editor and browser, `packaging` git hooks and package configuration, and
`run` executes them together.

The package re-exports the flat module's whole surface, internal helpers
included, so existing callers and tests keep working unchanged.
"""

from .agents import (
                     AGENT_DOC_NAMES,
                     INLINE_CODE_RE,
                     INVISIBLE_RE,
                     PROJECT_HOOK_RELS,
                     _check_agent_plugins,
                     _check_instruction_files,
                     _walk_hooks,
                     check_agent_hooks,
)
from .common import (
                     MAX_REPOS,
                     PAYLOAD_RE,
                     SKIP_DIRS,
                     _baseline,
                     _diff,
                     _finding,
                     _hash,
                     _home,
                     _json,
                     _read,
                     _save_baseline,
                     _short,
                     _strip_jsonc,
                     repos,
                     reset_cache,
)
from .extensions import EXT_ROOTS, _extension_dirs, _modified_after_install, check_extensions
from .mcp import (
                     PROJECT_MCP_RELS,
                     SHELL_CMD_RE,
                     USER_MCP_FILES,
                     _describe,
                     _mcp_sources,
                     _score_server,
                     _servers_in,
                     _windows_profiles,
                     check_mcp,
)
from .packaging import _check_pth_files, _is_packaging_shim, check_git_hooks, check_package_config
from .run import CAT_ORDER, SEV_ORDER, audit, sort_findings

__all__ = ["SEV_ORDER", "audit", "sort_findings", "check_mcp",
           "check_agent_hooks", "check_extensions", "check_git_hooks",
           "check_package_config", "repos", "reset_cache"]
