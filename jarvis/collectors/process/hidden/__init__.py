"""Do the process list, the scheduler and the kernel agree on what is running?

Split by the kind of evidence each part gathers: `views` enumerates processes
several independent ways, `sockets` looks for owners that do not exist,
`kernel` inspects modules, eBPF, io_uring and ftrace, `windows` covers the
other host, and `run` correlates them into findings.
"""

from .common import DEFAULT_SWEEP, PROC
from .kernel import (
                     bpf_hidden_pins,
                     bpf_programs,
                     ftrace_hook_list,
                     ftrace_hook_records,
                     ftrace_hooks,
                     hidden_modules,
                     injected_processes,
                     io_uring_state,
                     proc_overmounts,
)
from .run import SEV_ORDER, audit, audit_linux
from .sockets import _socket_table_safe, _visible_tcp_ports, hidden_listeners, orphan_sockets
from .views import (
                     SCHED_DEBUGFS,
                     is_thread,
                     pid_max,
                     pid_namespace_nested,
                     view_getdents,
                     view_kill_probe,
                     view_readdir,
                     view_sched_debug,
                     view_stat_sweep,
)
from .windows import audit_windows

__all__ = [
    "SEV_ORDER", "audit", "audit_linux", "audit_windows",
    "DEFAULT_SWEEP", "PROC",
    "bpf_hidden_pins", "bpf_programs", "ftrace_hook_list", "ftrace_hook_records", "ftrace_hooks", "hidden_modules",
    "injected_processes", "io_uring_state", "proc_overmounts",
    "hidden_listeners", "orphan_sockets", "_visible_tcp_ports",
    "SCHED_DEBUGFS", "is_thread", "pid_max", "pid_namespace_nested", "view_getdents", "view_kill_probe",
    "view_readdir", "view_sched_debug", "view_stat_sweep",
]
