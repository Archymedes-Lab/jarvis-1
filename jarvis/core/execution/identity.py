"""Persistent identities: which exact execution, not just which pid.

Pids are reused within a boot and restart across boots, so a bare pid is
never an identity. Every object gets a stable key:

  ProcessInstance  device / boot / guid (or pid+start) / executable
  ThreadInstance   process key / tid / created_at
  ModuleInstance   process key / base / path+hash / load_time
  ConnectionInstance process key / proto / endpoints / created_at

Keys are metadata only (no cmdlines, paths beyond module basename for
identity, no content). Pure, no IO.
"""


def process_key(*, device="", boot="", guid="", pid=0, start=""):
    if guid:
        return f"proc:guid:{guid}"
    return f"proc:{device or '?'}:{boot or '?'}:{pid}:{start or 'unknown-start'}"


def thread_key(process, tid=0, created=""):
    return f"thread:{process}:tid:{tid}:{created or 'unknown'}"


def module_key(process, base="", path="", h="", loaded=""):
    name = str(path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return f"mod:{process}:base:{base or '?'}:{name or '?'}:{h[:12] if h else '?'}:{loaded or '?'}"


def connection_key(process, proto="tcp", local="", remote="", created=""):
    return (f"conn:{process}:{str(proto).lower()}:{local or '?'}->"
            f"{remote or '?'}:{created or '?'}")


def describe_process(*, device="", boot="", guid="", pid=0, start="",
                     image="", signer=""):
    """Metadata-only process identity record. Never includes cmdlines."""
    name = str(image or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return {"key": process_key(device=device, boot=boot, guid=guid,
                               pid=pid, start=start),
            "device": device, "boot": boot, "guid": guid, "pid": int(pid or 0),
            "start": start, "image": name, "signer": signer or "unknown"}
