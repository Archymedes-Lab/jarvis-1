"""Container intelligence: what each running container can reach on the host.

Read-only. Nothing here starts, stops, execs into, or reconfigures a
container; it only inspects what Docker already reports. Docker absent or
not running is `unavailable`, never "no containers" — a stopped daemon must
not read as a clean fleet. Every check names the exact field it read, so a
finding can be verified by hand against `docker inspect`.

This is source-tested only: it has not been measured against a scenario
where a genuinely malicious container was present, so it is not registered
as a validated detection capability (see assurance.py).
"""

import ipaddress
import json
import os
import re
import selectors
import subprocess
import time
from contextvars import ContextVar
from datetime import datetime

from jarvis.core import collection
from jarvis.core.finding import finding as _finding

TIMEOUT_S = 20
MAX_CONTAINERS = 500
MAX_OUTPUT_BYTES = 1 << 20
AUDIT_TIMEOUT_S = 60
_deadline = ContextVar("container_deadline", default=None)
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
INSPECT_FORMAT = (
    '{"Id":{{json .Id}},"Name":{{json .Name}},'
    '"Config":{"Image":{{json .Config.Image}},"User":{{json .Config.User}},'
    # Variable NAMES only: Docker's template splits each NAME=value and
    # emits the name, so no value ever reaches this process or its store.
    '"Env":[{{range $i, $e := .Config.Env}}{{if $i}},{{end}}'
    '{{json (index (split $e "=") 0)}}{{end}}],"Cmd":{{json .Config.Cmd}},'
    '"Entrypoint":{{json .Config.Entrypoint}},"Tty":{{json .Config.Tty}}},'
    '"HostConfig":{"Privileged":{{json .HostConfig.Privileged}},'
    '"PidMode":{{json .HostConfig.PidMode}},'
    '"NetworkMode":{{json .HostConfig.NetworkMode}},'
    '"IpcMode":{{json .HostConfig.IpcMode}},'
    '"CapAdd":{{json .HostConfig.CapAdd}},'
    '"CapDrop":{{json .HostConfig.CapDrop}},'
    '"SecurityOpt":{{json .HostConfig.SecurityOpt}},'
    '"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},'
    '"PidsLimit":{{json .HostConfig.PidsLimit}},'
    '"Memory":{{json .HostConfig.Memory}},'
    '"RestartPolicy":{{json .HostConfig.RestartPolicy.Name}}},'
    '"Mounts":{{json .Mounts}},'
    '"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}}}'
)
IMAGE_FORMAT = '{"Created":{{json .Created}},"RepoDigests":{{json .RepoDigests}}}'
# Secret-shaped environment variable names. Only names are ever read or
# reported: `docker inspect` shows the values to any docker-group process,
# which is the finding, and JARVIS must not become a second copy of them.
SECRET_ENV = re.compile(r"(?i)(secret|token|passw|api[_-]?key|private[_-]?key|credential"
                        r"|aws_access|aws_secret|gpg_key|_key$)")
# Command shapes the exposed-Docker-API malware families use for the first
# stage (Akamai 2025, TeamPCP 2026): decode-and-pipe, download-and-pipe.
STAGER_SHAPE = re.compile(r"base64\s+(-d|--decode)[^|]*\|\s*(sh|bash|ash)\b"
                          r"|\b(curl|wget)\b[^|]*\|\s*(sh|bash|ash|python3?)\b"
                          r"|\becho\s+[A-Za-z0-9+/=]{40,}\s*\|")
TUNNEL_IMAGES = ("cloudflare/cloudflared", "ngrok/ngrok", "fatedier/frpc", "tailscale/tailscale")
TUNNEL_ENV = ("TUNNEL_TOKEN", "NGROK_AUTHTOKEN")
IMAGE_OLD_DAYS = 365
# Runtime versions below which a known escape or bypass exists. Only entries
# whose fixed version is stated by the vendor or the CVE record; the detail
# text names the source. Checked by exact version comparison, never by date.
RUNTIME_FIXES = (
    ("runc", (1, 3, 3), "CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881",
     "critical", "container escape through /proc writes and a /dev/console race; fixed in runc 1.2.8, 1.3.3 and 1.4.0-rc.3"),
    ("containerd", (2, 2, 4), "CVE-2026-46680", "high",
     "a crafted image with an oversized numeric USER runs as root although it looks non-root; fixed in containerd 1.7.32, 2.0.9, 2.2.4, 2.3.1"),
    ("docker", (29, 5, 1), "CVE-2026-41568", "medium",
     "a malicious container races `docker cp` to create files at any host path; fixed in Docker Engine 29.5.1"),
)
# Real container-breakout primitives, not general hardening advice.
DANGEROUS_CAPS = frozenset({
    "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT",
    "NET_ADMIN", "NET_RAW", "DAC_READ_SEARCH", "DAC_OVERRIDE", "BPF",
    "PERFMON", "ALL",
})
# Host paths whose read-write exposure inside a container is a host compromise
# primitive regardless of the container's own privilege flags.
SENSITIVE_HOST_PATHS = ("/", "/etc", "/root", "/boot", "/var/run/docker.sock",
                        "/run/docker.sock", "/proc", "/sys", "/home")
DOCKER_SOCK_NAMES = ("/var/run/docker.sock", "/run/docker.sock")


def _run(args):
    """Bound output and wall time; never expose raw daemon diagnostics."""
    deadline = min(_deadline.get() or float("inf"), time.monotonic() + TIMEOUT_S)
    if time.monotonic() >= deadline:
        return None, "audit time budget exhausted"
    try:
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            try:
                data = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            return None, "command time budget exhausted"
                        if not selector.select(remaining):
                            return None, "command time budget exhausted"
                        chunk = os.read(proc.stdout.fileno(), 65536)
                        if not chunk:
                            break
                        if len(data) + len(chunk) > MAX_OUTPUT_BYTES:
                            return None, "command output limit exceeded"
                        data.extend(chunk)
                code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
                if code:
                    return None, f"docker command failed (exit {code})"
                return data.decode("utf-8", "replace"), None
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, type(exc).__name__


def daemon_state():
    """(available, detail). False with a reason when Docker cannot be inspected."""
    out, err = _run([*DOCKER, "version", "--format", "{{.Server.Version}}"])
    if out is None:
        return False, err or "docker unavailable"
    return True, out.strip()


def list_containers():
    """[{id, name}] for every container Docker reports, running or not."""
    out, err = _run([*DOCKER, "ps", "-a", "--format", "{{.ID}}\t{{.Names}}"])
    if out is None:
        return None, err
    rows = []
    for line in out.splitlines():
        cid, _, name = line.partition("\t")
        if cid.strip():
            rows.append({"id": cid.strip(), "name": name.strip() or cid.strip()})
    return rows[:MAX_CONTAINERS], ("container inventory limit exceeded"
                                   if len(rows) > MAX_CONTAINERS else None)


def inspect(container_id):
    """Parsed `docker inspect` for one container, or None on any failure."""
    out, _err = _run([*DOCKER, "inspect", "--format", INSPECT_FORMAT, container_id])
    if out is None:
        return None
    try:
        cfg = json.loads(out)
    except ValueError:
        return None
    if not isinstance(cfg, dict) or not str(cfg.get("Id") or "").startswith(container_id):
        return None
    host = cfg.get("HostConfig")
    config = cfg.get("Config")
    net = cfg.get("NetworkSettings")
    mounts = cfg.get("Mounts")
    if (not isinstance(host, dict) or not isinstance(config, dict)
            or not isinstance(net, dict) or not isinstance(mounts, list)
            or not isinstance(host.get("Privileged"), bool)
            or any(not isinstance(host.get(k), str) for k in ("PidMode", "NetworkMode", "IpcMode"))
            or not isinstance(config.get("Image"), str)
            or not isinstance(cfg.get("Name"), str)):
        return None
    caps = host.get("CapAdd")
    ports = net.get("Ports")
    if ("CapAdd" not in host or "Ports" not in net
            or caps is not None and (not isinstance(caps, list) or any(not isinstance(c, str) for c in caps))
            or not isinstance(ports, (dict, type(None)))
            or any(not isinstance(m, dict) or not isinstance(m.get("RW"), bool)
                   or any(not isinstance(m.get(k), str) for k in ("Source", "Destination"))
                   for m in mounts)):
        return None
    for bindings in (ports or {}).values():
        if bindings is not None and (not isinstance(bindings, list)
                or any(not isinstance(b, dict)
                       or any(not isinstance(b.get(k), str) for k in ("HostIp", "HostPort"))
                       for b in bindings)):
            return None
    return cfg


def inspect_image(image_ref):
    """{created: epoch or None, digests: [..]} for one image, or None."""
    out, _err = _run([*DOCKER, "image", "inspect", "--format", IMAGE_FORMAT, image_ref])
    if out is None:
        return None
    try:
        data = json.loads(out)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    created = None
    raw = str(data.get("Created") or "")
    try:
        created = datetime.fromisoformat(raw.replace("Z", "+00:00")[:26] + "+00:00"
                                         if raw.endswith("Z") and len(raw) > 26 else
                                         raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        created = None
    digests = data.get("RepoDigests")
    return {"created": created, "digests": digests if isinstance(digests, list) else []}


def _mounts(cfg):
    return cfg.get("Mounts") or []


def _sensitive_mount(mount):
    src = str(mount.get("Source") or "")
    return mount.get("RW") and any(
        src == p or src.rstrip("/") == p.rstrip("/") for p in SENSITIVE_HOST_PATHS)


def _docker_sock_mounted(cfg):
    for m in _mounts(cfg):
        dst = str(m.get("Destination") or "")
        if dst in DOCKER_SOCK_NAMES or m.get("Source") in DOCKER_SOCK_NAMES:
            return True
    return False


def _dangerous_caps(cfg):
    host = cfg.get("HostConfig") or {}
    add = {str(c).upper().removeprefix("CAP_") for c in (host.get("CapAdd") or [])}
    return sorted(add & DANGEROUS_CAPS)


def _published_public(cfg):
    """Ports bound to a non-loopback host address, not just container-internal."""
    net = cfg.get("NetworkSettings") or {}
    out = []
    for container_port, bindings in (net.get("Ports") or {}).items():
        for b in bindings or []:
            # Docker's own semantics: an empty/absent HostIp binds all interfaces
            # (equivalent to 0.0.0.0), not localhost. Defaulting it to loopback
            # would hide the common case of a genuinely exposed port.
            host_ip = str(b.get("HostIp") or "") or "0.0.0.0"
            try:
                is_loopback = ipaddress.ip_address(host_ip).is_loopback
            except ValueError:
                is_loopback = False
            if not is_loopback:
                out.append(f"{host_ip}:{b.get('HostPort')}->{container_port}")
    return out


def assess(cfg, now=None, image_info=None):
    """One container's raw inspect data -> findings. Pure.

    `image_info` is the matching `inspect_image` result when the caller has
    it; `now` is the clock for image age."""
    host = cfg.get("HostConfig") or {}
    name = str((cfg.get("Name") or "")).lstrip("/") or cfg.get("Id", "")[:12]
    image = str(cfg.get("Config", {}).get("Image") or "unknown")
    where = f"{name} ({image})"
    out = []

    if host.get("Privileged"):
        out.append(_finding("containers", "critical", "privileged container",
                            f"{where} runs with HostConfig.Privileged=true: full device and "
                            f"kernel-capability access, equivalent to root on the host", where))
    if host.get("PidMode") == "host":
        out.append(_finding("containers", "high", "container shares the host PID namespace",
                            f"{where} has HostConfig.PidMode=host: it can see and signal "
                            f"every host process", where))
    if host.get("NetworkMode") == "host":
        out.append(_finding("containers", "medium", "container shares the host network namespace",
                            f"{where} has HostConfig.NetworkMode=host: no network isolation "
                            f"from the host", where))
    if host.get("IpcMode") == "host":
        out.append(_finding("containers", "medium", "container shares the host IPC namespace",
                            f"{where} has HostConfig.IpcMode=host", where))
    if _docker_sock_mounted(cfg):
        out.append(_finding("containers", "critical", "the Docker socket is mounted inside a container",
                            f"{where} can mount /var/run/docker.sock: this is equivalent to "
                            f"unrestricted root on the host by design of the Docker API, "
                            f"regardless of this container's own privilege flags", where))
    for m in _mounts(cfg):
        if _sensitive_mount(m):
            out.append(_finding("containers", "critical", "sensitive host path mounted read-write",
                                f"{where} mounts host path {m.get('Source')} read-write at "
                                f"{m.get('Destination')}", where))
    caps = _dangerous_caps(cfg)
    if caps:
        out.append(_finding("containers", "high", "container was granted extra kernel capabilities",
                            f"{where} HostConfig.CapAdd includes {', '.join(caps)}", where))
    for pub in _published_public(cfg):
        out.append(_finding("containers", "low", "container port reachable beyond loopback",
                            f"{where} publishes {pub}; confirm this is intended to be reachable "
                            f"from outside this host", where))
    out.extend(_posture(cfg, where, image, now=now, image_info=image_info))
    if not out:
        out.append(_finding("containers", "ok", "no elevated host access found",
                            f"{where}: not privileged, no host namespaces, no Docker socket, "
                            f"no sensitive host mounts, no added dangerous capabilities", where))
    return out


def _secopt(cfg):
    return [str(o).lower() for o in ((cfg.get("HostConfig") or {}).get("SecurityOpt") or [])]


def _command_text(cfg):
    config = cfg.get("Config") or {}
    parts = []
    for key in ("Entrypoint", "Cmd"):
        value = config.get(key)
        if isinstance(value, list):
            parts.extend(str(v) for v in value)
        elif isinstance(value, str):
            parts.append(value)
    return " ".join(parts)


def _posture(cfg, where, image, now=None, image_info=None):
    """Hardening and supply-chain posture of one container: how far an
    attacker who lands inside it can get, and how it could have been
    poisoned. Advisory severities; nothing here is a compromise claim."""
    host = cfg.get("HostConfig") or {}
    config = cfg.get("Config") or {}
    out = []
    secopt = _secopt(cfg)
    if any(o in ("seccomp=unconfined", "seccomp:unconfined") for o in secopt):
        out.append(_finding(
            "containers", "high", "container runs without the seccomp filter",
            f"{where} has seccomp=unconfined: every kernel syscall is reachable, including "
            f"the AF_ALG crypto sockets behind CVE-2026-31431 (Copy Fail) that the default "
            f"profile blocks; a kernel bug is then a host compromise", where))
    if any(o in ("apparmor=unconfined", "apparmor:unconfined") for o in secopt):
        out.append(_finding("containers", "medium", "container runs without an AppArmor profile",
                            f"{where} has apparmor=unconfined", where))
    user = str(config.get("User") or "").strip()
    runs_as_root = user in ("", "0", "root") or user.startswith(("0:", "root:"))
    if runs_as_root and not host.get("Privileged"):
        out.append(_finding(
            "containers", "medium", "container runs as root",
            f"{where} has no Config.User: a code-execution bug in the service is root inside "
            f"the container, which is where every escape primitive starts. Add `user:` in the "
            f"compose file or USER in the image.", where))
    if host.get("PidMode") == "host" and "SYS_PTRACE" in _dangerous_caps(cfg):
        out.append(_finding(
            "containers", "critical", "container can trace host processes",
            f"{where} combines PidMode=host with CAP_SYS_PTRACE: it can attach to and inject "
            f"into any host process, which is an escape without a kernel bug", where))
    if "no-new-privileges" not in " ".join(secopt) and not host.get("Privileged"):
        out.append(_finding(
            "containers", "low", "container allows privilege gain through setuid binaries",
            f"{where} lacks security_opt no-new-privileges:true", where))
    if not host.get("ReadonlyRootfs") and not host.get("Privileged"):
        out.append(_finding("containers", "low", "container root filesystem is writable",
                            f"{where}: a dropped binary persists for the container's life; "
                            f"read_only: true with tmpfs for scratch paths removes that", where))
    limits = []
    if not host.get("PidsLimit"):
        limits.append("pids")
    if not host.get("Memory"):
        limits.append("memory")
    if limits:
        out.append(_finding(
            "containers", "low", "container has no resource limits",
            f"{where} has no {' or '.join(limits)} limit: a miner or fork bomb inside it "
            f"takes the whole host with it (on a WSL workstation, the VM: measured "
            f"2026-10-23)", where))
    tag = image.rsplit("/", 1)[-1]
    if ":" not in tag or tag.endswith(":latest"):
        out.append(_finding(
            "containers", "low", "image pulled by a mutable tag",
            f"{where}: tag `{tag.split(':')[-1] if ':' in tag else 'latest'}` can be overwritten "
            f"upstream (Trivy March 2026, KICS April 2026, LiteLLM October 2026 all shipped "
            f"malware under existing tags); pin a digest (image@sha256:...)", where))
    if image_info and image_info.get("created") and now:
        age_days = (now - image_info["created"]) / 86400
        if age_days > IMAGE_OLD_DAYS:
            out.append(_finding(
                "containers", "medium", "image is more than a year old",
                f"{where}: built {int(age_days)} days ago; every CVE fixed since in its base "
                f"image and runtime is still present inside this container", where))
    names = []
    for item in config.get("Env") or []:
        name = str(item).split("=", 1)[0]
        if SECRET_ENV.search(name):
            names.append(name)
    if names:
        out.append(_finding(
            "containers", "medium", "secrets live in the container environment",
            f"{where} carries {len(names)} secret-shaped variable(s): {', '.join(sorted(names)[:8])}"
            f"{' ...' if len(names) > 8 else ''}. `docker inspect` prints the values to every "
            f"process in the docker group, and every child of PID 1 inherits them; the 2026 "
            f"container stealers (TeamPCP, PCPJack, LiteLLM) read exactly these. Compose "
            f"`secrets:` mounts them as files instead.", where))
    cmd = _command_text(cfg)
    if cmd and STAGER_SHAPE.search(cmd):
        out.append(_finding(
            "containers", "high", "container command is a decode-and-run stager",
            f"{where} starts with a command that decodes or downloads and pipes into a shell: "
            f"{cmd[:120]!r}. This is the first stage every exposed-Docker-API malware family "
            f"uses; confirm you wrote it.", where))
    tunnel = any(image.startswith(t) for t in TUNNEL_IMAGES) or any(
        str(e).split("=", 1)[0] in TUNNEL_ENV for e in config.get("Env") or [])
    if tunnel:
        out.append(_finding(
            "containers", "medium", "container opens an inbound tunnel from the internet",
            f"{where} runs a tunnel client: services on this machine are reachable from the "
            f"internet through it, bypassing the Windows firewall and the loopback-only "
            f"publishing checks above. Everything the tunnel exposes is an internet-facing "
            f"service and must be treated as such.", where))
    if str(host.get("RestartPolicy") or "") == "always" and runs_as_root:
        out.append(_finding(
            "containers", "low", "root container restarts unconditionally",
            f"{where} has restart=always as root: whatever lands inside it comes back after "
            f"every reboot, which is the persistence shape the Docker-API worms set", where))
    return out


def host_posture(info=None, group=None, listeners=None, versions=None, daemon_json=None,
                 docker_config=None):
    """Findings about the Docker host itself: who can drive the daemon, how it
    listens, what it protects containers with, and which known-vulnerable
    runtime versions it runs. Pure over measured dicts."""
    out = []
    info = info or {}
    members = [m for m in (group or []) if m and m != "root"]
    if members:
        out.append(_finding(
            "containers", "medium", "docker group grants root-equivalent control",
            f"{', '.join(members)} can create a container that mounts / and chroots into it: "
            f"the Docker daemon treats docker-group members as root. Any program running as "
            f"this user (including anything launched from Windows through WSL) has that power. "
            f"Rootless Docker or userns-remap narrows it.", "docker group"))
    for addr in listeners or []:
        tls = str(addr).endswith(":2376")
        out.append(_finding(
            "containers", "high" if tls else "critical",
            "Docker API listens on TCP",
            f"{addr}: {'TLS port; confirm client certificates are required' if tls else 'the unauthenticated API port that the 2025-2026 cryptojacking worms scan for (Akamai, PCPJack); anyone who reaches it is root on this host'}",
            "dockerd"))
    secopts = " ".join(str(o) for o in (info.get("SecurityOptions") or []))
    if "name=userns" not in secopts:
        out.append(_finding("containers", "medium", "container root is host root",
                            "userns-remap is off: UID 0 inside every container is UID 0 on the "
                            "host, so any escape lands as root. `userns-remap` in daemon.json or "
                            "rootless Docker maps it to an unprivileged range.", "dockerd"))
    if "name=seccomp" not in secopts:
        out.append(_finding("containers", "high", "default seccomp profile is not active",
                            "containers can reach every syscall", "dockerd"))
    if "name=apparmor" not in secopts and "name=selinux" not in secopts:
        out.append(_finding("containers", "low", "no mandatory access control for containers",
                            "neither AppArmor nor SELinux confines containers (the WSL kernel "
                            "ships without AppArmor); seccomp and capabilities are the only "
                            "kernel-side limits", "dockerd"))
    if info and info.get("LiveRestoreEnabled") is False:
        out.append(_finding("containers", "low", "live-restore is off",
                            "every daemon restart stops every container; with it on, containers "
                            "survive the daemon and the 2026-10-23 WSL relaunch would not have "
                            "restarted them from scratch", "dockerd"))
    insecure = [r for r in (info.get("RegistryConfig") or {}).get("InsecureRegistryCIDRs", []) or []
                if not str(r).startswith("127.")]
    insecure += list((info.get("RegistryConfig") or {}).get("IndexConfigs", {}) and [
        n for n, c in (info.get("RegistryConfig") or {}).get("IndexConfigs", {}).items()
        if isinstance(c, dict) and c.get("Secure") is False and not n.startswith("127.")])
    if insecure:
        out.append(_finding("containers", "high", "insecure registry configured",
                            f"{', '.join(map(str, insecure))}: images pulled over plain HTTP or "
                            f"without certificate checks can be swapped in transit", "daemon.json"))
    if daemon_json is None:
        out.append(_finding("containers", "low", "daemon runs on defaults",
                            "/etc/docker/daemon.json is absent: no-new-privileges, userns-remap, "
                            "icc=false, log limits and live-restore are all unset", "daemon.json"))
    elif isinstance(daemon_json, dict) and not daemon_json.get("no-new-privileges"):
        out.append(_finding("containers", "low", "no-new-privileges is not the default",
                            "set \"no-new-privileges\": true in daemon.json", "daemon.json"))
    for component, fixed, cve, severity, why in RUNTIME_FIXES:
        have = (versions or {}).get(component)
        parsed = _version(have)
        if parsed is None:
            continue
        if parsed < fixed:
            out.append(_finding(
                "containers", severity, f"{component} {have} has a known container-escape or bypass bug",
                f"{cve}: {why}. Update the package.", component))
    if docker_config and docker_config.get("auths") and not docker_config.get("credsStore") \
            and not docker_config.get("credHelpers"):
        regs = ", ".join(sorted(str(k) for k in docker_config["auths"]))
        out.append(_finding(
            "containers", "medium", "registry credentials stored unencrypted",
            f"~/.docker/config.json holds base64 logins for {regs} with no credential helper; "
            f"the 2026 container stealers (Trivy, LiteLLM, GhostLoader, Lumma) read this file "
            f"first. Use a credsStore and rotate the tokens.", "~/.docker/config.json"))
    return out


def _version(text):
    """'1.3.3-0ubuntu1~24.04.3' -> (1, 3, 3); None when unparseable."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(text or ""))
    return tuple(int(g) for g in m.groups()) if m else None


def host_facts():
    """Measured inputs for `host_posture`, each None when unreadable."""
    info = None
    out, _ = _run([*DOCKER, "info", "--format", "{{json .}}"])
    if out:
        try:
            info = json.loads(out)
        except ValueError:
            info = None
    group = []
    try:
        import grp
        group = list(grp.getgrnam("docker").gr_mem)
    except (KeyError, OSError):
        group = []
    listeners = []
    try:
        proc = subprocess.run(["ss", "-ltnH"], capture_output=True, text=True,
                              errors="replace", timeout=10)
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3].rsplit(":", 1)[-1] in ("2375", "2376"):
                listeners.append(parts[3])
    except (OSError, subprocess.SubprocessError):
        pass
    versions = {}
    if info:
        versions["docker"] = info.get("ServerVersion")
        for comp in info.get("Runtimes") or {}:
            pass
    for component, cmd in (("runc", ["runc", "--version"]), ("containerd", ["containerd", "--version"])):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                  timeout=10)
            first = (proc.stdout or "").splitlines()[0] if proc.stdout else ""
            versions[component] = first
        except (OSError, subprocess.SubprocessError, IndexError):
            continue
    daemon_json = None
    try:
        with open("/etc/docker/daemon.json", encoding="utf-8", errors="replace") as fh:
            daemon_json = json.load(fh)
    except (OSError, ValueError):
        daemon_json = None
    docker_config = None
    try:
        with open(os.path.expanduser("~/.docker/config.json"), encoding="utf-8", errors="replace") as fh:
            raw = json.load(fh)
        # Keys only: never the base64 logins themselves.
        docker_config = {"auths": sorted((raw.get("auths") or {}).keys()),
                         "credsStore": raw.get("credsStore"), "credHelpers": raw.get("credHelpers")}
    except (OSError, ValueError, AttributeError):
        docker_config = None
    return info, group, listeners, versions, daemon_json, docker_config


EVENTS_META = "containers_events_cursor_v1"
EVENTS_MAX = 500
EXEC_SHAPE = re.compile(r"\b(nsenter|chroot|mount|insmod|modprobe|base64\s+-d|curl|wget)\b")


def events_since(since_epoch, until_epoch):
    """Daemon events between two times as parsed dicts; None when unreadable.
    dockerd keeps events in memory only, so nothing survives a daemon restart."""
    out, _err = _run([*DOCKER, "events", "--since", str(int(since_epoch)),
                      "--until", str(int(until_epoch)), "--format", "{{json .}}"])
    if out is None:
        return None
    rows = []
    for line in out.splitlines()[:EVENTS_MAX]:
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def judge_events(rows):
    """Findings from daemon events: who was created with what, and what was
    executed inside running containers (ATT&CK T1609/T1610)."""
    out = []
    created, execs, suspicious = [], [], []
    for ev in rows or []:
        if ev.get("Type") != "container":
            continue
        attrs = (ev.get("Actor") or {}).get("Attributes") or {}
        name = attrs.get("name") or (ev.get("Actor") or {}).get("ID", "")[:12]
        action = str(ev.get("Action") or "")
        if action == "create":
            created.append(f"{name} ({attrs.get('image', '?')})")
        elif action.startswith("exec_create"):
            command = action.split(":", 1)[1].strip() if ":" in action else ""
            execs.append((name, command))
            if EXEC_SHAPE.search(command):
                suspicious.append((name, command))
    for name, command in suspicious[:10]:
        out.append(_finding(
            "containers", "high", f"escape-shaped command executed inside {name}",
            f"docker exec ran {command[:140]!r}: namespace entry, chroot, mounting, module "
            f"loading or decode-and-run inside a container is how an operator who already "
            f"holds the daemon breaks out or stages tooling (T1609/T1611)", name))
    if execs:
        latest = execs[-1]
        out.append(_finding(
            "containers", "low", f"{len(execs)} command(s) executed inside containers",
            f"most recent in {latest[0]}: {latest[1][:100]!r}. `docker exec` is the "
            f"container administration path (T1609); yours while you develop, an "
            f"intruder's when it is not.", "docker events"))
    if created:
        out.append(_finding(
            "containers", "low", f"{len(created)} container(s) created",
            ", ".join(created[:6]) + (" ..." if len(created) > 6 else "")
            + ". New containers are judged by the inspection above when they are still running.",
            "docker events"))
    return out


def _audit(hosts, store=None):
    if "wsl" not in hosts:
        return []
    if not any(os.path.exists(p) for p in DOCKER_SOCK_NAMES) and not any(
            os.access(os.path.join(d, "docker"), os.X_OK)
            for d in os.environ.get("PATH", "/usr/bin:/bin").split(os.pathsep)):
        return [_finding("containers", "ok", "Docker is not installed",
                         "no Docker socket or CLI on this host, so there are no "
                         "containers to inspect", "docker")]
    available, detail = daemon_state()
    if not available:
        collection.failed("containers", detail)
        return [_finding("containers", "low", "Docker is not available for inspection",
                         f"{detail}. Container risk on this host is unknown, not clean.",
                         "docker")]
    rows, err = list_containers()
    if rows is None:
        collection.failed("containers", err or "docker ps failed")
        return [_finding("containers", "low", "container list unavailable", str(err), "docker ps")]
    out = []
    inspected, unreadable = 0, []
    now = time.time()
    images = {}
    for row in rows:
        cfg = inspect(row["id"])
        if cfg is None:
            unreadable.append(row["name"])
            continue
        inspected += 1
        image = str((cfg.get("Config") or {}).get("Image") or "")
        if image and image not in images:
            images[image] = inspect_image(image)
        out.extend(assess(cfg, now=now, image_info=images.get(image)))
    out.extend(host_posture(*host_facts()))
    if store is not None:
        try:
            since = float(store.get_meta(EVENTS_META, "") or (now - 3600))
        except (TypeError, ValueError):
            since = now - 3600
        rows_ev = events_since(since, now)
        if rows_ev is None:
            out.append(_finding("containers", "low", "Docker events unreadable this run",
                                "exec and create activity inside containers was not judged",
                                "docker events"))
        else:
            out.extend(judge_events(rows_ev))
            store.set_meta(EVENTS_META, str(now))
    if err:
        collection.failed("containers", err)
        out.append(_finding("containers", "low", "container inventory truncated",
                            err, "docker ps"))
    if unreadable:
        collection.failed("containers", "some inspections unavailable")
        out.append(_finding(
            "containers", "low", "some containers could not be inspected",
            f"{len(unreadable)} container(s) returned no inspect data: "
            + ", ".join(unreadable[:10]) + (" ..." if len(unreadable) > 10 else ""),
            "docker inspect"))
    if inspected or not rows:
        collection.succeeded("containers")
    complete = not unreadable and not err
    out.append(_finding("containers", "ok" if complete else "low",
                        "container inventory complete" if complete else "container inventory incomplete",
                        f"{inspected} of {len(rows)} container(s) inspected", "docker ps"))
    return out


def audit(store=None, hosts=("wsl",)):
    token = _deadline.set(time.monotonic() + AUDIT_TIMEOUT_S)
    try:
        return _audit(hosts, store=store)
    finally:
        _deadline.reset(token)
