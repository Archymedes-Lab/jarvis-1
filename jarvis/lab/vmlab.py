"""Host-side control of the disposable Linux guest (QEMU/KVM in a locked-down container).

Design and invariants (each has a test):

  isolation   the container has no network, no capabilities, no privileged mode and
              exactly one device (/dev/kvm); the guest has a restricted NIC that
              reaches nothing, no shares, no audio or video passthrough, and a
              copy-on-write overlay over a read-only base image that is re-hashed
              after every run to prove nothing persisted
  authority   the host never executes emulator code: it is delivered inside the
              guest payload, and the guest marks itself a sandbox first
  politeness  refuse to start under CPU or memory pressure and run at low weight;
              the lab must never degrade the machine it protects
  data only   guest output is size-capped, hash-checked and parsed as JSON, never run
  cleanup     the container is removed by name on every path, disposal is verified
  images      each guest image is named in IMAGES with its checksum list and hash;
              an unknown name, a missing list or a mismatch is refused (fail closed)
  reboot      the guest may reboot only when Config.allow_reboot is set; QEMU stays in
              the same locked-down container and the run timeout still bounds it

Absent evidence stays absent: a run that cannot start reports why and returns no results.
"""

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from jarvis.core.paths import PACKAGE_DIR

ROOT = Path(os.path.expanduser("~/.cache/jarvis-vmlab"))
IMAGE_NAME = "noble-server-cloudimg-amd64.img"


@dataclass(frozen=True)
class Image:
    """A guest base image under ROOT/images: its file, its checksum list and hash."""
    key: str
    file: str            # relative to ROOT/images
    sums: str            # checksum list, relative to ROOT/images
    algo: str            # "sha256" or "sha512"
    os_name: str


# The default stays first and at the path older runs used (images/<noble file>).
IMAGES = {
    "ubuntu-24.04": Image("ubuntu-24.04", IMAGE_NAME, "SHA256SUMS", "sha256", "Ubuntu 24.04 LTS"),
    "debian-12": Image("debian-12", "debian-12/debian-12-genericcloud-amd64-20261026-2643.qcow2",
                       "debian-12/SHA512SUMS", "sha512", "Debian 12"),
    "ubuntu-22.04": Image("ubuntu-22.04", "ubuntu-22.04/jammy-server-cloudimg-amd64.img",
                          "ubuntu-22.04/SHA256SUMS", "sha256", "Ubuntu 22.04 LTS"),
}
DEFAULT_IMAGE = "ubuntu-24.04"
CONTAINER_IMAGE = "jarvis-vmlab:1"
MAX_SERIAL_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 1024 * 1024
BEGIN, END, SHA = "JVLAB-DATA-BEGIN", "JVLAB-DATA-END", "JVLAB-SHA256"
ANSI = re.compile(r"\x1b\[[0-9;?=]*[A-Za-z]")

# Payload: only what the guest needs, byte-identical to the code under test.
PAYLOAD_FILES = (
    "jarvis/__init__.py", "jarvis/core/__init__.py", "jarvis/core/reasoning/__init__.py",
    "jarvis/core/reasoning/vocab.py", "jarvis/platform/__init__.py", "jarvis/platform/spy_linux.py",
    "jarvis/lab/guest/__init__.py", "jarvis/lab/guest/emu_linux.py", "jarvis/lab/guest/linux_run.py",
)
GUEST_PATH = {"jarvis/lab/guest/emu_linux.py": "lab/emu_linux.py",
              "jarvis/lab/guest/linux_run.py": "lab/linux_run.py",
              "jarvis/lab/guest/__init__.py": "lab/__init__.py"}


@dataclass
class Config:
    root: Path = ROOT
    guest_mb: int = 1024
    cpus: int = 2
    timeout_s: int = 900
    max_cpu_pressure: float = 40.0      # percent of the last 60 s with runnable tasks waiting
    min_avail_mb: int = 2500
    min_free_gb: float = 3.0
    cpu_shares: int = 128               # low weight next to the user's own work
    container_image: str = CONTAINER_IMAGE
    kvm_gid: int | None = None
    image: str = DEFAULT_IMAGE
    allow_reboot: bool = False          # a guest reboot ends QEMU unless this is set
    extra: dict = field(default_factory=dict)


class LabError(RuntimeError):
    pass


# -- pure builders -------------------------------------------------------------

def _hex(path, chunk=1 << 20, algo="sha256"):
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def docker_command(cfg, run_dir, name, gid):
    """argv for the one container that hosts QEMU. Pure."""
    root = Path(cfg.root)
    return [
        "docker", "run", "--rm", "--name", name,
        "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", f"{os.getuid()}:{os.getgid()}", "--device", "/dev/kvm", "--group-add", str(gid),
        "--pids-limit", "256", "--memory", f"{cfg.guest_mb + 768}m", "--cpus", str(cfg.cpus),
        "--cpu-shares", str(cfg.cpu_shares), "--read-only", "--tmpfs", "/tmp:rw,size=64m",
        "-v", f"{root / 'images'}:/img:ro", "-v", f"{run_dir}:/work",
        cfg.container_image, "timeout", str(cfg.timeout_s + 30),
        "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
        "-smp", str(cfg.cpus), "-m", str(cfg.guest_mb), "-display", "none", "-monitor", "none",
        "-serial", "file:/work/serial.log", "-nic", "user,model=virtio-net-pci,restrict=on",
        "-bios", "/usr/share/OVMF/OVMF.fd",
        "-drive", "file=/work/overlay.qcow2,if=virtio,format=qcow2",
        "-drive", "file=/work/seed.iso,media=cdrom,readonly=on",
        "-drive", "id=payload,if=none,file=/work/payload.tar,format=raw,readonly=on",
        "-device", "virtio-blk-pci,drive=payload,serial=jvpayload",
        "-device", "virtio-keyboard-pci", "-audiodev", "none,id=snd0",
        "-device", "intel-hda", "-device", "hda-duplex,audiodev=snd0",
    ] + ([] if cfg.allow_reboot else ["-no-reboot"])


def helper_command(cfg, run_dir, *argv):
    """A short-lived helper container (seed ISO, overlay). Same restrictions, no device."""
    root = Path(cfg.root)
    return ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{root / 'images'}:/img:ro", "-v", f"{run_dir}:/work", cfg.container_image, *argv]


USER_DATA = """#cloud-config
runcmd:
  - [ sh, -c, "exec >/dev/ttyS0 2>&1; touch /etc/jarvis-arena-sandbox; mkdir -p /opt/lab; tar xf /dev/disk/by-id/virtio-jvpayload -C /opt/lab; python3 /opt/lab/lab/linux_run.py; poweroff -f" ]
"""


def scenario_records(controls):
    return [{"id": c.id, "emulator": c.emulator, "needs": c.needs,
             "expect_kinds": list(c.expect_kinds), "max_latency_s": c.max_latency_s} for c in controls]


def build_payload(run_dir, controls, package_dir=PACKAGE_DIR):
    """Write payload.tar and return {guest path: sha256} of everything shipped."""
    run_dir = Path(run_dir)
    base = Path(package_dir).parent
    hashes = {}
    with tarfile.open(run_dir / "payload.tar", "w", format=tarfile.PAX_FORMAT) as tar:
        for rel in PAYLOAD_FILES:
            src = base / rel
            data = src.read_bytes()
            dest = GUEST_PATH.get(rel, rel)
            info = tarfile.TarInfo(dest)
            info.size, info.mode, info.uid, info.gid, info.mtime = len(data), 0o644, 0, 0, 0
            tar.addfile(info, fileobj=__import__("io").BytesIO(data))
            hashes["/opt/lab/" + dest] = hashlib.sha256(data).hexdigest()
        raw = json.dumps(scenario_records(controls)).encode()
        info = tarfile.TarInfo("scenarios.json")
        info.size, info.mode, info.mtime = len(raw), 0o644, 0
        tar.addfile(info, fileobj=__import__("io").BytesIO(raw))
    return hashes


def parse_serial(text, expect_files=None):
    """(result, problems) from the guest console. Untrusted: capped, hash-checked, data only."""
    problems = []
    if len(text) > MAX_SERIAL_BYTES:
        text = text[-MAX_SERIAL_BYTES:]
        problems.append("console log truncated to its tail")
    lines = [ANSI.sub("", ln).replace("\r", "").strip() for ln in text.splitlines()]
    try:
        start = max(i for i, ln in enumerate(lines) if ln == BEGIN)
        stop = next(i for i in range(start + 1, len(lines)) if lines[i] == END)
    except (ValueError, StopIteration):
        return None, problems + ["guest result markers not found"]
    b64 = "".join(lines[start + 1:stop])
    if len(b64) > MAX_RESULT_BYTES * 4 // 3 + 8:
        return None, problems + ["guest result exceeds the size cap"]
    try:
        raw = base64.b64decode(b64, validate=True)
    except ValueError:
        return None, problems + ["guest result is not valid base64"]
    claimed = next((ln.split()[1] for ln in lines[stop + 1:stop + 6]
                    if ln.startswith(SHA + " ") and len(ln.split()) == 2), None)
    if claimed != hashlib.sha256(raw).hexdigest():
        return None, problems + ["guest result hash does not match its digest line"]
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None, problems + ["guest result is not valid JSON"]
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return None, problems + ["guest result has an unexpected shape"]
    if expect_files is not None and data.get("files_sha256") != {
            p: h for p, h in expect_files.items() if p.endswith(".py")}:
        problems.append("guest ran code that differs from the code under test")
    return data, problems


def pressure(read=None):
    """Host pressure: {cpu_avg60, mem_avail_mb, free_gb}. Missing data is None, not zero."""
    read = read or (lambda p: open(p, encoding="utf-8", errors="replace").read())
    out = {"cpu_avg60": None, "mem_avail_mb": None, "free_gb": None}
    try:
        m = re.search(r"some .*?avg60=([0-9.]+)", read("/proc/pressure/cpu"))
        out["cpu_avg60"] = float(m.group(1)) if m else None
    except (OSError, ValueError):
        pass
    try:
        m = re.search(r"MemAvailable:\s+(\d+) kB", read("/proc/meminfo"))
        out["mem_avail_mb"] = int(m.group(1)) // 1024 if m else None
    except (OSError, ValueError):
        pass
    try:
        st = os.statvfs(str(ROOT if ROOT.exists() else ROOT.parent))
        out["free_gb"] = round(st.f_bavail * st.f_frsize / 1e9, 1)
    except OSError:
        pass
    return out


def blockers(cfg, load, *, docker_ok=True, image_ok=True, kvm=True, container_ok=True):
    """Reasons the lab must not start now. Unknown load blocks: never assume idle."""
    out = []
    if not docker_ok:
        out.append("docker is unavailable")
    if not container_ok:
        out.append(f"container image {cfg.container_image} is missing")
    if not image_ok:
        out.append("guest base image is missing or does not match its signed checksum")
    if not kvm:
        out.append("/dev/kvm is not present")
    if load.get("cpu_avg60") is None:
        out.append("CPU pressure is unknown")
    elif load["cpu_avg60"] > cfg.max_cpu_pressure:
        out.append(f"CPU pressure {load['cpu_avg60']:.0f}% over the last minute exceeds {cfg.max_cpu_pressure:.0f}%")
    if load.get("mem_avail_mb") is None:
        out.append("available memory is unknown")
    elif load["mem_avail_mb"] < cfg.min_avail_mb:
        out.append(f"only {load['mem_avail_mb']} MB available; need {cfg.min_avail_mb} MB")
    if load.get("free_gb") is not None and load["free_gb"] < cfg.min_free_gb:
        out.append(f"only {load['free_gb']} GB free disk; need {cfg.min_free_gb} GB")
    return out


def image_of(cfg):
    """The Image the config names, or LabError for an unknown name."""
    img = IMAGES.get(getattr(cfg, "image", DEFAULT_IMAGE))
    if img is None:
        raise LabError(f"unknown guest image {cfg.image!r}; known: {', '.join(IMAGES)}")
    return img


def verify_base_image(cfg):
    """True when the base image matches its signed checksum list (verified at download).

    Fail closed: an unknown image, a missing list, a missing entry or a mismatch is False."""
    try:
        img = image_of(cfg)
    except LabError:
        return False
    images = Path(cfg.root) / "images"
    want = Path(img.file).name
    try:
        for line in (images / img.sums).read_text().splitlines():
            digest, _, name = line.partition(" ")
            if name.strip().lstrip("*") == want:
                return _hex(images / img.file, algo=img.algo) == digest.strip().lower()
    except (OSError, ValueError):
        return False
    return False


def overlay_argv(cfg, size=None):
    """qemu-img argv for the run's copy-on-write overlay over the configured image. Pure."""
    argv = ["qemu-img", "create", "-q", "-f", "qcow2", "-b", f"/img/{image_of(cfg).file}",
            "-F", "qcow2", "/work/overlay.qcow2"]
    return tuple(argv + ([size] if size else []))


# -- orchestration -------------------------------------------------------------

def run_linux(controls, cfg=None, *, runner=subprocess.run, popen=subprocess.Popen, sleep=time.sleep,
              clock=time.monotonic, load=None, verify=verify_base_image, keep_log=True):
    """Boot the guest, run the controls inside it, return parsed evidence and a lab report."""
    cfg = cfg or Config()
    report = {"started": int(time.time()), "isolation": {}, "blocked": [], "problems": []}
    load = load if load is not None else pressure()
    report["host_load"] = load

    def ok(argv):
        try:
            return runner(argv, capture_output=True, timeout=30).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    stop = blockers(cfg, load, docker_ok=ok(["docker", "version"]),
                    container_ok=ok(["docker", "image", "inspect", cfg.container_image]),
                    image_ok=verify(cfg), kvm=os.path.exists("/dev/kvm"))
    if stop:
        report["blocked"] = stop
        return None, report
    gid = cfg.kvm_gid if cfg.kvm_gid is not None else os.stat("/dev/kvm").st_gid
    run_id = uuid.uuid4().hex[:10]
    run_dir = Path(cfg.root) / "runs" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    name = f"jvlab-{run_id}"
    data = None
    try:
        expected = build_payload(run_dir, controls)
        (run_dir / "user-data").write_text(USER_DATA)
        (run_dir / "meta-data").write_text(f"instance-id: jvlab-{run_id}\nlocal-hostname: jvlab\n")
        for argv in (("sh", "-c", "cd /work && xorriso -as mkisofs -quiet -o seed.iso -V cidata -J -r user-data meta-data"),
                     overlay_argv(cfg)):
            r = runner(helper_command(cfg, run_dir, *argv), capture_output=True, timeout=120)
            if r.returncode != 0:
                raise LabError("helper container failed: " + r.stderr.decode("utf-8", "replace")[-200:])
        proc = popen(docker_command(cfg, run_dir, name, gid), stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
        end, serial = clock() + cfg.timeout_s, run_dir / "serial.log"
        text = ""
        while clock() < end:
            sleep(2)
            try:
                text = serial.read_text(errors="replace")
            except OSError:
                text = ""
            if SHA + " " in text or proc.poll() is not None:
                break
        else:
            report["problems"].append(f"guest did not finish within {cfg.timeout_s}s")
        try:
            text = serial.read_text(errors="replace")
        except OSError:
            pass
        data, problems = parse_serial(text, expected)
        report["problems"] += problems
    except LabError as exc:
        report["problems"].append(str(exc))
    finally:
        runner(["docker", "rm", "-f", name], capture_output=True, timeout=60)
        if keep_log and (run_dir / "serial.log").exists():
            keep = Path(cfg.root) / "last-serial.log"
            shutil.copyfile(run_dir / "serial.log", keep)
            os.chmod(keep, 0o600)
        shutil.rmtree(run_dir, ignore_errors=True)
    gone = runner(["docker", "ps", "-aq", "--filter", f"name={name}"], capture_output=True, timeout=30)
    report["isolation"] = {
        "container_removed": gone.returncode == 0 and not gone.stdout.strip(),
        "run_dir_removed": not run_dir.exists(),
        "base_image_unchanged": bool(verify(cfg)),
        "network": "none (container) + restricted user-mode NIC (guest)",
        "privileges": "non-root, no capabilities, only /dev/kvm",
    }
    return data, report
