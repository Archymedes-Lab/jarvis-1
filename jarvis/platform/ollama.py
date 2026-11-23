"""Download and install Ollama (the local model runtime) with the user's approval.

Argus-1's local-model features (open questions, plan notes, voice) need Ollama
on 127.0.0.1:11434. This module plans, downloads, verifies and installs it;
`jarvis model install` shows the plan and acts only on a person's approval.
Nothing here runs from the daemon or the web pages: installing software is the
owner's decision, every time.

    plan       newest Ollama release at least MIN_AGE_DAYS old (a compromised
               release is usually caught within days), the file for this
               platform, its size, and its SHA-256, which GitHub's digest and
               Ollama's own sha256sum.txt must agree on
    download   HTTPS to GitHub's release hosts only, redirects included, never
               past the published size; the bytes must match the SHA-256, or
               the file is deleted
    install    Windows: Ollama's own per-user installer, run only with a valid
               Authenticode signature by Ollama. Linux: unpacked under the
               user's home with a user service on loopback; no root, nothing
               system-wide
    uninstall  the reverse of each

Both checksums come from the same GitHub release, so they prove the download
is the file Ollama published there, not that the release itself is honest.
The age rule and, on Windows, the code signature are the defence against that.
"""

import calendar
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

RELEASES = "https://api.github.com/repos/ollama/ollama/releases?per_page=30"
MIN_AGE_DAYS = 7
HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
         "api.github.com"}
SIGNER = "Ollama"                       # Authenticode subject must name the publisher
CHUNK = 1 << 20
TIMEOUT_S = 60
LOOPBACK = "127.0.0.1:11434"


class InstallError(RuntimeError):
    pass


def asset_name(system, machine):
    """The release file for this platform, or None when Ollama ships none."""
    system, machine = system.lower(), machine.lower()
    if system == "windows" and machine in ("amd64", "x86_64"):
        return "OllamaSetup.exe"
    if system == "linux":
        return {"x86_64": "ollama-linux-amd64.tar.zst", "amd64": "ollama-linux-amd64.tar.zst",
                "aarch64": "ollama-linux-arm64.tar.zst", "arm64": "ollama-linux-arm64.tar.zst"}.get(machine)
    return None


def _published(rel):
    try:
        return calendar.timegm(time.strptime(rel.get("published_at") or "", "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, OverflowError):
        return None


def choose_release(releases, now=None, min_age_days=MIN_AGE_DAYS):
    """Newest published, non-prerelease release at least `min_age_days` old."""
    now = time.time() if now is None else now
    ok = [r for r in releases if isinstance(r, dict) and not r.get("draft") and not r.get("prerelease")
          and _published(r) is not None and now - _published(r) >= min_age_days * 86400]
    return max(ok, key=_published) if ok else None


def parse_sums(text):
    """sha256sum.txt -> {file name: sha256}."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(?:\./)?(\S+)\s*$", line.strip())
        if m:
            out[m.group(2)] = m.group(1).lower()
    return out


def allowed_url(url):
    parts = urlsplit(url or "")
    return (parts.scheme == "https" and parts.hostname in HOSTS and not parts.username
            and not parts.password and parts.port in (None, 443))


@dataclass
class Plan:
    target: str
    version: str = ""
    published: str = ""
    asset: str = ""
    url: str = ""
    size: int = 0
    sha256: str = ""
    problems: list = field(default_factory=list)

    def describe(self):
        if self.problems:
            return "Ollama cannot be installed safely right now:\n" + "\n".join(f"  - {p}" for p in self.problems)
        where = ("Ollama's own installer, for your Windows user (no administrator rights)"
                 if self.target == "windows" else
                 "under your home folder with a user service on 127.0.0.1 only (no root)")
        return (f"Install Ollama {self.version} (published {self.published}, at least "
                f"{MIN_AGE_DAYS} days old)\n"
                f"  file     {self.asset}, {self.size / 1e9:.2f} GB\n"
                f"  from     {self.url}\n"
                f"  sha256   {self.sha256} (GitHub and Ollama's sha256sum.txt agree)\n"
                f"  install  {where}\n"
                f"  checks   the download must match that SHA-256"
                + (", and the installer must carry a valid code signature by Ollama" if self.target == "windows" else "")
                + "\n  undo     jarvis model uninstall")


def make_plan(rel, sums_text, target, machine):
    plan = Plan(target=target)
    if not rel:
        plan.problems.append(f"no Ollama release is at least {MIN_AGE_DAYS} days old yet")
        return plan
    plan.version, plan.published = rel.get("tag_name", ""), rel.get("published_at", "")
    name = asset_name(target, machine)
    if not name:
        plan.problems.append(f"Ollama publishes no build for {target} on {machine}")
        return plan
    found = next((a for a in rel.get("assets") or [] if a.get("name") == name), None)
    if not found:
        plan.problems.append(f"release {plan.version} has no {name}")
        return plan
    plan.asset, plan.url, plan.size = name, found.get("browser_download_url", ""), int(found.get("size") or 0)
    if not allowed_url(plan.url) or urlsplit(plan.url).hostname != "github.com":
        plan.problems.append(f"the download address is not on github.com over HTTPS: {plan.url}")
    digest = str(found.get("digest") or "")
    github = digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else ""
    listed = parse_sums(sums_text).get(name, "")
    if not github:
        plan.problems.append(f"GitHub publishes no SHA-256 digest for {name}")
    if not listed:
        plan.problems.append(f"Ollama's sha256sum.txt does not list {name}")
    if github and listed and github != listed:
        plan.problems.append(f"GitHub's digest and Ollama's sha256sum.txt disagree for {name}")
    plan.sha256 = github if github and github == listed else ""
    if plan.size <= 0:
        plan.problems.append(f"{name} has no published size")
    return plan


class _GitHubOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl):
            raise InstallError(f"refused a redirect off GitHub's release hosts: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url, timeout=TIMEOUT_S):
    if not allowed_url(url):
        raise InstallError(f"refused: {url} is not a GitHub release address over HTTPS")
    opener = urllib.request.build_opener(_GitHubOnly)
    req = urllib.request.Request(url, headers={"User-Agent": "argus-1-model-installer",
                                               "Accept": "application/octet-stream, application/json"})
    return opener.open(req, timeout=timeout)


def fetch_json(url=RELEASES, opener=_open):
    with opener(url) as r:
        return json.loads(r.read(4 << 20).decode("utf-8"))


def fetch_text(url, opener=_open, limit=1 << 20):
    with opener(url) as r:
        return r.read(limit).decode("utf-8", "replace")


def download(url, dest, size, sha256, opener=_open, progress=None):
    """Stream `url` to `dest`; keep it only if it is exactly `size` bytes hashing to `sha256`."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    h, got = hashlib.sha256(), 0
    try:
        with opener(url) as r, open(part, "wb") as out:
            while True:
                block = r.read(CHUNK)
                if not block:
                    break
                got += len(block)
                if got > size:
                    raise InstallError(f"{dest.name} is larger than its published {size} bytes")
                h.update(block)
                out.write(block)
                if progress:
                    progress(got, size)
        if got != size:
            raise InstallError(f"{dest.name}: received {got} of {size} bytes")
        if h.hexdigest() != sha256:
            raise InstallError(f"{dest.name} does not match its published SHA-256; it was deleted")
        os.replace(part, dest)
        return dest
    except BaseException:
        for p in (part, dest):
            try:
                p.unlink()
            except OSError:
                pass
        raise


# ── Windows ─────────────────────────────────────────────────────────────────

def signature_problem(sig):
    """'' when the Authenticode result is a valid signature by Ollama."""
    if not isinstance(sig, dict):
        return "the installer's code signature could not be read"
    if sig.get("status") != "Valid":
        return f"the installer's code signature is {sig.get('status') or 'missing'}, not Valid"
    if SIGNER.lower() not in str(sig.get("subject") or "").lower():
        return f"the installer is signed by {sig.get('subject')!r}, not by {SIGNER}"
    return ""


def _ps_literal(text):
    return "'" + str(text).replace("'", "''") + "'"


def windows_install_script(installer):
    """PowerShell that checks the signature, then runs Ollama's per-user installer."""
    path = _ps_literal(installer)
    return ("$ErrorActionPreference='Stop';"
            f"$s=Get-AuthenticodeSignature -LiteralPath {path};"
            "$o=@{status=[string]$s.Status;subject=[string]$s.SignerCertificate.Subject;exit=$null};"
            f"if($o.status -eq 'Valid' -and $o.subject -match {_ps_literal(SIGNER)}){{"
            f"$p=Start-Process -FilePath {path} -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' "
            "-Wait -PassThru;$o.exit=$p.ExitCode};"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o|ConvertTo-Json -Compress)))")


def windows_uninstall_script():
    return ("$ErrorActionPreference='Stop';"
            "$u=Join-Path $env:LOCALAPPDATA 'Programs\\Ollama\\unins000.exe';"
            "$o=@{found=(Test-Path -LiteralPath $u);exit=$null};"
            "if($o.found){$p=Start-Process -FilePath $u -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES' "
            "-Wait -PassThru;$o.exit=$p.ExitCode};"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o|ConvertTo-Json -Compress)))")


# ── Linux ───────────────────────────────────────────────────────────────────

def linux_paths(home, version):
    root = Path(home) / ".local" / "share" / "argus" / "ollama"
    return {"root": root, "version": root / version, "current": root / "current",
            "unit": Path(home) / ".config" / "systemd" / "user" / "ollama.service",
            "link": Path(home) / ".local" / "bin" / "ollama"}


def linux_unit(current):
    return ("[Unit]\nDescription=Ollama local model runtime for ARGUS-1 (installed by `jarvis model install`)\n"
            "After=network-online.target\n\n[Service]\n"
            f"ExecStart={current}/bin/ollama serve\n"
            f"Environment=OLLAMA_HOST={LOOPBACK}\n"
            "Restart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n")


def _run(argv, timeout=600):
    r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout)
    if r.returncode:
        raise InstallError(f"{' '.join(argv[:3])} failed: {(r.stderr or r.stdout).strip()[-300:]}")
    return r.stdout


def linux_install(archive, version, home=None, run=_run):
    home = Path(home or Path.home())
    paths = linux_paths(home, version)
    if not (shutil.which("unzstd") or shutil.which("zstd")):
        raise InstallError("the zstd tool is needed to unpack Ollama (for example: sudo apt install zstd)")
    if paths["version"].exists():
        shutil.rmtree(paths["version"])
    paths["version"].mkdir(parents=True)
    run(["tar", "--use-compress-program=unzstd", "-xf", str(archive), "-C", str(paths["version"]),
         "--no-same-owner", "--no-same-permissions"])
    if not (paths["version"] / "bin" / "ollama").is_file():
        raise InstallError("the archive did not contain bin/ollama")
    tmp = paths["current"].with_name("current.new")
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    tmp.symlink_to(paths["version"])
    os.replace(tmp, paths["current"])
    paths["link"].parent.mkdir(parents=True, exist_ok=True)
    if paths["link"].is_symlink() or not paths["link"].exists():
        if paths["link"].is_symlink():
            paths["link"].unlink()
        paths["link"].symlink_to(paths["current"] / "bin" / "ollama")
    paths["unit"].parent.mkdir(parents=True, exist_ok=True)
    paths["unit"].write_text(linux_unit(paths["current"]))
    run(["systemctl", "--user", "daemon-reload"])
    run(["systemctl", "--user", "enable", "--now", "ollama.service"])
    return paths


def linux_uninstall(home=None, run=_run):
    home = Path(home or Path.home())
    paths = linux_paths(home, "x")
    if paths["unit"].exists():
        run(["systemctl", "--user", "disable", "--now", "ollama.service"])
        paths["unit"].unlink()
        run(["systemctl", "--user", "daemon-reload"])
    if paths["link"].is_symlink():
        paths["link"].unlink()
    if paths["root"].exists():
        shutil.rmtree(paths["root"])
    return paths["root"]


def install(plan, file, home=None):
    """Install the verified `file`. Windows runs through the interop/host bridge."""
    if plan.target == "linux":
        return linux_install(file, plan.version, home)
    from jarvis.platform import host
    from jarvis.platform import windows as win
    script = windows_install_script(host.windows_name(str(file)) if host.on_wsl() else str(file))
    result = win.ps_json(script, timeout=1800)
    problem = signature_problem(result)
    if problem:
        raise InstallError(problem + "; the installer was not run")
    if (result or {}).get("exit") != 0:
        raise InstallError(f"Ollama's installer exited with {(result or {}).get('exit')}")
    return result


def uninstall(target, home=None):
    if target == "linux":
        return linux_uninstall(home)
    from jarvis.platform import windows as win
    return win.ps_json(windows_uninstall_script(), timeout=900)
