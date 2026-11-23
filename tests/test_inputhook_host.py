"""The resident input-hook host (2026-10-31), executed in Windows PowerShell 5.1.

The host's sources are compiled from the reviewed script and exercised without
installing a hook: the deafness decision, the capped output queue, the key-line
writer, and memscan's recognition of the compiled assemblies. Installing a real
hook from the unit suite would register a keyboard hook on the owner's desktop
on every run, so the end-to-end run is scripts/dev/inputhook_smoke.py.
"""

import base64
import json
import re
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from jarvis.collectors.process import assemblies

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "jarvis/platform/win/inputhook.ps1"
POWERSHELL, WSLPATH = shutil.which("powershell.exe"), shutil.which("wslpath")


def winpath(path):
    return subprocess.run([WSLPATH, "-w", str(path)], capture_output=True, text=True,
                          check=True).stdout.strip()


def ps(body, timeout=180):
    """Compile the script's three sources the way the script does, then run `body`."""
    load = (
        "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
        f"$ast=[System.Management.Automation.Language.Parser]::ParseFile('{winpath(SCRIPT)}',[ref]$null,[ref]$null);"
        "$v=@{};foreach($a in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst]},$true)){"
        " $n=$a.Left.Extent.Text; if($n -in '$src','$audioSrc','$soundSrc'){ $v[$n]=$a.Right.Expression.Value } };"
        "Add-Type -TypeDefinition $v['$src'] -ReferencedAssemblies System.Management;"
        "Add-Type -TypeDefinition $v['$audioSrc'];Add-Type -TypeDefinition $v['$soundSrc'];"
        "$np=[Reflection.BindingFlags]'NonPublic,Static';"
    )
    encoded = base64.b64encode((load + body).encode("utf-16le")).decode("ascii")
    for _attempt in range(2):
        r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                           capture_output=True, text=True, errors="replace", timeout=timeout, cwd="/")
        if "UtilAcceptVsock" not in r.stderr:
            break
        time.sleep(5)
    if r.returncode:
        raise AssertionError(r.stderr or r.stdout)
    return json.loads(r.stdout.replace("\r", "").strip().splitlines()[-1])


@unittest.skipUnless(POWERSHELL and WSLPATH, "Windows PowerShell unavailable")
class HostBehaviourTests(unittest.TestCase):
    def test_deafness_decision(self):
        # DeafStep(passes, lastInput, prevInput, lastCallback, watchable)
        r = ps("[pscustomobject]@{"
               "heard=[JarvisHost]::DeafStep(0,[uint32]10000,[uint32]9000,9500,$true);"     # callback after input
               "edge=[JarvisHost]::DeafStep(1,[uint32]12000,[uint32]11000,10000,$true);"    # exactly 2000 ms
               "deaf1=[JarvisHost]::DeafStep(0,[uint32]15000,[uint32]14000,10000,$true);"
               "deaf2=[JarvisHost]::DeafStep(1,[uint32]16000,[uint32]15000,10000,$true);"
               # the 2026-10-31 false loop: an old unseen gap, no input since
               "stale=[JarvisHost]::DeafStep(1,[uint32]15000,[uint32]15000,10000,$true);"
               "elevated=[JarvisHost]::DeafStep(3,[uint32]16000,[uint32]15000,10000,$false);"  # UAC, admin window, lock screen
               "noinput=[JarvisHost]::DeafStep(3,[uint32]0,[uint32]0,10000,$true);"
               # GetTickCount wraps after 49.7 days: input just after the wrap, callback just before it
               "wrapdeaf=[JarvisHost]::DeafStep(0,[uint32]4000,[uint32]1000,-1000,$true);"
               "wrapheard=[JarvisHost]::DeafStep(0,[uint32]4294966000,[uint32]4294965000,500,$true)"
               "}|ConvertTo-Json -Compress")
        self.assertEqual(r, {"heard": 0, "edge": 0, "deaf1": 1, "deaf2": 2, "stale": 0,
                             "elevated": 0, "noinput": 0, "wrapdeaf": 1, "wrapheard": 0})

    def test_watchdog_needs_new_input_and_resets_after_a_reinstall(self):
        text = SCRIPT.read_text(encoding="utf-8")
        wd = text.split("static void Watchdog()", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("_prevInput = li;", wd)
        self.assertIn("!ForegroundElevated()", wd)
        self.assertLess(wd.index("_deafPasses = 0;"), wd.index('Report("reinstalling"'))
        self.assertIn("_stillReported = true", wd)

    def test_output_queue_is_capped_and_drops_are_counted(self):
        r = ps("for($i=0;$i -lt 8300;$i++){ [JarvisInputHook]::WriteState('{\"n\":' + $i + '}') };"
               "[pscustomobject]@{pending=[JarvisInputHook]::Pending();cap=[JarvisInputHook]::OutCap;"
               "dropped=[JarvisInputHook]::OutDropped}|ConvertTo-Json -Compress")
        self.assertEqual(r["pending"], r["cap"])
        self.assertEqual(r["dropped"], 8300 - r["cap"])

    def test_key_lines_are_formatted_by_the_worker_with_the_owner_named(self):
        d = Path(tempfile.mkdtemp(prefix="hookhost-", dir=Path.home() / ".cache"))
        self.addCleanup(shutil.rmtree, d, True)
        out = winpath(d / "out.jsonl")
        r = ps(f"[JarvisInputHook].GetField('_out',$np).SetValue($null,'{out}');"
               "$w=[JarvisInputHook].GetMethod('Write',$np,$null,[type[]]@([string],[uint32],[string],[bool]),$null);"
               "$w.Invoke($null,@('digit-key',[uint32]0,'digit-3',$false));"
               "$w.Invoke($null,@('control-key',[uint32]0x12,'volume-up',$true));"
               "[JarvisInputHook]::WriteState('{\"kind\":\"heartbeat\"}');"
               "$n=[JarvisInputHook]::FlushOut();"
               f"[pscustomobject]@{{n=$n;pending=[JarvisInputHook]::Pending();lines=[string[]]@(Get-Content '{out}')}}|ConvertTo-Json -Compress")
        self.assertEqual((r["n"], r["pending"]), (3, 0))
        rows = [json.loads(x) for x in r["lines"]]
        self.assertEqual([x["kind"] for x in rows], ["digit-key", "control-key", "heartbeat"])
        self.assertEqual((rows[0]["class"], rows[0]["injected"], rows[0]["lower_il"]), ("digit-3", 0, 0))
        self.assertEqual((rows[1]["injected"], rows[1]["lower_il"]), (1, 1))   # 0x12 carries 0x02
        # the foreground owner is "name:pid" or empty, never a bare pid
        self.assertRegex(rows[0]["fg"], r"^($|[^:\"]+:\d+$)")

    def test_audio_read_releases_and_returns_level_and_mute(self):
        r = ps("$a=[JarvisAudio]::Read();$s=[JarvisAudio]::Sessions();"
               "[pscustomobject]@{n=$a.Count;level=$a[0];muted=$a[1];rows=@($s)}|ConvertTo-Json -Compress")
        self.assertEqual(r["n"], 2)
        self.assertTrue(0 <= r["level"] <= 100 and r["muted"] in (0, 1))
        for row in r["rows"] or []:
            self.assertRegex(row, r"^\d+\|\d{1,3}\|[01]$")


@unittest.skipUnless(POWERSHELL and WSLPATH, "Windows PowerShell unavailable")
class SharedEnumeratorTests(unittest.TestCase):
    """2026-10-31: the volume sampler and the sound listener declared separate
    [ComImport] classes for the one per-process audio enumerator; whichever ran
    second died with InvalidCastException. Both start orders must work."""

    def _run(self, audio_first):
        first = "[void][JarvisAudio]::Read();[void][JarvisAudio]::Sessions();" if audio_first else ""
        return ps(first + "[JarvisSound.Listener]::Start();Start-Sleep 3;"
                  "$a=[JarvisAudio]::Read();$c=[JarvisSound.Listener]::Counters()|ConvertFrom-Json;"
                  "[pscustomobject]@{audio=$a.Count;state=$c.state;samples=$c.samples;errors=$c.errors}"
                  "|ConvertTo-Json -Compress")

    def test_audio_sampler_first(self):
        r = self._run(True)
        self.assertEqual((r["audio"], r["state"], r["errors"]), (2, "running", 0))
        self.assertGreater(r["samples"], 0)

    def test_listener_first(self):
        r = self._run(False)
        self.assertEqual((r["audio"], r["state"], r["errors"]), (2, "running", 0))

    def test_no_comimport_class_for_the_enumerator(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"\[ComImport,\s*Guid\(\"BCDE0395-E52F-467C-8E3D-C4579291692E\"\)\]\s*class")


def _strings(path):
    """memscan's #Strings reader (jarvis/platform/win/memscan.ps1), for a PE on disk."""
    b = path.read_bytes()
    u16 = lambda o: struct.unpack_from("<H", b, o)[0]   # noqa: E731
    u32 = lambda o: struct.unpack_from("<I", b, o)[0]   # noqa: E731
    pe = u32(0x3C)

    def off(rva):
        sec = pe + 24 + u16(pe + 20)
        for i in range(u16(pe + 6)):
            s = sec + 40 * i
            if u32(s + 12) <= rva < u32(s + 12) + max(u32(s + 8), u32(s + 16)):
                return rva - u32(s + 12) + u32(s + 20)
        return -1
    dirs = pe + 24 + (112 if u16(pe + 24) == 0x20B else 96)
    md = off(u32(off(u32(dirs + 14 * 8)) + 8))
    hdr = md + 16 + u32(md + 12)
    q = hdr + 4
    for _ in range(u16(hdr + 2)):
        o, size = u32(q), u32(q + 4)
        e = b.index(b"\0", q + 8)
        if b[q + 8:e] == b"#Strings":
            return [x.decode("utf-8", "replace") for x in b[md + o + 1:md + o + size].split(b"\0") if x]
        q = (e + 4) & ~3
    return []


@unittest.skipUnless(POWERSHELL and WSLPATH, "Windows PowerShell unavailable")
class OwnAssemblyRecognitionTests(unittest.TestCase):
    """memscan rates JARVIS's own in-memory code low only if every metadata name
    is in the script; an unrecognised assembly holding SetWindowsHookEx is high."""

    def test_core_and_audio_assemblies_are_fully_explained_by_the_script(self):
        d = Path(tempfile.mkdtemp(prefix="hookmd-", dir=Path.home() / ".cache"))
        self.addCleanup(shutil.rmtree, d, True)
        w = winpath(d)
        load = (f"$ast=[System.Management.Automation.Language.Parser]::ParseFile('{winpath(SCRIPT)}',[ref]$null,[ref]$null);"
                "foreach($a in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst]},$true)){"
                " $n=$a.Left.Extent.Text.TrimStart('$'); if($n -notin 'src','audioSrc'){ continue };"
                f" $o='{w}\\'+$n+'.dll';"
                " if($n -eq 'src'){ Add-Type -TypeDefinition $a.Right.Expression.Value -ReferencedAssemblies System.Management -OutputAssembly $o -OutputType Library }"
                " else { Add-Type -TypeDefinition $a.Right.Expression.Value -OutputAssembly $o -OutputType Library } };'{}'")
        r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand",
                            base64.b64encode(load.encode("utf-16le")).decode()],
                           capture_output=True, text=True, timeout=180, cwd="/")
        self.assertEqual(r.returncode, 0, r.stderr)
        assemblies._CACHE.pop("inputhook.ps1", None)
        idents, compiles, _ = assemblies._script_facts("inputhook.ps1")
        self.assertEqual(compiles, 3)
        for name in ("src.dll", "audioSrc.dll"):
            strings = _strings(d / name)
            self.assertGreater(len(strings), 50, name)
            self.assertEqual(assemblies.unexplained(strings, name, idents), [], name)


class HostSourceInvariants(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text(encoding="utf-8")

    def _body(self, signature):
        return self.text.split(signature, 1)[1].split("\n    }\n", 1)[0]

    def test_no_winforms_and_no_script_after_run(self):
        code = "\n".join(l for l in self.text.splitlines() if not l.lstrip().startswith(("#", "//")))
        self.assertNotIn("System.Windows.Forms", code)
        self.assertNotIn("Add_Tick", code)
        self.assertNotIn("[powershell]::Create()", code)
        self.assertEqual(self.text.rstrip().splitlines()[-1], "[JarvisHost]::Run($OutFile, $HeartbeatSeconds)")

    def test_hook_callbacks_do_no_io_and_no_process_lookups(self):
        for sig in ("static IntPtr KbProc(", "static IntPtr MsProc(", "static void Write(string kind, uint flags, string cls, bool injected)"):
            body = self._body(sig)
            for banned in ("File.", "Process.", "Foreground()", "WriteState(", "Thread.Sleep"):
                self.assertNotIn(banned, body, f"{sig} uses {banned}")

    def test_hook_thread_loop_only_pumps_and_answers(self):
        loop = self.text.split("while (GetMessage(out m, IntPtr.Zero, 0, 0) > 0) {", 1)[1].split("\n        }\n", 1)[0]
        self.assertIn("WM_APP_PING", loop)
        self.assertIn("JarvisInputHook.Reinstall()", loop)
        self.assertNotIn("Process.", loop)
        self.assertNotIn("File.", loop)

    def test_pulse_requires_a_live_hook_thread(self):
        self.assertIn("Volatile.Read(ref _pongTick) > PongStaleMs) return;", self._body("static void Pulse()"))

    def test_every_worker_task_is_isolated(self):
        worker = self._body("static void Worker()")
        calls = re.findall(r"\b(Sample\w+|DrainSound|Watchdog|Heartbeat|Pulse|Flush|JarvisInputHook\.PumpInjected)\b", worker)
        self.assertTrue(calls)
        for name in set(calls):
            self.assertIn(f", {name})", worker, name)        # only ever passed to Step("...", name)

    def test_no_compiler_generated_names(self):
        src = self.text
        self.assertNotIn("=>", src)
        self.assertNotIn(".Values", src)
        self.assertNotIn(".Keys)", src)


if __name__ == "__main__":
    unittest.main()
