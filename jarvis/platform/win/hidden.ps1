
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.wmi      = @(Get-CimInstance Win32_Process | ForEach-Object {
                  [pscustomobject]@{ pid=$_.ProcessId; name=$_.Name; path=$_.ExecutablePath } })
$o.api      = @(Get-Process | ForEach-Object {
                  [pscustomobject]@{ pid=$_.Id; name=$_.ProcessName; path=$_.Path;
                                     title=$_.MainWindowTitle } })
$o.tasklist = @((tasklist /fo csv /nh 2>$null) -split "`n" | Where-Object { $_ -match '^"' } |
                  ForEach-Object { $p = $_ -split '","'
                                   [pscustomobject]@{ name=$p[0].Trim('"'); pid=[int]($p[1]) } })
# TimeWait/Closed rows outlive their owner and keep its stale pid.
$o.netpids  = @((Get-NetTCPConnection | Where-Object { $_.State -notin 'TimeWait','Closed' }).OwningProcess |
                Sort-Object -Unique)

# --- view 5: OpenProcess sweep, i.e. the PspCidTable ----------------------
# The classic way to hide a process on Windows is DKOM: unlink its EPROCESS
# from ActiveProcessLinks, which is the list every enumeration API above walks.
# The handle table (PspCidTable) is a *separate* kernel structure, and unlinking
# from one does not unlink from the other -- so a pid that opens successfully
# while appearing in none of the enumerations is the signature of that attack.
# The loop lives in C# because 16k P/Invoke calls from PowerShell would take
# minutes; Windows pids are always multiples of four, so only those are tried.
Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class PidSweep {
  const uint STILL_ACTIVE = 259;
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetExitCodeProcess(IntPtr h, out uint code);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder buf, ref uint size);

  // A pid that opens is NOT necessarily a running process. When a process
  // exits, its kernel object -- and therefore its pid -- stays valid for as
  // long as anything still holds a handle to it, so OpenProcess keeps
  // succeeding on something that is already gone. Reporting those as concealed
  // processes produced ~27 false positives on an ordinary desktop. The exit
  // code is what separates the two: a live process has none yet.
  // 0 = nothing there. 1 = confirmed running. 2 = something is there but it
  // will not let us look, so we cannot tell running from already-exited.
  // Keeping 2 separate matters: ERROR_ACCESS_DENIED is returned both by
  // protected processes and by pids we have no way to qualify, and treating it
  // as proof of a concealed process is guesswork dressed up as a critical alert.
  public static int Probe(int pid) {
    IntPtr h = OpenProcess(0x1000, false, (uint)pid);
    if (h == IntPtr.Zero) {
      return Marshal.GetLastWin32Error() == 5 ? 2 : 0;
    }
    uint code;
    bool got = GetExitCodeProcess(h, out code);
    CloseHandle(h);
    if (!got) return 2;
    return code == STILL_ACTIVE ? 1 : 0;
  }

  public static bool Alive(int pid) { return Probe(pid) == 1; }

  // A concealed process still has a backing image; a dead object has none, so
  // this doubles as a second confirmation and names the binary in the report.
  public static string Image(int pid) {
    IntPtr h = OpenProcess(0x1000, false, (uint)pid);
    if (h == IntPtr.Zero) return "";
    var sb = new StringBuilder(1024); uint n = 1024;
    string s = QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : "";
    CloseHandle(h);
    return s;
  }

  public static int[] Live(int max) {
    var found = new List<int>();
    for (uint pid = 4; pid <= (uint)max; pid += 4) {
      if (Probe((int)pid) == 1) found.Add((int)pid);
    }
    return found.ToArray();
  }
  public static int[] Opaque(int max) {
    var found = new List<int>();
    for (uint pid = 4; pid <= (uint)max; pid += 4) {
      if (Probe((int)pid) == 2) found.Add((int)pid);
    }
    return found.ToArray();
  }
}
'@

# A sweep of 16k pids takes long enough that processes start and exit while it
# runs, and either one looks exactly like a concealed process. So the sweep is
# bracketed by two enumerations and only pids missing from BOTH survive, then
# each survivor is re-opened and re-checked against a third, fresh listing. What
# is left is a pid that was continuously openable and continuously absent, which
# no amount of ordinary process churn can produce.
$before = @{}
@(Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId }) +
  @(Get-Process | ForEach-Object { $_.Id }) | ForEach-Object { $before[[int]$_] = $true }

$sweep = @()
try { $sweep = [int[]][PidSweep]::Live(65535) } catch { $sweep = @() }

$after = @{}
@(Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId }) +
  @(Get-Process | ForEach-Object { $_.Id }) | ForEach-Object { $after[[int]$_] = $true }

$cand = @($sweep | Where-Object { -not $before.ContainsKey($_) -and -not $after.ContainsKey($_) })

Start-Sleep -Milliseconds 400
$third = @{}
@(Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId }) +
  @(Get-Process | ForEach-Object { $_.Id }) +
  @((tasklist /fo csv /nh 2>$null) -split "`n" | Where-Object { $_ -match '^"' } |
      ForEach-Object { [int](($_ -split '","')[1]) }) |
  ForEach-Object { $third[[int]$_] = $true }

$o.openable = @($cand |
    Where-Object { -not $third.ContainsKey($_) -and [PidSweep]::Alive($_) } |
    ForEach-Object { [pscustomobject]@{ pid=[int]$_; image=[string][PidSweep]::Image($_) } })
$o.openableTotal = @($sweep).Count
# Pids that exist in some form but refuse inspection. Reported as a gap in
# coverage, not as a detection.
$opaque = @()
try { $opaque = [int[]][PidSweep]::Opaque(65535) } catch { $opaque = @() }
$o.opaque = @($opaque | Where-Object { -not $third.ContainsKey($_) })

# --- view 6: the thread list ----------------------------------------------
# Threads are tracked separately from processes. A process unlinked from the
# process list still has threads, and they still name their owning process.
$o.threadOwners = @((Get-CimInstance Win32_Thread |
                     Select-Object -ExpandProperty ProcessHandle) |
                    Sort-Object -Unique | ForEach-Object { [int]$_ })

# --- view 7: the performance subsystem ------------------------------------
# Perfmon reads process data through a different provider chain again.
$o.perfpids = @()
try {
  $o.perfpids = @((Get-Counter '\Process(*)\ID Process' -ErrorAction Stop).CounterSamples |
                  ForEach-Object { [int]$_.CookedValue } | Where-Object { $_ -gt 0 } |
                  Sort-Object -Unique)
} catch { $o.perfpids = @() }

# --- view 8: what the service controller thinks is running ----------------
$o.svcpids = @(Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 } |
               ForEach-Object { [int]$_.ProcessId } | Sort-Object -Unique)

# --- verification pass ------------------------------------------------------
# Views 6-8 are each a single snapshot taken at a slightly different instant
# from the enumerations they are compared against, so a process that starts or
# exits in between shows up as concealed. Every candidate is therefore re-tested
# against one final, fresh listing and re-probed for life; only a pid that is
# still running and still absent survives. Without this the scan reports a
# couple of phantom criticals per run, which is worse than reporting nothing.
$verify = @{}
@(Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId }) +
  @(Get-Process | ForEach-Object { $_.Id }) +
  @((tasklist /fo csv /nh 2>$null) -split "`n" | Where-Object { $_ -match '^"' } |
      ForEach-Object { [int](($_ -split '","')[1]) }) |
  ForEach-Object { $verify[[int]$_] = $true }

function Confirm-Ghosts($pids) {
  @($pids | Where-Object {
      $_ -gt 4 -and -not $verify.ContainsKey($_) -and [PidSweep]::Probe($_) -eq 1 } |
    ForEach-Object { [pscustomobject]@{ pid=[int]$_; image=[string][PidSweep]::Image($_) } })
}
$o.ghostThreads = Confirm-Ghosts $o.threadOwners
$o.ghostPerf    = Confirm-Ghosts $o.perfpids
$o.ghostSvc     = Confirm-Ghosts $o.svcpids
$o.ghostNet     = Confirm-Ghosts $o.netpids

# WMI and the process API were listed one after the other at the start, so a
# process that started or exited between the two reads as hidden from one of
# them -- short-lived brokers (RuntimeBroker, HxTsr) did exactly that. Each
# disagreement is asked again of both views, by pid, now; only a process one
# view still sees and the other still does not is reported.
$wmiPids = @{}; $o.wmi | ForEach-Object { $wmiPids[[int]$_.pid] = $true }
$apiPids = @{}; $o.api | ForEach-Object { $apiPids[[int]$_.pid] = $true }
function In-Wmi([int]$id) { [bool](Get-CimInstance Win32_Process -Filter "ProcessId=$id") }
function In-Api([int]$id) { [bool](Get-Process -Id $id -ErrorAction SilentlyContinue) }
$o.apiOnly = @($apiPids.Keys | Where-Object { $_ -gt 4 -and -not $wmiPids.ContainsKey($_) -and
                                              (In-Api $_) -and -not (In-Wmi $_) })
$o.wmiOnly = @($wmiPids.Keys | Where-Object { $_ -gt 4 -and -not $apiPids.ContainsKey($_) -and
                                              (In-Wmi $_) -and -not (In-Api $_) })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
