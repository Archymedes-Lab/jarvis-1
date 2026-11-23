# Who called Beep()? Elevated broker job.
#
# Beep() opens \Device\Beep, sends one IOCTL and holds the handle while the
# tone plays; the Windows sound service plays it in the shared system-sounds
# session, so audio metadata never names the caller. The unelevated listener in
# inputhook.ps1 snapshots the handle table at the tone's onset, which names
# callers of tones of 120 ms or more (6/6, 2026-10-23) but misses shorter ones:
# a 50-100 ms tone is over before the ~35 ms scan runs (2026-11-03: 0 of 6
# short test tones named, and four real double 50 ms tones since 10-29 never
# named). It also cannot look inside elevated processes.
#
# Windows' Microsoft-Windows-Kernel-File provider logs every file open as
# event 12 (Create), with the device or file name and, in the event header,
# the process that opened it. This job keeps one trace session of that event
# running between broker runs ("JarvisBeepTrace", to a file in this
# admin-only folder), filtered in the kernel to opens of \Device\Beep only:
# an event-id filter (12) plus a payload filter on FileName. It changes no
# system setting; the session ends at reboot, so opens between boot and the
# first run after it are not seen, and that gap is reported.
#
# The filter is checked, not trusted (it is not documented for every
# kernel-mode provider):
#   * fail-fast: two seconds after the session starts, a flushed file over
#     $BreachBytes means the filter is not applied; the session is stopped and
#     the job reports "refused". The file is capped at $CapMB either way.
#   * every parsed event whose FileName is not \Device\Beep is counted as a
#     breach and dropped.
#   * a silent canary: right after the session starts, this job opens and
#     closes \Device\Beep itself, sending no IOCTL, so nothing plays. The next
#     run must find that open in the trace; if not, the trace is blind and
#     the job says so.
#
# Each run: stop the session (closing its file), start a fresh one with the
# canary, parse the closed file(s), name each opener as it was at the time
# (the live process if it started before the open, else Sysmon's process
# creation), keep a rolling 24 h inventory of at most $MaxRows opens, and
# print it as base64 JSON. It keeps process ids, image paths, start times,
# user and signer status. Never command lines, window titles or audio.

$ErrorActionPreference = 'Stop'
$Name = 'JarvisBeepTrace'
$Dir = Join-Path $env:ProgramData 'Jarvis\Broker\beeptrace'
$Etl = Join-Path $Dir 'session.etl'
$Inv = Join-Path $Dir 'inventory.json'
$Provider = [Guid]'edd08927-9cc4-4e65-b970-c2560fb5c289'   # Microsoft-Windows-Kernel-File
$CreateKeyword = 0x80                                         # KERNEL_FILE_KEYWORD_CREATE
$CreateEventId = 12
$BeepDevice = '\Device\Beep'
$CapMB = 4
$BreachBytes = 1MB
$FailFastSec = 2
$MaxPending = 3
$MaxRows = 500
$KeepSec = 24 * 3600
$PidsPerQuery = 20
$clock = [Diagnostics.Stopwatch]::StartNew()

$traceSrc = @'
using System;
using System.Runtime.InteropServices;
public static class JarvisBeepTrace {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern uint StartTraceW(out ulong handle, string name, IntPtr properties);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern uint ControlTraceW(ulong handle, string name, IntPtr properties, uint code);
    [DllImport("advapi32.dll")]
    static extern uint EnableTraceEx2(ulong handle, ref Guid provider, uint control, byte level,
                                      ulong matchAny, ulong matchAll, uint timeout, IntPtr parameters);
    [DllImport("tdh.dll")]
    static extern uint TdhEnumerateManifestProviderEvents(ref Guid provider, IntPtr buffer, ref uint size);
    [DllImport("tdh.dll")]
    static extern uint TdhCreatePayloadFilter(ref Guid provider, IntPtr descriptor, byte matchAny,
                                              uint count, IntPtr predicates, out IntPtr filter);
    [DllImport("tdh.dll")]
    static extern uint TdhAggregatePayloadFilters(uint count, IntPtr[] filters, byte[] matchAll, IntPtr descriptor);
    [DllImport("tdh.dll")]
    static extern uint TdhCleanupPayloadEventFilterDescriptor(IntPtr descriptor);
    [DllImport("tdh.dll")]
    static extern uint TdhDeletePayloadFilter(ref IntPtr filter);
    [DllImport("ntdll.dll")]
    static extern int NtCreateFile(out IntPtr handle, uint access, ref ObjectAttributes attributes,
                                   out IoStatusBlock status, IntPtr allocation, uint fileAttributes,
                                   uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
    [DllImport("ntdll.dll")] static extern int NtClose(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes {
        public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes;
        public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoStatusBlock { public IntPtr Status; public IntPtr Information; }

    // EVENT_TRACE_PROPERTIES (x64): 120 bytes, then the two names.
    const int PropsSize = 120, NameChars = 1024;
    const int LoggerNameAt = PropsSize, LogFileNameAt = PropsSize + NameChars * 2;
    const int TotalSize = PropsSize + NameChars * 4;
    const uint TracedGuid = 0x00020000, Sequential = 0x1;
    const uint Query = 0, Stop = 1, Flush = 3;
    const uint EventIdFilter = 0x80000200, PayloadFilter = 0x80000100;
    const ushort PayloadIs = 30, PayloadEq = 0;     // PAYLOAD_OPERATOR: string IS, numeric EQ
    public const uint AlreadyExists = 183, NotFound = 4201, AccessDenied = 5;

    static IntPtr Props(string name, string file, uint capMB) {
        IntPtr p = Marshal.AllocHGlobal(TotalSize);
        for (int i = 0; i < TotalSize; i++) Marshal.WriteByte(p, i, 0);
        Marshal.WriteInt32(p, 0, TotalSize);                  // Wnode.BufferSize
        Marshal.WriteInt32(p, 40, 1);                         // Wnode.ClientContext: QPC clock
        Marshal.WriteInt32(p, 44, unchecked((int)TracedGuid)); // Wnode.Flags
        Marshal.WriteInt32(p, 48, 16);                        // BufferSize, KB
        Marshal.WriteInt32(p, 52, 2);                         // MinimumBuffers
        Marshal.WriteInt32(p, 56, 4);                         // MaximumBuffers
        Marshal.WriteInt32(p, 60, (int)capMB);                // MaximumFileSize, MB
        Marshal.WriteInt32(p, 64, (int)Sequential);           // LogFileMode
        Marshal.WriteInt32(p, 68, 1);                         // FlushTimer, s
        Marshal.WriteInt32(p, 112, LogFileNameAt);
        Marshal.WriteInt32(p, 116, LoggerNameAt);
        if (name != null) WriteName(p, LoggerNameAt, name);
        if (file != null) WriteName(p, LogFileNameAt, file);
        return p;
    }

    static void WriteName(IntPtr p, int at, string text) {
        if (text.Length >= NameChars) throw new ArgumentException("name too long");
        char[] chars = text.ToCharArray();
        Marshal.Copy(chars, 0, new IntPtr(p.ToInt64() + at), chars.Length);
    }

    // 0 when running; otherwise the Win32 error (4201: no such session).
    public static uint QueryStatus(string name) {
        IntPtr p = Props(null, null, 0);
        try { return ControlTraceW(0, name, p, Query); } finally { Marshal.FreeHGlobal(p); }
    }

    public static uint StopSession(string name) {
        IntPtr p = Props(null, null, 0);
        try { return ControlTraceW(0, name, p, Stop); } finally { Marshal.FreeHGlobal(p); }
    }

    public static uint FlushSession(string name) {
        IntPtr p = Props(null, null, 0);
        try { return ControlTraceW(0, name, p, Flush); } finally { Marshal.FreeHGlobal(p); }
    }

    // Exact descriptors of every version of one event id, from the manifest.
    static byte[][] Descriptors(Guid provider, ushort id) {
        uint size = 0;
        uint rc = TdhEnumerateManifestProviderEvents(ref provider, IntPtr.Zero, ref size);
        if (rc != 122 || size == 0) throw new InvalidOperationException("manifest events: " + rc);
        IntPtr buf = Marshal.AllocHGlobal((int)size);
        try {
            rc = TdhEnumerateManifestProviderEvents(ref provider, buf, ref size);
            if (rc != 0) throw new InvalidOperationException("manifest events: " + rc);
            int count = Marshal.ReadInt32(buf);
            var found = new System.Collections.Generic.List<byte[]>();
            for (int i = 0; i < count; i++) {
                IntPtr d = new IntPtr(buf.ToInt64() + 8 + i * 16);
                if ((ushort)Marshal.ReadInt16(d) != id) continue;
                byte[] copy = new byte[16];
                Marshal.Copy(d, copy, 0, 16);
                found.Add(copy);
            }
            return found.ToArray();
        } finally { Marshal.FreeHGlobal(buf); }
    }

    static IntPtr PayloadFor(Guid provider, byte[] descriptor, string field, string value, ushort op) {
        IntPtr d = Marshal.AllocHGlobal(16);
        IntPtr fieldText = Marshal.StringToHGlobalUni(field);
        IntPtr valueText = Marshal.StringToHGlobalUni(value);
        IntPtr pred = Marshal.AllocHGlobal(24);       // PAYLOAD_FILTER_PREDICATE (x64)
        try {
            Marshal.Copy(descriptor, 0, d, 16);
            for (int i = 0; i < 24; i++) Marshal.WriteByte(pred, i, 0);
            Marshal.WriteIntPtr(pred, 0, fieldText);
            Marshal.WriteInt16(pred, 8, (short)op);
            Marshal.WriteIntPtr(pred, 16, valueText);
            IntPtr filter;
            uint rc = TdhCreatePayloadFilter(ref provider, d, 1, 1, pred, out filter);
            return rc == 0 ? filter : IntPtr.Zero;
        } finally {
            Marshal.FreeHGlobal(d); Marshal.FreeHGlobal(fieldText);
            Marshal.FreeHGlobal(valueText); Marshal.FreeHGlobal(pred);
        }
    }

    // Starts the session with both filters. Returns "" or why it did not.
    public static string Start(string name, string file, uint capMB, Guid provider, ulong keyword,
                               ushort eventId, string field, string value) {
        byte[][] descriptors = Descriptors(provider, eventId);
        if (descriptors.Length == 0) return "the provider manifest has no event " + eventId;
        var filters = new System.Collections.Generic.List<IntPtr>();
        string op = "is";
        foreach (byte[] d in descriptors) {
            IntPtr f = PayloadFor(provider, d, field, value, PayloadIs);
            if (f == IntPtr.Zero) { f = PayloadFor(provider, d, field, value, PayloadEq); op = "eq"; }
            if (f == IntPtr.Zero) {
                foreach (IntPtr g in filters) { IntPtr h = g; TdhDeletePayloadFilter(ref h); }
                return "the payload filter on " + field + " could not be built";
            }
            filters.Add(f);
        }
        IntPtr payloadDesc = Marshal.AllocHGlobal(16);
        IntPtr idFilter = Marshal.AllocHGlobal(8);
        IntPtr descs = Marshal.AllocHGlobal(32);
        IntPtr parameters = Marshal.AllocHGlobal(48);
        IntPtr props = Props(name, file, capMB);
        bool payloadBuilt = false;
        try {
            byte[] all = new byte[filters.Count];
            for (int i = 0; i < all.Length; i++) all[i] = 1;
            uint rc = TdhAggregatePayloadFilters((uint)filters.Count, filters.ToArray(), all, payloadDesc);
            if (rc != 0) return "the payload filters could not be combined (" + rc + ")";
            payloadBuilt = true;
            // EVENT_FILTER_EVENT_ID: FilterIn=1, Reserved, Count=1, Events[0]=id.
            for (int i = 0; i < 8; i++) Marshal.WriteByte(idFilter, i, 0);
            Marshal.WriteByte(idFilter, 0, 1);
            Marshal.WriteInt16(idFilter, 2, 1);
            Marshal.WriteInt16(idFilter, 4, (short)eventId);
            // Two EVENT_FILTER_DESCRIPTORs: the event id filter, then the payload filter.
            Marshal.WriteInt64(descs, 0, idFilter.ToInt64());
            Marshal.WriteInt32(descs, 8, 6);
            Marshal.WriteInt32(descs, 12, unchecked((int)EventIdFilter));
            Marshal.WriteInt64(descs, 16, Marshal.ReadInt64(payloadDesc, 0));
            Marshal.WriteInt32(descs, 24, Marshal.ReadInt32(payloadDesc, 8));
            Marshal.WriteInt32(descs, 28, unchecked((int)PayloadFilter));
            // ENABLE_TRACE_PARAMETERS version 2 (x64): filters at 32, count at 40.
            for (int i = 0; i < 48; i++) Marshal.WriteByte(parameters, i, 0);
            Marshal.WriteInt32(parameters, 0, 2);
            Marshal.WriteInt64(parameters, 32, descs.ToInt64());
            Marshal.WriteInt32(parameters, 40, 2);

            ulong handle;
            rc = StartTraceW(out handle, name, props);
            if (rc != 0) return "the trace session could not start (" + rc + ")";
            rc = EnableTraceEx2(handle, ref provider, 1, 4, keyword, 0, 0, parameters);
            if (rc != 0) {
                StopSession(name);
                return "the filtered provider could not be enabled (" + rc + ")";
            }
            return "";
        } finally {
            if (payloadBuilt) TdhCleanupPayloadEventFilterDescriptor(payloadDesc);
            foreach (IntPtr g in filters) { IntPtr h = g; TdhDeletePayloadFilter(ref h); }
            Marshal.FreeHGlobal(payloadDesc); Marshal.FreeHGlobal(idFilter);
            Marshal.FreeHGlobal(descs); Marshal.FreeHGlobal(parameters); Marshal.FreeHGlobal(props);
            LastOp = op;
        }
    }
    public static string LastOp = "";

    // Open and close \Device\Beep the way Beep() does, but send no IOCTL:
    // nothing plays. Returns 0 (STATUS_SUCCESS) or the NTSTATUS.
    public static int Canary() {
        IntPtr text = Marshal.StringToHGlobalUni(@"\Device\Beep");
        IntPtr name = Marshal.AllocHGlobal(16);
        try {
            var us = new UnicodeString();
            us.Length = (ushort)(@"\Device\Beep".Length * 2);
            us.MaximumLength = (ushort)(us.Length + 2);
            us.Buffer = text;
            Marshal.StructureToPtr(us, name, false);
            var oa = new ObjectAttributes();
            oa.Length = Marshal.SizeOf(typeof(ObjectAttributes));
            oa.ObjectName = name;
            oa.Attributes = 0x40;           // OBJ_CASE_INSENSITIVE
            IntPtr handle; IoStatusBlock io;
            // FILE_READ_DATA|FILE_WRITE_DATA, share read|write, FILE_OPEN.
            int status = NtCreateFile(out handle, 0x3, ref oa, out io, IntPtr.Zero, 0, 3, 1, 0, IntPtr.Zero, 0);
            if (status == 0) NtClose(handle);
            return status;
        } finally { Marshal.FreeHGlobal(name); Marshal.FreeHGlobal(text); }
    }
}
'@

function Unix([datetime]$t) { [DateTimeOffset]::new($t.ToUniversalTime()).ToUnixTimeSeconds() }
function UnixMs([datetime]$t) { [DateTimeOffset]::new($t.ToUniversalTime()).ToUnixTimeMilliseconds() }

function Read-Data($e) {
    $d = @{}
    foreach ($x in @(([xml]$e.ToXml()).Event.EventData.Data)) { if ($x) { $d[[string]$x.Name] = [string]$x.'#text' } }
    return $d
}

function Read-Open($e, [string]$device) {
    # One trace event as @{ beep; pid; ms }. beep is $false for any other file:
    # an event the kernel filter should have dropped.
    $d = Read-Data $e
    return @{ beep = ([string]$d['FileName'] -eq $device); pid = [int]$e.ProcessId
              ms = (UnixMs $e.TimeCreated); when = $e.TimeCreated }
}

function Test-Canary($state, [object[]]$opens) {
    # Did the previous run's own silent open of the device reach the trace?
    # $null when there was no canary to check.
    $c = $state.canary
    if (-not $c -or -not [int64]$c.ms) { return $null }
    foreach ($o in @($opens)) {
        if ($o.pid -eq [int]$c.pid -and [math]::Abs([int64]$o.ms - [int64]$c.ms) -le 10000) { return $true }
    }
    return $false
}

function Merge-Rows([object[]]$old, [object[]]$new, [int64]$nowMs, [int64]$keepMs, [int]$max) {
    # Newest $max rows of the last $keepMs; a row is pid+ms, so a re-parsed
    # file never doubles a row. Returns @{ rows; dropped }.
    $byKey = @{}
    foreach ($r in @($old) + @($new)) {
        if (-not $r) { continue }
        if ($nowMs - [int64]$r.ms -gt $keepMs) { continue }
        $byKey["$($r.pid)|$($r.ms)"] = $r
    }
    $rows = @($byKey.Values | Sort-Object { [int64]$_.ms } -Descending)
    $dropped = [Math]::Max(0, $rows.Count - $max)
    if ($rows.Count -gt $max) { $rows = $rows[0..($max - 1)] }
    return @{ rows = @($rows | Sort-Object { [int64]$_.ms }); dropped = $dropped }
}

function Find-Creator([object[]]$creates, [datetime]$when) {
    # The newest creation of this id at or before the open; a later one is a
    # reuse of the id, not the caller.
    $best = $null
    foreach ($c in @($creates)) {
        if ($c.time -le $when.AddSeconds(1) -and (-not $best -or $c.time -gt $best.time)) { $best = $c }
    }
    return $best
}

function Sysmon-Creates([int[]]$procIds, [int]$chunk) {
    $map = @{}; $failed = 0
    $ids = @($procIds | Sort-Object -Unique)
    for ($i = 0; $i -lt $ids.Count; $i += $chunk) {
        $part = @($ids[$i..([Math]::Min($i + $chunk, $ids.Count) - 1)])
        $or = ($part | ForEach-Object { "Data[@Name='ProcessId']='$_'" }) -join ' or '
        $xp = "*[System[EventID=1]] and *[EventData[$or]]"
        try {
            Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $xp -ErrorAction Stop | ForEach-Object {
                $d = Read-Data $_
                $p = 0
                if (-not [int]::TryParse($d['ProcessId'], [ref]$p)) { return }
                if (-not $map.ContainsKey($p)) { $map[$p] = New-Object System.Collections.ArrayList }
                [void]$map[$p].Add(@{ time = $_.TimeCreated; image = $d['Image']; user = $d['User'] })
            }
        } catch { if ($_.Exception.Message -notmatch 'No events') { $failed++ } }
    }
    return @{ map = $map; failed = $failed }
}

$sigCache = @{}
function Signer([string]$path) {
    if (-not $path) { return @{ status = 'unknown'; signer = '' } }
    if (-not $sigCache.ContainsKey($path)) {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $path
            $cn = if ($s.SignerCertificate) { ($s.SignerCertificate.Subject -replace '^.*?CN=("?)([^,"]+)\1.*$', '$2') } else { '' }
            $sigCache[$path] = @{ status = [string]$s.Status; signer = $cn }
        } catch { $sigCache[$path] = @{ status = 'unreadable'; signer = '' } }
    }
    return $sigCache[$path]
}

function Add-Pending([string]$dir, [string]$path) {
    # A closed trace is never deleted unparsed: it waits under a name that sorts by age.
    if (-not (Test-Path -LiteralPath $path)) { return }
    $ticks = [DateTime]::UtcNow.Ticks
    do { $dest = Join-Path $dir ('session.pending-{0:D19}.etl' -f $ticks); $ticks++ } while (Test-Path -LiteralPath $dest)
    Move-Item -LiteralPath $path -Destination $dest
}

# --- the run ----------------------------------------------------------------
# (tests load the functions above through the PowerShell parser; no switch here)
New-Item -ItemType Directory -Force $Dir | Out-Null
Add-Type -TypeDefinition $traceSrc
$errors = New-Object System.Collections.ArrayList
$boot = Unix (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$state = $null
if (Test-Path $Inv) { try { $state = Get-Content $Inv -Raw | ConvertFrom-Json } catch { $state = $null } }
if (-not $state -or [int64]$state.boot -ne $boot) {
    # A new boot: the session ended with the old one, and so did any canary
    # it was carrying. Opens from the last boot stay for their 24 h.
    $old = if ($state) { @($state.rows) } else { @() }
    $state = [pscustomobject]@{ boot = $boot; session_started = 0; runs = 0; rows = $old; canary = $null }
}

$fresh = $false
$running = [JarvisBeepTrace]::QueryStatus($Name) -eq 0
if ($running) { [void][JarvisBeepTrace]::StopSession($Name) } else { $fresh = $true }
$canaryChecked = $running -and $state.canary
Add-Pending $Dir $Etl

# Start the next window before parsing this one, so the gap stays short.
$mode = 'filtered'
$why = [JarvisBeepTrace]::Start($Name, $Etl, $CapMB, $Provider, $CreateKeyword, $CreateEventId, 'FileName', $BeepDevice)
$canary = $null
if ($why) {
    $mode = 'stopped'; [void]$errors.Add($why)
} else {
    if ($fresh) { $state.session_started = Unix (Get-Date) }
    $status = [JarvisBeepTrace]::Canary()
    if ($status -eq 0) { $canary = @{ pid = $PID; ms = (UnixMs (Get-Date)) } }
    else { [void]$errors.Add(('the canary could not open the Beep device (0x{0:X8})' -f $status)) }
    Start-Sleep -Seconds $FailFastSec
    [void][JarvisBeepTrace]::FlushSession($Name)
    $size = if (Test-Path -LiteralPath $Etl) { (Get-Item -LiteralPath $Etl).Length } else { 0 }
    if ($size -gt $BreachBytes) {
        # The kernel is not applying the filter: every file open is being logged.
        [void][JarvisBeepTrace]::StopSession($Name)
        Remove-Item -LiteralPath $Etl -ErrorAction SilentlyContinue
        $mode = 'refused'; $canary = $null
        [void]$errors.Add("the kernel filter was not applied: $size bytes in $FailFastSec s; the trace is off")
    }
}

# --- parse the closed files, oldest first ------------------------------------
$pending = @(Get-ChildItem -LiteralPath $Dir -Filter 'session.pending-*.etl' | Sort-Object Name)
$droppedFiles = 0
while ($pending.Count -gt $MaxPending) {
    Remove-Item -LiteralPath $pending[0].FullName -ErrorAction SilentlyContinue
    $pending = @($pending | Select-Object -Skip 1); $droppedFiles++
}
$parsed = 0; $breaches = 0; $failed = 0; $etlBytes = [int64]0; $capped = $false
$opens = New-Object System.Collections.ArrayList
$done = @()
foreach ($f in $pending) {
    $etlBytes += [int64]$f.Length
    if ([int64]$f.Length -ge ([int64]$CapMB * 1MB)) { $capped = $true }
    $ok = $true
    try {
        Get-WinEvent -Path $f.FullName -Oldest -FilterXPath "*[System[EventID=$CreateEventId]]" -ErrorAction Stop | ForEach-Object {
            try {
                $script:parsed++
                $o = Read-Open $_ $BeepDevice
                if (-not $o.beep) { $script:breaches++; return }
                [void]$opens.Add($o)
            } catch { $script:failed++ }
        }
    } catch { if ($_.Exception.Message -notmatch 'No events') { $failed++; $ok = $false } }
    if ($ok) { $done += $f }
}
# Only a window that was traced throughout and read in full can prove the
# canary missing; anything else leaves it unchecked, never "seen".
$canaryChecked = $canaryChecked -and $failed -eq 0 -and $droppedFiles -eq 0 -and -not $capped
$canarySeen = if ($canaryChecked) { Test-Canary $state $opens } else { $null }
$prevCanary = $state.canary

# --- who opened it: the live process first, then one batched Sysmon pass ----
$callers = @($opens | Where-Object { -not ($prevCanary -and $_.pid -eq [int]$prevCanary.pid) })
$procs = @{}
foreach ($id in @($callers | ForEach-Object { $_.pid } | Sort-Object -Unique)) {
    $p = Get-Process -Id $id -IncludeUserName -ErrorAction SilentlyContinue
    if ($p) {
        $st = $null; try { $st = $p.StartTime } catch { }
        $procs[$id] = @{ start = $st; path = [string]$p.Path; user = [string]$p.UserName; name = [string]$p.ProcessName }
        $p.Dispose()
    }
}
$need = @{}
foreach ($o in $callers) {
    $p = $procs[$o.pid]
    if ($p -and $p.start -and $p.start -le $o.when.AddSeconds(1)) {
        $o.who = @{ path = $p.path; start = Unix $p.start; user = $p.user; via = 'live' }
    } else { $need[$o.pid] = $true }
}
$identityFailures = 0
if ($need.Count) {
    $sm = Sysmon-Creates @($need.Keys) $PidsPerQuery
    $identityFailures = $sm.failed
    foreach ($o in $callers) {
        if ($o.who) { continue }
        $c = Find-Creator @($sm.map[$o.pid]) $o.when
        $o.who = if ($c) { @{ path = [string]$c.image; start = Unix $c.time; user = [string]$c.user; via = 'sysmon' } }
                 else { @{ path = ''; start = 0; user = ''; via = 'unresolved' } }
    }
}
$new = foreach ($o in $callers) {
    $sig = Signer $o.who.path
    [pscustomobject]@{ ms = [int64]$o.ms; pid = $o.pid; path = $o.who.path
                       name = [IO.Path]::GetFileNameWithoutExtension([string]$o.who.path)
                       start = [int64]$o.who.start; user = $o.who.user; via = $o.who.via
                       sig = $sig.status; signer = $sig.signer }
}
$merged = Merge-Rows @($state.rows) @($new) (UnixMs (Get-Date)) ([int64]$KeepSec * 1000) $MaxRows

$state.rows = $merged.rows
$state.canary = $canary
$state.runs = [int]$state.runs + 1
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$Inv.new" -Encoding UTF8
Move-Item -LiteralPath "$Inv.new" -Destination $Inv -Force
# Only now, with their opens written, are the parsed files removed.
foreach ($f in $done) { Remove-Item -LiteralPath $f.FullName -ErrorAction SilentlyContinue }

$o = [ordered]@{
    version = 1; boot = $boot; mode = $mode; op = [JarvisBeepTrace]::LastOp
    session_started = [int64]$state.session_started; fresh_session = $fresh; runs = $state.runs
    parsed = $parsed; breaches = $breaches; parse_failures = $failed
    etl_bytes = $etlBytes; etl_capped = $capped; files_parsed = $done.Count; dropped_files = $droppedFiles
    canary_checked = [bool]$canaryChecked; canary_seen = $canarySeen
    identity_failures = $identityFailures; rows_dropped = $merged.dropped
    run_seconds = [int]$clock.Elapsed.TotalSeconds
    errors = @($errors | Select-Object -First 8)
    opens = @($merged.rows)
}
$json = $o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
