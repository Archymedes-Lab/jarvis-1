# jarvis-procfeed: live process table for the /procs view (read-only).
#
# One NtQuerySystemInformation(SystemProcessInformation) call per tick gives
# every process's id, parent, image name, session, creation time, CPU times
# and working set in a single buffer: no process handles are opened, so a tick
# costs a few milliseconds whatever runs. A process seen for the first time
# also gets its image path from SystemProcessIdInformation, again by process
# id and without a handle (measured 2026-10-24: 306 processes in 60 ms,
# protected ones included). Consecutive tables are diffed here and only the
# changes are written, one JSON object per line on stdout:
#
#   hello  protocol, tick, logical CPUs, whether Sysmon starts are subscribed
#   snap   the whole table (first line, then every RESYNC_S) so a lost line
#          can never leave the viewer wrong for long
#   d      one per tick, also the heartbeat: added rows, exited ids, updates
#   ev     a Sysmon process start as it is written, so a process that lives
#          less than one tick is still seen
#
# Rows are [key, pid, ppid, name, created_ms, cpu, rss_kb, session, path].
# The path and the Sysmon start's SHA-256 are for the daemon's identity check
# (web/procidentity.py) and are removed before anything reaches a viewer.
# Never a command line: the Sysmon subscription reads ProcessId,
# ParentProcessId, Image, UtcTime and Hashes from each record and nothing else.
#
# Bounds: the process exits when its stdin closes (the daemon stopped
# reading), when a write fails, or after 30 minutes, whichever is first.
# Tick 500 ms: measured 2026-10-23 at 26 ms CPU per second (2.6% of one core)
# with ~300 processes, frames 520 ms apart at the median; 250 ms cost 43 ms/s.
$ErrorActionPreference = 'Stop'
$src = @'
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

public static class JarvisProcFeed {
    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int needed);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern int QueryDosDevice(string device, StringBuilder target, int max);

    const int SystemProcessInformation = 5;
    const int SystemProcessIdInformation = 88;
    const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

    class Row {
        public long Pid; public long Ppid; public string Name; public long Created;
        public long Cpu100ns; public long Rss; public int Session;
        public double CpuPct; public long SentRss; public double SentCpu;
        public string Path = "";
    }

    static readonly object Gate = new object();
    static TextWriter Out;
    static volatile bool Stop;
    static IntPtr Buf = IntPtr.Zero;
    static int BufLen = 1 << 20;

    static string Esc(string s) {
        var b = new StringBuilder(s.Length + 2);
        b.Append('"');
        foreach (char c in s) {
            if (c == '"' || c == '\\') { b.Append('\\'); b.Append(c); }
            else if (c < 0x20) b.Append("\\u").Append(((int)c).ToString("x4"));
            else b.Append(c);
        }
        return b.Append('"').ToString();
    }

    static void Emit(string line) {
        lock (Gate) {
            try { Out.Write(line); Out.Write('\n'); Out.Flush(); }
            catch (IOException) { Stop = true; }
        }
    }

    static long NowMs() {
        return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
    }

    // FILETIME (100 ns since 1601) to Unix milliseconds.
    static long FileTimeMs(long ft) { return ft <= 0 ? 0 : ft / 10000 - 11644473600000L; }

    static string Key(Row r) { return r.Pid + ":" + r.Created; }

    // "\Device\HarddiskVolume4" -> "C:", so paths read like the scan baseline's.
    static List<KeyValuePair<string, string>> Drives = new List<KeyValuePair<string, string>>();
    static DateTime DrivesAt = DateTime.MinValue;

    static void LoadDrives() {
        var found = new List<KeyValuePair<string, string>>();
        for (char c = 'A'; c <= 'Z'; c++) {
            var target = new StringBuilder(1024);
            if (QueryDosDevice(c + ":", target, target.Capacity) > 0)
                found.Add(new KeyValuePair<string, string>(target.ToString().Split('\0')[0] + "\\", c + ":\\"));
        }
        Drives = found; DrivesAt = DateTime.UtcNow;
    }

    static string DosPath(string nt) {
        if (!nt.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase)) return nt;
        for (int pass = 0; pass < 2; pass++) {
            foreach (var d in Drives)
                if (nt.StartsWith(d.Key, StringComparison.OrdinalIgnoreCase)) return d.Value + nt.Substring(d.Key.Length);
            // A drive mounted since the last look: reload at most every 30 s.
            if ((DateTime.UtcNow - DrivesAt).TotalSeconds < 30) break;
            LoadDrives();
        }
        return nt;
    }

    // The image path of one process by id, without opening it. "" when the
    // process has no image file (Registry, Secure System) or is already gone.
    static string ImagePath(long pid) {
        int max = 2048;
        for (int attempt = 0; attempt < 2; attempt++) {
            IntPtr name = Marshal.AllocHGlobal(max), info = Marshal.AllocHGlobal(24);
            try {
                // SYSTEM_PROCESS_ID_INFORMATION: ProcessId, then a UNICODE_STRING
                // whose buffer the caller supplies.
                Marshal.WriteInt64(info, 0, pid);
                Marshal.WriteInt16(info, 8, 0);
                Marshal.WriteInt16(info, 10, (short)max);
                Marshal.WriteInt32(info, 12, 0);
                Marshal.WriteIntPtr(info, 16, name);
                int needed;
                int status = NtQuerySystemInformation(SystemProcessIdInformation, info, 24, out needed);
                if (status == StatusInfoLengthMismatch && attempt == 0) {
                    max = Math.Min(65534, Math.Max(max * 2, Marshal.ReadInt16(info, 10) & 0xFFFF));
                    continue;
                }
                if (status != 0) return "";
                int len = Marshal.ReadInt16(info, 8) & 0xFFFF;
                return DosPath(Marshal.PtrToStringUni(name, len / 2));
            } finally {
                Marshal.FreeHGlobal(name); Marshal.FreeHGlobal(info);
            }
        }
        return "";
    }

    // x64 SYSTEM_PROCESS_INFORMATION offsets.
    static Dictionary<string, Row> Read() {
        int needed;
        while (true) {
            if (Buf == IntPtr.Zero) Buf = Marshal.AllocHGlobal(BufLen);
            int status = NtQuerySystemInformation(SystemProcessInformation, Buf, BufLen, out needed);
            if (status == StatusInfoLengthMismatch) {
                Marshal.FreeHGlobal(Buf); Buf = IntPtr.Zero;
                BufLen = Math.Max(needed + (1 << 16), BufLen * 2);
                continue;
            }
            if (status != 0) throw new InvalidOperationException("NtQuerySystemInformation " + status.ToString("x8"));
            break;
        }
        var rows = new Dictionary<string, Row>();
        long off = 0;
        while (true) {
            IntPtr p = new IntPtr(Buf.ToInt64() + off);
            int next = Marshal.ReadInt32(p, 0);
            var r = new Row();
            r.Created = FileTimeMs(Marshal.ReadInt64(p, 32));
            r.Cpu100ns = Marshal.ReadInt64(p, 40) + Marshal.ReadInt64(p, 48);
            int nameLen = Marshal.ReadInt16(p, 56) & 0xFFFF;
            IntPtr namePtr = Marshal.ReadIntPtr(p, 64);
            r.Pid = Marshal.ReadIntPtr(p, 80).ToInt64();
            r.Ppid = Marshal.ReadIntPtr(p, 88).ToInt64();
            r.Session = Marshal.ReadInt32(p, 100);
            r.Rss = Marshal.ReadIntPtr(p, 144).ToInt64();
            r.Name = namePtr == IntPtr.Zero ? (r.Pid == 0 ? "Idle" : "System") : Marshal.PtrToStringUni(namePtr, nameLen / 2);
            // The idle pseudo-process is not a process and would dominate CPU.
            if (r.Pid != 0) rows[Key(r)] = r;
            if (next == 0) break;
            off += next;
        }
        return rows;
    }

    static string RowJson(Row r) {
        return "[" + Esc(Key(r)) + "," + r.Pid + "," + r.Ppid + "," + Esc(r.Name) + "," + r.Created + ","
             + r.CpuPct.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + ","
             + (r.Rss / 1024) + "," + r.Session + "," + Esc(r.Path) + "]";
    }

    static void Snap(long seq, Dictionary<string, Row> rows) {
        var b = new StringBuilder("{\"k\":\"snap\",\"seq\":" + seq + ",\"t\":" + NowMs()
                                  + ",\"self_cpu_ms\":" + SelfCpuMs() + ",\"p\":[");
        bool first = true;
        foreach (var r in rows.Values) {
            if (!first) b.Append(',');
            b.Append(RowJson(r)); first = false;
            r.SentCpu = r.CpuPct; r.SentRss = r.Rss;
        }
        Emit(b.Append("]}").ToString());
    }

    // This helper's own CPU time, so its cost is measured in use, not assumed.
    static long SelfCpuMs() {
        return (long)System.Diagnostics.Process.GetCurrentProcess().TotalProcessorTime.TotalMilliseconds;
    }

    static readonly Regex DataField = new Regex("<Data Name='(ProcessId|ParentProcessId|Image|UtcTime|Hashes)'>([^<]*)</Data>");
    static readonly Regex Sha256 = new Regex("SHA256=([0-9A-Fa-f]{64})");

    static string Subscribe() {
        try {
            var q = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, "*[System[EventID=1]]");
            var w = new EventLogWatcher(q);
            w.EventRecordWritten += (s, e) => {
                if (e.EventRecord == null) return;
                string xml;
                try { xml = e.EventRecord.ToXml(); } catch (Exception) { return; }
                string pid = "0", ppid = "0", image = "", utc = "", sha = "";
                foreach (Match m in DataField.Matches(xml)) {
                    string v = m.Groups[2].Value;
                    switch (m.Groups[1].Value) {
                        case "ProcessId": pid = v; break;
                        case "ParentProcessId": ppid = v; break;
                        case "Image": image = v; break;
                        case "UtcTime": utc = v; break;
                        case "Hashes": var h = Sha256.Match(v); if (h.Success) sha = h.Groups[1].Value.ToLowerInvariant(); break;
                    }
                }
                long a, b2;
                if (!long.TryParse(pid, out a) || !long.TryParse(ppid, out b2)) return;
                Emit("{\"k\":\"ev\",\"t\":" + NowMs() + ",\"pid\":" + a + ",\"ppid\":" + b2
                     + ",\"name\":" + Esc(image.Substring(image.LastIndexOf('\\') + 1)) + ",\"utc\":" + Esc(utc)
                     + ",\"path\":" + Esc(image) + ",\"sha256\":" + Esc(sha) + "}");
            };
            w.Enabled = true;
            return "sysmon";
        } catch (Exception ex) {
            return "unavailable: " + ex.GetType().Name;
        }
    }

    public static void Run(int tickMs, int maxSeconds, int resyncSeconds) {
        Out = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false));
        var reader = new Thread(() => {
            try { var stdin = Console.OpenStandardInput(); var b = new byte[64]; while (stdin.Read(b, 0, b.Length) > 0) { } }
            catch (Exception) { }
            Stop = true;
        });
        reader.IsBackground = true;
        reader.Start();
        int cpus = Environment.ProcessorCount;
        string events = Subscribe();
        LoadDrives();
        Emit("{\"k\":\"hello\",\"v\":2,\"tick\":" + tickMs + ",\"cpus\":" + cpus + ",\"events\":" + Esc(events)
             + ",\"self\":" + System.Diagnostics.Process.GetCurrentProcess().Id + "}");
        var started = DateTime.UtcNow;
        var lastResync = started;
        long seq = 0;
        var prev = Read();
        foreach (var r in prev.Values) r.Path = ImagePath(r.Pid);
        long prevT = DateTime.UtcNow.Ticks;
        Snap(seq++, prev);
        while (!Stop && (DateTime.UtcNow - started).TotalSeconds < maxSeconds) {
            Thread.Sleep(tickMs);
            var cur = Read();
            long t = DateTime.UtcNow.Ticks;
            double wall = Math.Max(1, t - prevT) * (double)cpus;
            var add = new StringBuilder(); var upd = new StringBuilder(); var gone = new StringBuilder();
            foreach (var kv in cur) {
                Row r = kv.Value, old;
                if (prev.TryGetValue(kv.Key, out old)) {
                    r.Path = old.Path;
                    r.CpuPct = Math.Max(0, Math.Min(100, (r.Cpu100ns - old.Cpu100ns) * 100.0 / wall));
                    r.SentCpu = old.SentCpu; r.SentRss = old.SentRss;
                    if (Math.Abs(r.CpuPct - r.SentCpu) >= 0.5 || Math.Abs(r.Rss - r.SentRss) > Math.Max(1L << 20, r.SentRss / 50)) {
                        if (upd.Length > 0) upd.Append(',');
                        upd.Append("[" + Esc(kv.Key) + "," + r.CpuPct.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + "," + (r.Rss / 1024) + "]");
                        r.SentCpu = r.CpuPct; r.SentRss = r.Rss;
                    }
                } else {
                    r.Path = ImagePath(r.Pid);
                    if (add.Length > 0) add.Append(',');
                    add.Append(RowJson(r));
                    r.SentCpu = r.CpuPct; r.SentRss = r.Rss;
                }
            }
            foreach (var k in prev.Keys) {
                if (!cur.ContainsKey(k)) { if (gone.Length > 0) gone.Append(','); gone.Append(Esc(k)); }
            }
            prev = cur; prevT = t;
            if ((DateTime.UtcNow - lastResync).TotalSeconds >= resyncSeconds) {
                Snap(seq++, cur); lastResync = DateTime.UtcNow; continue;
            }
            Emit("{\"k\":\"d\",\"seq\":" + (seq++) + ",\"t\":" + NowMs() + ",\"a\":[" + add + "],\"x\":[" + gone + "],\"u\":[" + upd + "]}");
        }
        Emit("{\"k\":\"bye\",\"t\":" + NowMs() + ",\"self_cpu_ms\":" + SelfCpuMs() + "}");
    }
}
'@
Add-Type -TypeDefinition $src -ReferencedAssemblies System.Core
[JarvisProcFeed]::Run(500, 1800, 30)
