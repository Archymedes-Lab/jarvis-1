# Instruction-level inspection of running processes.
#
# Three questions, none of which any other collector here asks:
#
#   1. Is there executable memory that no file backs? A module loaded from
#      disk is MEM_IMAGE. Code that was written into a process at runtime —
#      reflective loading, manual mapping, plain shellcode — is MEM_PRIVATE
#      and executable, because there is no file for it to be backed by.
#
#   2. Do ntdll's syscall stubs still look like syscall stubs? On x64 every
#      one begins `4C 8B D1 B8 <ssn>` (mov r10,rcx; mov eax,SSN). A jump at
#      byte zero means something is intercepting the call before the kernel
#      ever sees it.
#
#   3. Are the per-process exploit mitigations actually on? CFG, ACG and
#      CET/shadow-stack are the difference between a memory bug being a crash
#      and being an execution primitive.
#
#   4. Is there a whole PE image -- a DLL, an EXE or a .NET assembly -- in
#      memory that no file backs? The loader maps real modules as MEM_IMAGE,
#      and a file mapping names its file. A PE header at the start of private
#      or pagefile-backed memory is a module that was copied in, not loaded:
#      reflective DLL loading, manual mapping, or a .NET assembly loaded from
#      a byte array (execute-assembly, PowerShell cradles, and PowerShell's own
#      Add-Type). JIT code never starts with a PE header, so this check does
#      not share the JIT runtime's excuse. For a managed assembly the scan
#      also reads its metadata #Strings heap (type, method, field and native
#      import names) so the WSL side can tell whether a reviewed JARVIS script
#      compiled it. Nothing is executed or loaded to do so.
#
# Without elevation only processes owned by this user can be opened. That is
# reported rather than silently reducing the sample.
# First statement: module autoloading searches only the system module folders.
$env:PSModulePath = "$([Environment]::SystemDirectory)\WindowsPowerShell\v1.0\Modules;$([Environment]::GetFolderPath('ProgramFiles'))\WindowsPowerShell\Modules"
$ErrorActionPreference = 'SilentlyContinue'
# The user the broker was installed for, recorded by SID at install in this
# administrator-only folder. The broker runs as SYSTEM, so per-user state is
# read from HKEY_USERS\<SID>, read-only, never from this process's environment.
$UserSid = ''
try { $UserSid = [string](Get-Content -LiteralPath (Join-Path $PSScriptRoot 'user.json') -Raw | ConvertFrom-Json).sid } catch { }
if ($UserSid -notmatch '^S-1-(5-21|12-1)(-\d+)+$') { $UserSid = '' }
function Get-UserLocalAppData([string]$sid) {
    # From the administrator-owned profile list, not an environment variable.
    if (-not $sid) { return '' }
    $key = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    $profile = (Get-ItemProperty -LiteralPath $key -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
    if (-not $profile) { return '' }
    return (Join-Path $profile 'AppData\Local')
}

$src = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public static class JarvisMem
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION64 {
        public ulong BaseAddress; public ulong AllocationBase;
        public uint AllocationProtect; public int __alignment1;
        public ulong RegionSize; public uint State; public uint Protect;
        public uint Type; public int __alignment2;
    }

    const uint MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000, MEM_IMAGE = 0x1000000;
    const uint PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20,
               PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80;
    const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(IntPtr h, IntPtr addr,
        out MEMORY_BASIC_INFORMATION64 mbi, int len);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf,
        int size, out IntPtr read);
    [DllImport("psapi.dll", SetLastError = true)]
    static extern bool EnumProcessModulesEx(IntPtr h, [Out] IntPtr[] mods, int cb,
        out int needed, uint filter);
    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    static extern uint GetModuleBaseName(IntPtr h, IntPtr mod, StringBuilder name, int size);
    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    static extern uint GetMappedFileNameW(IntPtr h, IntPtr addr, StringBuilder name, uint size);
    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    static extern uint GetModuleFileNameEx(IntPtr h, IntPtr mod, StringBuilder name, int size);

    // The main image, so a runtime linked into the executable itself (a .NET
    // single-file app) can be verified from the file on the WSL side.
    public static string MainPath(IntPtr h)
    {
        var sb = new StringBuilder(1024);
        return GetModuleFileNameEx(h, IntPtr.Zero, sb, sb.Capacity) == 0 ? "" : sb.ToString();
    }
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string name);

    // Engines that compile code at run time. Loaded, one of these explains
    // private executable memory; a name on an allowlist only claims to.
    static readonly string[] JitRuntimes = {
        "coreclr.dll", "clr.dll", "mscorwks.dll", "clrjit.dll", "mrt100_app.dll",
        "EmbeddedBrowserWebView.dll", "libcef.dll", "v8.dll", "jscript9.dll",
        "chakra.dll", "jvm.dll",
    };

    public static string Runtime(IntPtr h)
    {
        var mods = new IntPtr[2048];
        int needed;
        // 3 = LIST_MODULES_ALL, so a 32-bit runtime in a WOW64 process counts.
        if (!EnumProcessModulesEx(h, mods, IntPtr.Size * mods.Length, out needed, 3)) return "";
        int count = Math.Min(needed / IntPtr.Size, mods.Length);
        var name = new StringBuilder(260);
        for (int i = 0; i < count; i++)
        {
            name.Length = 0;
            if (GetModuleBaseName(h, mods[i], name, name.Capacity) == 0) continue;
            string n = name.ToString();
            foreach (var jit in JitRuntimes)
                if (string.Equals(n, jit, StringComparison.OrdinalIgnoreCase)) return jit;
        }
        return "";
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr mod, string name);

    static bool IsExec(uint p)
    {
        return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ
            || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    public class Region { public ulong Base; public ulong Size; public uint Protect; }

    // Executable memory with no file behind it.
    public static List<Region> Unbacked(IntPtr h, int cap)
    {
        var found = new List<Region>();
        ulong addr = 0;
        MEMORY_BASIC_INFORMATION64 mbi;
        int guard = 0;
        while (VirtualQueryEx(h, (IntPtr)addr, out mbi,
                              Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64))) != 0)
        {
            if (guard++ > 200000) break;
            if (mbi.RegionSize == 0) break;
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && IsExec(mbi.Protect))
                found.Add(new Region { Base = mbi.BaseAddress,
                                       Size = mbi.RegionSize, Protect = mbi.Protect });
            addr = mbi.BaseAddress + mbi.RegionSize;
            if (addr >= 0x7FFFFFFF0000UL) break;
            if (found.Count >= cap) break;
        }
        return found;
    }

    const uint MEM_MAPPED = 0x40000, PAGE_NOACCESS = 0x01, PAGE_GUARD = 0x100;
    const int HeaderBytes = 4096;
    const int MaxImageBytes = 4 << 20;       // read at most 4 MiB of one image
    const int MaxStrings = 3000, MaxStringLength = 128;

    static string Esc(string v)
    {
        var sb = new StringBuilder(v.Length + 8);
        foreach (char c in v)
        {
            if (c == '\\' || c == '"') sb.Append('\\').Append(c);
            else if (c < 0x20 || c > 0x7e) sb.Append('?');
            else sb.Append(c);
        }
        return sb.ToString();
    }

    static ushort U16(byte[] b, int o) { return (o >= 0 && o + 2 <= b.Length) ? BitConverter.ToUInt16(b, o) : (ushort)0; }
    static uint U32(byte[] b, int o) { return (o >= 0 && o + 4 <= b.Length) ? BitConverter.ToUInt32(b, o) : 0u; }

    // A copied-in image keeps its on-disk (flat) layout, so an RVA is
    // translated through the section table, not added to the base.
    static int RvaToOffset(byte[] b, int pe, uint rva)
    {
        int count = U16(b, pe + 6), table = pe + 24 + U16(b, pe + 20);
        for (int i = 0; i < count && i < 96; i++)
        {
            int s = table + i * 40;
            uint va = U32(b, s + 12), vsize = U32(b, s + 8), raw = U32(b, s + 20), rsize = U32(b, s + 16);
            if (rva >= va && rva < va + Math.Max(vsize, rsize))
            {
                long off = (long)rva - va + raw;
                return off >= 0 && off < b.Length ? (int)off : -1;
            }
        }
        return -1;
    }

    // Module name and the identifiers of a managed image's #Strings heap.
    static string Metadata(byte[] b, int pe)
    {
        ushort magic = U16(b, pe + 24);
        int dirs = pe + 24 + (magic == 0x20b ? 112 : 96);
        uint cor = U32(b, dirs + 14 * 8);
        if (cor == 0) return "";
        int corOff = RvaToOffset(b, pe, cor);
        int md = corOff < 0 ? -1 : RvaToOffset(b, pe, U32(b, corOff + 8));
        if (md < 0 || U32(b, md) != 0x424A5342) return ",\"managed\":true,\"parsed\":false";
        int verLen = (int)U32(b, md + 12);
        int hdr = md + 16 + verLen;
        int streams = U16(b, hdr + 2), q = hdr + 4;
        int strOff = -1, strSize = 0, tabOff = -1;
        for (int i = 0; i < streams && i < 8; i++)
        {
            int off = (int)U32(b, q), size = (int)U32(b, q + 4), e = q + 8;
            while (e < b.Length && b[e] != 0 && e < q + 40) e++;
            if (e >= b.Length) break;
            string name = Encoding.ASCII.GetString(b, q + 8, e - q - 8);
            if (name == "#Strings") { strOff = md + off; strSize = size; }
            else if (name == "#~") tabOff = md + off;
            q = (e + 4) & ~3;
        }
        if (strOff <= 0 || strOff >= b.Length) return ",\"managed\":true,\"parsed\":false";
        int end = (int)Math.Min((long)b.Length, (long)strOff + strSize);
        var sb = new StringBuilder(",\"managed\":true,\"parsed\":true");
        // Module is metadata table 0, so its first row is at the start of the
        // table data: Generation (2) then Name (a #Strings index).
        if (tabOff > 0 && tabOff + 24 < b.Length)
        {
            ulong valid = BitConverter.ToUInt64(b, tabOff + 8);
            int tables = 0;
            for (int t = 0; t < 64; t++) if (((valid >> t) & 1) != 0) tables++;
            int row = tabOff + 24 + 4 * tables;
            int nameIndex = (b[tabOff + 6] & 1) != 0 ? (int)U32(b, row + 2) : U16(b, row + 2);
            int n = strOff + nameIndex, z = n;
            while (z < end && b[z] != 0) z++;
            if (n < end && z - n <= MaxStringLength)
                sb.Append(",\"module\":\"").Append(Esc(Encoding.ASCII.GetString(b, n, z - n))).Append("\"");
        }
        sb.Append(",\"strings\":[");
        int kept = 0, total = 0, start = strOff + 1;
        for (int i = strOff + 1; i < end; i++)
        {
            if (b[i] != 0) continue;
            int len = i - start;
            if (len > 0)
            {
                total++;
                if (kept < MaxStrings && len <= MaxStringLength)
                {
                    if (kept > 0) sb.Append(",");
                    sb.Append("\"").Append(Esc(Encoding.UTF8.GetString(b, start, len))).Append("\"");
                    kept++;
                }
            }
            start = i + 1;
        }
        sb.Append("],\"strings_total\":").Append(total);
        return sb.ToString();
    }

    // PE images in committed memory that is neither a loader-mapped image nor
    // a mapping of a named file.
    public static string Foreign(IntPtr h, int cap, ref int reads)
    {
        var sb = new StringBuilder();
        ulong addr = 0;
        MEMORY_BASIC_INFORMATION64 mbi;
        int guard = 0, found = 0;
        var head = new byte[HeaderBytes];
        while (VirtualQueryEx(h, (IntPtr)addr, out mbi,
                              Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64))) != 0)
        {
            if (guard++ > 200000 || mbi.RegionSize == 0) break;
            bool readable = mbi.Protect != 0 && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
            if (mbi.State == MEM_COMMIT && mbi.BaseAddress == mbi.AllocationBase
                && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) && readable)
            {
                IntPtr got;
                reads++;
                if (ReadProcessMemory(h, (IntPtr)mbi.BaseAddress, head, HeaderBytes, out got)
                    && (long)got >= 0x200 && head[0] == 0x4D && head[1] == 0x5A)
                {
                    int pe = (int)U32(head, 0x3C);
                    bool isPe = pe > 0 && pe + 0x108 < HeaderBytes && head[pe] == 0x50
                                && head[pe + 1] == 0x45 && head[pe + 2] == 0 && head[pe + 3] == 0;
                    var file = new StringBuilder(520);
                    bool named = isPe && mbi.Type == MEM_MAPPED
                                 && GetMappedFileNameW(h, (IntPtr)mbi.BaseAddress, file, 520) > 0;
                    if (isPe && !named)
                    {
                        int n = (int)Math.Min(mbi.RegionSize, (ulong)MaxImageBytes);
                        var image = new byte[n];
                        IntPtr read;
                        if (!ReadProcessMemory(h, (IntPtr)mbi.BaseAddress, image, n, out read)) image = head;
                        if (found > 0) sb.Append(",");
                        sb.Append("{\"base\":").Append(mbi.BaseAddress)
                          .Append(",\"size\":").Append(mbi.RegionSize)
                          .Append(",\"protect\":").Append(mbi.Protect)
                          .Append(",\"exec\":").Append(IsExec(mbi.Protect) ? "true" : "false")
                          .Append(",\"private\":").Append(mbi.Type == MEM_PRIVATE ? "true" : "false")
                          .Append(",\"machine\":").Append(U16(head, pe + 4));
                        string meta = "";
                        try { meta = Metadata(image, pe); } catch { meta = ",\"managed\":true,\"parsed\":false"; }
                        sb.Append(meta.Length > 0 ? meta : ",\"managed\":false").Append("}");
                        if (++found >= cap) break;
                    }
                }
            }
            addr = mbi.BaseAddress + mbi.RegionSize;
            if (addr >= 0x7FFFFFFF0000UL) break;
        }
        return sb.ToString();
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CommandLineToArgvW(string line, out int count);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr p);

    // How a PowerShell host was launched, parsed with Windows' own argv rules
    // (WSL quotes a -Command script and escapes its quotes). For -Command only
    // the SHA-256 of the decoded script text leaves this process, never the
    // text: the WSL side compares it with the reviewed scripts.
    public static string Launch(string line)
    {
        if (string.IsNullOrEmpty(line)) return "{\"launch\":\"other\"}";
        int n;
        IntPtr argv = CommandLineToArgvW(line, out n);
        if (argv == IntPtr.Zero) return "{\"launch\":\"other\"}";
        var args = new string[n];
        try { for (int i = 0; i < n; i++) args[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size)); }
        finally { LocalFree(argv); }
        for (int i = 1; i < n; i++)
        {
            string a = args[i].ToLowerInvariant();
            if ((a == "-file" || a == "-f") && i + 1 < n)
                return "{\"launch\":\"file\",\"file\":\"" + Esc(args[i + 1]) + "\"}";
            if (a == "-e" || a == "-ec" || a == "-enc" || a == "-encodedcommand")
                return "{\"launch\":\"encoded\"}";
            if ((a == "-command" || a == "-c") && i + 1 < n)
            {
                string body = string.Join(" ", args, i + 1, n - i - 1);
                string sha;
                using (var h = System.Security.Cryptography.SHA256.Create())
                    sha = BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(body))).Replace("-", "").ToLowerInvariant();
                return "{\"launch\":\"command\",\"command_sha256\":\"" + sha + "\",\"command_length\":" + body.Length + "}";
            }
        }
        return "{\"launch\":\"other\"}";
    }

    // The syscall stubs most worth watching: allocation, protection changes,
    // thread creation and process access are what an injector has to call.
    static readonly string[] Watched = {
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
        "NtCreateThreadEx", "NtOpenProcess", "NtMapViewOfSection",
        "NtQueryInformationProcess", "NtSetContextThread", "NtResumeThread",
        "NtCreateUserProcess", "NtDeviceIoControlFile", "NtLoadDriver",
    };

    public static string StubReport(IntPtr h)
    {
        IntPtr nt = GetModuleHandle("ntdll.dll");
        if (nt == IntPtr.Zero) return "";
        var sb = new StringBuilder();
        foreach (var name in Watched)
        {
            IntPtr fn = GetProcAddress(nt, name);
            if (fn == IntPtr.Zero) continue;
            var buf = new byte[8];
            IntPtr got;
            if (!ReadProcessMemory(h, fn, buf, buf.Length, out got)) continue;
            if (got == IntPtr.Zero) continue;
            // Healthy x64 stub: 4C 8B D1 B8 <ssn:4>
            bool clean = (buf[0] == 0x4C && buf[1] == 0x8B && buf[2] == 0xD1 && buf[3] == 0xB8);
            if (clean) continue;
            var hex = new StringBuilder();
            for (int i = 0; i < buf.Length; i++) hex.Append(buf[i].ToString("X2"));
            if (sb.Length > 0) sb.Append(";");
            sb.Append(name).Append("=").Append(hex.ToString());
        }
        return sb.ToString();
    }

    public static string Scan(int maxProcs, int regionCap)
    {
        var sb = new StringBuilder();
        sb.Append("[");
        bool first = true;
        int opened = 0, denied = 0, reads = 0;
        int self = Process.GetCurrentProcess().Id;
        foreach (var p in Process.GetProcesses())
        {
            if (opened >= maxProcs) break;
            IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, p.Id);
            if (h == IntPtr.Zero) { denied++; continue; }
            opened++;
            try
            {
                var regions = Unbacked(h, regionCap);
                string stubs = StubReport(h);
                string foreign = Foreign(h, 32, ref reads);
                if (regions.Count == 0 && stubs.Length == 0 && foreign.Length == 0) continue;
                ulong total = 0; uint rwx = 0;
                foreach (var r in regions) {
                    total += r.Size;
                    if (r.Protect == PAGE_EXECUTE_READWRITE) rwx++;
                }
                string runtime = regions.Count > 0 ? Runtime(h) : "";
                string path = regions.Count > 0 && runtime.Length == 0 ? MainPath(h) : "";
                if (!first) sb.Append(",");
                first = false;
                sb.Append("{\"pid\":").Append(p.Id)
                  .Append(",\"name\":\"").Append(p.ProcessName.Replace("\"", "")).Append("\"")
                  .Append(",\"regions\":").Append(regions.Count)
                  .Append(",\"bytes\":").Append(total)
                  .Append(",\"rwx\":").Append(rwx)
                  .Append(",\"runtime\":\"").Append(runtime).Append("\"")
                  .Append(",\"path\":\"").Append(path.Replace("\\", "\\\\").Replace("\"", "")).Append("\"")
                  .Append(",\"stubs\":\"").Append(stubs).Append("\"")
                  .Append(",\"self\":").Append(p.Id == self ? "true" : "false")
                  .Append(",\"foreign\":[").Append(foreign).Append("]}");
            }
            catch { }
            finally { CloseHandle(h); }
        }
        sb.Append("]");
        return "{\"opened\":" + opened + ",\"denied\":" + denied + ",\"reads\":" + reads +
               ",\"procs\":" + sb.ToString() + "}";
    }
}
'@

Add-Type -TypeDefinition $src

$o = [ordered]@{}
$scanWatch = [Diagnostics.Stopwatch]::StartNew()
$o.memory = [JarvisMem]::Scan(400, 4000) | ConvertFrom-Json
$o.scan_ms = $scanWatch.ElapsedMilliseconds
$o.local_app_data = Get-UserLocalAppData $UserSid

# Who hosts each copied-in image: executable, how it was launched, and its
# parent. Only for the few processes that have one; never the full command
# line, which for a -Command launch is the whole script.
$o.hosts = @()
foreach ($p in @($o.memory.procs | Where-Object { @($_.foreign).Count -gt 0 })) {
  $w = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.pid)" -EA SilentlyContinue
  if (-not $w) { continue }
  $par = Get-CimInstance Win32_Process -Filter "ProcessId=$($w.ParentProcessId)" -EA SilentlyContinue
  $launch = [JarvisMem]::Launch([string]$w.CommandLine) | ConvertFrom-Json
  $o.hosts += [pscustomobject]@{
    pid = $p.pid; exe = [string]$w.ExecutablePath; launch = [string]$launch.launch
    file = [string]$launch.file; command_sha256 = [string]$launch.command_sha256
    command_length = [int]$launch.command_length
    parent_pid = [int]$w.ParentProcessId; parent_exe = [string]$par.ExecutablePath
  }
}

# Per-process mitigations. Get-ProcessMitigation is built in on Win10+ and
# needs no P/Invoke; only a sample of processes is queried because it is slow.
$o.mitigations = @()
foreach ($n in @('explorer','WindowsTerminal','firefox','msedge','powershell',
                 'Code','node','python','ollama','Teams')) {
  $proc = Get-Process -Name $n -EA SilentlyContinue | Select-Object -First 1
  if (-not $proc) { continue }
  $m = Get-ProcessMitigation -Id $proc.Id -EA SilentlyContinue
  if (-not $m) { continue }
  $o.mitigations += [pscustomobject]@{
    name = $n
    pid  = $proc.Id
    cfg  = [string]$m.CFG.Enable
    dep  = [string]$m.DEP.Enable
    aslr = [string]$m.ASLR.ForceRelocateImages
    acg  = [string]$m.DynamicCode.ProhibitDynamicCode
    cet  = [string]$m.UserShadowStack.UserShadowStack
    sig  = [string]$m.BinarySignature.MicrosoftSignedOnly
  }
}

$sys = Get-ProcessMitigation -System -EA SilentlyContinue
$o.system = [pscustomobject]@{
  dep  = [string]$sys.DEP.Enable
  cfg  = [string]$sys.CFG.Enable
  aslr = [string]$sys.ASLR.ForceRelocateImages
  botm = [string]$sys.ASLR.BottomUp
  heap = [string]$sys.Heap.TerminateOnError
  cet  = [string]$sys.UserShadowStack.UserShadowStack
}

$json = [pscustomobject]$o | ConvertTo-Json -Depth 6 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
