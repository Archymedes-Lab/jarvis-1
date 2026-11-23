# Injected-keystroke monitor.
#
# Windows tags every keyboard and mouse event that did not come from real
# hardware. A low-level hook is the only place that tag is visible, so this
# installs one and watches for it.
#
# It deliberately does NOT record what the person at the keyboard typed. A hook
# that logs arbitrary hardware key values is a keylogger, and writing one to an
# unencrypted disk would be a worse problem than the one it detects. Real keys
# are counted without identity, apart from a short allowlist of families the
# operator asked to timestamp: =/+, /?, ./ >, and digits 0-9.
#
# Injected keys are the opposite case: nobody typed them, and "which key, from
# where, into what" is the whole investigation. Each one is recorded forensically
# — virtual key, scan code, the exact character it produces under the focused
# window's layout, modifiers, raw flags, dwExtraInfo, millisecond time, the
# focused window and control — and every burst gets a context record naming the
# lower-integrity and just-started processes that could have sent it.
#
# The one exception is a long printable burst: that is what a password manager's
# auto-type looks like, so past -RedactBurstOver printable characters the text
# is replaced by its length and composition. A lone phantom character is always
# kept exactly. -RedactBurstOver -1 disables redaction.
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [int]$HeartbeatSeconds = 60,
    [int]$RedactBurstOver = 6
)

$ErrorActionPreference = 'Stop'

$src = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Management;
using System.Reflection;

public static class JarvisInputHook
{
    // Flags on KBDLLHOOKSTRUCT / MSLLHOOKSTRUCT.
    const uint LLKHF_INJECTED           = 0x10;
    const uint LLKHF_LOWER_IL_INJECTED  = 0x02;

    const int WH_KEYBOARD_LL = 13;
    const int WH_MOUSE_LL    = 14;

    [StructLayout(LayoutKind.Sequential)]
    struct KBDLLHOOKSTRUCT {
        public uint vkCode; public uint scanCode; public uint flags;
        public uint time; public IntPtr dwExtraInfo;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct MSLLHOOKSTRUCT {
        public int x; public int y; public uint mouseData; public uint flags;
        public uint time; public IntPtr dwExtraInfo;
    }

    delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr SetWindowsHookEx(int id, HookProc fn, IntPtr mod, uint tid);
    [DllImport("user32.dll")]
    static extern IntPtr CallNextHookEx(IntPtr hk, int nCode, IntPtr wp, IntPtr lp);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string name);
    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);

    static IntPtr _kb, _ms;
    static HookProc _kbProc, _msProc;      // kept alive; a collected delegate crashes the hook
    static string _out;
    static readonly object _lock = new object();

    public static long RealKeys, InjectedKeys, RealClicks, InjectedClicks;
    public static long RealMoves, InjectedMoves;

    // Reset once per heartbeat and persisted as a single aggregate row. These
    // counters retain every typing event statistically without retaining a key
    // code or character, which keeps anomaly baselines useful and passwords
    // unrecoverable.
    public static long WindowRealKeys, WindowInjectedKeys;
    public static long WindowRealKeyGaps, WindowRealKeySub20, WindowRealKeySub8;
    public static long WindowCadRunMax;
    public static long WindowEqualsKeys, WindowSlashKeys, WindowPeriodKeys;
    public static long WindowDigitKeys;

    // Injected key-up events, and the count of distinct injected cursor-move
    // bursts (a run of injected moves with no >400 ms gap). Key-down alone
    // missed the release half of a synthetic keystroke; the burst count makes
    // a short reposition-and-click visible instead of being lost between the
    // every-250th-move samples.
    public static long InjectedKeyUps, InjectedMoveBursts;

    // Real-keystroke cadence. Hardware-level injection — a malicious HID
    // filter driver, a BadUSB device, an IOCTL straight to kbdclass — arrives
    // with no injected flag set and is otherwise identical to a person typing.
    // Timing is the only tell: humans do not hold a sub-8 ms inter-key gap, or
    // a long run of gaps all within 2 ms of each other.
    public static long RealKeyGaps, RealKeySub20, RealKeySub8, CadRunMax;
    static uint _lastRealKeyTick, _lastInjMoveTick, _lastVk;
    static long _lastGap = -1, _cadRun;

    // Input latency. Every low-level hook sits in a chain, and each one delays
    // every event until it returns. A cursor that feels slower than it used to
    // is the symptom a slow hook produces, so the delay is measured rather
    // than guessed: d.time is when the event was generated, GetTickCount is
    // now, and the difference is how long it spent traversing the chain ahead
    // of us. This hook is itself in that chain, so it measures its own cost
    // too — which is the honest thing for it to do.
    public static long LatSamples, LatTotalMs, LatMaxMs, LatOver50;

    [DllImport("kernel32.dll")]
    static extern uint GetTickCount();

    static void Latency(uint eventTime)
    {
        long d = (long)(GetTickCount() - eventTime);
        if (d < 0 || d > 10000) return;        // tick wrap or a stale event
        LatSamples++;
        LatTotalMs += d;
        if (d > LatMaxMs) LatMaxMs = d;
        if (d > 50) LatOver50++;
    }

    // A coarse bucket, recorded only for injected events. Enough to tell an
    // injected Enter from an injected character without ever reconstructing
    // what was typed.
    // Volume, media and launch keys. These carry no text -- knowing that the
    // volume-down key was pressed reveals nothing about what was typed -- so
    // unlike ordinary keystrokes they are recorded in full, injected or not.
    // That is the point: a control activation the user did not perform is only
    // visible if the real ones are logged too.
    public static string ControlClass(uint vk)
    {
        switch (vk) {
            case 0xAD: return "volume-mute";
            case 0xAE: return "volume-down";
            case 0xAF: return "volume-up";
            case 0xB0: return "media-next";
            case 0xB1: return "media-prev";
            case 0xB2: return "media-stop";
            case 0xB3: return "media-play-pause";
            case 0xB4: return "launch-mail";
            case 0xB5: return "launch-media-select";
            case 0xB6: return "launch-app1";
            case 0xB7: return "launch-app2";
            case 0xA6: return "browser-back";
            case 0xA7: return "browser-forward";
            case 0xA8: return "browser-refresh";
            case 0xA9: return "browser-stop";
            case 0xAA: return "browser-search";
            case 0xAB: return "browser-favorites";
            case 0xAC: return "browser-home";
            default:   return "";
        }
    }

    // Counted separately so a control activation is never lost inside the
    // aggregate keystroke totals.
    public static long ControlKeys, ControlKeysInjected;
    static uint _lastCtrlTick;

    // Milliseconds since the last control key of any kind, capped. The volume
    // sampler uses this to decide whether a level change had a key behind it.
    public static long MsSinceControlKey()
    {
        if (_lastCtrlTick == 0) return 999999;
        long d = (long)unchecked((uint)Environment.TickCount - _lastCtrlTick);
        return d < 0 ? 999999 : d;
    }

    static string KeyClass(uint vk)
    {
        if (vk == 0xBB) return "equals-plus";       // = / + physical key
        if (vk == 0xBF || vk == 0x6F) return "slash-question";
        if (vk == 0xBE || vk == 0x6E) return "period-greater";
        // Top-row and numpad digits. Named individually so a phantom "3"
        // can be located; not a general character log.
        if (vk >= 0x30 && vk <= 0x39) return "digit-" + (vk - 0x30);
        if (vk >= 0x60 && vk <= 0x69) return "digit-" + (vk - 0x60);
        if (vk >= 0x70 && vk <= 0x87) return "function";
        if (vk == 0xE7) return "unicode-packet";    // SendInput KEYEVENTF_UNICODE
        if (vk == 0xE5) return "ime-processkey";
        if (vk == 0x0D) return "enter";
        if (vk == 0x09) return "tab";
        if (vk == 0x1B) return "escape";
        if (vk == 0x08) return "backspace";
        if (vk >= 0x21 && vk <= 0x28) return "navigation";
        if (vk == 0x5B || vk == 0x5C) return "windows-key";
        if (vk >= 0x10 && vk <= 0x12) return "modifier";
        if (vk == 0x11 || vk == 0xA2 || vk == 0xA3) return "control";
        return "character";
    }

    static bool IsDigitClass(string cls)
    {
        return cls.Length == 7 && cls.StartsWith("digit-")
            && cls[6] >= '0' && cls[6] <= '9';
    }

    public static string Foreground()
    {
        try {
            uint pid;
            GetWindowThreadProcessId(GetForegroundWindow(), out pid);
            if (pid == 0) return "";
            using (var p = Process.GetProcessById((int)pid)) return p.ProcessName + ":" + pid;
        } catch { return ""; }
    }

    // Timing analysis for genuine (un-flagged) keystrokes. See the cadence
    // counters above for why this is the only signal for driver-level input.
    static void Cadence(uint eventTime, uint vk)
    {
        if (vk == 0xBB) WindowEqualsKeys++;
        if (vk == 0xBF || vk == 0x6F) WindowSlashKeys++;
        if (vk == 0xBE || vk == 0x6E) WindowPeriodKeys++;
        if ((vk >= 0x30 && vk <= 0x39) || (vk >= 0x60 && vk <= 0x69))
            WindowDigitKeys++;
        if (_lastRealKeyTick != 0) {
            long gap = (long)(eventTime - _lastRealKeyTick);
            // Key auto-repeat (a held key) is regular and fast but benign, so
            // it is counted as a gap but kept out of the "too fast" and
            // "robotically even" tallies.
            bool repeat = (vk == _lastVk && gap >= 0 && gap < 60);
            if (gap >= 0 && gap < 5000) {
                RealKeyGaps++;
                WindowRealKeyGaps++;
                if (!repeat && gap < 20) RealKeySub20++;
                if (!repeat && gap < 8)  RealKeySub8++;
                if (!repeat && gap < 20) WindowRealKeySub20++;
                if (!repeat && gap < 8)  WindowRealKeySub8++;
                if (!repeat && _lastGap >= 0 && gap < 120
                        && Math.Abs(gap - _lastGap) <= 2) {
                    _cadRun++;
                    if (_cadRun > CadRunMax) CadRunMax = _cadRun;
                    if (_cadRun > WindowCadRunMax) WindowCadRunMax = _cadRun;
                } else if (!repeat) {
                    _cadRun = 0;
                }
                _lastGap = gap;
            } else {
                _cadRun = 0; _lastGap = -1;
            }
        }
        _lastRealKeyTick = eventTime;
        _lastVk = vk;
    }

    static void Write(string kind, uint flags, string cls)
    {
        Write(kind, flags, cls, true);
    }

    // Called on the hook thread, so it only records the facts that are gone a
    // moment later (time, foreground pid) and queues them. Until 2026-10-31 it
    // opened the output file and built a Process object here, per control,
    // digit and punctuation key, inside the callback Windows times.
    static void Write(string kind, uint flags, string cls, bool injected)
    {
        uint pid = 0;
        try { GetWindowThreadProcessId(GetForegroundWindow(), out pid); } catch { }
        Enqueue(new OutItem { Ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Kind = kind,
                              Flags = flags, Cls = cls, Injected = injected, FgPid = pid });
    }

    // Every output line goes through one capped queue, written by the host's
    // worker thread in batches. A full queue drops and counts; the count rides
    // the heartbeat.
    class OutItem {
        public string Text;                    // a finished line, or null for a key line
        public long Ts; public string Kind, Cls; public uint Flags, FgPid; public bool Injected;
    }
    static readonly ConcurrentQueue<OutItem> _outq = new ConcurrentQueue<OutItem>();
    static int _outCount;
    public const int OutCap = 8192;
    public static long OutDropped;

    static void Enqueue(OutItem item)
    {
        if (Interlocked.Increment(ref _outCount) > OutCap) {
            Interlocked.Decrement(ref _outCount);
            Interlocked.Increment(ref OutDropped);
            return;
        }
        _outq.Enqueue(item);
    }

    public static void WriteState(string json)
    {
        Enqueue(new OutItem { Text = json });
    }

    public static int Pending() { return Volatile.Read(ref _outCount); }

    // Worker thread: format queued key lines (process names resolved once per
    // batch) and append the batch with one open/close. The file is truncated
    // by the WSL side after each read, so it is never held open.
    public static int FlushOut()
    {
        if (Volatile.Read(ref _outCount) == 0) return 0;
        var sb = new StringBuilder();
        var names = new Dictionary<uint, string>();
        int n = 0;
        OutItem it;
        while (n < 4096 && _outq.TryDequeue(out it)) {
            Interlocked.Decrement(ref _outCount);
            n++;
            if (it.Text != null) { sb.Append(it.Text).Append(Environment.NewLine); continue; }
            string name;
            if (!names.TryGetValue(it.FgPid, out name)) {
                name = "";
                if (it.FgPid != 0) {
                    // An owner that exited before the flush keeps its pid.
                    name = "?:" + it.FgPid;
                    try { using (var p = Process.GetProcessById((int)it.FgPid)) name = p.ProcessName + ":" + it.FgPid; }
                    catch { }
                }
                names[it.FgPid] = name;
            }
            sb.Append("{\"ts\":").Append(it.Ts)
              .Append(",\"kind\":\"").Append(it.Kind).Append("\"")
              .Append(",\"injected\":").Append(it.Injected ? 1 : 0)
              .Append(",\"lower_il\":").Append((it.Flags & LLKHF_LOWER_IL_INJECTED) != 0 ? 1 : 0)
              .Append(",\"class\":\"").Append(it.Cls).Append("\"")
              .Append(",\"fg\":\"").Append(name.Replace("\"", "")).Append("\"}")
              .Append(Environment.NewLine);
        }
        if (sb.Length > 0) {
            lock (_lock) {
                try { File.AppendAllText(_out, sb.ToString()); } catch { }
            }
        }
        return n;
    }

    // ---- forensic capture of injected keys -----------------------------------
    //
    // An injected key is software typing, not the person, so it is recorded in
    // full. The hook callback itself only copies the raw event and the facts
    // that are gone a moment later (modifier state, the layout and window in
    // focus); everything slow — process names, integrity levels, candidate
    // injectors, disk writes — happens on a background writer, because Windows
    // silently removes a low-level hook that takes too long to return.

    [DllImport("user32.dll")]
    static extern IntPtr GetKeyboardLayout(uint tid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int ToUnicodeEx(uint vk, uint scan, byte[] state, StringBuilder buf,
                                  int cch, uint flags, IntPtr hkl);
    [DllImport("user32.dll")]
    static extern short GetAsyncKeyState(int vk);
    [DllImport("user32.dll")]
    static extern short GetKeyState(int vk);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int GetKeyNameText(int lParam, StringBuilder sb, int n);
    // Reads the cached title without sending WM_GETTEXT, so a hung target
    // window cannot stall the hook.
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int InternalGetWindowText(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int GetClassName(IntPtr h, StringBuilder sb, int n);
    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int l, t, r, b; }
    [StructLayout(LayoutKind.Sequential)]
    struct GUITHREADINFO {
        public int cbSize; public uint flags;
        public IntPtr hwndActive, hwndFocus, hwndCapture, hwndMenuOwner, hwndMoveSize, hwndCaret;
        public RECT rcCaret;
    }
    [DllImport("user32.dll")]
    static extern bool GetGUIThreadInfo(uint tid, ref GUITHREADINFO g);
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll")]
    static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr tok);
    [DllImport("advapi32.dll")]
    static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int ret);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthority(IntPtr sid, uint n);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool QueryFullProcessImageName(IntPtr p, int flags, StringBuilder sb, ref int size);
    [DllImport("kernel32.dll")]
    static extern bool GetProcessTimes(IntPtr p, out long create, out long exit,
                                       out long kernel, out long user);
    [DllImport("kernel32.dll")]
    static extern bool ProcessIdToSessionId(uint pid, out uint session);

    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint TOKEN_QUERY = 0x8;
    const int TokenIntegrityLevel = 25, TokenIsAppContainer = 29;

    class InjEvent {
        public long Ms, SinceRealKey, SinceRealClick, SinceRealMove;
        public bool Down;
        public uint Vk, Scan, Flags, Tick, FgPid, FgTid;
        public ulong Extra;
        public string Chr = "", Mods = "", Title = "", WinClass = "", FocusClass = "";
    }

    static readonly ConcurrentQueue<InjEvent> _inj = new ConcurrentQueue<InjEvent>();
    static int _redactOver = 6;
    public static long InjDropped;
    static long _lastRealKeyMs, _lastRealClickMs, _lastRealMoveMs;

    static long NowMs() { return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); }

    static long Since(long now, long then) { return then == 0 ? -1 : now - then; }

    static bool Held(int vk) { return (GetAsyncKeyState(vk) & 0x8000) != 0; }

    static string Mods()
    {
        var m = new List<string>();
        if (Held(0x10)) m.Add("shift");
        if (Held(0x11)) m.Add("ctrl");
        if (Held(0x12)) m.Add("alt");
        if (Held(0x5B) || Held(0x5C)) m.Add("win");
        if ((GetKeyState(0x14) & 1) != 0) m.Add("capslock");
        return string.Join("+", m);
    }

    // The character this key produces in the focused window, under that
    // window's own keyboard layout and the modifiers held right now. Flag 0x4
    // tells ToUnicodeEx not to touch the kernel keyboard state, so translating
    // here cannot eat a dead key the user is composing.
    static string CharFor(uint vk, uint scan, uint fgTid)
    {
        // VK_PACKET is SendInput with KEYEVENTF_UNICODE: there is no key at all,
        // and the scan code field carries the UTF-16 unit itself.
        if (vk == 0xE7) return ((char)(scan & 0xFFFF)).ToString();
        try {
            var state = new byte[256];
            if (Held(0x10)) state[0x10] = 0x80;
            if (Held(0x11)) state[0x11] = 0x80;
            if (Held(0x12)) state[0x12] = 0x80;
            if ((GetKeyState(0x14) & 1) != 0) state[0x14] = 0x01;
            var sb = new StringBuilder(16);
            int n = ToUnicodeEx(vk, scan, state, sb, sb.Capacity, 0x4, GetKeyboardLayout(fgTid));
            string r = sb.ToString();
            if (n > 0) return r.Length > n ? r.Substring(0, n) : r;
            if (n < 0) return "dead:" + (r.Length > 0 ? r.Substring(0, 1) : "");
        } catch { }
        return "";
    }

    static void Capture(KBDLLHOOKSTRUCT d, bool down)
    {
        // A runaway injector must not grow memory without bound; the counters
        // above still count every event, and the drop is reported.
        if (_inj.Count > 20000) { Interlocked.Increment(ref InjDropped); return; }
        var e = new InjEvent();
        e.Ms = NowMs(); e.Down = down;
        e.Vk = d.vkCode; e.Scan = d.scanCode; e.Flags = d.flags; e.Tick = d.time;
        e.Extra = unchecked((ulong)d.dwExtraInfo.ToInt64());
        e.SinceRealKey = Since(e.Ms, _lastRealKeyMs);
        e.SinceRealClick = Since(e.Ms, _lastRealClickMs);
        e.SinceRealMove = Since(e.Ms, _lastRealMoveMs);
        try {
            IntPtr fg = GetForegroundWindow();
            e.FgTid = GetWindowThreadProcessId(fg, out e.FgPid);
            var sb = new StringBuilder(256);
            InternalGetWindowText(fg, sb, sb.Capacity); e.Title = sb.ToString();
            sb.Length = 0; GetClassName(fg, sb, sb.Capacity); e.WinClass = sb.ToString();
            var gi = new GUITHREADINFO(); gi.cbSize = Marshal.SizeOf(typeof(GUITHREADINFO));
            if (GetGUIThreadInfo(e.FgTid, ref gi) && gi.hwndFocus != IntPtr.Zero) {
                sb.Length = 0; GetClassName(gi.hwndFocus, sb, sb.Capacity);
                e.FocusClass = sb.ToString();
            }
        } catch { }
        e.Mods = Mods();
        if (down) e.Chr = CharFor(d.vkCode, d.scanCode, e.FgTid);
        _inj.Enqueue(e);
    }

    static string VkName(uint vk)
    {
        if ((vk >= 0x41 && vk <= 0x5A) || (vk >= 0x30 && vk <= 0x39)) return "VK_" + (char)vk;
        if (vk >= 0x60 && vk <= 0x69) return "VK_NUMPAD" + (vk - 0x60);
        if (vk >= 0x70 && vk <= 0x87) return "VK_F" + (vk - 0x6F);
        switch (vk) {
            case 0x08: return "VK_BACK";     case 0x09: return "VK_TAB";
            case 0x0D: return "VK_RETURN";   case 0x10: return "VK_SHIFT";
            case 0x11: return "VK_CONTROL";  case 0x12: return "VK_MENU";
            case 0x13: return "VK_PAUSE";    case 0x14: return "VK_CAPITAL";
            case 0x1B: return "VK_ESCAPE";   case 0x20: return "VK_SPACE";
            case 0x21: return "VK_PRIOR";    case 0x22: return "VK_NEXT";
            case 0x23: return "VK_END";      case 0x24: return "VK_HOME";
            case 0x25: return "VK_LEFT";     case 0x26: return "VK_UP";
            case 0x27: return "VK_RIGHT";    case 0x28: return "VK_DOWN";
            case 0x2C: return "VK_SNAPSHOT"; case 0x2D: return "VK_INSERT";
            case 0x2E: return "VK_DELETE";   case 0x5B: return "VK_LWIN";
            case 0x5C: return "VK_RWIN";     case 0x5D: return "VK_APPS";
            case 0xA0: return "VK_LSHIFT";   case 0xA1: return "VK_RSHIFT";
            case 0xA2: return "VK_LCONTROL"; case 0xA3: return "VK_RCONTROL";
            case 0xA4: return "VK_LMENU";    case 0xA5: return "VK_RMENU";
            case 0xBA: return "VK_OEM_1";    case 0xBB: return "VK_OEM_PLUS";
            case 0xBC: return "VK_OEM_COMMA"; case 0xBD: return "VK_OEM_MINUS";
            case 0xBE: return "VK_OEM_PERIOD"; case 0xBF: return "VK_OEM_2";
            case 0xC0: return "VK_OEM_3";    case 0xDB: return "VK_OEM_4";
            case 0xDC: return "VK_OEM_5";    case 0xDD: return "VK_OEM_6";
            case 0xDE: return "VK_OEM_7";    case 0xE5: return "VK_PROCESSKEY";
            case 0xE7: return "VK_PACKET";   case 0xFF: return "VK_NONE";
        }
        return "VK_0x" + vk.ToString("X2");
    }

    static string KeyName(InjEvent e)
    {
        try {
            int lp = (int)((e.Scan & 0xFF) << 16);
            if ((e.Flags & 0x01) != 0) lp |= 1 << 24;          // LLKHF_EXTENDED
            var sb = new StringBuilder(64);
            GetKeyNameText(lp, sb, sb.Capacity);
            return sb.ToString();
        } catch { return ""; }
    }

    static bool Printable(InjEvent e)
    {
        return e.Down && e.Chr.Length > 0 && !e.Chr.StartsWith("dead:")
            && e.Chr[0] >= 0x20 && e.Chr[0] != 0x7F;
    }

    static string Esc(string s)
    {
        if (s == null) return "";
        var o = new StringBuilder(s.Length + 8);
        foreach (char c in s) {
            if (c == '"' || c == '\\') o.Append('\\').Append(c);
            else if (c < 0x20 || c > 0x7E) o.Append("\\u").Append(((int)c).ToString("x4"));
            else o.Append(c);
        }
        return o.ToString();
    }

    class J {
        readonly StringBuilder _b = new StringBuilder("{");
        bool _first = true;
        void Key(string k) {
            if (!_first) _b.Append(',');
            _first = false;
            _b.Append('"').Append(k).Append("\":");
        }
        public J S(string k, string v) { Key(k); _b.Append('"').Append(Esc(v)).Append('"'); return this; }
        public J N(string k, long v) { Key(k); _b.Append(v); return this; }
        public J Raw(string k, string json) { Key(k); _b.Append(json); return this; }
        public string Done() { return _b.Append('}').ToString(); }
    }

    static string IlName(int rid)
    {
        if (rid < 0) return "unknown";
        if (rid < 0x1000) return "untrusted";
        if (rid < 0x2000) return "low";
        if (rid < 0x3000) return "medium";
        if (rid < 0x4000) return "high";
        return "system";
    }

    static int Integrity(IntPtr proc)
    {
        IntPtr tok;
        if (!OpenProcessToken(proc, TOKEN_QUERY, out tok)) return -1;
        try {
            int len;
            GetTokenInformation(tok, TokenIntegrityLevel, IntPtr.Zero, 0, out len);
            if (len <= 0) return -1;
            IntPtr buf = Marshal.AllocHGlobal(len);
            try {
                if (!GetTokenInformation(tok, TokenIntegrityLevel, buf, len, out len)) return -1;
                IntPtr sid = Marshal.ReadIntPtr(buf);
                int count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                return Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(tok); }
    }

    static bool IsAppContainer(IntPtr proc)
    {
        IntPtr tok;
        if (!OpenProcessToken(proc, TOKEN_QUERY, out tok)) return false;
        IntPtr buf = Marshal.AllocHGlobal(4);
        try {
            int len;
            return GetTokenInformation(tok, TokenIsAppContainer, buf, 4, out len)
                && Marshal.ReadInt32(buf) != 0;
        } finally { Marshal.FreeHGlobal(buf); CloseHandle(tok); }
    }

    static string ImagePath(IntPtr proc)
    {
        var sb = new StringBuilder(1024); int size = sb.Capacity;
        return QueryFullProcessImageName(proc, 0, sb, ref size) ? sb.ToString() : "";
    }

    // One process, described the way the burst needs it. Returns null if the
    // process cannot be opened even for limited query.
    static J Describe(int pid, long burstMs)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try {
            int rid = Integrity(h);
            long create, exit, kernel, user, startedMs = 0;
            if (GetProcessTimes(h, out create, out exit, out kernel, out user) && create > 0)
                startedMs = new DateTimeOffset(DateTime.FromFileTimeUtc(create)).ToUnixTimeMilliseconds();
            string name = "";
            try { using (var p = Process.GetProcessById(pid)) name = p.ProcessName; } catch { }
            return new J().N("pid", pid).S("name", name).S("il", IlName(rid))
                .N("appcontainer", IsAppContainer(h) ? 1 : 0)
                .N("started_ms_before", startedMs == 0 ? -1 : burstMs - startedMs)
                .S("path", ImagePath(h));
        } catch { return null; }
        finally { CloseHandle(h); }
    }

    // Who could have sent it. Windows does not record the sending process, so
    // this is a suspect list, not an attribution: processes in the desktop
    // session that run below medium integrity (when the event says it came from
    // a lower integrity level) and anything that started in the two minutes
    // before the burst.
    static string Candidates(long burstMs, uint fgPid, bool lowerIl)
    {
        var sb = new StringBuilder("[");
        uint fgSession;
        if (!ProcessIdToSessionId(fgPid, out fgSession)) fgSession = uint.MaxValue;
        int n = 0;
        Process[] all;
        try { all = Process.GetProcesses(); } catch { return "[]"; }
        foreach (var p in all) {
            try {
                if (n >= 80) continue;
                int pid = p.Id;
                uint sess;
                if (fgSession != uint.MaxValue &&
                    (!ProcessIdToSessionId((uint)pid, out sess) || sess != fgSession)) continue;
                IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) continue;
                int rid; long startedMs = 0;
                try {
                    rid = Integrity(h);
                    long create, exit, kernel, user;
                    if (GetProcessTimes(h, out create, out exit, out kernel, out user) && create > 0)
                        startedMs = new DateTimeOffset(DateTime.FromFileTimeUtc(create)).ToUnixTimeMilliseconds();
                } finally { CloseHandle(h); }
                long age = startedMs == 0 ? -1 : burstMs - startedMs;
                bool recent = startedMs != 0 && age >= -2000 && age <= 120000;
                bool low = rid >= 0 && rid < 0x2000;
                if (!(recent || (lowerIl && low))) continue;
                J d = Describe(pid, burstMs);
                if (d == null) continue;
                d.S("why", recent && low ? "lower-integrity,started-recently"
                                         : recent ? "started-recently" : "lower-integrity");
                if (n++ > 0) sb.Append(',');
                sb.Append(d.Done());
            } catch { }
            finally { p.Dispose(); }
        }
        return sb.Append(']').ToString();
    }

    static readonly List<InjEvent> _pendingInj = new List<InjEvent>();

    // One step of the injected-burst writer; the host's worker calls it every
    // 100 ms (it had a thread of its own until 2026-10-31).
    public static void PumpInjected()
    {
        try {
            InjEvent e;
            while (_inj.TryDequeue(out e)) _pendingInj.Add(e);
            // A burst ends after 800 ms of silence, which keeps one paste or
            // one auto-type together and separates unrelated phantoms.
            if (_pendingInj.Count > 0 &&
                    (NowMs() - _pendingInj[_pendingInj.Count - 1].Ms > 800 || _pendingInj.Count >= 2000)) {
                Flush(_pendingInj);
                _pendingInj.Clear();
            }
        } catch { _pendingInj.Clear(); }
    }

    static void Flush(List<InjEvent> ev)
    {
        InjEvent first = ev[0], last = ev[ev.Count - 1];
        string burst = first.Ms + "-" + first.Tick;
        int downs = 0, ups = 0, printable = 0, upper = 0, lower = 0, digit = 0, space = 0, symbol = 0;
        bool anyLowerIl = false;
        var text = new StringBuilder();
        var extras = new List<string>();
        var held = new Dictionary<uint, int>();
        var secretVks = new HashSet<uint>();
        foreach (var e in ev) {
            if ((e.Flags & LLKHF_LOWER_IL_INJECTED) != 0) anyLowerIl = true;
            string x = "0x" + e.Extra.ToString("X");
            if (!extras.Contains(x) && extras.Count < 8) extras.Add(x);
            int c;
            held.TryGetValue(e.Vk, out c);
            if (e.Down) { downs++; held[e.Vk] = c + 1; }
            else { ups++; held[e.Vk] = c - 1; }
            if (!Printable(e)) continue;
            printable++;
            secretVks.Add(e.Vk);
            text.Append(e.Chr);
            char ch = e.Chr[0];
            if (char.IsUpper(ch)) upper++;
            else if (char.IsLower(ch)) lower++;
            else if (char.IsDigit(ch)) digit++;
            else if (char.IsWhiteSpace(ch)) space++;
            else symbol++;
        }
        bool redact = _redactOver >= 0 && printable > _redactOver;
        var unmatched = new List<string>();
        foreach (var kv in held)
            if (kv.Value != 0 && !(redact && secretVks.Contains(kv.Key)))
                unmatched.Add("\"" + VkName(kv.Key) + (kv.Value > 0 ? " down-without-up" : " up-without-down") + "\"");

        string fgName = "";
        try { using (var p = Process.GetProcessById((int)first.FgPid)) fgName = p.ProcessName; } catch { }
        string fg = first.FgPid == 0 ? "" : fgName + ":" + first.FgPid;

        int seq = 0;
        foreach (var e in ev) {
            if (seq >= 400) break;
            bool hide = redact && Printable(e);
            string cls = KeyClass(e.Vk);
            if (hide && cls.StartsWith("digit-")) cls = "digit";
            var j = new J()
                .N("ts", e.Ms / 1000).S("kind", e.Down ? "key" : "key-up")
                .N("injected", 1)
                .N("lower_il", (e.Flags & LLKHF_LOWER_IL_INJECTED) != 0 ? 1 : 0)
                .S("class", cls).S("fg", fg.Replace("\"", ""))
                .N("ms", e.Ms).S("burst", burst).N("seq", seq++)
                .N("vk", hide ? -1L : (long)e.Vk).S("vk_name", hide ? "" : VkName(e.Vk))
                .N("scan", hide ? -1L : (long)e.Scan).S("key_name", hide ? "" : KeyName(e))
                .S("chr", hide ? "" : e.Chr).N("redacted", hide ? 1 : 0)
                .S("mods", e.Mods).S("flags", "0x" + e.Flags.ToString("X2"))
                .N("extended", (e.Flags & 0x01) != 0 ? 1 : 0)
                .N("alt_down", (e.Flags & 0x20) != 0 ? 1 : 0)
                .S("extra", "0x" + e.Extra.ToString("X")).N("event_tick", e.Tick);
            WriteState(j.Done());
        }

        var comp = new J().N("upper", upper).N("lower", lower).N("digit", digit)
            .N("space", space).N("symbol", symbol);
        var fgProc = first.FgPid == 0 ? null : Describe((int)first.FgPid, first.Ms);
        var summary = new J()
            .N("ts", first.Ms / 1000).S("kind", "inject-burst").S("burst", burst)
            .N("ms_start", first.Ms).N("ms_end", last.Ms)
            .N("events", ev.Count).N("downs", downs).N("ups", ups)
            .N("printable", printable).N("redacted", redact ? 1 : 0)
            .S("text", redact ? "" : text.ToString()).Raw("composition", comp.Done())
            .N("lower_il", anyLowerIl ? 1 : 0)
            .Raw("extra_values", "[\"" + string.Join("\",\"", extras) + "\"]")
            .Raw("unmatched", "[" + string.Join(",", unmatched) + "]")
            .S("fg", fg.Replace("\"", "")).S("fg_title", first.Title)
            .S("fg_class", first.WinClass).S("focus_class", first.FocusClass)
            .Raw("fg_process", fgProc == null ? "null" : fgProc.Done())
            .N("ms_since_real_key", first.SinceRealKey)
            .N("ms_since_real_click", first.SinceRealClick)
            .N("ms_since_real_move", first.SinceRealMove)
            .N("dropped_total", Interlocked.Read(ref InjDropped))
            .Raw("candidates", Candidates(first.Ms, first.FgPid, anyLowerIl));
        WriteState(summary.Done());
    }

    // Tick of the newest callback of either hook: compared with the session's
    // last-input time, it shows input the hooks never saw.
    public static int LastCallbackTick, LastKbTick, LastMsTick;

    static IntPtr KbProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        LastCallbackTick = LastKbTick = Environment.TickCount;
        if (nCode >= 0) {
            var d = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
            int msg = (int)wParam;
            bool down = (msg == 0x0100 || msg == 0x0104);
            bool up   = (msg == 0x0101 || msg == 0x0105);
            bool injected = (d.flags & LLKHF_INJECTED) != 0;
            if (down || up) Latency(d.time);
            if (down) {
                string ctl = ControlClass(d.vkCode);
                if (ctl.Length > 0) {
                    ControlKeys++;
                    if (injected) ControlKeysInjected++;
                    _lastCtrlTick = (uint)Environment.TickCount;
                    Write("control-key", d.flags, ctl, injected);
                }
                if (injected) {
                    InjectedKeys++;
                    WindowInjectedKeys++;
                    Capture(d, true);
                } else {
                    RealKeys++;
                    WindowRealKeys++;
                    _lastRealKeyMs = NowMs();
                    Cadence(d.time, d.vkCode);
                    // Watched real-key families are already counted in
                    // aggregate. Timestamping them adds resolution, not a
                    // general content log: a phantom "." or "3" gets a time,
                    // a foreground window and a real/injected verdict, and
                    // letters / other symbols stay anonymous counts only.
                    string pc = KeyClass(d.vkCode);
                    if (pc == "period-greater" || pc == "slash-question" ||
                        pc == "equals-plus") {
                        Write("punct-key", d.flags, pc, false);
                    } else if (IsDigitClass(pc)) {
                        Write("digit-key", d.flags, pc, false);
                    }
                }
            } else if (up && injected) {
                InjectedKeyUps++;
                Capture(d, false);
            }
        }
        return CallNextHookEx(_kb, nCode, wParam, lParam);
    }

    static IntPtr MsProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        LastCallbackTick = LastMsTick = Environment.TickCount;
        if (nCode >= 0) {
            var d = (MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(MSLLHOOKSTRUCT));
            int msg = (int)wParam;
            bool click = (msg == 0x0201 || msg == 0x0204);
            bool move  = (msg == 0x0200);
            bool inj   = (d.flags & 0x01) != 0;       // LLMHF_INJECTED

            if (move) {
                Latency(d.time);
                if (inj) {
                    InjectedMoves++;
                    // Movement is continuous, so a line per event would be
                    // megabytes. Write one at the start of every burst — a run
                    // broken by a >400 ms gap — so a brief synthetic reposition
                    // is caught, not just multiples of 250. Keep the every-250
                    // sample as a heartbeat inside a long continuous burst.
                    long since = _lastInjMoveTick == 0
                        ? 999999 : (long)(d.time - _lastInjMoveTick);
                    if (since > 400) {
                        InjectedMoveBursts++;
                        Write("move", d.flags, "cursor");
                    } else if (InjectedMoves % 250 == 0) {
                        Write("move", d.flags, "cursor");
                    }
                    _lastInjMoveTick = d.time;
                } else {
                    RealMoves++;
                    _lastRealMoveMs = NowMs();
                }
            } else if (click) {
                Latency(d.time);
                if (inj) {
                    InjectedClicks++;
                    Write("click", d.flags, "button");
                } else {
                    RealClicks++;
                    _lastRealClickMs = NowMs();
                }
            }
        }
        return CallNextHookEx(_ms, nCode, wParam, lParam);
    }

    public static void Start(string outFile, int redactOver)
    {
        _out = outFile;
        _redactOver = redactOver;
        LastCallbackTick = Environment.TickCount;
        _kbProc = KbProc;
        _msProc = MsProc;
        IntPtr mod = GetModuleHandle(null);
        _kb = SetWindowsHookEx(WH_KEYBOARD_LL, _kbProc, mod, 0);
        _ms = SetWindowsHookEx(WH_MOUSE_LL,    _msProc, mod, 0);
        if (_kb == IntPtr.Zero) throw new Exception("SetWindowsHookEx (keyboard) failed");
    }

    [DllImport("user32.dll")]
    static extern bool UnhookWindowsHookEx(IntPtr hk);

    // Windows removes a low-level hook without notice when its thread overruns
    // LowLevelHooksTimeout. Must run on the thread that installed the hooks
    // (the one pumping messages). Returns true if the keyboard hook is back.
    public static bool Reinstall()
    {
        // New hooks first, then the old ones go: there is no instant with no
        // hook. If Windows already removed the old one, unhooking it is a no-op.
        IntPtr mod = GetModuleHandle(null);
        IntPtr kb = SetWindowsHookEx(WH_KEYBOARD_LL, _kbProc, mod, 0);
        IntPtr ms = SetWindowsHookEx(WH_MOUSE_LL,    _msProc, mod, 0);
        if (kb != IntPtr.Zero) { if (_kb != IntPtr.Zero) UnhookWindowsHookEx(_kb); _kb = kb; }
        if (ms != IntPtr.Zero) { if (_ms != IntPtr.Zero) UnhookWindowsHookEx(_ms); _ms = ms; }
        return kb != IntPtr.Zero;
    }

    public static string Counters()
    {
        long avg = LatSamples > 0 ? LatTotalMs / LatSamples : 0;
        return "{\"real_keys\":" + RealKeys + ",\"injected_keys\":" + InjectedKeys +
               ",\"real_clicks\":" + RealClicks + ",\"injected_clicks\":" + InjectedClicks +
               ",\"real_moves\":" + RealMoves + ",\"injected_moves\":" + InjectedMoves +
               ",\"injected_keyups\":" + InjectedKeyUps +
               ",\"injected_move_bursts\":" + InjectedMoveBursts +
               ",\"real_key_gaps\":" + RealKeyGaps +
               ",\"real_key_sub20\":" + RealKeySub20 +
               ",\"real_key_sub8\":" + RealKeySub8 +
               ",\"cad_run_max\":" + CadRunMax +
               ",\"lat_avg_ms\":" + avg + ",\"lat_max_ms\":" + LatMaxMs +
               ",\"lat_over50\":" + LatOver50 + ",\"lat_samples\":" + LatSamples + "}";
    }

    public static string TakeWindowCounters()
    {
        lock (_lock) {
            string value = "{\"real_keys\":" + WindowRealKeys +
                ",\"injected_keys\":" + WindowInjectedKeys +
                ",\"real_key_gaps\":" + WindowRealKeyGaps +
                ",\"real_key_sub20\":" + WindowRealKeySub20 +
                ",\"real_key_sub8\":" + WindowRealKeySub8 +
                ",\"cad_run_max\":" + WindowCadRunMax +
                ",\"equals_keys\":" + WindowEqualsKeys +
                ",\"slash_keys\":" + WindowSlashKeys +
                ",\"period_keys\":" + WindowPeriodKeys +
                ",\"digit_keys\":" + WindowDigitKeys + "}";
            WindowRealKeys = WindowInjectedKeys = 0;
            WindowRealKeyGaps = WindowRealKeySub20 = WindowRealKeySub8 = 0;
            WindowCadRunMax = 0;
            WindowEqualsKeys = WindowSlashKeys = WindowPeriodKeys = 0;
            WindowDigitKeys = 0;
            return value;
        }
    }
}

// The resident host (2026-10-31). Before it, five WinForms timers ran
// PowerShell code on the hook thread every 1-60 s and a second runspace looped
// for brightness: the interpreter woke several times a second for the life of
// the process, and every tick delayed the hook. Now the PowerShell launcher
// calls Run() once and never runs script again:
//   hook thread   installs the hooks, pumps messages, answers pings; nothing else
//   worker thread everything periodic, each task isolated, one output writer
// The sound listener keeps its own 25 ms metering thread.
public static class JarvisHost
{
    [StructLayout(LayoutKind.Sequential)]
    struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam, lParam; public uint time; public int x, y; }
    [StructLayout(LayoutKind.Sequential)]
    struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
    [DllImport("user32.dll")] static extern int GetMessage(out MSG m, IntPtr h, uint min, uint max);
    [DllImport("user32.dll")] static extern bool PeekMessage(out MSG m, IntPtr h, uint min, uint max, uint remove);
    [DllImport("user32.dll")] static extern bool PostThreadMessage(uint tid, uint msg, IntPtr w, IntPtr l);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LASTINPUTINFO li);
    [DllImport("user32.dll")] static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern bool GetUserObjectInformation(IntPtr h, int index, StringBuilder buf, int len, out int needed);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll")] static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr tok);
    [DllImport("advapi32.dll")] static extern bool GetTokenInformation(IntPtr tok, int cls, out int value, int len, out int ret);

    const uint WM_APP_PING = 0x8001, WM_APP_REHOOK = 0x8002;
    public const int DeafGapMs = 2000;          // input this much newer than the last callback
    public const int DeafPasses = 2;            // on consecutive 1 s checks, on the user's desktop
    public const int RehookMinGapMs = 30000;    // at most one reinstall per 30 s
    public const int PongStaleMs = 15000;       // hook thread silent this long: no pulse

    static uint _hookTid;
    static int _pongTick;
    static string _out, _alive;
    static int _heartbeatMs, _ownSession;

    // watchdog state (worker thread only, except the counters read by Hook())
    static int _deafPasses, _lastRehookTick, _rehookPending;
    static uint _prevInput;
    static bool _stillReported;
    public static long Reinstalls, ReinstallFailures, DeafEpisodes, DeafUnrecovered;
    static long _lastReinstallTs;

    // optional parts, bound by reflection so one that failed to compile leaves the rest running
    static Func<int[]> _audioRead; static Func<int> _audioLevel; static Func<bool> _audioMuted;
    static Func<string[]> _audioSessions;
    static Func<string> _soundTake, _soundCounters;
    static string _soundState = "{\"state\":\"unavailable: listener did not compile\"}";

    public static void Run(string outFile, int heartbeatSeconds)
    {
        _out = outFile;
        _alive = Path.ChangeExtension(outFile, ".alive");
        _heartbeatMs = Math.Max(5, heartbeatSeconds) * 1000;
        using (var me = Process.GetCurrentProcess()) _ownSession = me.SessionId;
        _hookTid = GetCurrentThreadId();
        MSG m;
        PeekMessage(out m, IntPtr.Zero, 0, 0, 0);   // creates this thread's queue before anyone posts to it
        _pongTick = Environment.TickCount;
        Bind();
        var w = new Thread(Worker);
        w.IsBackground = true; w.Name = "jarvis-host-worker";
        w.Start();
        // Startup garbage (compilation, binding) is collected once; nothing
        // periodic allocates on this thread afterwards.
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        while (GetMessage(out m, IntPtr.Zero, 0, 0) > 0) {
            if (m.hwnd != IntPtr.Zero) continue;
            if (m.message == WM_APP_PING) { _pongTick = Environment.TickCount; }
            else if (m.message == WM_APP_REHOOK) {
                bool ok = false;
                try { ok = JarvisInputHook.Reinstall(); } catch { }
                if (ok) Interlocked.Increment(ref Reinstalls); else Interlocked.Increment(ref ReinstallFailures);
                Interlocked.Exchange(ref _rehookPending, 0);
            }
        }
    }

    static MethodInfo Find(string type, string method)
    {
        // Explicit types and the two-argument GetMethod keep every metadata
        // name of this assembly visible in the script text, which is how memscan
        // recognises JARVIS's own in-memory code (collectors/process/assemblies.py).
        foreach (Assembly a in AppDomain.CurrentDomain.GetAssemblies()) {
            Type t = null;
            try { t = a.GetType(type, false); } catch { }
            if (t != null) {
                try { return t.GetMethod(method, BindingFlags.Public | BindingFlags.Static); }
                catch (AmbiguousMatchException) { return null; }
            }
        }
        return null;
    }

    static T Bind<T>(string type, string method) where T : class
    {
        var mi = Find(type, method);
        if (mi == null) return null;
        try { return Delegate.CreateDelegate(typeof(T), mi, false) as T; } catch { return null; }
    }

    static void Bind()
    {
        _audioRead = Bind<Func<int[]>>("JarvisAudio", "Read");
        _audioLevel = Bind<Func<int>>("JarvisAudio", "Level");
        _audioMuted = Bind<Func<bool>>("JarvisAudio", "Muted");
        _audioSessions = Bind<Func<string[]>>("JarvisAudio", "Sessions");
        var start = Bind<Action>("JarvisSound.Listener", "Start");
        _soundTake = Bind<Func<string>>("JarvisSound.Listener", "Take");
        _soundCounters = Bind<Func<string>>("JarvisSound.Listener", "Counters");
        if (start != null && _soundTake != null && _soundCounters != null) {
            try { start(); _soundState = null; }
            catch { _soundState = "{\"state\":\"unavailable: listener did not start\"}"; _soundTake = null; }
        }
    }

    // ---- the worker ---------------------------------------------------------
    static void Worker()
    {
        int t0 = Environment.TickCount;
        int next1s = t0, next2s = t0, nextPulse = t0, nextBeat = t0 + _heartbeatMs;
        Step("pulse", Pulse);
        Step("audio", SampleAudio); Step("apps", SampleApps);
        while (true) {
            int now = Environment.TickCount;
            Step("injected", JarvisInputHook.PumpInjected);
            if (now - next1s >= 0) {
                next1s = now + 1000;
                PostThreadMessage(_hookTid, WM_APP_PING, IntPtr.Zero, IntPtr.Zero);
                Step("audio", SampleAudio); Step("sound", DrainSound); Step("watchdog", Watchdog);
            }
            if (now - next2s >= 0) { next2s = now + 2000; Step("apps", SampleApps); Step("brightness", SampleBrightness); }
            if (now - nextBeat >= 0) { nextBeat = now + _heartbeatMs; Step("heartbeat", Heartbeat); }
            if (now - nextPulse >= 0) { nextPulse = now + 10000; Step("pulse", Pulse); }
            // Anything queued is on disk within one 100 ms tick: the old hook
            // appended each line synchronously, so a kill must not cost more.
            if (JarvisInputHook.Pending() > 0) Step("flush", Flush);
            Thread.Sleep(100);
        }
    }

    public static long TaskFaults;
    static string _lastFault = "";
    // A task that throws is counted and named in the heartbeat; it never stops
    // the worker or the other tasks.
    static void Flush() { JarvisInputHook.FlushOut(); }

    static void Step(string task, Action a)
    {
        try { a(); }
        catch (Exception e) {
            Interlocked.Increment(ref TaskFaults);
            var b = new StringBuilder();
            foreach (char c in (task + ": " + e.GetType().FullName + " " + e.Message))
                if (c >= 32 && c < 127 && c != '"' && c != '\\' && b.Length < 160) b.Append(c);
            _lastFault = b.ToString();
        }
    }

    // A contentless liveness beat, read by the WSL watchdog as a file mtime.
    // Written only while the hook thread answers pings, so a wedged message
    // loop stops it exactly as before, and a dead worker stops it too.
    static void Pulse()
    {
        if (Environment.TickCount - Volatile.Read(ref _pongTick) > PongStaleMs) return;
        File.WriteAllText(_alive, Process.GetCurrentProcess().Id + ":" + DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    static void Heartbeat()
    {
        long ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        int desk = -1;
        var shells = Process.GetProcessesByName("explorer");
        try { if (shells.Length > 0) desk = shells[0].SessionId; }
        finally { foreach (var p in shells) p.Dispose(); }
        string snd = _soundState ?? _soundCounters();
        int pid;
        using (var me = Process.GetCurrentProcess()) pid = me.Id;
        JarvisInputHook.WriteState("{\"ts\":" + ts + ",\"kind\":\"heartbeat\",\"pid\":" + pid +
            ",\"session\":" + _ownSession + ",\"desktop\":" + desk +
            ",\"counters\":" + JarvisInputHook.Counters() +
            ",\"window\":" + JarvisInputHook.TakeWindowCounters() +
            ",\"sound\":" + snd + ",\"hook\":" + Hook() + "}");
    }

    public static string Hook()
    {
        long priv = 0;
        using (var me = Process.GetCurrentProcess()) priv = me.PrivateMemorySize64;
        return "{\"reinstalls\":" + Interlocked.Read(ref Reinstalls) +
               ",\"reinstall_failures\":" + Interlocked.Read(ref ReinstallFailures) +
               ",\"deaf_episodes\":" + Interlocked.Read(ref DeafEpisodes) +
               ",\"deaf_unrecovered\":" + Interlocked.Read(ref DeafUnrecovered) +
               ",\"last_reinstall\":" + Interlocked.Read(ref _lastReinstallTs) +
               ",\"out_dropped\":" + Interlocked.Read(ref JarvisInputHook.OutDropped) +
               ",\"task_faults\":" + Interlocked.Read(ref TaskFaults) +
               ",\"last_fault\":\"" + _lastFault + "\"" +
               ",\"private_mb\":" + (priv >> 20) + "}";
    }

    // ---- deafness watchdog ----------------------------------------------------
    static uint LastInputTick()
    {
        var li = new LASTINPUTINFO(); li.cbSize = (uint)Marshal.SizeOf(li);
        return GetLastInputInfo(ref li) ? li.dwTime : 0;
    }

    // Input on the secure desktop (lock screen, UAC prompt) never reaches a
    // hook on the user's desktop, and must not read as deafness.
    static bool OnUserDesktop()
    {
        IntPtr h = OpenInputDesktop(0, false, 0x0001);
        if (h == IntPtr.Zero) return false;
        try {
            var sb = new StringBuilder(64); int need;
            return GetUserObjectInformation(h, 2, sb, sb.Capacity * 2, out need)
                && string.Equals(sb.ToString(), "Default", StringComparison.OrdinalIgnoreCase);
        } finally { CloseDesktop(h); }
    }

    // UIPI: a normal-integrity hook is not called for input to an elevated
    // window (an administrator terminal, the UAC-launched installer), the same
    // way it is not called on the secure desktop. Unknown counts as elevated:
    // a process whose token cannot be opened is above us.
    static bool ForegroundElevated()
    {
        uint pid;
        GetWindowThreadProcessId(GetForegroundWindow(), out pid);
        if (pid == 0) return true;
        IntPtr p = OpenProcess(0x1000, false, (int)pid);
        if (p == IntPtr.Zero) return true;
        try {
            IntPtr tok;
            if (!OpenProcessToken(p, 0x8, out tok)) return true;
            try {
                int elevated, ret;
                return !GetTokenInformation(tok, 20, out elevated, 4, out ret) || elevated != 0;
            } finally { CloseHandle(tok); }
        } finally { CloseHandle(p); }
    }

    // Pure decision, unit-tested: consecutive deaf passes after this one. A
    // pass counts only when NEW input arrived since the previous check and the
    // hooks saw none of it: an old unseen gap with no input since is not
    // evidence (2026-10-31: judging the same frozen gap every 30 s while the
    // owner was idle reinstalled the hook seven times in five minutes).
    public static int DeafStep(int passes, uint lastInput, uint prevInput, int lastCallback, bool watchable)
    {
        if (lastInput == 0 || !watchable || lastInput == prevInput) return 0;
        int gap = unchecked((int)(lastInput - (uint)lastCallback));
        return gap > DeafGapMs ? passes + 1 : 0;
    }

    static void Watchdog()
    {
        uint li = LastInputTick();
        int cb = Volatile.Read(ref JarvisInputHook.LastCallbackTick);
        bool watchable = li != 0 && li != _prevInput && OnUserDesktop() && !ForegroundElevated();
        _deafPasses = DeafStep(_deafPasses, li, _prevInput, cb, watchable);
        _prevInput = li;
        if (_deafPasses == 0) { _stillReported = false; return; }
        if (_deafPasses < DeafPasses || Volatile.Read(ref _rehookPending) != 0) return;
        int now = Environment.TickCount;
        if (_lastRehookTick != 0 && now - _lastRehookTick < RehookMinGapMs) {
            // New input still unseen after a reinstall: once per episode.
            if (!_stillReported) { Report("still-deaf", li, cb, ref DeafUnrecovered); _stillReported = true; }
            return;
        }
        _lastRehookTick = now;
        _deafPasses = 0;                 // a new episode needs fresh evidence
        Interlocked.Exchange(ref _rehookPending, 1);
        Report("reinstalling", li, cb, ref DeafEpisodes);
        Interlocked.Exchange(ref _lastReinstallTs, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        if (!PostThreadMessage(_hookTid, WM_APP_REHOOK, IntPtr.Zero, IntPtr.Zero))
            Interlocked.Exchange(ref _rehookPending, 0);
    }

    static void Report(string state, uint li, int cb, ref long counter)
    {
        Interlocked.Increment(ref counter);
        long gap = unchecked((int)(li - (uint)cb));
        // Which hook went quiet: decides between a dropped hook and input one
        // of them is never shown (a hook installed later that swallows keys,
        // touch or pen input that bypasses the mouse hook).
        long kb = unchecked((int)(li - (uint)Volatile.Read(ref JarvisInputHook.LastKbTick)));
        long ms = unchecked((int)(li - (uint)Volatile.Read(ref JarvisInputHook.LastMsTick)));
        JarvisInputHook.WriteState("{\"ts\":" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() +
            ",\"kind\":\"hook-state\",\"state\":\"" + state + "\",\"unseen_ms\":" + gap +
            ",\"kb_quiet_ms\":" + kb + ",\"mouse_quiet_ms\":" + ms +
            ",\"fg\":\"" + JarvisInputHook.Foreground().Replace("\"", "") + "\"}");
    }

    // ---- samplers (the logic of the former PowerShell timers, unchanged) --------
    static int _lastVol = -1; static bool _lastMute;

    static string Keyed(out long gap)
    {
        gap = JarvisInputHook.MsSinceControlKey();
        // 1500 ms is generous for the gap between a key-down and the level
        // actually moving; beyond it, no key explains the change.
        return gap <= 1500 ? "1" : "0";
    }

    static void SampleAudio()
    {
        int v; bool m;
        if (_audioRead != null) { var r = _audioRead(); v = r[0]; m = r[1] != 0; }
        else if (_audioLevel != null && _audioMuted != null) { v = _audioLevel(); m = _audioMuted(); }
        else return;
        if (_lastVol < 0) { _lastVol = v; _lastMute = m; return; }
        if (v == _lastVol && m == _lastMute) return;
        long gap; string keyed = Keyed(out gap);
        JarvisInputHook.WriteState("{\"ts\":" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() +
            ",\"kind\":\"control-state\",\"control\":\"volume\",\"from\":" + _lastVol + ",\"to\":" + v +
            ",\"muted\":" + (m ? 1 : 0) + ",\"was_muted\":" + (_lastMute ? 1 : 0) +
            ",\"keyed\":" + keyed + ",\"key_gap_ms\":" + gap +
            ",\"fg\":\"" + JarvisInputHook.Foreground().Replace("\"", "") + "\"}");
        _lastVol = v; _lastMute = m;
    }

    // Per-app levels: the master sampler cannot see one app turned up in the
    // mixer, or an app raising its own session.
    static readonly Dictionary<string, string> _appVol = new Dictionary<string, string>();
    static readonly Dictionary<string, string> _appNames = new Dictionary<string, string>();

    static void SampleApps()
    {
        if (_audioSessions == null) return;
        var rows = _audioSessions();
        var seen = new HashSet<string>();
        foreach (var row in rows) {
            var parts = row.Split('|');
            if (parts.Length < 3) continue;
            string appPid = parts[0], state = parts[1] + "|" + parts[2];
            seen.Add(appPid);
            if (!_appNames.ContainsKey(appPid)) {
                string name = "?";
                try { using (var p = Process.GetProcessById(int.Parse(appPid))) name = p.ProcessName; } catch { }
                _appNames[appPid] = name;
            }
            string was;
            if (!_appVol.TryGetValue(appPid, out was)) { _appVol[appPid] = state; continue; }
            if (was == state) continue;
            var old = was.Split('|');
            long gap; string keyed = Keyed(out gap);
            JarvisInputHook.WriteState("{\"ts\":" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() +
                ",\"kind\":\"control-state\",\"control\":\"app-volume\",\"app\":\"" + _appNames[appPid].Replace("\"", "") +
                "\",\"pid\":" + appPid + ",\"from\":" + old[0] + ",\"to\":" + parts[1] +
                ",\"muted\":" + parts[2] + ",\"was_muted\":" + old[1] +
                ",\"keyed\":" + keyed + ",\"key_gap_ms\":" + gap +
                ",\"fg\":\"" + JarvisInputHook.Foreground().Replace("\"", "") + "\"}");
            _appVol[appPid] = state;
        }
        var gone = new List<string>();
        foreach (KeyValuePair<string, string> kv in _appVol) if (!seen.Contains(kv.Key)) gone.Add(kv.Key);
        foreach (string g in gone) { _appVol.Remove(g); _appNames.Remove(g); }
    }

    // Brightness: Fn+brightness goes through ACPI/WMI and never produces a key,
    // and Windows dims on its own, so the level is sampled. After 30 failures
    // in a row (no provider) the sampler stops; the controls collector reports it.
    static readonly Dictionary<string, int> _bright = new Dictionary<string, int>();
    static int _brightFailures;
    static ManagementObjectSearcher _brightQuery;

    static void SampleBrightness()
    {
        if (_brightFailures >= 30) return;
        try {
            if (_brightQuery == null)
            {
                // Bounded: a hung WMI provider must not stall the worker (and
                // with it the pulse) the way it could only stall its own
                // runspace before.
                EnumerationOptions options = new EnumerationOptions();
                ((ManagementOptions)options).Timeout = TimeSpan.FromSeconds(2);
                _brightQuery = new ManagementObjectSearcher(new ManagementScope(@"root\WMI"),
                    new ObjectQuery("SELECT InstanceName, CurrentBrightness FROM WmiMonitorBrightness"), options);
            }
            using (ManagementObjectCollection rows = _brightQuery.Get()) {
                ManagementObjectCollection.ManagementObjectEnumerator it = rows.GetEnumerator();
                while (it.MoveNext()) {
                    using (ManagementBaseObject r = it.Current) {
                        string id = Convert.ToString(r["InstanceName"]);
                        int v = Convert.ToInt32(r["CurrentBrightness"]);
                        int last;
                        if (!_bright.TryGetValue(id, out last)) { _bright[id] = v; continue; }
                        if (last == v) continue;
                        long gap; string keyed = Keyed(out gap);
                        var disp = new StringBuilder();
                        foreach (char c in id) if (char.IsLetterOrDigit(c) && c < 128 || c == '_') { if (disp.Length < 24) disp.Append(c); }
                        JarvisInputHook.WriteState("{\"ts\":" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() +
                            ",\"kind\":\"control-state\",\"control\":\"brightness\",\"from\":" + last + ",\"to\":" + v +
                            ",\"display\":\"" + disp + "\",\"idle_s\":" + IdleSeconds() +
                            ",\"keyed\":" + keyed + ",\"key_gap_ms\":" + gap +
                            ",\"fg\":\"" + JarvisInputHook.Foreground().Replace("\"", "") + "\"}");
                        _bright[id] = v;
                    }
                }
            }
            _brightFailures = 0;
        } catch {
            _brightFailures++;
            if (_brightQuery != null) { _brightQuery.Dispose(); _brightQuery = null; }
        }
    }

    public static long IdleSeconds()
    {
        uint li = LastInputTick();
        if (li == 0) return -1;
        return (long)unchecked((uint)Environment.TickCount - li) / 1000;
    }

    static void DrainSound()
    {
        if (_soundTake == null) return;
        // Bounded per tick; the listener's own budget caps what can be queued.
        for (int i = 0; i < 64; i++) {
            string line = _soundTake();
            if (line == null) break;
            JarvisInputHook.WriteState(line);
        }
    }
}
'@

Add-Type -TypeDefinition $src -ReferencedAssemblies System.Management

# Record our own pid. Matching on command lines to find this process does not
# work: the query itself contains the script name, so it matches itself and the
# helper looks like it is already running when it never started.
[JarvisInputHook]::Start($OutFile, $RedactBurstOver)

# Written only after the hook is actually installed, so the pid file's presence
# means "watching", not merely "process started". Start() throws if
# SetWindowsHookEx fails, and in that case no pid file appears at all.
$pidFile = [IO.Path]::ChangeExtension($OutFile, '.pid')
Set-Content -Path $pidFile -Value $PID -Encoding ascii

# The heartbeat (with the helper's and the desktop's session, so a hook outside
# the desktop session is visibly alive and counting nothing) and the 10 s
# liveness pulse are written by the host's worker; see JarvisHost.Run below.

# --- audio state sampler ------------------------------------------------------
# The keyboard hook sees volume keys. It does not see everything that can change
# the volume: a consumer-control HID often delivers WM_APPCOMMAND straight to the
# foreground window without traversing WH_KEYBOARD_LL, and any process can move
# the master level through CoreAudio with no input event at all.
#
# So the level itself is sampled, and each change is logged with how long ago a
# control key was seen. A change with no key behind it is the signal worth
# having: something moved the volume that was not the keyboard in front of you.
$audioSrc = @'
using System;
using System.Runtime.InteropServices;
[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioEndpointVolume {
  int RegisterControlChangeNotify(IntPtr n);
  int UnregisterControlChangeNotify(IntPtr n);
  int GetChannelCount(out uint c);
  int SetMasterVolumeLevel(float f, ref Guid g);
  int SetMasterVolumeLevelScalar(float f, ref Guid g);
  int GetMasterVolumeLevel(out float f);
  int GetMasterVolumeLevelScalar(out float f);
  int SetChannelVolumeLevel(uint i, float f, ref Guid g);
  int SetChannelVolumeLevelScalar(uint i, float f, ref Guid g);
  int GetChannelVolumeLevel(uint i, out float f);
  int GetChannelVolumeLevelScalar(uint i, out float f);
  int SetMute(bool m, ref Guid g);
  int GetMute(out bool m);
}
[Guid("D666063F-1587-4E43-81F1-B948E807363F"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDevice {
  int Activate(ref Guid iid, int ctx, IntPtr p, [MarshalAs(UnmanagedType.IUnknown)] out object o);
}
[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator {
  int EnumAudioEndpoints(int f, int m, out IntPtr c);
  int GetDefaultAudioEndpoint(int flow, int role, out IMMDevice d);
}
// Per-app audio sessions: each app's own volume slider in the Windows mixer.
[Guid("77AA99A0-1BD6-484F-8BC7-2C654C9A9B6F"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioSessionManager2 {
  int GetAudioSessionControl(IntPtr g, int f, out IntPtr c);
  int GetSimpleAudioVolume(IntPtr g, int f, out IntPtr v);
  int GetSessionEnumerator(out IAudioSessionEnumerator e);
}
[Guid("E2F5BB11-0570-40CA-ACDD-3AA01277DEE8"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioSessionEnumerator { int GetCount(out int n); int GetSession(int i, out IAudioSessionControl2 s); }
[Guid("bfb7ff88-7239-4fc9-8fa2-07c950be9c6d"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioSessionControl2 {
  int GetState(out int s); int GetDisplayName(out IntPtr n); int SetDisplayName(IntPtr n, IntPtr g);
  int GetIconPath(out IntPtr p); int SetIconPath(IntPtr p, IntPtr g); int GetGroupingParam(out Guid g);
  int SetGroupingParam(IntPtr g, IntPtr c); int RegisterAudioSessionNotification(IntPtr n);
  int UnregisterAudioSessionNotification(IntPtr n); int GetSessionIdentifier(out IntPtr s);
  int GetSessionInstanceIdentifier(out IntPtr s); int GetProcessId(out uint pid);
  [PreserveSig] int IsSystemSoundsSession();
}
[Guid("87CE5498-68D6-44E5-9215-6DA47EF883D8"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface ISimpleAudioVolume { int SetMasterVolume(float f, IntPtr g); int GetMasterVolume(out float f); int SetMute(bool m, IntPtr g); int GetMute(out bool m); }
// The default device is looked up on every read (it can change at any time).
// COM wrappers are deliberately NOT released here: the runtime keeps one
// wrapper per COM object for the whole process, and the sound listener holds
// the same enumerator, devices and sessions. Releasing them stopped the
// listener with InvalidCastException in every smoke run (2026-10-31); the GC
// frees these, and the host's private memory stayed flat without it.
public class JarvisAudio {
  // Created by CLSID and used only through interfaces. The sound listener
  // declared its own [ComImport] class for the same CLSID; Windows returns one
  // enumerator per process and the runtime caches its wrapper under the class
  // that created it first, so whichever sampler started second failed with
  // InvalidCastException (measured 2026-10-31: the listener stopped, or the
  // volume sampler failed silently, depending on which won the race).
  static readonly Type EnumeratorType = Type.GetTypeFromCLSID(new Guid("BCDE0395-E52F-467C-8E3D-C4579291692E"));
  static IMMDeviceEnumerator Enumerator() { return (IMMDeviceEnumerator)Activator.CreateInstance(EnumeratorType); }
  static IAudioEndpointVolume Endpoint() {
    IMMDevice dev;
    Enumerator().GetDefaultAudioEndpoint(0, 1, out dev);
    Guid iid = typeof(IAudioEndpointVolume).GUID;
    object o; dev.Activate(ref iid, 23, IntPtr.Zero, out o);
    return (IAudioEndpointVolume)o;
  }
  // { level 0-100, muted 0/1 } from one endpoint lookup instead of two.
  public static int[] Read() {
    var ep = Endpoint(); float f; bool m;
    ep.GetMasterVolumeLevelScalar(out f); ep.GetMute(out m);
    return new int[] { (int)Math.Round(f * 100), m ? 1 : 0 };
  }
  public static int Level() { return Read()[0]; }
  public static bool Muted() { return Read()[1] != 0; }
  // "pid|volume|muted" for every app session on the default output device.
  public static string[] Sessions() {
    IMMDevice dev;
    Enumerator().GetDefaultAudioEndpoint(0, 1, out dev);
    Guid iid = typeof(IAudioSessionManager2).GUID; object o;
    dev.Activate(ref iid, 23, IntPtr.Zero, out o);
    IAudioSessionEnumerator en; ((IAudioSessionManager2)o).GetSessionEnumerator(out en);
    int n; en.GetCount(out n);
    var list = new System.Collections.Generic.List<string>();
    for (int i = 0; i < n; i++) {
      IAudioSessionControl2 s; en.GetSession(i, out s);
      if (s.IsSystemSoundsSession() == 0) continue;
      uint pid; s.GetProcessId(out pid);
      var v = (ISimpleAudioVolume)s; float f; bool m; v.GetMasterVolume(out f); v.GetMute(out m);
      list.Add(pid + "|" + (int)Math.Round(f * 100) + "|" + (m ? 1 : 0));
    }
    return list.ToArray();
  }
}
'@
# Optional: if it does not compile the host simply has no audio sampler.
try { Add-Type -TypeDefinition $audioSrc -ErrorAction Stop } catch { }

# --- brightness state sampler --------------------------------------------------
# The keyboard hook sees no brightness key at all on most laptops: Fn+brightness
# goes through ACPI/WMI straight to the display driver and never produces a
# virtual key, and Windows moves brightness on its own. The host samples
# WmiMonitorBrightness every 2 s on its worker thread (the WMI read takes tens
# of milliseconds, never on the hook thread) and logs each change with the key
# gap and the session idle time (JarvisHost.SampleBrightness).

# --- continuous sound listener ------------------------------------------------
# The 5-minute audio collector meters output for 8 s, about 2.7% of the time, so
# a beep heard at the desk was almost never on record. This listener reads the
# same scalar peak meter (IAudioMeterInformation, 0..1) of every active OUTPUT
# device every 25 ms, all the time, on its own thread. It never opens a stream,
# never reads audio buffers and never touches a capture (microphone) device:
# amplitude only, so tone, words and music are never observed.
#
# Each app's audio session is metered on its own, so a beep stays a beep while
# another app plays music on the same device (a whole-device meter measured on
# 2026-10-23 never went quiet while Firefox played, and caught nothing). A
# sound episode starts when a session's peak rises from silence and ends after
# 2 s of silence; an episode whose sound lasted 1.5 s or less is a beep. The
# session names its owner exactly (pid, process name, start time), or is the
# shared "system sounds" session, which also carries Beep() tones and console
# bells, so their calling program is not named here. Sound on a device that no
# session explains is recorded as a device-level episode with no owner.
# Episodes are queued here and drained by the host's worker into the hook's
# single output queue, so a sound line can never interleave with a key line. Its
# counters ride the heartbeat, so a dead listener and a silent machine are
# distinguishable.
#
# Not seen: sounds shorter than one 25 ms poll (a click); a new app's first
# sound shorter than the 250 ms session rescan while another app is already
# playing on that device; anything that does not pass through Windows audio
# (BIOS/EC beeps); audio a session plays at zero volume.
$soundSrc = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
namespace JarvisSound {
[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IDeviceEnumerator {
    [PreserveSig] int EnumAudioEndpoints(int flow, uint mask, out IDeviceCollection devices);
    [PreserveSig] int GetDefaultAudioEndpoint(int flow, int role, out IDevice device);
}
[Guid("0BD7A1BE-7A1A-44DB-8397-CC5392387B5E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IDeviceCollection {
    [PreserveSig] int GetCount(out uint count);
    [PreserveSig] int Item(uint index, out IDevice device);
}
[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IDevice {
    [PreserveSig] int Activate(ref Guid iid, uint context, IntPtr activation, [MarshalAs(UnmanagedType.IUnknown)] out object result);
    [PreserveSig] int OpenPropertyStore(uint access, out IntPtr store);
    [PreserveSig] int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);
}
[Guid("77AA99A0-1BD6-484F-8BC7-2C654C9A9B6F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface ISessionManager2 {
    [PreserveSig] int GetAudioSessionControl(IntPtr guid, uint flags, out IntPtr control);
    [PreserveSig] int GetSimpleAudioVolume(IntPtr guid, uint flags, out IntPtr volume);
    [PreserveSig] int GetSessionEnumerator(out ISessionEnumerator enumerator);
}
[Guid("E2F5BB11-0570-40CA-ACDD-3AA01277DEE8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface ISessionEnumerator {
    [PreserveSig] int GetCount(out int count);
    [PreserveSig] int GetSession(int index, out ISessionControl2 control);
}
[Guid("BFB7FF88-7239-4FC9-8FA2-07C950BE9C6D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface ISessionControl2 {
    [PreserveSig] int GetState(out int state);
    [PreserveSig] int GetDisplayName(out IntPtr name);
    [PreserveSig] int SetDisplayName(IntPtr name, IntPtr context);
    [PreserveSig] int GetIconPath(out IntPtr path);
    [PreserveSig] int SetIconPath(IntPtr path, IntPtr context);
    [PreserveSig] int GetGroupingParam(out Guid group);
    [PreserveSig] int SetGroupingParam(IntPtr group, IntPtr context);
    [PreserveSig] int RegisterAudioSessionNotification(IntPtr events);
    [PreserveSig] int UnregisterAudioSessionNotification(IntPtr events);
    [PreserveSig] int GetSessionIdentifier(out IntPtr id);
    [PreserveSig] int GetSessionInstanceIdentifier(out IntPtr id);
    [PreserveSig] int GetProcessId(out uint pid);
    [PreserveSig] int IsSystemSoundsSession();
}
[Guid("C02216F6-8C67-4B5B-9D00-D008E73E0064"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IPeakMeter {
    [PreserveSig] int GetPeakValue(out float peak);
}
// One metered source: an app's audio session, or a device's own meter for
// sound that no session on it explains (an exclusive-mode or protected stream).
class Track {
    public string Key; public IPeakMeter Meter; public object Com; public bool Seen;
    public bool Active; public long StartMs, LastLoudMs, EndedMs = -1; public double Max; public int Pulses;
    public bool WasLoud; public long StartUnixMs; public long QuietMs, IdleS;
    public string DeviceId = "", Source = "session", App = "", ProcStart = "", Fg = "";
    public uint Pid, FgPid; public bool Known, Sys;
    // JSON fragments: who called Beep() for this episode, and whose console it is.
    public volatile string Caller = ""; public string ConsoleOwner = "";
}
class Device {
    public string Id; public IDevice Com; public IPeakMeter Meter; public object Manager;
    public List<Track> Sessions = new List<Track>(); public Track Unexplained;
    public long NextSessionScan, LastSessionScan = -1;
}
// Who called Beep(). Measured 2026-10-23: Beep() opens \Device\Beep with read|
// write-data access, holds it while the tone plays and closes it afterwards;
// the tone itself is played by the Windows sound service (taskhostw, which keeps
// its own handle open all the time) through the shared system-sounds session.
// So at the onset of a system-sounds sound, one snapshot of the system handle
// table names whoever has \Device\Beep open right now. Holders already present
// in the quiet baseline, or for 10 s or more, are persistent: reported apart,
// never as the caller. Only file handles with exactly Beep's access are opened
// and named; a name is compared and dropped, never kept. Handles this unelevated
// helper cannot duplicate (elevated or protected processes) are counted, not
// guessed. The lookup runs on its own thread, at most once a second.
static class BeepCallers {
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int needed);
    [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr handle, int infoClass, IntPtr buffer, int length, out int needed);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr process, int infoClass, ref BasicInformation info, int length, out int needed);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [StructLayout(LayoutKind.Sequential)] struct HandleEntry {
        public IntPtr Object; public IntPtr UniqueProcessId; public IntPtr HandleValue; public uint GrantedAccess;
        public ushort CreatorBackTraceIndex; public ushort ObjectTypeIndex; public uint HandleAttributes; public uint Reserved;
    }
    [StructLayout(LayoutKind.Sequential)] struct BasicInformation {
        public IntPtr ExitStatus; public IntPtr PebBaseAddress; public IntPtr AffinityMask; public IntPtr BasePriority;
        public IntPtr UniqueProcessId; public IntPtr InheritedFromUniqueProcessId;
    }
    const int ExtendedHandleInformation = 64, ObjectNameInformation = 1, ProcessBasicInformation = 0;
    const int MaxBufferBytes = 64 << 20, MinGapMs = 1000, PersistAfterMs = 10000, WedgedMs = 5000, MaxHolders = 4;
    const uint BeepAccess = 0x3, DupHandle = 0x40, QueryLimited = 0x1000, SameAccess = 2;
    const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    const string BeepDevice = @"\Device\Beep";
    static readonly AutoResetEvent Wake = new AutoResetEvent(false);
    static readonly Stopwatch Clock = Stopwatch.StartNew();
    static volatile Track Next;
    static HashSet<string> NotBeep = new HashSet<string>();
    static HashSet<string> Blocked = new HashSet<string>();
    static bool Baselined;
    static Dictionary<string, long> Holders = new Dictionary<string, long>();
    static HashSet<string> Persistent = new HashSet<string>();
    static long Lookups, Found, Uninspectable, Skipped, LastMs = -100000, RunningSinceMs = -1, LastLookupMs;
    static int BufferBytes = 1 << 23;
    static volatile string PersistentList = "";
    static volatile string State = "starting";

    public static void Start() {
        var worker = new Thread(Run);
        worker.IsBackground = true;
        worker.Name = "jarvis-beep-callers";
        worker.Start();
    }

    public static string Counters() {
        long since = Interlocked.Read(ref RunningSinceMs);
        string state = since >= 0 && Clock.ElapsedMilliseconds - since > WedgedMs ? "wedged" : State;
        return ",\"beep_state\":\"" + Listener.Esc(state) + "\",\"beep_lookups\":" + Interlocked.Read(ref Lookups) +
               ",\"beep_callers\":" + Interlocked.Read(ref Found) +
               ",\"beep_uninspectable\":" + Interlocked.Read(ref Uninspectable) +
               ",\"beep_skipped\":" + Interlocked.Read(ref Skipped) +
               ",\"beep_lookup_ms\":" + Interlocked.Read(ref LastLookupMs) +
               ",\"beep_holders\":\"" + Listener.Esc(PersistentList) + "\"";
    }

    // Ask who is beeping for this sound. While a lookup runs the newest request
    // waits; closer than a second to the last lookup it is skipped, and says so.
    public static void Request(Track t) {
        if (Clock.ElapsedMilliseconds - Interlocked.Read(ref LastMs) < MinGapMs) {
            t.Caller = "\"caller\":\"skipped\""; Interlocked.Increment(ref Skipped); return;
        }
        t.Caller = "\"caller\":\"pending\"";
        Next = t;
        Wake.Set();
    }

    static void Run() {
        try {
            Lookup(null);       // the quiet baseline: whoever holds the device now holds it all the time
            State = "running";
            while (true) {
                Wake.WaitOne();
                Track t = Next;
                Next = null;
                if (t == null) continue;
                Interlocked.Exchange(ref LastMs, Clock.ElapsedMilliseconds);
                t.Caller = Lookup(t);
            }
        } catch (Exception error) { State = "stopped: " + error.GetType().Name; }
    }

    static string Lookup(Track t) {
        long now = Clock.ElapsedMilliseconds;
        Interlocked.Exchange(ref RunningSinceMs, now);
        Interlocked.Increment(ref Lookups);
        try { return Scan(t, now); }
        finally {
            Interlocked.Exchange(ref LastLookupMs, Clock.ElapsedMilliseconds - now);
            Interlocked.Exchange(ref RunningSinceMs, -1);
        }
    }

    static string Scan(Track t, long now) {
        IntPtr buffer;
        while (true) {
            buffer = Marshal.AllocHGlobal(BufferBytes);
            int needed;
            int status = NtQuerySystemInformation(ExtendedHandleInformation, buffer, BufferBytes, out needed);
            if (status == 0) break;
            Marshal.FreeHGlobal(buffer);
            if (status != StatusInfoLengthMismatch || BufferBytes >= MaxBufferBytes) return "\"caller\":\"lookup failed\"";
            BufferBytes *= 2;
        }
        var holders = new List<string>();
        var notBeep = new HashSet<string>();
        var blockedNow = new HashSet<string>();
        int blocked = 0, blockedNew = 0;
        IntPtr self = GetCurrentProcess();
        try {
            long count = Marshal.ReadIntPtr(buffer).ToInt64();
            int size = Marshal.SizeOf(typeof(HandleEntry));
            long fits = ((long)BufferBytes - 2 * IntPtr.Size) / size;
            if (count > fits) count = fits;
            // Read only the access mask of each of the ~140k entries; decoding
            // every entry costs over 100 ms, and almost none have Beep's access.
            int accessAt = (int)Marshal.OffsetOf(typeof(HandleEntry), "GrantedAccess");
            long first = buffer.ToInt64() + 2 * IntPtr.Size;
            for (long i = 0; i < count; i++) {
                if ((uint)Marshal.ReadInt32(new IntPtr(first + i * size + accessAt)) != BeepAccess) continue;
                var entry = (HandleEntry)Marshal.PtrToStructure(new IntPtr(first + i * size), typeof(HandleEntry));
                uint pid = (uint)entry.UniqueProcessId.ToInt64();
                string key = pid + ":" + entry.HandleValue.ToInt64() + ":" + entry.Object.ToInt64();
                if (NotBeep.Contains(key)) { notBeep.Add(key); continue; }
                // A handle this helper cannot open stays unopenable: count it,
                // and count it as new when it was not there last time, which is
                // what an elevated caller's fresh \Device\Beep handle looks like.
                if (Blocked.Contains(key)) { blockedNow.Add(key); blocked++; continue; }
                IntPtr process = OpenProcess(DupHandle, false, pid);
                IntPtr copy = IntPtr.Zero;
                bool copied = process != IntPtr.Zero &&
                    DuplicateHandle(process, entry.HandleValue, self, out copy, 0, false, SameAccess);
                if (process != IntPtr.Zero) CloseHandle(process);
                if (!copied) {
                    blockedNow.Add(key); blocked++;
                    if (Baselined) blockedNew++;
                    continue;
                }
                string name = ObjectName(copy);
                CloseHandle(copy);
                if (name == BeepDevice) holders.Add(key); else notBeep.Add(key);
            }
        } finally { Marshal.FreeHGlobal(buffer); }
        NotBeep = notBeep;      // only handles that still exist stay cached
        Blocked = blockedNow;
        Baselined = true;

        var current = new Dictionary<string, long>();
        for (int i = 0; i < holders.Count; i++) {
            long first;
            current[holders[i]] = Holders.TryGetValue(holders[i], out first) ? first : now;
        }
        Holders = current;
        var kept = new HashSet<string>();
        for (int i = 0; i < holders.Count; i++) {
            long first = current[holders[i]];
            if (t == null || Persistent.Contains(holders[i]) || now - first >= PersistAfterMs) kept.Add(holders[i]);
        }
        Persistent = kept;
        var listed = new StringBuilder();
        int shown = 0;
        for (int i = 0; i < holders.Count && shown < MaxHolders; i++) {
            if (!kept.Contains(holders[i])) continue;
            uint holderPid = PidOf(holders[i]);
            listed.Append(shown++ > 0 ? " " : "").Append(NameOf(holderPid)).Append(':').Append(holderPid);
        }
        PersistentList = listed.ToString();
        if (t == null) return "";
        if (blockedNew > 0) Interlocked.Add(ref Uninspectable, blockedNew);
        string counts = ",\"caller_blocked\":" + blocked + ",\"caller_blocked_new\":" + blockedNew;
        for (int i = 0; i < holders.Count; i++) {
            if (kept.Contains(holders[i])) continue;
            uint callerPid = PidOf(holders[i]);
            Interlocked.Increment(ref Found);
            return "\"caller\":\"found\",\"caller_pid\":" + callerPid + ProcessFields(callerPid, "caller") + counts;
        }
        // No Beep() caller this helper can see. With no new unopenable handle
        // either, nobody called Beep(): a Windows event sound or PlaySound.
        // Either way the foreground's process tree is added as an inference.
        return "\"caller\":\"" + (blockedNew > 0 ? "none visible" : "none") + "\"" + counts + Likely(t.FgPid);
    }

    // The likely source of a tone nobody could be seen calling: the programs
    // under the window that was in front at its onset. Measured 2026-11-03:
    // four double 50 ms Beep() tones since 10-29 played while Windows Terminal
    // was in front and its one Windows shell (PowerShell, whose line editor
    // dings on a key that does nothing) was the only candidate; tones that
    // short end before the handle snapshot. Console hosts, WSL launchers and
    // the terminal itself never call Beep(), so they are not candidates; the
    // window's own process is one only when nothing runs under it. A single
    // candidate is named with its start time; several are listed, none named.
    // This is an inference and is reported as one, never as the caller.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct ProcessEntry {
        public uint Size; public uint Usage; public uint ProcessId; public IntPtr DefaultHeapId; public uint ModuleId;
        public uint Threads; public uint ParentProcessId; public int PriorityBase; public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExeFile;
    }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry entry);
    const int MaxTreeDepth = 4, MaxTreeNodes = 64, MaxListed = 4;
    static readonly string[] NotCallers = { "conhost", "openconsole", "windowsterminal", "wsl", "wslhost", "wslrelay", "wslservice" };

    internal static bool NotCaller(string name) {
        string n = name.ToLowerInvariant();
        if (n.EndsWith(".exe")) n = n.Substring(0, n.Length - 4);
        if (n.StartsWith("ubuntu")) return true;       // the distro launchers (ubuntu.exe, ubuntu2404.exe)
        return Array.IndexOf(NotCallers, n) >= 0;
    }

    static string Likely(uint fgPid) {
        if (fgPid == 0) return "";
        var names = new Dictionary<uint, string>();
        var children = new Dictionary<uint, List<uint>>();
        IntPtr snap = CreateToolhelp32Snapshot(0x2, 0);            // TH32CS_SNAPPROCESS
        if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return "";
        try {
            var e = new ProcessEntry(); e.Size = (uint)Marshal.SizeOf(typeof(ProcessEntry));
            if (!Process32FirstW(snap, ref e)) return "";
            do {
                names[e.ProcessId] = e.ExeFile ?? "";
                if (e.ParentProcessId != e.ProcessId) {
                    List<uint> kids;
                    if (!children.TryGetValue(e.ParentProcessId, out kids)) children[e.ParentProcessId] = kids = new List<uint>();
                    kids.Add(e.ProcessId);
                }
            } while (Process32NextW(snap, ref e));
        } finally { CloseHandle(snap); }
        if (!names.ContainsKey(fgPid)) return "";
        var found = new List<uint>();
        var level = new List<uint> { fgPid };
        int visited = 0;
        for (int depth = 0; depth < MaxTreeDepth && level.Count > 0 && visited < MaxTreeNodes; depth++) {
            var next = new List<uint>();
            foreach (uint pid in level) {
                List<uint> kids;
                if (!children.TryGetValue(pid, out kids)) continue;
                foreach (uint kid in kids) {
                    if (++visited > MaxTreeNodes) break;
                    next.Add(kid);
                    if (!NotCaller(names[kid])) found.Add(kid);
                }
            }
            level = next;
        }
        if (found.Count == 0 && !NotCaller(names[fgPid])) found.Add(fgPid);
        if (found.Count == 0) return "";
        var listed = new StringBuilder();
        for (int i = 0; i < found.Count && i < MaxListed; i++) {
            string n = names[found[i]];
            if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) n = n.Substring(0, n.Length - 4);
            listed.Append(i > 0 ? " " : "").Append(n).Append(':').Append(found[i]);
        }
        if (found.Count > MaxListed) listed.Append(" +").Append(found.Count - MaxListed);
        uint one = found.Count == 1 ? found[0] : 0;
        return ",\"likely_pid\":" + one + ",\"likely_n\":" + Math.Min(found.Count, MaxTreeNodes) +
               ",\"likely_list\":\"" + Listener.Esc(listed.ToString()) + "\"" +
               (one != 0 ? ProcessFields(one, "likely") : "");
    }

    static uint PidOf(string key) { return UInt32.Parse(key.Substring(0, key.IndexOf(':'))); }

    static string NameOf(uint pid) {
        try { using (Process process = Process.GetProcessById((int)pid)) return process.ProcessName; }
        catch (Exception) { return "?"; }
    }

    static string ObjectName(IntPtr handle) {
        IntPtr buffer = Marshal.AllocHGlobal(1024);
        try {
            int needed;
            if (NtQueryObject(handle, ObjectNameInformation, buffer, 1024, out needed) != 0) return "";
            int length = Marshal.ReadInt16(buffer) & 0xFFFF;          // UNICODE_STRING.Length, bytes
            IntPtr text = Marshal.ReadIntPtr(buffer, IntPtr.Size);
            if (length == 0 || text == IntPtr.Zero) return "";
            return Marshal.PtrToStringUni(text, length / 2);
        } finally { Marshal.FreeHGlobal(buffer); }
    }

    // ",\"<prefix>_app\":...,\"<prefix>_start\":..." for a pid, empty strings if it is gone.
    public static string ProcessFields(uint pid, string prefix) {
        string app = "", start = "";
        try {
            using (Process process = Process.GetProcessById((int)pid)) {
                app = process.ProcessName;
                try { start = process.StartTime.ToUniversalTime().ToString("o"); } catch (Exception) { }
            }
        } catch (Exception) { }
        return ",\"" + prefix + "_app\":\"" + Listener.Esc(app) + "\",\"" + prefix + "_start\":\"" + Listener.Esc(start) + "\"";
    }

    // The process that created a console host: the program whose bell it plays.
    // Its start must precede the host's, so a reused pid is never blamed.
    public static string ConsoleOwner(uint hostPid) {
        IntPtr process = OpenProcess(QueryLimited, false, hostPid);
        if (process == IntPtr.Zero) return "";
        try {
            var info = new BasicInformation();
            int needed;
            if (NtQueryInformationProcess(process, ProcessBasicInformation, ref info, Marshal.SizeOf(typeof(BasicInformation)), out needed) != 0)
                return "";
            uint parent = (uint)info.InheritedFromUniqueProcessId.ToInt64();
            if (parent == 0) return "";
            using (Process host = Process.GetProcessById((int)hostPid))
            using (Process owner = Process.GetProcessById((int)parent)) {
                if (owner.StartTime > host.StartTime) return "";
                return ",\"console_pid\":" + parent + ProcessFields(parent, "console");
            }
        } catch (Exception) { return ""; }
        finally { CloseHandle(process); }
    }
}
public static class Listener {
    const int StepMs = 25, QuietEndMs = 2000, MaxBeepMs = 1500, EnumEveryMs = 10000, SessionScanMs = 250;
    const int MaxEndpoints = 16, MaxSessions = 32, LinesPerMinute = 30, QueueCap = 256;
    const long OpenSplitMs = 600000;
    const double OnPeak = 0.01;
    static readonly ConcurrentQueue<string> Lines = new ConcurrentQueue<string>();
    static long Samples, Episodes, Beeps, Dropped, Errors, Enumerations, LastSample;
    static int Endpoints, SessionCount, Pending, MinuteLines;
    static long MinuteStart;
    static volatile string State = "starting";

    [StructLayout(LayoutKind.Sequential)] struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
    [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);

    public static void Start() {
        var worker = new Thread(Run);
        worker.IsBackground = true;
        worker.Name = "jarvis-sound-listener";
        worker.SetApartmentState(ApartmentState.MTA);
        worker.Start();
        BeepCallers.Start();
    }

    // One queued line, or null when none is waiting.
    public static string Take() {
        string line;
        if (!Lines.TryDequeue(out line)) return null;
        Interlocked.Decrement(ref Pending);
        return line;
    }

    public static string Counters() {
        return "{\"state\":\"" + Esc(State) + "\",\"samples\":" + Interlocked.Read(ref Samples) +
               ",\"endpoints\":" + Endpoints + ",\"sessions\":" + SessionCount +
               ",\"episodes\":" + Interlocked.Read(ref Episodes) +
               ",\"beeps\":" + Interlocked.Read(ref Beeps) + ",\"dropped\":" + Interlocked.Read(ref Dropped) +
               ",\"errors\":" + Interlocked.Read(ref Errors) +
               ",\"restarts\":" + Interlocked.Read(ref Restarts) +
               ",\"enumerations\":" + Interlocked.Read(ref Enumerations) +
               ",\"last_sample\":" + Interlocked.Read(ref LastSample) + BeepCallers.Counters() + "}";
    }

    // A COM fault (an audio session vanishing mid-scan raised InvalidCastException
    // in a smoke run on 2026-10-31) used to end the listener until the hook
    // restarted. Now the loop starts over with fresh devices, counted in
    // Errors; only RestartLimit faults inside RestartWindowMs stop it.
    const int RestartLimit = 20;
    const long RestartWindowMs = 600000;
    public static long Restarts;

    static void Run() {
        var faults = new Queue<long>();
        while (true) {
            try { Loop(); return; }
            catch (Exception error) {
                Interlocked.Increment(ref Errors);
                long t = UnixMs();
                faults.Enqueue(t);
                while (faults.Count > 0 && t - faults.Peek() > RestartWindowMs) faults.Dequeue();
                if (faults.Count >= RestartLimit) { State = "stopped: " + error.GetType().Name; return; }
                State = "restarting: " + error.GetType().Name;
                Interlocked.Increment(ref Restarts);
                Thread.Sleep(1000);
                State = "running";
            }
        }
    }

    static void Release(object value) {
        if (value != null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value);
    }

    static long UnixMs() { return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); }

    static void Loop() {
        // By CLSID and through the interface only: see JarvisAudio for why a
        // [ComImport] class here broke whenever the volume sampler ran first.
        var enumerator = (IDeviceEnumerator)Activator.CreateInstance(
            Type.GetTypeFromCLSID(new Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")));
        var devices = new List<Device>();
        var clock = Stopwatch.StartNew();
        long nextEnum = 0;
        while (true) {
            long now = clock.ElapsedMilliseconds;
            if (now >= nextEnum) { devices = RefreshDevices(enumerator, devices); nextEnum = now + EnumEveryMs; }
            bool failed = false;
            int sessions = 0;
            for (int d = 0; d < devices.Count; d++) {
                Device dev = devices[d];
                if (now >= dev.NextSessionScan) { RefreshSessions(dev, now); dev.NextSessionScan = now + SessionScanMs; }
                bool explained = false;
                for (int i = 0; i < dev.Sessions.Count; i++) {
                    float peak;
                    if (!Read(dev.Sessions[i].Meter, out peak)) { failed = true; continue; }
                    if (peak >= OnPeak) explained = true;
                    Step(dev.Sessions[i], peak, now);
                }
                sessions += dev.Sessions.Count;
                float level;
                if (!Read(dev.Meter, out level)) { failed = true; continue; }
                // Sound on the device that no known session carries: either a
                // session that started since the last scan (look now), or a
                // stream with no session at all. Only once the session list is
                // fresh is it counted as unexplained.
                bool unexplained = level >= OnPeak && !explained;
                if (unexplained && now - dev.LastSessionScan > 2 * StepMs) {
                    dev.NextSessionScan = now; unexplained = false;
                }
                Step(dev.Unexplained, unexplained ? level : 0f, now);
            }
            SessionCount = sessions;
            // A meter read failure usually means the device went away: look again soon.
            if (failed && nextEnum > now + 1000) nextEnum = now + 1000;
            Interlocked.Exchange(ref LastSample, UnixMs() / 1000);
            State = devices.Count > 0 ? "running" : "running, no active output device";
            Thread.Sleep(StepMs);
        }
    }

    static bool Read(IPeakMeter meter, out float peak) {
        int hr;
        try { hr = meter.GetPeakValue(out peak); } catch (Exception) { hr = -1; peak = 0f; }
        if (hr != 0 || float.IsNaN(peak) || peak < 0f || peak > 1f) {
            Interlocked.Increment(ref Errors); peak = 0f; return false;
        }
        Interlocked.Increment(ref Samples);
        return true;
    }

    static void Step(Track t, float peak, long now) {
        bool loud = peak >= OnPeak;
        if (!t.Active) {
            if (!loud) return;
            t.Active = true; t.StartMs = now; t.LastLoudMs = now; t.Max = peak; t.Pulses = 1; t.WasLoud = true;
            t.StartUnixMs = UnixMs();
            t.QuietMs = t.EndedMs < 0 ? -1 : now - t.EndedMs;
            t.IdleS = IdleSeconds(); t.Fg = Foreground(out t.FgPid);
            t.Caller = "";
            if (t.Sys) BeepCallers.Request(t);
        } else if (loud) {
            if (!t.WasLoud) t.Pulses++;
            t.WasLoud = true; t.LastLoudMs = now; if (peak > t.Max) t.Max = peak;
            if (now - t.StartMs >= OpenSplitMs) {
                Emit(t, true);
                t.Active = true; t.StartMs = now; t.StartUnixMs = UnixMs(); t.Max = peak; t.Pulses = 1; t.QuietMs = 0;
            }
        } else {
            t.WasLoud = false;
            if (now - t.LastLoudMs >= QuietEndMs) { Emit(t, false); t.EndedMs = t.LastLoudMs; }
        }
    }

    static List<Device> RefreshDevices(IDeviceEnumerator enumerator, List<Device> old) {
        Interlocked.Increment(ref Enumerations);
        var fresh = new List<Device>();
        IDeviceCollection list = null;
        try {
            uint count;
            if (enumerator.EnumAudioEndpoints(0, 1, out list) != 0 || list == null || list.GetCount(out count) != 0) {
                Interlocked.Increment(ref Errors); return old;
            }
            if (count > MaxEndpoints) count = MaxEndpoints;
            for (uint i = 0; i < count; i++) {
                IDevice com = null; object meter = null; object manager = null; bool kept = false;
                try {
                    string id;
                    if (list.Item(i, out com) != 0 || com == null || com.GetId(out id) != 0 || String.IsNullOrEmpty(id)) continue;
                    Device existing = null;
                    for (int k = 0; k < old.Count; k++) if (old[k].Id == id) existing = old[k];
                    if (existing != null) { fresh.Add(existing); old.Remove(existing); continue; }
                    Guid meterIid = typeof(IPeakMeter).GUID;
                    Guid managerIid = typeof(ISessionManager2).GUID;
                    if (com.Activate(ref meterIid, 23, IntPtr.Zero, out meter) != 0 || meter == null ||
                        com.Activate(ref managerIid, 23, IntPtr.Zero, out manager) != 0 || manager == null) {
                        Interlocked.Increment(ref Errors); continue;
                    }
                    var dev = new Device();
                    dev.Id = id; dev.Com = com; dev.Meter = (IPeakMeter)meter; dev.Manager = manager;
                    dev.Unexplained = new Track();
                    dev.Unexplained.Key = "device"; dev.Unexplained.DeviceId = id; dev.Unexplained.Source = "device";
                    fresh.Add(dev); kept = true;
                } catch (Exception) { Interlocked.Increment(ref Errors); }
                finally { if (!kept) { Release(manager); Release(meter); Release(com); } }
            }
        } finally { Release(list); }
        // Devices that went away: close the episodes they were in, then let go.
        for (int k = 0; k < old.Count; k++) {
            Device gone = old[k];
            for (int i = 0; i < gone.Sessions.Count; i++) Drop(gone.Sessions[i], true);
            if (gone.Unexplained.Active) Emit(gone.Unexplained, true);
            Release(gone.Manager); Release(gone.Meter); Release(gone.Com);
        }
        Endpoints = fresh.Count;
        return fresh;
    }

    // A session that goes away ended its sound with it (a console host exits
    // right after its bell); a device that goes away cut its sound off.
    static void Drop(Track t, bool cut) {
        if (t.Active) Emit(t, cut);
        Release(t.Com);
    }

    // Keep one track per session for as long as the session exists, so each
    // app's sound is measured on its own meter: a beep stays a beep even while
    // another app plays music on the same device.
    static void RefreshSessions(Device dev, long now) {
        ISessionEnumerator list = null;
        try {
            int count;
            if (((ISessionManager2)dev.Manager).GetSessionEnumerator(out list) != 0 || list == null ||
                list.GetCount(out count) != 0 || count < 0) {
                Interlocked.Increment(ref Errors); return;
            }
            if (count > MaxSessions) count = MaxSessions;
            for (int k = 0; k < dev.Sessions.Count; k++) dev.Sessions[k].Seen = false;
            for (int i = 0; i < count; i++) {
                ISessionControl2 session = null; bool kept = false;
                try {
                    if (list.GetSession(i, out session) != 0 || session == null) continue;
                    string key = InstanceKey(session);
                    if (key.Length == 0) continue;
                    Track existing = null;
                    for (int k = 0; k < dev.Sessions.Count; k++) if (dev.Sessions[k].Key == key) existing = dev.Sessions[k];
                    if (existing != null) { existing.Seen = true; continue; }
                    var meter = session as IPeakMeter;
                    if (meter == null) continue;
                    var t = new Track();
                    t.Key = key; t.Com = session; t.Meter = meter; t.Seen = true; t.DeviceId = dev.Id;
                    Describe(t, session);
                    dev.Sessions.Add(t); kept = true;
                } catch (Exception) { Interlocked.Increment(ref Errors); }
                finally { if (!kept) Release(session); }
            }
            for (int k = dev.Sessions.Count - 1; k >= 0; k--) {
                if (dev.Sessions[k].Seen) continue;
                Drop(dev.Sessions[k], false); dev.Sessions.RemoveAt(k);
            }
            dev.LastSessionScan = now;
        } catch (Exception) { Interlocked.Increment(ref Errors); }
        finally { Release(list); }
    }

    static string InstanceKey(ISessionControl2 session) {
        IntPtr text;
        if (session.GetSessionInstanceIdentifier(out text) != 0 || text == IntPtr.Zero) return "";
        try { return Marshal.PtrToStringUni(text) ?? ""; }
        finally { Marshal.FreeCoTaskMem(text); }
    }

    // Who the session belongs to, fixed when it is first seen. The shared
    // system-sounds session (which also carries Beep() tones and console
    // bells) is reported as such, never as a process.
    static void Describe(Track t, ISessionControl2 session) {
        uint pid;
        int pidHr = session.GetProcessId(out pid);
        t.Sys = session.IsSystemSoundsSession() == 0;
        t.Pid = pidHr == 0 ? pid : 0;
        t.App = t.Sys ? "system sounds" : "";
        if (pidHr != 0 || t.Sys) return;
        try {
            using (Process process = Process.GetProcessById((int)pid)) {
                t.App = process.ProcessName;
                t.ProcStart = process.StartTime.ToUniversalTime().ToString("o");
                t.Known = true;
            }
        } catch (Exception) { }
        if (String.Equals(t.App, "conhost", StringComparison.OrdinalIgnoreCase) ||
            String.Equals(t.App, "OpenConsole", StringComparison.OrdinalIgnoreCase))
            t.ConsoleOwner = BeepCallers.ConsoleOwner(t.Pid);
    }

    static void Emit(Track t, bool open) {
        t.Active = false;
        long duration = t.LastLoudMs - t.StartMs + StepMs;
        bool beep = !open && duration <= MaxBeepMs;
        Interlocked.Increment(ref Episodes);
        if (beep) Interlocked.Increment(ref Beeps);
        long minute = Environment.TickCount / 60000;
        if (minute != MinuteStart) { MinuteStart = minute; MinuteLines = 0; }
        if (MinuteLines >= LinesPerMinute || Pending >= QueueCap) { Interlocked.Increment(ref Dropped); return; }
        MinuteLines++;
        var line = new StringBuilder(360);
        line.Append("{\"ts\":").Append(t.StartUnixMs / 1000)
            .Append(",\"kind\":\"sound\",\"sound\":\"").Append(beep ? "beep" : "sound")
            .Append("\",\"source\":\"").Append(t.Source)
            .Append("\",\"ms\":").Append(t.StartUnixMs)
            .Append(",\"dur_ms\":").Append(duration)
            .Append(",\"pulses\":").Append(t.Pulses)
            .Append(",\"peak\":").Append(Math.Round(t.Max, 4).ToString(System.Globalization.CultureInfo.InvariantCulture))
            .Append(",\"endpoint\":\"").Append(Esc(t.DeviceId))
            .Append("\",\"pid\":").Append(t.Pid)
            .Append(",\"app\":\"").Append(Esc(t.App))
            .Append("\",\"proc_start\":\"").Append(Esc(t.ProcStart))
            .Append("\",\"known\":").Append(t.Known ? 1 : 0)
            .Append(",\"sys\":").Append(t.Sys ? 1 : 0)
            .Append(",\"quiet_ms\":").Append(t.QuietMs)
            .Append(",\"idle_s\":").Append(t.IdleS)
            .Append(",\"open\":").Append(open ? 1 : 0)
            .Append(t.Caller.Length > 0 ? "," + t.Caller : "").Append(t.ConsoleOwner)
            .Append(",\"fg\":\"").Append(Esc(t.Fg)).Append("\"}");
        Lines.Enqueue(line.ToString());
        Interlocked.Increment(ref Pending);
    }

    static long IdleSeconds() {
        var li = new LASTINPUTINFO(); li.cbSize = (uint)Marshal.SizeOf(li);
        if (!GetLastInputInfo(ref li)) return -1;
        return (long)unchecked((uint)Environment.TickCount - li.dwTime) / 1000;
    }

    static string Foreground(out uint pid) {
        pid = 0;
        try {
            GetWindowThreadProcessId(GetForegroundWindow(), out pid);
            if (pid == 0) return "";
            using (Process process = Process.GetProcessById((int)pid)) return process.ProcessName;
        } catch (Exception) { return ""; }
    }

    // JSON string body: printable ASCII only, quotes and backslashes dropped, capped.
    internal static string Esc(string value) {
        if (String.IsNullOrEmpty(value)) return "";
        var text = new StringBuilder(value.Length);
        for (int i = 0; i < value.Length && text.Length < 160; i++) {
            char c = value[i];
            if (c >= ' ' && c < (char)127 && c != '"' && c != '\\') text.Append(c);
        }
        return text.ToString();
    }
}
}
'@
# Optional like the audio sampler: the host binds the listener if it compiled
# and its heartbeat says "unavailable" otherwise.
try { Add-Type -TypeDefinition $soundSrc -ErrorAction Stop } catch { }

# No PowerShell runs after this line: the host pumps the hook's messages on
# this thread and does everything periodic on its worker.
[JarvisHost]::Run($OutFile, $HeartbeatSeconds)
