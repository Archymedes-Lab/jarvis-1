# Bounded observation of visible top-level window SHOW events in this session.
# No screenshots, titles, typed input, clipboard, or persistent hooks.
$ErrorActionPreference='Stop'
$seconds=__SECONDS__
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
public class JarvisWindowTrace {
    public class Row {
        public string time;
        public long hwnd;
        public uint pid;
        public string process;
        public string windowClass;
    }
    public class Result {
        public string startedAt;
        public string endedAt;
        public int sessionId;
        public int observerPid;
        public bool capped;
        public List<Row> windows = new List<Row>();
    }
    delegate void HookProc(IntPtr hook, uint evt, IntPtr hwnd, int obj, int child, uint thread, uint time);
    [StructLayout(LayoutKind.Sequential)] struct Point { public int x; public int y; }
    [StructLayout(LayoutKind.Sequential)] struct Msg { public IntPtr hwnd; public uint message; public UIntPtr wParam; public IntPtr lParam; public uint time; public Point pt; public uint lPrivate; }
    [DllImport("user32.dll")] static extern IntPtr SetWinEventHook(uint min, uint max, IntPtr module, HookProc proc, uint pid, uint thread, uint flags);
    [DllImport("user32.dll")] static extern bool UnhookWinEvent(IntPtr hook);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr hwnd, StringBuilder name, int count);
    [DllImport("user32.dll")] static extern bool PeekMessage(out Msg msg, IntPtr hwnd, uint min, uint max, uint remove);
    [DllImport("user32.dll")] static extern bool TranslateMessage(ref Msg msg);
    [DllImport("user32.dll")] static extern IntPtr DispatchMessage(ref Msg msg);
    public static Result Run(int seconds) {
        Result result = new Result();
        result.startedAt=DateTime.UtcNow.ToString("o");
        result.observerPid=Process.GetCurrentProcess().Id;
        result.sessionId=Process.GetCurrentProcess().SessionId;
        HookProc callback = delegate(IntPtr hook, uint evt, IntPtr hwnd, int obj, int child, uint thread, uint time) {
            try {
                if(hwnd==IntPtr.Zero || obj!=0 || child!=0 || !IsWindowVisible(hwnd) || GetAncestor(hwnd,2)!=hwnd) return;
                if(result.windows.Count>=10000) {result.capped=true; return;}
                uint pid; GetWindowThreadProcessId(hwnd,out pid);
                StringBuilder name=new StringBuilder(256); GetClassName(hwnd,name,256);
                string process="unavailable";
                try {using(Process p=Process.GetProcessById((int)pid)) {process=p.ProcessName;}} catch {}
                result.windows.Add(new Row {time=DateTime.UtcNow.ToString("o"),hwnd=hwnd.ToInt64(),pid=pid,process=process,windowClass=name.ToString()});
            } catch {}
        };
        IntPtr handle=SetWinEventHook(0x8002,0x8002,IntPtr.Zero,callback,0,0,0);
        if(handle==IntPtr.Zero) throw new InvalidOperationException("Window event hook could not be installed");
        try {
            Stopwatch timer=Stopwatch.StartNew();
            while(timer.Elapsed.TotalSeconds<seconds) {
                Msg msg;
                while(PeekMessage(out msg,IntPtr.Zero,0,0,1)) {TranslateMessage(ref msg); DispatchMessage(ref msg);}
                Thread.Sleep(10);
            }
        } finally {UnhookWinEvent(handle); GC.KeepAlive(callback);}
        result.endedAt=DateTime.UtcNow.ToString("o");
        return result;
    }
}
'@
$o=[JarvisWindowTrace]::Run($seconds)
$json=$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
