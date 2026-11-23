$ErrorActionPreference = 'Stop'
$state = @{ endpoints=@(); defaults=@(); sessions=@(); errors=@(); truncated=$false }

# Read Core Audio metadata only. This process never opens a render/capture
# stream and never reads audio buffers. The only signal-level input is the
# scalar peak value of IAudioMeterInformation (0..1), sampled for a short,
# bounded burst to spot beep-like transients; tone, content and audibility are
# never observed. The .NET process exits after one pass.
$source = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
class MMDeviceEnumeratorClass { }

[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator {
    [PreserveSig] int EnumAudioEndpoints(int flow, uint mask, out IMMDeviceCollection devices);
    [PreserveSig] int GetDefaultAudioEndpoint(int flow, int role, out IMMDevice device);
    [PreserveSig] int GetDevice([MarshalAs(UnmanagedType.LPWStr)] string id, out IMMDevice device);
    [PreserveSig] int RegisterEndpointNotificationCallback(IntPtr callback);
    [PreserveSig] int UnregisterEndpointNotificationCallback(IntPtr callback);
}
[Guid("0BD7A1BE-7A1A-44DB-8397-CC5392387B5E"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceCollection {
    [PreserveSig] int GetCount(out uint count);
    [PreserveSig] int Item(uint index, out IMMDevice device);
}
[Guid("D666063F-1587-4E43-81F1-B948E807363F"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDevice {
    [PreserveSig] int Activate(ref Guid iid, uint context, IntPtr activation, [MarshalAs(UnmanagedType.IUnknown)] out object result);
    [PreserveSig] int OpenPropertyStore(uint access, out IntPtr store);
    [PreserveSig] int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);
    [PreserveSig] int GetState(out uint state);
}
[Guid("77AA99A0-1BD6-484F-8BC7-2C654C9A9B6F"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioSessionManager2 {
    [PreserveSig] int GetAudioSessionControl(IntPtr guid, uint flags, out IntPtr control);
    [PreserveSig] int GetSimpleAudioVolume(IntPtr guid, uint flags, out IntPtr volume);
    [PreserveSig] int GetSessionEnumerator(out IAudioSessionEnumerator enumerator);
    [PreserveSig] int RegisterSessionNotification(IntPtr notification);
    [PreserveSig] int UnregisterSessionNotification(IntPtr notification);
    [PreserveSig] int RegisterDuckNotification(IntPtr sessionId, IntPtr notification);
    [PreserveSig] int UnregisterDuckNotification(IntPtr notification);
}
[Guid("E2F5BB11-0570-40CA-ACDD-3AA01277DEE8"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioSessionEnumerator {
    [PreserveSig] int GetCount(out int count);
    [PreserveSig] int GetSession(int index, out IAudioSessionControl2 control);
}
[Guid("BFB7FF88-7239-4FC9-8FA2-07C950BE9C6D"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioSessionControl2 {
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
    [PreserveSig] int SetDuckingPreference(bool optOut);
}
[Guid("C02216F6-8C67-4B5B-9D00-D008E73E0064"),
 InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioMeterInformation {
    [PreserveSig] int GetPeakValue(out float peak);
}
public class JarvisAudioEvent {
    public string endpoint { get; set; }
    public int startMs { get; set; }
    public int durationMs { get; set; }
    public double peak { get; set; }
    public uint pid { get; set; }
    public string processStart { get; set; }
    public bool identityKnown { get; set; }
    public bool systemSounds { get; set; }
}
public class JarvisAudioBurst {
    public int durationMs;
    public int elapsedMs;
    public int samples;
    public int endpointsSampled;
    public int sustained;
    public bool truncated;
    public List<JarvisAudioEvent> events = new List<JarvisAudioEvent>();
    public List<string> errors = new List<string>();
}
class JarvisMeterTrack {
    public string id; public IMMDevice device; public IAudioMeterInformation meter;
    public bool active, fromStart; public int startMs, lastLoudMs; public double max;
    public uint pid; public string processStart; public bool known, systemSounds;
}
public class JarvisAudioEndpoint {
    public string id { get; set; }
    public string flow { get; set; }
    public uint state { get; set; }
}
public class JarvisAudioDefault {
    public string flow { get; set; }
    public string role { get; set; }
    public string id { get; set; }
}
public class JarvisAudioSession {
    public string endpoint { get; set; }
    public string flow { get; set; }
    public int state { get; set; }
    public uint pid { get; set; }
    public string processStart { get; set; }
    public int processSession { get; set; }
    public bool systemSounds { get; set; }
    public bool identityKnown { get; set; }
    public bool singleProcess { get; set; }
}
public class JarvisAudioSnapshot {
    public List<JarvisAudioEndpoint> endpoints = new List<JarvisAudioEndpoint>();
    public List<JarvisAudioDefault> defaults = new List<JarvisAudioDefault>();
    public List<JarvisAudioSession> sessions = new List<JarvisAudioSession>();
    public List<string> errors = new List<string>();
    public bool truncated;
    public JarvisAudioBurst burst = new JarvisAudioBurst();
    const int MaxEndpoints = 64;
    const int MaxSessions = 256;
    static void Release(object value) {
        if (value != null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value);
    }
    public static JarvisAudioSnapshot Read() {
        var result = new JarvisAudioSnapshot();
        IMMDeviceEnumerator devices = null;
        IMMDeviceCollection list = null;
        string phase = "activation";
        try {
            devices = (IMMDeviceEnumerator)new MMDeviceEnumeratorClass();
            phase = "enumeration";
            uint count;
            if (devices.EnumAudioEndpoints(2, 15, out list) != 0 || list == null || list.GetCount(out count) != 0) {
                result.errors.Add("Core Audio endpoint enumeration unavailable"); return result;
            }
            if (count > MaxEndpoints) { result.truncated = true; count = MaxEndpoints; }
            for (uint i = 0; i < count; i++) {
                IMMDevice device = null;
                try {
                    if (list.Item(i, out device) != 0 || device == null) {
                        result.errors.Add("Core Audio endpoint item unavailable"); continue;
                    }
                    string id; uint state;
                    if (device.GetId(out id) != 0 || device.GetState(out state) != 0 || String.IsNullOrEmpty(id)) {
                        result.errors.Add("Core Audio endpoint identity unavailable"); continue;
                    }
                    string flow = id.IndexOf("{0.0.1.", StringComparison.OrdinalIgnoreCase) >= 0 ? "capture" :
                                  id.IndexOf("{0.0.0.", StringComparison.OrdinalIgnoreCase) >= 0 ? "render" : "unknown";
                    if (flow == "unknown") result.errors.Add("Core Audio endpoint flow unknown");
                    result.endpoints.Add(new JarvisAudioEndpoint { id=id, flow=flow, state=state });
                    if (state == 1 && flow != "unknown") ReadSessions(device, id, flow, result);
                } catch (Exception) { result.errors.Add("Core Audio endpoint read failed"); }
                finally { Release(device); }
            }
            string[] roles = { "console", "multimedia", "communications" };
            for (int flow = 0; flow <= 1; flow++) for (int role = 0; role < 3; role++) {
                IMMDevice device = null;
                try {
                    int hr = devices.GetDefaultAudioEndpoint(flow, role, out device);
                    string id = null;
                    if (hr == 0 && device != null && device.GetId(out id) != 0)
                        result.errors.Add("Core Audio default identity unavailable");
                    else if (hr != 0 && hr != unchecked((int)0x80070490))
                        result.errors.Add("Core Audio default query failed");
                    result.defaults.Add(new JarvisAudioDefault { flow=flow == 0 ? "render" : "capture", role=roles[role], id=id });
                } catch (Exception) { result.errors.Add("Core Audio default query failed"); }
                finally { Release(device); }
            }
            phase = "burst";
            try { result.burst = SampleBurst(devices); }
            catch (Exception) { result.burst.errors.Add("peak meter burst failed"); }
        } catch (Exception error) { result.errors.Add("Core Audio " + phase + " unavailable: " + error.GetType().Name + " " + error.HResult.ToString("X8")); }
        finally { Release(list); Release(devices); }
        return result;
    }
    // Bounded transient detector. Beep-like = a rise from silence inside the
    // window that falls back to silence inside it within MaxBeepMs. Sound that
    // is already playing at the window edges is counted, never called a beep.
    const int BurstMs = 8000, StepMs = 20, HoldMs = 120, MaxBeepMs = 1500, MaxEvents = 32;
    const double OnPeak = 0.01;
    static JarvisAudioBurst SampleBurst(IMMDeviceEnumerator devices) {
        var burst = new JarvisAudioBurst { durationMs = BurstMs };
        var tracks = new List<JarvisMeterTrack>();
        IMMDeviceCollection list = null;
        try {
            uint count;
            if (devices.EnumAudioEndpoints(0, 1, out list) != 0 || list == null || list.GetCount(out count) != 0) {
                burst.errors.Add("peak meter endpoint enumeration unavailable"); return burst;
            }
            if (count > 16) { burst.truncated = true; count = 16; }
            for (uint i = 0; i < count; i++) {
                IMMDevice device = null; object meterObject = null; bool kept = false;
                try {
                    string id;
                    if (list.Item(i, out device) != 0 || device == null || device.GetId(out id) != 0) {
                        burst.errors.Add("peak meter endpoint unavailable"); continue;
                    }
                    Guid iid = typeof(IAudioMeterInformation).GUID;
                    if (device.Activate(ref iid, 23, IntPtr.Zero, out meterObject) != 0 || meterObject == null) {
                        burst.errors.Add("peak meter unavailable"); continue;
                    }
                    tracks.Add(new JarvisMeterTrack { id=id, device=device, meter=(IAudioMeterInformation)meterObject });
                    kept = true;
                } finally { if (!kept) { Release(meterObject); Release(device); } }
            }
            burst.endpointsSampled = tracks.Count;
            var clock = Stopwatch.StartNew();
            bool first = true;
            while (clock.ElapsedMilliseconds < BurstMs) {
                int now = (int)clock.ElapsedMilliseconds;
                foreach (var t in tracks) {
                    float peak;
                    if (t.meter.GetPeakValue(out peak) != 0 || float.IsNaN(peak) || peak < 0f || peak > 1f) {
                        if (burst.errors.Count < 8) burst.errors.Add("peak meter read failed"); continue;
                    }
                    burst.samples++;
                    bool loud = peak >= OnPeak;
                    if (!t.active) {
                        if (!loud) continue;
                        t.active = true; t.fromStart = first; t.startMs = now; t.lastLoudMs = now; t.max = peak;
                        Attribute(t);
                    } else if (loud) {
                        t.lastLoudMs = now; if (peak > t.max) t.max = peak;
                    } else if (now - t.lastLoudMs >= HoldMs) {
                        Finish(t, burst, false);
                    }
                }
                first = false;
                System.Threading.Thread.Sleep(StepMs);
            }
            burst.elapsedMs = (int)clock.ElapsedMilliseconds;
            foreach (var t in tracks) if (t.active) Finish(t, burst, true);
        } finally {
            foreach (var t in tracks) { Release(t.meter); Release(t.device); }
            Release(list);
        }
        return burst;
    }
    static void Finish(JarvisMeterTrack t, JarvisAudioBurst burst, bool openEnded) {
        int duration = t.lastLoudMs - t.startMs + StepMs;
        t.active = false;
        if (openEnded || t.fromStart || duration > MaxBeepMs) { burst.sustained++; return; }
        if (burst.events.Count >= MaxEvents) { burst.truncated = true; return; }
        burst.events.Add(new JarvisAudioEvent { endpoint=t.id, startMs=t.startMs, durationMs=duration,
            peak=Math.Round(t.max, 4), pid=t.pid, processStart=t.processStart,
            identityKnown=t.known, systemSounds=t.systemSounds });
    }
    // Attribute the onset to the session whose own meter is loudest; a shared
    // or system-sounds session is reported as such, never as a process.
    static void Attribute(JarvisMeterTrack t) {
        object managerObject = null; IAudioSessionEnumerator enumerator = null;
        t.pid = 0; t.processStart = null; t.known = false; t.systemSounds = false;
        try {
            Guid iid = typeof(IAudioSessionManager2).GUID;
            int count;
            if (t.device.Activate(ref iid, 23, IntPtr.Zero, out managerObject) != 0 || managerObject == null) return;
            if (((IAudioSessionManager2)managerObject).GetSessionEnumerator(out enumerator) != 0 || enumerator == null ||
                enumerator.GetCount(out count) != 0 || count < 0 || count > 64) return;
            float best = 0f;
            for (int i = 0; i < count; i++) {
                IAudioSessionControl2 session = null;
                try {
                    if (enumerator.GetSession(i, out session) != 0 || session == null) continue;
                    var sessionMeter = session as IAudioMeterInformation;
                    float peak;
                    if (sessionMeter == null || sessionMeter.GetPeakValue(out peak) != 0 || peak < OnPeak || peak <= best) continue;
                    uint pid;
                    int pidHr = session.GetProcessId(out pid);
                    best = peak;
                    t.systemSounds = session.IsSystemSoundsSession() == 0;
                    t.pid = pidHr == 0 ? pid : 0; t.processStart = null; t.known = false;
                    if (pidHr == 0 && !t.systemSounds) {
                        try {
                            using (Process process = Process.GetProcessById((int)pid)) {
                                t.processStart = process.StartTime.ToUniversalTime().ToString("o");
                                t.known = true;
                            }
                        } catch (Exception) { }
                    }
                } catch (Exception) { }
                finally { Release(session); }
            }
        } catch (Exception) { }
        finally { Release(enumerator); Release(managerObject); }
    }
    static void ReadSessions(IMMDevice device, string id, string flow, JarvisAudioSnapshot result) {
        object managerObject = null; IAudioSessionEnumerator enumerator = null;
        try {
            Guid iid = typeof(IAudioSessionManager2).GUID;
            if (device.Activate(ref iid, 23, IntPtr.Zero, out managerObject) != 0 || managerObject == null) {
                result.errors.Add("Core Audio session manager unavailable"); return;
            }
            var manager = (IAudioSessionManager2)managerObject;
            int count;
            if (manager.GetSessionEnumerator(out enumerator) != 0 || enumerator == null ||
                enumerator.GetCount(out count) != 0 || count < 0) {
                result.errors.Add("Core Audio session enumeration unavailable"); return;
            }
            for (int i = 0; i < count; i++) {
                if (result.sessions.Count >= MaxSessions) { result.truncated = true; break; }
                IAudioSessionControl2 session = null;
                try {
                    if (enumerator.GetSession(i, out session) != 0 || session == null) {
                        result.errors.Add("Core Audio session item unavailable"); continue;
                    }
                    int sessionState; uint pid;
                    int stateHr = session.GetState(out sessionState);
                    int pidHr = session.GetProcessId(out pid);
                    if (stateHr != 0 || pidHr < 0) {
                        result.errors.Add("Core Audio session state unavailable"); continue;
                    }
                    var row = new JarvisAudioSession { endpoint=id, flow=flow, state=sessionState,
                        pid=pid, processSession=-1, systemSounds=session.IsSystemSoundsSession()==0,
                        singleProcess=pidHr==0 };
                    try {
                        using (Process process = Process.GetProcessById((int)pid)) {
                            row.processStart = process.StartTime.ToUniversalTime().ToString("o");
                            row.processSession = process.SessionId;
                            row.identityKnown = row.singleProcess;
                        }
                    } catch (Exception) { row.identityKnown = false; }
                    result.sessions.Add(row);
                } catch (Exception) { result.errors.Add("Core Audio session read failed"); }
                finally { Release(session); }
            }
        } catch (Exception) { result.errors.Add("Core Audio session manager failed"); }
        finally { Release(enumerator); Release(managerObject); }
    }
}
'@

try {
  Add-Type -TypeDefinition $source -ErrorAction Stop
  $state = [JarvisAudioSnapshot]::Read()
} catch {
  $state.errors += ('Core Audio metadata probe unavailable: ' + $_.Exception.GetType().Name)
}
# Presence at the moment of a beep (collectors/host/beepcheck.py): the Windows
# sessions and the names of running programs, read in this same process so the
# check costs no extra PowerShell start. Names only; nothing about their content.
$presence = [ordered]@{ sessions = @(); procs = @(); error = '' }
try {
  $q = (& "$env:SystemRoot\System32\qwinsta.exe" 2>$null) | Select-Object -Skip 1
  foreach ($line in $q) {
    $t = ($line -replace '^[ >]', '').Trim() -split '\s+'
    if ($t.Count -ge 3) { $presence.sessions += [ordered]@{ name = $t[0]; user = $(if ($t.Count -ge 4) { $t[1] } else { '' }); state = $t[-1] } }
  }
} catch { $presence.error = 'sessions: ' + $_.Exception.GetType().Name }
try { $presence.procs = @(Get-Process | ForEach-Object { $_.ProcessName.ToLower() } | Sort-Object -Unique) } catch { }
if ($state -is [System.Collections.IDictionary]) { $state['presence'] = $presence }
else { $state | Add-Member -NotePropertyName presence -NotePropertyValue $presence -Force }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($state | ConvertTo-Json -Depth 6 -Compress)))
