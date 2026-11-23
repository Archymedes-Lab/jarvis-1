//! The daemon's lifecycle as the app manages it: detect, start, recover, report.
//!
//! The app is still only a client. It never monitors anything itself. What it
//! owns is making sure the monitoring program is running and telling the truth
//! about it:
//!
//! * **Start.** When nothing answers on the daemon's port, start it through the
//!   installer's supported mechanism (the logon scheduled task) and only if that
//!   task does not exist, directly. Never both: that would race two daemons for
//!   one port. A port that already answers is never "started" again.
//! * **Recover.** A daemon that stopped is restarted, within a budget
//!   (`Governor`): a daemon that dies again and again is reported as failing,
//!   with its reason, instead of being restarted in a loop forever.
//! * **Report.** `Status` is what the person sees. It is derived from facts
//!   (can the program be found, does it answer, did the pulse say healthy, are
//!   collectors blind). "Monitoring" is shown only when all of them hold.

use serde::Serialize;
use serde_json::Value;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::pulse;

/// How long a freshly started daemon gets to open its port. A first start on a
/// slow disk verifies its own code before it listens.
const START_WAIT: Duration = Duration::from_secs(45);
/// At most this many starts per window; after that the failure is reported.
const MAX_STARTS: usize = 3;
const WINDOW: Duration = Duration::from_secs(600);
const TASK_NAME: &str = "jarvis native service";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Looking, or waiting for a start to finish.
    Starting,
    /// Answering, healthy, no collector blind.
    Live,
    /// Answering, but the daemon itself says something is not working.
    Degraded,
    /// Not installed on this computer.
    NotInstalled,
    /// Installed, answering, but this app is not authorised.
    NotAuthorised,
    /// Installed but not answering, and starting it did not work.
    Stopped,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    /// One plain sentence for the person.
    pub message: String,
    /// What to do or what was found, when there is more to say. For blind
    /// collectors this is a short count by cause; `blind` names every one.
    pub detail: String,
    /// Every collector the daemon reported blind, each with its cause, so the
    /// interface can group them instead of printing one long sentence. Never
    /// filtered: a limitation is grouped, not hidden.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blind: Vec<Blind>,
}

/// Why a collector cannot fully see, sorted into the few causes a person can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlindKind {
    /// This edition runs without the elevated sensor (platform/admin_sensor.py).
    AdminSensor,
    /// It ran and failed.
    Failed,
    /// It has not reported within its window.
    Stale,
    /// The daemon gave another reason, or none.
    Other,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Blind {
    pub job: String,
    pub label: String,
    pub reason: String,
    pub kind: BlindKind,
}

/// The daemon's words for "this edition has no administrator sensor"
/// (jarvis/core/mechanisms.py NEEDS_ADMIN_SENSOR).
const NEEDS_ADMIN_SENSOR: &str = "Needs administrator sensor";

impl Status {
    fn new(phase: Phase, message: &str, detail: impl Into<String>) -> Self {
        Status { phase, message: message.into(), detail: detail.into(), blind: Vec::new() }
    }
}

/// Why a collector is blind, from what the daemon reports about it. An explicit
/// `reason` wins; otherwise the failure flags are put in plain words.
fn blind_reason(b: &Value) -> (String, BlindKind) {
    if let Some(r) = b.get("reason").and_then(Value::as_str).filter(|r| !r.is_empty()) {
        let kind = if r == NEEDS_ADMIN_SENSOR { BlindKind::AdminSensor } else { BlindKind::Other };
        return (r.to_string(), kind);
    }
    if b.get("error").and_then(Value::as_bool) == Some(true) {
        return ("it failed the last time it ran".into(), BlindKind::Failed);
    }
    match b.get("freshness").and_then(Value::as_str) {
        Some("STALE") => ("it has not reported recently".into(), BlindKind::Stale),
        _ => ("no reason given".into(), BlindKind::Other),
    }
}

/// The blind list from a pulse, in the daemon's order, bounded so a runaway
/// peer cannot grow the status without limit (the registry has ~100 collectors).
pub fn blind_items(p: &Value) -> Vec<Blind> {
    const MAX_BLIND: usize = 256;
    p.get("blind")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .take(MAX_BLIND)
                .map(|b| {
                    let job = b.get("job").and_then(Value::as_str).unwrap_or("").chars().take(64).collect::<String>();
                    let label = b
                        .get("label")
                        .and_then(Value::as_str)
                        .filter(|l| !l.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| if job.is_empty() { "a check".into() } else { job.clone() });
                    let (reason, kind) = blind_reason(b);
                    Blind { job, label: label.chars().take(120).collect(), reason: reason.chars().take(300).collect(), kind }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// "9 need the administrator sensor · 7 have not reported recently · …":
/// one short line by cause, largest first, for the CLI and tooltips.
pub fn blind_summary(items: &[Blind]) -> String {
    let count = |k: BlindKind| items.iter().filter(|b| b.kind == k).count();
    let mut parts: Vec<(usize, String)> = Vec::new();
    for (kind, one, many) in [
        (BlindKind::AdminSensor, "needs the administrator sensor", "need the administrator sensor"),
        (BlindKind::Stale, "has not reported recently", "have not reported recently"),
        (BlindKind::Failed, "failed the last time it ran", "failed the last time they ran"),
        (BlindKind::Other, "has another problem", "have other problems"),
    ] {
        let n = count(kind);
        if n > 0 {
            parts.push((n, format!("{n} {}", if n == 1 { one } else { many })));
        }
    }
    parts.sort_by(|a, b| b.0.cmp(&a.0));
    parts.into_iter().map(|(_, s)| s).collect::<Vec<_>>().join(" · ")
}

/// What a pulse from the daemon means for the person. `blind` lists collectors
/// that cannot run; each is named so the limitation is explained, not hidden.
pub fn classify_pulse(p: &Value) -> Status {
    if p.get("ok").and_then(Value::as_bool) != Some(true) {
        return Status::new(Phase::Degraded, "ARGUS-INSTINCT is running, but its latest report did not come through", "It tries again by itself in a moment.");
    }
    let blind = blind_items(p);
    let n = blind.len();
    let summary = blind_summary(&blind);
    let with = |message: &str| Status { phase: Phase::Degraded, message: message.into(), detail: summary.clone(), blind: blind.clone() };
    if p.get("healthy").and_then(Value::as_bool) != Some(true) {
        if n == 0 {
            return Status::new(Phase::Degraded, "ARGUS-INSTINCT is running, but says part of it is not working", "");
        }
        return with(&if n == 1 {
            "ARGUS-INSTINCT is running, but 1 of its checks is not working".to_string()
        } else {
            format!("ARGUS-INSTINCT is running, but {n} of its checks are not working")
        });
    }
    if n > 0 {
        return with(&if n == 1 {
            "ARGUS-INSTINCT can't fully check 1 part of your computer right now".to_string()
        } else {
            format!("ARGUS-INSTINCT can't fully check {n} parts of your computer right now")
        });
    }
    Status::new(Phase::Live, "ARGUS-INSTINCT is watching your computer", "")
}

/// Restart budget: at most `MAX_STARTS` starts per `WINDOW`.
#[derive(Debug, Default)]
pub struct Governor {
    starts: Vec<Instant>,
}

impl Governor {
    pub fn allow(&mut self, now: Instant) -> bool {
        self.starts.retain(|t| now.duration_since(*t) < WINDOW);
        if self.starts.len() >= MAX_STARTS {
            return false;
        }
        self.starts.push(now);
        true
    }
}

/// Where the daemon's runtime is installed. Injectable for tests.
pub fn runtime_home(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(py) = env("JARVIS_PYTHON").filter(|p| !p.is_empty()) {
        return Path::new(&py).parent().map(Path::to_path_buf);
    }
    if cfg!(windows) {
        return env("JARVIS_HOME")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .or_else(app_dir_with_engine)
            .or_else(|| env("LOCALAPPDATA").map(|l| Path::new(&l).join("Programs").join("Jarvis")));
    }
    None
}

/// The ARGUS-INSTINCT Setup installs the app beside its engine:
/// `<folder>\argus-desktop.exe` and `<folder>\engine\argus-instinct.exe`.
fn app_dir_with_engine() -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    dir.join("engine").join(ENGINE_EXE).is_file().then_some(dir)
}

/// The released Windows engine's file name (release/build_windows.py, EXE).
pub const ENGINE_EXE: &str = "argus-instinct.exe";

/// The daemon's own state folder (`~/.jarvis`, renamed in releases): where it keeps its
/// stop marker and the note explaining a refused restart. `JARVIS_STATE_DIR` overrides it (tests).
pub fn state_dir(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(d) = env("JARVIS_STATE_DIR").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d));
    }
    env("USERPROFILE").or_else(|| env("HOME")).map(|h| Path::new(&h).join(".jarvis"))
}

/// True when someone ran `jarvis stop`: monitoring is off on purpose, so the app must not undo it.
pub fn stopped_on_purpose(env: &dyn Fn(&str) -> Option<String>, exists: &dyn Fn(&Path) -> bool) -> bool {
    state_dir(env).is_some_and(|d| exists(&d.join("stopped-on-purpose")))
}

/// Why the supervisor refused to restart the daemon (a crash loop), if it said so in the last 15 minutes.
pub fn refusal_note(env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let path = state_dir(env)?.join("start-refused.txt");
    let age = std::fs::metadata(&path).ok()?.modified().ok()?.elapsed().ok()?;
    if age > Duration::from_secs(900) {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let text: String = text.trim().chars().take(600).collect();
    (!text.is_empty()).then_some(text)
}

/// The packaged program (a compiled `jarvis.exe` that is both the CLI and the
/// daemon) when the installer put one in `home`.
pub fn packaged_exe(home: &Path, exists: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    [home.join("engine").join(ENGINE_EXE), home.join("jarvis.exe")].into_iter().find(|exe| exists(exe))
}

pub fn installed(env: &dyn Fn(&str) -> Option<String>, exists: &dyn Fn(&Path) -> bool) -> bool {
    if env("JARVIS_PYTHON").filter(|p| !p.is_empty()).is_some() {
        return true;
    }
    if cfg!(windows) {
        return runtime_home(env).is_some_and(|h| packaged_exe(&h, exists).is_some() || exists(&h.join("python").join("python.exe")));
    }
    ["/usr/local/bin/jarvis-svc", "/usr/bin/jarvis-svc"].iter().any(|p| exists(Path::new(p)))
}

/// True when something accepts connections on the daemon's loopback port.
pub fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(2)).is_ok()
}

/// The native service's own folder (`%LOCALAPPDATA%/Jarvis/NativeService`, renamed in releases):
/// its supervisor keeps its state there, and a `pause` file there means maintenance.
pub fn service_dir(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    env("LOCALAPPDATA").map(|l| Path::new(&l).join("Jarvis").join("NativeService"))
}

/// True while the supervisor is paused for maintenance: it checks but starts and stops nothing,
/// and this app must not start the daemon behind its back either.
pub fn paused_for_maintenance(env: &dyn Fn(&str) -> Option<String>, exists: &dyn Fn(&Path) -> bool) -> bool {
    service_dir(env).is_some_and(|d| exists(&d.join("pause")))
}

/// True when the installer's service owns the daemon: the engine is installed and this is not a
/// development run (`JARVIS_PYTHON`). Then the supervisor, not this app, starts and restarts it.
pub fn managed_by_service(env: &dyn Fn(&str) -> Option<String>, exists: &dyn Fn(&Path) -> bool) -> bool {
    env("JARVIS_PYTHON").filter(|p| !p.is_empty()).is_none()
        && runtime_home(env).is_some_and(|h| packaged_exe(&h, exists).is_some())
}

/// What to do about a daemon that is not answering.
#[derive(Debug, PartialEq, Eq)]
pub enum StartPlan {
    /// Ask the service's scheduled task to run (it is already supervising; an extra run is ignored).
    RunTask,
    /// Development and bare installs only: start the program directly.
    StartDirect,
    /// Leave it alone and say why.
    Refuse(String),
}

/// A daemon the service supervises is never started a second way: a copy started here would run
/// outside the supervisor's restart budget and logs, and would undo `native stop` (which removes
/// the task on purpose, for an upgrade or a removal). With the task absent or not runnable, the
/// honest answer is that the service is not running, with what to do about it.
pub fn plan_start(managed: bool, task: &Result<bool, String>) -> StartPlan {
    match (managed, task) {
        (_, Ok(true)) => StartPlan::RunTask,
        (true, Ok(false)) => StartPlan::Refuse(
            "The part of ARGUS-INSTINCT that checks your computer was turned off, usually for an update or a removal. Nothing is being checked until it is set up again: run the ARGUS-INSTINCT installer. This app does not start it a second way, so nothing runs twice."
                .into(),
        ),
        (true, Err(e)) => StartPlan::Refuse(format!(
            "Windows would not start the part of ARGUS-INSTINCT that checks your computer ({e}). This app does not start it a second way, so nothing runs twice."
        )),
        (false, _) => StartPlan::StartDirect,
    }
}

#[cfg(windows)]
fn hidden(c: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    c.creation_flags(0x0800_0000) // CREATE_NO_WINDOW
}
#[cfg(not(windows))]
fn hidden(c: &mut Command) -> &mut Command {
    c
}

/// Ask the installer's scheduled task to start the daemon. Ok(true): the task
/// exists and was started; Ok(false): there is no such task.
fn start_task() -> Result<bool, String> {
    if !cfg!(windows) {
        return Ok(false);
    }
    let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let exe = Path::new(&sys).join("System32").join("schtasks.exe");
    let mut q = Command::new(&exe);
    q.args(["/Query", "/TN", TASK_NAME]).stdout(Stdio::null()).stderr(Stdio::null());
    if !hidden(&mut q).status().map(|s| s.success()).unwrap_or(false) {
        return Ok(false);
    }
    let mut r = Command::new(&exe);
    r.args(["/Run", "/TN", TASK_NAME]).stdout(Stdio::null()).stderr(Stdio::null());
    match hidden(&mut r).status() {
        Ok(s) if s.success() => Ok(true),
        _ => Err("Windows would not start the ARGUS-INSTINCT background task".into()),
    }
}

/// Start the daemon directly, detached from this app (closing the app must not
/// stop monitoring). Only used when the installer's task does not exist.
fn start_direct(env: &dyn Fn(&str) -> Option<String>, port: u16) -> Result<(), String> {
    let home = runtime_home(env).ok_or("The part of ARGUS-INSTINCT that checks your computer was not found")?;
    let port_s = port.to_string();
    let mut c = match (env("JARVIS_PYTHON").filter(|p| !p.is_empty()), packaged_exe(&home, &|p| p.exists())) {
        (Some(py), _) => {
            let mut c = Command::new(py);
            c.args(["-m", "jarvis", "serve", "--port", &port_s, "--supervised"]);
            c
        }
        (None, Some(exe)) => {
            let mut c = Command::new(exe);
            c.args(["serve", "--port", &port_s, "--supervised"]).current_dir(&home);
            c
        }
        (None, None) => {
            let mut c = Command::new(home.join("python").join("python.exe"));
            c.args(["-m", "jarvis", "serve", "--port", &port_s, "--supervised"]);
            c
        }
    };
    c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    if let Some(app) = env("JARVIS_APP_DIR").filter(|p| !p.is_empty()).map(PathBuf::from).or_else(|| Some(home.join("app")).filter(|p| p.is_dir())) {
        c.current_dir(app);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000 | 0x0000_0008); // no window, detached from this app
    }
    c.spawn().map(|_| ()).map_err(|e| format!("could not start ARGUS-INSTINCT ({e})"))
}

/// Make sure the daemon answers, starting it when it does not. Returns the
/// status to show: `Live`-class statuses are decided by the pulse, not here,
/// so this returns `Starting` once the port is open.
/// Set once this app has heard from the daemon. On a PC where the daemon runs
/// inside Linux (WSL) nothing here looks "installed", so a short daemon restart
/// used to read as "not installed" (2026-11-05).
static SEEN_DAEMON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn mark_seen() {
    SEEN_DAEMON.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// What to say when nothing answers and no engine is installed on this side.
pub fn not_answering_or_missing(seen: bool) -> Status {
    if seen {
        Status::new(
            Phase::Stopped,
            "ARGUS-INSTINCT is not answering right now",
            "It was answering a moment ago. It usually comes back by itself within a minute or two; \
             nothing new is being checked until then. If this stays, restart the computer.",
        )
    } else {
        Status::new(
            Phase::NotInstalled,
            "The part of ARGUS-INSTINCT that checks your computer is not installed",
            "Run the ARGUS-INSTINCT installer to add it. Nothing is being checked until then.",
        )
    }
}

pub fn ensure_running(governor: &mut Governor, port: u16) -> Status {
    let env = |k: &str| std::env::var(k).ok();
    if !installed(&env, &|p| p.exists()) {
        return not_answering_or_missing(SEEN_DAEMON.load(std::sync::atomic::Ordering::Relaxed));
    }
    if listening(port) {
        return Status::new(Phase::Starting, "Connecting to ARGUS-INSTINCT", "");
    }
    if paused_for_maintenance(&env, &|p| p.exists()) {
        return Status::new(
            Phase::Stopped,
            "ARGUS-INSTINCT is paused for maintenance",
            "Someone paused it on purpose, so nothing is being started or restarted until the pause ends. This app will not start it meanwhile.",
        );
    }
    if stopped_on_purpose(&env, &|p| p.exists()) {
        return Status::new(
            Phase::Stopped,
            "ARGUS-INSTINCT was turned off on purpose",
            "Someone turned it off (jarvis stop). Nothing is being checked until it is turned on again (jarvis start). This app will not turn it back on by itself.",
        );
    }
    if !governor.allow(Instant::now()) {
        return Status::new(
            Phase::Stopped,
            "ARGUS-INSTINCT has stopped and could not be started again",
            "It was restarted several times in the last ten minutes and stopped each time. Nothing is being checked. Restart the computer, or reinstall ARGUS-INSTINCT if this keeps happening.",
        );
    }
    // The service's task is the supported way, and where one exists it is the only way (plan_start).
    let task = start_task();
    let started = match plan_start(managed_by_service(&env, &|p| p.exists()), &task) {
        StartPlan::RunTask => Ok(()),
        StartPlan::StartDirect => start_direct(&env, port),
        StartPlan::Refuse(why) => {
            return Status::new(Phase::Stopped, "ARGUS-INSTINCT is not watching your computer", why);
        }
    };
    if let Err(e) = started {
        return Status::new(Phase::Stopped, "ARGUS-INSTINCT is not running and could not be started", e);
    }
    let end = Instant::now() + START_WAIT;
    while Instant::now() < end {
        if listening(port) {
            return Status::new(Phase::Starting, "ARGUS-INSTINCT started; connecting", "");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let why = refusal_note(&env).unwrap_or_else(|| format!("It did not open its local port within {} seconds.", START_WAIT.as_secs()));
    Status::new(Phase::Stopped, "ARGUS-INSTINCT was started but is not answering", why)
}

/// The last status, for the interface to read.
static CURRENT: Mutex<Option<Status>> = Mutex::new(None);

pub fn set(s: Status) {
    if let Ok(mut g) = CURRENT.lock() {
        *g = Some(s);
    }
}

pub fn current() -> Status {
    CURRENT
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| Status::new(Phase::Starting, "Starting ARGUS-INSTINCT", ""))
}

/// The status after a failed token fetch or refused request.
pub fn from_error(e: &str) -> Status {
    if e.contains("not paired") || e.contains("refused this app") {
        Status::new(Phase::NotAuthorised, "This app is not allowed to talk to ARGUS-INSTINCT yet", e)
    } else {
        Status::new(Phase::Stopped, "ARGUS-INSTINCT is not reachable", e)
    }
}

/// Used by `--check`: Ok when the daemon answers after at most one start.
pub fn ensure_for_check() -> Status {
    ensure_running(&mut Governor::default(), pulse::port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_engine_the_argus_instinct_setup_installs() {
        // ARGUS-INSTINCT-Setup puts the engine in engine\argus-instinct.exe
        // beside the app; the older layout had jarvis.exe at the top.
        let home = Path::new("C:\\Users\\u\\AppData\\Local\\Programs\\ARGUS-INSTINCT");
        let engine = home.join("engine").join(ENGINE_EXE);
        assert_eq!(packaged_exe(home, &|p: &Path| p == engine.as_path()), Some(engine.clone()));
        let legacy = home.join("jarvis.exe");
        assert_eq!(packaged_exe(home, &|p: &Path| p == legacy.as_path()), Some(legacy.clone()));
        assert_eq!(packaged_exe(home, &|_: &Path| false), None);
    }
    use serde_json::json;

    #[test]
    fn healthy_and_nothing_blind_is_the_only_live() {
        let p = json!({"ok": true, "healthy": true, "blind": [], "score": 95});
        assert_eq!(classify_pulse(&p).phase, Phase::Live);
    }

    #[test]
    fn a_blind_collector_is_degraded_and_named_with_its_reason() {
        let p = json!({"ok": true, "healthy": true,
            "blind": [{"job": "sysmon", "label": "Windows event log", "reason": "needs administrator rights"}]});
        let s = classify_pulse(&p);
        assert_eq!(s.phase, Phase::Degraded);
        assert!(s.message.contains("can't fully check 1 part of"), "{}", s.message);
        assert_eq!(s.blind.len(), 1);
        assert_eq!((s.blind[0].label.as_str(), s.blind[0].reason.as_str()), ("Windows event log", "needs administrator rights"));
        assert_eq!(s.blind[0].kind, BlindKind::Other);
    }

    #[test]
    fn blind_collectors_are_explained_from_the_daemons_flags() {
        let p = json!({"ok": true, "healthy": true, "blind": [
            {"job": "scan", "label": "Processes", "freshness": "STALE", "error": false},
            {"job": "net", "label": "Network", "freshness": "FRESH", "error": true},
            {"job": "x"}]});
        let s = classify_pulse(&p);
        assert!(s.message.contains("3 parts"));
        let got: Vec<(&str, &str, BlindKind)> = s.blind.iter().map(|b| (b.label.as_str(), b.reason.as_str(), b.kind)).collect();
        assert_eq!(got, vec![
            ("Processes", "it has not reported recently", BlindKind::Stale),
            ("Network", "it failed the last time it ran", BlindKind::Failed),
            ("x", "no reason given", BlindKind::Other),
        ]);
    }

    #[test]
    fn many_blind_collectors_are_grouped_by_cause_and_none_is_dropped() {
        // The shape of a Windows install without the elevated sensor (2026-11-09 report).
        let mut blind = Vec::new();
        for i in 0..9 {
            blind.push(json!({"job": format!("a{i}"), "label": format!("A{i}"), "reason": "Needs administrator sensor", "freshness": "UNAVAILABLE"}));
        }
        for i in 0..7 {
            blind.push(json!({"job": format!("s{i}"), "label": format!("S{i}"), "freshness": "STALE"}));
        }
        for i in 0..6 {
            blind.push(json!({"job": format!("f{i}"), "label": format!("F{i}"), "error": true}));
        }
        let s = classify_pulse(&json!({"ok": true, "healthy": false, "blind": blind}));
        assert_eq!(s.phase, Phase::Degraded);
        assert_eq!(s.message, "ARGUS-INSTINCT is running, but 22 of its checks are not working");
        assert_eq!(s.blind.len(), 22, "grouped, never hidden");
        assert_eq!(s.blind.iter().filter(|b| b.kind == BlindKind::AdminSensor).count(), 9);
        assert_eq!(s.detail, "9 need the administrator sensor · 7 have not reported recently · 6 failed the last time they ran");
        assert!(s.detail.len() < 120, "the short line stays short: {}", s.detail);
    }

    #[test]
    fn the_status_json_carries_the_grouping_keys_the_interface_reads() {
        let s = classify_pulse(&json!({"ok": true, "healthy": true, "blind": [
            {"job": "sysmon", "label": "Sysmon", "reason": "Needs administrator sensor"}]}));
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["blind"][0]["kind"], "admin_sensor");
        assert_eq!(v["blind"][0]["job"], "sysmon");
        let live = serde_json::to_value(classify_pulse(&json!({"ok": true, "healthy": true, "blind": []}))).unwrap();
        assert!(live.get("blind").is_none(), "an empty list is left out");
    }

    #[test]
    fn a_hostile_blind_list_is_bounded() {
        let huge: Vec<Value> = (0..5000).map(|i| json!({"job": "j".repeat(500), "label": format!("{i}{}", "L".repeat(5000))})).collect();
        let s = classify_pulse(&json!({"ok": true, "healthy": true, "blind": huge}));
        assert_eq!(s.blind.len(), 256);
        assert!(s.blind.iter().all(|b| b.job.chars().count() <= 64 && b.label.chars().count() <= 120));
    }

    #[test]
    fn unhealthy_or_incomplete_pulses_are_never_live() {
        for p in [json!({"ok": true, "healthy": false}), json!({"ok": true}), json!({"ok": false}), json!({}), json!(null)] {
            assert_eq!(classify_pulse(&p).phase, Phase::Degraded, "{p}");
        }
    }

    #[test]
    fn the_governor_stops_a_restart_loop_and_forgives_after_the_window() {
        let mut g = Governor::default();
        let t0 = Instant::now();
        assert!(g.allow(t0) && g.allow(t0) && g.allow(t0));
        assert!(!g.allow(t0), "a fourth start inside ten minutes is refused");
        assert!(g.allow(t0 + WINDOW + Duration::from_secs(1)), "and allowed again afterwards");
    }

    #[test]
    fn not_installed_is_said_plainly_and_nothing_is_started() {
        let none = |_: &str| None;
        if cfg!(windows) {
            let env = |k: &str| (k == "LOCALAPPDATA").then(|| "C:\\Users\\nobody\\AppData\\Local".to_string());
            assert!(!installed(&env, &|_| false));
        } else {
            assert!(!installed(&none, &|_| false));
        }
        assert!(installed(&|k: &str| (k == "JARVIS_PYTHON").then(|| "x".to_string()), &|_| false));
    }

    #[test]
    fn errors_map_to_a_reason_the_person_can_act_on() {
        assert_eq!(from_error("ARGUS-INSTINCT is not paired with this app. ...").phase, Phase::NotAuthorised);
        assert_eq!(from_error("could not reach ARGUS-INSTINCT").phase, Phase::Stopped);
    }

    #[test]
    fn listening_sees_a_real_socket_and_a_closed_one() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(listening(port));
        drop(l);
        assert!(!listening(port));
    }

    #[test]
    fn a_daemon_heard_before_is_not_called_missing() {
        let first = not_answering_or_missing(false);
        assert_eq!(first.phase, Phase::NotInstalled);
        let later = not_answering_or_missing(true);
        assert_eq!(later.phase, Phase::Stopped);
        assert!(later.message.contains("not answering right now"), "{}", later.message);
        assert!(!later.message.contains("not installed"));
    }

    #[test]
    fn a_supervised_install_is_never_started_a_second_way() {
        // The service owns the daemon: with its task gone (native stop) or not runnable, do nothing.
        assert!(matches!(plan_start(true, &Ok(false)), StartPlan::Refuse(m) if m.contains("turned off")));
        assert!(matches!(plan_start(true, &Err("denied".into())), StartPlan::Refuse(m) if m.contains("denied")));
        // The task, when it exists, is asked: running it again is harmless (the supervisor ignores a repeat).
        assert_eq!(plan_start(true, &Ok(true)), StartPlan::RunTask);
        assert_eq!(plan_start(false, &Ok(true)), StartPlan::RunTask);
    }

    #[test]
    fn a_development_run_may_still_start_the_program_directly() {
        assert_eq!(plan_start(false, &Ok(false)), StartPlan::StartDirect);
        assert_eq!(plan_start(false, &Err("x".into())), StartPlan::StartDirect);
    }

    #[test]
    fn the_engine_layout_means_managed_and_a_development_override_means_not() {
        let home = Path::new("H");
        let engine = home.join("engine").join(ENGINE_EXE);
        let env = |k: &str| (k == "JARVIS_HOME").then(|| "H".to_string());
        if cfg!(windows) {
            assert!(managed_by_service(&env, &|p| p == engine));
            assert!(!managed_by_service(&env, &|_| false), "no engine: nothing for a service to own");
        }
        let dev = |k: &str| match k {
            "JARVIS_PYTHON" => Some("py.exe".to_string()),
            "JARVIS_HOME" => Some("H".to_string()),
            _ => None,
        };
        assert!(!managed_by_service(&dev, &|p| p == engine), "a development override is never managed");
    }

    #[test]
    fn a_maintenance_pause_is_seen_in_the_services_own_folder() {
        let env = |k: &str| (k == "LOCALAPPDATA").then(|| "L".to_string());
        let pause = Path::new("L").join("Jarvis").join("NativeService").join("pause");
        assert!(paused_for_maintenance(&env, &|p| p == pause));
        assert!(!paused_for_maintenance(&env, &|_| false));
        assert!(!paused_for_maintenance(&|_: &str| None, &|_| true));
    }

    fn temp_state(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("argus-life-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_state_folder_is_the_daemons_own_unless_overridden() {
        let env = |k: &str| (k == "USERPROFILE").then(|| "C-profile".to_string());
        assert_eq!(state_dir(&env), Some(Path::new("C-profile").join(".jarvis")));
        let over = |k: &str| match k {
            "JARVIS_STATE_DIR" => Some("elsewhere".to_string()),
            "USERPROFILE" => Some("C-profile".to_string()),
            _ => None,
        };
        assert_eq!(state_dir(&over), Some(PathBuf::from("elsewhere")));
        assert_eq!(state_dir(&|_: &str| None), None);
    }

    #[test]
    fn an_intentional_stop_is_seen_through_the_marker_file() {
        let env = |k: &str| (k == "USERPROFILE").then(|| "P".to_string());
        let marker = Path::new("P").join(".jarvis").join("stopped-on-purpose");
        assert!(stopped_on_purpose(&env, &|p| p == marker));
        assert!(!stopped_on_purpose(&env, &|_| false), "no marker: a stopped daemon is restarted");
        assert!(!stopped_on_purpose(&|_: &str| None, &|_| true), "no state folder: nothing to read");
    }

    #[test]
    fn the_refusal_reason_is_shown_while_fresh_and_dropped_when_old() {
        let dir = temp_state("refusal");
        let env = {
            let d = dir.display().to_string();
            move |k: &str| (k == "JARVIS_STATE_DIR").then(|| d.clone())
        };
        assert_eq!(refusal_note(&env), None, "no note: no reason invented");
        let note = dir.join("start-refused.txt");
        std::fs::write(&note, "  started 5 times in the last 60 minutes  \n").unwrap();
        assert_eq!(refusal_note(&env).as_deref(), Some("started 5 times in the last 60 minutes"));
        let old = std::time::SystemTime::now() - Duration::from_secs(3 * 3600);
        std::fs::File::options().write(true).open(&note).unwrap().set_modified(old).unwrap();
        assert_eq!(refusal_note(&env), None, "an old note describes a different problem");
    }
}
