//! First-run provisioning: the app pairs itself with the daemon on this machine.
//!
//! Nobody should have to run `jarvis desktop pair` and copy a token. When the
//! app has no client token it asks the local daemon runtime (the one the
//! installer put on this machine) to issue one, using the daemon's own
//! `desktop pair` command, and stores it where pairing.rs reads it.
//!
//! What this keeps from the manual flow, deliberately:
//! * The credential is still a per-client, revocable, hashed-at-rest token
//!   issued by the daemon. Nothing is weakened; only the copying is gone.
//! * The token travels over a pipe from the daemon's CLI to this process. It
//!   is never a command-line argument, an environment variable or a log line.
//! * The file is created exclusively, with owner-only permissions (0600; on
//!   Windows the inherited ACL is replaced with one grant to the current user).
//! * A *missing* file is provisioned. A token the daemon refuses (revoked) is
//!   not silently replaced: revoking a client must stay meaningful.
//!
//! Only a daemon whose store this account can write can be provisioned this
//! way (the Windows per-user install). A Linux service-account daemon needs
//! one elevation (polkit); that path is `via_pkexec`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::pairing;

/// A failed attempt is not repeated more often than this (the pulse loop asks
/// every few seconds; each attempt starts a process).
const RETRY_AFTER: Duration = Duration::from_secs(30);
const PAIR_TIMEOUT: Duration = Duration::from_secs(60);
const CLIENT_NAME: &str = "desktop";

static LAST_FAILURE: Mutex<Option<(Instant, String)>> = Mutex::new(None);

/// The command that issues a client token on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
}

/// Find the local daemon runtime. `env` is injectable for tests.
///
/// * `JARVIS_PYTHON`: an explicit interpreter (development, tests).
/// * Windows: the installer's private Python, `%LOCALAPPDATA%\Programs\Jarvis`
///   (or `JARVIS_HOME`).
/// * elsewhere: the service account's launcher, through polkit.
pub fn pair_command(env: &dyn Fn(&str) -> Option<String>, exists: &dyn Fn(&Path) -> bool) -> Option<PairCommand> {
    let name = client_name(env);
    let pair_args = |mut head: Vec<String>| {
        head.extend(["desktop".into(), "pair".into(), "--name".into(), name.clone()]);
        head
    };
    if let Some(py) = env("JARVIS_PYTHON").filter(|p| !p.is_empty()) {
        return Some(PairCommand { program: PathBuf::from(py), args: pair_args(vec!["-m".into(), "jarvis".into()]) });
    }
    if cfg!(windows) {
        let home = crate::lifecycle::runtime_home(env)?;
        if let Some(exe) = crate::lifecycle::packaged_exe(&home, exists) {
            return Some(PairCommand { program: exe, args: pair_args(vec![]) });
        }
        let py = home.join("python").join("python.exe");
        return exists(&py).then(|| PairCommand { program: py, args: pair_args(vec!["-m".into(), "jarvis".into()]) });
    }
    for svc in ["/usr/local/bin/jarvis-svc", "/usr/bin/jarvis-svc"] {
        let p = Path::new(svc);
        if exists(p) {
            let pk = ["/usr/bin/pkexec"].into_iter().map(Path::new).find(|p| exists(p))?;
            let mut args = vec![p.display().to_string()];
            args.extend(pair_args(vec![]));
            return Some(PairCommand { program: pk.to_path_buf(), args });
        }
    }
    None
}

/// The client's name in the daemon's list: `desktop`, or `desktop-<account>`
/// where several accounts share one daemon.
fn client_name(env: &dyn Fn(&str) -> Option<String>) -> String {
    if cfg!(windows) {
        return CLIENT_NAME.into();
    }
    match env("USER").filter(|u| !u.is_empty() && u.len() <= 28 && u.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')) {
        Some(u) => format!("{CLIENT_NAME}-{u}"),
        None => CLIENT_NAME.into(),
    }
}

/// The last non-empty stdout line that is a client token. The daemon prints its
/// explanation on stderr and the token alone on stdout.
pub fn token_from_output(stdout: &str) -> Option<String> {
    stdout.lines().map(str::trim).rev().find(|l| !l.is_empty()).filter(|l| pairing::valid_token(l)).map(str::to_string)
}

fn run_pair(cmd: &PairCommand) -> Result<String, String> {
    let mut c = Command::new(&cmd.program);
    c.args(&cmd.args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console flash for the user
    }
    let mut child = c.spawn().map_err(|e| format!("could not start the ARGUS-INSTINCT program ({e})"))?;
    let mut out = child.stdout.take().ok_or("no output pipe")?;
    // Read on a thread so a stalled child cannot hang the app past the timeout.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut std::io::Read::take(&mut out, 4096), &mut s);
        let _ = tx.send(s);
    });
    let stdout = match rx.recv_timeout(PAIR_TIMEOUT) {
        Ok(s) => s,
        Err(_) => {
            let _ = child.kill();
            return Err("ARGUS-INSTINCT did not answer the pairing request in time".into());
        }
    };
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("ARGUS-INSTINCT refused to pair this app".into());
    }
    token_from_output(&stdout).ok_or_else(|| "ARGUS-INSTINCT did not return a client token".to_string())
}

/// Store `token` at `path`: exclusive temp file, owner-only, then rename.
pub fn store_token(path: &Path, token: &str) -> Result<(), String> {
    if !pairing::valid_token(token) {
        return Err("that is not a client token".into());
    }
    let dir = path.parent().ok_or("the token path has no folder")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("could not create {} ({e})", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let tmp = dir.join(format!(".client.token.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| -> Result<(), String> {
        let mut f = opts.open(&tmp).map_err(|e| format!("could not write the token ({e})"))?;
        restrict_to_owner(&tmp)?; // before the secret is in the file
        f.write_all(token.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        std::fs::rename(&tmp, path).map_err(|e| format!("could not store the token ({e})"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Windows: drop inherited access and grant only the current user. Other
/// platforms get 0600 at creation. Failing to restrict is a failure: a secret
/// must not be stored with the access it cannot be shown to have.
fn restrict_to_owner(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let user = std::env::var("USERNAME").map_err(|_| "cannot tell which account this is".to_string())?;
        let domain = std::env::var("USERDOMAIN").unwrap_or_default();
        let who = if domain.is_empty() { user } else { format!("{domain}\\{user}") };
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let st = Command::new(Path::new(&sys).join("System32").join("icacls.exe"))
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("{who}:(R,W,D)"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .status()
            .map_err(|e| format!("could not restrict the token file ({e})"))?;
        if !st.success() {
            return Err("could not restrict the token file to this account".into());
        }
    }
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

/// Provision with an injected issuer (tests), refusing to overwrite a token file that is there.
pub fn provision_with(path: &Path, issue: &dyn Fn() -> Result<String, String>) -> Result<(), String> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Err("a token file already exists; it is not replaced".into());
    }
    let token = issue()?;
    store_token(path, &token)
}

fn missing_runtime() -> String {
    "The part of ARGUS-INSTINCT that checks your computer is not installed. Run the ARGUS-INSTINCT installer, \
     or install the server edition for a Linux machine."
        .into()
}

/// Pair this app with the local daemon, if there is one and no token yet.
/// Throttled: a failure is remembered for RETRY_AFTER and returned as is.
pub fn ensure(path: &Path) -> Result<(), String> {
    if let Ok(g) = LAST_FAILURE.lock() {
        if let Some((at, why)) = g.as_ref() {
            if at.elapsed() < RETRY_AFTER {
                return Err(why.clone());
            }
        }
    }
    let env = |k: &str| std::env::var(k).ok();
    let outcome = match pair_command(&env, &|p| p.exists()) {
        None => Err(missing_runtime()),
        Some(cmd) => provision_with(path, &|| run_pair(&cmd)),
    };
    if let Ok(mut g) = LAST_FAILURE.lock() {
        *g = outcome.as_ref().err().map(|e| (Instant::now(), e.clone()));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "jc1_0123456789ab_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO-_";

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("argus-prov-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_token_is_the_last_valid_line_of_stdout_and_nothing_else() {
        assert_eq!(token_from_output(&format!("{GOOD}\n")).as_deref(), Some(GOOD));
        assert_eq!(token_from_output(&format!("note\r\n{GOOD}\r\n\r\n")).as_deref(), Some(GOOD));
        assert_eq!(token_from_output(""), None);
        assert_eq!(token_from_output("paired client abc"), None);
        assert_eq!(token_from_output(&format!("{GOOD}\ntrailing text")), None);
    }

    #[test]
    fn provisioning_writes_the_token_and_leaves_no_temp_file() {
        let d = tmp("write");
        let path = d.join("cfg").join("client.token");
        provision_with(&path, &|| Ok(GOOD.to_string())).unwrap();
        assert_eq!(pairing::read_token(&path).unwrap(), GOOD);
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("client.token")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn an_existing_token_file_is_never_replaced() {
        let d = tmp("keep");
        let path = d.join("client.token");
        std::fs::write(&path, "revoked-but-ours").unwrap();
        let called = std::cell::Cell::new(false);
        let r = provision_with(&path, &|| {
            called.set(true);
            Ok(GOOD.to_string())
        });
        assert!(r.is_err());
        assert!(!called.get(), "must not even ask the daemon for a second token");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "revoked-but-ours");
    }

    #[test]
    fn a_daemon_failure_or_a_bad_token_stores_nothing() {
        let d = tmp("fail");
        let path = d.join("client.token");
        assert!(provision_with(&path, &|| Err("refused".into())).is_err());
        assert!(provision_with(&path, &|| Ok("not-a-token".into())).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn the_runtime_is_found_where_the_installer_puts_it() {
        let env = |k: &str| match k {
            "JARVIS_PYTHON" => Some("C:/dev/py.exe".to_string()),
            _ => None,
        };
        let c = pair_command(&env, &|_| false).unwrap();
        assert_eq!(c.program, PathBuf::from("C:/dev/py.exe"));
        assert_eq!(&c.args[..2], ["-m", "jarvis"]);
        assert!(c.args.windows(2).any(|w| w == ["pair", "--name"]));
        // The token is never an argument of this command.
        assert!(c.args.iter().all(|a| !a.starts_with("jc1_")));
        let none = |_: &str| None;
        assert_eq!(pair_command(&none, &|_| false), None);
    }

    #[cfg(windows)]
    #[test]
    fn windows_uses_the_private_python_under_local_app_data() {
        let env = |k: &str| (k == "LOCALAPPDATA").then(|| "C:\\Users\\u\\AppData\\Local".to_string());
        let want = Path::new("C:\\Users\\u\\AppData\\Local").join("Programs").join("Jarvis").join("python").join("python.exe");
        assert_eq!(pair_command(&env, &|p| p == want).unwrap().program, want);
        assert_eq!(pair_command(&env, &|_| false), None, "no runtime installed: say so, do not guess");
    }

    #[cfg(windows)]
    #[test]
    fn the_packaged_program_is_preferred_and_takes_no_module_arguments() {
        let local = r"C:\Users\u\AppData\Local";
        let env = |k: &str| (k == "LOCALAPPDATA").then(|| local.to_string());
        let home = Path::new(local).join("Programs").join("Jarvis");
        let exe = home.join("jarvis.exe");
        let c = pair_command(&env, &|p| p == exe || p == home.join("python").join("python.exe")).unwrap();
        assert_eq!(c.program, exe);
        assert_eq!(c.args, ["desktop", "pair", "--name", "desktop"]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_restricts_the_file_to_the_current_account() {
        let d = tmp("acl");
        let path = d.join("client.token");
        store_token(&path, GOOD).unwrap();
        let sys = std::env::var("SystemRoot").unwrap();
        let out = Command::new(Path::new(&sys).join("System32").join("icacls.exe")).arg(&path).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let user = std::env::var("USERNAME").unwrap();
        assert!(text.contains(&user), "{text}");
        for other in ["Everyone", "BUILTIN\\Users", "Authenticated Users"] {
            assert!(!text.contains(other), "{other} can read the token: {text}");
        }
    }
}
