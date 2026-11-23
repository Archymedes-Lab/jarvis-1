//! The app's paired client token (jarvis/web/clients.py).
//!
//! The daemon no longer hands its dashboard cookie to a peer whose account it
//! cannot identify, and from Windows across WSL it never can. The app is
//! paired explicitly instead: the owner runs `jarvis desktop pair --name desktop`
//! on the daemon's machine and saves the printed token to this app's own
//! config folder (`client.token`), where only the owner can read it. The app
//! sends it as `X-JARVIS-Token` on every request; it never reaches the page.
//!
//! Std only, so it is tested on its own (`rustc --test src/pairing.rs`).

use std::path::{Path, PathBuf};

/// The app's identifier (tauri.conf.json), which names its config folder.
pub const APP_DIR: &str = "local.jarvis.desktop";
pub const FILE_NAME: &str = "client.token";

/// `jc1_` + 12 lowercase hex + `_` + 43 URL-safe base64 characters.
pub fn valid_token(t: &str) -> bool {
    let Some(rest) = t.strip_prefix("jc1_") else { return false };
    let Some((id, secret)) = rest.split_once('_') else { return false };
    id.len() == 12
        && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && secret.len() == 43
        && secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Where the token lives: JARVIS_CLIENT_TOKEN_FILE, else the app's config
/// folder (%APPDATA%\local.jarvis.desktop on Windows, $XDG_CONFIG_HOME or
/// ~/.config elsewhere). `env` is injectable for tests.
pub fn token_path(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(p) = env("JARVIS_CLIENT_TOKEN_FILE").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let base = if cfg!(windows) {
        env("APPDATA").map(PathBuf::from)
    } else {
        env("XDG_CONFIG_HOME")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .or_else(|| env("HOME").map(|h| Path::new(&h).join(".config")))
    }?;
    Some(base.join(APP_DIR).join(FILE_NAME))
}

/// What the person sees when the app is not paired, with the exact steps.
pub fn unpaired_message(path: Option<&Path>) -> String {
    let where_ = path.map(|p| p.display().to_string()).unwrap_or_else(|| "the app's config folder".into());
    format!(
        "ARGUS-INSTINCT is not paired with this app. On the machine running ARGUS-INSTINCT, run \
         `jarvis desktop pair --name desktop` (under the service account: \
         `sudo jarvis-svc desktop pair --name desktop`) and save the token \
         it prints, on its own line, to {where_}. Only you should be able to read that file."
    )
}

/// The token from `path`, or why it cannot be used. On Unix a file that its
/// group or others can read is refused; on Windows the file is expected in
/// the profile's AppData, which only the owner can read by default.
pub fn read_token(path: &Path) -> Result<String, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| unpaired_message(Some(path)))?;
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file; pair again", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{} can be read by other accounts; run `chmod 600` on it and pair again",
                path.display()
            ));
        }
    }
    if meta.len() > 512 {
        return Err(format!("{} is not a client token; pair again", path.display()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| unpaired_message(Some(path)))?;
    let t = text.trim();
    if valid_token(t) {
        Ok(t.to_string())
    } else {
        Err(format!("{} does not hold a client token; pair again", path.display()))
    }
}

/// The token for this process's environment. A missing token file is
/// provisioned from the local daemon (provision.rs); anything else wrong with
/// it (unreadable, loose permissions, not a token) is reported, never replaced.
pub fn client_token() -> Result<String, String> {
    let path = token_path(&|k| std::env::var(k).ok()).ok_or_else(|| unpaired_message(None))?;
    if std::fs::symlink_metadata(&path).is_err() {
        crate::provision::ensure(&path).map_err(|why| format!("{why} {}", unpaired_message(Some(&path))))?;
    }
    read_token(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "jc1_0123456789ab_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO-_";

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jarvis-pairing-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    fn write(path: &Path, text: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn token_format_matches_the_daemon() {
        assert!(valid_token(GOOD));
        for bad in [
            "",
            "jc1_",
            &GOOD[..GOOD.len() - 1],
            &format!("{GOOD}x"),
            &GOOD.replace("jc1_", "jc2_"),
            &GOOD.replace("0123456789ab", "0123456789AB"),
            &GOOD.replace('-', "+"),
            &format!("{GOOD}\r\nInjected: 1"),
        ] {
            assert!(!valid_token(bad), "{bad}");
        }
    }

    #[test]
    fn path_prefers_the_override_then_the_config_folder() {
        let env = |k: &str| match k {
            "JARVIS_CLIENT_TOKEN_FILE" => Some("/x/t".to_string()),
            _ => None,
        };
        assert_eq!(token_path(&env), Some(PathBuf::from("/x/t")));
        let env = |k: &str| match k {
            "APPDATA" => Some("/appdata".to_string()),
            "XDG_CONFIG_HOME" => Some("/xdg".to_string()),
            "HOME" => Some("/home/u".to_string()),
            _ => None,
        };
        let p = token_path(&env).unwrap();
        assert!(p.ends_with(Path::new(APP_DIR).join(FILE_NAME)));
        assert!(token_path(&|_: &str| None).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_private_file_is_read_and_anything_else_is_refused_with_steps() {
        let d = tmp("read");
        let p = d.join(FILE_NAME);
        let missing = read_token(&p).unwrap_err();
        assert!(missing.contains("jarvis desktop pair"), "{missing}");
        write(&p, &format!("{GOOD}\n"), 0o600);
        assert_eq!(read_token(&p).unwrap(), GOOD);
        write(&p, GOOD, 0o644);
        assert!(read_token(&p).unwrap_err().contains("other accounts"));
        write(&p, "not a token", 0o600);
        assert!(read_token(&p).is_err());
        let link = d.join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(read_token(&link).unwrap_err().contains("not a regular file"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
