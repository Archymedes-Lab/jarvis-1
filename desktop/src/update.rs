//! The update notice: which release this app is, whether a newer one is published, and a button that
//! opens the download page.
//!
//! Nothing here downloads or installs anything, and the app makes no network request of its own. The
//! service reads the public release manifest (`jarvis/service/updates.py`, `GET /api/update`) and this
//! module compares what it says with the release this binary was built as. The page that opens is a fixed
//! address in this file, never one taken from the service's answer.

use serde_json::{json, Value};
use std::process::Command;
use std::time::Duration;

use crate::api;

/// The release this binary was built as (`ARGUS_RELEASE`, set by release/build_desktop.py), or "dev".
pub const RELEASE: &str = match option_env!("ARGUS_RELEASE") {
    Some(v) => v,
    None => "dev",
};

const DOWNLOAD_PAGE: &str = "https://www.archymedes.xyz/en/solutions/argus/#download";
const TIMEOUT: Duration = Duration::from_secs(30);

/// (year, month, day, n) for YYYY.MM.DD, YYYY.MM.DD-N or YYYY.MM.DD.N; None for anything else.
fn key(v: &str) -> Option<(u32, u32, u32, u32)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let parts: Vec<&str> = v.split(|c| c == '.' || c == '-').collect();
    if !(parts.len() == 3 || parts.len() == 4) {
        return None;
    }
    let num = |s: &str, width: usize| -> Option<u32> {
        (s.len() == width && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
    };
    let (y, m, d) = (num(parts[0], 4)?, num(parts[1], 2)?, num(parts[2], 2)?);
    if !(2000..=2999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let n = match parts.get(3) {
        None => 1,
        Some(s) => {
            if s.is_empty() || s.len() > 4 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse::<u32>().ok()?.max(1)   // -0 (CI's first build of a day) and no suffix both mean the first
        }
    };
    Some((y, m, d, n))
}

/// True only when both are release versions and `latest` is strictly after `current`. A development
/// build ("dev") is never told to update.
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (key(latest), key(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

fn summary(current: &str, answer: &Value) -> Value {
    let latest = answer.get("latest").and_then(Value::as_str).filter(|v| key(v).is_some());
    let newer = latest.is_some_and(|l| is_newer(l, current));
    json!({
        "current": current,
        "latest": latest,
        "newer": newer,
        "enabled": answer.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        "checked": answer.get("checked").and_then(Value::as_i64).unwrap_or(0),
        "error": answer.get("error").and_then(Value::as_str).unwrap_or("").chars().take(120).collect::<String>(),
    })
}

#[tauri::command]
pub fn app_version() -> String {
    RELEASE.to_string()
}

/// Ask the service for the newest published release and compare it with this build.
#[tauri::command]
pub async fn check_update() -> Result<Value, String> {
    let answer = api::blocking(|| api::get_json("/api/update", TIMEOUT)).await?;
    Ok(summary(RELEASE, &answer))
}

/// Open the download page in the default browser. The address is fixed; the page takes no argument.
#[tauri::command]
pub fn open_download_page() -> Result<(), String> {
    let mut cmd = if cfg!(windows) {
        Command::new("explorer.exe")
    } else {
        Command::new("xdg-open")
    };
    cmd.arg(DOWNLOAD_PAGE).spawn().map(|_| ()).map_err(|e| format!("could not open the browser: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_is_by_date_then_number() {
        assert!(is_newer("2026.11.04-0", "2026.11.03-0"));
        assert!(is_newer("2026.11.03-2", "2026.11.03-1"));
        assert!(is_newer("2026.11.03-10", "2026.11.03-9"));
        assert!(is_newer("2026.11.03-2", "2026.11.03"));
        assert!(!is_newer("2026.11.03-0", "2026.11.03-0"));
        assert!(!is_newer("2026.11.02-5", "2026.11.03-0"));
        assert!(is_newer("v2026.11.04", "2026.11.03.5"));
    }

    #[test]
    fn a_build_that_is_not_a_release_is_never_told_to_update() {
        assert!(!is_newer("2026.11.04-0", "dev"));
        assert!(!is_newer("tomorrow", "2026.11.03-0"));
        assert!(!is_newer("2026.13.40", "2026.11.03-0"));
        assert!(!is_newer("2026.11.04-0x", "2026.11.03-0"));
        assert!(!is_newer("", ""));
    }

    #[test]
    fn the_summary_ignores_a_bad_version_from_the_service() {
        let s = summary("2026.11.03-0", &json!({"latest": "<script>", "enabled": true}));
        assert_eq!(s["newer"], false);
        assert!(s["latest"].is_null());
        let s = summary("2026.11.03-0", &json!({"latest": "2026.11.09-0", "checked": 5}));
        assert_eq!((s["newer"].clone(), s["latest"].clone()), (json!(true), json!("2026.11.09-0")));
    }

    #[test]
    fn the_page_is_https_on_the_release_site() {
        assert!(DOWNLOAD_PAGE.starts_with("https://www.archymedes.xyz/"));
    }
}
