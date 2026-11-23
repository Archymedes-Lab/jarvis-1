//! The few preferences the shell itself owns: which native notifications to
//! show. Kept in one small JSON file in the app's config folder and applied
//! by the shell, so they hold whether or not the window is open. Monitoring
//! is the daemon's and is not affected by any of them: these only decide what
//! this app interrupts you with.

use crate::watch::Kind;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// New high and critical findings.
    pub notify_findings: bool,
    /// A collector went blind, or the score crossed the gate.
    pub notify_health: bool,
    /// The daemon stopped answering, or came back.
    pub notify_outage: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { notify_findings: true, notify_health: true, notify_outage: true }
    }
}

impl Settings {
    pub fn allows(&self, kind: Kind) -> bool {
        match kind {
            Kind::Finding => self.notify_findings,
            Kind::Collector | Kind::Score => self.notify_health,
            Kind::Outage => self.notify_outage,
        }
    }

    /// A damaged or missing file means the defaults (everything on), never off:
    /// a corrupt preference must not silence alerts.
    pub fn parse(text: &str) -> Settings {
        serde_json::from_str(text).unwrap_or_default()
    }
}

static CURRENT: RwLock<Settings> = RwLock::new(Settings { notify_findings: true, notify_health: true, notify_outage: true });
static PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn load(dir: PathBuf) {
    let file = dir.join("settings.json");
    if let Ok(text) = std::fs::read_to_string(&file) {
        if let Ok(mut s) = CURRENT.write() {
            *s = Settings::parse(&text);
        }
    }
    let _ = PATH.set(file);
}

pub fn current() -> Settings {
    CURRENT.read().map(|s| *s).unwrap_or_default()
}

pub fn store(next: Settings) -> Result<(), String> {
    if let Ok(mut s) = CURRENT.write() {
        *s = next;
    }
    let file = PATH.get().ok_or("settings location unknown")?;
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let tmp = file.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&next).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, file).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_settings() -> Settings {
    current()
}

#[tauri::command]
pub fn set_settings(settings: Settings) -> Result<Settings, String> {
    store(settings)?;
    Ok(current())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_everything_on() {
        let s = Settings::default();
        assert!([Kind::Finding, Kind::Collector, Kind::Score, Kind::Outage].iter().all(|k| s.allows(*k)));
    }

    #[test]
    fn each_switch_controls_only_its_kind() {
        let s = Settings { notify_findings: false, ..Settings::default() };
        assert!(!s.allows(Kind::Finding) && s.allows(Kind::Outage) && s.allows(Kind::Collector));
        let s = Settings { notify_outage: false, ..Settings::default() };
        assert!(!s.allows(Kind::Outage) && s.allows(Kind::Finding));
        let s = Settings { notify_health: false, ..Settings::default() };
        assert!(!s.allows(Kind::Collector) && !s.allows(Kind::Score) && s.allows(Kind::Finding));
    }

    #[test]
    fn a_damaged_file_never_silences_alerts() {
        assert_eq!(Settings::parse("not json {{"), Settings::default());
        assert_eq!(Settings::parse(""), Settings::default());
        assert_eq!(Settings::parse(r#"{"notify_outage": false}"#), Settings { notify_outage: false, ..Settings::default() });
    }
}
