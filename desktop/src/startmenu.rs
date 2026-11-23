//! The app in the Start menu, directly (not in a folder), on Windows.
//!
//! The released Windows app is a single exe with no installer, so nothing else
//! would put it in the Start menu. On every start it makes sure
//! `<Start menu>\Programs\ARGUS-INSTINCT.lnk` exists and points at this exe (it is
//! rewritten when the exe has moved), with the app's AppUserModelID on the
//! shortcut: Windows shows an unpackaged app's toasts only for an ID that a
//! Start menu shortcut carries. Current user only, no administrator rights.
//! `--remove-shortcut` takes it away again, which is how a bare exe uninstalls.
//! The installers create the same file, so there is never a second entry.
//! `--install-shortcut` writes it without opening the app (the Setup's silent
//! install). A shortcut of the old name (ARGUS-1.lnk) is removed only when it
//! points at this same exe; one pointing elsewhere is another install's.

use std::path::{Path, PathBuf};

pub const SHORTCUT: &str = "ARGUS-INSTINCT.lnk";
pub const LEGACY_SHORTCUTS: &[&str] = &["ARGUS-1.lnk"];
pub const DESCRIPTION: &str = "ARGUS-INSTINCT security monitor (window, tray and notifications)";

/// What `ensure` should do, given where the exe is and what the shortcut holds now.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    Keep,
    Write,
}

/// Paths compare the way Windows does: case-insensitively, either slash.
pub fn same_path(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| p.to_string_lossy().replace('/', "\\").trim_end_matches('\\').to_lowercase();
    norm(a) == norm(b)
}

pub fn plan(exe: &Path, current_target: Option<&Path>) -> Plan {
    match current_target {
        Some(t) if same_path(t, exe) => Plan::Keep,
        _ => Plan::Write,
    }
}

pub fn shortcut_in(programs: &Path) -> PathBuf {
    programs.join(SHORTCUT)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::mem::ManuallyDrop;
    use windows::core::{Interface, HSTRING, PWSTR};
    use windows::Win32::Storage::EnhancedStorage::PKEY_AppUserModel_ID;
    use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW;
    use windows::Win32::System::Com::StructuredStorage::{
        PropVariantClear, PROPVARIANT, PROPVARIANT_0, PROPVARIANT_0_0, PROPVARIANT_0_0_0,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IPersistFile,
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, STGM_READ,
    };
    use windows::Win32::System::Variant::VT_LPWSTR;
    use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
    use windows::Win32::UI::Shell::{
        FOLDERID_Programs, IShellLinkW, SHGetKnownFolderPath, SHStrDupW, ShellLink, KF_FLAG_DEFAULT,
    };

    fn err(what: &str, e: windows::core::Error) -> String {
        format!("{what}: {e}")
    }

    fn programs() -> Result<PathBuf, String> {
        unsafe {
            let p = SHGetKnownFolderPath(&FOLDERID_Programs, KF_FLAG_DEFAULT, None)
                .map_err(|e| err("Start menu folder", e))?;
            let s = p.to_string().map_err(|e| format!("Start menu folder: {e}"));
            CoTaskMemFree(Some(p.0 as _));
            Ok(PathBuf::from(s?))
        }
    }

    fn target(link: &Path) -> Option<PathBuf> {
        unsafe {
            let shell: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
            shell.cast::<IPersistFile>().ok()?.Load(&HSTRING::from(link.as_os_str()), STGM_READ).ok()?;
            let mut buf = [0u16; 1024];
            let mut fd = WIN32_FIND_DATAW::default();
            shell.GetPath(&mut buf, &mut fd, 0).ok()?;
            let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            (n > 0).then(|| PathBuf::from(String::from_utf16_lossy(&buf[..n])))
        }
    }

    /// A VT_LPWSTR PROPVARIANT (the AppUserModelID property's type; the crate's
    /// `From<&str>` makes a VT_BSTR, which the shell does not accept for it).
    unsafe fn lpwstr(value: &str) -> Result<PROPVARIANT, String> {
        let s: PWSTR = SHStrDupW(&HSTRING::from(value)).map_err(|e| err("AppUserModelID", e))?;
        Ok(PROPVARIANT {
            Anonymous: PROPVARIANT_0 {
                Anonymous: ManuallyDrop::new(PROPVARIANT_0_0 {
                    vt: VT_LPWSTR,
                    Anonymous: PROPVARIANT_0_0_0 { pwszVal: s },
                    ..Default::default()
                }),
            },
        })
    }

    fn write(link: &Path, exe: &Path, aumid: &str) -> Result<(), String> {
        unsafe {
            let shell: IShellLinkW =
                CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).map_err(|e| err("shell link", e))?;
            shell.SetPath(&HSTRING::from(exe.as_os_str())).map_err(|e| err("target", e))?;
            if let Some(dir) = exe.parent() {
                shell.SetWorkingDirectory(&HSTRING::from(dir.as_os_str())).map_err(|e| err("folder", e))?;
            }
            shell.SetDescription(&HSTRING::from(DESCRIPTION)).map_err(|e| err("description", e))?;
            let store: IPropertyStore = shell.cast().map_err(|e| err("property store", e))?;
            let mut id = lpwstr(aumid)?;
            let set = store.SetValue(&PKEY_AppUserModel_ID, &id).and_then(|_| store.Commit());
            let _ = PropVariantClear(&mut id);
            set.map_err(|e| err("AppUserModelID", e))?;
            shell
                .cast::<IPersistFile>()
                .map_err(|e| err("save", e))?
                .Save(&HSTRING::from(link.as_os_str()), true)
                .map_err(|e| err("save", e))
        }
    }

    /// COM on a thread of its own, so the webview's apartment is never touched.
    fn with_com<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
        std::thread::spawn(move || unsafe {
            let init = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            let out = f();
            if init.is_ok() {
                CoUninitialize();
            }
            out
        })
        .join()
        .map_err(|_| "Start menu worker panicked".to_string())
    }

    pub fn ensure(aumid: &str) -> Result<bool, String> {
        let aumid = aumid.to_string();
        with_com(move || {
            let exe = std::env::current_exe().map_err(|e| format!("own path: {e}"))?;
            let dir = programs()?;
            for old in LEGACY_SHORTCUTS {
                let legacy = dir.join(old);
                if legacy.exists() && target(&legacy).is_some_and(|t| same_path(&t, &exe)) {
                    let _ = std::fs::remove_file(&legacy);
                }
            }
            let link = shortcut_in(&dir);
            let current = if link.exists() { target(&link) } else { None };
            match plan(&exe, current.as_deref()) {
                Plan::Keep => Ok(false),
                Plan::Write => write(&link, &exe, &aumid).map(|_| true),
            }
        })?
    }

    pub fn remove() -> Result<bool, String> {
        let dir = programs()?;
        if let Ok(exe) = std::env::current_exe() {
            for old in LEGACY_SHORTCUTS {
                let legacy = dir.join(old);
                let ours = with_com({
                    let legacy = legacy.clone();
                    let exe = exe.clone();
                    move || legacy.exists() && target(&legacy).is_some_and(|t| same_path(&t, &exe))
                });
                if ours.unwrap_or(false) {
                    let _ = std::fs::remove_file(&legacy);
                }
            }
        }
        let link = shortcut_in(&dir);
        match std::fs::remove_file(&link) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("{}: {e}", link.display())),
        }
    }
}

/// Make sure the Start menu shortcut exists and points here. Ok(true) when it
/// was written now. A no-op on other platforms (the Linux package ships its
/// own menu entry).
pub fn ensure(aumid: &str) -> Result<bool, String> {
    #[cfg(windows)]
    return imp::ensure(aumid);
    #[cfg(not(windows))]
    {
        let _ = aumid;
        Ok(false)
    }
}

/// Remove the Start menu shortcut. Ok(true) when one was removed.
pub fn remove() -> Result<bool, String> {
    #[cfg(windows)]
    return imp::remove();
    #[cfg(not(windows))]
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_existing_shortcut_to_this_exe_is_kept() {
        let exe = Path::new(r"C:\Users\u\AppData\Local\Programs\ARGUS-1\argus-desktop.exe");
        assert_eq!(plan(exe, Some(exe)), Plan::Keep);
        // Windows paths are case-insensitive and accept either slash.
        let other = Path::new("c:/users/U/AppData/Local/Programs/ARGUS-1/ARGUS-DESKTOP.EXE");
        assert_eq!(plan(exe, Some(other)), Plan::Keep);
    }

    #[test]
    fn a_missing_or_moved_shortcut_is_written() {
        let exe = Path::new(r"C:\Users\u\Downloads\argus-desktop.exe");
        assert_eq!(plan(exe, None), Plan::Write);
        let old = Path::new(r"C:\Users\u\Desktop\argus-desktop.exe");
        assert_eq!(plan(exe, Some(old)), Plan::Write);
    }

    #[test]
    fn the_shortcut_sits_directly_in_programs() {
        let programs = Path::new(r"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs");
        let link = shortcut_in(programs);
        assert_eq!(link.parent(), Some(programs));
        assert_eq!(link.file_name().unwrap(), "ARGUS-INSTINCT.lnk");
    }

    #[test]
    fn other_platforms_do_nothing() {
        #[cfg(not(windows))]
        {
            assert_eq!(ensure("local.argus.desktop"), Ok(false));
            assert_eq!(remove(), Ok(false));
        }
    }
}
