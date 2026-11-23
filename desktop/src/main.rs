//! ARGUS-INSTINCT desktop: an always-open window, tray and notifications over the
//! local daemon (docs/architecture/DESKTOP-APP.md).
//!
//! The app is a client, never the monitor. `jarvis serve` collects, scores
//! and responds whether or not this is running; nothing here observes the
//! machine or acts on it.
//!
//! Trust boundary (v2):
//! * The window shows the interface bundled into this binary (ui/, Svelte),
//!   never a page from the network, and may not navigate anywhere else.
//! * That interface reaches the daemon only through the typed commands in
//!   api.rs, which build.rs and capabilities/main.json limit to the main
//!   window. It has no HTTP, file, shell or window permission of its own and
//!   never sees the API token.
//! * Every command is one loopback request through the daemon's own checks
//!   (Host, token). The app adds no route into the daemon.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Without the production asset protocol Tauri compiles in development mode
// (`cfg(dev)`, set by tauri-build), whatever the optimisation level. A release
// binary must never be that build: refuse it rather than ship it.
#[cfg(all(dev, not(debug_assertions)))]
compile_error!("release builds need `--features custom-protocol` (see docs/architecture/DESKTOP-APP.md)");

mod api;
mod brand;
mod lifecycle;
mod pairing;
mod provision;
mod pulse;
#[allow(dead_code)] // rules only; capture arrives in a later slice
mod screenguard;
mod settings;
mod startmenu;
mod update;
mod watch;

use std::thread;
use std::time::{Duration, Instant};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Url, WebviewUrl, WebviewWindowBuilder, WindowEvent, Wry};
use tauri_plugin_notification::NotificationExt;
use watch::{Level, View, Watch};

const MAIN: &str = "main";
const POLL_WHEN_REFUSED: Duration = Duration::from_secs(15);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

struct Tray {
    icon: TrayIcon<Wry>,
    status: MenuItem<Wry>,
}

/// The only page this window may show is the bundled interface (served from
/// tauri://localhost, or http(s)://tauri.localhost on Windows).
fn allowed(url: &Url) -> bool {
    let host = url.host_str().unwrap_or("");
    match url.scheme() {
        "http" | "https" => host == "tauri.localhost",
        "tauri" => host == "localhost",
        _ => false,
    }
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(MAIN) {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// A 32x32 tray dot in the level's colour, drawn in code (no image assets).
fn dot(level: Level) -> Image<'static> {
    let (r, g, b) = match level {
        Level::Good => (34, 197, 94),
        Level::Attention => (245, 158, 11),
        Level::Alarm => (214, 112, 76),
        Level::Unknown => (100, 116, 139),
    };
    const N: usize = 32;
    let mut px = vec![0u8; N * N * 4];
    let c = N as f32 / 2.0;
    for y in 0..N {
        for x in 0..N {
            let d = ((x as f32 + 0.5 - c).powi(2) + (y as f32 + 0.5 - c).powi(2)).sqrt();
            let a = (13.5 - d).clamp(0.0, 1.0);
            let i = (y * N + x) * 4;
            px[i..i + 4].copy_from_slice(&[r, g, b, (a * 255.0) as u8]);
        }
    }
    Image::new_owned(px, N as u32, N as u32)
}

fn apply(app: &AppHandle, view: View, last: &mut Option<Level>) {
    if let Some(tray) = app.try_state::<Tray>() {
        // Windows caps tray tooltips at 127 characters.
        let tip: String = view.line.chars().take(120).collect();
        let _ = tray.icon.set_tooltip(Some(&tip));
        let _ = tray.status.set_text(&tip);
        if *last != Some(view.level) {
            let _ = tray.icon.set_icon(Some(dot(view.level)));
            *last = Some(view.level);
        }
    }
    let prefs = settings::current();
    for t in view.toasts.into_iter().filter(|t| prefs.allows(t.kind)) {
        let _ = app.notification().builder().title(&brand::brand(&t.title)).body(&brand::brand(&t.body)).show();
    }
}

fn pulse_loop(app: AppHandle) {
    let mut watch = Watch::default();
    let mut last = None;
    let mut backoff = Duration::from_secs(1);
    let mut governor = lifecycle::Governor::default();
    loop {
        let mut got = false;
        let end = pulse::stream(&mut |p| {
            got = true;
            lifecycle::mark_seen();
            lifecycle::set(lifecycle::classify_pulse(&p));
            // The interface refetches state when the daemon says it changed.
            let _ = app.emit_to(MAIN, "pulse", &p);
            apply(&app, watch.pulse(&p), &mut last);
        });
        match end {
            pulse::End::Refused => {
                // Up, but every stream slot is taken (or we were refused):
                // poll the same summary instead of going dark.
                match pulse::poll() {
                    Ok(p) => {
                        lifecycle::set(lifecycle::classify_pulse(&p));
                        let _ = app.emit_to(MAIN, "pulse", &p);
                        apply(&app, watch.pulse(&p), &mut last)
                    }
                    Err(e) => {
                        lifecycle::set(lifecycle::from_error(&e.to_string()));
                        let _ = app.emit_to(MAIN, "daemon-down", ());
                        apply(&app, watch.unreachable(Instant::now()), &mut last)
                    }
                }
                thread::sleep(POLL_WHEN_REFUSED);
            }
            _ if got => backoff = Duration::from_secs(1), // stream ended normally
            _ => {
                // Nothing answered. Start the daemon if it is installed and not
                // running (within the restart budget), and say what is true.
                lifecycle::set(lifecycle::ensure_running(&mut governor, pulse::port()));
                let _ = app.emit_to(MAIN, "daemon-down", ());
                apply(&app, watch.unreachable(Instant::now()), &mut last);
                thread::sleep(backoff);
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "ARGUS-INSTINCT — connecting", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open ARGUS-INSTINCT", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Close this app (monitoring continues)", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&status, &sep, &open, &quit])?;
    let icon = TrayIconBuilder::with_id("jarvis")
        .icon(dot(Level::Unknown))
        .tooltip("ARGUS-INSTINCT — connecting")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| match ev.id().as_ref() {
            "open" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = ev
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    app.manage(Tray { icon, status });
    Ok(())
}

fn main() {
    // `--remove-shortcut`: take the Start menu entry away (a bare exe's uninstall).
    if std::env::args().any(|a| a == "--remove-shortcut") {
        match startmenu::remove() {
            Ok(true) => println!("removed the Start menu entry"),
            Ok(false) => println!("there was no Start menu entry"),
            Err(e) => eprintln!("could not remove the Start menu entry: {e}"),
        }
        return;
    }
    // `--install-shortcut`: write the Start menu entry without opening the app
    // (the Setup's silent install); the ID is the app identifier its toasts use.
    if std::env::args().any(|a| a == "--install-shortcut") {
        match startmenu::ensure(pairing::APP_DIR) {
            Ok(true) => println!("wrote the Start menu entry"),
            Ok(false) => println!("the Start menu entry was already there"),
            Err(e) => {
                eprintln!("could not write the Start menu entry: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    // `--check`: headless self-test for installers and release tests. Pairs if
    // needed, asks the daemon for its pulse, reports by exit code only (this
    // is a windowless program): 0 monitoring answers, 2 cannot pair, 3 daemon
    // not answering.
    if std::env::args().any(|a| a == "--check") {
        let st = lifecycle::ensure_for_check();
        if matches!(st.phase, lifecycle::Phase::NotInstalled | lifecycle::Phase::Stopped) {
            eprintln!("{} {}", st.message, st.detail);
            std::process::exit(3);
        }
        if let Err(e) = pairing::client_token() {
            eprintln!("{e}");
            std::process::exit(2);
        }
        match pulse::poll() {
            Ok(_) => std::process::exit(0),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(3);
            }
        }
    }
    // `--hidden`: start in the tray (used by the logon task).
    let hidden = std::env::args().any(|a| a == "--hidden");
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            api::daemon_state,
            api::daemon_status,
            api::app_status,
            api::run_collector,
            api::answer_question,
            api::ask_jarvis,
            api::score_coach,
            api::decide_fix,
            api::autopilot_status,
            api::autopilot_decide,
            api::autopilot_policy,
            settings::get_settings,
            settings::set_settings,
            api::pause_monitoring,
            api::resume_monitoring,
            api::protection_status,
            api::protection_scan,
            api::geo_state,
            api::coverage_state,
            api::world_state,
            api::procs_baseline,
            api::procs_snapshot,
            api::open_page,
            api::phone_status,
            api::phone_devices,
            api::phone_pair_current,
            api::phone_pair_start,
            api::phone_pair_poll,
            api::phone_pair_confirm,
            api::phone_pair_cancel,
            api::phone_revoke,
            api::phone_test,
            update::app_version,
            update::check_update,
            update::open_download_page,
            api::licence_state,
            api::licence_action,
            api::open_licence_page,
        ])
        .setup(move |app| {
            if let Ok(dir) = app.path().app_config_dir() {
                settings::load(dir);
            }
            build_tray(app)?;
            WebviewWindowBuilder::new(app, MAIN, WebviewUrl::App("index.html".into()))
                .title("ARGUS-INSTINCT")
                .inner_size(1440.0, 920.0)
                .min_inner_size(720.0, 480.0)
                .visible(!hidden)
                .on_navigation(allowed)
                .build()?;
            // In the Start menu directly, under the ID its toasts use. Never fatal:
            // the app works without the entry, and says why it is missing.
            let aumid = app.config().identifier.clone();
            thread::Builder::new().name("jarvis-startmenu".into()).spawn(move || {
                if let Err(e) = startmenu::ensure(&aumid) {
                    eprintln!("Start menu entry not written: {e}");
                }
            })?;
            let handle = app.handle().clone();
            thread::Builder::new()
                .name("jarvis-pulse".into())
                .spawn(move || pulse_loop(handle))?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing hides to the tray: "always open" is the point, and the
            // tray menu is the explicit way out.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == MAIN {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("ARGUS-INSTINCT desktop failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        s.parse().unwrap()
    }

    #[test]
    fn navigation_is_pinned_to_the_bundled_interface() {
        assert!(allowed(&u("http://tauri.localhost/index.html")));
        assert!(allowed(&u("https://tauri.localhost/index.html")));
        assert!(allowed(&u("tauri://localhost/index.html")));
        // The daemon's own page is no longer shown: its API is reached only
        // through the commands, never by navigating the window to it.
        assert!(!allowed(&u("http://127.0.0.1:8787/")));
        assert!(!allowed(&u("http://localhost:8787/geo")));
        assert!(!allowed(&u("https://example.com/")));
        assert!(!allowed(&u("http://tauri.localhost.evil.example/")));
        assert!(!allowed(&u("file:///C:/Windows/")));
        assert!(!allowed(&u("javascript:alert(1)")));
    }
}
