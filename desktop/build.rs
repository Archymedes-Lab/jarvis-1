// Only these commands exist for the interface, and capabilities/main.json
// grants them to the main window alone. Anything not listed here cannot be
// invoked, whatever the page does.
fn main() {
    // The release this binary is (release/build_desktop.py sets it); "dev" when unset.
    println!("cargo:rerun-if-env-changed=ARGUS_RELEASE");
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "daemon_state",
            "daemon_status",
            "app_status",
            "run_collector",
            "answer_question",
            "ask_jarvis",
            "score_coach",
            "decide_fix",
            "billing_status",
            "billing_checkout",
            "autopilot_status",
            "autopilot_decide",
            "autopilot_policy",
            "get_settings",
            "set_settings",
            "pause_monitoring",
            "resume_monitoring",
            "protection_status",
            "protection_scan",
            "geo_state",
            "coverage_state",
            "world_state",
            "procs_baseline",
            "procs_snapshot",
            "open_page",
            "phone_status",
            "phone_devices",
            "phone_pair_current",
            "phone_pair_start",
            "phone_pair_poll",
            "phone_pair_confirm",
            "phone_pair_cancel",
            "phone_revoke",
            "phone_test",
            "app_version",
            "check_update",
            "open_download_page",
            "licence_state",
            "licence_action",
            "open_licence_page",
        ]),
    ))
    .expect("tauri build");
}
