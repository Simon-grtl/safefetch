fn main() {
    // Declaring the app commands generates one `allow-<command>` permission per
    // command; only those listed in capabilities/main.json are callable from
    // the webview. Any command missing from the capability is refused.
    let commands: &[&str] = &[
        "submit_links",
        "list_jobs",
        "cancel_job",
        "retry_job",
        "force_download",
        "rescan_job",
        "release_job",
        "discard_job",
        "clear_finished",
        "upload_to_virustotal",
        "open_virustotal_report",
        "reveal_delivered",
        "get_settings",
        "save_settings",
        "choose_destination",
        "has_api_key",
        "set_api_key",
        "delete_api_key",
        "environment",
        "update_signatures",
        "check_app_update",
        "install_app_update",
    ];
    let attrs = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(commands));
    if let Err(e) = tauri_build::try_build(attrs) {
        panic!("tauri build failed: {e:#}");
    }
}
