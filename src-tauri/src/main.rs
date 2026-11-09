// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(all(feature = "dev-connector", not(debug_assertions)))]
compile_error!(
    "the dev-connector feature (tauri-connector) must never be enabled in release builds"
);

mod commands;
mod keyring_store;

use std::sync::Arc;

use safefetch_core::{Engine, EngineConfig, EventSink, JobSnapshot};
use tauri::{AppHandle, Emitter, Manager};

struct TauriSink(AppHandle);

impl EventSink for TauriSink {
    fn job_updated(&self, job: &JobSnapshot) {
        let _ = self.0.emit_to("main", "job-updated", job);
    }
}

/// WebKitGTK's DMA-BUF renderer shows a blank window on many Linux setups
/// (proprietary NVIDIA driver, some Wayland compositors, VMs without GPU).
/// SafeFetch's interface gains nothing from it, so it is disabled unless the
/// user sets WEBKIT_DISABLE_DMABUF_RENDERER explicitly. Must run before any
/// thread is started.
#[cfg(target_os = "linux")]
fn linux_webkit_workarounds() {
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    linux_webkit_workarounds();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SAFEFETCH_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    // reqwest (ours and the updater's) uses rustls without a bundled provider.
    safefetch_core::net::ensure_crypto_provider();

    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build());

    #[cfg(all(debug_assertions, feature = "dev-connector"))]
    {
        // Loopback only (also the crate's default since 0.17; older versions bound 0.0.0.0).
        builder = builder.plugin(
            tauri_plugin_connector::ConnectorBuilder::new()
                .bind_address("127.0.0.1")
                .build(),
        );
    }

    let result = builder
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            let sink = Arc::new(TauriSink(app.handle().clone()));
            let engine = tauri::async_runtime::block_on(async move {
                Engine::new(
                    EngineConfig::new(config_dir),
                    Arc::new(keyring_store::KeyringStore),
                    sink,
                    tokio::runtime::Handle::current(),
                )
            })?;
            engine.start_background_tasks();
            app.manage(engine);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::submit_links,
            commands::list_jobs,
            commands::cancel_job,
            commands::retry_job,
            commands::force_download,
            commands::rescan_job,
            commands::release_job,
            commands::discard_job,
            commands::clear_finished,
            commands::upload_to_virustotal,
            commands::open_virustotal_report,
            commands::reveal_delivered,
            commands::get_settings,
            commands::save_settings,
            commands::choose_destination,
            commands::has_api_key,
            commands::set_api_key,
            commands::delete_api_key,
            commands::environment,
            commands::update_signatures,
            commands::check_app_update,
            commands::install_app_update,
        ])
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("SafeFetch failed to start: {e}");
        std::process::exit(1);
    }
}
