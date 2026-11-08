//! The ONLY functions the webview can call. Each takes typed, validated
//! arguments (job ids, settings struct); none accepts a path, a URL to open,
//! a command line or a file to read. Paths come from the native picker and
//! URLs to open are rebuilt from validated data on the Rust side.

use safefetch_core::engine::{EnvironmentStatus, JobSnapshot, SubmitResult};
use safefetch_core::settings::UiSettings;
use safefetch_core::{Engine, Error};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_updater::UpdaterExt;

type CmdResult<T> = Result<T, Error>;

const MAX_INPUT: usize = 1_000_000;

#[tauri::command]
pub async fn submit_links(engine: State<'_, Engine>, text: String) -> CmdResult<SubmitResult> {
    if text.len() > MAX_INPUT {
        return Err(Error::Policy("too much text pasted at once".into()));
    }
    Ok(engine.submit(&text))
}

#[tauri::command]
pub async fn list_jobs(engine: State<'_, Engine>) -> CmdResult<Vec<JobSnapshot>> {
    Ok(engine.jobs())
}

#[tauri::command]
pub async fn cancel_job(engine: State<'_, Engine>, id: u64) -> CmdResult<()> {
    engine.cancel(id)
}

#[tauri::command]
pub async fn retry_job(engine: State<'_, Engine>, id: u64) -> CmdResult<()> {
    engine.retry(id)
}

#[tauri::command]
pub async fn force_download(engine: State<'_, Engine>, id: u64) -> CmdResult<()> {
    engine.force_download(id)
}

#[tauri::command]
pub async fn rescan_job(engine: State<'_, Engine>, id: u64) -> CmdResult<()> {
    engine.rescan(id)
}

#[tauri::command]
pub async fn release_job(engine: State<'_, Engine>, id: u64) -> CmdResult<String> {
    engine.release(id)
}

#[tauri::command]
pub async fn discard_job(engine: State<'_, Engine>, id: u64) -> CmdResult<()> {
    engine.discard(id)
}

#[tauri::command]
pub async fn clear_finished(engine: State<'_, Engine>) -> CmdResult<()> {
    engine.clear_finished();
    Ok(())
}

/// Explicit upload. The confirmation is a NATIVE dialog shown by Rust, so
/// a compromised webview cannot trigger an upload on its own.
#[tauri::command]
pub async fn upload_to_virustotal(
    app: AppHandle,
    engine: State<'_, Engine>,
    id: u64,
) -> CmdResult<String> {
    use tauri_plugin_dialog::{MessageDialogButtons, MessageDialogKind};
    let name = engine.job(id).map(|j| j.file_name).ok_or(Error::NotFound)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .message(format!(
            "Upload \"{name}\" to VirusTotal?\n\nThe FILE itself will be sent. Uploaded files can be downloaded by VirusTotal's partners and security researchers. Never upload private or confidential files."
        ))
        .title("Upload to VirusTotal")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom("Upload".into(), "Cancel".into()))
        .show(move |ok| {
            let _ = tx.send(ok);
        });
    if !rx.await.unwrap_or(false) {
        return Err(Error::Cancelled);
    }
    engine.upload_to_virustotal(id).await
}

#[tauri::command]
pub async fn open_virustotal_report(
    app: AppHandle,
    engine: State<'_, Engine>,
    id: u64,
) -> CmdResult<()> {
    let link = engine.virustotal_link(id).ok_or(Error::NotFound)?;
    // Only VirusTotal report pages, rebuilt and checked here.
    let url = url::Url::parse(&link).map_err(|_| Error::NotFound)?;
    if url.scheme() != "https"
        || url.host_str() != Some("www.virustotal.com")
        || !url.path().starts_with("/gui/")
    {
        return Err(Error::Policy(
            "refusing to open a non-VirusTotal link".into(),
        ));
    }
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(|e| Error::Internal(e.to_string()))
}

/// Show a delivered file in the file manager (never opens/executes it).
#[tauri::command]
pub async fn reveal_delivered(app: AppHandle, engine: State<'_, Engine>, id: u64) -> CmdResult<()> {
    let path = engine.delivered_path(id).ok_or(Error::NotFound)?;
    let dest = engine.settings().destination_dir.ok_or(Error::NotFound)?;
    if path.parent() != Some(dest.as_path()) {
        return Err(Error::Policy("not a delivered file".into()));
    }
    app.opener()
        .reveal_item_in_dir(&path)
        .map_err(|e| Error::Internal(e.to_string()))
}

#[tauri::command]
pub async fn get_settings(engine: State<'_, Engine>) -> CmdResult<UiSettings> {
    Ok(engine.ui_settings())
}

#[tauri::command]
pub async fn save_settings(
    engine: State<'_, Engine>,
    settings: UiSettings,
) -> CmdResult<UiSettings> {
    engine.update_ui_settings(&settings)
}

/// The destination can only be chosen with the OS folder picker.
#[tauri::command]
pub async fn choose_destination(
    app: AppHandle,
    engine: State<'_, Engine>,
) -> CmdResult<Option<UiSettings>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("Choose the destination folder")
        .pick_folder(move |p| {
            let _ = tx.send(p);
        });
    let picked = rx.await.map_err(|e| Error::Internal(e.to_string()))?;
    let Some(fp) = picked else { return Ok(None) };
    let path = fp.into_path().map_err(|e| Error::Internal(e.to_string()))?;
    engine.set_destination(&path).map(Some)
}

#[tauri::command]
pub async fn has_api_key(engine: State<'_, Engine>) -> CmdResult<bool> {
    Ok(engine.has_api_key())
}

/// Write-only: the key can be replaced or removed, never read back.
#[tauri::command]
pub async fn set_api_key(engine: State<'_, Engine>, key: String) -> CmdResult<()> {
    engine.set_api_key(key)
}

#[tauri::command]
pub async fn delete_api_key(engine: State<'_, Engine>) -> CmdResult<()> {
    engine.delete_api_key()
}

#[tauri::command]
pub async fn environment(engine: State<'_, Engine>) -> CmdResult<EnvironmentStatus> {
    Ok(engine.environment().await)
}

#[tauri::command]
pub async fn update_signatures(engine: State<'_, Engine>) -> Result<String, String> {
    engine.update_signatures().await
}

#[derive(Serialize)]
pub struct UpdateInfo {
    version: String,
    notes: Option<String>,
}

#[tauri::command]
pub async fn check_app_update(app: AppHandle) -> Result<Option<UpdateInfo>, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let update = updater.check().await.map_err(|e| e.to_string())?;
    Ok(update.map(|u| UpdateInfo {
        version: u.version.clone(),
        notes: u.body.clone(),
    }))
}

/// Downloads the update, verifies its minisign signature against the public
/// key embedded in tauri.conf.json (the plugin refuses unsigned updates),
/// installs it and restarts.
#[tauri::command]
pub async fn install_app_update(app: AppHandle) -> Result<(), String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let Some(update) = updater.check().await.map_err(|e| e.to_string())? else {
        return Err("no update available".into());
    };
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| e.to_string())?;
    app.restart();
}
