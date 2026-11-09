//! Job orchestration: link check → download → scan → verdict → delivery.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Notify;
use url::Url;

use crate::delivery;
use crate::download::{self, DownloadContext, Progress, SpaceProbe};
use crate::error::{Error, Result};
use crate::fsutil::now_unix;
use crate::hash;
use crate::history::{url_hash, History, HistoryEntry};
use crate::input::{parse_links, InputError, LinkRequest};
use crate::net::{build_client, display_url, host_is_local, ClientOptions};
use crate::quarantine::{ItemMeta, ItemState, Quarantine};
use crate::sanitize::{filename_from_url, sanitize_filename, NameWarning};
use crate::scanners::virustotal::{RateLimiter, VtClient, VtStats};
use crate::scanners::{clamav, defender};
use crate::secrets::{validate_vt_key, SecretStore, SecretString};
use crate::settings::{Settings, UiSettings};
use crate::verdict::{
    decide, Detection, EngineResult, ScanReport, Thresholds, Verdict, VerdictLevel, VtFileResult,
};

const MIB: u64 = 1024 * 1024;

// ------------------------------------------------------------------ types --

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Queued,
    CheckingLink,
    Downloading,
    Scanning,
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// Clean (or released by the user) and moved to the destination.
    Delivered {
        path: String,
    },
    /// Dangerous: the file was deleted.
    Deleted,
    /// Suspect / not analyzed: waiting for the user's decision.
    Quarantined,
    /// The link was blocked before downloading anything.
    Blocked {
        reason: String,
    },
    /// Already downloaded earlier (same link or identical content).
    AlreadyDownloaded {
        path: String,
    },
    Failed {
        error: String,
        resumable: bool,
    },
    Cancelled {
        resumable: bool,
    },
    /// Removed from quarantine by the user.
    Discarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkStatus {
    Skipped,
    Unknown,
    Clean,
    Warning,
    Blocked,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkCheck {
    pub status: LinkStatus,
    pub details: Vec<String>,
    pub detections: Vec<Detection>,
    pub permalink: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobSnapshot {
    pub id: u64,
    pub display_url: String,
    pub final_host: Option<String>,
    pub file_name: String,
    pub name_warnings: Vec<NameWarning>,
    pub size: Option<u64>,
    pub downloaded: u64,
    pub speed_bps: u64,
    pub stage: Stage,
    pub outcome: Option<Outcome>,
    pub link_check: Option<LinkCheck>,
    pub verdict: Option<Verdict>,
    pub warnings: Vec<String>,
    pub expected_sha256: Option<String>,
}

pub trait EventSink: Send + Sync + 'static {
    fn job_updated(&self, job: &JobSnapshot);
}

/// Discards events (tests, headless use).
pub struct NullSink;
impl EventSink for NullSink {
    fn job_updated(&self, _job: &JobSnapshot) {}
}

#[derive(Debug, Clone, Serialize)]
pub struct SubmitResult {
    pub added: Vec<u64>,
    pub errors: Vec<InputError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvironmentStatus {
    pub os: &'static str,
    pub clamscan: Option<String>,
    pub freshclam: Option<String>,
    pub clamd: Option<String>,
    pub clamav_version: Option<String>,
    pub signatures_age_days: Option<i64>,
    pub defender: Option<String>,
    pub has_api_key: bool,
    pub destination: Option<String>,
    pub quarantine_dir: Option<String>,
    pub install_help: Vec<String>,
}

/// Engine construction parameters (tests shorten delays and mock services).
pub struct EngineConfig {
    pub config_dir: PathBuf,
    pub retry_base_delay: Duration,
    pub vt_base: Option<Url>,
    pub vt_backoff: Duration,
    pub space_probe: Option<Arc<SpaceProbe>>,
}

impl EngineConfig {
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            config_dir,
            retry_base_delay: Duration::from_secs(2),
            vt_base: None,
            vt_backoff: Duration::from_secs(30),
            space_probe: None,
        }
    }
}

struct Job {
    snap: JobSnapshot,
    request: LinkRequest,
    qid: Option<String>,
    cancel: Arc<AtomicBool>,
    force_link: bool,
    running: bool,
    last_bytes: u64,
    last_tick: Instant,
}

/// Concurrency gate whose limit can change at runtime.
struct Gate {
    active: Mutex<usize>,
    notify: Notify,
}

struct GateGuard<'a>(&'a Gate);
impl Drop for GateGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut a) = self.0.active.lock() {
            *a = a.saturating_sub(1);
        }
        self.0.notify.notify_waiters();
    }
}

impl Gate {
    async fn acquire(&self, max: impl Fn() -> usize, cancel: &AtomicBool) -> Option<GateGuard<'_>> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut a = self.active.lock().ok()?;
                if *a < max() {
                    *a += 1;
                    return Some(GateGuard(self));
                }
            }
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
        }
    }
}

struct Inner {
    cfg: EngineConfig,
    rt: tokio::runtime::Handle,
    settings: RwLock<Settings>,
    jobs: Mutex<BTreeMap<u64, Job>>,
    next_id: AtomicU64,
    gate: Gate,
    scan_lock: tokio::sync::Mutex<()>,
    limiter: Arc<RateLimiter>,
    vt: Mutex<Option<Arc<VtClient>>>,
    secrets: Arc<dyn SecretStore>,
    history: Mutex<History>,
    sink: Arc<dyn EventSink>,
    last_signature_update: Mutex<Option<(u64, std::result::Result<String, String>)>>,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

fn lock_err<T>(_: T) -> Error {
    Error::Internal("lock poisoned".into())
}

// ----------------------------------------------------------------- engine --

impl Engine {
    pub fn new(
        cfg: EngineConfig,
        secrets: Arc<dyn SecretStore>,
        sink: Arc<dyn EventSink>,
        rt: tokio::runtime::Handle,
    ) -> Result<Self> {
        crate::fsutil::create_private_dir(&cfg.config_dir)?;
        let settings = Settings::load(&cfg.config_dir.join("settings.json"))?;
        let history = History::load(&cfg.config_dir.join("history.json"));
        let limiter = Arc::new(RateLimiter::new(
            Duration::from_secs(settings.vt_min_interval_secs),
            settings.vt_daily_quota,
        ));
        let engine = Self {
            inner: Arc::new(Inner {
                cfg,
                rt,
                settings: RwLock::new(settings),
                jobs: Mutex::new(BTreeMap::new()),
                next_id: AtomicU64::new(1),
                gate: Gate {
                    active: Mutex::new(0),
                    notify: Notify::new(),
                },
                scan_lock: tokio::sync::Mutex::new(()),
                limiter,
                vt: Mutex::new(None),
                secrets,
                history: Mutex::new(history),
                sink,
                last_signature_update: Mutex::new(None),
            }),
        };
        engine.restore_quarantine();
        Ok(engine)
    }

    // ---- settings & secrets ----

    pub fn settings(&self) -> Settings {
        self.inner.settings()
    }

    pub fn ui_settings(&self) -> UiSettings {
        self.settings().to_ui()
    }

    pub fn update_ui_settings(&self, ui: &UiSettings) -> Result<UiSettings> {
        let mut s = self.settings();
        s.apply_ui(ui);
        s.validate()?;
        s.save(&self.inner.settings_path())?;
        *self.inner.settings.write().map_err(lock_err)? = s.clone();
        self.inner.gate.notify.notify_waiters();
        Ok(s.to_ui())
    }

    /// Set the destination folder (from the native picker only).
    pub fn set_destination(&self, dir: &Path) -> Result<UiSettings> {
        // dunce: canonical path without Windows' \\?\ verbatim prefix.
        let dir = dunce::canonicalize(dir)
            .map_err(|_| Error::InvalidSettings("the folder does not exist".into()))?;
        if !dir.is_dir() {
            return Err(Error::InvalidSettings("not a folder".into()));
        }
        let mut s = self.settings();
        if s.destination_dir.as_deref() != Some(dir.as_path()) {
            let busy = self
                .inner
                .jobs
                .lock()
                .map(|jobs| jobs.values().any(|j| j.running || j.qid.is_some()))
                .unwrap_or(true);
            if busy {
                return Err(Error::InvalidSettings(
                    "finish or delete the downloads and quarantined files before changing the destination"
                        .into(),
                ));
            }
        }
        let qroot = s
            .quarantine_dir
            .clone()
            .unwrap_or_else(|| Quarantine::default_root(&dir));
        let q = Quarantine::open(qroot)?; // also proves the folder is writable
        if delivery::same_volume(q.root(), &dir) == Some(false) {
            return Err(Error::InvalidSettings(
                "the quarantine folder must be on the same disk as the destination".into(),
            ));
        }
        s.destination_dir = Some(dir);
        s.save(&self.inner.settings_path())?;
        *self.inner.settings.write().map_err(lock_err)? = s.clone();
        self.restore_quarantine();
        Ok(s.to_ui())
    }

    pub fn has_api_key(&self) -> bool {
        matches!(self.inner.secrets.get(), Ok(Some(_)))
    }

    pub fn set_api_key(&self, key: String) -> Result<()> {
        let key = key.trim().to_string();
        if !validate_vt_key(&key) {
            return Err(Error::InvalidSettings(
                "a VirusTotal API key is 64 hexadecimal characters".into(),
            ));
        }
        self.inner.secrets.set(&SecretString::new(key))?;
        *self.inner.vt.lock().map_err(lock_err)? = None;
        Ok(())
    }

    pub fn delete_api_key(&self) -> Result<()> {
        self.inner.secrets.delete()?;
        *self.inner.vt.lock().map_err(lock_err)? = None;
        Ok(())
    }

    // ---- jobs ----

    pub fn jobs(&self) -> Vec<JobSnapshot> {
        self.inner
            .jobs
            .lock()
            .map(|j| j.values().map(|j| j.snap.clone()).collect())
            .unwrap_or_default()
    }

    pub fn job(&self, id: u64) -> Option<JobSnapshot> {
        self.inner
            .jobs
            .lock()
            .ok()?
            .get(&id)
            .map(|j| j.snap.clone())
    }

    pub fn submit(&self, text: &str) -> SubmitResult {
        let (requests, errors) = parse_links(text);
        let mut added = Vec::new();
        for req in requests {
            // Same link already queued/running, or its file is still in quarantine: skip.
            let dup = self.inner.jobs.lock().map(|jobs| {
                jobs.values().any(|j| {
                    j.request.url == req.url && (j.snap.outcome.is_none() || j.qid.is_some())
                })
            });
            if dup.unwrap_or(false) {
                continue;
            }
            let id = self.inner.add_job(req, None, None);
            added.push(id);
            self.spawn(id);
        }
        SubmitResult { added, errors }
    }

    fn spawn(&self, id: u64) {
        let inner = self.inner.clone();
        {
            let Ok(mut jobs) = inner.jobs.lock() else {
                return;
            };
            let Some(job) = jobs.get_mut(&id) else { return };
            if job.running {
                return;
            }
            job.running = true;
            job.cancel.store(false, Ordering::Relaxed);
        }
        self.inner.rt.spawn(async move {
            let outcome = match inner.process(id).await {
                Ok(o) => o,
                Err(Error::Cancelled) => Outcome::Cancelled {
                    resumable: inner.has_partial(id),
                },
                Err(e) => {
                    // A finished download is never thrown away because of a later
                    // error (scan, delivery…): "retry" goes straight to analysis.
                    let complete = inner.download_complete(id);
                    let resumable = (complete || e.is_transient()) && inner.has_partial(id);
                    if !resumable {
                        inner.drop_partial(id);
                    }
                    Outcome::Failed {
                        error: e.to_string(),
                        resumable,
                    }
                }
            };
            inner.update(id, |j| {
                j.running = false;
                j.snap.stage = Stage::Finished;
                j.snap.speed_bps = 0;
                j.snap.outcome = Some(outcome.clone());
            });
        });
    }

    pub fn cancel(&self, id: u64) -> Result<()> {
        let jobs = self.inner.jobs.lock().map_err(lock_err)?;
        let job = jobs.get(&id).ok_or(Error::NotFound)?;
        job.cancel.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Retry (resuming if possible) a failed or cancelled job.
    pub fn retry(&self, id: u64) -> Result<()> {
        self.restart(
            id,
            |o| matches!(o, Some(Outcome::Failed { .. } | Outcome::Cancelled { .. })),
            false,
        )
    }

    /// Download a link that VirusTotal blocked, on explicit user request.
    pub fn force_download(&self, id: u64) -> Result<()> {
        self.restart(id, |o| matches!(o, Some(Outcome::Blocked { .. })), true)
    }

    /// Re-run the scanners on a quarantined file (e.g. after installing ClamAV).
    pub fn rescan(&self, id: u64) -> Result<()> {
        self.restart(id, |o| matches!(o, Some(Outcome::Quarantined)), false)
    }

    fn restart(
        &self,
        id: u64,
        allowed: impl Fn(&Option<Outcome>) -> bool,
        force: bool,
    ) -> Result<()> {
        self.inner.with_job(id, |j| {
            if j.running || !allowed(&j.snap.outcome) {
                return Err(Error::Policy(
                    "this action is not available for this item".into(),
                ));
            }
            j.force_link |= force;
            j.snap.outcome = None;
            j.snap.stage = Stage::Queued;
            Ok(())
        })??;
        self.spawn(id);
        Ok(())
    }

    /// Deliver a quarantined (suspect / not analyzed) file on user request.
    pub fn release(&self, id: u64) -> Result<String> {
        let (qid, level) = self.inner.with_job(id, |j| {
            if j.running || j.snap.outcome != Some(Outcome::Quarantined) {
                return Err(Error::Policy(
                    "only quarantined items can be released".into(),
                ));
            }
            let level = j.snap.verdict.as_ref().map(|v| v.level);
            if level == Some(VerdictLevel::Dangerous) {
                return Err(Error::Policy("dangerous files cannot be released".into()));
            }
            j.qid.clone().ok_or(Error::NotFound).map(|q| (q, level))
        })??;
        let s = self.settings();
        let dest = s
            .destination_dir
            .clone()
            .ok_or_else(|| Error::Policy("no destination folder".into()))?;
        let q = self.inner.quarantine(&s)?;
        let meta = q.load_meta(&qid)?;
        let path = delivery::deliver(&q.data_path(&qid)?, &dest, &meta.file_name)?;
        if let Err(e) = q.remove(&qid) {
            tracing::warn!("could not remove quarantine sidecar: {e}");
        }
        self.inner.record_history(
            &meta,
            level.unwrap_or(VerdictLevel::NotAnalyzed),
            Some(path.clone()),
        );
        let shown = path.display().to_string();
        self.inner.update(id, |j| {
            j.qid = None;
            j.snap.outcome = Some(Outcome::Delivered {
                path: shown.clone(),
            });
            j.snap
                .warnings
                .push("Released from quarantine by the user despite the verdict".into());
        });
        Ok(shown)
    }

    /// Delete a quarantined file on user request.
    pub fn discard(&self, id: u64) -> Result<()> {
        let qid = self.inner.with_job(id, |j| {
            if j.running {
                return Err(Error::Policy("cancel the download first".into()));
            }
            Ok(j.qid.clone())
        })??;
        if let Some(qid) = qid {
            let s = self.settings();
            self.inner.quarantine(&s)?.remove(&qid)?;
        }
        self.inner.update(id, |j| {
            j.qid = None;
            j.snap.outcome = Some(Outcome::Discarded);
            j.snap.stage = Stage::Finished;
        });
        Ok(())
    }

    /// Remove finished items from the list (files are not touched; items
    /// still in quarantine stay listed).
    pub fn clear_finished(&self) {
        if let Ok(mut jobs) = self.inner.jobs.lock() {
            jobs.retain(|_, j| j.running || j.snap.outcome.is_none() || j.qid.is_some());
        }
    }

    /// EXPLICIT USER ACTION: upload a quarantined file to VirusTotal.
    pub async fn upload_to_virustotal(&self, id: u64) -> Result<String> {
        let qid = self.inner.with_job(id, |j| {
            if j.snap.outcome != Some(Outcome::Quarantined) {
                return Err(Error::Policy(
                    "only quarantined items can be uploaded".into(),
                ));
            }
            j.qid.clone().ok_or(Error::NotFound)
        })??;
        let vt = self
            .inner
            .vt_client()
            .ok_or_else(|| Error::Policy("set a VirusTotal API key first".into()))?;
        let s = self.settings();
        let q = self.inner.quarantine(&s)?;
        let meta = q.load_meta(&qid)?;
        let sha = meta.sha256.ok_or(Error::NotFound)?;
        vt.upload_file(&q.data_path(&qid)?, &sha)
            .await
            .map_err(|e| Error::Network(e.to_string()))
    }

    pub fn virustotal_link(&self, id: u64) -> Option<String> {
        let j = self.job(id)?;
        j.verdict
            .and_then(|v| v.virustotal_link)
            .or_else(|| j.link_check.and_then(|l| l.permalink))
    }

    pub fn delivered_path(&self, id: u64) -> Option<PathBuf> {
        match self.job(id)?.outcome? {
            Outcome::Delivered { path } | Outcome::AlreadyDownloaded { path } => {
                Some(PathBuf::from(path))
            }
            _ => None,
        }
    }

    // ---- environment ----

    pub async fn environment(&self) -> EnvironmentStatus {
        let s = self.settings();
        let clamscan = s
            .clamav
            .clamscan_path
            .clone()
            .or_else(|| clamav::find_executable("clamscan"));
        let freshclam = s
            .clamav
            .freshclam_path
            .clone()
            .or_else(|| clamav::find_executable("freshclam"));
        let clamd = match clamav::choose_backend(&s.clamav, 1) {
            clamav::Backend::Clamd { address } => Some(address),
            _ => None,
        };
        let version = clamav::version(&s.clamav).await;
        let age = version.as_deref().and_then(signature_age_days);
        EnvironmentStatus {
            os: std::env::consts::OS,
            clamscan: clamscan.map(|p| p.display().to_string()),
            freshclam: freshclam.map(|p| p.display().to_string()),
            clamd,
            clamav_version: version,
            signatures_age_days: age,
            defender: defender::find_mpcmdrun().map(|p| p.display().to_string()),
            has_api_key: self.has_api_key(),
            destination: s.destination_dir.as_ref().map(|p| p.display().to_string()),
            quarantine_dir: self
                .inner
                .quarantine(&s)
                .ok()
                .map(|q| q.root().display().to_string()),
            install_help: install_help(),
        }
    }

    pub async fn update_signatures(&self) -> std::result::Result<String, String> {
        let r = clamav::update_signatures(&self.settings().clamav).await;
        if let Ok(mut l) = self.inner.last_signature_update.lock() {
            *l = Some((now_unix(), r.clone()));
        }
        r
    }

    /// Daily freshclam while the app runs (if enabled in settings).
    pub fn start_background_tasks(&self) {
        let engine = self.clone();
        self.inner.rt.spawn(async move {
            loop {
                if engine.settings().auto_update_signatures {
                    if let Err(e) = engine.update_signatures().await {
                        tracing::warn!("signature update failed: {e}");
                    }
                }
                tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
            }
        });
    }

    /// Rebuild the job list from items left in quarantine (after a restart).
    fn restore_quarantine(&self) {
        let s = self.settings();
        let Ok(q) = self.inner.quarantine(&s) else {
            return;
        };
        for meta in q.list() {
            let known = self
                .inner
                .jobs
                .lock()
                .map(|j| j.values().any(|j| j.qid.as_deref() == Some(&meta.id)))
                .unwrap_or(true);
            if known {
                continue;
            }
            let Ok(url) = Url::parse(&meta.url) else {
                continue;
            };
            let outcome = match meta.state {
                ItemState::AwaitingDecision => Outcome::Quarantined,
                _ => Outcome::Failed {
                    error: "Interrupted; it can be resumed".into(),
                    resumable: true,
                },
            };
            let req = LinkRequest {
                url,
                expected_sha256: meta.expected_sha256.clone(),
            };
            let id = self
                .inner
                .add_job(req, Some(meta.id.clone()), Some(outcome));
            self.inner.update(id, |j| {
                j.snap.file_name = meta.file_name.clone();
                j.snap.name_warnings = meta.name_warnings.clone();
                j.snap.verdict = meta.verdict.clone();
                j.snap.size = meta.total_size;
                j.snap.downloaded = q.data_len(&meta.id);
                j.snap.stage = Stage::Finished;
            });
        }
    }
}

// ------------------------------------------------------------------ inner --

impl Inner {
    fn settings(&self) -> Settings {
        self.settings.read().map(|s| s.clone()).unwrap_or_default()
    }

    fn settings_path(&self) -> PathBuf {
        self.cfg.config_dir.join("settings.json")
    }

    fn quarantine(&self, s: &Settings) -> Result<Quarantine> {
        let root = match (&s.quarantine_dir, &s.destination_dir) {
            (Some(q), _) => q.clone(),
            (None, Some(d)) => Quarantine::default_root(d),
            (None, None) => {
                return Err(Error::Policy(
                    "choose a destination folder in Settings first".into(),
                ))
            }
        };
        Quarantine::open(root)
    }

    fn vt_client(&self) -> Option<Arc<VtClient>> {
        let mut cache = self.vt.lock().ok()?;
        if let Some(c) = cache.as_ref() {
            return Some(c.clone());
        }
        let key = self.secrets.get().ok().flatten()?;
        let c = Arc::new(
            VtClient::new(
                &key,
                self.limiter.clone(),
                self.cfg.vt_base.clone(),
                self.cfg.vt_backoff,
            )
            .ok()?,
        );
        *cache = Some(c.clone());
        Some(c)
    }

    fn add_job(&self, request: LinkRequest, qid: Option<String>, outcome: Option<Outcome>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let guess = filename_from_url(&request.url)
            .map(|n| sanitize_filename(&n).name)
            .unwrap_or_else(|| "download".into());
        let mut warnings = Vec::new();
        if request.url.scheme() == "http" {
            warnings.push(
                "Plain HTTP link: the file could be altered in transit. Prefer HTTPS.".into(),
            );
        }
        let snap = JobSnapshot {
            id,
            display_url: display_url(&request.url),
            final_host: None,
            file_name: guess,
            name_warnings: Vec::new(),
            size: None,
            downloaded: 0,
            speed_bps: 0,
            stage: if outcome.is_some() {
                Stage::Finished
            } else {
                Stage::Queued
            },
            outcome,
            link_check: None,
            verdict: None,
            warnings,
            expected_sha256: request.expected_sha256.clone(),
        };
        let job = Job {
            snap: snap.clone(),
            request,
            qid,
            cancel: Arc::new(AtomicBool::new(false)),
            force_link: false,
            running: false,
            last_bytes: 0,
            last_tick: Instant::now(),
        };
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(id, job);
        }
        self.sink.job_updated(&snap);
        id
    }

    fn with_job<R>(&self, id: u64, f: impl FnOnce(&mut Job) -> R) -> Result<R> {
        let mut jobs = self.jobs.lock().map_err(lock_err)?;
        let job = jobs.get_mut(&id).ok_or(Error::NotFound)?;
        let r = f(job);
        let snap = job.snap.clone();
        drop(jobs);
        self.sink.job_updated(&snap);
        Ok(r)
    }

    fn update(&self, id: u64, f: impl FnOnce(&mut Job)) {
        let _ = self.with_job(id, f);
    }

    fn on_progress(&self, id: u64, p: Progress) {
        self.update(id, |j| {
            let now = Instant::now();
            let dt = now.duration_since(j.last_tick).as_secs_f64();
            if dt >= 0.5 {
                let inst = (p.downloaded.saturating_sub(j.last_bytes)) as f64 / dt;
                // Exponential moving average for a stable display.
                j.snap.speed_bps = if j.snap.speed_bps == 0 {
                    inst as u64
                } else {
                    (0.7 * j.snap.speed_bps as f64 + 0.3 * inst) as u64
                };
                j.last_bytes = p.downloaded;
                j.last_tick = now;
            }
            j.snap.downloaded = p.downloaded;
            j.snap.size = p.total.or(j.snap.size);
        });
    }

    fn has_partial(&self, id: u64) -> bool {
        let qid = self
            .jobs
            .lock()
            .ok()
            .and_then(|j| j.get(&id).and_then(|j| j.qid.clone()));
        let s = self.settings();
        match (qid, self.quarantine(&s)) {
            (Some(qid), Ok(q)) => q.load_meta(&qid).is_ok(),
            _ => false,
        }
    }

    fn download_complete(&self, id: u64) -> bool {
        let qid = self
            .jobs
            .lock()
            .ok()
            .and_then(|j| j.get(&id).and_then(|j| j.qid.clone()));
        match (qid, self.quarantine(&self.settings())) {
            (Some(qid), Ok(q)) => q
                .load_meta(&qid)
                .is_ok_and(|m| m.state != ItemState::Downloading),
            _ => false,
        }
    }

    fn drop_partial(&self, id: u64) {
        let qid = self
            .jobs
            .lock()
            .ok()
            .and_then(|mut j| j.get_mut(&id).and_then(|j| j.qid.take()));
        if let (Some(qid), Ok(q)) = (qid, self.quarantine(&self.settings())) {
            let _ = q.remove(&qid);
        }
    }

    fn record_history(&self, meta: &ItemMeta, verdict: VerdictLevel, delivered: Option<PathBuf>) {
        let Ok(url) = Url::parse(&meta.url) else {
            return;
        };
        if let Ok(mut h) = self.history.lock() {
            let _ = h.record(HistoryEntry {
                url_hash: url_hash(&url),
                sha256: meta.sha256.clone(),
                file_name: meta.file_name.clone(),
                verdict,
                delivered_path: delivered,
                at: now_unix(),
            });
        }
    }

    async fn link_check(&self, vt: &VtClient, url: &Url, s: &Settings) -> LinkCheck {
        let mut details = Vec::new();
        let mut detections = Vec::new();
        let mut blocked = false;
        let mut warning = false;
        let mut errors = 0;
        let mut known = false;
        let mut permalink = None;
        let mut consider =
            |what: &str,
             r: std::result::Result<Option<VtStats>, crate::scanners::virustotal::VtError>,
             threshold: u32| match r {
                Ok(None) => details.push(format!("VirusTotal has no data for this {what}")),
                Ok(Some(st)) => {
                    known = true;
                    if permalink.is_none() || st.malicious > 0 {
                        permalink = Some(st.permalink.clone());
                    }
                    details.push(format!(
                        "{what}: {} malicious, {} suspicious detections",
                        st.malicious, st.suspicious
                    ));
                    if st.malicious >= threshold {
                        blocked = true;
                    } else if st.malicious > 0 || st.suspicious > 0 {
                        warning = true;
                    }
                    detections.extend(
                        st.detections
                            .iter()
                            .filter(|d| d.category == "malicious")
                            .map(|d| Detection {
                                source: format!("VirusTotal {what} / {}", d.engine),
                                name: d.result.clone().unwrap_or_else(|| "malicious".into()),
                            }),
                    );
                }
                Err(e) => {
                    errors += 1;
                    details.push(format!("{what} lookup failed: {e}"));
                }
            };
        consider(
            "URL",
            vt.lookup_url(vt_safe_url(url).as_str()).await,
            s.url_block_threshold,
        );
        if let Some(url::Host::Domain(d)) = url.host() {
            consider(
                "domain",
                vt.lookup_domain(&d.to_ascii_lowercase()).await,
                s.domain_block_threshold,
            );
        }
        let status = if blocked {
            LinkStatus::Blocked
        } else if warning {
            LinkStatus::Warning
        } else if errors > 0 {
            LinkStatus::Error
        } else if known {
            LinkStatus::Clean
        } else {
            LinkStatus::Unknown
        };
        LinkCheck {
            status,
            details,
            detections,
            permalink,
        }
    }

    /// Full pipeline for one job. Returns the final outcome.
    async fn process(self: &Arc<Self>, id: u64) -> Result<Outcome> {
        let (req, force, cancel, existing_qid) = self.with_job(id, |j| {
            (
                j.request.clone(),
                j.force_link,
                j.cancel.clone(),
                j.qid.clone(),
            )
        })?;
        let s = self.settings();
        let dest = s
            .destination_dir
            .clone()
            .ok_or_else(|| Error::Policy("choose a destination folder in Settings first".into()))?;
        if req.url.scheme() == "http" && !s.allow_http {
            return Err(Error::Policy(
                "plain HTTP links are disabled in Settings".into(),
            ));
        }
        let q = self.quarantine(&s)?;
        let uh = url_hash(&req.url);
        let vt = self.vt_client();

        let mut meta = match &existing_qid {
            Some(qid) => q.load_meta(qid)?,
            None => {
                if let Some(prev) = self.history.lock().map_err(lock_err)?.delivered_url(&uh) {
                    let path = prev
                        .delivered_path
                        .clone()
                        .unwrap_or_default()
                        .display()
                        .to_string();
                    return Ok(Outcome::AlreadyDownloaded { path });
                }
                if !force
                    && self
                        .history
                        .lock()
                        .map_err(lock_err)?
                        .dangerous_url(&uh)
                        .is_some()
                {
                    return Ok(Outcome::Blocked {
                        reason: "this link previously delivered a dangerous file".into(),
                    });
                }

                // ---- 1. link reputation (nothing is fetched yet) ----
                self.update(id, |j| j.snap.stage = Stage::CheckingLink);
                if let Some(vt) = &vt {
                    let lc = self.link_check(vt, &req.url, &s).await;
                    let blocked = lc.status == LinkStatus::Blocked;
                    self.update(id, |j| j.snap.link_check = Some(lc.clone()));
                    if blocked && !force {
                        return Ok(Outcome::Blocked {
                            reason: "VirusTotal reports this link as malicious".into(),
                        });
                    }
                } else {
                    self.update(id, |j| {
                        j.snap.link_check = Some(LinkCheck {
                            status: LinkStatus::Skipped,
                            details: vec![
                                "No VirusTotal API key: link reputation not checked".into()
                            ],
                            detections: vec![],
                            permalink: None,
                        })
                    });
                }
                if cancel.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                let url = req.url.to_string();
                let expected = req.expected_sha256.clone();
                let meta = q.create_item(|qid| ItemMeta {
                    id: qid,
                    url,
                    final_url: None,
                    etag: None,
                    last_modified: None,
                    total_size: None,
                    expected_sha256: expected,
                    sha256: None,
                    file_name: "download".into(),
                    name_warnings: vec![],
                    state: ItemState::Downloading,
                    verdict: None,
                    created_at: now_unix(),
                })?;
                self.update(id, |j| j.qid = Some(meta.id.clone()));
                meta
            }
        };

        // ---- 2. download into quarantine ----
        if meta.state == ItemState::Downloading {
            let guard = {
                let me = self.clone();
                self.gate
                    .acquire(
                        move || usize::from(me.settings().max_concurrent_downloads),
                        &cancel,
                    )
                    .await
                    .ok_or(Error::Cancelled)?
            };
            self.update(id, |j| {
                j.snap.stage = Stage::Downloading;
                j.last_tick = Instant::now();
                j.last_bytes = q.data_len(&meta.id);
            });
            let public_only = !host_is_local(&req.url);
            let client = build_client(&ClientOptions {
                connect_timeout: Duration::from_secs(s.connect_timeout_secs),
                idle_timeout: Duration::from_secs(s.idle_timeout_secs),
                public_only,
            })?;
            let default_probe: Arc<SpaceProbe> = Arc::new(download::available_space);
            let probe = self.cfg.space_probe.clone().unwrap_or(default_probe);
            let me = self.clone();
            let progress = move |p: Progress| me.on_progress(id, p);
            let ctx = DownloadContext {
                client: &client,
                public_only,
                allow_http: s.allow_http,
                max_redirects: s.max_redirects,
                max_retries: s.max_retries,
                retry_base_delay: self.cfg.retry_base_delay,
                max_size: (s.max_file_size_mib > 0)
                    .then(|| s.max_file_size_mib.saturating_mul(MIB)),
                min_free: s.min_free_space_mib.saturating_mul(MIB),
                space_probe: probe.as_ref(),
                cancel: &cancel,
                progress: &progress,
            };
            let mut first = None;
            if q.data_len(&meta.id) == 0 {
                let (resp, final_url) = download::open(&ctx, &req.url, 0, None).await?;
                self.update(id, |j| {
                    j.snap.final_host = final_url.host_str().map(str::to_string)
                });
                let host_changed = final_url.host_str() != req.url.host_str();
                if host_changed {
                    self.update(id, |j| {
                        j.snap.warnings.push(format!(
                            "Redirected to another site: {}",
                            display_url(&final_url)
                        ))
                    });
                }
                match (&vt, host_changed && !force) {
                    (Some(vt), true) => {
                        drop(resp); // check the final URL before receiving its body
                        let lc = self.link_check(vt, &final_url, &s).await;
                        let blocked = lc.status == LinkStatus::Blocked;
                        self.update(id, |j| {
                            let mut merged = j.snap.link_check.clone().unwrap_or(LinkCheck {
                                status: LinkStatus::Unknown,
                                details: vec![],
                                detections: vec![],
                                permalink: None,
                            });
                            merged
                                .details
                                .push(format!("Final URL ({}):", display_url(&final_url)));
                            merged.details.extend(lc.details.clone());
                            merged.detections.extend(lc.detections.clone());
                            if lc.status > merged.status {
                                merged.status = lc.status;
                            }
                            j.snap.link_check = Some(merged);
                        });
                        if blocked {
                            q.remove(&meta.id)?;
                            self.update(id, |j| j.qid = None);
                            return Ok(Outcome::Blocked {
                                reason: "VirusTotal reports the redirect target as malicious"
                                    .into(),
                            });
                        }
                    }
                    _ => first = Some((resp, final_url.clone())),
                }
                // Pin the checked target: a re-open that lands elsewhere is refused.
                meta.final_url = Some(final_url.to_string());
                q.save_meta(&meta)?;
            }
            download::download_resumable(&ctx, &q, &mut meta, first).await?;
            drop(guard);
            if let Some(w) = q.mark_untrusted(
                &meta.id,
                &meta
                    .final_url
                    .as_deref()
                    .and_then(|u| Url::parse(u).ok())
                    .map(|u| display_url(&u))
                    .unwrap_or_default(),
            ) {
                self.update(id, |j| j.snap.warnings.push(w));
            }
            self.update(id, |j| {
                j.snap.file_name = meta.file_name.clone();
                j.snap.name_warnings = meta.name_warnings.clone();
                j.snap.size = meta.total_size;
            });
        }

        // ---- 3. analysis (never opens or executes the file) ----
        self.update(id, |j| {
            j.snap.stage = Stage::Scanning;
            j.snap.speed_bps = 0;
        });
        let _scan = self.scan_lock.lock().await;
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let path = q.data_path(&meta.id)?;
        if !path.is_file() {
            // Typically removed by the OS real-time antivirus right after download.
            let _ = q.remove(&meta.id);
            self.update(id, |j| {
                j.qid = None;
                j.snap.warnings.push("The file disappeared from quarantine, most likely removed by your system antivirus.".into());
            });
            self.record_history(&meta, VerdictLevel::Dangerous, None);
            return Ok(Outcome::Deleted);
        }
        let hpath = path.clone();
        let sha = tokio::task::spawn_blocking(move || hash::sha256_file(&hpath, |_| {}))
            .await
            .map_err(|e| Error::Internal(e.to_string()))??;
        meta.sha256 = Some(sha.clone());
        q.save_meta(&meta)?;

        if let Some(prev) = self.history.lock().map_err(lock_err)?.delivered_sha(&sha) {
            let path = prev
                .delivered_path
                .clone()
                .unwrap_or_default()
                .display()
                .to_string();
            q.remove(&meta.id)?;
            self.update(id, |j| {
                j.qid = None;
                j.snap.warnings.push(
                    "Identical content was already delivered; the new copy was discarded.".into(),
                );
            });
            return Ok(Outcome::AlreadyDownloaded { path });
        }

        let vt_file = match &vt {
            None => VtFileResult::NoApiKey,
            Some(c) => c.lookup_file(&sha).await,
        };
        let clam = clamav::scan(&s.clamav, &path).await;
        let def = if cfg!(windows) && s.use_defender {
            match defender::scan(&path).await {
                // Not installed / disabled (e.g. third-party antivirus): it is an
                // optional extra engine, so it must not block a Clean verdict.
                EngineResult::Unavailable(why) => {
                    self.update(id, |j| {
                        j.snap
                            .warnings
                            .push(format!("Microsoft Defender not used: {why}"))
                    });
                    EngineResult::Skipped
                }
                other => other,
            }
        } else {
            EngineResult::Skipped
        };
        let report = ScanReport {
            sha256: sha,
            expected_sha256: meta.expected_sha256.clone(),
            virustotal: vt_file,
            clamav: clam,
            defender: def,
        };
        let verdict = decide(
            report,
            Thresholds {
                vt_dangerous: s.vt_dangerous_threshold,
                vt_suspicious: s.vt_suspicious_threshold,
                require_virustotal: s.require_virustotal,
            },
        );
        self.update(id, |j| j.snap.verdict = Some(verdict.clone()));

        // ---- 4. act on the verdict ----
        match verdict.level {
            VerdictLevel::Clean => {
                let delivered = match delivery::deliver(&path, &dest, &meta.file_name) {
                    Ok(p) => p,
                    Err(e) => {
                        // Keep the (clean) file: never lose a finished download.
                        meta.state = ItemState::AwaitingDecision;
                        meta.verdict = Some(verdict);
                        q.save_meta(&meta)?;
                        self.update(id, |j| {
                            j.snap.warnings.push(format!(
                                "Clean, but delivery failed ({e}). The file is kept in quarantine; use “Release”."
                            ))
                        });
                        return Ok(Outcome::Quarantined);
                    }
                };
                if let Err(e) = q.remove(&meta.id) {
                    tracing::warn!("could not remove quarantine sidecar: {e}");
                }
                self.record_history(&meta, VerdictLevel::Clean, Some(delivered.clone()));
                self.update(id, |j| j.qid = None);
                Ok(Outcome::Delivered {
                    path: delivered.display().to_string(),
                })
            }
            VerdictLevel::Dangerous => {
                q.remove(&meta.id)?;
                self.record_history(&meta, VerdictLevel::Dangerous, None);
                self.update(id, |j| j.qid = None);
                tracing::warn!(file = %meta.file_name, "dangerous file deleted");
                Ok(Outcome::Deleted)
            }
            VerdictLevel::Suspect | VerdictLevel::NotAnalyzed => {
                meta.state = ItemState::AwaitingDecision;
                meta.verdict = Some(verdict);
                q.save_meta(&meta)?;
                Ok(Outcome::Quarantined)
            }
        }
    }
}

impl PartialOrd for LinkStatus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for LinkStatus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let rank = |s: &LinkStatus| match s {
            LinkStatus::Skipped => 0,
            LinkStatus::Unknown => 1,
            LinkStatus::Clean => 2,
            LinkStatus::Error => 3,
            LinkStatus::Warning => 4,
            LinkStatus::Blocked => 5,
        };
        rank(self).cmp(&rank(other))
    }
}

// ---------------------------------------------------------------- helpers --

/// The URL as sent to VirusTotal: never the user name, password or fragment.
/// (The query string is kept: VirusTotal identifies URLs by their full text.)
pub fn vt_safe_url(url: &Url) -> Url {
    let mut u = url.clone();
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_fragment(None);
    u
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// "ClamAV 1.5.4/27800/Sun Nov  8 08:30:00 2026" → days since that date.
pub fn signature_age_days(version: &str) -> Option<i64> {
    let date = version.splitn(3, '/').nth(2)?;
    let parts: Vec<&str> = date.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == parts[1])? as i64
        + 1;
    let day: i64 = parts[2].parse().ok()?;
    let year: i64 = parts[4].parse().ok()?;
    let today = i64::try_from(now_unix() / 86_400).ok()?;
    Some(today - days_from_civil(year, month, day))
}

pub fn install_help() -> Vec<String> {
    match std::env::consts::OS {
        "windows" => vec![
            "Download the ClamAV Windows installer (.msi) from https://www.clamav.net/downloads and install it.".into(),
            "In C:\\Program Files\\ClamAV, copy conf_examples\\freshclam.conf.sample to freshclam.conf and delete the line containing \"Example\".".into(),
            "Run freshclam.exe once to download the signatures, then restart SafeFetch.".into(),
        ],
        "macos" => vec![
            "Install Homebrew (https://brew.sh), then run: brew install clamav".into(),
            "cp $(brew --prefix)/etc/clamav/freshclam.conf.sample $(brew --prefix)/etc/clamav/freshclam.conf and remove the \"Example\" line.".into(),
            "Run: freshclam".into(),
        ],
        _ => vec![
            "Debian/Ubuntu: sudo apt install clamav clamav-freshclam".into(),
            "Fedora: sudo dnf install clamav clamav-update — then sudo freshclam".into(),
            "Arch Linux / CachyOS: sudo pacman -S clamav && sudo freshclam && sudo systemctl enable --now clamav-freshclam.service".into(),
            "Signatures are kept up to date by the clamav-freshclam service (systemctl status clamav-freshclam).".into(),
            "To save a VirusTotal key you need a keyring service: KWallet on KDE Plasma (CachyOS default), gnome-keyring elsewhere.".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert!(signature_age_days("ClamAV 1.5.4/27800/Sun Nov  8 08:30:00 2026").is_some());
        assert_eq!(signature_age_days("ClamAV 1.5.4"), None);
    }
}
