//! Test helpers: a raw HTTP/1.1 server able to misbehave (cut connections,
//! ignore Range, lie about sizes, redirect forever) and engine plumbing.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use safefetch_core::engine::{Engine, EngineConfig, JobSnapshot, NullSink, Stage};
use safefetch_core::secrets::{MemorySecretStore, SecretStore};
use safefetch_core::settings::{ClamAvMode, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const EICAR: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[derive(Debug, Clone)]
pub struct Req {
    pub path: String,
    pub range_from: Option<u64>,
    pub headers: String,
}

pub enum Body {
    Bytes(Vec<u8>),
    /// N zero bytes generated on the fly (large-file tests).
    Zeros(u64),
}

pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Body,
    /// Close the connection after this many body bytes.
    pub cut_after: Option<u64>,
    /// Override Content-Length (to lie about the size).
    pub content_length: Option<u64>,
}

impl Resp {
    pub fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: Body::Bytes(body),
            cut_after: None,
            content_length: None,
        }
    }
    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
    pub fn redirect(to: &str) -> Self {
        Self::ok(vec![]).status(302).header("Location", to)
    }
    pub fn status(mut self, s: u16) -> Self {
        self.status = s;
        self
    }
}

pub type Handler = Arc<dyn Fn(&Req, usize) -> Resp + Send + Sync>;

pub struct RawServer {
    pub base: String,
    pub requests: Arc<Mutex<Vec<Req>>>,
}

impl RawServer {
    pub async fn start(handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let counter = Arc::new(AtomicUsize::new(0));
        let reqs = requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let handler = handler.clone();
                let reqs = reqs.clone();
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        let Ok(n) = sock.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let text = String::from_utf8_lossy(&buf).to_string();
                    let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let range_from = text
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("range:"))
                        .and_then(|l| l.split('=').nth(1))
                        .and_then(|r| r.trim().trim_end_matches('-').parse().ok());
                    let req = Req {
                        path,
                        range_from,
                        headers: text,
                    };
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    reqs.lock().unwrap().push(req.clone());
                    let resp = handler(&req, n);
                    let body_len = match &resp.body {
                        Body::Bytes(b) => b.len() as u64,
                        Body::Zeros(n) => *n,
                    };
                    let reason = match resp.status {
                        200 => "OK",
                        206 => "Partial Content",
                        302 => "Found",
                        416 => "Range Not Satisfiable",
                        _ => "X",
                    };
                    let mut head = format!(
                        "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: {}\r\n",
                        resp.status,
                        reason,
                        resp.content_length.unwrap_or(body_len)
                    );
                    for (k, v) in &resp.headers {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                    head.push_str("\r\n");
                    if sock.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let limit = resp.cut_after.unwrap_or(u64::MAX).min(body_len);
                    match resp.body {
                        Body::Bytes(b) => {
                            let _ = sock.write_all(&b[..limit as usize]).await;
                        }
                        Body::Zeros(_) => {
                            let chunk = vec![0u8; 1 << 20];
                            let mut sent = 0u64;
                            while sent < limit {
                                let n = (limit - sent).min(chunk.len() as u64) as usize;
                                if sock.write_all(&chunk[..n]).await.is_err() {
                                    return;
                                }
                                sent += n as u64;
                            }
                        }
                    }
                    let _ = sock.flush().await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        Self { base, requests }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub fn count(&self, path: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == path)
            .count()
    }
}

/// Serve `data` honouring `Range`.
pub fn range_response(data: &[u8], req: &Req) -> Resp {
    match req.range_from {
        Some(from) if (from as usize) < data.len() => {
            let mut r = Resp::ok(data[from as usize..].to_vec()).status(206);
            r.headers.push((
                "Content-Range".into(),
                format!("bytes {from}-{}/{}", data.len() - 1, data.len()),
            ));
            r.headers.push(("ETag".into(), "\"v1\"".into()));
            r
        }
        Some(_) => Resp::ok(vec![]).status(416),
        None => Resp::ok(data.to_vec()).header("ETag", "\"v1\""),
    }
}

/// An absolute path (on every OS) that does not exist.
pub fn missing_exe() -> PathBuf {
    std::env::temp_dir().join("safefetch-test-no-such-program")
}

pub fn find_clamscan() -> Option<PathBuf> {
    safefetch_core::scanners::clamav::find_executable("clamscan")
}

/// Custom signature DB: an MD5 hash signature for the EICAR string, so the
/// tests do not depend on downloading the official ~300 MB database.
pub fn write_test_db(dir: &Path) -> PathBuf {
    let db = dir.join("clamdb");
    std::fs::create_dir_all(&db).unwrap();
    // md5(EICAR) = 44d88612fea8a8f36de82e1278abb02f, 68 bytes.
    std::fs::write(
        db.join("test.hdb"),
        "44d88612fea8a8f36de82e1278abb02f:68:SafeFetch.Test.EICAR\n",
    )
    .unwrap();
    db
}

pub struct Env {
    pub dir: tempfile::TempDir,
    pub dest: PathBuf,
    pub config: PathBuf,
    pub engine: Engine,
    pub secrets: Arc<MemorySecretStore>,
}

pub struct EnvOptions {
    pub settings: Box<dyn Fn(&mut Settings)>,
    pub vt_base: Option<String>,
    pub vt_key: bool,
    pub space: Option<u64>,
}

impl Default for EnvOptions {
    fn default() -> Self {
        Self {
            settings: Box::new(|_| {}),
            vt_base: None,
            vt_key: false,
            space: None,
        }
    }
}

pub fn env(opts: EnvOptions) -> Env {
    let dir = tempfile::tempdir().unwrap();
    env_in(dir, opts)
}

pub fn env_in(dir: tempfile::TempDir, opts: EnvOptions) -> Env {
    let dest = dir.path().join("Downloads");
    let config = dir.path().join("config");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let mut s = Settings {
        destination_dir: Some(dest.canonicalize().unwrap()),
        vt_min_interval_secs: 0,
        ..Default::default()
    };
    s.clamav.mode = ClamAvMode::ClamscanOnly;
    s.clamav.database_dir = Some(write_test_db(dir.path()));
    s.clamav.clamscan_path = find_clamscan();
    // Tests must not depend on the CI runner's Defender state.
    s.use_defender = false;
    (opts.settings)(&mut s);
    if !config.join("settings.json").exists() {
        s.save(&config.join("settings.json")).unwrap();
    }
    let secrets = Arc::new(MemorySecretStore::default());
    if opts.vt_key {
        secrets
            .set(&safefetch_core::secrets::SecretString::new("a".repeat(64)))
            .unwrap();
    }
    let mut cfg = EngineConfig::new(config.clone());
    cfg.retry_base_delay = Duration::from_millis(20);
    cfg.vt_backoff = Duration::from_millis(10);
    cfg.vt_base = opts.vt_base.map(|b| url::Url::parse(&b).unwrap());
    if let Some(space) = opts.space {
        cfg.space_probe = Some(Arc::new(move |_p: &Path| Ok(space)));
    }
    let engine = Engine::new(
        cfg,
        secrets.clone(),
        Arc::new(NullSink),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    Env {
        dest: dest.canonicalize().unwrap(),
        dir,
        config,
        engine,
        secrets,
    }
}

impl Env {
    pub async fn wait(&self, id: u64) -> JobSnapshot {
        for _ in 0..1200 {
            if let Some(j) = self.engine.job(id) {
                if j.stage == Stage::Finished && j.outcome.is_some() {
                    return j;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("job {id} did not finish: {:?}", self.engine.job(id));
    }

    pub async fn run(&self, line: &str) -> JobSnapshot {
        let r = self.engine.submit(line);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(r.added.len(), 1);
        self.wait(r.added[0]).await
    }

    pub fn dest_files(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.dest)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != ".safefetch-quarantine")
            .collect();
        v.sort();
        v
    }

    pub fn quarantine_files(&self) -> Vec<String> {
        std::fs::read_dir(self.dest.join(".safefetch-quarantine"))
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Skip a ClamAV-dependent test when ClamAV is not installed locally
/// (CI installs it, so these tests always run there).
#[macro_export]
macro_rules! require_clamav {
    () => {
        if common::find_clamscan().is_none() {
            if std::env::var_os("SAFEFETCH_REQUIRE_CLAMAV").is_some() {
                panic!("clamscan is required (SAFEFETCH_REQUIRE_CLAMAV is set)");
            }
            eprintln!("SKIPPED: clamscan not installed");
            return;
        }
    };
}
