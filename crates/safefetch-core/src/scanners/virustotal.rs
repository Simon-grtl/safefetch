//! VirusTotal API v3 client.
//!
//! Privacy: only URLs, domains and SHA-256 hashes are sent. Uploading a file
//! is a separate function that the app calls only after an explicit,
//! confirmed user action (uploaded files become available to VT partners).
//!
//! Quota: the free public API allows 4 requests/minute and 500/day. A shared
//! [`RateLimiter`] spaces requests and HTTP 429 triggers exponential backoff.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;
use serde_json::Value;

use crate::error::net_err;
use crate::secrets::SecretString;
use crate::verdict::{EngineDetection, VtFileResult};

pub const DEFAULT_BASE: &str = "https://www.virustotal.com/api/v3/";
pub const GUI_BASE: &str = "https://www.virustotal.com/gui/";
/// Direct upload limit of `POST /files` (larger needs an upload URL).
pub const MAX_DIRECT_UPLOAD: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VtError {
    #[error("invalid VirusTotal API key")]
    Unauthorized,
    #[error("VirusTotal quota exhausted ({0})")]
    Quota(String),
    #[error("VirusTotal answered HTTP {0}")]
    Http(u16),
    #[error("VirusTotal unreachable: {0}")]
    Network(String),
    #[error("unexpected VirusTotal response")]
    Parse,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VtStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub detections: Vec<EngineDetection>,
    pub permalink: String,
}

struct LimiterState {
    next_allowed: Instant,
    day_started: Instant,
    day_count: u32,
}

/// Process-wide request spacing + daily cap shared by all jobs.
pub struct RateLimiter {
    interval: Duration,
    daily_quota: u32,
    state: Mutex<LimiterState>,
}

impl RateLimiter {
    pub fn new(interval: Duration, daily_quota: u32) -> Self {
        let now = Instant::now();
        Self {
            interval,
            daily_quota,
            state: Mutex::new(LimiterState {
                next_allowed: now,
                day_started: now,
                day_count: 0,
            }),
        }
    }

    /// Reserve a slot and wait for it.
    pub async fn acquire(&self) -> Result<(), VtError> {
        let wait = {
            let mut s = self.state.lock().map_err(|_| VtError::Parse)?;
            let now = Instant::now();
            if now.duration_since(s.day_started) >= Duration::from_secs(86_400) {
                s.day_started = now;
                s.day_count = 0;
            }
            if self.daily_quota > 0 && s.day_count >= self.daily_quota {
                return Err(VtError::Quota("daily request limit reached".into()));
            }
            s.day_count += 1;
            let slot = s.next_allowed.max(now);
            s.next_allowed = slot + self.interval;
            slot.saturating_duration_since(now)
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        Ok(())
    }

    /// Push every future request back (after a 429).
    pub fn penalize(&self, d: Duration) {
        if let Ok(mut s) = self.state.lock() {
            let t = Instant::now() + d;
            if t > s.next_allowed {
                s.next_allowed = t;
            }
        }
    }
}

pub struct VtClient {
    http: reqwest::Client,
    base: url::Url,
    limiter: std::sync::Arc<RateLimiter>,
    backoff_base: Duration,
    max_429_retries: u32,
}

impl VtClient {
    pub fn new(
        key: &SecretString,
        limiter: std::sync::Arc<RateLimiter>,
        base: Option<url::Url>,
        backoff_base: Duration,
    ) -> Result<Self, VtError> {
        crate::net::ensure_crypto_provider();
        let mut headers = HeaderMap::new();
        let mut v = HeaderValue::from_str(key.expose()).map_err(|_| VtError::Unauthorized)?;
        v.set_sensitive(true); // never printed by reqwest/hyper debug output
        headers.insert("x-apikey", v);
        let http = reqwest::Client::builder()
            .user_agent(crate::net::USER_AGENT)
            .default_headers(headers)
            .https_only(base.is_none())
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| VtError::Network(e.without_url().to_string()))?;
        let base = match base {
            Some(b) => b,
            None => url::Url::parse(DEFAULT_BASE).map_err(|_| VtError::Parse)?,
        };
        Ok(Self {
            http,
            base,
            limiter,
            backoff_base,
            max_429_retries: 4,
        })
    }

    async fn get(&self, path: &str) -> Result<Option<Value>, VtError> {
        let url = self.base.join(path).map_err(|_| VtError::Parse)?;
        let mut attempt = 0;
        loop {
            self.limiter.acquire().await?;
            let resp = self
                .http
                .get(url.clone())
                .send()
                .await
                .map_err(|e| match net_err(e) {
                    crate::Error::Network(m) => VtError::Network(m),
                    other => VtError::Network(other.to_string()),
                })?;
            match resp.status() {
                StatusCode::OK => {
                    return resp
                        .json::<Value>()
                        .await
                        .map(Some)
                        .map_err(|_| VtError::Parse)
                }
                StatusCode::NOT_FOUND => return Ok(None),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                    return Err(VtError::Unauthorized)
                }
                StatusCode::TOO_MANY_REQUESTS => {
                    // VT returns 429 both for per-minute and daily quota.
                    let body: Value = resp.json().await.unwrap_or(Value::Null);
                    let code = body
                        .pointer("/error/code")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if code == "QuotaExceededError" && attempt >= 1 {
                        return Err(VtError::Quota("VirusTotal quota exceeded".into()));
                    }
                    if attempt >= self.max_429_retries {
                        return Err(VtError::Quota(
                            "too many requests, gave up after retries".into(),
                        ));
                    }
                    let delay = self.backoff_base * 2u32.pow(attempt);
                    tracing::warn!(attempt, ?delay, "VirusTotal 429, backing off");
                    self.limiter.penalize(delay);
                    attempt += 1;
                }
                s if s.is_server_error() && attempt < 2 => {
                    attempt += 1;
                    tokio::time::sleep(self.backoff_base).await;
                }
                s => return Err(VtError::Http(s.as_u16())),
            }
        }
    }

    /// VT URL identifier: unpadded base64url of the URL.
    pub fn url_id(url: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes())
    }

    pub async fn lookup_url(&self, url: &str) -> Result<Option<VtStats>, VtError> {
        let id = Self::url_id(url);
        let permalink = format!("{GUI_BASE}url/{id}");
        Ok(self
            .get(&format!("urls/{id}"))
            .await?
            .map(|v| parse_stats(&v, permalink)))
    }

    pub async fn lookup_domain(&self, domain: &str) -> Result<Option<VtStats>, VtError> {
        if !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(VtError::Parse);
        }
        let permalink = format!("{GUI_BASE}domain/{domain}");
        Ok(self
            .get(&format!("domains/{domain}"))
            .await?
            .map(|v| parse_stats(&v, permalink)))
    }

    pub async fn lookup_file(&self, sha256: &str) -> VtFileResult {
        if crate::input::parse_sha256(sha256).is_none() {
            return VtFileResult::Failed {
                error: "invalid hash".into(),
            };
        }
        let permalink = format!("{GUI_BASE}file/{sha256}");
        match self.get(&format!("files/{sha256}")).await {
            Ok(None) => VtFileResult::Unknown,
            Ok(Some(v)) => {
                let s = parse_stats(&v, permalink);
                VtFileResult::Found {
                    malicious: s.malicious,
                    suspicious: s.suspicious,
                    undetected: s.undetected,
                    harmless: s.harmless,
                    detections: s.detections,
                    permalink: s.permalink,
                }
            }
            Err(e) => VtFileResult::Failed {
                error: e.to_string(),
            },
        }
    }

    /// EXPLICIT USER ACTION ONLY. Uploads the file (≤ 32 MiB) for analysis.
    /// Returns the GUI link of the file report.
    pub async fn upload_file(&self, path: &Path, sha256: &str) -> Result<String, VtError> {
        let len = tokio::fs::metadata(path)
            .await
            .map_err(|e| VtError::Network(e.to_string()))?
            .len();
        if len > MAX_DIRECT_UPLOAD {
            return Err(VtError::Quota(
                "files above 32 MiB cannot be uploaded with the free API".into(),
            ));
        }
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| VtError::Network(e.to_string()))?;
        let part = reqwest::multipart::Part::bytes(bytes).file_name("sample.bin");
        let form = reqwest::multipart::Form::new().part("file", part);
        self.limiter.acquire().await?;
        let url = self.base.join("files").map_err(|_| VtError::Parse)?;
        let resp = self
            .http
            .post(url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| VtError::Network(e.without_url().to_string()))?;
        match resp.status() {
            s if s.is_success() => Ok(format!("{GUI_BASE}file/{sha256}")),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(VtError::Unauthorized),
            StatusCode::TOO_MANY_REQUESTS => Err(VtError::Quota("rate limited".into())),
            s => Err(VtError::Http(s.as_u16())),
        }
    }
}

fn u32_at(v: &Value, p: &str) -> u32 {
    v.pointer(p)
        .and_then(Value::as_u64)
        .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX))
}

pub fn parse_stats(v: &Value, permalink: String) -> VtStats {
    let base = "/data/attributes/last_analysis_stats";
    let mut detections: Vec<EngineDetection> = v
        .pointer("/data/attributes/last_analysis_results")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(engine, r)| {
                    let category = r.get("category")?.as_str()?.to_string();
                    matches!(category.as_str(), "malicious" | "suspicious").then(|| {
                        EngineDetection {
                            engine: engine.clone(),
                            category,
                            result: r.get("result").and_then(Value::as_str).map(str::to_string),
                        }
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    detections.sort_by(|a, b| a.engine.cmp(&b.engine));
    VtStats {
        malicious: u32_at(v, &format!("{base}/malicious")),
        suspicious: u32_at(v, &format!("{base}/suspicious")),
        harmless: u32_at(v, &format!("{base}/harmless")),
        undetected: u32_at(v, &format!("{base}/undetected")),
        detections,
        permalink,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn body(mal: u32) -> Value {
        serde_json::json!({"data": {"attributes": {
            "last_analysis_stats": {"malicious": mal, "suspicious": 1, "harmless": 5, "undetected": 60},
            "last_analysis_results": {
                "EngineA": {"category": "malicious", "result": "Trojan.X"},
                "EngineB": {"category": "undetected", "result": null},
                "EngineC": {"category": "suspicious", "result": "Heur"}
            }
        }}})
    }

    async fn client(server: &MockServer, interval_ms: u64) -> VtClient {
        let key = SecretString::new("k".repeat(64));
        let lim = Arc::new(RateLimiter::new(Duration::from_millis(interval_ms), 500));
        VtClient::new(
            &key,
            lim,
            Some(url::Url::parse(&format!("{}/api/v3/", server.uri())).unwrap()),
            Duration::from_millis(10),
        )
        .unwrap()
    }

    #[test]
    fn url_id_is_unpadded_base64url() {
        assert_eq!(
            VtClient::url_id("http://www.example.com/"),
            "aHR0cDovL3d3dy5leGFtcGxlLmNvbS8"
        );
    }

    #[tokio::test]
    async fn file_lookup_found_and_unknown() {
        let server = MockServer::start().await;
        let sha = "a".repeat(64);
        Mock::given(method("GET"))
            .and(path(format!("/api/v3/files/{sha}")))
            .and(header("x-apikey", "k".repeat(64).as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(body(4)))
            .mount(&server)
            .await;
        let c = client(&server, 0).await;
        match c.lookup_file(&sha).await {
            VtFileResult::Found {
                malicious,
                detections,
                permalink,
                ..
            } => {
                assert_eq!(malicious, 4);
                assert_eq!(detections.len(), 2);
                assert_eq!(detections[0].engine, "EngineA");
                assert!(permalink.ends_with(&sha));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(c.lookup_file(&"b".repeat(64)).await, VtFileResult::Unknown);
        assert!(matches!(
            c.lookup_file("not-a-hash").await,
            VtFileResult::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn backs_off_on_429_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/domains/example.com"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_json(serde_json::json!({"error": {"code": "TooManyRequestsError"}})),
            )
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v3/domains/example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body(0)))
            .mount(&server)
            .await;
        let c = client(&server, 0).await;
        let s = c.lookup_domain("example.com").await.unwrap().unwrap();
        assert_eq!(s.malicious, 0);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn gives_up_after_repeated_429() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let c = client(&server, 0).await;
        assert!(matches!(
            c.lookup_url("https://x.example/").await,
            Err(VtError::Quota(_))
        ));
    }

    #[tokio::test]
    async fn unauthorized_is_reported() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let c = client(&server, 0).await;
        assert_eq!(
            c.lookup_url("https://x.example/").await,
            Err(VtError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn rejects_weird_domains() {
        let server = MockServer::start().await;
        let c = client(&server, 0).await;
        assert!(c.lookup_domain("../files/x").await.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn limiter_spaces_requests() {
        let lim = RateLimiter::new(Duration::from_millis(50), 0);
        let t = Instant::now();
        for _ in 0..4 {
            lim.acquire().await.unwrap();
        }
        assert!(t.elapsed() >= Duration::from_millis(150));
    }

    #[tokio::test]
    async fn daily_quota_is_enforced() {
        let lim = RateLimiter::new(Duration::ZERO, 2);
        lim.acquire().await.unwrap();
        lim.acquire().await.unwrap();
        assert!(matches!(lim.acquire().await, Err(VtError::Quota(_))));
    }
}
