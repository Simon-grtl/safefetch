//! Streaming download into quarantine with resume, size and disk checks.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use reqwest::header::{
    HeaderMap, ACCEPT_ENCODING, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, ETAG, IF_RANGE,
    LAST_MODIFIED, LOCATION, RANGE,
};
use reqwest::{Client, Response};
use tokio::io::{AsyncSeekExt, AsyncWriteExt, BufWriter};
use url::Url;

use crate::error::{net_err, Error, Result};
use crate::net::check_redirect;
use crate::quarantine::{ItemMeta, ItemState, Quarantine};
use crate::sanitize::choose_name;

const MIB: u64 = 1024 * 1024;
const DISK_RECHECK_EVERY: u64 = 64 * MIB;
const PROGRESS_EVERY: Duration = Duration::from_millis(200);

pub type SpaceProbe = dyn Fn(&Path) -> std::io::Result<u64> + Send + Sync;

/// Default free-space probe.
pub fn available_space(path: &Path) -> std::io::Result<u64> {
    fs4::available_space(path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub downloaded: u64,
    pub total: Option<u64>,
}

pub struct DownloadContext<'a> {
    pub client: &'a Client,
    pub public_only: bool,
    pub allow_http: bool,
    pub max_redirects: u8,
    pub max_retries: u8,
    pub retry_base_delay: Duration,
    /// None = unlimited.
    pub max_size: Option<u64>,
    pub min_free: u64,
    pub space_probe: &'a SpaceProbe,
    pub cancel: &'a AtomicBool,
    pub progress: &'a (dyn Fn(Progress) + Send + Sync),
}

/// Send a GET and follow redirects manually, validating every hop.
pub async fn open(
    ctx: &DownloadContext<'_>,
    url: &Url,
    offset: u64,
    validator: Option<&str>,
) -> Result<(Response, Url)> {
    let mut current = url.clone();
    let mut hops = 0u8;
    loop {
        let mut req = ctx
            .client
            .get(current.clone())
            .header(ACCEPT_ENCODING, "identity");
        if offset > 0 {
            req = req.header(RANGE, format!("bytes={offset}-"));
            if let Some(v) = validator {
                req = req.header(IF_RANGE, v);
            }
        }
        let resp = req.send().await.map_err(net_err)?;
        let status = resp.status();
        if status.is_redirection() && status.as_u16() != 304 {
            hops += 1;
            if hops > ctx.max_redirects {
                return Err(Error::Policy(format!(
                    "more than {} redirects",
                    ctx.max_redirects
                )));
            }
            let loc = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| Error::Network("redirect without a valid Location header".into()))?;
            let next = current
                .join(loc)
                .map_err(|_| Error::Policy("redirect to an invalid URL".into()))?;
            check_redirect(&current, &next, ctx.public_only)?;
            if next.scheme() == "http" && !ctx.allow_http {
                return Err(Error::Policy(
                    "redirect to plain HTTP refused by settings".into(),
                ));
            }
            current = next;
            continue;
        }
        if status.as_u16() == 416 || status.is_success() {
            return Ok((resp, current));
        }
        return Err(Error::HttpStatus(status.as_u16()));
    }
}

fn header_str(h: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Parse `Content-Range: bytes start-end/total` → (start, Some(total)).
pub fn parse_content_range(v: &str) -> Option<(u64, Option<u64>)> {
    let rest = v.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end: u64 = end.trim().parse().ok()?;
    if end < start {
        return None;
    }
    let total = match total.trim() {
        "*" => None,
        t => {
            let t: u64 = t.parse().ok()?;
            if end >= t {
                return None;
            }
            Some(t)
        }
    };
    Some((start, total))
}

/// Strong ETag if available, else Last-Modified, for `If-Range`.
fn validator(meta: &ItemMeta) -> Option<String> {
    match &meta.etag {
        Some(e) if !e.starts_with("W/") => Some(e.clone()),
        _ => meta.last_modified.clone(),
    }
}

/// Download (or resume) `meta` into quarantine, retrying transient failures.
/// `first` is an already-open response for the original URL (offset 0).
pub async fn download_resumable(
    ctx: &DownloadContext<'_>,
    q: &Quarantine,
    meta: &mut ItemMeta,
    mut first: Option<(Response, Url)>,
) -> Result<()> {
    let original = Url::parse(&meta.url).map_err(|e| Error::InvalidUrl(e.to_string()))?;
    let mut attempt: u8 = 0;
    loop {
        if ctx.cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let offset = q.data_len(&meta.id);
        let opened = match first.take() {
            Some(r) if offset == 0 => Ok(r),
            _ => open(ctx, &original, offset, validator(meta).as_deref()).await,
        };
        let result = match opened {
            Ok((resp, final_url)) => {
                // The redirect target must not change between attempts.
                let same_host = meta
                    .final_url
                    .as_deref()
                    .and_then(|u| Url::parse(u).ok())
                    .is_none_or(|prev| {
                        prev.host_str() == final_url.host_str()
                            && prev.scheme() == final_url.scheme()
                    });
                if !same_host {
                    Err(Error::Policy(
                        "the redirect target changed while resuming".into(),
                    ))
                } else {
                    write_body(ctx, q, meta, resp, &original, &final_url, offset).await
                }
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => return Ok(()),
            Err(e) if e.is_transient() && attempt < ctx.max_retries => {
                attempt += 1;
                let delay = ctx.retry_base_delay * 2u32.saturating_pow(u32::from(attempt - 1));
                tracing::warn!(id = %meta.id, attempt, error = %e, "transient download error, retrying");
                let deadline = Instant::now() + delay;
                while Instant::now() < deadline {
                    if ctx.cancel.load(Ordering::Relaxed) {
                        return Err(Error::Cancelled);
                    }
                    tokio::time::sleep(Duration::from_millis(100).min(delay)).await;
                }
            }
            Err(e) => return Err(e),
        }
    }
}

async fn write_body(
    ctx: &DownloadContext<'_>,
    q: &Quarantine,
    meta: &mut ItemMeta,
    resp: Response,
    original: &Url,
    final_url: &Url,
    mut offset: u64,
) -> Result<()> {
    let path = q.data_path(&meta.id)?;
    let headers = resp.headers().clone();
    let status = resp.status().as_u16();

    let total: Option<u64> = match status {
        206 => {
            let cr = header_str(&headers, CONTENT_RANGE)
                .and_then(|v| parse_content_range(&v))
                .ok_or_else(|| Error::Network("invalid Content-Range in 206 response".into()))?;
            if cr.0 != offset {
                truncate(&path, 0).await?;
                return Err(Error::Network(
                    "server resumed at the wrong position; restarting".into(),
                ));
            }
            cr.1
        }
        416 => {
            if meta.total_size == Some(offset) && offset > 0 {
                return finish(q, meta).await; // already complete
            }
            truncate(&path, 0).await?;
            return Err(Error::Incomplete(0));
        }
        200 => {
            if offset > 0 {
                // Server ignored Range or the file changed (If-Range): restart.
                truncate(&path, 0).await?;
                offset = 0;
            }
            header_str(&headers, CONTENT_LENGTH).and_then(|v| v.trim().parse().ok())
        }
        s => return Err(Error::HttpStatus(s)),
    };

    if offset > 0 {
        if let (Some(prev), Some(now)) = (meta.total_size, total) {
            if prev != now {
                truncate(&path, 0).await?;
                return Err(Error::Network("the remote file changed; restarting".into()));
            }
        }
    }
    if let (Some(t), Some(max)) = (total, ctx.max_size) {
        if t > max {
            return Err(Error::TooLarge(format!(
                "announced {} MiB, limit {} MiB",
                t / MIB,
                max / MIB
            )));
        }
    }
    let avail = (ctx.space_probe)(q.root())?;
    if let Some(t) = total {
        let need = t.saturating_sub(offset) + ctx.min_free;
        if avail < need {
            return Err(Error::DiskSpace(format!(
                "{} MiB needed (including {} MiB reserve), {} MiB free",
                need / MIB,
                ctx.min_free / MIB,
                avail / MIB
            )));
        }
    } else if avail < ctx.min_free {
        return Err(Error::DiskSpace(format!("only {} MiB free", avail / MIB)));
    }

    if offset == 0 {
        let cd = header_str(&headers, CONTENT_DISPOSITION);
        let name = choose_name(cd.as_deref(), final_url, original);
        meta.file_name = name.name;
        meta.name_warnings = name.warnings;
        meta.etag = header_str(&headers, ETAG);
        meta.last_modified = header_str(&headers, LAST_MODIFIED);
        meta.final_url = Some(final_url.to_string());
    }
    meta.total_size = total;
    meta.state = ItemState::Downloading;
    q.save_meta(meta)?;

    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .await?;
    let mut file = BufWriter::with_capacity(1 << 20, file);
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    // Drop any stale bytes beyond the resume point.
    file.get_ref().set_len(offset).await?;

    let mut done = offset;
    let mut since_disk_check = 0u64;
    let mut last_progress = Instant::now();
    (ctx.progress)(Progress {
        downloaded: done,
        total,
    });
    let mut stream = resp.bytes_stream();
    let outcome: Result<()> = loop {
        if ctx.cancel.load(Ordering::Relaxed) {
            break Err(Error::Cancelled);
        }
        let chunk = match stream.next().await {
            None => break Ok(()),
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                break Err(match net_err(e) {
                    Error::Network(_) => Error::Incomplete(done),
                    other => other,
                })
            }
        };
        let n = chunk.len() as u64;
        if let Some(t) = total {
            if done + n > t {
                break Err(Error::SizeMismatch(format!(
                    "server sent more than the announced {t} bytes"
                )));
            }
        }
        if let Some(max) = ctx.max_size {
            if done + n > max {
                break Err(Error::TooLarge(format!(
                    "exceeds the {} MiB limit",
                    max / MIB
                )));
            }
        }
        if let Err(e) = file.write_all(&chunk).await {
            break Err(e.into());
        }
        done += n;
        since_disk_check += n;
        if since_disk_check >= DISK_RECHECK_EVERY {
            since_disk_check = 0;
            match (ctx.space_probe)(q.root()) {
                Ok(a) if a < ctx.min_free => {
                    break Err(Error::DiskSpace(format!(
                        "free space fell below {} MiB",
                        ctx.min_free / MIB
                    )))
                }
                Err(e) => break Err(e.into()),
                _ => {}
            }
        }
        if last_progress.elapsed() >= PROGRESS_EVERY {
            last_progress = Instant::now();
            (ctx.progress)(Progress {
                downloaded: done,
                total,
            });
        }
    };
    file.flush().await?;
    file.get_ref().sync_all().await?;
    (ctx.progress)(Progress {
        downloaded: done,
        total,
    });
    outcome?;

    if let Some(t) = total {
        if done < t {
            return Err(Error::Incomplete(done));
        }
    }
    meta.total_size = Some(done);
    finish(q, meta).await
}

async fn finish(q: &Quarantine, meta: &mut ItemMeta) -> Result<()> {
    meta.state = ItemState::Downloaded;
    q.save_meta(meta)
}

async fn truncate(path: &Path, len: u64) -> Result<()> {
    let f = tokio::fs::OpenOptions::new().write(true).open(path).await?;
    f.set_len(len).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_range() {
        assert_eq!(parse_content_range("bytes 0-99/100"), Some((0, Some(100))));
        assert_eq!(parse_content_range("bytes 50-99/*"), Some((50, None)));
        assert_eq!(parse_content_range("bytes 50-99/60"), None);
        assert_eq!(parse_content_range("bytes 99-50/100"), None);
        assert_eq!(parse_content_range("items 0-1/2"), None);
        assert_eq!(parse_content_range("bytes x-1/2"), None);
    }
}
