//! ClamAV integration (clamscan and clamd).
//!
//! THE critical pitfall: by default ClamAV silently reports "OK" for data it
//! skipped because of size limits (verified with ClamAV 1.5: a 2.2 GB file is
//! reported "OK" without being scanned). SafeFetch therefore:
//! - raises the limits explicitly on every clamscan call;
//! - always passes `--alert-exceeds-max=yes` and `--alert-encrypted=yes`, and maps
//!   `Heuristics.Limits.Exceeded.*` / `Heuristics.Encrypted.*` to "Not scanned";
//! - refuses files ≥ 2 GiB up-front: libclamav cannot scan them at all
//!   ("scanning files greater than 2147483647 bytes is not supported");
//! - uses clamd only when its clamd.conf is readable and provably sufficient
//!   (limits high enough and `AlertExceedsMax yes`), otherwise clamscan.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::settings::{ClamAvMode, ClamAvSettings};
use crate::verdict::EngineResult;

/// libclamav hard limit (ClamAV ≤ 1.5): 2 GiB − 1 per file.
pub const CLAMAV_MAX_FILE: u64 = 2_147_483_647;
const MIB: u64 = 1024 * 1024;

pub fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

/// Look for an executable in PATH and well-known install locations.
pub fn find_executable(base: &str) -> Option<PathBuf> {
    let name = exe_name(base);
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(pf) = std::env::var_os(var) {
                dirs.push(PathBuf::from(pf).join("ClamAV"));
            }
        }
    } else {
        dirs.extend(
            [
                "/usr/bin",
                "/usr/local/bin",
                "/opt/homebrew/bin",
                "/usr/sbin",
                "/usr/local/sbin",
                "/opt/homebrew/sbin",
                // Official ClamAV macOS installer (.pkg)
                "/usr/local/clamav/bin",
                "/usr/local/clamav/sbin",
            ]
            .map(PathBuf::from),
        );
    }
    dirs.into_iter()
        .filter(|d| d.is_absolute()) // never resolve relative PATH entries (e.g. ".")
        .map(|d| d.join(&name))
        .find(|p| p.is_file())
}

/// Build clamscan arguments. The file path comes last, after `--`.
pub fn clamscan_args(s: &ClamAvSettings, file: &Path) -> Vec<OsString> {
    let fsz = s.max_filesize_mib.min(CLAMAV_MAX_FILE / MIB);
    let mut a: Vec<OsString> = vec![
        "--no-summary".into(),
        "--stdout".into(),
        "--infected".into(),
        format!("--max-filesize={fsz}M").into(),
        format!("--max-scansize={}M", s.max_scansize_mib).into(),
        format!("--max-files={}", s.max_files).into(),
        format!("--max-recursion={}", s.max_recursion).into(),
        format!("--max-scantime={}", s.max_scantime_secs * 1000).into(),
        format!("--pcre-max-filesize={fsz}M").into(),
        "--alert-exceeds-max=yes".into(),
        "--alert-encrypted=yes".into(),
        "--scan-archive=yes".into(),
        // Needed to detect silent truncation of archive members (see above).
        "--debug".into(),
    ];
    if let Some(db) = &s.database_dir {
        let mut d = OsString::from("--database=");
        d.push(db.as_os_str());
        a.push(d);
    }
    a.push("--".into());
    a.push(file.as_os_str().to_owned());
    a
}

/// Classify a signature name reported by ClamAV.
fn classify(names: Vec<String>) -> EngineResult {
    let (limits, threats): (Vec<String>, Vec<String>) = names.into_iter().partition(|n| {
        n.starts_with("Heuristics.Limits.Exceeded") || n.starts_with("Heuristics.Encrypted")
    });
    if !threats.is_empty() {
        EngineResult::Infected(threats)
    } else if !limits.is_empty() {
        EngineResult::NotScanned(format!("ClamAV stopped early: {}", limits.join(", ")))
    } else {
        EngineResult::Clean
    }
}

/// libclamav debug messages proving that some data was NOT fully scanned.
/// Verified with ClamAV 1.5.4: an archive member larger than MaxFileSize is
/// silently truncated ("cli_unzip: trimming output size to maxfilesize") and
/// `--alert-exceeds-max` does NOT report it. We therefore run clamscan with
/// `--debug` and look for these markers on stderr (streamed, bounded memory).
const TRUNCATION_MARKERS: &[&str] = &[
    "trimming output size",
    "exceeded",
    "exceeds max",
    "too large",
    // Members ClamAV could not decompress while other tools can (found by the
    // security audit: LZMA-compressed entries, lying local-header sizes,
    // forced ZIP64 headers). Verified on ClamAV 1.5.4.
    "unsupported method",
    "extraction failed",
    "stream out of file",
    "unusable masked data",
    "decompression failed",
];

pub fn truncation_marker(line: &str) -> Option<String> {
    let l = line.to_ascii_lowercase();
    if !l.starts_with("libclamav debug") {
        return None;
    }
    // "Skipping decompression ... size: 0, compressed data not available" is
    // logged for directory entries and empty files: benign. Any non-empty
    // entry ClamAV skips means unscanned content.
    let skipped_nonempty = l.contains("skipping decompression") && !l.contains("size: 0,");
    (skipped_nonempty || TRUNCATION_MARKERS.iter().any(|m| l.contains(m))).then(|| {
        line.trim_start_matches("LibClamAV debug:")
            .trim()
            .chars()
            .take(160)
            .collect()
    })
}

/// Turn a libclamav error line into a message the user can act on.
pub fn explain_error(line: &str) -> String {
    let short: String = line.chars().take(160).collect();
    if line.contains("fmap_get_hash") || line.contains("error calculating") {
        // Seen on Homebrew ClamAV 1.5.4 built against OpenSSL 4 (Nov 2026):
        // ClamAV cannot hash files, so hash signatures never match.
        format!("{short} — this ClamAV installation cannot compute file hashes (known problem with Homebrew ClamAV built on OpenSSL 4). Install the official ClamAV package from clamav.net instead.")
    } else {
        short
    }
}

/// Parse clamscan output (`--stdout --infected`) and exit code.
/// Exit codes: 0 = clean, 1 = found, 2 = error (also used when a limit
/// heuristic fires on huge files). `truncated` holds debug evidence that
/// part of the data was skipped.
pub fn parse_clamscan_output(
    stdout: &str,
    stderr_tail: &str,
    exit_code: Option<i32>,
    truncated: Option<&str>,
) -> EngineResult {
    let names: Vec<String> = stdout
        .lines()
        .filter_map(|l| l.strip_suffix(" FOUND"))
        .filter_map(|l| l.rsplit_once(": ").map(|(_, sig)| sig.trim().to_string()))
        .collect();
    let result = match (exit_code, names.is_empty()) {
        (_, false) => classify(names),
        (Some(0), true) => EngineResult::Clean,
        (Some(1), true) => {
            EngineResult::Error("clamscan reported a detection without a name".into())
        }
        (code, true) => {
            let detail = stderr_tail
                .lines()
                .rfind(|l| !l.trim().is_empty())
                .unwrap_or("no output");
            EngineResult::Error(format!("clamscan failed (exit {code:?}): {detail}"))
        }
    };
    match (result, truncated) {
        (EngineResult::Clean, Some(why)) => {
            EngineResult::NotScanned(format!("ClamAV skipped part of the data: {why}"))
        }
        (r, _) => r,
    }
}

pub async fn scan_with_clamscan(exe: &Path, s: &ClamAvSettings, file: &Path) -> EngineResult {
    use tokio::io::AsyncBufReadExt;
    let mut cmd = tokio::process::Command::new(exe);
    crate::fsutil::no_console_window(&mut cmd);
    cmd.args(clamscan_args(s, file))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return EngineResult::Unavailable(format!("cannot run clamscan: {e}")),
    };
    let (Some(mut stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return EngineResult::Error("clamscan pipes unavailable".into());
    };
    let work = async {
        let out_task = async {
            let mut buf = Vec::new();
            // --infected keeps stdout tiny; cap it anyway.
            let _ = (&mut stdout).take(1 << 20).read_to_end(&mut buf).await;
            buf
        };
        let err_task = async {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            let mut truncated: Option<String> = None;
            let mut tail: Vec<String> = Vec::new();
            let mut unrar_missing = false;
            while let Ok(Some(line)) = lines.next_line().await {
                if line.contains("unrar support unavailable") {
                    unrar_missing = true;
                }
                if truncated.is_none() {
                    truncated = truncation_marker(&line)
                        // Any libclamav error means part of the data was not
                        // scanned (re-audit: truncated .xz only logs an Error).
                        .or_else(|| {
                            line.starts_with("LibClamAV Error:")
                                .then(|| explain_error(&line))
                        })
                        // Some ClamAV builds ship without RAR support (e.g.
                        // Debian/Ubuntu): RAR content would be skipped silently.
                        .or_else(|| {
                            (unrar_missing && line.contains("Recognized RAR file"))
                                .then(|| "this ClamAV build cannot unpack RAR archives".to_string())
                        });
                }
                if !line.starts_with("LibClamAV debug") {
                    tail.push(line);
                    if tail.len() > 20 {
                        tail.remove(0);
                    }
                }
            }
            (truncated, tail.join("\n"))
        };
        let (out, (truncated, tail)) = tokio::join!(out_task, err_task);
        let status = child.wait().await;
        (out, truncated, tail, status)
    };
    let timeout = Duration::from_secs(s.max_scantime_secs + 600);
    match tokio::time::timeout(timeout, work).await {
        Err(_) => EngineResult::Error("clamscan timed out".into()),
        Ok((_, _, _, Err(e))) => EngineResult::Error(format!("clamscan: {e}")),
        Ok((out, truncated, tail, Ok(status))) => parse_clamscan_output(
            &String::from_utf8_lossy(&out),
            &tail,
            status.code(),
            truncated.as_deref(),
        ),
    }
}

// ---------------------------------------------------------------- clamd ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClamdConf {
    pub max_file_size: u64,
    pub max_scan_size: u64,
    pub stream_max_length: u64,
    pub alert_exceeds_max: bool,
    pub alert_encrypted: bool,
    pub local_socket: Option<String>,
    pub tcp: Option<(String, u16)>,
    /// `Scan*` options set to "no" (e.g. ScanArchive no): unusable for us.
    pub scan_disabled: Vec<String>,
}

/// Parse a size such as "100M", "4G", "512K" or "1048576".
pub fn parse_size(v: &str) -> Option<u64> {
    let v = v.trim();
    let (num, mul) = match v.chars().last()? {
        'k' | 'K' => (&v[..v.len() - 1], 1024),
        'm' | 'M' => (&v[..v.len() - 1], MIB),
        'g' | 'G' => (&v[..v.len() - 1], 1024 * MIB),
        _ => (v, 1),
    };
    num.trim().parse::<u64>().ok()?.checked_mul(mul)
}

/// Parse clamd.conf. Missing keys take ClamAV's documented defaults
/// (conservative values are used where versions differ).
pub fn parse_clamd_conf(text: &str) -> ClamdConf {
    let mut c = ClamdConf {
        max_file_size: 100 * MIB,
        max_scan_size: 400 * MIB,
        stream_max_length: 25 * MIB,
        alert_exceeds_max: false,
        alert_encrypted: false,
        local_socket: None,
        tcp: None,
        scan_disabled: Vec::new(),
    };
    let mut tcp_addr = "127.0.0.1".to_string();
    let mut tcp_port = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        let (k, v) = (it.next().unwrap_or(""), it.next().unwrap_or("").trim());
        let yes = matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "1");
        match k {
            "MaxFileSize" => c.max_file_size = parse_size(v).unwrap_or(c.max_file_size),
            "MaxScanSize" => c.max_scan_size = parse_size(v).unwrap_or(c.max_scan_size),
            "StreamMaxLength" => c.stream_max_length = parse_size(v).unwrap_or(c.stream_max_length),
            "AlertExceedsMax" => c.alert_exceeds_max = yes,
            "AlertEncrypted" => c.alert_encrypted = yes,
            k if k.starts_with("Scan")
                && !yes
                && matches!(v.to_ascii_lowercase().as_str(), "no" | "false" | "0") =>
            {
                c.scan_disabled.push(k.to_string())
            }
            "LocalSocket" => c.local_socket = Some(v.to_string()),
            "TCPSocket" => tcp_port = v.parse().ok(),
            "TCPAddr" => tcp_addr = v.to_string(),
            _ => {}
        }
    }
    // 0 means "no limit" for MaxFileSize/MaxScanSize in ClamAV.
    for v in [&mut c.max_file_size, &mut c.max_scan_size] {
        if *v == 0 {
            *v = u64::MAX;
        }
    }
    c.tcp = tcp_port.map(|p| (tcp_addr, p));
    c
}

impl ClamdConf {
    /// clamd may be used for a file of `size` only if it would alert (not
    /// silently pass) on anything it cannot fully scan.
    pub fn sufficient_for(&self, size: u64) -> Result<(), String> {
        if !self.scan_disabled.is_empty() {
            return Err(format!(
                "clamd.conf disables scanning: {}",
                self.scan_disabled.join(", ")
            ));
        }
        if !self.alert_exceeds_max {
            return Err("clamd.conf lacks \"AlertExceedsMax yes\"".into());
        }
        if !self.alert_encrypted {
            return Err("clamd.conf lacks \"AlertEncrypted yes\"".into());
        }
        if self.stream_max_length < size || self.max_file_size < size {
            return Err("clamd size limits are lower than the file size".into());
        }
        // clamd cannot report silently truncated archive members (no debug
        // stream), so require the maximum member size libclamav supports.
        if self.max_file_size < (CLAMAV_MAX_FILE / MIB) * MIB {
            return Err("clamd.conf MaxFileSize must be at least 2047M".into());
        }
        Ok(())
    }
}

pub fn default_clamd_conf_paths() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [
        "/etc/clamav/clamd.conf",
        "/etc/clamd.d/scan.conf",
        "/etc/clamd.conf",
        "/usr/local/etc/clamd.conf",
        "/opt/homebrew/etc/clamav/clamd.conf",
        "/usr/local/etc/clamav/clamd.conf",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if cfg!(windows) {
        if let Some(pf) = std::env::var_os("ProgramFiles") {
            v.insert(0, PathBuf::from(pf).join("ClamAV").join("clamd.conf"));
        }
    }
    v
}

/// Parse clamd's INSTREAM reply.
pub fn parse_clamd_reply(reply: &str) -> EngineResult {
    let reply = reply.trim_end_matches(['\0', '\n']).trim();
    if let Some(sig) = reply.strip_suffix(" FOUND") {
        let name = sig.rsplit_once(": ").map_or(sig, |(_, n)| n).to_string();
        return classify(vec![name]);
    }
    if reply.ends_with(": OK") {
        return EngineResult::Clean;
    }
    if reply.contains("size limit exceeded") {
        return EngineResult::NotScanned("clamd StreamMaxLength exceeded".into());
    }
    EngineResult::Error(format!("clamd: {reply}"))
}

async fn instream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut sock: S,
    file: &Path,
) -> std::io::Result<String> {
    sock.write_all(b"zINSTREAM\0").await?;
    let mut f = tokio::fs::File::open(file).await?;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let len = u32::try_from(n).map_err(std::io::Error::other)?;
        sock.write_all(&len.to_be_bytes()).await?;
        sock.write_all(&buf[..n]).await?;
    }
    sock.write_all(&0u32.to_be_bytes()).await?;
    sock.flush().await?;
    let mut reply = Vec::new();
    sock.take(4096).read_to_end(&mut reply).await?;
    Ok(String::from_utf8_lossy(&reply).into_owned())
}

#[cfg(unix)]
async fn instream_unix(path: &str, file: &Path) -> std::io::Result<String> {
    let s = tokio::net::UnixStream::connect(path).await?;
    instream(s, file).await
}

#[cfg(not(unix))]
async fn instream_unix(_path: &str, _file: &Path) -> std::io::Result<String> {
    Err(std::io::Error::other(
        "unix sockets are not supported on this OS",
    ))
}

pub async fn scan_with_clamd(address: &str, file: &Path, timeout: Duration) -> EngineResult {
    let fut = async {
        if let Some(addr) = address.strip_prefix("tcp:") {
            let s = tokio::net::TcpStream::connect(addr).await?;
            instream(s, file).await
        } else if let Some(path) = address.strip_prefix("unix:") {
            instream_unix(path, file).await
        } else {
            Err(std::io::Error::other("bad clamd address"))
        }
    };
    match tokio::time::timeout(timeout, fut).await {
        Err(_) => EngineResult::Error("clamd timed out".into()),
        Ok(Err(e)) => EngineResult::Error(format!("clamd: {e}")),
        Ok(Ok(reply)) => parse_clamd_reply(&reply),
    }
}

// ------------------------------------------------------------- frontend ----

/// What will be used to scan, decided once per scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    Clamd { address: String },
    Clamscan { exe: PathBuf },
    None(String),
}

pub fn choose_backend(s: &ClamAvSettings, size: u64) -> Backend {
    let clamscan = s
        .clamscan_path
        .clone()
        .or_else(|| find_executable("clamscan"));
    let clamd = || -> Result<String, String> {
        let conf_path = s
            .clamd_conf_path
            .clone()
            .or_else(|| default_clamd_conf_paths().into_iter().find(|p| p.is_file()))
            .ok_or("no readable clamd.conf")?;
        let text = std::fs::read_to_string(&conf_path).map_err(|e| e.to_string())?;
        let conf = parse_clamd_conf(&text);
        conf.sufficient_for(size)?;
        if let Some(a) = &s.clamd_address {
            return Ok(a.clone());
        }
        if let Some(sock) = conf.local_socket {
            return Ok(format!("unix:{sock}"));
        }
        if let Some((h, p)) = conf.tcp {
            return Ok(format!("tcp:{h}:{p}"));
        }
        Err("clamd.conf has no socket".into())
    };
    match s.mode {
        ClamAvMode::ClamscanOnly => clamscan.map_or_else(
            || Backend::None("clamscan not found".into()),
            |exe| Backend::Clamscan { exe },
        ),
        ClamAvMode::ClamdOnly => match clamd() {
            Ok(address) => Backend::Clamd { address },
            Err(e) => Backend::None(format!("clamd not usable: {e}")),
        },
        // clamscan first: only its --debug stream can reveal archive members
        // ClamAV skipped. clamd is the fallback when clamscan is missing.
        ClamAvMode::Auto => match (clamscan, clamd()) {
            (Some(exe), _) => Backend::Clamscan { exe },
            (None, Ok(address)) => Backend::Clamd { address },
            (None, Err(_)) => Backend::None("ClamAV is not installed (clamscan not found)".into()),
        },
    }
}

/// Scan a quarantined file with the best available ClamAV backend.
pub async fn scan(s: &ClamAvSettings, file: &Path) -> EngineResult {
    let size = match tokio::fs::metadata(file).await {
        Ok(m) => m.len(),
        Err(e) => return EngineResult::Error(format!("cannot read file: {e}")),
    };
    if size > CLAMAV_MAX_FILE {
        return EngineResult::NotScanned(format!(
            "file is {} MiB; ClamAV cannot scan files larger than 2 GiB",
            size / MIB
        ));
    }
    if size > s.max_filesize_mib.saturating_mul(MIB) {
        return EngineResult::NotScanned(format!(
            "file exceeds the configured ClamAV limit of {} MiB",
            s.max_filesize_mib
        ));
    }
    // Structural check independent of ClamAV (re-audit F1): ZIPs whose local
    // headers disagree with the central directory are skipped by ClamAV.
    if let Some(problem) = {
        let p = file.to_path_buf();
        tokio::task::spawn_blocking(move || crate::archive::zip_problem(&p))
            .await
            .unwrap_or(Some("archive check failed".into()))
    } {
        return EngineResult::NotScanned(format!("ZIP structure not scannable: {problem}"));
    }
    match choose_backend(s, size) {
        Backend::Clamd { address } => {
            // clamd gives no way to know whether every archive member was
            // decompressed (security audit F2): a "clean" container from clamd
            // is never trusted.
            if looks_like_container(file) {
                return EngineResult::NotScanned(
                    "archive/container scanned through clamd cannot be proven complete; install clamscan".into(),
                );
            }
            let r = scan_with_clamd(
                &address,
                file,
                Duration::from_secs(s.max_scantime_secs + 600),
            )
            .await;
            // If clamd is down, fall back to clamscan rather than giving up.
            if let (EngineResult::Error(_), ClamAvMode::Auto) = (&r, s.mode) {
                if let Some(exe) = s
                    .clamscan_path
                    .clone()
                    .or_else(|| find_executable("clamscan"))
                {
                    return scan_with_clamscan(&exe, s, file).await;
                }
            }
            r
        }
        Backend::Clamscan { exe } => scan_with_clamscan(&exe, s, file).await,
        Backend::None(why) => EngineResult::Unavailable(why),
    }
}

/// Magic-byte sniffing of formats ClamAV unpacks (archives, installers,
/// office/PDF containers, disk images, executables that may embed archives).
pub fn looks_like_container(file: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(file) else {
        return true;
    };
    let mut head = vec![0u8; 0x9006];
    let n = f.read(&mut head).unwrap_or(0);
    let h = &head[..n];
    let starts = |m: &[u8]| h.starts_with(m);
    let at = |off: usize, m: &[u8]| h.len() >= off + m.len() && &h[off..off + m.len()] == m;
    let magic = starts(b"PK\x03\x04")
        || starts(b"PK\x05\x06")
        || starts(b"PK\x07\x08")
        || starts(&[0x1f, 0x8b])
        || starts(b"BZh")
        || starts(&[0xfd, b'7', b'z', b'X', b'Z', 0])
        || starts(&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c])
        || starts(b"Rar!\x1a\x07")
        || starts(&[0x28, 0xb5, 0x2f, 0xfd])
        || starts(b"MSCF")
        || starts(b"ITSF")
        || starts(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
        || starts(b"%PDF")
        || starts(b"MZ")
        || starts(&[0x7f, b'E', b'L', b'F'])
        || starts(&[0xcf, 0xfa, 0xed, 0xfe])
        || starts(&[0xca, 0xfe, 0xba, 0xbe])
        || starts(&[0x60, 0xea])
        || at(2, b"-lh")
        || at(257, b"ustar")
        || at(0x8001, b"CD001")
        || at(0x8801, b"CD001")
        || at(0x9001, b"CD001")
        || starts(b"xar!")
        || starts(b"!<arch>")
        || starts(&[0x1f, 0x9d])
        || starts(b"{\\rtf");
    if magic {
        return true;
    }
    // ZIP appended to other data (self-extractor style): EOCD near the end.
    if let Ok(len) = f.metadata().map(|m| m.len()) {
        if len >= 22 && matches!(crate::archive::find_eocd(&mut f, len), Ok(Some(_))) {
            return true;
        }
    }
    // Apple disk image: "koly" trailer in the last 512 bytes.
    let mut tail = [0u8; 4];
    f.seek(SeekFrom::End(-512)).is_ok() && f.read_exact(&mut tail).is_ok() && &tail == b"koly"
}

/// ClamAV version and signature date (from `clamscan --version`), e.g.
/// "ClamAV 1.5.4/27800/Sun Nov  8 08:30:00 2026".
pub async fn version(s: &ClamAvSettings) -> Option<String> {
    let exe = s
        .clamscan_path
        .clone()
        .or_else(|| find_executable("clamscan"))?;
    let mut cmd = tokio::process::Command::new(exe);
    crate::fsutil::no_console_window(&mut cmd);
    cmd.arg("--version").stdin(Stdio::null()).kill_on_drop(true);
    if let Some(db) = &s.database_dir {
        let mut d = OsString::from("--database=");
        d.push(db.as_os_str());
        cmd.arg(d);
    }
    let out = tokio::time::timeout(Duration::from_secs(60), cmd.output())
        .await
        .ok()?
        .ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// Run freshclam (signature update). Returns its output for display.
pub async fn update_signatures(s: &ClamAvSettings) -> Result<String, String> {
    let exe = s
        .freshclam_path
        .clone()
        .or_else(|| find_executable("freshclam"))
        .ok_or("freshclam not found")?;
    let mut cmd = tokio::process::Command::new(exe);
    crate::fsutil::no_console_window(&mut cmd);
    cmd.arg("--stdout").stdin(Stdio::null()).kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(900), cmd.output())
        .await
        .map_err(|_| "freshclam timed out".to_string())?
        .map_err(|e| format!("cannot run freshclam: {e}"))?;
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    let tail: String = text
        .lines()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    if out.status.success() {
        Ok(tail)
    } else {
        Err(tail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_raise_limits_and_alert() {
        let s = ClamAvSettings {
            max_filesize_mib: 9999,
            ..Default::default()
        };
        let a: Vec<String> = clamscan_args(&s, Path::new("/q/x.quarantine"))
            .iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect();
        assert!(a.contains(&"--alert-exceeds-max=yes".to_string()));
        assert!(a.contains(&"--alert-encrypted=yes".to_string()));
        assert!(
            a.contains(&"--max-filesize=2047M".to_string()),
            "capped to libclamav max: {a:?}"
        );
        assert_eq!(a[a.len() - 2], "--");
        assert_eq!(a[a.len() - 1], "/q/x.quarantine");
    }

    #[test]
    fn clamscan_output_parsing() {
        assert_eq!(
            parse_clamscan_output("", "", Some(0), None),
            EngineResult::Clean
        );
        assert_eq!(
            parse_clamscan_output("/q/a: Win.Test.EICAR_HDB-1 FOUND\n", "", Some(1), None),
            EngineResult::Infected(vec!["Win.Test.EICAR_HDB-1".into()])
        );
        // Limit hit on a huge file: exit code 2 but a FOUND line.
        let r = parse_clamscan_output(
            "/q/a: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n/q/a: Virus(es) detected ERROR\n",
            "",
            Some(2),
            None,
        );
        assert!(matches!(r, EngineResult::NotScanned(_)), "{r:?}");
        assert!(matches!(
            parse_clamscan_output("/q/a: Heuristics.Encrypted.Zip FOUND\n", "", Some(1), None),
            EngineResult::NotScanned(_)
        ));
        // A real threat beats a limit alert.
        assert!(matches!(
            parse_clamscan_output("/q/a: Heuristics.Limits.Exceeded.MaxFiles FOUND\n/q/a: Eicar FOUND\n", "", Some(1), None),
            EngineResult::Infected(v) if v == vec!["Eicar".to_string()]
        ));
        assert!(matches!(
            parse_clamscan_output("", "ERROR: Can't open file", Some(2), None),
            EngineResult::Error(_)
        ));
        // File names containing ": " do not confuse the parser.
        assert_eq!(
            parse_clamscan_output("/q/a: b: Eicar FOUND\n", "", Some(1), None),
            EngineResult::Infected(vec!["Eicar".into()])
        );
    }

    #[test]
    fn truncation_is_never_clean() {
        let m = truncation_marker(
            "LibClamAV debug: cli_unzip: trimming output size to maxfilesize (20971520)",
        );
        assert!(m.is_some());
        assert!(truncation_marker("LibClamAV debug: Matcher[0]: GENERIC: AC sigs: 97").is_none());
        assert!(truncation_marker("some other exceeded line").is_none());
        assert!(matches!(
            parse_clamscan_output("", "", Some(0), m.as_deref()),
            EngineResult::NotScanned(_)
        ));
        // A detection still wins over truncation.
        assert!(matches!(
            parse_clamscan_output("/q/a: Eicar FOUND\n", "", Some(1), m.as_deref()),
            EngineResult::Infected(_)
        ));
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("25M"), Some(25 * MIB));
        assert_eq!(parse_size("4G"), Some(4096 * MIB));
        assert_eq!(parse_size("512k"), Some(512 * 1024));
        assert_eq!(parse_size("1048576"), Some(1_048_576));
        assert_eq!(parse_size("lots"), None);
    }

    #[test]
    fn clamd_conf() {
        let c =
            parse_clamd_conf("# comment\nLocalSocket /run/clamav/clamd.ctl\nMaxFileSize 2000M\n");
        assert_eq!(c.local_socket.as_deref(), Some("/run/clamav/clamd.ctl"));
        assert_eq!(c.max_file_size, 2000 * MIB);
        assert!(c.sufficient_for(1).is_err(), "AlertExceedsMax missing");
        let c = parse_clamd_conf("TCPSocket 3310\nAlertExceedsMax yes\nAlertEncrypted yes\nStreamMaxLength 2000M\nMaxFileSize 2047M\nMaxScanSize 0\n");
        assert!(parse_clamd_conf(
            "AlertExceedsMax yes\nAlertEncrypted yes\nStreamMaxLength 2000M\nMaxFileSize 1000M\n"
        )
        .sufficient_for(1)
        .is_err());
        assert_eq!(c.tcp, Some(("127.0.0.1".into(), 3310)));
        assert!(c.sufficient_for(1000 * MIB).is_ok());
        assert!(c.sufficient_for(2001 * MIB).is_err());
        assert_eq!(c.max_scan_size, u64::MAX);
    }

    #[test]
    fn clamd_replies() {
        assert_eq!(parse_clamd_reply("stream: OK\0"), EngineResult::Clean);
        assert_eq!(
            parse_clamd_reply("stream: Eicar-Signature FOUND\0"),
            EngineResult::Infected(vec!["Eicar-Signature".into()])
        );
        assert!(matches!(
            parse_clamd_reply("stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0"),
            EngineResult::NotScanned(_)
        ));
        assert!(matches!(
            parse_clamd_reply("INSTREAM size limit exceeded. ERROR\0"),
            EngineResult::NotScanned(_)
        ));
        assert!(matches!(
            parse_clamd_reply("garbage"),
            EngineResult::Error(_)
        ));
    }

    #[tokio::test]
    async fn oversize_files_are_not_scanned() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        let f = std::fs::File::create(&p).unwrap();
        f.set_len(CLAMAV_MAX_FILE + 1).unwrap(); // sparse
        assert!(matches!(
            scan(&ClamAvSettings::default(), &p).await,
            EngineResult::NotScanned(_)
        ));
        f.set_len(3 * MIB).unwrap();
        let s = ClamAvSettings {
            max_filesize_mib: 2,
            ..Default::default()
        };
        assert!(matches!(scan(&s, &p).await, EngineResult::NotScanned(_)));
    }

    #[tokio::test]
    async fn missing_clamscan_is_unavailable_not_clean() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        let s = ClamAvSettings {
            mode: ClamAvMode::ClamscanOnly,
            clamscan_path: Some(d.path().join("does-not-exist")),
            ..Default::default()
        };
        assert!(matches!(scan(&s, &p).await, EngineResult::Unavailable(_)));
    }

    #[test]
    fn clamd_conf_with_scanning_disabled_is_refused() {
        let c = parse_clamd_conf("AlertExceedsMax yes\nAlertEncrypted yes\nStreamMaxLength 2047M\nMaxFileSize 2047M\nScanArchive no\n");
        assert!(c.sufficient_for(1).is_err());
    }

    #[test]
    fn container_sniffing() {
        let d = tempfile::tempdir().unwrap();
        let w = |name: &str, data: &[u8]| {
            let p = d.path().join(name);
            std::fs::write(&p, data).unwrap();
            p
        };
        assert!(looks_like_container(&w("z", b"PK\x03\x04rest")));
        assert!(looks_like_container(&w("g", &[0x1f, 0x8b, 8, 0])));
        assert!(looks_like_container(&w("e", b"MZ\x90\x00")));
        assert!(looks_like_container(&w("p", b"%PDF-1.7")));
        let mut tar = vec![0u8; 600];
        tar[257..262].copy_from_slice(b"ustar");
        assert!(looks_like_container(&w("t", &tar)));
        assert!(!looks_like_container(&w("txt", b"just some text")));
        assert!(!looks_like_container(&w("bin", &[7u8; 4096])));
    }

    #[test]
    fn auto_mode_prefers_clamscan() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("clamscan");
        std::fs::write(&exe, b"").unwrap();
        let conf = d.path().join("clamd.conf");
        std::fs::write(&conf, "LocalSocket /x.sock\nAlertExceedsMax yes\nAlertEncrypted yes\nStreamMaxLength 2047M\nMaxFileSize 2047M\n").unwrap();
        let s = ClamAvSettings {
            clamscan_path: Some(exe.clone()),
            clamd_conf_path: Some(conf),
            ..Default::default()
        };
        assert_eq!(choose_backend(&s, 10), Backend::Clamscan { exe });
    }

    #[tokio::test]
    async fn clamd_never_vouches_for_containers() {
        let d = tempfile::tempdir().unwrap();
        let conf = d.path().join("clamd.conf");
        std::fs::write(&conf, "TCPSocket 1\nAlertExceedsMax yes\nAlertEncrypted yes\nStreamMaxLength 2047M\nMaxFileSize 2047M\n").unwrap();
        let s = ClamAvSettings {
            mode: ClamAvMode::ClamdOnly,
            clamd_conf_path: Some(conf),
            ..Default::default()
        };
        let z = d.path().join("a.quarantine");
        std::fs::write(&z, b"PK\x03\x04whatever").unwrap();
        assert!(matches!(scan(&s, &z).await, EngineResult::NotScanned(_)));
    }

    #[test]
    fn archive_failure_markers() {
        for l in [
            "LibClamAV debug: cli_unzip: unsupported method (14)",
            "LibClamAV debug: cli_unzip: extraction failed",
            "LibClamAV debug: cli_unzip: local header - stream out of file",
            "LibClamAV debug: cli_unzip: Skipping decompression of file entry at offset: 0x0, size: 68, compressed data not available",
        ] {
            assert!(truncation_marker(l).is_some(), "{l}");
        }
        // Directory entries / empty files are benign.
        assert!(truncation_marker("LibClamAV debug: cli_unzip: Skipping decompression of file entry at offset: 0x0, size: 0, compressed data not available").is_none());
    }

    #[test]
    fn broken_hashing_gets_an_actionable_message() {
        let m = explain_error("LibClamAV Error: fmap_get_hash: error calculating sha2-256 hash!");
        assert!(m.contains("official ClamAV package"));
        assert_eq!(
            explain_error("LibClamAV Error: other"),
            "LibClamAV Error: other"
        );
    }
}
