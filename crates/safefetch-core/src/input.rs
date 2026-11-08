//! Parsing of the text the user pastes: one link per line, optionally
//! followed by the expected SHA-256 (`URL<space>HASH` or `URL sha256:HASH`).

use serde::Serialize;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRequest {
    pub url: Url,
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InputError {
    pub line: usize,
    pub message: String,
}

/// Normalise a SHA-256 written by a human: hex, 64 chars, optional prefix.
pub fn parse_sha256(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s
        .strip_prefix("sha256:")
        .or_else(|| s.strip_prefix("SHA256:"))
        .unwrap_or(s);
    (s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_ascii_lowercase())
}

pub fn parse_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw.trim()).map_err(|e| format!("not a valid URL ({e})"))?;
    match url.scheme() {
        "https" | "http" => {}
        other => {
            return Err(format!(
                "unsupported scheme \"{other}\" (only https and http)"
            ))
        }
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("the link has no host".into());
    }
    Ok(url)
}

/// Parse the pasted text. Blank lines and lines starting with '#' are ignored;
/// duplicate links in the same batch are kept once.
pub fn parse_links(text: &str) -> (Vec<LinkRequest>, Vec<InputError>) {
    let mut ok: Vec<LinkRequest> = Vec::new();
    let mut errors = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let raw_url = parts.next().unwrap_or_default();
        let hash = parts.next();
        if parts.next().is_some() {
            errors.push(InputError {
                line: i + 1,
                message: "expected \"URL [sha256]\"".into(),
            });
            continue;
        }
        let url = match parse_url(raw_url) {
            Ok(u) => u,
            Err(message) => {
                errors.push(InputError {
                    line: i + 1,
                    message,
                });
                continue;
            }
        };
        let expected_sha256 = match hash {
            None => None,
            Some(h) => match parse_sha256(h) {
                Some(h) => Some(h),
                None => {
                    errors.push(InputError {
                        line: i + 1,
                        message: "the checksum must be a 64-character SHA-256 in hex".into(),
                    });
                    continue;
                }
            },
        };
        if let Some(existing) = ok.iter_mut().find(|r| r.url == url) {
            if existing.expected_sha256.is_none() {
                existing.expected_sha256 = expected_sha256;
            }
            continue;
        }
        ok.push(LinkRequest {
            url,
            expected_sha256,
        });
    }
    (ok, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    const H: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parses_lines() {
        let text = format!(
            "https://a.example/x.zip\n\n# comment\nhttps://b.example/y.iso {}\nhttp://c.example/z sha256:{H}\n",
            H.to_uppercase()
        );
        let (ok, err) = parse_links(&text);
        assert!(err.is_empty(), "{err:?}");
        assert_eq!(ok.len(), 3);
        assert_eq!(ok[0].expected_sha256, None);
        assert_eq!(ok[1].expected_sha256.as_deref(), Some(H));
        assert_eq!(ok[2].expected_sha256.as_deref(), Some(H));
    }

    #[test]
    fn rejects_bad_input() {
        let (ok, err) = parse_links(
            "ftp://x.example/a\nfile:///etc/passwd\njavascript:alert(1)\nhttps://ok.example/a nothex\nnot a url at all\n",
        );
        assert!(ok.is_empty());
        assert_eq!(err.len(), 5);
        assert_eq!(err[0].line, 1);
    }

    #[test]
    fn deduplicates_within_batch() {
        let (ok, _) = parse_links(&format!("https://a.example/x\nhttps://a.example/x {H}\n"));
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].expected_sha256.as_deref(), Some(H));
    }
}
