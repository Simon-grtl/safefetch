//! Publisher checksum lists (`SHA256SUMS`, `file.iso.sha256`…).
//!
//! The user may give, instead of a SHA-256, the link to the publisher's
//! checksum file. SafeFetch fetches it (small, size-limited, same network
//! rules as a download), finds the line for the downloaded file and compares.
//! GPG signatures of the list are NOT verified yet: this protects against a
//! corrupted or swapped file on a mirror, not against a compromised publisher
//! site serving both the file and the list.

use serde::{Deserialize, Serialize};

/// A checksum list larger than this is refused (real lists are a few KiB).
pub const MAX_LIST_SIZE: u64 = 1024 * 1024;

/// Result of checking a file against a checksum list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChecksumListResult {
    /// The file is listed; its expected SHA-256 is in `ScanReport::expected_sha256`.
    Found { source: String, entry: String },
    /// The list was read but does not mention this file.
    NotListed { source: String },
    /// The list could not be fetched or parsed.
    Unavailable { source: String, error: String },
}

/// One `hash  name` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub sha256: String,
    pub name: String,
}

fn hex64(s: &str) -> Option<String> {
    (s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_ascii_lowercase())
}

/// Parse GNU (`hash  name`, `hash *name`, `\hash  escaped\nname`) and BSD
/// (`SHA256 (name) = hash`) formats, plus a bare hash on its own line.
pub fn parse(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // BSD style.
        if let Some(rest) = line
            .strip_prefix("SHA256 (")
            .or_else(|| line.strip_prefix("SHA2-256 ("))
        {
            if let Some((name, hash)) = rest.rsplit_once(") = ") {
                if let Some(h) = hex64(hash.trim()) {
                    out.push(Entry {
                        sha256: h,
                        name: name.to_string(),
                    });
                }
            }
            continue;
        }
        // GNU style; a leading backslash means the name is escaped.
        let (escaped, line) = match line.strip_prefix('\\') {
            Some(l) => (true, l),
            None => (false, line),
        };
        let (hash, rest) = match line.split_once(char::is_whitespace) {
            Some((h, r)) => (h, r),
            None => (line, ""),
        };
        let Some(h) = hex64(hash) else { continue };
        let mut name = rest.trim_start().to_string();
        if let Some(n) = name.strip_prefix('*') {
            name = n.to_string();
        }
        if escaped {
            name = name.replace("\\n", "\n").replace("\\\\", "\\");
        }
        out.push(Entry { sha256: h, name });
    }
    out
}

fn base_name(name: &str) -> &str {
    let n = name.trim_start_matches("./");
    n.rsplit(['/', '\\']).next().unwrap_or(n)
}

/// Find the entry for a file. `candidates` are the names the file may have
/// (name from the server, last segment of the final and original URLs).
/// A list with a single entry and no usable name (e.g. `file.iso.sha256`
/// containing only the hash) matches that single entry.
pub fn find<'a>(entries: &'a [Entry], candidates: &[String]) -> Option<&'a Entry> {
    let wanted: Vec<&str> = candidates
        .iter()
        .map(|c| c.trim())
        .filter(|c| !c.is_empty())
        .collect();
    let exact = entries
        .iter()
        .find(|e| wanted.iter().any(|w| base_name(&e.name) == *w));
    if exact.is_some() {
        return exact;
    }
    let ci = entries.iter().find(|e| {
        wanted
            .iter()
            .any(|w| base_name(&e.name).eq_ignore_ascii_case(w))
    });
    if ci.is_some() {
        return ci;
    }
    match entries {
        [only] if only.name.is_empty() => Some(only),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    fn names(c: &[&str]) -> Vec<String> {
        c.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn gnu_and_bsd_formats() {
        let text = format!(
            "# comment\n{A}  ubuntu-24.04-desktop-amd64.iso\r\n{B} *./sub/tool.zip\nSHA256 (debian.iso) = {A}\nnot a line\n"
        );
        let e = parse(&text);
        assert_eq!(e.len(), 3);
        assert_eq!(
            find(&e, &names(&["tool.zip"])).unwrap().sha256,
            B.to_ascii_lowercase()
        );
        assert_eq!(find(&e, &names(&["debian.iso"])).unwrap().sha256, A);
        assert_eq!(
            find(&e, &names(&["x", "ubuntu-24.04-desktop-amd64.iso"]))
                .unwrap()
                .name,
            "ubuntu-24.04-desktop-amd64.iso"
        );
        assert!(find(&e, &names(&["other.iso"])).is_none());
    }

    #[test]
    fn single_hash_file() {
        let e = parse(&format!("{A}\n"));
        assert_eq!(find(&e, &names(&["whatever.iso"])).unwrap().sha256, A);
        // A single entry WITH a different name does not match.
        let e = parse(&format!("{A}  other.iso\n"));
        assert!(find(&e, &names(&["whatever.iso"])).is_none());
    }

    #[test]
    fn names_with_spaces_and_case() {
        let e = parse(&format!("{A}  My File (1).ISO\n"));
        assert!(find(&e, &names(&["My File (1).ISO"])).is_some());
        assert!(find(&e, &names(&["my file (1).iso"])).is_some());
    }
}
