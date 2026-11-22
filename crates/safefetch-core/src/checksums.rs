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
/// Overall deadline for fetching a list (connect + redirects + body).
pub const FETCH_DEADLINE_SECS: u64 = 120;

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
    /// The names this file goes by (link, redirect target, server-supplied
    /// name) point to DIFFERENT entries: the server may be passing off another
    /// listed file as the one requested.
    Conflict { source: String, names: Vec<String> },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<'a> {
    Found(&'a Entry),
    NotListed,
    /// Candidate names match entries with different hashes.
    Conflict(Vec<String>),
}

fn entry_for<'a>(entries: &'a [Entry], name: &str) -> Option<&'a Entry> {
    entries
        .iter()
        .find(|e| base_name(&e.name) == name)
        .or_else(|| {
            entries
                .iter()
                .find(|e| base_name(&e.name).eq_ignore_ascii_case(name))
        })
}

/// Find the entry for a file. `candidates` are the names the file goes by,
/// MOST TRUSTED FIRST: the last segment of the link the user typed, then of
/// the redirect target, then the name supplied by the server. The first one
/// found in the list wins, but if two candidates name entries with different
/// hashes the result is a [`Lookup::Conflict`] — a server must not be able to
/// pick which listed file it is checked against.
/// A list with a single entry and no name (e.g. `file.iso.sha256` holding
/// only the hash) matches that single entry.
pub fn find<'a>(entries: &'a [Entry], candidates: &[String]) -> Lookup<'a> {
    let mut first: Option<&Entry> = None;
    let mut matched: Vec<(String, &Entry)> = Vec::new();
    for c in candidates
        .iter()
        .map(|c| c.trim())
        .filter(|c| !c.is_empty())
    {
        if let Some(e) = entry_for(entries, c) {
            first.get_or_insert(e);
            matched.push((c.to_string(), e));
        }
    }
    if let Some(f) = first {
        if matched.iter().any(|(_, e)| e.sha256 != f.sha256) {
            let mut names: Vec<String> = matched.into_iter().map(|(n, _)| n).collect();
            names.dedup();
            return Lookup::Conflict(names);
        }
        return Lookup::Found(f);
    }
    match entries {
        [only] if only.name.is_empty() => Lookup::Found(only),
        _ => Lookup::NotListed,
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

    fn found<'a>(e: &'a [Entry], c: &[&str]) -> &'a Entry {
        match find(e, &names(c)) {
            Lookup::Found(x) => x,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn server_cannot_choose_another_listed_file() {
        // The link asks for distro.iso; the server calls its content tool.zip,
        // another file of the same list with a different hash.
        let e = parse(&format!("{A}  distro.iso\n{B}  tool.zip\n"));
        assert!(matches!(
            find(&e, &names(&["distro.iso", "tool.zip"])),
            Lookup::Conflict(n) if n == vec!["distro.iso".to_string(), "tool.zip".to_string()]
        ));
        // Same hash under two names: no conflict; the link's name wins.
        let e = parse(&format!("{A}  distro.iso\n{A}  distro-latest.iso\n"));
        assert_eq!(
            found(&e, &["distro.iso", "distro-latest.iso"]).name,
            "distro.iso"
        );
        // Unknown link name (e.g. /download?id=3): the server name is used.
        let e = parse(&format!("{A}  distro.iso\n{B}  tool.zip\n"));
        assert_eq!(found(&e, &["download", "distro.iso"]).name, "distro.iso");
    }

    #[test]
    fn gnu_and_bsd_formats() {
        let text = format!(
            "# comment\n{A}  ubuntu-24.04-desktop-amd64.iso\r\n{B} *./sub/tool.zip\nSHA256 (debian.iso) = {A}\nnot a line\n"
        );
        let e = parse(&text);
        assert_eq!(e.len(), 3);
        assert_eq!(found(&e, &["tool.zip"]).sha256, B.to_ascii_lowercase());
        assert_eq!(found(&e, &["debian.iso"]).sha256, A);
        assert_eq!(
            found(&e, &["x", "ubuntu-24.04-desktop-amd64.iso"]).name,
            "ubuntu-24.04-desktop-amd64.iso"
        );
        assert_eq!(find(&e, &names(&["other.iso"])), Lookup::NotListed);
    }

    #[test]
    fn single_hash_file() {
        let e = parse(&format!("{A}\n"));
        assert_eq!(found(&e, &["whatever.iso"]).sha256, A);
        // A single entry WITH a different name does not match.
        let e = parse(&format!("{A}  other.iso\n"));
        assert_eq!(find(&e, &names(&["whatever.iso"])), Lookup::NotListed);
    }

    #[test]
    fn names_with_spaces_and_case() {
        let e = parse(&format!("{A}  My File (1).ISO\n"));
        found(&e, &["My File (1).ISO"]);
        found(&e, &["my file (1).iso"]);
    }
}
