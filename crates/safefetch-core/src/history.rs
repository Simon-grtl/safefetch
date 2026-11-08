//! "Never download twice": a small persistent index of finished jobs.
//!
//! URLs are stored as SHA-256 digests (no plain URLs, which may contain
//! tokens), together with the file SHA-256, the verdict and the delivered path.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::fsutil;
use crate::hash::sha256_bytes;
use crate::verdict::VerdictLevel;

const MAX_ENTRIES: usize = 50_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub url_hash: String,
    pub sha256: Option<String>,
    pub file_name: String,
    pub verdict: VerdictLevel,
    pub delivered_path: Option<PathBuf>,
    pub at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct History {
    entries: Vec<HistoryEntry>,
    #[serde(skip)]
    path: PathBuf,
}

/// Canonical form used for de-duplication (fragment removed).
pub fn url_hash(url: &url::Url) -> String {
    let mut u = url.clone();
    u.set_fragment(None);
    sha256_bytes(u.as_str().as_bytes())
}

impl History {
    pub fn load(path: &Path) -> Self {
        let mut h: History = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        h.path = path.to_path_buf();
        h
    }

    fn save(&self) -> Result<()> {
        let json = serde_json::to_vec(self).map_err(|e| crate::Error::Internal(e.to_string()))?;
        fsutil::write_atomic(&self.path, &json)
    }

    pub fn record(&mut self, e: HistoryEntry) -> Result<()> {
        self.entries.push(e);
        if self.entries.len() > MAX_ENTRIES {
            let excess = self.entries.len() - MAX_ENTRIES;
            self.entries.drain(..excess);
        }
        self.save()
    }

    /// A previous clean delivery of this URL whose file still exists.
    pub fn delivered_url(&self, url_hash: &str) -> Option<&HistoryEntry> {
        self.entries.iter().rev().find(|e| {
            e.url_hash == url_hash && e.delivered_path.as_ref().is_some_and(|p| p.is_file())
        })
    }

    /// The URL was previously judged dangerous.
    pub fn dangerous_url(&self, url_hash: &str) -> Option<&HistoryEntry> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.url_hash == url_hash && e.verdict == VerdictLevel::Dangerous)
    }

    /// A previously delivered file with identical content that still exists.
    pub fn delivered_sha(&self, sha: &str) -> Option<&HistoryEntry> {
        self.entries.iter().rev().find(|e| {
            e.sha256.as_deref() == Some(sha)
                && e.delivered_path.as_ref().is_some_and(|p| p.is_file())
        })
    }

    pub fn clear(&mut self) -> Result<()> {
        self.entries.clear();
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_lookups() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("delivered.bin");
        std::fs::write(&file, b"x").unwrap();
        let mut h = History::load(&d.path().join("h.json"));
        let u = url::Url::parse("https://e.example/a?x=1#frag").unwrap();
        let uh = url_hash(&u);
        assert_eq!(
            uh,
            url_hash(&url::Url::parse("https://e.example/a?x=1").unwrap())
        );
        h.record(HistoryEntry {
            url_hash: uh.clone(),
            sha256: Some("s".into()),
            file_name: "a".into(),
            verdict: VerdictLevel::Clean,
            delivered_path: Some(file.clone()),
            at: 1,
        })
        .unwrap();
        assert!(h.delivered_url(&uh).is_some());
        assert!(h.delivered_sha("s").is_some());
        // Persisted, and stores no plain URL.
        let raw = std::fs::read_to_string(d.path().join("h.json")).unwrap();
        assert!(!raw.contains("e.example"));
        let h2 = History::load(&d.path().join("h.json"));
        assert!(h2.delivered_url(&uh).is_some());
        // If the user deleted the delivered file, the link may be downloaded again.
        std::fs::remove_file(&file).unwrap();
        assert!(h2.delivered_url(&uh).is_none());
    }
}
