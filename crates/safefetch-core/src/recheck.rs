//! Weekly re-check of delivered files.
//!
//! A file delivered as Clean may be recognized as malware days later, once
//! antivirus vendors have caught up. Once a week (while SafeFetch runs, with
//! a VirusTotal key), the SHA-256 of every delivered file that still exists is
//! looked up again on VirusTotal — by hash only, never the file. A file now
//! flagged produces an alert the user sees in the main window.
//!
//! State (`recheck.json`, private): last run, when each hash was last looked
//! up, and the alerts. No URL is stored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::fsutil;
use crate::verdict::VerdictLevel;

pub const WEEK_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecheckAlert {
    /// Stable id for UI actions (the file's SHA-256).
    pub id: String,
    pub file_name: String,
    pub delivered_path: PathBuf,
    pub delivered_at: u64,
    pub found_at: u64,
    pub level: VerdictLevel,
    pub malicious: u32,
    pub suspicious: u32,
    pub permalink: String,
    pub detections: Vec<String>,
    #[serde(default)]
    pub dismissed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RecheckSummary {
    pub checked: u32,
    pub remaining: u32,
    pub new_alerts: u32,
    pub errors: Vec<String>,
    pub last_run: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RecheckState {
    pub last_run: Option<u64>,
    /// sha256 → last lookup time.
    #[serde(default)]
    pub checked: BTreeMap<String, u64>,
    #[serde(default)]
    pub alerts: Vec<RecheckAlert>,
    #[serde(skip)]
    path: PathBuf,
}

/// A delivered file to look up again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub sha256: String,
    pub file_name: String,
    pub delivered_path: PathBuf,
    pub delivered_at: u64,
}

impl RecheckState {
    pub fn load(path: &Path) -> Self {
        let mut s: RecheckState = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        s.path = path.to_path_buf();
        s
    }

    pub fn save(&self) -> Result<()> {
        let json = serde_json::to_vec(self).map_err(|e| crate::Error::Internal(e.to_string()))?;
        fsutil::write_atomic(&self.path, &json)
    }

    pub fn due(&self, now: u64) -> bool {
        self.last_run
            .is_none_or(|t| now.saturating_sub(t) >= WEEK_SECS)
    }

    /// Files to look up in this run: not looked up during the last week,
    /// least recently checked first, at most `max`.
    pub fn select(
        &self,
        candidates: Vec<Candidate>,
        now: u64,
        max: usize,
    ) -> (Vec<Candidate>, usize) {
        let mut due: Vec<Candidate> = candidates
            .into_iter()
            .filter(|c| {
                self.checked
                    .get(&c.sha256)
                    .is_none_or(|t| now.saturating_sub(*t) >= WEEK_SECS - 3600)
            })
            .collect();
        due.sort_by_key(|c| self.checked.get(&c.sha256).copied().unwrap_or(0));
        let total = due.len();
        due.truncate(max);
        let remaining = total - due.len();
        (due, remaining)
    }

    /// Record a new alert, or refresh an existing one. Returns true if new
    /// (or newly worse than an alert the user dismissed).
    pub fn raise(&mut self, alert: RecheckAlert) -> bool {
        match self.alerts.iter_mut().find(|a| a.id == alert.id) {
            Some(existing) => {
                let worse = alert.malicious > existing.malicious || alert.level > existing.level;
                let dismissed = existing.dismissed && !worse;
                *existing = RecheckAlert { dismissed, ..alert };
                worse
            }
            None => {
                self.alerts.push(alert);
                true
            }
        }
    }

    pub fn active_alerts(&self) -> Vec<RecheckAlert> {
        self.alerts
            .iter()
            .filter(|a| !a.dismissed)
            .cloned()
            .collect()
    }

    pub fn dismiss(&mut self, id: &str) -> bool {
        match self.alerts.iter_mut().find(|a| a.id == id) {
            Some(a) => {
                a.dismissed = true;
                true
            }
            None => false,
        }
    }

    /// Forget hashes whose files no longer exist (keeps the state small).
    pub fn retain_checked(&mut self, keep: &[String]) {
        self.checked.retain(|k, _| keep.contains(k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(sha: &str) -> Candidate {
        Candidate {
            sha256: sha.into(),
            file_name: format!("{sha}.bin"),
            delivered_path: PathBuf::from(format!("/x/{sha}")),
            delivered_at: 1,
        }
    }

    fn alert(id: &str, malicious: u32) -> RecheckAlert {
        RecheckAlert {
            id: id.into(),
            file_name: "f".into(),
            delivered_path: PathBuf::from("/x/f"),
            delivered_at: 1,
            found_at: 2,
            level: VerdictLevel::Dangerous,
            malicious,
            suspicious: 0,
            permalink: "https://www.virustotal.com/gui/file/x".into(),
            detections: vec![],
            dismissed: false,
        }
    }

    #[test]
    fn weekly_schedule_and_selection() {
        let d = tempfile::tempdir().unwrap();
        let mut s = RecheckState::load(&d.path().join("r.json"));
        let now = 10 * WEEK_SECS;
        assert!(s.due(now));
        s.last_run = Some(now - 3600);
        assert!(!s.due(now));
        s.checked.insert("a".into(), now - 60); // just checked
        s.checked.insert("b".into(), now - 2 * WEEK_SECS);
        let (sel, rest) = s.select(vec![cand("a"), cand("b"), cand("c")], now, 1);
        // never-checked "c" first, then "b"; "a" is not due
        assert_eq!(sel, vec![cand("c")]);
        assert_eq!(rest, 1);
        s.save().unwrap();
        let s2 = RecheckState::load(&d.path().join("r.json"));
        assert_eq!(s2.last_run, Some(now - 3600));
    }

    #[test]
    fn alerts_dismiss_and_escalate() {
        let d = tempfile::tempdir().unwrap();
        let mut s = RecheckState::load(&d.path().join("r.json"));
        assert!(s.raise(alert("x", 3)));
        assert!(!s.raise(alert("x", 3)));
        assert!(s.dismiss("x"));
        assert!(s.active_alerts().is_empty());
        // Same detections: stays dismissed. More engines: shown again.
        s.raise(alert("x", 3));
        assert!(s.active_alerts().is_empty());
        assert!(s.raise(alert("x", 9)));
        assert_eq!(s.active_alerts().len(), 1);
    }
}
