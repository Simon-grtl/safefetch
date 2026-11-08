//! User settings. The VirusTotal API key is deliberately NOT part of this
//! structure: it lives in the OS keyring (see [`crate::secrets`]).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClamAvMode {
    /// clamd if its configuration is provably sufficient, otherwise clamscan.
    #[default]
    Auto,
    ClamscanOnly,
    ClamdOnly,
}

/// ClamAV configuration. Executable/socket paths can only be changed by
/// editing `settings.json` by hand — never from the UI — so that a
/// compromised webview cannot make the app run an arbitrary program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClamAvSettings {
    pub mode: ClamAvMode,
    pub clamscan_path: Option<PathBuf>,
    pub freshclam_path: Option<PathBuf>,
    /// "unix:/path/to/clamd.sock" or "tcp:127.0.0.1:3310".
    pub clamd_address: Option<String>,
    pub clamd_conf_path: Option<PathBuf>,
    /// Custom signature directory (`clamscan -d`). Used by the test-suite.
    pub database_dir: Option<PathBuf>,
    pub max_filesize_mib: u64,
    pub max_scansize_mib: u64,
    pub max_files: u64,
    pub max_recursion: u32,
    pub max_scantime_secs: u64,
}

impl Default for ClamAvSettings {
    fn default() -> Self {
        Self {
            mode: ClamAvMode::Auto,
            clamscan_path: None,
            freshclam_path: None,
            clamd_address: None,
            clamd_conf_path: None,
            database_dir: None,
            // libclamav cannot scan a single file of 2 GiB or more; see clamav.rs.
            max_filesize_mib: 2047,
            max_scansize_mib: 4000,
            max_files: 100_000,
            max_recursion: 30,
            max_scantime_secs: 1800,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub destination_dir: Option<PathBuf>,
    /// Override of the quarantine directory; must be on the destination volume.
    pub quarantine_dir: Option<PathBuf>,
    pub max_concurrent_downloads: u8,
    /// VirusTotal file detections (malicious) at or above → Dangerous.
    pub vt_dangerous_threshold: u32,
    /// VirusTotal file detections at or above (and below dangerous) → Suspect.
    pub vt_suspicious_threshold: u32,
    /// VirusTotal URL detections at or above → link blocked.
    pub url_block_threshold: u32,
    /// VirusTotal domain detections at or above → link blocked.
    pub domain_block_threshold: u32,
    /// When true, a failed/unavailable VirusTotal lookup makes the file "Not analyzed".
    pub require_virustotal: bool,
    /// Plain-HTTP links are allowed (with a warning) when true, refused otherwise.
    pub allow_http: bool,
    pub max_redirects: u8,
    pub connect_timeout_secs: u64,
    /// Maximum time without receiving any byte.
    pub idle_timeout_secs: u64,
    pub max_retries: u8,
    /// 0 = unlimited.
    pub max_file_size_mib: u64,
    /// Minimum free space kept on the quarantine volume.
    pub min_free_space_mib: u64,
    /// Free VirusTotal API: 4 requests/min and 500/day.
    pub vt_min_interval_secs: u64,
    pub vt_daily_quota: u32,
    pub use_defender: bool,
    pub auto_update_signatures: bool,
    pub check_app_updates: bool,
    pub clamav: ClamAvSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            destination_dir: None,
            quarantine_dir: None,
            max_concurrent_downloads: 2,
            vt_dangerous_threshold: 3,
            vt_suspicious_threshold: 1,
            url_block_threshold: 2,
            domain_block_threshold: 3,
            require_virustotal: false,
            allow_http: true,
            max_redirects: 5,
            connect_timeout_secs: 20,
            idle_timeout_secs: 60,
            max_retries: 3,
            max_file_size_mib: 102_400,
            min_free_space_mib: 512,
            vt_min_interval_secs: 15,
            vt_daily_quota: 500,
            use_defender: true,
            auto_update_signatures: true,
            check_app_updates: true,
            clamav: ClamAvSettings::default(),
        }
    }
}

/// The subset of settings the UI may change. Paths to executables, the
/// quarantine location and ClamAV limits are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiSettings {
    pub destination_dir: Option<String>,
    pub max_concurrent_downloads: u8,
    pub vt_dangerous_threshold: u32,
    pub vt_suspicious_threshold: u32,
    pub url_block_threshold: u32,
    pub domain_block_threshold: u32,
    pub require_virustotal: bool,
    pub allow_http: bool,
    pub max_file_size_mib: u64,
    pub use_defender: bool,
    pub auto_update_signatures: bool,
    pub check_app_updates: bool,
}

impl Settings {
    pub fn to_ui(&self) -> UiSettings {
        UiSettings {
            destination_dir: self
                .destination_dir
                .as_ref()
                .map(|p| p.display().to_string()),
            max_concurrent_downloads: self.max_concurrent_downloads,
            vt_dangerous_threshold: self.vt_dangerous_threshold,
            vt_suspicious_threshold: self.vt_suspicious_threshold,
            url_block_threshold: self.url_block_threshold,
            domain_block_threshold: self.domain_block_threshold,
            require_virustotal: self.require_virustotal,
            allow_http: self.allow_http,
            max_file_size_mib: self.max_file_size_mib,
            use_defender: self.use_defender,
            auto_update_signatures: self.auto_update_signatures,
            check_app_updates: self.check_app_updates,
        }
    }

    /// Apply UI-editable fields (the destination is ignored: it can only be
    /// changed through the native folder picker).
    pub fn apply_ui(&mut self, ui: &UiSettings) {
        self.max_concurrent_downloads = ui.max_concurrent_downloads;
        self.vt_dangerous_threshold = ui.vt_dangerous_threshold;
        self.vt_suspicious_threshold = ui.vt_suspicious_threshold;
        self.url_block_threshold = ui.url_block_threshold;
        self.domain_block_threshold = ui.domain_block_threshold;
        self.require_virustotal = ui.require_virustotal;
        self.allow_http = ui.allow_http;
        self.max_file_size_mib = ui.max_file_size_mib;
        self.use_defender = ui.use_defender;
        self.auto_update_signatures = ui.auto_update_signatures;
        self.check_app_updates = ui.check_app_updates;
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::InvalidSettings(m.to_string()));
        if !(1..=8).contains(&self.max_concurrent_downloads) {
            return bad("Simultaneous downloads must be between 1 and 8.");
        }
        if self.vt_suspicious_threshold == 0 {
            return bad("The suspicious threshold must be at least 1.");
        }
        if self.vt_dangerous_threshold < self.vt_suspicious_threshold {
            return bad("The dangerous threshold must be ≥ the suspicious threshold.");
        }
        if self.url_block_threshold == 0 || self.domain_block_threshold == 0 {
            return bad("Link blocking thresholds must be at least 1.");
        }
        if self.max_redirects > 20 {
            return bad("At most 20 redirects.");
        }
        if self.connect_timeout_secs == 0 || self.idle_timeout_secs == 0 {
            return bad("Timeouts must be positive.");
        }
        for p in [&self.destination_dir, &self.quarantine_dir]
            .into_iter()
            .flatten()
        {
            if !p.is_absolute() {
                return bad("Folders must be absolute paths.");
            }
        }
        for p in [
            &self.clamav.clamscan_path,
            &self.clamav.freshclam_path,
            &self.clamav.clamd_conf_path,
            &self.clamav.database_dir,
        ]
        .into_iter()
        .flatten()
        {
            if !p.is_absolute() {
                return bad("ClamAV paths must be absolute.");
            }
        }
        if let Some(addr) = &self.clamav.clamd_address {
            if !(addr.starts_with("unix:") || addr.starts_with("tcp:")) {
                return bad("clamd_address must start with unix: or tcp:");
            }
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let s: Settings = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::InvalidSettings(format!("settings.json: {e}")))?;
                s.validate()?;
                Ok(s)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| Error::Internal(e.to_string()))?;
        crate::fsutil::write_atomic(path, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Settings::default().validate().unwrap();
    }

    #[test]
    fn invalid_values_are_rejected() {
        let mut s = Settings {
            max_concurrent_downloads: 0,
            ..Default::default()
        };
        assert!(s.validate().is_err());
        s.max_concurrent_downloads = 2;
        s.vt_dangerous_threshold = 1;
        s.vt_suspicious_threshold = 2;
        assert!(s.validate().is_err());
        s.vt_dangerous_threshold = 3;
        s.clamav.clamscan_path = Some("relative/clamscan".into());
        assert!(s.validate().is_err());
    }

    #[test]
    fn ui_cannot_change_paths() {
        let mut s = Settings::default();
        let mut ui = s.to_ui();
        ui.destination_dir = Some("/tmp/evil".into());
        ui.vt_dangerous_threshold = 5;
        s.apply_ui(&ui);
        assert_eq!(s.destination_dir, None);
        assert_eq!(s.vt_dangerous_threshold, 5);
    }

    #[test]
    fn roundtrip_and_partial_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("settings.json");
        assert_eq!(Settings::load(&p).unwrap(), Settings::default());
        std::fs::write(&p, br#"{"max_concurrent_downloads": 4}"#).unwrap();
        assert_eq!(Settings::load(&p).unwrap().max_concurrent_downloads, 4);
        let s = Settings {
            vt_dangerous_threshold: 7,
            ..Default::default()
        };
        s.save(&p).unwrap();
        assert_eq!(Settings::load(&p).unwrap().vt_dangerous_threshold, 7);
    }
}
