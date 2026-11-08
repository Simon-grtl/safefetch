//! Quarantine storage.
//!
//! Every download lives in `<quarantine>/<32 random hex>.quarantine` with a
//! sidecar `<id>.json`. The data file:
//! - has a random name and a non-executable, unassociated extension;
//! - is created with mode 0600 (never executable) on Linux/macOS;
//! - carries the Mark-of-the-Web on Windows and `com.apple.quarantine` on macOS;
//! - is never opened by SafeFetch except to be hashed or streamed to clamd.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::fsutil;
use crate::sanitize::NameWarning;
use crate::verdict::Verdict;

pub const QUARANTINE_DIR_NAME: &str = ".safefetch-quarantine";
const DATA_EXT: &str = "quarantine";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    Downloading,
    Downloaded,
    AwaitingDecision,
}

/// Persistent record of a quarantined item (sidecar JSON, mode 0600).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemMeta {
    pub id: String,
    pub url: String,
    pub final_url: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub total_size: Option<u64>,
    pub expected_sha256: Option<String>,
    pub sha256: Option<String>,
    pub file_name: String,
    #[serde(default)]
    pub name_warnings: Vec<NameWarning>,
    pub state: ItemState,
    pub verdict: Option<Verdict>,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct Quarantine {
    root: PathBuf,
}

/// An id is exactly 32 lowercase hex chars; anything else is refused so that
/// ids coming back from the UI can never be used for path traversal.
pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Quarantine {
    /// Open (and create) the quarantine directory.
    pub fn open(root: PathBuf) -> Result<Self> {
        let existed = root.is_dir();
        fsutil::create_private_dir(&root)?;
        #[cfg(windows)]
        if !existed {
            hide_on_windows(&root);
        }
        let _ = existed;
        Ok(Self { root })
    }

    /// Default location: a hidden folder inside the destination, which
    /// guarantees the same volume (atomic delivery by rename/link).
    pub fn default_root(destination: &Path) -> PathBuf {
        destination.join(QUARANTINE_DIR_NAME)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn data_path(&self, id: &str) -> Result<PathBuf> {
        if !valid_id(id) {
            return Err(Error::Policy("invalid quarantine id".into()));
        }
        Ok(self.root.join(format!("{id}.{DATA_EXT}")))
    }

    fn meta_path(&self, id: &str) -> Result<PathBuf> {
        if !valid_id(id) {
            return Err(Error::Policy("invalid quarantine id".into()));
        }
        Ok(self.root.join(format!("{id}.json")))
    }

    /// Create a new, empty, private data file and return its id.
    pub fn create_item(&self, meta_template: impl FnOnce(String) -> ItemMeta) -> Result<ItemMeta> {
        for _ in 0..8 {
            let id = fsutil::random_hex(16);
            let path = self.data_path(&id)?;
            match fsutil::private_file_options()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => {
                    let meta = meta_template(id);
                    self.save_meta(&meta)?;
                    return Ok(meta);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::Internal(
            "could not allocate a unique quarantine name".into(),
        ))
    }

    pub fn save_meta(&self, meta: &ItemMeta) -> Result<()> {
        let json = serde_json::to_vec_pretty(meta).map_err(|e| Error::Internal(e.to_string()))?;
        fsutil::write_atomic(&self.meta_path(&meta.id)?, &json)
    }

    pub fn load_meta(&self, id: &str) -> Result<ItemMeta> {
        let bytes = fs::read(self.meta_path(id)?).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::NotFound
            } else {
                e.into()
            }
        })?;
        serde_json::from_slice(&bytes).map_err(|e| Error::Internal(format!("corrupt sidecar: {e}")))
    }

    /// All items currently in quarantine (corrupt sidecars are skipped).
    pub fn list(&self) -> Vec<ItemMeta> {
        let Ok(rd) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut items: Vec<ItemMeta> = rd
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let id = name.strip_suffix(".json")?;
                valid_id(id).then(|| self.load_meta(id).ok()).flatten()
            })
            .collect();
        items.sort_by_key(|m| m.created_at);
        items
    }

    pub fn data_len(&self, id: &str) -> u64 {
        self.data_path(id)
            .ok()
            .and_then(|p| fs::metadata(p).ok())
            .map_or(0, |m| m.len())
    }

    /// Delete the data file and its sidecar.
    pub fn remove(&self, id: &str) -> Result<()> {
        for p in [self.data_path(id)?, self.meta_path(id)?] {
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        #[cfg(windows)]
        {
            if let Ok(p) = self.data_path(id) {
                let _ = fs::remove_file(format!("{}:Zone.Identifier", p.display()));
            }
        }
        Ok(())
    }

    /// Apply OS-level "downloaded from the internet" markers. Returns a
    /// warning string if the marker could not be applied (e.g. FAT volume).
    pub fn mark_untrusted(&self, id: &str, host_url: &str) -> Option<String> {
        let path = self.data_path(id).ok()?;
        if let Err(e) = fsutil::set_private_non_exec(&path) {
            return Some(format!("could not restrict permissions: {e}"));
        }
        mark_os(&path, host_url).err()
    }
}

#[cfg(windows)]
fn mark_os(path: &Path, host_url: &str) -> std::result::Result<(), String> {
    // Mark-of-the-Web: NTFS alternate data stream read by SmartScreen/Office.
    let ads = format!("{}:Zone.Identifier", path.display());
    let content = format!("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={host_url}\r\n");
    fs::write(ads, content)
        .map_err(|e| format!("Mark-of-the-Web not applied (non-NTFS volume?): {e}"))
}

#[cfg(target_os = "macos")]
fn mark_os(path: &Path, _host_url: &str) -> std::result::Result<(), String> {
    // Same format as browsers: flags;hex-timestamp;agent;
    let value = format!("0083;{:08x};SafeFetch;", fsutil::now_unix());
    xattr::set(path, "com.apple.quarantine", value.as_bytes())
        .map_err(|e| format!("macOS quarantine attribute not applied: {e}"))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn mark_os(_path: &Path, _host_url: &str) -> std::result::Result<(), String> {
    // Linux has no system-wide equivalent; 0600 (no exec bit) is the protection.
    Ok(())
}

#[cfg(windows)]
fn hide_on_windows(path: &Path) {
    // Best effort; absolute path so no PATH/app-dir hijacking is possible.
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let attrib = Path::new(&root).join("System32").join("attrib.exe");
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = std::process::Command::new(attrib)
        .arg("+h")
        .arg(path)
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: String) -> ItemMeta {
        ItemMeta {
            id,
            url: "https://example.com/a".into(),
            final_url: None,
            etag: None,
            last_modified: None,
            total_size: None,
            expected_sha256: None,
            sha256: None,
            file_name: "a".into(),
            name_warnings: vec![],
            state: ItemState::Downloading,
            verdict: None,
            created_at: 1,
        }
    }

    #[test]
    fn ids_are_validated() {
        assert!(valid_id(&"a".repeat(32)));
        for bad in [
            "../../etc/passwd",
            "",
            "A".repeat(32).as_str(),
            &"a".repeat(31),
            "../aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(!valid_id(bad), "{bad}");
        }
        let d = tempfile::tempdir().unwrap();
        let q = Quarantine::open(d.path().join("q")).unwrap();
        assert!(q.data_path("../x").is_err());
        assert!(q.remove("../../x").is_err());
    }

    #[test]
    fn items_are_private_and_random() {
        let d = tempfile::tempdir().unwrap();
        let q = Quarantine::open(d.path().join("q")).unwrap();
        let a = q.create_item(meta).unwrap();
        let b = q.create_item(meta).unwrap();
        assert_ne!(a.id, b.id);
        let p = q.data_path(&a.id).unwrap();
        assert_eq!(p.extension().unwrap(), "quarantine");
        assert!(q.mark_untrusted(&a.id, "https://example.com/").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(q.root()).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(q.list().len(), 2);
        q.remove(&a.id).unwrap();
        assert_eq!(q.list().len(), 1);
        assert!(!p.exists());
    }
}
