//! Delivery of a clean file to the destination folder.
//!
//! Atomic and no-clobber: the file is hard-linked to its final name (which
//! fails atomically if the name exists — unlike `rename`, which silently
//! replaces on Unix), then the quarantine name is removed. Both names are on
//! the same volume, so no data is copied. If the volume does not support
//! hard links (FAT/exFAT), `rename` is used after an existence check
//! (a small race window that is documented).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::fsutil;

/// "name.ext" → "name (n).ext"
pub fn numbered_name(name: &str, n: u32) -> String {
    if n == 0 {
        return name.to_string();
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} ({n}).{ext}"),
        _ => format!("{name} ({n})"),
    }
}

/// Move `src` (in quarantine) to `dest_dir/name`, never overwriting.
/// `name` must already be sanitized. Returns the final path.
pub fn deliver(src: &Path, dest_dir: &Path, name: &str) -> Result<PathBuf> {
    if name.contains(['/', '\\']) || name.is_empty() || name.starts_with('.') {
        return Err(Error::Policy("unsafe delivery name".into()));
    }
    let dest_dir = dunce::canonicalize(dest_dir)?;
    for n in 0..1000u32 {
        let target = dest_dir.join(numbered_name(name, n));
        // Defense in depth: the target must be a direct child of dest_dir.
        if target.parent() != Some(dest_dir.as_path()) {
            return Err(Error::Policy(
                "delivery path escapes the destination".into(),
            ));
        }
        match fs::hard_link(src, &target) {
            Ok(()) => {
                fs::remove_file(src)?;
                fsutil::set_delivered_permissions(&target)?;
                sync_dir(&dest_dir);
                return Ok(target);
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::Unsupported | ErrorKind::PermissionDenied
                ) || e.raw_os_error() == Some(1) =>
            {
                // Hard links not supported here: rename with an existence check.
                if target.exists() || target.symlink_metadata().is_ok() {
                    continue;
                }
                fs::rename(src, &target)?;
                fsutil::set_delivered_permissions(&target)?;
                sync_dir(&dest_dir);
                return Ok(target);
            }
            Err(e) if is_cross_device(&e) => {
                return Err(Error::Policy(
                    "quarantine and destination are on different volumes".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::Internal(
        "too many files with the same name in the destination".into(),
    ))
}

fn is_cross_device(e: &std::io::Error) -> bool {
    // EXDEV (18) on Linux/macOS, ERROR_NOT_SAME_DEVICE (17) on Windows.
    if cfg!(windows) {
        e.raw_os_error() == Some(17)
    } else {
        e.raw_os_error() == Some(18) || e.kind() == ErrorKind::CrossesDevices
    }
}

fn sync_dir(_dir: &Path) {
    #[cfg(unix)]
    if let Ok(f) = fs::File::open(_dir) {
        let _ = f.sync_all();
    }
}

/// On Unix, check that two paths are on the same device.
pub fn same_volume(a: &Path, b: &Path) -> Option<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (ma, mb) = (fs::metadata(a).ok()?, fs::metadata(b).ok()?);
        Some(ma.dev() == mb.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbering() {
        assert_eq!(numbered_name("a.zip", 0), "a.zip");
        assert_eq!(numbered_name("a.tar.gz", 2), "a.tar (2).gz");
        assert_eq!(numbered_name("README", 1), "README (1)");
    }

    #[test]
    fn delivers_without_overwriting() {
        let d = tempfile::tempdir().unwrap();
        let dest = d.path().join("dest");
        let q = dest.join(".q");
        fs::create_dir_all(&q).unwrap();
        fs::write(dest.join("file.txt"), b"existing").unwrap();
        let src = q.join("x.quarantine");
        fs::write(&src, b"new").unwrap();
        let out = deliver(&src, &dest, "file.txt").unwrap();
        assert_eq!(out.file_name().unwrap(), "file (1).txt");
        assert_eq!(fs::read(dest.join("file.txt")).unwrap(), b"existing");
        assert_eq!(fs::read(&out).unwrap(), b"new");
        assert!(!src.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&out).unwrap().permissions().mode() & 0o111,
                0,
                "never executable"
            );
        }
    }

    #[test]
    fn refuses_unsafe_names() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("s");
        fs::write(&src, b"x").unwrap();
        for bad in ["../x", "a/b", "a\\b", "", ".hidden"] {
            assert!(deliver(&src, d.path(), bad).is_err(), "{bad}");
        }
        assert!(src.exists());
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_planted_symlink() {
        // An attacker-planted symlink with the target name must not be followed/overwritten.
        let d = tempfile::tempdir().unwrap();
        let dest = d.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        let victim = d.path().join("victim");
        fs::write(&victim, b"precious").unwrap();
        std::os::unix::fs::symlink(&victim, dest.join("file.txt")).unwrap();
        let src = dest.join("s.quarantine");
        fs::write(&src, b"new").unwrap();
        let out = deliver(&src, &dest, "file.txt").unwrap();
        assert_eq!(out.file_name().unwrap(), "file (1).txt");
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
    }
}
