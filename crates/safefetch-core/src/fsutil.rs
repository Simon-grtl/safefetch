//! Small file-system helpers with restrictive permissions.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::error::Result;

/// Create a directory (and parents) readable only by the current user on Unix.
pub fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Open options for a new private file: 0600 on Unix (never executable).
pub fn private_file_options() -> OpenOptions {
    #[allow(unused_mut)] // only mutated on Unix
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// Ensure a file has no execute bit and is private (Unix); no-op elsewhere.
pub fn set_private_non_exec(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let _ = path;
    Ok(())
}

/// Readable by others but never executable (used for delivered files).
pub fn set_delivered_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    }
    let _ = path;
    Ok(())
}

/// Write a file atomically: temp file in the same directory, fsync, rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent directory"))?;
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        random_hex(6)
    ));
    {
        let mut f: File = private_file_options()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Cryptographically random hex string of `bytes` random bytes.
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    // getrandom only fails if the OS RNG is unavailable; fall back to a
    // time-based value rather than panicking (names need uniqueness, the
    // security relevance is low because files are created with create_new).
    if getrandom::fill(&mut buf).is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (t >> ((i % 16) * 8)) as u8;
        }
    }
    hex::encode(buf)
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Never flash a console window when the GUI app starts a console program
/// (clamscan, freshclam, MpCmdRun) on Windows.
pub fn no_console_window(cmd: &mut tokio::process::Command) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let _ = cmd;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_and_private_perms() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.json");
        write_atomic(&p, b"hello").unwrap();
        write_atomic(&p, b"world").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"world");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // No temp files left behind.
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn random_hex_is_random() {
        let a = random_hex(16);
        assert_eq!(a.len(), 32);
        assert_ne!(a, random_hex(16));
    }
}
