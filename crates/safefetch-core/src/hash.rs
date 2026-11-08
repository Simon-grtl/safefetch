//! Streaming SHA-256 (constant memory, any file size).

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

const BUF: usize = 1 << 20;

/// Hash a file; `progress(bytes_done)` is called after every chunk.
pub fn sha256_file(path: &Path, mut progress: impl FnMut(u64)) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; BUF];
    let mut done = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        done += n as u64;
        progress(done);
    }
    Ok(hex::encode(h.finalize()))
}

pub fn sha256_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Constant-time-ish comparison of two lowercase hex digests.
pub fn digests_equal(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| {
            acc | (x.to_ascii_lowercase() ^ y.to_ascii_lowercase())
        }) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, b"").unwrap();
        assert_eq!(
            sha256_file(&p, |_| {}).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(
            sha256_file(&p, |_| {}).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Multi-chunk file equals in-memory hash.
        let data: Vec<u8> = (0..(3 * BUF + 17)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &data).unwrap();
        let mut calls = 0;
        assert_eq!(
            sha256_file(&p, |_| calls += 1).unwrap(),
            sha256_bytes(&data)
        );
        assert_eq!(calls, 4);
    }

    #[test]
    fn digest_compare() {
        assert!(digests_equal("abCD", "ABcd"));
        assert!(!digests_equal("abcd", "abce"));
        assert!(!digests_equal("abc", "abcd"));
    }
}
