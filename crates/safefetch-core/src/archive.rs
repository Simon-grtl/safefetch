//! Structural check of ZIP files, independent of ClamAV.
//!
//! The security audit showed that ZIPs whose local headers disagree with the
//! central directory (method, sizes, "masked" flag…) make ClamAV skip the
//! member silently, while other unzip tools still extract it. A ZIP is only
//! considered scannable if every central-directory entry has a matching,
//! plain local header. Only reads headers (the file is never extracted).
//!
//! Limitation: only the top-level ZIP is checked; a malformed ZIP nested in a
//! valid one relies on ClamAV's own debug markers (see clamav.rs).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const EOCD_SIG: &[u8] = b"PK\x05\x06";
const CDH_SIG: &[u8] = b"PK\x01\x02";
const LFH_SIG: &[u8] = b"PK\x03\x04";
const MAX_CD: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 200_000;
/// Compression methods libclamav decompresses: stored, deflate, deflate64, bzip2.
const SUPPORTED_METHODS: &[u16] = &[0, 8, 9, 12];

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Position of the End Of Central Directory record, if the file ends like a ZIP.
pub fn find_eocd(f: &mut File, len: u64) -> std::io::Result<Option<(u64, Vec<u8>)>> {
    let tail_len = len.min(22 + 65_535);
    f.seek(SeekFrom::Start(len - tail_len))?;
    let mut tail = vec![0u8; tail_len as usize];
    f.read_exact(&mut tail)?;
    let mut i = tail.len().saturating_sub(22) as isize;
    while i >= 0 {
        let p = i as usize;
        if &tail[p..p + 4] == EOCD_SIG {
            let comment = usize::from(u16le(&tail, p + 20));
            if p + 22 + comment == tail.len() {
                return Ok(Some((len - tail_len + p as u64, tail[p..p + 22].to_vec())));
            }
        }
        i -= 1;
    }
    Ok(None)
}

/// `None` = not a ZIP, or a consistent ZIP. `Some(reason)` = a ZIP that
/// ClamAV may not fully scan.
pub fn zip_problem(path: &Path) -> Option<String> {
    check(path).unwrap_or_else(|e| Some(format!("unreadable archive structure: {e}")))
}

fn check(path: &Path) -> std::io::Result<Option<String>> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    if len < 22 {
        return Ok(None);
    }
    let mut head = [0u8; 4];
    f.read_exact(&mut head)?;
    let starts_zip = head == *LFH_SIG;
    let Some((eocd_pos, eocd)) = find_eocd(&mut f, len)? else {
        return Ok(starts_zip.then(|| "ZIP without a central directory".to_string()));
    };
    let total = u16le(&eocd, 10);
    let cd_size = u32le(&eocd, 12);
    let cd_off = u32le(&eocd, 16);
    if total == 0xffff || cd_size == 0xffff_ffff || cd_off == 0xffff_ffff {
        return Ok(Some("ZIP64 archive: structure cannot be verified".into()));
    }
    if u16le(&eocd, 4) != 0 || u16le(&eocd, 6) != 0 {
        return Ok(Some("multi-disk ZIP".into()));
    }
    let (cd_size, cd_off) = (u64::from(cd_size), u64::from(cd_off));
    // Bytes prepended to the archive (self-extractors).
    let Some(base) = eocd_pos.checked_sub(cd_size + cd_off) else {
        return Ok(Some("inconsistent central directory position".into()));
    };
    if cd_size > MAX_CD {
        return Ok(Some("central directory too large to verify".into()));
    }
    let cd_start = base + cd_off;
    f.seek(SeekFrom::Start(cd_start))?;
    let mut cd = vec![0u8; cd_size as usize];
    f.read_exact(&mut cd)?;

    let mut p = 0usize;
    let mut count = 0usize;
    while p + 46 <= cd.len() {
        if &cd[p..p + 4] != CDH_SIG {
            return Ok(Some("corrupt central directory".into()));
        }
        count += 1;
        if count > MAX_ENTRIES {
            return Ok(Some("too many entries to verify".into()));
        }
        let flags = u16le(&cd, p + 8);
        let method = u16le(&cd, p + 10);
        let crc = u32le(&cd, p + 16);
        let csize = u32le(&cd, p + 20);
        let usize_ = u32le(&cd, p + 24);
        let nlen = usize::from(u16le(&cd, p + 28));
        let elen = usize::from(u16le(&cd, p + 30));
        let clen = usize::from(u16le(&cd, p + 32));
        let lofs = u64::from(u32le(&cd, p + 42));
        if p + 46 + nlen > cd.len() {
            return Ok(Some("corrupt central directory".into()));
        }
        let name = cd[p + 46..p + 46 + nlen].to_vec();
        let shown = String::from_utf8_lossy(&name)
            .chars()
            .take(60)
            .collect::<String>();
        if flags & 0x0001 != 0 {
            return Ok(Some(format!("encrypted entry \"{shown}\"")));
        }
        if flags & 0x2000 != 0 {
            return Ok(Some(format!("entry \"{shown}\" uses masked headers")));
        }
        if !SUPPORTED_METHODS.contains(&method) {
            return Ok(Some(format!(
                "entry \"{shown}\" uses compression method {method} that ClamAV cannot unpack"
            )));
        }
        if csize == 0xffff_ffff || usize_ == 0xffff_ffff || lofs == 0xffff_ffff {
            return Ok(Some(format!("entry \"{shown}\" uses ZIP64 fields")));
        }

        // Matching local header.
        let lpos = base + lofs;
        if lpos + 30 > cd_start {
            return Ok(Some(format!(
                "entry \"{shown}\" points outside the archive"
            )));
        }
        f.seek(SeekFrom::Start(lpos))?;
        let mut lh = [0u8; 30];
        f.read_exact(&mut lh)?;
        if lh[..4] != *LFH_SIG {
            return Ok(Some(format!("entry \"{shown}\" has no local header")));
        }
        let lflags = u16le(&lh, 6);
        let lmethod = u16le(&lh, 8);
        let lcrc = u32le(&lh, 14);
        let lcsize = u32le(&lh, 18);
        let lusize = u32le(&lh, 22);
        let lnlen = usize::from(u16le(&lh, 26));
        let lelen = u64::from(u16le(&lh, 28));
        let mut lname = vec![0u8; lnlen];
        f.read_exact(&mut lname)?;
        let descriptor = flags & 0x0008 != 0;
        let sizes_ok = descriptor && lcsize == 0 && lusize == 0 && lcrc == 0
            || (lcrc == crc && lcsize == csize && lusize == usize_);
        if lflags != flags || lmethod != method || lname != name || !sizes_ok {
            return Ok(Some(format!(
                "entry \"{shown}\": local header disagrees with the central directory"
            )));
        }
        if lpos + 30 + lnlen as u64 + lelen + u64::from(csize) > cd_start {
            return Ok(Some(format!(
                "entry \"{shown}\" overlaps the central directory"
            )));
        }
        p += 46 + nlen + elen + clen;
    }
    if count != usize::from(total) {
        return Ok(Some(
            "entry count does not match the central directory".into(),
        ));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eicar_zip() -> Vec<u8> {
        // Minimal stored ZIP built by hand (no extra fields).
        let data = b"hello";
        let crc = 0x3610_a686u32; // crc32("hello")
        let name = b"a.txt";
        let mut z = Vec::new();
        z.extend_from_slice(LFH_SIG);
        z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&5u32.to_le_bytes());
        z.extend_from_slice(&5u32.to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(name);
        z.extend_from_slice(data);
        let cd_off = z.len() as u32;
        z.extend_from_slice(CDH_SIG);
        z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&5u32.to_le_bytes());
        z.extend_from_slice(&5u32.to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&[0u8; 12]); // extra, comment, disk, int attr, ext attr (4)
        z.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        z.extend_from_slice(name);
        let cd_size = z.len() as u32 - cd_off;
        z.extend_from_slice(EOCD_SIG);
        z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        z.extend_from_slice(&cd_size.to_le_bytes());
        z.extend_from_slice(&cd_off.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z
    }

    type Mutation = Box<dyn Fn(&mut Vec<u8>)>;

    fn write(d: &tempfile::TempDir, name: &str, b: &[u8]) -> std::path::PathBuf {
        let p = d.path().join(name);
        std::fs::write(&p, b).unwrap();
        p
    }

    #[test]
    fn consistent_zip_passes_and_non_zip_is_ignored() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(zip_problem(&write(&d, "ok.zip", &eicar_zip())), None);
        assert_eq!(
            zip_problem(&write(
                &d,
                "t.txt",
                b"just some text, long enough to matter"
            )),
            None
        );
        // Self-extractor style prefix is accepted when consistent.
        let mut sfx = b"#!/bin/sh\necho hi\n".to_vec();
        sfx.extend(eicar_zip());
        // Offsets in the archive are relative to its own start: still consistent.
        assert_eq!(zip_problem(&write(&d, "sfx.zip", &sfx)), None);
    }

    #[test]
    fn audit_evasion_variants_are_flagged() {
        let d = tempfile::tempdir().unwrap();
        let base = eicar_zip();
        let variants: Vec<(&str, Mutation)> = vec![
            ("masked flag", Box::new(|z| z[7] |= 0x20)),
            ("local method 8", Box::new(|z| z[8] = 8)),
            (
                "local csize 0",
                Box::new(|z| z[18..22].copy_from_slice(&0u32.to_le_bytes())),
            ),
            (
                "local csize 1",
                Box::new(|z| z[18..22].copy_from_slice(&1u32.to_le_bytes())),
            ),
            (
                "lzma both",
                Box::new(|z| {
                    z[8] = 14;
                    let c = z.windows(4).position(|w| w == CDH_SIG).unwrap();
                    z[c + 10] = 14;
                }),
            ),
            (
                "zip64 sizes",
                Box::new(|z| {
                    let c = z.windows(4).position(|w| w == CDH_SIG).unwrap();
                    z[c + 20..c + 24].copy_from_slice(&u32::MAX.to_le_bytes());
                }),
            ),
            (
                "encrypted",
                Box::new(|z| {
                    z[6] |= 1;
                    let c = z.windows(4).position(|w| w == CDH_SIG).unwrap();
                    z[c + 8] |= 1;
                }),
            ),
        ];
        for (what, f) in variants {
            let mut z = base.clone();
            f(&mut z);
            assert!(zip_problem(&write(&d, "v.zip", &z)).is_some(), "{what}");
        }
        // Truncated archive (no central directory).
        assert!(zip_problem(&write(&d, "trunc.zip", &base[..30])).is_some());
    }
}
