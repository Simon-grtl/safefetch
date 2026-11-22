//! Runs only with the official ClamAV database (`SAFEFETCH_CLAMAV_DB`, set by
//! the CI job "official ClamAV database"); skipped otherwise.
//!
//! Closes residual risk 2 of SECURITY_AUDIT.md: clamscan always runs with
//! `--debug`, and its stderr is searched for truncation markers. With the
//! full database, libclamav prints far more debug output while loading
//! ~8 million signatures: none of it may turn an ordinary, complete scan into
//! "Not analyzed", and detections must still work.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::time::Instant;

use common::*;
use safefetch_core::engine::Outcome;
use safefetch_core::verdict::{EngineResult, VerdictLevel};

macro_rules! require_official_db {
    () => {
        if official_db().is_none() {
            eprintln!("SKIPPED: SAFEFETCH_CLAMAV_DB not set");
            return;
        }
        assert!(find_clamscan().is_some(), "clamscan is required");
    };
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cur = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut cur);
        for (name, data) in entries {
            z.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(data).unwrap();
        }
        z.finish().unwrap();
    }
    cur.into_inner()
}

/// Ordinary files of several kinds, each must be Clean (complete scan).
fn benign_samples() -> Vec<(&'static str, Vec<u8>)> {
    let png = [
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, b'I', b'H', b'D', b'R', 0,
        0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89, 0, 0, 0, 0, b'I', b'E', b'N',
        b'D', 0xae, 0x42, 0x60, 0x82,
    ]
    .to_vec();
    let pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n".to_vec();
    let text = "Lorem ipsum dolor sit amet.\n".repeat(2000).into_bytes();
    let zip = zip_of(&[
        ("readme.txt", b"hello from inside a zip"),
        ("data/table.csv", b"a,b,c\n1,2,3\n"),
    ]);
    let nested = zip_of(&[("inner.zip", &zip), ("notes.txt", b"nested")]);
    let mut v = vec![
        ("notes.txt", text),
        ("pixel.png", png),
        ("doc.pdf", pdf),
        ("bundle.zip", zip),
        ("nested.zip", nested),
    ];
    // A real program (the CI job runs on Linux). Not this test binary: it
    // embeds stray ZIP header bytes, which ClamAV reports as "unusable masked
    // data" and SafeFetch therefore, on purpose, as Not analyzed.
    if let Ok(exe) = std::fs::read("/usr/bin/ls") {
        v.push(("ls", exe));
    }
    v
}

#[tokio::test(flavor = "multi_thread")]
async fn official_db_keeps_ordinary_files_clean() {
    require_official_db!();
    let e = env(EnvOptions::default());
    let src = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    for (name, data) in benign_samples() {
        let p = src.path().join(name);
        std::fs::write(&p, data).unwrap();
        paths.push(p);
    }
    let n = paths.len();
    let started = Instant::now();
    let r = e.engine.submit_local(paths);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    for id in r.added {
        let j = e.wait(id).await;
        let v = j.verdict.clone().unwrap();
        assert!(
            matches!(v.report.clamav, EngineResult::Clean),
            "{}: ClamAV result {:?} — reasons {:?}",
            j.file_name,
            v.report.clamav,
            v.reasons
        );
        assert_eq!(
            v.level,
            VerdictLevel::Clean,
            "{}: {:?}",
            j.file_name,
            v.reasons
        );
    }
    eprintln!(
        "official database: {} files scanned in {:.1} s (signatures loaded once per file)",
        n,
        started.elapsed().as_secs_f64()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn official_db_detects_eicar_plain_and_in_archives() {
    require_official_db!();
    let e = env(EnvOptions::default());
    let src = tempfile::tempdir().unwrap();
    let samples = [
        ("eicar.com", EICAR.to_vec()),
        ("eicar.zip", zip_of(&[("eicar.com", EICAR)])),
        (
            "nested.zip",
            zip_of(&[("inner.zip", &zip_of(&[("x/eicar.com", EICAR)]))]),
        ),
    ];
    let mut paths = Vec::new();
    for (name, data) in &samples {
        let p = src.path().join(name);
        std::fs::write(&p, data).unwrap();
        paths.push(p);
    }
    let r = e.engine.submit_local(paths);
    for id in r.added {
        let j = e.wait(id).await;
        assert!(matches!(j.outcome, Some(Outcome::Analyzed { .. })));
        let v = j.verdict.unwrap();
        assert_eq!(
            v.level,
            VerdictLevel::Dangerous,
            "{}: {:?}",
            j.file_name,
            v.reasons
        );
    }
}
