//! clamd integration (runs when SAFEFETCH_CLAMD_CONF points to a clamd.conf of a
//! running clamd loaded with the test signature; CI starts one).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;

use safefetch_core::scanners::clamav::{self, Backend};
use safefetch_core::settings::{ClamAvMode, ClamAvSettings};
use safefetch_core::verdict::EngineResult;

fn settings() -> Option<ClamAvSettings> {
    let conf = std::env::var_os("SAFEFETCH_CLAMD_CONF")?;
    Some(ClamAvSettings {
        mode: ClamAvMode::ClamdOnly,
        clamd_conf_path: Some(conf.into()),
        ..Default::default()
    })
}

#[tokio::test]
async fn clamd_instream_detects_and_passes() {
    let Some(s) = settings() else {
        eprintln!("SKIPPED: SAFEFETCH_CLAMD_CONF not set");
        return;
    };
    assert!(
        matches!(clamav::choose_backend(&s, 100), Backend::Clamd { .. }),
        "{:?}",
        clamav::choose_backend(&s, 100)
    );
    let d = tempfile::tempdir().unwrap();
    let bad = d.path().join("a.quarantine");
    std::fs::write(&bad, common::EICAR).unwrap();
    assert!(matches!(
        clamav::scan(&s, &bad).await,
        EngineResult::Infected(_)
    ));
    let good = d.path().join("b.quarantine");
    std::fs::File::create(&good)
        .unwrap()
        .write_all(&vec![3u8; 5 * 1024 * 1024])
        .unwrap();
    assert_eq!(clamav::scan(&s, &good).await, EngineResult::Clean);
}

#[tokio::test]
async fn insufficient_clamd_conf_is_not_used() {
    let d = tempfile::tempdir().unwrap();
    let conf = d.path().join("clamd.conf");
    std::fs::write(&conf, "LocalSocket /nonexistent.sock\nMaxFileSize 100M\n").unwrap();
    let s = ClamAvSettings {
        mode: ClamAvMode::ClamdOnly,
        clamd_conf_path: Some(conf),
        ..Default::default()
    };
    assert!(matches!(clamav::choose_backend(&s, 10), Backend::None(_)));
    let f = d.path().join("f");
    std::fs::write(&f, b"x").unwrap();
    assert!(matches!(
        clamav::scan(&s, &f).await,
        EngineResult::Unavailable(_)
    ));
}
