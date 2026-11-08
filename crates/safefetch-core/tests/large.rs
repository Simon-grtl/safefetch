//! Large-file test (≈3 GiB written to a temp dir). Ignored by default:
//! `cargo test --release -p safefetch-core --test large -- --ignored`
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::*;
use safefetch_core::engine::Outcome;
use safefetch_core::verdict::VerdictLevel;

fn rss_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find(|l| l.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn three_gib_file_streams_with_constant_memory_and_is_never_clean() {
    const SIZE: u64 = 3 * 1024 * 1024 * 1024;
    let srv = RawServer::start(Arc::new(|_req: &Req, _n| Resp {
        status: 200,
        headers: vec![],
        body: Body::Zeros(SIZE),
        cut_after: None,
        content_length: None,
    }))
    .await;
    let e = env(EnvOptions::default());
    let before = rss_kib();
    let r = e.engine.submit(&srv.url("/huge.iso"));
    let id = r.added[0];
    let mut peak = 0;
    loop {
        if let Some(rss) = rss_kib() {
            peak = peak.max(rss);
        }
        let j = e.engine.job(id).unwrap();
        if j.outcome.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let j = e.wait(id).await;
    assert_eq!(j.downloaded, SIZE);
    // > 2 GiB: ClamAV cannot scan it, so the file must stay in quarantine.
    assert_eq!(j.outcome, Some(Outcome::Quarantined), "{j:#?}");
    assert_eq!(j.verdict.unwrap().level, VerdictLevel::NotAnalyzed);
    if let (Some(b), true) = (before, peak > 0) {
        let growth_mib = peak.saturating_sub(b) / 1024;
        eprintln!("RSS growth during 3 GiB download: {growth_mib} MiB");
        assert!(growth_mib < 200, "memory grew by {growth_mib} MiB");
    }
}
