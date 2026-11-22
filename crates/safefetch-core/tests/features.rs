//! End-to-end tests of the v0.2 features: local file analysis, publisher
//! checksum lists, real type vs. extension, weekly re-check of delivered files.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::*;
use safefetch_core::checksums::ChecksumListResult;
use safefetch_core::engine::Outcome;
use safefetch_core::hash::sha256_bytes;
use safefetch_core::verdict::VerdictLevel;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

type StaticFile = (&'static str, Vec<u8>, Vec<(&'static str, &'static str)>);

fn static_server(files: Vec<StaticFile>) -> Handler {
    Arc::new(move |req: &Req, _n| {
        for (p, data, headers) in &files {
            if req.path == *p {
                let mut r = range_response(data, req);
                for (k, v) in headers {
                    r = r.header(k, v);
                }
                return r;
            }
        }
        Resp::ok(b"not found".to_vec()).status(404)
    })
}

async fn wait_local(e: &Env, paths: Vec<std::path::PathBuf>) -> Vec<safefetch_core::JobSnapshot> {
    let r = e.engine.submit_local(paths);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let mut out = Vec::new();
    for id in r.added {
        out.push(e.wait(id).await);
    }
    out
}

// ------------------------------------------------------------ local files --

#[tokio::test(flavor = "multi_thread")]
async fn local_files_are_analyzed_in_place_and_never_touched() {
    require_clamav!();
    let e = env(EnvOptions::default());
    let src = tempfile::tempdir().unwrap();
    let clean = src.path().join("notes.txt");
    let bad = src.path().join("eicar.com");
    std::fs::write(&clean, b"just some notes").unwrap();
    std::fs::write(&bad, EICAR).unwrap();

    let jobs = wait_local(&e, vec![clean.clone(), bad.clone()]).await;
    let (jc, jb) = (&jobs[0], &jobs[1]);
    assert!(jc.local);
    assert!(
        matches!(&jc.outcome, Some(Outcome::Analyzed { path }) if path.ends_with("notes.txt")),
        "{jc:#?}"
    );
    assert_eq!(jc.verdict.as_ref().unwrap().level, VerdictLevel::Clean);
    assert_eq!(
        jc.verdict.as_ref().unwrap().report.sha256,
        sha256_bytes(b"just some notes")
    );
    assert_eq!(jb.verdict.as_ref().unwrap().level, VerdictLevel::Dangerous);
    assert!(matches!(jb.outcome, Some(Outcome::Analyzed { .. })));

    // Never moved, copied, modified or deleted — even the dangerous one.
    assert_eq!(std::fs::read(&clean).unwrap(), b"just some notes");
    assert_eq!(std::fs::read(&bad).unwrap(), EICAR);
    assert!(e.dest_files().is_empty(), "{:?}", e.dest_files());
    assert!(e.quarantine_files().is_empty());
    assert_eq!(
        e.engine.local_path(jb.id).unwrap(),
        dunce::canonicalize(&bad).unwrap()
    );

    // Re-scan is available for analyzed files; release/upload are not.
    e.engine.rescan(jc.id).unwrap();
    let again = e.wait(jc.id).await;
    assert_eq!(again.verdict.unwrap().level, VerdictLevel::Clean);
    assert!(e.engine.release(jc.id).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn folders_and_missing_files_are_refused() {
    let e = env(EnvOptions::default());
    let src = tempfile::tempdir().unwrap();
    let r = e
        .engine
        .submit_local(vec![src.path().to_path_buf(), src.path().join("nope.bin")]);
    assert!(r.added.is_empty());
    assert_eq!(r.errors.len(), 2);
    assert!(r.errors[0].contains("folders"), "{:?}", r.errors);
}

#[tokio::test(flavor = "multi_thread")]
async fn local_program_disguised_as_pdf_is_suspect() {
    require_clamav!();
    let e = env(EnvOptions::default());
    let src = tempfile::tempdir().unwrap();
    let f = src.path().join("facture.pdf");
    let mut pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff".to_vec();
    pe.resize(512, 0);
    std::fs::write(&f, &pe).unwrap();
    let j = &wait_local(&e, vec![f]).await[0];
    let v = j.verdict.as_ref().unwrap();
    assert_eq!(v.level, VerdictLevel::Suspect, "{:?}", v.reasons);
    assert!(v.report.type_mismatch.as_ref().unwrap().disguised_program);
    assert!(v.reasons.iter().any(|r| r.contains("Windows program")));
}

// ------------------------------------------------- downloads: file type --

#[tokio::test(flavor = "multi_thread")]
async fn downloaded_program_disguised_as_document_stays_in_quarantine() {
    require_clamav!();
    let mut pe = b"MZ\x90\x00".to_vec();
    pe.resize(1024, 0);
    let srv = RawServer::start(static_server(vec![(
        "/dl",
        pe,
        vec![(
            "Content-Disposition",
            "attachment; filename=\"invoice.pdf\"",
        )],
    )]))
    .await;
    let e = env(EnvOptions::default());
    let j = e.run(&srv.url("/dl")).await;
    assert_eq!(j.outcome, Some(Outcome::Quarantined), "{j:#?}");
    assert_eq!(j.verdict.unwrap().level, VerdictLevel::Suspect);
    assert!(e.dest_files().is_empty());
}

// ------------------------------------------------------- checksum lists --

const ISO: &[u8] = b"pretend this is a large ISO image";

fn sums_server(sums: &str) -> Handler {
    static_server(vec![
        ("/pub/distro-1.0.iso", ISO.to_vec(), vec![]),
        ("/pub/SHA256SUMS", sums.as_bytes().to_vec(), vec![]),
    ])
}

#[tokio::test(flavor = "multi_thread")]
async fn checksum_list_match_is_verified() {
    require_clamav!();
    let sums = format!(
        "{}  other.iso\n{}  distro-1.0.iso\n",
        "0".repeat(64),
        sha256_bytes(ISO)
    );
    let srv = RawServer::start(sums_server(&sums)).await;
    let e = env(EnvOptions::default());
    let j = e
        .run(&format!(
            "{} {}",
            srv.url("/pub/distro-1.0.iso"),
            srv.url("/pub/SHA256SUMS")
        ))
        .await;
    let v = j.verdict.clone().unwrap();
    assert_eq!(v.level, VerdictLevel::Clean, "{:?}", v.reasons);
    assert!(matches!(
        v.report.checksum_list,
        Some(ChecksumListResult::Found { ref entry, .. }) if entry == "distro-1.0.iso"
    ));
    assert_eq!(
        j.expected_sha256.as_deref(),
        Some(sha256_bytes(ISO).as_str())
    );
    assert!(matches!(j.outcome, Some(Outcome::Delivered { .. })));
}

#[tokio::test(flavor = "multi_thread")]
async fn checksum_list_mismatch_missing_entry_and_unreachable_list() {
    require_clamav!();
    // Wrong hash for the file ⇒ Suspect.
    let srv = RawServer::start(sums_server(&format!(
        "{}  distro-1.0.iso\n",
        "a".repeat(64)
    )))
    .await;
    let e = env(EnvOptions::default());
    let line = format!(
        "{} {}",
        srv.url("/pub/distro-1.0.iso"),
        srv.url("/pub/SHA256SUMS")
    );
    let j = e.run(&line).await;
    assert_eq!(j.verdict.unwrap().level, VerdictLevel::Suspect);

    // File not listed ⇒ Suspect.
    let srv = RawServer::start(sums_server(&format!("{}  other.iso\n", "a".repeat(64)))).await;
    let e = env(EnvOptions::default());
    let line = format!(
        "{} {}",
        srv.url("/pub/distro-1.0.iso"),
        srv.url("/pub/SHA256SUMS")
    );
    let j = e.run(&line).await;
    let v = j.verdict.unwrap();
    assert_eq!(v.level, VerdictLevel::Suspect);
    assert!(matches!(
        v.report.checksum_list,
        Some(ChecksumListResult::NotListed { .. })
    ));

    // List unreachable (404) ⇒ Not analyzed, never Clean.
    let srv = RawServer::start(sums_server("")).await;
    let e = env(EnvOptions::default());
    let line = format!(
        "{} {}",
        srv.url("/pub/distro-1.0.iso"),
        srv.url("/pub/MISSING")
    );
    let j = e.run(&line).await;
    let v = j.verdict.unwrap();
    assert_eq!(v.level, VerdictLevel::NotAnalyzed, "{:?}", v.reasons);
    assert!(matches!(
        v.report.checksum_list,
        Some(ChecksumListResult::Unavailable { .. })
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_checksum_list_is_refused() {
    require_clamav!();
    let huge = "x".repeat(2 * 1024 * 1024);
    let srv = RawServer::start(sums_server(&huge)).await;
    let e = env(EnvOptions::default());
    let j = e
        .run(&format!(
            "{} {}",
            srv.url("/pub/distro-1.0.iso"),
            srv.url("/pub/SHA256SUMS")
        ))
        .await;
    let v = j.verdict.unwrap();
    assert_eq!(v.level, VerdictLevel::NotAnalyzed);
    assert!(
        v.reasons.iter().any(|r| r.contains("too large")),
        "{:?}",
        v.reasons
    );
}

// ------------------------------------------------------- weekly re-check --

async fn mount_file_stats(s: &MockServer, malicious: u32) {
    s.reset().await;
    let body = serde_json::json!({"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "harmless": 10, "undetected": 50},
        "last_analysis_results": {"Engine1": {"category": if malicious > 0 {"malicious"} else {"harmless"}, "result": "Trojan.Late"}}
    }}});
    Mock::given(method("GET"))
        .and(path_regex("^/api/v3/files/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(s)
        .await;
    for p in ["^/api/v3/urls/", "^/api/v3/domains/"] {
        Mock::given(method("GET"))
            .and(path_regex(p))
            .respond_with(ResponseTemplate::new(404))
            .mount(s)
            .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn weekly_recheck_alerts_on_files_flagged_after_delivery() {
    require_clamav!();
    let vt = MockServer::start().await;
    mount_file_stats(&vt, 0).await;
    let srv = RawServer::start(static_server(vec![
        ("/a.bin", b"first delivered file".to_vec(), vec![]),
        ("/b.bin", b"second delivered file".to_vec(), vec![]),
    ]))
    .await;
    let e = env(EnvOptions {
        vt_base: Some(format!("{}/api/v3/", vt.uri())),
        vt_key: true,
        ..Default::default()
    });
    for p in ["/a.bin", "/b.bin"] {
        let j = e.run(&srv.url(p)).await;
        assert!(
            matches!(j.outcome, Some(Outcome::Delivered { .. })),
            "{j:#?}"
        );
    }

    // A week later, VirusTotal now flags the content.
    mount_file_stats(&vt, 7).await;
    let r = e.engine.recheck_now().await.unwrap();
    assert_eq!(r.checked, 2);
    assert_eq!(r.new_alerts, 2);
    let st = e.engine.recheck_status();
    assert_eq!(st.alerts.len(), 2);
    let a = &st.alerts[0];
    assert_eq!(a.level, VerdictLevel::Dangerous);
    assert!(a.delivered_path.is_file());
    assert!(a.detections[0].contains("Trojan.Late"));
    // Hash lookups only: no upload, no URL lookup during the re-check.
    let reqs = vt.received_requests().await.unwrap();
    assert!(reqs
        .iter()
        .all(|r| r.method.as_str() == "GET" && r.url.path().starts_with("/api/v3/files/")));
    // Delivered files are never deleted by the re-check.
    assert_eq!(e.dest_files(), vec!["a.bin", "b.bin"]);

    // Checked this week: a second run does not query again.
    let r = e.engine.recheck_now().await.unwrap();
    assert_eq!(r.checked, 0);

    e.engine.dismiss_recheck_alert(&a.id).unwrap();
    assert_eq!(e.engine.recheck_status().alerts.len(), 1);
    assert!(e.engine.dismiss_recheck_alert("nope").is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn recheck_needs_an_api_key() {
    let e = env(EnvOptions::default());
    assert!(e.engine.recheck_now().await.is_err());
}
