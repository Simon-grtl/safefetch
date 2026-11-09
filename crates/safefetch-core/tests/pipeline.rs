//! End-to-end tests: real HTTP server, real quarantine, real clamscan
//! (with a test signature for EICAR), mocked VirusTotal.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::sync::Arc;

use common::*;
use safefetch_core::engine::{LinkStatus, Outcome};
use safefetch_core::hash::sha256_bytes;
use safefetch_core::verdict::VerdictLevel;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

/// (path, body, extra headers)
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

#[tokio::test(flavor = "multi_thread")]
async fn clean_file_is_delivered_with_clean_name() {
    require_clamav!();
    let srv = RawServer::start(static_server(vec![(
        "/dl",
        b"hello, harmless world".to_vec(),
        vec![("Content-Disposition", "attachment; filename=\"report.pdf\"")],
    )]))
    .await;
    let e = env(EnvOptions::default());
    let j = e.run(&srv.url("/dl")).await;
    assert!(
        matches!(j.outcome, Some(Outcome::Delivered { .. })),
        "{j:#?}"
    );
    assert_eq!(j.verdict.as_ref().unwrap().level, VerdictLevel::Clean);
    assert_eq!(e.dest_files(), vec!["report.pdf"]);
    assert_eq!(
        std::fs::read(e.dest.join("report.pdf")).unwrap(),
        b"hello, harmless world"
    );
    assert!(
        e.quarantine_files().is_empty(),
        "quarantine must be empty: {:?}",
        e.quarantine_files()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn eicar_is_detected_and_deleted() {
    require_clamav!();
    let srv = RawServer::start(static_server(vec![("/eicar.com", EICAR.to_vec(), vec![])])).await;
    let e = env(EnvOptions::default());
    let j = e.run(&srv.url("/eicar.com")).await;
    assert_eq!(j.outcome, Some(Outcome::Deleted), "{j:#?}");
    // On a machine whose own real-time antivirus removes EICAR first (Windows
    // runners), SafeFetch reports the deletion without a verdict: also correct.
    if let Some(v) = j.verdict {
        assert_eq!(v.level, VerdictLevel::Dangerous);
        assert!(
            v.detections
                .iter()
                .any(|d| d.name.contains("SafeFetch.Test.EICAR")),
            "{:?}",
            v.detections
        );
    }
    assert!(e.dest_files().is_empty());
    assert!(e.quarantine_files().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn eicar_inside_zip_and_nested_zip_is_detected() {
    require_clamav!();
    let inner = zip_of(&[("readme.txt", b"hi"), ("eicar.com", EICAR)]);
    let nested = zip_of(&[("inner.zip", &inner)]);
    let srv = RawServer::start(static_server(vec![
        ("/a.zip", inner, vec![]),
        ("/b.zip", nested, vec![]),
    ]))
    .await;
    let e = env(EnvOptions::default());
    for p in ["/a.zip", "/b.zip"] {
        let j = e.run(&srv.url(p)).await;
        assert_eq!(j.outcome, Some(Outcome::Deleted), "{p}: {j:#?}");
    }
    assert!(e.dest_files().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn eicar_next_to_large_member_is_detected() {
    require_clamav!();
    let z = zip_of(&[
        ("big.bin", &vec![0u8; 30 * 1024 * 1024]),
        ("eicar.com", EICAR),
    ]);
    let srv = RawServer::start(static_server(vec![("/mix.zip", z, vec![])])).await;
    let e = env(EnvOptions::default());
    let j = e.run(&srv.url("/mix.zip")).await;
    assert_eq!(j.outcome, Some(Outcome::Deleted), "{j:#?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn truncated_archive_member_is_not_analyzed() {
    require_clamav!();
    // ClamAV 1.5 silently truncates archive members above MaxFileSize, even
    // with --alert-exceeds-max. Here MaxFileSize is lowered to 20 MiB to
    // reproduce it with a 30 MiB member: the verdict must NOT be Clean.
    let z = zip_of(&[("big.bin", &vec![1u8; 30 * 1024 * 1024])]);
    let srv = RawServer::start(static_server(vec![("/t.zip", z, vec![])])).await;
    let e = env(EnvOptions {
        settings: Box::new(|s| s.clamav.max_filesize_mib = 20),
        ..Default::default()
    });
    let j = e.run(&srv.url("/t.zip")).await;
    assert_eq!(j.outcome, Some(Outcome::Quarantined), "{j:#?}");
    let v = j.verdict.unwrap();
    assert_eq!(v.level, VerdictLevel::NotAnalyzed, "{:?}", v.reasons);
}

#[tokio::test(flavor = "multi_thread")]
async fn clamav_limit_exceeded_is_never_clean() {
    require_clamav!();
    // 60 MiB of zeros compresses to ~60 KiB: a mini zip bomb.
    let bomb = zip_of(&[("zeros.bin", &vec![0u8; 60 * 1024 * 1024])]);
    let srv = RawServer::start(static_server(vec![
        ("/bomb.zip", bomb, vec![]),
        ("/big.bin", vec![7u8; 3 * 1024 * 1024], vec![]),
    ]))
    .await;
    let e = env(EnvOptions {
        settings: Box::new(|s| {
            s.clamav.max_scansize_mib = 10;
            s.clamav.max_filesize_mib = 2;
        }),
        ..Default::default()
    });
    for p in ["/bomb.zip", "/big.bin"] {
        let j = e.run(&srv.url(p)).await;
        assert_eq!(j.outcome, Some(Outcome::Quarantined), "{p}: {j:#?}");
        let v = j.verdict.unwrap();
        assert_eq!(v.level, VerdictLevel::NotAnalyzed, "{p}: {:?}", v.reasons);
    }
    assert!(e.dest_files().is_empty(), "nothing may be delivered");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_clamav_means_not_analyzed() {
    let srv = RawServer::start(static_server(vec![("/f.txt", b"data".to_vec(), vec![])])).await;
    let e = env(EnvOptions {
        settings: Box::new(|s| s.clamav.clamscan_path = Some(missing_exe())),
        ..Default::default()
    });
    let j = e.run(&srv.url("/f.txt")).await;
    assert_eq!(j.outcome, Some(Outcome::Quarantined));
    assert_eq!(j.verdict.unwrap().level, VerdictLevel::NotAnalyzed);
}

#[tokio::test(flavor = "multi_thread")]
async fn checksum_mismatch_is_suspect_then_user_decides() {
    require_clamav!();
    let data = b"some installer".to_vec();
    let srv = RawServer::start(static_server(vec![("/setup.bin", data.clone(), vec![])])).await;
    let e = env(EnvOptions::default());
    let wrong = "0".repeat(64);
    let j = e.run(&format!("{} {wrong}", srv.url("/setup.bin"))).await;
    assert_eq!(j.outcome, Some(Outcome::Quarantined));
    assert_eq!(j.verdict.unwrap().level, VerdictLevel::Suspect);
    assert!(e.dest_files().is_empty());
    // The user releases it explicitly.
    let p = e.engine.release(j.id).unwrap();
    assert!(p.ends_with("setup.bin"));
    assert_eq!(e.dest_files(), vec!["setup.bin"]);
    assert!(e.quarantine_files().is_empty());

    // With the right checksum it is delivered directly.
    let srv2 = RawServer::start(static_server(vec![(
        "/setup2.bin",
        b"other".to_vec(),
        vec![],
    )]))
    .await;
    let j = e
        .run(&format!(
            "{} {}",
            srv2.url("/setup2.bin"),
            sha256_bytes(b"other")
        ))
        .await;
    assert!(
        matches!(j.outcome, Some(Outcome::Delivered { .. })),
        "{j:#?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn discard_removes_quarantined_file() {
    let srv = RawServer::start(static_server(vec![("/x", b"x".to_vec(), vec![])])).await;
    let e = env(EnvOptions {
        settings: Box::new(|s| s.clamav.clamscan_path = Some(missing_exe())),
        ..Default::default()
    });
    let j = e.run(&srv.url("/x")).await;
    assert_eq!(j.outcome, Some(Outcome::Quarantined));
    assert_eq!(e.quarantine_files().len(), 2); // data + sidecar
    e.engine.discard(j.id).unwrap();
    assert!(e.quarantine_files().is_empty());
    assert!(e.engine.release(j.id).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn malicious_names_are_sanitized() {
    require_clamav!();
    let srv = RawServer::start(static_server(vec![
        (
            "/a",
            b"a".to_vec(),
            vec![(
                "Content-Disposition",
                "attachment; filename*=UTF-8''..%2F..%2F..%2Ftmp%2Ffacture.pdf.exe",
            )],
        ),
        (
            "/b",
            b"b".to_vec(),
            vec![(
                "Content-Disposition",
                "attachment; filename*=UTF-8''photo%E2%80%AEgpj.scr",
            )],
        ),
        (
            "/c",
            b"c".to_vec(),
            vec![("Content-Disposition", "attachment; filename=\"CON\"")],
        ),
        (
            "/d",
            b"d".to_vec(),
            vec![("Content-Disposition", "attachment; filename=\"...\"")],
        ),
    ]))
    .await;
    let e = env(EnvOptions::default());
    for p in ["/a", "/b", "/c", "/d"] {
        let j = e.run(&srv.url(p)).await;
        assert!(
            matches!(j.outcome, Some(Outcome::Delivered { .. })),
            "{p}: {j:#?}"
        );
    }
    assert_eq!(
        e.dest_files(),
        vec!["_CON", "download", "facture_pdf.exe", "photogpj.scr"]
    );
    // Nothing escaped the destination.
    assert!(!e.dir.path().join("tmp").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn resumes_after_network_cut() {
    require_clamav!();
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();
    let d2 = data.clone();
    let srv = RawServer::start(Arc::new(move |req: &Req, n| {
        let mut r = range_response(&d2, req);
        if n == 0 {
            r.cut_after = Some(1_000_000); // connection drops at 1 MB
        }
        r
    }))
    .await;
    let e = env(EnvOptions::default());
    let j = e.run(&srv.url("/big.bin")).await;
    assert!(
        matches!(j.outcome, Some(Outcome::Delivered { .. })),
        "{j:#?}"
    );
    assert_eq!(std::fs::read(e.dest.join("big.bin")).unwrap(), data);
    let reqs = srv.requests.lock().unwrap().clone();
    assert!(reqs.len() >= 2);
    assert!(
        reqs[1].range_from.unwrap_or(0) >= 1_000_000,
        "second request must resume: {:?}",
        reqs[1].range_from
    );
    assert!(reqs[1]
        .headers
        .to_ascii_lowercase()
        .contains("if-range: \"v1\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn server_ignoring_range_restarts_cleanly() {
    require_clamav!();
    let data: Vec<u8> = (0..500_000u32).map(|i| (i % 7) as u8).collect();
    let d2 = data.clone();
    let srv = RawServer::start(Arc::new(move |_req: &Req, n| {
        let mut r = Resp::ok(d2.clone()); // always 200, full body
        if n == 0 {
            r.cut_after = Some(100_000);
        }
        r
    }))
    .await;
    let e = env(EnvOptions::default());
    let j = e.run(&srv.url("/f.bin")).await;
    assert!(
        matches!(j.outcome, Some(Outcome::Delivered { .. })),
        "{j:#?}"
    );
    assert_eq!(std::fs::read(e.dest.join("f.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn short_body_is_incomplete_and_resumable() {
    let srv = RawServer::start(Arc::new(|_req: &Req, _n| {
        let mut r = Resp::ok(vec![1u8; 50]);
        r.content_length = Some(100); // announces 100, sends 50
        r
    }))
    .await;
    let e = env(EnvOptions {
        settings: Box::new(|s| s.max_retries = 1),
        ..Default::default()
    });
    let j = e.run(&srv.url("/short")).await;
    match j.outcome {
        Some(Outcome::Failed { resumable, .. }) => assert!(resumable),
        other => panic!("{other:?}"),
    }
    assert!(e.dest_files().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn not_enough_disk_space_fails_before_writing() {
    let srv = RawServer::start(Arc::new(|_req: &Req, _n| Resp::ok(vec![0u8; 10_000]))).await;
    let e = env(EnvOptions {
        space: Some(1024),
        ..Default::default()
    });
    let j = e.run(&srv.url("/x")).await;
    match &j.outcome {
        Some(Outcome::Failed { error, resumable }) => {
            assert!(error.contains("disk space"), "{error}");
            assert!(!resumable);
        }
        other => panic!("{other:?}"),
    }
    assert!(e.quarantine_files().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn max_size_is_enforced() {
    let srv = RawServer::start(Arc::new(|_req: &Req, _n| {
        Resp::ok(vec![0u8; 3 * 1024 * 1024])
    }))
    .await;
    let e = env(EnvOptions {
        settings: Box::new(|s| s.max_file_size_mib = 1),
        ..Default::default()
    });
    let j = e.run(&srv.url("/x")).await;
    assert!(
        matches!(&j.outcome, Some(Outcome::Failed { error, .. }) if error.contains("too large")),
        "{j:#?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_loops_are_cut() {
    let srv = RawServer::start(Arc::new(|req: &Req, _n| {
        Resp::redirect(&format!("{}x", req.path))
    }))
    .await;
    let e = env(EnvOptions::default());
    let j = e.run(&srv.url("/r")).await;
    assert!(
        matches!(&j.outcome, Some(Outcome::Failed { error, .. }) if error.contains("redirects")),
        "{j:#?}"
    );
    assert_eq!(srv.requests.lock().unwrap().len(), 6); // 1 + max_redirects(5)
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_to_other_scheme_is_refused() {
    let srv = RawServer::start(Arc::new(|_req: &Req, _n| {
        Resp::redirect("file:///etc/passwd")
    }))
    .await;
    let e = env(EnvOptions::default());
    let j = e.run(&srv.url("/r")).await;
    assert!(
        matches!(&j.outcome, Some(Outcome::Failed { error, .. }) if error.contains("scheme")),
        "{j:#?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http_can_be_disabled() {
    let srv = RawServer::start(static_server(vec![("/x", b"x".to_vec(), vec![])])).await;
    let e = env(EnvOptions {
        settings: Box::new(|s| s.allow_http = false),
        ..Default::default()
    });
    let j = e.run(&srv.url("/x")).await;
    assert!(
        matches!(&j.outcome, Some(Outcome::Failed { error, .. }) if error.contains("HTTP")),
        "{j:#?}"
    );
    assert_eq!(srv.requests.lock().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn never_downloads_twice() {
    require_clamav!();
    let srv = RawServer::start(static_server(vec![
        ("/a.iso", b"same content".to_vec(), vec![]),
        ("/mirror/a.iso", b"same content".to_vec(), vec![]),
    ]))
    .await;
    let e = env(EnvOptions::default());
    let j1 = e.run(&srv.url("/a.iso")).await;
    assert!(matches!(j1.outcome, Some(Outcome::Delivered { .. })));
    // Same link: not fetched again at all.
    let j2 = e.run(&srv.url("/a.iso")).await;
    assert!(
        matches!(j2.outcome, Some(Outcome::AlreadyDownloaded { .. })),
        "{j2:#?}"
    );
    assert_eq!(srv.count("/a.iso"), 1);
    // Same content from another link: discarded after hashing.
    let j3 = e.run(&srv.url("/mirror/a.iso")).await;
    assert!(
        matches!(j3.outcome, Some(Outcome::AlreadyDownloaded { .. })),
        "{j3:#?}"
    );
    assert_eq!(e.dest_files(), vec!["a.iso"]);
    assert!(e.quarantine_files().is_empty());
    // Duplicate lines in one batch are collapsed.
    let r = e.engine.submit(&format!("{u}\n{u}\n", u = srv.url("/b")));
    assert_eq!(r.added.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_then_resume() {
    require_clamav!();
    let data: Vec<u8> = (0..40_000_000u32).map(|i| (i % 249) as u8).collect();
    let d2 = data.clone();
    let srv = RawServer::start(Arc::new(move |req: &Req, _| range_response(&d2, req))).await;
    let e = env(EnvOptions::default());
    let r = e.engine.submit(&srv.url("/big"));
    let id = r.added[0];
    // Wait until some bytes arrived, then cancel.
    for _ in 0..200 {
        if e.engine.job(id).unwrap().downloaded > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    e.engine.cancel(id).unwrap();
    let j = e.wait(id).await;
    if let Some(Outcome::Cancelled { resumable }) = j.outcome {
        assert!(resumable);
        e.engine.retry(id).unwrap();
        let j = e.wait(id).await;
        assert!(
            matches!(j.outcome, Some(Outcome::Delivered { .. })),
            "{j:#?}"
        );
    } else {
        // Very fast machine: finished before the cancel landed.
        assert!(
            matches!(j.outcome, Some(Outcome::Delivered { .. })),
            "{j:#?}"
        );
    }
    assert_eq!(std::fs::read(e.dest.join("big")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn quarantine_survives_restart() {
    let srv = RawServer::start(static_server(vec![("/x", b"x".to_vec(), vec![])])).await;
    let dir = tempfile::tempdir().unwrap();
    let opts = || EnvOptions {
        settings: Box::new(|s| s.clamav.clamscan_path = Some(missing_exe())),
        ..Default::default()
    };
    let e = env_in(dir, opts());
    let j = e.run(&srv.url("/x")).await;
    assert_eq!(j.outcome, Some(Outcome::Quarantined));
    // New engine on the same config/destination.
    let dir = e.dir;
    drop(e.engine);
    let e2 = env_in(dir, opts());
    let jobs = e2.engine.jobs();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].outcome, Some(Outcome::Quarantined));
    assert_eq!(
        jobs[0].verdict.as_ref().unwrap().level,
        VerdictLevel::NotAnalyzed
    );
}

// ------------------------------------------------------------ VirusTotal --

async fn vt_server(url_mal: u32, file_mal: u32) -> MockServer {
    let s = MockServer::start().await;
    let stats = |m: u32| {
        serde_json::json!({"data": {"attributes": {
            "last_analysis_stats": {"malicious": m, "suspicious": 0, "harmless": 10, "undetected": 50},
            "last_analysis_results": {"Engine1": {"category": if m > 0 {"malicious"} else {"harmless"}, "result": "Mal/Generic"}}
        }}})
    };
    Mock::given(method("GET"))
        .and(path_regex("^/api/v3/urls/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stats(url_mal)))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("^/api/v3/files/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stats(file_mal)))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("^/api/v3/domains/"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&s)
        .await;
    s
}

#[tokio::test(flavor = "multi_thread")]
async fn virustotal_malicious_link_is_blocked_before_download() {
    let vt = vt_server(5, 0).await;
    let srv = RawServer::start(static_server(vec![("/x", b"x".to_vec(), vec![])])).await;
    let e = env(EnvOptions {
        vt_base: Some(format!("{}/api/v3/", vt.uri())),
        vt_key: true,
        ..Default::default()
    });
    let j = e.run(&srv.url("/x")).await;
    assert!(matches!(j.outcome, Some(Outcome::Blocked { .. })), "{j:#?}");
    assert_eq!(j.link_check.unwrap().status, LinkStatus::Blocked);
    assert_eq!(
        srv.requests.lock().unwrap().len(),
        0,
        "the file server must not be contacted"
    );
    // Never sends the file: no POST to VirusTotal.
    assert!(vt
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|r| r.method.as_str() == "GET"));
}

#[tokio::test(flavor = "multi_thread")]
async fn virustotal_file_thresholds() {
    require_clamav!();
    for (mal, expected) in [
        (0, VerdictLevel::Clean),
        (1, VerdictLevel::Suspect),
        (2, VerdictLevel::Suspect),
        (3, VerdictLevel::Dangerous),
    ] {
        let vt = vt_server(0, mal).await;
        let srv = RawServer::start(static_server(vec![(
            "/f",
            format!("payload {mal}").into_bytes(),
            vec![],
        )]))
        .await;
        let e = env(EnvOptions {
            vt_base: Some(format!("{}/api/v3/", vt.uri())),
            vt_key: true,
            ..Default::default()
        });
        let j = e.run(&srv.url("/f")).await;
        let v = j.verdict.clone().unwrap();
        assert_eq!(v.level, expected, "malicious={mal}: {:?}", v.reasons);
        assert!(v.virustotal_link.unwrap().contains("/gui/file/"));
        // Only hashes/URLs were sent: every VT request is a GET.
        assert!(vt
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }
}

// ------------------------------------------------------ audit regressions --

#[tokio::test(flavor = "multi_thread")]
async fn redirect_target_switch_after_virustotal_check_is_refused() {
    // First answer: redirect to /good (checked by VirusTotal). After the
    // check, SafeFetch re-requests the link: the server now redirects to /evil.
    let vt = vt_server(0, 0).await;
    let port = Arc::new(std::sync::Mutex::new(0u16));
    let p2 = port.clone();
    let srv = RawServer::start(Arc::new(move |req: &Req, n| {
        let port = *p2.lock().unwrap();
        match (req.path.as_str(), n) {
            ("/start", 0) => Resp::redirect(&format!("http://localhost:{port}/good")),
            ("/start", _) => Resp::redirect(&format!("http://localhost:{port}/evil")),
            _ => Resp::ok(b"payload".to_vec()),
        }
    }))
    .await;
    *port.lock().unwrap() = srv.base.rsplit(':').next().unwrap().parse().unwrap();
    let e = env(EnvOptions {
        vt_base: Some(format!("{}/api/v3/", vt.uri())),
        vt_key: true,
        ..Default::default()
    });
    let j = e.run(&srv.url("/start")).await;
    // The checked target (/good) is fetched directly; /evil is never contacted.
    assert_eq!(srv.count("/evil"), 0, "unchecked target fetched: {j:#?}");
    assert!(srv.count("/good") >= 1);
    assert!(!matches!(j.outcome, Some(Outcome::Failed { .. })), "{j:#?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn credentials_in_links_never_reach_virustotal() {
    use base64::Engine as _;
    let vt = vt_server(0, 0).await;
    let srv = RawServer::start(static_server(vec![("/x", b"x".to_vec(), vec![])])).await;
    let e = env(EnvOptions {
        vt_base: Some(format!("{}/api/v3/", vt.uri())),
        vt_key: true,
        ..Default::default()
    });
    let url = srv.url("/x").replace("http://", "http://alice:S3cretPw@");
    let _ = e.run(&url).await;
    for r in vt.received_requests().await.unwrap() {
        let p = r.url.path().to_string();
        assert!(!p.contains("S3cretPw"));
        if let Some(id) = p.strip_prefix("/api/v3/urls/") {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(id)
                .unwrap();
            let decoded = String::from_utf8(decoded).unwrap();
            assert!(
                !decoded.contains("S3cretPw") && !decoded.contains("alice"),
                "{decoded}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_file_is_kept_when_delivery_fails() {
    require_clamav!();
    let srv = RawServer::start(static_server(vec![("/f.bin", b"clean".to_vec(), vec![])])).await;
    let e = env(EnvOptions::default());
    // Fill every candidate name so delivery cannot find a free one.
    std::fs::write(e.dest.join("f.bin"), b"o").unwrap();
    for n in 1..1000 {
        std::fs::write(e.dest.join(format!("f ({n}).bin")), b"o").unwrap();
    }
    let j = e.run(&srv.url("/f.bin")).await;
    assert_eq!(j.outcome, Some(Outcome::Quarantined), "{j:#?}");
    assert_eq!(j.verdict.as_ref().unwrap().level, VerdictLevel::Clean);
    assert_eq!(
        e.quarantine_files().len(),
        2,
        "the downloaded file must be kept"
    );
    // Free a name: the user can now release it without downloading again.
    std::fs::remove_file(e.dest.join("f.bin")).unwrap();
    e.engine.release(j.id).unwrap();
    assert_eq!(std::fs::read(e.dest.join("f.bin")).unwrap(), b"clean");
    assert_eq!(srv.count("/f.bin"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_resume_offset_restarts_cleanly() {
    require_clamav!();
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 11) as u8).collect();
    let d2 = data.clone();
    let srv = RawServer::start(Arc::new(move |req: &Req, n| {
        if req.range_from.is_some() {
            // Lies: claims to resume but starts at 0.
            let mut r = Resp::ok(d2.clone()).status(206);
            r.headers.push((
                "Content-Range".into(),
                format!("bytes 0-{}/{}", d2.len() - 1, d2.len()),
            ));
            return r;
        }
        let mut r = Resp::ok(d2.clone());
        if n == 0 {
            r.cut_after = Some(50_000);
        }
        r
    }))
    .await;
    let e = env(EnvOptions {
        settings: Box::new(|s| s.max_retries = 4),
        ..Default::default()
    });
    let j = e.run(&srv.url("/w.bin")).await;
    assert!(
        matches!(j.outcome, Some(Outcome::Delivered { .. })),
        "{j:#?}"
    );
    assert_eq!(std::fs::read(e.dest.join("w.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn state_guards_and_destination_change() {
    let srv = RawServer::start(static_server(vec![("/x", b"x".to_vec(), vec![])])).await;
    let e = env(EnvOptions {
        settings: Box::new(|s| s.clamav.clamscan_path = Some(missing_exe())),
        ..Default::default()
    });
    let j = e.run(&srv.url("/x")).await;
    assert_eq!(j.outcome, Some(Outcome::Quarantined));
    // Invalid transitions are refused.
    assert!(e.engine.force_download(j.id).is_err());
    assert!(e.engine.retry(j.id).is_err());
    // Re-pasting the same link while its file is in quarantine is ignored.
    assert!(e.engine.submit(&srv.url("/x")).added.is_empty());
    // Changing destination with a quarantined item is refused.
    let other = e.dir.path().join("Other");
    std::fs::create_dir_all(&other).unwrap();
    assert!(e.engine.set_destination(&other).is_err());
    // Rescan works (still not analyzed without ClamAV).
    e.engine.rescan(j.id).unwrap();
    let j = e.wait(j.id).await;
    assert_eq!(j.outcome, Some(Outcome::Quarantined));
    e.engine.discard(j.id).unwrap();
    e.engine.clear_finished();
    assert!(e.engine.set_destination(&other).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_checked_target_with_switched_chain_is_refused() {
    // The checked target now answers 403 and the link redirects elsewhere:
    // SafeFetch must refuse instead of downloading the unchecked file.
    let vt = vt_server(0, 0).await;
    let port = Arc::new(std::sync::Mutex::new(0u16));
    let p2 = port.clone();
    let srv = RawServer::start(Arc::new(move |req: &Req, n| {
        let port = *p2.lock().unwrap();
        match (req.path.as_str(), n) {
            ("/start", 0) => Resp::redirect(&format!("http://localhost:{port}/good")),
            ("/start", _) => Resp::redirect(&format!("http://localhost:{port}/evil")),
            ("/good", 1) => Resp::ok(b"good payload".to_vec()),
            ("/good", _) => Resp::ok(b"gone".to_vec()).status(403),
            _ => Resp::ok(b"evil payload".to_vec()),
        }
    }))
    .await;
    *port.lock().unwrap() = srv.base.rsplit(':').next().unwrap().parse().unwrap();
    let e = env(EnvOptions {
        vt_base: Some(format!("{}/api/v3/", vt.uri())),
        vt_key: true,
        ..Default::default()
    });
    let j = e.run(&srv.url("/start")).await;
    assert!(
        matches!(&j.outcome, Some(Outcome::Failed { error, .. }) if error.contains("redirect target changed")),
        "{j:#?}"
    );
    assert!(e.dest_files().is_empty());
    assert!(e.quarantine_files().is_empty());
}

/// Patch a little-endian u16/u32 field.
fn put(buf: &mut [u8], off: usize, v: u32, len: usize) {
    buf[off..off + len].copy_from_slice(&v.to_le_bytes()[..len]);
}

fn find(buf: &[u8], sig: &[u8]) -> usize {
    buf.windows(sig.len()).position(|w| w == sig).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn archives_clamav_cannot_unpack_are_never_clean() {
    // Security audit F1: zips that ClamAV fails to decompress (while other
    // tools may succeed) used to come back "Clean".
    require_clamav!();
    let base = zip_of(&[("eicar.com", EICAR)]);
    let local = find(&base, b"PK\x03\x04");
    let central = find(&base, b"PK\x01\x02");
    let mut lzma = base.clone(); // compression method 14 (LZMA)
    put(&mut lzma, local + 8, 14, 2);
    put(&mut lzma, central + 10, 14, 2);
    let mut bad_size = base.clone(); // lying local-header compressed size
    put(&mut bad_size, local + 18, 0x7fff_ffff, 4);
    let mut zip64 = base.clone(); // sizes forced to the ZIP64 marker
    put(&mut zip64, local + 18, 0xffff_ffff, 4);
    put(&mut zip64, local + 22, 0xffff_ffff, 4);
    let srv = RawServer::start(static_server(vec![
        ("/lzma.zip", lzma, vec![]),
        ("/size.zip", bad_size, vec![]),
        ("/z64.zip", zip64, vec![]),
    ]))
    .await;
    let e = env(EnvOptions::default());
    for p in ["/lzma.zip", "/size.zip", "/z64.zip"] {
        let j = e.run(&srv.url(p)).await;
        let level = j.verdict.as_ref().map(|v| v.level);
        assert!(
            matches!(
                level,
                Some(VerdictLevel::NotAnalyzed) | Some(VerdictLevel::Dangerous)
            ),
            "{p}: {j:#?}"
        );
    }
    assert!(
        e.dest_files().is_empty(),
        "nothing may be delivered: {:?}",
        e.dest_files()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reaudit_zip_and_xz_evasions_are_never_clean() {
    // Re-audit of F1: masked-header flag, local method/size disagreeing with
    // the central directory, a self-extractor-style prefix, and a truncated
    // .xz that still decompresses partially with `xz -dc`.
    require_clamav!();
    let base = zip_of(&[("eicar.com", EICAR)]);
    let local = find(&base, b"PK\x03\x04");
    let mut masked = base.clone();
    masked[local + 7] |= 0x20; // general-purpose flag bit 13
    let mut method0 = base.clone();
    put(&mut method0, local + 8, 0, 2);
    let mut csize0 = base.clone();
    put(&mut csize0, local + 18, 0, 4);
    let mut prefixed = b"#!/bin/sh\nexit 0\n".repeat(60);
    prefixed.extend_from_slice(&masked);
    let truncated_xz = hex_decode("fd377a585a000004e6d6b4460200210116000000742fe5a301004358354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a00faab49d4013391b6");
    let srv = RawServer::start(static_server(vec![
        ("/masked.zip", masked, vec![]),
        ("/m0.zip", method0, vec![]),
        ("/c0.zip", csize0, vec![]),
        ("/sfx.bin", prefixed, vec![]),
        ("/t.xz", truncated_xz, vec![]),
    ]))
    .await;
    let e = env(EnvOptions::default());
    for p in ["/masked.zip", "/m0.zip", "/c0.zip", "/sfx.bin", "/t.xz"] {
        let j = e.run(&srv.url(p)).await;
        let level = j.verdict.as_ref().map(|v| v.level);
        assert!(
            matches!(
                level,
                Some(VerdictLevel::NotAnalyzed) | Some(VerdictLevel::Dangerous)
            ),
            "{p}: {j:#?}"
        );
    }
    assert!(
        e.dest_files().is_empty(),
        "nothing may be delivered: {:?}",
        e.dest_files()
    );
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
