//! Verdict engine: a pure function from scan results + thresholds to a verdict.

use serde::{Deserialize, Serialize};

/// Result of one local engine (ClamAV, Defender).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum EngineResult {
    /// The whole file (and archive contents) was scanned, nothing found.
    Clean,
    /// Threat names.
    Infected(Vec<String>),
    /// The engine ran but could not inspect everything (limit, encryption…).
    NotScanned(String),
    /// The engine is not installed / not reachable.
    Unavailable(String),
    /// The engine failed.
    Error(String),
    /// Not applicable on this OS or disabled by the user.
    Skipped,
}

impl EngineResult {
    fn complete(&self) -> bool {
        matches!(self, EngineResult::Clean | EngineResult::Infected(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineDetection {
    pub engine: String,
    pub category: String,
    pub result: Option<String>,
}

/// VirusTotal file lookup by hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VtFileResult {
    NoApiKey,
    /// VirusTotal has never seen this hash.
    Unknown,
    Found {
        malicious: u32,
        suspicious: u32,
        undetected: u32,
        harmless: u32,
        detections: Vec<EngineDetection>,
        permalink: String,
    },
    Failed {
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub sha256: String,
    pub expected_sha256: Option<String>,
    pub virustotal: VtFileResult,
    pub clamav: EngineResult,
    pub defender: EngineResult,
    /// The publisher's checksum list given instead of a SHA-256, if any.
    #[serde(default)]
    pub checksum_list: Option<crate::checksums::ChecksumListResult>,
    /// The content does not match the file name's extension.
    #[serde(default)]
    pub type_mismatch: Option<crate::filetype::TypeMismatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictLevel {
    Clean,
    NotAnalyzed,
    Suspect,
    Dangerous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    pub vt_dangerous: u32,
    pub vt_suspicious: u32,
    pub require_virustotal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    pub source: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub level: VerdictLevel,
    pub reasons: Vec<String>,
    pub detections: Vec<Detection>,
    pub virustotal_link: Option<String>,
    pub report: ScanReport,
}

/// Apply the rules (the worst signal wins):
///
/// | Situation                                   | Verdict      |
/// |---------------------------------------------|--------------|
/// | ClamAV or Defender detects a threat         | Dangerous    |
/// | VirusTotal ≥ dangerous threshold            | Dangerous    |
/// | VirusTotal ≥ suspicious threshold           | Suspect      |
/// | Expected SHA-256 ≠ computed SHA-256         | Suspect      |
/// | File missing from the publisher's checksums | Suspect      |
/// | Program disguised as a document/media file  | Suspect      |
/// | Publisher's checksum list unavailable       | Not analyzed |
/// | A local scan hit a limit, failed or missing | Not analyzed |
/// | No signal and local scans complete          | Clean        |
pub fn decide(report: ScanReport, t: Thresholds) -> Verdict {
    let mut level = VerdictLevel::Clean;
    let mut reasons = Vec::new();
    let mut detections = Vec::new();
    let raise = |l: VerdictLevel, level: &mut VerdictLevel| {
        if l > *level {
            *level = l;
        }
    };

    for (name, r) in [
        ("ClamAV", &report.clamav),
        ("Microsoft Defender", &report.defender),
    ] {
        match r {
            EngineResult::Infected(threats) => {
                raise(VerdictLevel::Dangerous, &mut level);
                reasons.push(format!("{name} detected: {}", threats.join(", ")));
                detections.extend(threats.iter().map(|n| Detection {
                    source: name.into(),
                    name: n.clone(),
                }));
            }
            EngineResult::NotScanned(why) => {
                raise(VerdictLevel::NotAnalyzed, &mut level);
                reasons.push(format!("{name} could not analyze the whole file: {why}"));
            }
            EngineResult::Unavailable(why) => {
                raise(VerdictLevel::NotAnalyzed, &mut level);
                reasons.push(format!("{name} unavailable: {why}"));
            }
            EngineResult::Error(why) => {
                raise(VerdictLevel::NotAnalyzed, &mut level);
                reasons.push(format!("{name} failed: {why}"));
            }
            EngineResult::Clean => reasons.push(format!("{name}: no threat found")),
            EngineResult::Skipped => {}
        }
    }
    // A verdict of Clean requires at least one complete local scan.
    if !report.clamav.complete() && !report.defender.complete() {
        raise(VerdictLevel::NotAnalyzed, &mut level);
    }

    let mut link = None;
    match &report.virustotal {
        VtFileResult::Found {
            malicious,
            suspicious,
            detections: d,
            permalink,
            ..
        } => {
            link = Some(permalink.clone());
            if *malicious >= t.vt_dangerous {
                raise(VerdictLevel::Dangerous, &mut level);
                reasons.push(format!(
                    "VirusTotal: {malicious} engines flag this file as malicious"
                ));
            } else if *malicious >= t.vt_suspicious {
                raise(VerdictLevel::Suspect, &mut level);
                reasons.push(format!(
                    "VirusTotal: {malicious} engine(s) flag this file as malicious"
                ));
            } else {
                reasons.push(format!(
                    "VirusTotal: known file, 0 malicious detections ({suspicious} suspicious)"
                ));
            }
            detections.extend(
                d.iter()
                    .filter(|e| e.category == "malicious")
                    .map(|e| Detection {
                        source: format!("VirusTotal / {}", e.engine),
                        name: e.result.clone().unwrap_or_else(|| "malicious".into()),
                    }),
            );
        }
        VtFileResult::Unknown => {
            reasons.push("VirusTotal: hash never seen before (no data)".into())
        }
        VtFileResult::NoApiKey => {
            if t.require_virustotal {
                raise(VerdictLevel::NotAnalyzed, &mut level);
            }
            reasons.push("VirusTotal: not queried (no API key)".into());
        }
        VtFileResult::Failed { error } => {
            if t.require_virustotal {
                raise(VerdictLevel::NotAnalyzed, &mut level);
            }
            reasons.push(format!("VirusTotal lookup failed: {error}"));
        }
    }

    use crate::checksums::ChecksumListResult;
    let list_source = match &report.checksum_list {
        Some(ChecksumListResult::Found { source, entry }) => {
            Some(format!(" (\"{entry}\" in {source})"))
        }
        Some(ChecksumListResult::NotListed { source }) => {
            raise(VerdictLevel::Suspect, &mut level);
            reasons.push(format!(
                "The publisher's checksum list ({source}) does not mention this file: it cannot be verified"
            ));
            None
        }
        Some(ChecksumListResult::Conflict { source, names }) => {
            raise(VerdictLevel::Suspect, &mut level);
            reasons.push(format!(
                "The names this file goes by ({}) match different entries of the publisher's checksum list ({source}): it cannot be verified",
                names.join(", ")
            ));
            None
        }
        Some(ChecksumListResult::Unavailable { source, error }) => {
            raise(VerdictLevel::NotAnalyzed, &mut level);
            reasons.push(format!(
                "The publisher's checksum list ({source}) could not be read: {error}"
            ));
            None
        }
        None => None,
    };
    if let Some(expected) = &report.expected_sha256 {
        let from = list_source.as_deref().unwrap_or("");
        if crate::hash::digests_equal(expected, &report.sha256) {
            reasons.push(format!("SHA-256 matches the expected checksum{from}"));
        } else {
            raise(VerdictLevel::Suspect, &mut level);
            reasons.push(format!(
                "SHA-256 mismatch: expected {expected}{from}, got {} — the file is not the one you expected",
                report.sha256
            ));
        }
    }

    if let Some(m) = &report.type_mismatch {
        if m.disguised_program {
            raise(VerdictLevel::Suspect, &mut level);
            reasons.push(format!(
                "The name ends in .{} but the file is really {}: a program disguised as a harmless file is a classic trick",
                m.extension, m.detected_label
            ));
        } else {
            reasons.push(format!(
                "The extension .{} does not match the content, which is {}",
                m.extension, m.detected_label
            ));
        }
    }

    Verdict {
        level,
        reasons,
        detections,
        virustotal_link: link,
        report,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Thresholds = Thresholds {
        vt_dangerous: 3,
        vt_suspicious: 1,
        require_virustotal: false,
    };
    const SHA: &str = "aa";

    fn vt(n: u32) -> VtFileResult {
        VtFileResult::Found {
            malicious: n,
            suspicious: 0,
            undetected: 60,
            harmless: 0,
            detections: (0..n)
                .map(|i| EngineDetection {
                    engine: format!("E{i}"),
                    category: "malicious".into(),
                    result: Some("Trojan".into()),
                })
                .collect(),
            permalink: "https://www.virustotal.com/gui/file/aa".into(),
        }
    }

    fn report(clam: EngineResult, vt: VtFileResult, expected: Option<&str>) -> ScanReport {
        ScanReport {
            sha256: SHA.into(),
            expected_sha256: expected.map(str::to_string),
            virustotal: vt,
            clamav: clam,
            defender: EngineResult::Skipped,
            checksum_list: None,
            type_mismatch: None,
        }
    }

    #[test]
    fn local_detection_is_dangerous() {
        let v = decide(
            report(
                EngineResult::Infected(vec!["Eicar-Signature".into()]),
                VtFileResult::Unknown,
                None,
            ),
            T,
        );
        assert_eq!(v.level, VerdictLevel::Dangerous);
        assert_eq!(v.detections[0].name, "Eicar-Signature");
        let mut r = report(EngineResult::Clean, VtFileResult::Unknown, None);
        r.defender = EngineResult::Infected(vec!["Virus:DOS/EICAR_Test_File".into()]);
        assert_eq!(decide(r, T).level, VerdictLevel::Dangerous);
    }

    #[test]
    fn virustotal_thresholds() {
        assert_eq!(
            decide(report(EngineResult::Clean, vt(0), None), T).level,
            VerdictLevel::Clean
        );
        assert_eq!(
            decide(report(EngineResult::Clean, vt(1), None), T).level,
            VerdictLevel::Suspect
        );
        assert_eq!(
            decide(report(EngineResult::Clean, vt(2), None), T).level,
            VerdictLevel::Suspect
        );
        assert_eq!(
            decide(report(EngineResult::Clean, vt(3), None), T).level,
            VerdictLevel::Dangerous
        );
        let custom = Thresholds {
            vt_dangerous: 10,
            vt_suspicious: 5,
            require_virustotal: false,
        };
        assert_eq!(
            decide(report(EngineResult::Clean, vt(4), None), custom).level,
            VerdictLevel::Clean
        );
        assert_eq!(
            decide(report(EngineResult::Clean, vt(5), None), custom).level,
            VerdictLevel::Suspect
        );
        assert_eq!(
            decide(report(EngineResult::Clean, vt(10), None), custom).level,
            VerdictLevel::Dangerous
        );
    }

    #[test]
    fn hash_mismatch_is_suspect() {
        let v = decide(
            report(EngineResult::Clean, VtFileResult::Unknown, Some("bb")),
            T,
        );
        assert_eq!(v.level, VerdictLevel::Suspect);
        let v = decide(
            report(EngineResult::Clean, VtFileResult::Unknown, Some("AA")),
            T,
        );
        assert_eq!(v.level, VerdictLevel::Clean);
    }

    #[test]
    fn limits_and_failures_are_never_clean() {
        for r in [
            EngineResult::NotScanned("Heuristics.Limits.Exceeded.MaxFileSize".into()),
            EngineResult::Unavailable("clamscan not found".into()),
            EngineResult::Error("exit code 2".into()),
            EngineResult::Skipped,
        ] {
            assert_eq!(
                decide(report(r, VtFileResult::Unknown, None), T).level,
                VerdictLevel::NotAnalyzed
            );
        }
        // Defender complete but ClamAV hit a limit: still not analyzed.
        let mut r = report(
            EngineResult::NotScanned("limit".into()),
            VtFileResult::Unknown,
            None,
        );
        r.defender = EngineResult::Clean;
        assert_eq!(decide(r, T).level, VerdictLevel::NotAnalyzed);
    }

    #[test]
    fn worst_signal_wins() {
        let v = decide(
            report(EngineResult::Infected(vec!["X".into()]), vt(1), Some("bb")),
            T,
        );
        assert_eq!(v.level, VerdictLevel::Dangerous);
        let v = decide(
            report(EngineResult::NotScanned("limit".into()), vt(1), None),
            T,
        );
        assert_eq!(v.level, VerdictLevel::Suspect);
    }

    #[test]
    fn virustotal_required_option() {
        let strict = Thresholds {
            require_virustotal: true,
            ..T
        };
        assert_eq!(
            decide(
                report(EngineResult::Clean, VtFileResult::NoApiKey, None),
                strict
            )
            .level,
            VerdictLevel::NotAnalyzed
        );
        assert_eq!(
            decide(
                report(
                    EngineResult::Clean,
                    VtFileResult::Failed {
                        error: "429".into()
                    },
                    None
                ),
                strict
            )
            .level,
            VerdictLevel::NotAnalyzed
        );
        assert_eq!(
            decide(report(EngineResult::Clean, VtFileResult::NoApiKey, None), T).level,
            VerdictLevel::Clean
        );
        assert_eq!(
            decide(
                report(EngineResult::Clean, VtFileResult::Unknown, None),
                strict
            )
            .level,
            VerdictLevel::Clean
        );
    }

    #[test]
    fn checksum_list_outcomes() {
        use crate::checksums::ChecksumListResult;
        let mut r = report(EngineResult::Clean, VtFileResult::Unknown, Some("aa"));
        r.checksum_list = Some(ChecksumListResult::Found {
            source: "https://e.example/SHA256SUMS".into(),
            entry: "x.iso".into(),
        });
        let v = decide(r, T);
        assert_eq!(v.level, VerdictLevel::Clean);
        assert!(v.reasons.iter().any(|r| r.contains("SHA256SUMS")));
        let mut r = report(EngineResult::Clean, VtFileResult::Unknown, None);
        r.checksum_list = Some(ChecksumListResult::NotListed { source: "s".into() });
        assert_eq!(decide(r, T).level, VerdictLevel::Suspect);
        let mut r = report(EngineResult::Clean, VtFileResult::Unknown, None);
        r.checksum_list = Some(ChecksumListResult::Unavailable {
            source: "s".into(),
            error: "HTTP 404".into(),
        });
        assert_eq!(decide(r, T).level, VerdictLevel::NotAnalyzed);
        // A matching publisher checksum never turns an unscanned file Clean.
        let mut r = report(
            EngineResult::NotScanned("2 GiB".into()),
            VtFileResult::Unknown,
            Some("aa"),
        );
        r.checksum_list = Some(ChecksumListResult::Found {
            source: "s".into(),
            entry: "x.iso".into(),
        });
        assert_eq!(decide(r, T).level, VerdictLevel::NotAnalyzed);
    }

    #[test]
    fn disguised_program_is_suspect() {
        use crate::filetype::{Kind, TypeMismatch};
        let mut r = report(EngineResult::Clean, VtFileResult::Unknown, None);
        r.type_mismatch = Some(TypeMismatch {
            extension: "pdf".into(),
            detected: Kind::WindowsProgram,
            detected_label: Kind::WindowsProgram.label().into(),
            disguised_program: true,
        });
        assert_eq!(decide(r, T).level, VerdictLevel::Suspect);
        let mut r = report(EngineResult::Clean, VtFileResult::Unknown, None);
        r.type_mismatch = Some(TypeMismatch {
            extension: "jpg".into(),
            detected: Kind::Png,
            detected_label: Kind::Png.label().into(),
            disguised_program: false,
        });
        assert_eq!(decide(r, T).level, VerdictLevel::Clean);
    }
}
