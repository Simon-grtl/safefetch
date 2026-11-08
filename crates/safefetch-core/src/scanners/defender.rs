//! Microsoft Defender command-line scan (Windows only).
//!
//! `MpCmdRun.exe -Scan -ScanType 3 -File <path> -DisableRemediation`
//! - exit code 0: no threat; 2: threat found; anything else: error.
//! - `-DisableRemediation` keeps Defender from deleting the file itself, so
//!   SafeFetch remains the one deciding (and reporting) what happens.
//!
//! Uncertainty (documented in DECISIONS.md): Microsoft does not document
//! Defender's size/archive limits for custom scans, so a "clean" result from
//! Defender alone is never enough for a Clean verdict; ClamAV must also be
//! complete.

use std::path::{Path, PathBuf};

use crate::verdict::EngineResult;

/// Extract threat names from MpCmdRun output ("Threat   : Virus:DOS/EICAR_Test_File").
pub fn parse_output(stdout: &str, exit_code: Option<i32>) -> EngineResult {
    let threats: Vec<String> = stdout
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("Threat")?;
            let (_, name) = rest.split_once(':')?;
            let name = name.trim();
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect();
    match exit_code {
        Some(0) => EngineResult::Clean,
        Some(2) => EngineResult::Infected(if threats.is_empty() {
            vec!["threat detected".into()]
        } else {
            threats
        }),
        other => {
            let last = stdout
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .trim();
            EngineResult::Error(format!("MpCmdRun exit {other:?}: {last}"))
        }
    }
}

/// Locate MpCmdRun.exe: newest platform folder first, then the legacy path.
pub fn find_mpcmdrun() -> Option<PathBuf> {
    if !cfg!(windows) {
        return None;
    }
    let mut candidates = Vec::new();
    if let Some(pd) = std::env::var_os("ProgramData") {
        let platform = Path::new(&pd)
            .join("Microsoft")
            .join("Windows Defender")
            .join("Platform");
        if let Ok(rd) = std::fs::read_dir(&platform) {
            let mut versions: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            versions.sort(); // version folders sort lexicographically well enough; newest last
            candidates.extend(versions.into_iter().rev().map(|v| v.join("MpCmdRun.exe")));
        }
    }
    if let Some(pf) = std::env::var_os("ProgramFiles") {
        candidates.push(Path::new(&pf).join("Windows Defender").join("MpCmdRun.exe"));
    }
    candidates.into_iter().find(|p| p.is_file())
}

pub async fn scan(file: &Path) -> EngineResult {
    let Some(exe) = find_mpcmdrun() else {
        return EngineResult::Unavailable("Microsoft Defender (MpCmdRun.exe) not found".into());
    };
    let mut cmd = tokio::process::Command::new(exe);
    crate::fsutil::no_console_window(&mut cmd);
    cmd.args(["-Scan", "-ScanType", "3", "-File"])
        .arg(file)
        .arg("-DisableRemediation")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(std::time::Duration::from_secs(3600), cmd.output()).await {
        Err(_) => EngineResult::Error("Defender scan timed out".into()),
        Ok(Err(e)) => EngineResult::Unavailable(format!("cannot run MpCmdRun: {e}")),
        Ok(Ok(out)) => parse_output(&String::from_utf8_lossy(&out.stdout), out.status.code()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        assert_eq!(
            parse_output("Scan starting...\nScan finished.\n", Some(0)),
            EngineResult::Clean
        );
        let out = "Scan starting...\nScan finished.\nScanning C:\\q\\x found 1 threats.\n\
                   <===========================LIST OF DETECTED THREATS==========================>\n\
                   ----------------------------- Threat information ------------------------------\n\
                   Threat                  : Virus:DOS/EICAR_Test_File\nResources               : 1 total\n";
        assert_eq!(
            parse_output(out, Some(2)),
            EngineResult::Infected(vec!["Virus:DOS/EICAR_Test_File".into()])
        );
        assert!(matches!(
            parse_output("failed", Some(-2147024894)),
            EngineResult::Error(_)
        ));
        assert!(matches!(parse_output("", None), EngineResult::Error(_)));
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn unavailable_off_windows() {
        assert!(matches!(
            scan(Path::new("/nonexistent")).await,
            EngineResult::Unavailable(_)
        ));
    }
}
