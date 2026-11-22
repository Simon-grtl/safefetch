//! Maintainer commands, run through cargo aliases (see `.cargo/config.toml`):
//!
//! ```text
//! cargo bump 0.2.0          # set the version everywhere it is written
//! cargo bump --check        # all files agree?
//! cargo bump --check 0.2.0  # all files say 0.2.0? (used by the release workflow)
//! ```
//!
//! Standard library only, so it behaves the same on Windows, macOS and Linux.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Packages of the workspace whose version follows `workspace.package`.
const PACKAGES: &[&str] = &["safefetch", "safefetch-core"];

/// The workspace root: the nearest folder, from the current one upwards,
/// whose Cargo.toml declares `[workspace]`. Found at run time (a path baked in
/// at compile time would point at another checkout sharing the build cache).
fn root() -> Result<PathBuf, String> {
    let start = std::env::current_dir().map_err(|e| e.to_string())?;
    start
        .ancestors()
        .find(|d| {
            std::fs::read_to_string(d.join("Cargo.toml"))
                .is_ok_and(|t| t.lines().any(|l| l.trim() == "[workspace]"))
        })
        .map(Path::to_path_buf)
        .ok_or_else(|| "run this inside the SafeFetch repository".into())
}

fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

/// One place where the version is written.
struct Spot {
    file: &'static str,
    /// Current version found in `text`.
    read: fn(&str) -> Option<String>,
    /// New text with the version replaced.
    write: fn(&str, &str) -> Option<String>,
}

fn quoted_after<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix(prefix)?;
    let rest = rest.trim_start().strip_prefix('"')?;
    rest.split('"').next()
}

/// `version = "x"` inside `[workspace.package]` of the root Cargo.toml.
fn cargo_toml_read(text: &str) -> Option<String> {
    let mut in_section = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_section = t == "[workspace.package]";
            continue;
        }
        if in_section {
            if let Some(v) = quoted_after(t, "version =") {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn cargo_toml_write(text: &str, new: &str) -> Option<String> {
    let mut in_section = false;
    let mut done = false;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let t = line.trim();
        if t.starts_with('[') {
            in_section = t == "[workspace.package]";
        } else if in_section && !done && quoted_after(t, "version =").is_some() {
            out.push_str(&format!("version = \"{new}\"\n"));
            done = true;
            continue;
        }
        out.push_str(line);
    }
    done.then_some(out)
}

/// Top-level `"version": "x"` of tauri.conf.json (the first one, at 2 spaces).
fn tauri_read(text: &str) -> Option<String> {
    text.lines()
        .find(|l| l.starts_with("  \"version\":"))
        .and_then(|l| quoted_after(l.trim_start().strip_prefix("\"version\":")?, ""))
        .map(str::to_string)
}

fn tauri_write(text: &str, new: &str) -> Option<String> {
    let mut done = false;
    let out: String = text
        .split_inclusive('\n')
        .map(|l| {
            if !done && l.starts_with("  \"version\":") {
                done = true;
                let comma = if l.trim_end().ends_with(',') { "," } else { "" };
                format!("  \"version\": \"{new}\"{comma}\n")
            } else {
                l.to_string()
            }
        })
        .collect();
    done.then_some(out)
}

fn pkgbuild_read(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("pkgver="))
        .map(|v| v.trim().to_string())
}

fn pkgbuild_write(text: &str, new: &str) -> Option<String> {
    let mut found = false;
    let out: String = text
        .split_inclusive('\n')
        .map(|l| {
            if l.starts_with("pkgver=") {
                found = true;
                format!("pkgver={new}\n")
            } else if l.starts_with("pkgrel=") {
                // A new upstream version starts again at release 1.
                "pkgrel=1\n".to_string()
            } else {
                l.to_string()
            }
        })
        .collect();
    found.then_some(out)
}

/// `version` of the workspace packages in Cargo.lock (all must agree).
fn lock_read(text: &str) -> Option<String> {
    let mut versions = Vec::new();
    let mut current: Option<&str> = None;
    for line in text.lines() {
        if let Some(n) = quoted_after(line, "name =") {
            current = Some(n);
        } else if let (Some(n), Some(v)) = (current, quoted_after(line, "version =")) {
            if PACKAGES.contains(&n) {
                versions.push(v.to_string());
            }
            current = None;
        }
    }
    match versions.as_slice() {
        [first, rest @ ..]
            if versions.len() == PACKAGES.len() && rest.iter().all(|v| v == first) =>
        {
            Some(first.clone())
        }
        [] => None,
        _ => Some(format!("(differs: {})", versions.join(", "))),
    }
}

fn lock_write(text: &str, new: &str) -> Option<String> {
    let mut current: Option<String> = None;
    let mut changed = 0;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if let Some(n) = quoted_after(line, "name =") {
            current = Some(n.to_string());
        } else if quoted_after(line, "version =").is_some() {
            if current.as_deref().is_some_and(|n| PACKAGES.contains(&n)) {
                out.push_str(&format!("version = \"{new}\"\n"));
                changed += 1;
                current = None;
                continue;
            }
            current = None;
        }
        out.push_str(line);
    }
    (changed == PACKAGES.len()).then_some(out)
}

const SPOTS: &[Spot] = &[
    Spot {
        file: "Cargo.toml",
        read: cargo_toml_read,
        write: cargo_toml_write,
    },
    Spot {
        file: "Cargo.lock",
        read: lock_read,
        write: lock_write,
    },
    Spot {
        file: "src-tauri/tauri.conf.json",
        read: tauri_read,
        write: tauri_write,
    },
    Spot {
        file: "packaging/arch/PKGBUILD",
        read: pkgbuild_read,
        write: pkgbuild_write,
    },
];

fn read(root: &Path, file: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(file)).map_err(|e| format!("{file}: {e}"))
}

fn check(root: &Path, expected: Option<&str>) -> Result<String, String> {
    let mut found = Vec::new();
    for s in SPOTS {
        let text = read(root, s.file)?;
        let v = (s.read)(&text).ok_or_else(|| format!("{}: version not found", s.file))?;
        found.push((s.file, v));
    }
    let reference = expected.map_or_else(|| found[0].1.clone(), str::to_string);
    let wrong: Vec<String> = found
        .iter()
        .filter(|(_, v)| *v != reference)
        .map(|(f, v)| format!("  {f}: {v}"))
        .collect();
    if wrong.is_empty() {
        Ok(reference)
    } else {
        Err(format!(
            "expected version {reference}, but:\n{}\nRun: cargo bump {reference}",
            wrong.join("\n")
        ))
    }
}

fn bump(root: &Path, new: &str) -> Result<(), String> {
    // Prepare everything first: nothing is written unless every file can change.
    let mut updates = Vec::new();
    for s in SPOTS {
        let text = read(root, s.file)?;
        let updated = (s.write)(&text, new)
            .ok_or_else(|| format!("{}: could not find where the version is written", s.file))?;
        updates.push((s.file, updated));
    }
    for (file, text) in updates {
        std::fs::write(root.join(file), text).map_err(|e| format!("{file}: {e}"))?;
        println!("  updated {file}");
    }
    check(root, Some(new)).map(|_| ())
}

fn usage() -> ExitCode {
    eprintln!("usage: cargo bump <X.Y.Z> | cargo bump --check [X.Y.Z]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let root = match root() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Accept "v0.2.0" too (a tag name).
    let norm = |v: &str| v.trim().trim_start_matches('v').to_string();
    let result = match args.as_slice() {
        ["bump", "--check"] => check(&root, None).map(|v| format!("All files say {v}.")),
        ["bump", "--check", v] => {
            let v = norm(v);
            check(&root, Some(&v)).map(|v| format!("All files say {v}."))
        }
        ["bump", v] if !v.starts_with('-') => {
            let v = norm(v);
            if !valid_version(&v) {
                eprintln!("error: \"{v}\" is not a version like 0.2.0");
                return ExitCode::from(2);
            }
            bump(&root, &v).map(|()| {
                format!(
                    "Version set to {v}. Next steps:\n  git commit -am \"Release v{v}\"\n  git tag v{v}\n  git push origin HEAD v{v}\nThe tag starts the Release workflow (draft release with signed installers)."
                )
            })
        }
        _ => return usage(),
    };
    match result {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARGO: &str = "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[profile.release]\nversion = \"9\"\n";
    const LOCK: &str = "[[package]]\nname = \"safefetch\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"safefetch-core\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"0.1.0\"\n";
    const TAURI: &str = "{\n  \"productName\": \"SafeFetch\",\n  \"version\": \"0.1.0\",\n  \"plugins\": { \"x\": { \"version\": \"1\" } }\n}\n";
    const PKG: &str = "pkgname=safefetch\npkgver=0.1.0\npkgrel=3\n";

    #[test]
    fn versions() {
        assert!(valid_version("0.2.0"));
        assert!(valid_version("10.20.30"));
        for bad in ["0.2", "0.2.0-rc1", "01.2.3", "a.b.c", ""] {
            assert!(!valid_version(bad), "{bad}");
        }
    }

    #[test]
    fn rewrites_only_the_right_lines() {
        let c = cargo_toml_write(CARGO, "0.2.0").unwrap();
        assert_eq!(cargo_toml_read(&c).as_deref(), Some("0.2.0"));
        assert!(c.contains("[profile.release]\nversion = \"9\""));
        let l = lock_write(LOCK, "0.2.0").unwrap();
        assert_eq!(lock_read(&l).as_deref(), Some("0.2.0"));
        assert!(l.contains("name = \"serde\"\nversion = \"0.1.0\""));
        let t = tauri_write(TAURI, "0.2.0").unwrap();
        assert_eq!(tauri_read(&t).as_deref(), Some("0.2.0"));
        assert!(t.contains("\"version\": \"1\""));
        let p = pkgbuild_write(PKG, "0.2.0").unwrap();
        assert_eq!(pkgbuild_read(&p).as_deref(), Some("0.2.0"));
        assert!(p.contains("pkgrel=1\n"));
    }

    #[test]
    fn whole_repository_round_trip() {
        let d = std::env::temp_dir().join(format!("xtask-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for (f, t) in [
            ("Cargo.toml", CARGO),
            ("Cargo.lock", LOCK),
            ("src-tauri/tauri.conf.json", TAURI),
            ("packaging/arch/PKGBUILD", PKG),
        ] {
            let p = d.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, t).unwrap();
        }
        assert_eq!(check(&d, None).unwrap(), "0.1.0");
        assert!(check(&d, Some("0.2.0")).is_err());
        bump(&d, "0.2.0").unwrap();
        assert_eq!(check(&d, Some("0.2.0")).unwrap(), "0.2.0");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_real_repository_is_consistent() {
        check(&root().unwrap(), None).unwrap();
    }
}
