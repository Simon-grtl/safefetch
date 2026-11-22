//! ClamAV signature updates that work without a terminal.
//!
//! Why the plain `freshclam` call was not enough:
//! - **Windows / macOS (official installers):** `freshclam.conf` does not exist
//!   until the user copies the sample and deletes the `Example` line, and the
//!   database lives in a folder only an administrator can write.
//! - **Linux:** the database belongs to the `clamav` user and is maintained by
//!   the `clamav-freshclam` service; `freshclam` run by the user fails (and
//!   would conflict with the service anyway).
//!
//! What SafeFetch does now:
//! - Linux: if the `clamav-freshclam` service is active, nothing to do. If it
//!   exists but is stopped, the user can enable it in one click (`pkexec`
//!   shows the system password prompt).
//! - Everywhere else (and on Linux without the service): if the system update
//!   fails, SafeFetch keeps its **own copy** of the signatures in the user's
//!   profile (`freshclam --config-file=<ours> --datadir=<ours>`, no
//!   administrator rights) and scans with `clamscan --database=<ours>`.
//! - Windows: one click creates a daily Scheduled Task running that same
//!   update, so signatures stay fresh while SafeFetch is closed.
//!
//! All programs are started by absolute path with an argument vector.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;

use crate::scanners::clamav::find_executable;
use crate::settings::ClamAvSettings;

const FRESHCLAM_TIMEOUT: Duration = Duration::from_secs(900);
/// Name of the Windows Scheduled Task (root folder: creating a sub-folder
/// may need administrator rights).
pub const TASK_NAME: &str = "SafeFetch - ClamAV signature update";
pub const LINUX_SERVICE: &str = "clamav-freshclam.service";

/// SafeFetch's private signature store (inside the app data folder).
#[derive(Debug, Clone)]
pub struct Managed {
    pub root: PathBuf,
}

impl Managed {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("clamav"),
        }
    }
    pub fn database_dir(&self) -> PathBuf {
        self.root.join("database")
    }
    pub fn config_file(&self) -> PathBuf {
        self.root.join("freshclam.conf")
    }
    /// True when clamscan is configured to use this store.
    pub fn in_use(&self, s: &ClamAvSettings) -> bool {
        s.database_dir.as_deref() == Some(self.database_dir().as_path())
    }

    /// Create the folders and a minimal freshclam.conf. The database folder
    /// is passed with `--datadir` (an argument, so paths with spaces are safe).
    pub fn prepare(&self) -> std::io::Result<()> {
        crate::fsutil::create_private_dir(&self.root).map_err(std::io::Error::other)?;
        crate::fsutil::create_private_dir(&self.database_dir()).map_err(std::io::Error::other)?;
        let conf = "# Written by SafeFetch: ClamAV signatures kept in your user profile,\n\
                    # updated without administrator rights. Do not edit.\n\
                    DatabaseMirror database.clamav.net\n";
        crate::fsutil::write_atomic(&self.config_file(), conf.as_bytes())
            .map_err(std::io::Error::other)
    }

    pub fn freshclam_args(&self) -> Vec<OsString> {
        let mut conf = OsString::from("--config-file=");
        conf.push(self.config_file().as_os_str());
        let mut data = OsString::from("--datadir=");
        data.push(self.database_dir().as_os_str());
        vec!["--stdout".into(), conf, data]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Active,
    Inactive,
    Missing,
}

/// What the UI needs to offer the right button.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureStatus {
    /// Signatures come from SafeFetch's private store.
    pub managed: bool,
    pub managed_dir: Option<String>,
    /// Linux only: state of the clamav-freshclam system service.
    pub service: Option<ServiceState>,
    /// Windows only: whether the daily Scheduled Task exists.
    pub scheduled_task: Option<bool>,
}

/// Successful update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReport {
    pub message: String,
    /// Switch clamscan to this database folder (SafeFetch's private store).
    pub use_database: Option<PathBuf>,
}

fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Run a program (absolute path, argument vector) and return (success, output tail).
async fn run(exe: &Path, args: &[OsString], timeout: Duration) -> Result<(bool, String), String> {
    let mut cmd = tokio::process::Command::new(exe);
    crate::fsutil::no_console_window(&mut cmd);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let out = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| format!("{name} timed out"))?
        .map_err(|e| format!("cannot run {name}: {e}"))?;
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    Ok((out.status.success(), tail(&text, 8)))
}

fn freshclam_exe(s: &ClamAvSettings) -> Result<PathBuf, String> {
    s.freshclam_path
        .clone()
        .or_else(|| find_executable("freshclam"))
        .ok_or_else(|| {
            "freshclam not found: install ClamAV first (see “How to install ClamAV”)".into()
        })
}

/// Update the signatures, choosing the method that works on this system.
pub async fn update(s: &ClamAvSettings, managed: &Managed) -> Result<UpdateReport, String> {
    let exe = freshclam_exe(s)?;
    if managed.in_use(s) {
        return run_managed(&exe, managed)
            .await
            .map(|message| UpdateReport {
                message,
                use_database: None,
            });
    }
    let service = service_state().await;
    if service == Some(ServiceState::Active) && s.database_dir.is_none() {
        return Ok(UpdateReport {
            message: "Signatures are kept up to date by the clamav-freshclam system service; nothing to do.".into(),
            use_database: None,
        });
    }
    let system = match run(&exe, &["--stdout".into()], FRESHCLAM_TIMEOUT).await {
        Ok((true, out)) => {
            return Ok(UpdateReport {
                message: out,
                use_database: None,
            })
        }
        Ok((false, out)) => out,
        Err(e) => e,
    };
    if service == Some(ServiceState::Inactive) {
        return Err(format!(
            "{system}\n\nOn this system ClamAV signatures are updated by the clamav-freshclam service, which is not running. Click “Enable automatic updates” (your password will be asked)."
        ));
    }
    if s.database_dir.is_some() {
        // A database folder chosen by hand in settings.json: never replaced.
        return Err(system);
    }
    match run_managed(&exe, managed).await {
        Ok(out) => Ok(UpdateReport {
            message: format!(
                "The system-wide update failed, so SafeFetch now keeps its own copy of the signatures in {} (no administrator rights needed).\n{out}",
                managed.database_dir().display()
            ),
            use_database: Some(managed.database_dir()),
        }),
        Err(own) => Err(format!(
            "System-wide update failed:\n{system}\n\nSafeFetch's own update also failed:\n{own}"
        )),
    }
}

async fn run_managed(exe: &Path, managed: &Managed) -> Result<String, String> {
    managed
        .prepare()
        .map_err(|e| format!("cannot prepare {}: {e}", managed.root.display()))?;
    match run(exe, &managed.freshclam_args(), FRESHCLAM_TIMEOUT).await? {
        (true, out) => Ok(out),
        (false, out) => Err(out),
    }
}

pub async fn status(s: &ClamAvSettings, managed: &Managed) -> SignatureStatus {
    let in_use = managed.in_use(s);
    SignatureStatus {
        managed: in_use,
        managed_dir: in_use.then(|| managed.database_dir().display().to_string()),
        service: service_state().await,
        scheduled_task: scheduled_task_exists().await,
    }
}

// ------------------------------------------------------------------ Linux --

#[cfg(target_os = "linux")]
fn systemctl() -> Option<PathBuf> {
    ["/usr/bin/systemctl", "/bin/systemctl"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// State of the clamav-freshclam service (None outside Linux / without systemd).
pub async fn service_state() -> Option<ServiceState> {
    #[cfg(target_os = "linux")]
    {
        let sc = systemctl()?;
        let t = Duration::from_secs(10);
        let listed = run(
            &sc,
            &[
                "list-unit-files".into(),
                "--no-legend".into(),
                "--no-pager".into(),
                LINUX_SERVICE.into(),
            ],
            t,
        )
        .await
        .ok()?;
        if !listed.1.contains("clamav-freshclam") {
            return Some(ServiceState::Missing);
        }
        let active = run(&sc, &["is-active".into(), LINUX_SERVICE.into()], t)
            .await
            .ok()?;
        Some(if active.0 && active.1.trim() == "active" {
            ServiceState::Active
        } else {
            ServiceState::Inactive
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Enable and start the clamav-freshclam service. `pkexec` shows the
/// desktop's password prompt (polkit); nothing runs without the user's consent.
pub async fn enable_service() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        let sc = systemctl().ok_or("systemd not found")?;
        let pkexec = ["/usr/bin/pkexec", "/bin/pkexec"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or("pkexec (polkit) is not installed: run `sudo systemctl enable --now clamav-freshclam.service` in a terminal")?;
        let (ok, out) = run(
            &pkexec,
            &[
                sc.into_os_string(),
                "enable".into(),
                "--now".into(),
                LINUX_SERVICE.into(),
            ],
            Duration::from_secs(300),
        )
        .await?;
        if !ok {
            return Err(if out.is_empty() {
                "cancelled or not authorized".into()
            } else {
                out
            });
        }
        Ok("Automatic signature updates are enabled (clamav-freshclam service).".into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("only available on Linux".into())
    }
}

// ---------------------------------------------------------------- Windows --

#[cfg(windows)]
fn system32(exe: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    Path::new(&root).join("System32").join(exe)
}

pub async fn scheduled_task_exists() -> Option<bool> {
    #[cfg(windows)]
    {
        let r = run(
            &system32("schtasks.exe"),
            &["/Query".into(), "/TN".into(), TASK_NAME.into()],
            Duration::from_secs(20),
        )
        .await
        .ok()?;
        Some(r.0)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Quote one argument for a Windows command line (CommandLineToArgvW rules).
fn win_quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// Task Scheduler XML: daily run as the current user, least privilege,
/// catches up after a missed run, no window (conhost --headless).
pub fn task_xml(conhost: &str, freshclam: &str, args: &[String], minute: u32) -> String {
    let mut arguments = vec!["--headless".to_string(), win_quote(freshclam)];
    arguments.extend(args.iter().map(|a| win_quote(a)));
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Daily ClamAV signature update for SafeFetch (created from SafeFetch; delete it there or in Task Scheduler).</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-01-01T12:{minute:02}:00</StartBoundary>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
      <Arguments>{}</Arguments>
    </Exec>
  </Actions>
</Task>
"#,
        xml_escape(conhost),
        xml_escape(&arguments.join(" "))
    )
}

/// Create (or replace) the daily Scheduled Task running freshclam with the
/// same arguments SafeFetch uses. Windows only; no administrator rights.
pub async fn schedule_task(s: &ClamAvSettings, managed: &Managed) -> Result<String, String> {
    #[cfg(windows)]
    {
        let exe = freshclam_exe(s)?;
        let args: Vec<String> = if managed.in_use(s) {
            managed
                .freshclam_args()
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        } else {
            vec!["--stdout".into()]
        };
        let minute = u32::from_str_radix(&crate::fsutil::random_hex(1), 16).unwrap_or(7) % 60;
        let xml = task_xml(
            &system32("conhost.exe").display().to_string(),
            &exe.display().to_string(),
            &args,
            minute,
        );
        // schtasks /XML expects UTF-16 LE with a byte-order mark.
        let mut bytes = vec![0xff, 0xfe];
        for u in xml.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        crate::fsutil::create_private_dir(&managed.root).map_err(|e| e.to_string())?;
        let file = managed.root.join("scheduled-task.xml");
        crate::fsutil::write_atomic(&file, &bytes).map_err(|e| e.to_string())?;
        let (ok, out) = run(
            &system32("schtasks.exe"),
            &[
                "/Create".into(),
                "/TN".into(),
                TASK_NAME.into(),
                "/XML".into(),
                file.into_os_string(),
                "/F".into(),
            ],
            Duration::from_secs(30),
        )
        .await?;
        if ok {
            Ok(format!(
                "Daily signature update scheduled (Task Scheduler: “{TASK_NAME}”)."
            ))
        } else {
            Err(out)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (s, managed);
        Err("only available on Windows".into())
    }
}

pub async fn unschedule_task() -> Result<String, String> {
    #[cfg(windows)]
    {
        let (ok, out) = run(
            &system32("schtasks.exe"),
            &[
                "/Delete".into(),
                "/TN".into(),
                TASK_NAME.into(),
                "/F".into(),
            ],
            Duration::from_secs(30),
        )
        .await?;
        if ok {
            Ok("The daily signature update task was removed.".into())
        } else {
            Err(out)
        }
    }
    #[cfg(not(windows))]
    {
        Err("only available on Windows".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_quoting() {
        assert_eq!(win_quote("--stdout"), "--stdout");
        assert_eq!(
            win_quote(r"--datadir=C:\Users\Jean Dupont\db"),
            r#""--datadir=C:\Users\Jean Dupont\db""#
        );
        assert_eq!(win_quote(r"C:\a b\"), r#""C:\a b\\""#);
        assert_eq!(win_quote(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn task_xml_is_escaped_and_headless() {
        let x = task_xml(
            r"C:\Windows\System32\conhost.exe",
            r"C:\Program Files\ClamAV\freshclam.exe",
            &[r"--config-file=C:\Users\A&B\f.conf".into()],
            5,
        );
        assert!(x.contains("--headless &quot;C:\\Program Files\\ClamAV\\freshclam.exe&quot;"));
        assert!(x.contains("A&amp;B"));
        assert!(x.contains("T12:05:00"));
        assert!(x.contains("<RunLevel>LeastPrivilege</RunLevel>"));
    }

    #[test]
    fn managed_store_layout() {
        let d = tempfile::tempdir().unwrap();
        let m = Managed::new(d.path());
        m.prepare().unwrap();
        let conf = std::fs::read_to_string(m.config_file()).unwrap();
        assert!(conf.contains("DatabaseMirror database.clamav.net"));
        assert!(!conf.contains("Example"));
        assert!(m.database_dir().is_dir());
        let args = m.freshclam_args();
        assert!(args[2].to_string_lossy().starts_with("--datadir="));
        let mut s = ClamAvSettings::default();
        assert!(!m.in_use(&s));
        s.database_dir = Some(m.database_dir());
        assert!(m.in_use(&s));
    }

    #[tokio::test]
    async fn missing_freshclam_is_reported() {
        let d = tempfile::tempdir().unwrap();
        let s = ClamAvSettings {
            freshclam_path: Some(d.path().join("no-such-freshclam")),
            database_dir: Some(d.path().join("custom")),
            ..Default::default()
        };
        // A hand-chosen database folder is never replaced by the private store.
        let r = update(&s, &Managed::new(d.path())).await;
        assert!(r.is_err());
        assert!(!Managed::new(d.path()).database_dir().exists());
    }
}
