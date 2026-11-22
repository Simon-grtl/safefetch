# SafeFetch

Download files **into quarantine**, check them, and deliver **only clean files** to your folder.
Free, open source (MIT), for Windows, macOS and Linux.

```
paste links ─► VirusTotal link check ─► download to quarantine ─► SHA-256 ─► VirusTotal hash
            ─► ClamAV (+ Defender on Windows) ─► ✅ delivered | ⚠️ you decide | ❌ deleted
```

## What it does
- One link per line, optionally followed by the expected SHA-256 **or the link to the publisher's `SHA256SUMS` file** (SafeFetch finds the line for the file and compares).
- **Analyze files already on your computer**: "Analyze local files…" or drop them on the window. They are hashed and scanned in place, never moved, modified or deleted.
- Links known as malicious by VirusTotal are blocked **before** anything is downloaded.
- Files are streamed (constant memory — tested with 3 GiB) into a hidden quarantine folder inside your destination, under a random non-executable name, with resume after network cuts.
- The file is never opened or executed. It is hashed, looked up on VirusTotal **by hash only**, and scanned by ClamAV (and Microsoft Defender on Windows).
- **Clean** → moved atomically to your folder with a cleaned name. **Dangerous** → deleted with a detailed alert. **Suspect / Not analyzed** → stays in quarantine until you release or delete it.
- The same link or the same content is never downloaded/delivered twice.
- **Real type vs. extension**: a program disguised as a document (`invoice.pdf` that is really a Windows `.exe`) is Suspect and stays in quarantine.
- **Weekly re-check** (with a VirusTotal key): the SHA-256 of every delivered file is looked up again once a week; a file detected after its delivery raises an alert in the window.
- **ClamAV signatures without a terminal**: on Linux, one click enables the `clamav-freshclam` service; on Windows/macOS, if the system update needs administrator rights, SafeFetch keeps its own copy of the signatures in your profile; on Windows, one click creates a daily Scheduled Task.

## What it cannot do (please read)
- Antivirus engines only recognize **known** threats. "Clean" means *no engine flagged it*, not *guaranteed safe*.
- **ClamAV cannot scan files of 2 GiB or more.** Such files (ISOs, large archives…) always end up "Not analyzed": you decide, ideally with the publisher's SHA-256 or `SHA256SUMS` link (a match is shown as "Publisher checksum ✓"). The list's GPG signature is not verified yet: a match proves the file is the one the publisher's site lists, not that the site itself is uncompromised.
- A program containing stray ZIP header bytes can be reported "Not analyzed" (ClamAV cannot unpack the fake archive): the safe direction.
- Encrypted archives (password-protected ZIPs…) cannot be inspected → "Not analyzed".
- Without a VirusTotal API key, there is no link reputation check and no hash lookup.
- A program already running on your computer with your rights could tamper with files; SafeFetch does not sandbox the OS.

## Install
Windows, macOS, Linux (Debian/Ubuntu, Fedora, **Arch Linux, CachyOS** via the PKGBUILD in `packaging/arch`, or AppImage). See [docs/INSTALL.md](docs/INSTALL.md). In short: install ClamAV, update its signatures, install SafeFetch, choose a destination folder, optionally add a free VirusTotal API key.

## Build from source
```bash
# Linux deps (Debian/Ubuntu)
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev libdbus-1-dev clamav
# Linux deps (Arch Linux / CachyOS)
sudo pacman -S --needed base-devel rust webkit2gtk-4.1 gtk3 dbus clamav
cargo install tauri-cli --version "^2" --locked
cargo test --workspace            # 150+ tests incl. EICAR, zip bombs, resume, redirects
cargo tauri dev                   # run in development
cargo tauri build                 # installers in target/release/bundle/
```
Development with runtime inspection (tauri-connector, never in release builds):
`cargo tauri dev --features dev-connector --config src-tauri/tauri.dev.conf.json`

## Use of AI
SafeFetch was built with the help of an AI assistant (Claude, by Anthropic): code, tests, documentation and security reviews were produced with AI assistance, under the direction of the project's author. The security audit findings and the decisions taken are documented in `SECURITY_AUDIT.md` and `DECISIONS.md`.

## Project layout
| Path | Content |
|---|---|
| `crates/safefetch-core` | All logic (download, quarantine, scanners, verdict, delivery) + tests |
| `src-tauri` | Tauri adapter: commands, keychain, capabilities, config |
| `ui` | The single window (HTML/CSS/JS, no framework) |
| `xtask` | Maintainer commands: `cargo bump 0.2.0` sets the version in every file |
| `docs/ARCHITECTURE.md` | Modules, data flow, threat model |
| `DECISIONS.md` | Why things are the way they are |
| `SECURITY_AUDIT.md` | Audit findings and fixes |
| `.claude/claude-security-guidance.md` | Security rules every change must respect |
