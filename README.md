# SafeFetch

Download files **into quarantine**, check them, and deliver **only clean files** to your folder.
Free, open source (MIT), for Windows, macOS and Linux.

```
paste links ─► VirusTotal link check ─► download to quarantine ─► SHA-256 ─► VirusTotal hash
            ─► ClamAV (+ Defender on Windows) ─► ✅ delivered | ⚠️ you decide | ❌ deleted
```

## What it does
- One link per line, optionally followed by the expected SHA-256.
- Links known as malicious by VirusTotal are blocked **before** anything is downloaded.
- Files are streamed (constant memory — tested with 3 GiB) into a hidden quarantine folder inside your destination, under a random non-executable name, with resume after network cuts.
- The file is never opened or executed. It is hashed, looked up on VirusTotal **by hash only**, and scanned by ClamAV (and Microsoft Defender on Windows).
- **Clean** → moved atomically to your folder with a cleaned name. **Dangerous** → deleted with a detailed alert. **Suspect / Not analyzed** → stays in quarantine until you release or delete it.
- The same link or the same content is never downloaded/delivered twice.

## What it cannot do (please read)
- Antivirus engines only recognize **known** threats. "Clean" means *no engine flagged it*, not *guaranteed safe*.
- **ClamAV cannot scan files of 2 GiB or more.** Such files (ISOs, large archives…) always end up "Not analyzed": you decide, ideally by comparing the publisher's SHA-256.
- Encrypted archives (password-protected ZIPs…) cannot be inspected → "Not analyzed".
- Without a VirusTotal API key, there is no link reputation check and no hash lookup.
- A program already running on your computer with your rights could tamper with files; SafeFetch does not sandbox the OS.

## Install
See [docs/INSTALL.md](docs/INSTALL.md). In short: install ClamAV, update its signatures, install SafeFetch, choose a destination folder, optionally add a free VirusTotal API key.

## Build from source
```bash
# Linux deps (Debian/Ubuntu)
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev libdbus-1-dev clamav
cargo install tauri-cli --version "^2" --locked
cargo test --workspace            # 90+ tests incl. EICAR, zip bombs, resume, redirects
cargo tauri dev                   # run in development
cargo tauri build                 # installers in target/release/bundle/
```
Development with runtime inspection (tauri-connector, never in release builds):
`cargo tauri dev --features dev-connector --config src-tauri/tauri.dev.conf.json`

## Project layout
| Path | Content |
|---|---|
| `crates/safefetch-core` | All logic (download, quarantine, scanners, verdict, delivery) + tests |
| `src-tauri` | Tauri adapter: commands, keychain, capabilities, config |
| `ui` | The single window (HTML/CSS/JS, no framework) |
| `docs/ARCHITECTURE.md` | Modules, data flow, threat model |
| `DECISIONS.md` | Why things are the way they are |
| `SECURITY_AUDIT.md` | Audit findings and fixes |
| `.claude/claude-security-guidance.md` | Security rules every change must respect |
