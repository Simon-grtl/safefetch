# DECISIONS.md — SafeFetch

Short, dated record of the choices that shape the project. Update it whenever a
choice changes; keep the "why" and the alternative that was rejected.

## 2026-11-08 — Initial build (phases 1 → 9)

### Stack
- **Rust + Tauri 2 (stable 2.x), vanilla HTML/CSS/JS front-end, no bundler.**
  Why: memory safety, small binaries (~12 MB release binary on Linux), one code base for 3 OSes, capability-based IPC.
  Rejected: Electron (heavier, larger attack surface), Tauri 3 alpha (not stable), a JS framework (more dependencies, no benefit for one window).
- **All logic in `crates/safefetch-core`, GUI-independent.** The Tauri crate is an adapter. Lets the whole pipeline be tested headless with real HTTP servers and real ClamAV.

### Download & quarantine
- **Quarantine = `<destination>/.safefetch-quarantine/`** (0700, hidden attribute on Windows). Guarantees the same volume, so delivery is atomic and copy-free. Alternative (separate folder elsewhere) rejected: needs a cross-volume copy or a same-volume check on Windows that `std` cannot express.
- **Random 128-bit names + `.quarantine` extension + mode 0600 + MOTW/`com.apple.quarantine`.** No association → double-click does not run anything.
- **Manual redirect loop** (max 5 by default) validating every hop; no https→http; public→private hops refused; a DNS resolver that refuses private addresses when the user typed a public URL (DNS-rebinding defence); and each redirect target is resolved locally and must be public, which also holds when a system proxy is used (audit F3). Names internal by convention or resolving to private IPs are refused; names that do not resolve locally are allowed, so proxy-only-DNS corporate networks keep working (re-audit).
- **Re-open after a check goes to the checked URL** (audit M1): the VirusTotal-checked final URL is requested directly; if it expired, the original link is followed and must land on the same scheme/host/port/path.
- **VirusTotal never receives user:password or #fragment** of a link (audit M2).
- **A finished download is never discarded because of a later error** (scan/delivery): it stays in quarantine (audit M3).
- **When the redirect target is on another host, VirusTotal checks the final URL before its body is read.**
- **Resume:** `Range` + `If-Range` (strong ETag, else Last-Modified); 200 ⇒ restart from 0; 206 at the wrong offset ⇒ restart; size change between attempts ⇒ restart; redirect target host change while resuming ⇒ refused.
- **`Accept-Encoding: identity` and no decompression features in reqwest**, so Content-Length = file bytes and no transport-level decompression bomb.
- **Never download twice:** history of SHA-256(URL) and file SHA-256 (no plain URLs stored). Same link already delivered (file still present) ⇒ not fetched. Same content from another link ⇒ copy discarded after hashing. Interrupted downloads resume from the quarantine after a restart.
- **Delivery = hard link + unlink** (atomic, never overwrites; `rename` silently replaces on Unix). FAT/exFAT fallback: existence check + rename (small race, documented). Delivered files are 0644 (never executable); MOTW/xattr are kept.

### Scanning & verdict
- **ClamAV hard facts verified on ClamAV 1.5.4 during development:**
  1. Default `clamscan` reports a 2.2 GB file as **OK without scanning it**.
  2. libclamav cannot scan a single file ≥ 2 GiB (warning: "scanning files greater than 2147483647 bytes is not supported").
  3. With `--alert-exceeds-max=yes`, top-level size and MaxScanSize overruns are reported (`Heuristics.Limits.Exceeded.*`).
  4. **But archive members larger than MaxFileSize are silently truncated** ("cli_unzip: trimming output size to maxfilesize") even with `--alert-exceeds-max`.
  ⇒ Decisions: files ≥ 2 GiB are "Not analyzed"; clamscan runs with MaxFileSize 2047M, MaxScanSize 4000M, max-files 100000, recursion 30, scan-time 30 min, `--alert-exceeds-max`, `--alert-encrypted`, and **`--debug` whose stderr is scanned (streamed) for truncation markers**; any marker ⇒ "Not analyzed".
- **clamscan first, clamd only as a fallback** (changed after the security audit, F2). clamd cannot reveal skipped archive members (no debug stream) and was shown to return OK for an archive whose 2.2 GiB member hides EICAR. So: Auto mode uses clamscan whenever installed; clamd (if its clamd.conf proves `AlertExceedsMax yes`, `AlertEncrypted yes`, `MaxFileSize ≥ 2047M`, enough `StreamMaxLength`, and no `Scan* no`) is used only when clamscan is missing, and its "clean" is never accepted for containers (archives, installers, PDF/Office, executables, disk images) ⇒ Not analyzed. This deliberately deviates from "clamd if available": slower (clamscan reloads signatures per file) but never wrongly Clean.
- **Own ZIP structural check before ClamAV** (re-audit F1, `archive.rs`): local headers must match the central directory, supported methods only, no ZIP64/encryption. Any `LibClamAV Error:` line and RAR files on ClamAV builds without unrar ⇒ Not analyzed.
- **Archive failures are "Not analyzed"** (audit F1): debug markers `unsupported method`, `extraction failed`, `stream out of file`, non-empty `skipping decompression`, `trimming output size`, `exceeded`…
- **Defender:** optional extra engine: missing/disabled Defender is skipped with a warning (audit M4); errors still block Clean. `MpCmdRun -Scan -ScanType 3 -File <f> -DisableRemediation` (Defender reports but does not delete). Its archive/size limits are undocumented, so a Defender "clean" alone never yields Clean.
- **Verdict rules** (worst signal wins): local detection or VT ≥ dangerous threshold (3) ⇒ Dangerous (deleted); VT ≥ suspicious threshold (1) or checksum mismatch ⇒ Suspect; any local engine incomplete/failed/missing ⇒ Not analyzed; Clean requires at least one complete local scan. VirusTotal failure/no key does not block Clean unless "require VirusTotal" is enabled (default off, so the app works without a key).
- **VT counts:** thresholds use the `malicious` count only; `suspicious` is shown but not counted.
- **Link pre-check:** blocked when URL detections ≥ 2 or domain detections ≥ 3 (configurable). The user can still "Download anyway" into quarantine (the file is still scanned).
- **Scans are serialized** (one at a time) — clamscan loads the whole signature DB per run (RAM/CPU heavy); downloads stay parallel (1–8, default 2).

### VirusTotal
- Uploads need a **native confirmation dialog shown by Rust** (a compromised webview cannot trigger one).
- API v3, `x-apikey` header marked sensitive. Shared rate limiter: 15 s spacing (4/min) and 500/day by default; 429 ⇒ exponential backoff that delays every queued request. Upload exists only as an explicit, double-confirmed action, ≤ 32 MiB (free API direct-upload limit).

### Secrets & UI security
- `keyring` 3 (Credential Manager / Keychain / Secret Service). **No plaintext fallback**: if no keychain exists (e.g. headless Linux without gnome-keyring), saving the key fails with a clear message.
- The key is write-only from the UI. Executable paths, the quarantine location and ClamAV limits are editable only in `settings.json` by hand.
- Capabilities: only per-command `allow-*` permissions generated by `build.rs` + event listen. Dialog/opener/updater plugins are used from Rust only. CSP `'self'`, `freezePrototype`, no remote content.
- `withGlobalTauri: true` (no bundler). Acceptable because the page loads only local scripts under a strict CSP.

### Dependencies
- reqwest **0.13** (same as Tauri's updater ⇒ one HTTP stack), `rustls-no-provider` + `rustls/ring` (ring is already in Tauri's tree), OS verifier via rustls-platform-verifier. OpenSSL/native-tls are banned in `deny.toml`.
- `fs4` for free disk space, `xattr` (macOS only), `getrandom` for names, `unicode-normalization` for NFKC. Dev-only: wiremock, tempfile, zip 9 (zip 2.x had 4 advisories).
- Accepted advisories (unmaintained/unsound notices through Tauri's Linux GTK/D-Bus stack): RUSTSEC-2024-0370, 2026-0370, 2026-0371, 2026-0372, 2024-0429 — listed with reasons in `deny.toml` and `.cargo/audit.toml`.

### Dev tooling
- tauri-connector (crate `tauri-plugin-connector` 0.17) behind feature `dev-connector`, registered only under `cfg(all(debug_assertions, feature))`, bound to 127.0.0.1, capability injected only by `tauri.dev.conf.json`. `compile_error!` if enabled in release; CI checks `cargo tree` and the binary.

### Packaging
- `tauri-action` builds .msi + NSIS .exe (Windows), universal .dmg/.app (macOS), .deb/.rpm/AppImage (Linux); `createUpdaterArtifacts` + `latest.json`. Updater public key must be set in `tauri.conf.json`; the release workflow refuses to run while the placeholder is present.
- License: MIT.
