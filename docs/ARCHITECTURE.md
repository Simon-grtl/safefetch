# SafeFetch — Architecture (Phase 1)

SafeFetch downloads files into a quarantine area, verifies them without ever
opening or executing them, and only moves files judged clean into the user's
destination folder.

## 1. Components

```
┌──────────────────────────── Tauri window (ui/) ────────────────────────────┐
│ index.html + app.js + style.css — no framework, no CDN, strict CSP          │
│ Talks ONLY to the app-specific commands listed in capabilities/main.json    │
└───────────────▲───────────────────────────────────────────┬────────────────┘
                │ "job-updated" events                       │ invoke(cmd)
┌───────────────┴───────────────────────────────────────────▼────────────────┐
│ src-tauri (thin adapter)                                                    │
│  commands.rs  — typed commands, no generic shell / fs / http access          │
│  keyring store (OS credential vault) · native folder picker · updater        │
└───────────────▲─────────────────────────────────────────────────────────────┘
                │ Rust API
┌───────────────┴─────────────────────────────────────────────────────────────┐
│ crates/safefetch-core (no Tauri dependency, fully unit/integration tested)  │
│                                                                             │
│ input      parse "URL [sha256]" lines                                       │
│ engine     job orchestration, concurrency gate, scan serialisation          │
│ net        HTTP client, manual redirects, SSRF guard (public-only resolver) │
│ download   streaming, Range resume, size/disk checks, retries               │
│ quarantine random names, 0600/0700, MOTW, macOS quarantine xattr, sidecars  │
│ hash       streaming SHA-256                                                │
│ scanners/  virustotal (rate limiter + backoff) · clamav (clamd/clamscan)    │
│            · defender (Windows MpCmdRun)                                    │
│ verdict    pure function: scan report + thresholds → verdict                │
│ delivery   no-clobber atomic move (hard link + unlink), unique names        │
│ sanitize   filename hardening                                               │
│ history    dedupe by URL hash and file SHA-256 ("never download twice")     │
│ settings   validated JSON config (API key is NOT in it)                     │
│ secrets    SecretStore trait (keyring in the app, memory in tests)          │
└─────────────────────────────────────────────────────────────────────────────┘
```

The security-relevant logic lives in `safefetch-core`, which compiles and is
tested without a GUI. The Tauri crate is an adapter; it holds no business logic.

## 2. Data flow for one link

```
input line ──► parse (URL, optional SHA-256)
   │
   ├─► history: URL already delivered and file still present? → "Already downloaded"
   │
   ├─► VirusTotal URL + domain lookup (hash of URL only, never the file)
   │       malicious ≥ block threshold → BLOCKED (nothing is fetched)
   │
   ├─► GET with manual redirects (≤ N hops, no https→http downgrade,
   │   no public→private/loopback hop, public-only DNS resolver)
   │       final host ≠ original host → VirusTotal check of the final URL
   │
   ├─► disk-space check → stream to <quarantine>/<random>.quarantine (0600)
   │       Range resume, announced vs real size, max size, retries
   │       MOTW (Windows) / com.apple.quarantine (macOS)
   │
   ├─► [scan lock — one scan at a time]
   │       SHA-256 (streaming) → compare with expected
   │       history: same SHA already delivered? → duplicate, discard copy
   │       VirusTotal file lookup by hash
   │       ClamAV (clamd only if its config is provably sufficient, else clamscan
   │                with raised limits + --alert-exceeds-max)
   │       Defender (Windows, -DisableRemediation)
   │
   └─► verdict ──► CLEAN       → atomic no-clobber move to destination
                   DANGEROUS   → delete + detailed alert
                   SUSPECT /
                   NOT ANALYZED → stays in quarantine; user releases or deletes
```

## 3. Threat model (simplified STRIDE)

| # | Who | Entry point | What they try | STRIDE | Mitigation |
|---|-----|-------------|---------------|--------|------------|
| T1 | Malicious web server | `Content-Disposition` / URL path | Write outside destination (`../`, absolute path, `\`), overwrite user files, hide the real extension (RTLO, `invoice.pdf.exe`, padding spaces), Windows device names | Tampering, Spoofing | `sanitize` module (NFKC, last component only, control/bidi/invisible chars removed, reserved names prefixed, deceptive double extension rewritten), no-clobber delivery |
| T2 | Malicious server | HTTP redirects | SSRF to router/NAS/localhost services, downgrade to HTTP, infinite redirects | Elevation, Info disclosure | Manual redirect loop, max hops, scheme allow-list, no downgrade, public-only resolver when the user typed a public URL |
| T3 | Malicious server | Response body/headers | Disk exhaustion, lying `Content-Length`, gzip bomb at transport level, slowloris | DoS | Free-space check before/during, max size, announced vs real size, `Accept-Encoding: identity` and no auto-decompression, connect + idle timeouts |
| T4 | Malware author | File content | Evade scanners: file bigger than ClamAV limits, deep/encrypted archives, zip bombs | Spoofing (false "clean") | Limits raised explicitly, `--alert-exceeds-max` and `--alert-encrypted` → "Not analyzed", never "Clean"; size above ClamAV's hard limit → "Not analyzed" |
| T5 | Malware author | Quarantine folder | User double-clicks the file; OS auto-executes | Elevation | Random name, `.quarantine` extension, mode 0600, MOTW / quarantine xattr, file never opened by SafeFetch |
| T6 | Network attacker (MITM) | HTTP links | Swap the file | Tampering | HTTPS preferred, warning on HTTP, optional expected SHA-256, rustls with OS roots |
| T7 | Compromised/XSS'd webview | IPC | Run commands, read/write arbitrary files, exfiltrate API key | Elevation, Info disclosure | No shell/fs/http plugins exposed, per-command permissions, strict CSP, no remote content, scanner paths not settable from UI, API key write-only from UI |
| T8 | Local user/malware | Config / logs | Steal VirusTotal key | Info disclosure | Key only in OS keyring, redacted `Debug`, header marked sensitive, never logged |
| T9 | Supply chain | Crates, update channel | Malicious dependency or update | Tampering | `cargo audit`, `cargo deny` (licenses, sources, advisories), lockfile, signed updater artifacts, small dependency set |
| T10 | Privacy | VirusTotal | Leak private files | Info disclosure | Only hashes/URLs sent; upload is a separate, explicit, confirmed action |
| T11 | VirusTotal quota | API | 429 storms, daily quota exhaustion | DoS | Shared rate limiter (min interval + daily cap), exponential backoff honouring 429 |

### Out of scope / residual risk
- A local attacker with the user's privileges can modify a file between
  scan and delivery (TOCTOU). Defending against that requires OS sandboxing.
- Antivirus engines detect known threats; new or targeted malware can pass
  every scanner. "Clean" means "no engine flagged it", not "safe".
- Files larger than ClamAV's hard ceiling (~4 GB) cannot be scanned by ClamAV.
