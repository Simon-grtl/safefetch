# SafeFetch — Security audit (phase 8), 2026-11-08

## Method
The plugins requested for this phase (claude-security, OWASP Security Audit,
Trail of Bits static-analysis / sharp-edges) were **not installed** in the
session that built the project. They were replaced by:

| Requested | Used instead |
|---|---|
| claude-security (verified findings) | Independent auditor agent, attacker mindset, required to prove each finding (PoC programs and crafted samples) |
| OWASP Security Audit | Second independent agent: pre-merge code review + OWASP-style audit, findings by severity and confidence |
| Trail of Bits static-analysis | Semgrep with 6 project rules (each verified to fire on bad code); public packs `p/rust`, `p/javascript`, `p/secrets` run in CI (not reachable from the build environment) |
| Trail of Bits sharp-edges | Manual review of sharp APIs: `rename` vs no-clobber, `canonicalize` on Windows, `Command` resolution, rustls provider, cfg-gated OS code |
| cargo audit / cargo deny | Run locally: clean (5 documented "unmaintained/unsound" notices from Tauri's Linux stack accepted with reasons) |

Re-run the original plugins when available; this document lists what they should re-check.

## Findings and fixes

| ID | Source | Severity | Finding | Fix | Regression test |
|---|---|---|---|---|---|
| F1 | Attacker audit | **High** | ZIPs ClamAV cannot unpack (LZMA method, lying local sizes, forced ZIP64) were reported **Clean** and delivered | More libclamav debug markers (`unsupported method`, `extraction failed`, `stream out of file`, non-empty `skipping decompression`) ⇒ Not analyzed | `archives_clamav_cannot_unpack_are_never_clean`, `archive_failure_markers` |
| F2 | Attacker audit | **High** | clamd (configured as required) returned OK for a 2.2 GiB archive member, the F1 samples, and accepted `ScanArchive no` | Auto mode uses clamscan first; clamd only as fallback, never trusted for containers (magic sniffing ⇒ Not analyzed); any `Scan* no` rejects clamd | `clamd_never_vouches_for_containers`, `clamd_conf_with_scanning_disabled_is_refused`, `auto_mode_prefers_clamscan` |
| F3 | Attacker audit | Medium | With a system HTTP proxy, the public-only DNS resolver is bypassed: redirects to `intranet.corp` reached internal hosts and leaked them to VirusTotal | Every redirect target (public link) is resolved locally and must resolve only to public addresses | `redirect_targets_must_resolve_publicly` |
| F4 | Attacker audit | Low | Braille-blank padding (U+2800) hid `.exe` behind `facture.pdf`; `.dmg`, `.jnlp`… not flagged | More invisible chars removed; extensions added | `invisible_padding_cannot_hide_the_real_extension` |
| B1 | Code review | Blocker (CI) | `/nonexistent` is not absolute on Windows → tests panic | OS-independent absolute path helper | (CI) |
| M1 | Code review | Major | After the VirusTotal check of a redirect target, the re-request could follow a switched chain | `final_url` pinned before download; re-open requests the checked URL directly; fallback must match scheme/host/port/path | `redirect_target_switch_after_virustotal_check_is_refused`, `expired_checked_target_with_switched_chain_is_refused` |
| M2 | Code review | Major | `user:password@` in links sent to VirusTotal | Userinfo and fragment stripped before lookups | `credentials_in_links_never_reach_virustotal` |
| M3 | Code review | Major | A Clean file was deleted when delivery failed | File kept in quarantine; completed downloads are never dropped | `clean_file_is_kept_when_delivery_fails` |
| M4 | Code review | Major | Windows without Defender ⇒ every file Not analyzed | Defender `Unavailable` ⇒ skipped with a warning (errors still block) | — (Windows) |
| M5 | Code review | Major | Console windows flashing on Windows | `CREATE_NO_WINDOW` on every child process; `attrib` only at creation | — (Windows) |
| m1–m9 | Code review | Minor | destination change stranding quarantine; re-paste duplicates; stale state after partial failures; resume across file versions (ETag); broad markers; `\\?\` paths; release guard; Defender in tests; upload confirmation only in JS | Refusal while items pending; dedupe incl. quarantine; log-and-continue; ETag check on 206; markers narrowed; `dunce`; guard on `/OWNER/`; tests disable Defender; **native Rust confirmation dialog** for uploads | `state_guards_and_destination_change`, `wrong_resume_offset_restarts_cleanly` |

## Re-audit of the fixes (same attacker auditor, PoCs re-run, header fuzzing)

| Fix | Re-audit result | Follow-up fix | Test |
|---|---|---|---|
| F1 | **Incomplete**: ZIP with local-header flag bit 13 ("masked"), local method 0 or local csize 0/1 disagreeing with the central directory, and a truncated `.xz` (only a `LibClamAV Error:` line) were still delivered Clean | (1) New `archive.rs`: structural ZIP check independent of ClamAV — every central entry must have an identical local header (flags, method, CRC, sizes, name; data-descriptor case handled), only methods ClamAV unpacks, no ZIP64/encrypted/multi-disk, SFX prefixes handled; (2) any `LibClamAV Error:` line ⇒ Not analyzed; (3) marker `unusable masked data`; (4) ClamAV builds without RAR support (Debian/Ubuntu) ⇒ RAR content Not analyzed | `reaudit_zip_and_xz_evasions_are_never_clean`, `audit_evasion_variants_are_flagged` |
| F2 | Verified; gap: ZIP after a text prefix not seen as a container by clamd path | Container sniffing also looks for a ZIP end-of-central-directory near the end of the file | `container_sniffing` + archive tests |
| F3 | Internal names blocked, but **regression**: networks where only the proxy resolves names broke every redirect | Names internal by convention (`.internal`, `.corp`, `.local`, single label…) and names resolving to private IPs are refused; names that do not resolve locally are allowed (proxy decides) | `redirect_targets_must_resolve_publicly` |
| F4 | Mostly verified; U+1CBC, U+180B, U+1BCA0, U+1D159 and `facture.pdf_.exe` still passed; `.msh`/`.cab` missing | Full Default_Ignorable_Code_Point + Cf ranges + blank-looking chars; decoy check ignores `_ - . space` filler; extensions added | `reaudit_padding_variants` |

Verified in the real GUI (release build): a clean file is delivered, EICAR in a ZIP is deleted, the LZMA evasion ZIP stays in quarantine as "Not analyzed".

## Residual risks (accepted, documented)
1. **Nested malformed archives / unknown failure modes.** The structural ZIP check covers the top-level file only; a malformed ZIP *inside* a valid one relies on ClamAV debug markers and error lines. Detection of "ClamAV skipped this" relies on libclamav debug messages; formats or messages not yet seen (other RAR/7z corruptions, future ClamAV versions) may slip through. Mitigation: markers are checked in CI against crafted samples; re-check at each ClamAV major version.
2. **`--debug` with the full official signature database** was not measured here (only a one-signature test DB was available). Expected impact: more stderr to stream (bounded memory) and possibly false "Not analyzed" — the safe direction.
3. **Files ≥ 2 GiB** are never scanned by ClamAV (libclamav limit): always Not analyzed.
4. **Proxy with split DNS**: if the proxy resolves a name differently from the local resolver, the redirect guard can be wrong.
5. **TOCTOU by local malware** with the user's rights (between scan and delivery): out of scope without OS sandboxing.
6. **Windows/macOS-specific code** (MOTW, `com.apple.quarantine`, Defender parsing, `CREATE_NO_WINDOW`) is compiled and tested only in CI, not in the build environment.
7. **Signature-based detection** cannot catch new or targeted malware.
