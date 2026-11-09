# Installing SafeFetch

SafeFetch needs **ClamAV** to judge files Clean. Without it, every file stays in
quarantine as "Not analyzed". The app detects ClamAV on first launch and shows
these steps if it is missing.

## 1. Install ClamAV and its signatures

### Windows
1. Download the ClamAV installer (`clamav-x.y.z.win.x64.msi`) from https://www.clamav.net/downloads and install it (default: `C:\Program Files\ClamAV`).
2. In that folder, copy `conf_examples\freshclam.conf.sample` to `freshclam.conf`, open it and delete the line `Example`.
3. Run `freshclam.exe` once (as administrator if it was installed for all users). SafeFetch then refreshes signatures daily while it runs.
4. Microsoft Defender is used in addition, automatically, if present.

### macOS
Use the **official installer**, not Homebrew. Since November 2026 Homebrew's `clamav` (1.5.4_1) is built on OpenSSL 4 and cannot hash files or load the official signatures ([Cisco-Talos/clamav#1887](https://github.com/Cisco-Talos/clamav/issues/1887)). SafeFetch detects it and reports files as "Not analyzed", but nothing can be scanned.

1. Download `clamav-<version>.macos.universal.pkg` from https://github.com/Cisco-Talos/clamav/releases and open it (installs into `/usr/local/clamav`).
2. Configure and download the signatures:
```bash
cd /usr/local/clamav/etc
sudo cp freshclam.conf.sample freshclam.conf && sudo sed -i '' '/^Example/d' freshclam.conf
sudo /usr/local/clamav/bin/freshclam
```

### Linux
```bash
# Debian / Ubuntu
sudo apt install clamav clamav-freshclam      # the clamav-freshclam service updates signatures daily
# Fedora
sudo dnf install clamav clamav-update && sudo freshclam
# Arch Linux / CachyOS
sudo pacman -S clamav
sudo freshclam
sudo systemctl enable --now clamav-freshclam.service   # daily signature updates
```
> **Arch / CachyOS and OpenSSL 4.** Arch is rebuilding its packages on OpenSSL 4 (`clamav 1.5.4-2` is in staging as of November 2026). ClamAV 1.5 does not work with OpenSSL 4 yet ([Cisco-Talos/clamav#1887](https://github.com/Cisco-Talos/clamav/issues/1887)). If that update reaches you before a fix, SafeFetch will show every file as "Not analyzed" with the message "this ClamAV build cannot compute file hashes": nothing is wrongly marked Clean, but nothing can be scanned until a fixed `clamav` package is released.
On Linux the system service owns the signature database, so the in-app "Update signatures" button may fail without root: that is expected, the service does it.

### clamd (fallback only)
SafeFetch always prefers `clamscan`, because only clamscan lets it detect archive content that ClamAV silently skipped. clamd is used only when clamscan is not installed, and even then archives/installers scanned by clamd are reported "Not analyzed". clamd is used only if its `clamd.conf` is readable, has no `Scan... no` option, and contains:
```
AlertExceedsMax yes
AlertEncrypted yes
MaxFileSize 2047M
MaxScanSize 4000M
StreamMaxLength 2047M
```
Otherwise it uses `clamscan`, with these limits passed on the command line.

## 2. Install SafeFetch
Download the installer for your OS from the project's Releases page:
- Windows: `.msi` or `-setup.exe`
- macOS: `.dmg` (universal)
- Linux: `.AppImage`, `.deb` or `.rpm`
- Arch Linux / CachyOS: build the package with the provided PKGBUILD (below), or use the `.AppImage`

Updates are offered in the app and are **verified with the project's signing key** before installation. On Linux the app installs updates itself only for the AppImage; packages installed with pacman/apt/dnf are updated by the package manager.

### Arch Linux / CachyOS
```bash
sudo pacman -S --needed base-devel git
git clone https://github.com/Simon-grtl/safefetch.git
cd safefetch/packaging/arch
makepkg -si          # builds from the tagged release and installs (pulls clamav as a dependency)
```
Then follow the ClamAV steps above (`sudo freshclam`, enable `clamav-freshclam.service`). SafeFetch appears in the application menu.

- **VirusTotal key storage:** KDE Plasma (CachyOS default) uses KWallet; make sure KWallet is enabled (*System Settings → KDE Wallet*). On GNOME, Hyprland, Sway… install `gnome-keyring`.
- **Blank window:** SafeFetch already disables WebKitGTK's DMA-BUF renderer, the usual cause with NVIDIA drivers and some Wayland setups. If the window is still blank, start it once with `WEBKIT_DISABLE_COMPOSITING_MODE=1 safefetch` and report it.

> Unsigned builds: until the project obtains OS code-signing certificates, Windows SmartScreen and macOS Gatekeeper may warn on first launch. Check the SHA-256 of the installer against the one published in the release notes.

## 3. First launch
1. Click **Choose destination folder** (clean files go there; quarantine is a hidden sub-folder).
2. Optional: **Settings → VirusTotal API key**. Get a free key at https://www.virustotal.com (account → API key). It is stored in your system keychain. Free API limits: 4 lookups/minute, 500/day — SafeFetch queues requests accordingly.
3. Paste links, click **Fetch & scan**.

### Linux keychain note
The key is stored through the Secret Service API (GNOME Keyring, or KWallet on KDE Plasma/CachyOS). On a desktop without one, saving the key fails on purpose (SafeFetch never stores it in plain text).

## Settings file
`settings.json` in the app config folder (`%APPDATA%\io.github.safefetch.app`, `~/Library/Application Support/io.github.safefetch.app`, `~/.config/io.github.safefetch.app`). Advanced options that are intentionally **not** editable from the UI: `clamav.clamscan_path`, `clamav.freshclam_path`, `clamav.clamd_address`, `clamav.clamd_conf_path`, ClamAV limits, `quarantine_dir`.

## For maintainers: signed releases
1. `cargo tauri signer generate -w safefetch.key` (keep the private key and password secret).
2. Put the content of `safefetch.key.pub` into `plugins.updater.pubkey` in `src-tauri/tauri.conf.json`, and set the `endpoints` URL to your repository.
3. Add `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` as GitHub secrets.
4. Push a tag `vX.Y.Z`: `.github/workflows/release.yml` builds and signs all installers and `latest.json` (draft release).
