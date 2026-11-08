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
```bash
brew install clamav
cp "$(brew --prefix)/etc/clamav/freshclam.conf.sample" "$(brew --prefix)/etc/clamav/freshclam.conf"
sed -i '' '/^Example/d' "$(brew --prefix)/etc/clamav/freshclam.conf"
freshclam
```

### Linux
```bash
# Debian / Ubuntu
sudo apt install clamav clamav-freshclam      # the clamav-freshclam service updates signatures daily
# Fedora
sudo dnf install clamav clamav-update && sudo freshclam
# Arch
sudo pacman -S clamav && sudo freshclam
```
On Linux the system service owns the signature database, so the in-app "Update signatures" button may fail without root: that is expected, the service does it.

### Optional: clamd (faster for many files)
SafeFetch uses clamd only if its `clamd.conf` is readable and contains:
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

Updates are offered in the app and are **verified with the project's signing key** before installation.

> Unsigned builds: until the project obtains OS code-signing certificates, Windows SmartScreen and macOS Gatekeeper may warn on first launch. Check the SHA-256 of the installer against the one published in the release notes.

## 3. First launch
1. Click **Choose destination folder** (clean files go there; quarantine is a hidden sub-folder).
2. Optional: **Settings → VirusTotal API key**. Get a free key at https://www.virustotal.com (account → API key). It is stored in your system keychain. Free API limits: 4 lookups/minute, 500/day — SafeFetch queues requests accordingly.
3. Paste links, click **Fetch & scan**.

### Linux keychain note
The key is stored through the Secret Service API (GNOME Keyring, KWallet…). On a desktop without one, saving the key fails on purpose (SafeFetch never stores it in plain text).

## Settings file
`settings.json` in the app config folder (`%APPDATA%\io.github.safefetch.app`, `~/Library/Application Support/io.github.safefetch.app`, `~/.config/io.github.safefetch.app`). Advanced options that are intentionally **not** editable from the UI: `clamav.clamscan_path`, `clamav.freshclam_path`, `clamav.clamd_address`, `clamav.clamd_conf_path`, ClamAV limits, `quarantine_dir`.

## For maintainers: signed releases
1. `cargo tauri signer generate -w safefetch.key` (keep the private key and password secret).
2. Put the content of `safefetch.key.pub` into `plugins.updater.pubkey` in `src-tauri/tauri.conf.json`, and set the `endpoints` URL to your repository.
3. Add `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` as GitHub secrets.
4. Push a tag `vX.Y.Z`: `.github/workflows/release.yml` builds and signs all installers and `latest.json` (draft release).
