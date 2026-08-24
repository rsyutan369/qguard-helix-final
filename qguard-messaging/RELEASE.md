# QGuard Messaging — Release & Deploy Runbook

Everything needed to cut a new installer and (when you're ready) push it live.
Two mental models to keep straight:

- **Build** = produce the signed `.exe` + `latest.json`. Local, reversible.
- **Deploy** = make those files reachable by the website and by installed apps.
  Outward-facing. This is a separate, deliberate step.

`build -> publish -> deploy`. Only the first two run on your machine.

---

## TL;DR

```powershell
# From qguard-messaging/ — LOCAL build for testing / manual download (no deploy):
pwsh tools/release.ps1 -Version 1.3.0

# When you decide to GO LIVE (build + commit + push main -> triggers deploy):
pwsh tools/release.ps1 -Version 1.3.0 -Notes "What changed in this release" -Push
```

`release.ps1` sets the version in all three places, builds + signs the installer,
publishes it to `public/downloads/`, and syncs the website size label. `-Push`
also commits and pushes `main`.

### Release notes

`-Notes` goes into `latest.json`. Installed apps show only the version number in
the update banner, so that string is not where users learn what changed —
[`CHANGELOG.md`](./CHANGELOG.md) is. Write the user-facing note there first,
then pass a one-line summary to `-Notes`.

For 1.3.0 that line is:

```
Quantum Vault: recipient fingerprint verification is now required before sealing, identity passphrases are checked for real strength, and ML-KEM key generation is conformant to final FIPS 203. Nothing you already have needs migrating — see CHANGELOG.md.
```

A release that changes behaviour users will *notice* needs the changelog entry
written before the build, not after. 1.3.0 is the worked example: three enforced
checks that each look like a regression until the reason is on the page.

The built installer is always at:
`%LOCALAPPDATA%\qguard-messaging-target\release\bundle\nsis\QGuard Messaging_<version>_x64-setup.exe`
and copied to `public/downloads/QGuard-Messaging-Setup.exe`.

---

## One-time prerequisites (do these before your FIRST production release)

### 1. Offline backup of the updater signing key — REQUIRED
`src-tauri/updater-keys/` (`qguard-messaging.key` + `.password` + `.pub`) is
gitignored. It is the ONLY thing that can sign updates your installed apps will
accept. If it is lost, no installed app can ever auto-update again — everyone
must reinstall manually.
- A copy already exists at `E:\MYPROJECTS\New Project 2026\PQC_Migration`.
- Keep at least one copy off this machine (USB / password manager / cloud vault).

### 2. Point the updater endpoint at a domain that actually serves the files
The app polls, **compiled in at build time**, `plugins.updater.endpoints` in
`src-tauri/tauri.conf.json`. Today that is:

```
https://api.qguard.dev/downloads/latest.json     <-- currently NOT serving (HTTP 000)
```

The live site is **`qguardhelix.com` (Cloudflare Pages)**, which serves
`public/downloads/`. So for production, either:

- **(A)** bring `api.qguard.dev/downloads/` online (point it at the same deploy), or
- **(B)** switch the endpoint to the live domain:
  ```jsonc
  // src-tauri/tauri.conf.json
  "updater": { "endpoints": ["https://qguardhelix.com/downloads/latest.json"], ... }
  ```
  and always release with `-BaseUrl https://qguardhelix.com` so `latest.json`'s
  download URL matches:
  ```powershell
  pwsh tools/release.ps1 -Version 1.3.0 -BaseUrl https://qguardhelix.com -Push
  ```

> ⚠️ **Baked-in endpoint caveat.** Apps ALREADY installed carry whatever endpoint
> was compiled into them. Changing the endpoint only helps devices running a
> build that already has the new endpoint. So the first build with the corrected
> endpoint must be distributed **manually** (download link); auto-update takes
> over from the release after that. Pick the endpoint before you ship widely.

---

## What a release does (the pipeline)

1. **Version** set in three files (a missed bump silently disables auto-update):
   - `src-tauri/tauri.conf.json`  → `"version"`
   - `src-tauri/Cargo.toml`       → `[package] version`
   - `src/app/qguard-messaging/_shared.tsx` → `MESSAGING_INSTALLER.version`
   The Tauri updater only offers an update when `latest.json`'s version is
   **higher** (semver) than the installed one — so every release must bump.
2. **Build + sign** via `tools/release-installer.ps1`: loads the signing key,
   runs `npx tauri build` (4x retry for the AV file-lock, `os error 32`), and
   signs the NSIS installer + the updater artifact.
3. **Publish**: copies the exe to `public/downloads/QGuard-Messaging-Setup.exe`
   and writes a signed `public/downloads/latest.json`.
4. **Website size label** synced to the real installer (`MESSAGING_INSTALLER.sizeMb`).

---

## Going live (deploy)

`public/downloads/` is committed to git, and the site builds from source
(`vite build`), which copies `public/downloads/` into the deploy. So deploy =
**commit the release files + push `main`**; the host (Cloudflare Pages) rebuilds
`qguardhelix.com`.

- Easiest: run the release with `-Push` (it commits + pushes for you).
- Manual: `git add public/downloads <the 3 version files> && git commit -m "Release x.y.z" && git push origin main`

After pushing, confirm on your Cloudflare Pages dashboard that the build finished,
then verify in a browser.

---

## Verify after deploy

- `https://qguardhelix.com/qguard-messaging` — download button reads **v<new>**,
  and the file downloads (~4–5 MB, not a tiny HTML page).
- `https://<your-updater-domain>/downloads/latest.json` — shows the new `version`
  and a `signature`.
- An installed older build should offer the update on next launch (the in-app
  `UpdateBanner`), install it, and relaunch.

---

## Rollback

The previous installer + manifest are in git history. To revert the live download:

```powershell
git revert <release-commit>   # or: git checkout <prev-commit> -- public/downloads
git push origin main
```

Then redeploy. (Auto-update has no "downgrade": clients only move to a HIGHER
version, so a bad release is fixed by shipping a higher patch version, not by
lowering the manifest.)

---

## Manual fallback (no script)

1. Edit the version in the three files above.
2. `pwsh tools/release-installer.ps1 -Notes "..."` (add `-BaseUrl https://qguardhelix.com` for prod).
3. Update `sizeMb` in `_shared.tsx`.
4. Commit `public/downloads` + the version files, push `main`.

See also `Qguard_Wiki/Messaging_Installer_Distribution`.
