# QGuard Messaging — Android Native Build Guide (NDK Setup + Build)

Covers NDK setup, building the APK from CLI and Android Studio, and release
signing. Applies to the project under `qguard-messaging/src-tauri`.

## Prerequisites

| Tool | Version used | Location |
|------|--------------|----------|
| Android Studio | any recent | host install |
| Android SDK | platforms 34+, build-tools 34+ | `%LOCALAPPDATA%\Android\Sdk` |
| Android NDK | **r27 (27.2.12479018)** | `%LOCALAPPDATA%\Android\Sdk\ndk\27.2.12479018` |
| JDK | 21 (Android Studio JBR) | `C:\Program Files\Android\Android Studio\jbr` |
| Rust | 1.77+ with Android targets | `rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android` |
| Node | project standard | — |

Install the NDK once:

```powershell
& "$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\latest\bin\sdkmanager.bat" --install "ndk;27.2.12479018"
```

## Environment (every build shell)

```powershell
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
$env:NDK_HOME     = "$env:ANDROID_HOME\ndk\27.2.12479018"
$env:JAVA_HOME    = "C:\Program Files\Android\Android Studio\jbr"
```

## Build commands (from `qguard-messaging/`)

```powershell
# Debug APK, physical ARM64 device (fastest)
npx tauri android build --apk --target aarch64 --debug

# Release APK (signed with the upload keystore, see below)
npx tauri android build --apk --target aarch64

# Universal / all ABIs (arm64 + arm + x86 + x86_64)
npx tauri android build --apk

# Play Store AAB
npx tauri android build --aab

# Live-reload development on a connected device/emulator
npx tauri android dev
```

APK output: `src-tauri/gen/android/app/build/outputs/apk/<flavor>/<profile>/`.

## Android Studio

Open `qguard-messaging/src-tauri/gen/android` as the project. The `rust`
Gradle plugin (buildSrc) drives `cargo` through the Tauri CLI for each ABI
flavor automatically on Run/Build.

## Windows symlink note

Tauri places the built `libqguard_messaging_lib.so` into `app/src/main/jniLibs`
via a **symlink**, which Windows only allows in **Developer Mode**. There are
two ways to build:

### A. Enable Developer Mode (recommended — one-time, unlocks every path)

`Settings → System → For developers → Developer Mode → On` (or, elevated:
`reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 1 /f`).
Then `npx tauri android build --apk` and Android Studio both work directly.

### B. No admin — build the library, copy it, assemble via Gradle

The CLI symlink runs before Gradle, so `tauri android build` can't be repaired
from Gradle. Instead let the CLI cross-compile the library (it builds the `.so`
with the correct NDK linker, then fails *only* at the symlink), copy that `.so`
into `jniLibs`, and run the Gradle assemble task while excluding the Rust task
that would re-symlink:

```powershell
# 1. Cross-compile the native library — succeeds; only the final symlink errors
npx tauri android build --apk --target aarch64 --debug   # expected: symlink error, .so built

# 2. Copy the freshly built .so into jniLibs (the exact file the CLI failed to symlink)
$so = "$env:LOCALAPPDATA\qguard-messaging-target\aarch64-linux-android\debug\libqguard_messaging_lib.so"
New-Item -ItemType Directory -Force src-tauri\gen\android\app\src\main\jniLibs\arm64-v8a | Out-Null
Copy-Item $so src-tauri\gen\android\app\src\main\jniLibs\arm64-v8a\ -Force

# 3. Assemble the APK, skipping the re-symlinking Rust task
cd src-tauri\gen\android
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"   # see note below
.\gradlew assembleArm64Debug -x rustBuildArm64Debug --console=plain
```

**`JAVA_HOME` must point at a JDK.** It is unset on this machine, so Gradle
auto-detects a toolchain and can land on the Adoptium *JRE*, failing with
`Toolchain installation '...jre-17...' does not provide the required
capabilities: [JAVA_COMPILER]`. Android Studio's bundled JBR is a full JDK and
is the toolchain Studio itself uses. Building from inside Android Studio never
hits this, which is why it only shows up on the CLI path.

APK: `app/build/outputs/apk/arm64/debug/app-arm64-debug.apk`. For release, use
`--target aarch64` (no `--debug`) in step 1, copy from the `release/` dir, then
`.\gradlew assembleArm64Release -x rustBuildArm64Release`. The Gradle task alias
is `Arm64` (arch name), while the cargo/CLI target triple is `aarch64` — the
`-x` exclude must use the `Arm64` form. The `buildSrc BuildTask` also auto-copies
on symlink failure for the Android Studio build path.

## Release signing

- Upload keystore: `%USERPROFILE%\.android\qguard-upload-keystore.jks`
  (RSA-4096, alias `qguard-upload`, validity 10000 days) — **outside the repo**.
- `src-tauri/gen/android/keystore.properties` (gitignored) holds
  `storeFile` / `keyAlias` / `password`; the release `signingConfig` in
  `app/build.gradle.kts` reads it when present and builds unsigned otherwise.
- Rotate by regenerating the keystore and updating the properties file.

## Version stamping

`versionCode`/`versionName` come from `src-tauri/tauri.conf.json` `version`
(via the generated `tauri.properties`) — bump it there only.

## Cargo target dir

`src-tauri/.cargo/config.toml` redirects build artifacts to
`%LOCALAPPDATA%\qguard-messaging-target` (Search-indexing/Defender race
mitigation). Android `.so` files land under
`<target-dir>/<triple>/<profile>/libqguard_messaging_lib.so`.
