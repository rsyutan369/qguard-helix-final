# Final Qguard Messaging logo and icons

The approved master is `brand/qguard-messaging-logo.png`, copied byte-for-byte from the user's final supplied transparent PNG. SHA-256: `3d70345a2d9b3020dc773151cc9a0f3e7bf2820e03a07950d0f27c5082c1a821`. The existing onboarding splash uses the identical file.

Updated assets cover in-app branding (login, desktop sidebar, mobile header, About and subscription header), favicon, desktop taskbar/window/shortcut icons, Windows installer header/sidebar, Android adaptive/legacy/round launcher icons at all five densities, and the Play Store icon. Login artwork no longer has a circular image crop, so the Q tail remains visible. Authentication, encryption, workflows and application configuration are unchanged.

`tools/brand-assets.mjs` now retains the complete master canvas and writes assets atomically, which avoids truncating files mapped by Windows image viewers. Android foregrounds use the full master at 60dp on the 108dp adaptive canvas; the visible artwork fits inside the centred 66dp safe circle.

Asset generation only was performed. No frontend, Rust, Android, Gradle, desktop, installer or release build was run. All five existing release installers were hash-checked and remain unchanged. The updated branding will enter application binaries when a build is explicitly requested.

Verification: `artifacts/final-branding/verification.json`. Visual preview: `artifacts/final-branding/brand-preview.png`. Dimensions, safe-circle bounds, ICO/ICNS containers, installer BMP headers, supplied-master integrity, unchanged functional source and unchanged release installers were checked. No application regression suite was needed for the raster replacements and two logo-clipping style changes.

To regenerate the editable raster assets, run `node tools/brand-assets.mjs`. Generate desktop icon formats with `npm run tauri -- icon src-tauri/app-icon.png --output artifacts/final-branding/generated-icons`, then replace the top-level desktop icon files under `src-tauri/icons` atomically from staging. Reapply `node tools/brand-assets.mjs --android-only` after icon generation to preserve adaptive foreground padding and the existing navy background. These commands generate image assets; they do not compile or package an application.
