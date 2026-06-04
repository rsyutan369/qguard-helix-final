# Deployment Guide

1. Apply `supabase/migrations/001_secure_messaging.sql` to the QGuard Supabase project.
2. Configure Supabase Auth MFA policies.
3. Confirm the private `messaging-files` bucket exists.
4. Set frontend environment variables:

```env
VITE_SUPABASE_URL=...
VITE_SUPABASE_ANON_KEY=...
```

5. Install desktop dependencies:

```powershell
npm install
npm run tauri dev
```

6. Build:

```powershell
npm run build
npm run tauri build
```

7. Run security checks before release:

```powershell
cd src-tauri
cargo test
cargo clippy --all-targets --all-features
cargo audit
```

8. Configure truth-driven release hardening markers before producing a signed desktop build. These values must only be set by the release pipeline after the matching control has actually run:

```powershell
$env:QGUARD_SIGNED_BUILD="1"
$env:QGUARD_EXPECTED_BINARY_SHA3="<sha3-256-of-signed-release-binary>"
$env:QGUARD_CONTROL_FLOW_FLATTENING="1"
$env:QGUARD_STRING_ENCRYPTION="1"
npm run tauri build
```

Without those release markers, the Quantum Security module intentionally reports the affected controls as `Review` and lowers the Security Score.
