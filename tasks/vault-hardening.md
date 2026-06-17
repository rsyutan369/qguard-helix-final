# Vault Hardening — plan (post-audit)

Audit verdict: file **content** is already PQ/HNDL-safe (AES-256-GCM under a DEK
wrapped via HKDF-SHA3-256(ML-KEM-1024 ‖ X25519); ML-DSA-65 signatures). Three
boundaries remain. User approved closing all three.

## H1 — Argon2id KEK (replaces PBKDF2 for the passphrase→KEK step)
- Why: master secret keys are wrapped under the passphrase and the wrapped bundle
  is stored server-side → harvestable. PBKDF2 is GPU/ASIC-friendly; a weak passphrase
  is brute-forceable offline (Grover ~halves it). Argon2id is memory-hard.
- Change: `wrapMasterKeys` → Argon2id (bundle `v:3`, `kdf:'Argon2id+HKDF-SHA3-256'`,
  params stored). `unwrapMasterKeys` dispatches on `bundle.kdf` → backward-compatible
  with existing `v:2` PBKDF2 bundles. Transparent re-wrap on unlock for legacy bundles.
- Params: Argon2id t=2, m=19456 KiB (~19 MiB), p=1 (OWASP-balanced, browser-safe).
- Verify: headless wrap→unwrap round-trip + legacy-bundle unwrap (`tools/vault-crypto/kek-test.ts`).

## H2 — Strong passphrase enforcement
- Why: passphrase entropy is the real HNDL parameter once H1 is in.
- Change: dependency-free strength estimator (`src/lib/vault/passphrase-strength.ts`):
  length, char-class, repeat/sequence/common-pattern penalties, entropy estimate.
  Enforce min acceptable score at create (block weak). Wire into `VaultPassphrase.tsx`.
- Verify: unit checks on the estimator; tsc + build.

## H3 — Encrypt filenames/metadata (no plaintext name/MIME at rest)
- Why: `original_filename`, `mime_type` are cleartext columns; name also leaks via
  `envelope_meta.signedMetadata.fileName`. Content is sealed but names/types/sizes leak.
- Change (contained, no schema migration, backward compatible):
  - Client-derived metadata key: HKDF-SHA3-256(encSecretKey, info='vault-metadata-key').
  - Seal `{filename, mime}` with AES-256-GCM → store in `envelope_meta.sealedMeta`.
  - Store a non-identifying placeholder in `original_filename`; stop putting the raw
    name in `signedMetadata` (sign over a SHA3-256 name hash instead).
  - List/download decrypt `sealedMeta` after unlock; legacy files (no sealedMeta) fall
    back to `original_filename`. Pre-unlock shows "Encrypted".
- Verify: headless seal→open round-trip; tsc + build.
- Follow-ups (flagged, need authenticated session): shared-link name display, audit-log
  description scrubbing, optional migration of existing cleartext names.

## H4 — Recipient-bound default for sensitive shares (DONE)
- `ShareLinkModal` now uses an explicit **Security Level** selector defaulting to
  **recipient-bound** (ML-KEM-1024 wrapped key → intercepted link cannot decrypt).
  Password = strong; "Link only" = convenience, with an explicit interception warning.
  State refactored to a single `shareMode`; booleans derived (no JSX churn). tsc + build clean.

## H5 — App-wide Content-Security-Policy, tested (DONE)
- Build-time `cspMetaPlugin` (vite.config) injects a strict CSP `<meta>` into the
  built index.html: `script-src 'self' '<sha256 of inline bootstrap>'` (NOT
  'unsafe-inline'), `object-src 'none'`, `base-uri 'self'`, `img-src 'self' blob: data:`,
  and `connect-src` tightened to the real Supabase origins from `.env`. `preview.headers`
  add X-Frame-Options/Referrer-Policy/Permissions-Policy (meta can't express frame-ancestors).
- **Tested live** (vite preview + Playwright): app renders, inline script hash matches
  (theme applies), **zero CSP violations**. The CSP correctly blocked third-party
  placeholder avatars (randomuser.me / loremfaces.net) in `Landing.tsx` → replaced with
  local data-URI initials avatars (`initialsAvatar`), removing the external dependency.
- Note: the existing dev-only `/vault/shared` CSP is unchanged; this adds production
  coverage app-wide.

## H6 — Deployment security-header configs (DONE)
- Ready-to-use, host-agnostic header configs added so production also sends HSTS,
  `frame-ancestors`/X-Frame-Options, Referrer-Policy, Permissions-Policy, and COOP
  (the things a `<meta>` CSP cannot express). The build's `<meta>` stays the source of
  truth for the env-specific resource policy, so the header files never drift across
  Supabase projects. Files: `vercel.json`, `public/_headers` (Netlify + Cloudflare
  Pages), `public/.htaccess` (Apache/Hostinger/cPanel), `deploy/nginx-security-headers.conf`,
  and `deploy/DEPLOYMENT-HEADERS.md` (guide + DigitalOcean App Platform spec + optional
  full-CSP-as-header variant). Verified `_headers` + `.htaccess` ship into `dist/` on build;
  `vercel.json` is valid JSON. `/vault/shared/*` gets a `no-referrer` + `no-store` override.

## Gates
`npx tsx tools/vault-crypto/kek-test.ts` · `npx tsc --noEmit` · `npx vite build`
· existing `npx tsx tools/q-shrink/roundtrip-test.ts` must stay green.

## Status (verified)
- **H1 Argon2id — DONE.** `wrapMasterKeys` now Argon2id (bundle v3); `unwrapMasterKeys`
  dispatches on `kdf` (v2 PBKDF2 still unwraps); transparent re-wrap on unlock via
  `bundleNeedsKdfUpgrade`. KEK test 11/11. tsc + build clean.
- **H2 Strong passphrase — DONE.** `passphrase-strength.ts` estimator (entropy +
  repeat/sequence/common-word penalties); `VaultPassphrase` blocks create unless
  `acceptable` (≥12 chars, ≥60 bits, score ≥3). tsc + build clean.
- **H3 Filename/MIME — sealing + share-token embedding DONE; owner file-browser cutover REMAINS.**
  - Done: `sealFileMeta`/`openFileMeta` (tested); both upload handlers seal name+MIME
    into `envelope_meta.sealedMeta` (zero regression).
  - Done: **share-token embedding** (design decision: embed name in the token).
    `packShareEnvelope`/`unpackShareEnvelope` seal `{filename, mime}` inside the
    encrypted share payload (under fragment / password / recipient key). The owner
    modal now sends a `'Encrypted share'` placeholder to the server; the recipient
    page recovers the real name on decrypt. Backward compatible (legacy shares fall
    back to the server name). Tested: `tools/vault-crypto/share-embed-test.ts` (11/11,
    incl. magic-collision false-positive safety + tamper rejection).
  - Remaining (needs authenticated E2E test): flip `vault_files.original_filename`
    to a placeholder on upload + patch the owner's loaded `files` array by decrypting
    `envelope_meta.sealedMeta` (one centralized override → all 21 render sites + the
    download path). Server analytics dashboards will then show placeholders (correct
    ZK behavior). This is the last step that touches the owner's own file browser, so
    it must be smoke-tested live before shipping.
