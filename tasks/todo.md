# Secure Chat Android — open-conversation bounce (2026-07-12)

## Root cause (verified on emulator with 2 test accounts + DB forensics)
Investigation ruled OUT the suspected causes and pinned the real one:
- Android DOES register a messaging_device + prekeys correctly (proved: a fresh
  Android login for a new account produced a healthy device — 1 active signed
  prekey + 24 one-time prekeys). Search, RLS, and conversation INSERT all work
  (a real 2-party conversation was created when messaging a keyed recipient).
- REAL BUG = React state race in SecureChatPage. `startPrivateChat`/`openConversation`
  set `activeConversationId` to the just-created conversation, but the parent
  `conversations` prop only updates after an async refresh + realtime round trip.
  The "keep a valid selection" effect saw the new id was absent from the (stale)
  visible list and reset `activeConversationId` to `visibleConversations[0]` (the
  self-only starter conversation), stranding the user on the wrong thread ("Open
  a contact chat before sending", stuck "Loading encrypted history…") — or, for a
  recipient with no published keys, `startPrivateChat` early-returned AFTER
  `closeNewChat()` already closed the modal, so the tap silently dropped back to
  the list = the reported "returns to Search Users" bounce.

## Fix (src/pages/SecureChatPage.tsx)
- [x] Optimistic conversation overlay: `pendingConversations` state merged into
      `effectiveConversations`; a freshly created conversation (with real
      member_user_ids so the recipient resolves and sending works) is visible
      instantly, then pruned when the server row lands.
- [x] Reset effect made overlay-aware: only recovers a fallback selection when the
      current conversation has TRULY vanished from the full set — never because
      it is view-filtered or still settling in the overlay.
- [x] `startPrivateChat` returns a success boolean; `startChatWithUser` closes the
      New Chat modal ONLY on success. Every failure path sets a visible, honest
      `contactAction` (updated copy: keys publish on desktop OR Android) — no
      silent close/bounce.
- [x] Breadcrumb logging (`logChatFlow`) on user-select / create / open / error,
      visible in `adb logcat` (webview console) so a failed open is never silent.
- [x] Verified: tsc + vite build clean.
- [x] Rebuilt x86_64 debug APK + emulator E2E (2 confirmed test accounts, since
      cleaned up): New Chat → teslagreat101 opens the CORRECT thread ("Ready",
      "Private channel with teslagreat101"), history resolves, and a real message
      sent ("Verified · Replay-safe"). Reopen-from-list also correct. No bounce.
- [ ] Follow-up: rebuild arm64 release APK for real devices (x86_64 emulator only
      so far). Side note: hard process-kill returns app to login (session
      persistence) — separate from this bug.

## Manual test cases
1. Open existing conversation: tap a conversation in the list → thread opens to
   that exact conversation (no self-only swap), history loads.
2. Create new conversation (keyed recipient): New Chat → search → Message → thread
   opens to the NEW conversation, "E2EE active", compose enabled, send delivers.
3. Device-less recipient: New Chat → search someone with no device → Message →
   modal STAYS open with a clear "hasn't set up a device yet" message (no bounce).
4. Navigation after app restart: relaunch, unlock chat PIN, open a conversation.
5. Offline/reconnect: lose network mid-open → clear error; on reconnect, retry works.

---

# Quantum Vault on Android — content:// URI support (2026-07-12)

## Root cause (test_images/android_error2.png)
1. Android SAF pickers (dialog plugin 2.7.1) return `content://` URIs, but every
   vault command does `std::fs`/`File::open` on the raw string → "No such file or
   directory (os error 2)" on encrypt source + decrypt source.
2. `tauri-plugin-dialog` has NO mobile folder picker ("Folder picker is not
   implemented on mobile") → folder encrypt/decrypt cannot work on Android.
3. Names derive from URI basename → "Decrypting msf%3A33" instead of the filename.

## Done
- [x] New `src-tauri/src/security/content_uri.rs`: JNI ContentResolver bridge
      (openFileDescriptor → detached fd → std::fs::File; DISPLAY_NAME/SIZE query),
      desktop stubs. Reuses keystore.rs JNI pattern (jni + ndk-context).
- [x] vault.rs: `open_vault_source` (content-aware read), `VaultDest` (native
      tmp+rename vs direct SAF fd write + truncate-on-abort), content-aware
      name/size in encrypt. Converted file encrypt/decrypt/verify + recovery/
      enterprise decrypt; rewrap rejects content URIs (in-place temp+rename).
- [x] New commands `vault_resolve_name` (async — provider query off main thread)
      + `vault_default_encrypt_dest` (Android encrypt dest = app-private
      data_dir/vault/files/<name>.qvault so registry paths stay durable).
- [x] QuantumVaultPage.tsx: resolved display names in logs/suggestions (no more
      msf%3A33), Android skips save dialog on encrypt, folder buttons hidden on
      Android + handler guards, re-protect uses registry paths on Android.
- [x] Verified: host cargo check + unit tests (uri_tail/percent-decode), tsc +
      vite build, x86_64-linux-android cargo build via tauri CLI (caught E0499
      borrow errors host check missed), gradle assembleX86_64Debug, installed on
      emulator — app boots clean, no native errors in logcat.
- [ ] PENDING USER: on-device encrypt/decrypt round-trip needs login + workspace
      PIN (only the user has them). Test file staged at
      /sdcard/Download/qguard-vault-test.txt on emulator-5554.
- [ ] After user confirms: rebuild arm64 release APK with the fix.

---

# /pqc-solutions marketing page (2026-07-10)

## Done
- [x] New public marketing page `src/pages/PqcSolutions.tsx` + route `/pqc-solutions` in
      App.tsx (top-level, alongside the other four solution pages).
- [x] Maps all six Problems_To_Solve_1..6 to platform capabilities per
      Qguard_Wiki/Problem_Solution_Traceability.md (Trust-State Discovery, Migration Gate,
      TLS Trust Path Cost, Scanner/Shadow Crypto + Shor-vs-Grover threat model, QKMS,
      Readiness/Planner/Sandbox/Crypto Agility).
- [x] Reuses SolutionLayout + messaging/QR atoms from `_solution-shared.tsx` (violet lead
      accent). Signature: dark "PROBLEM_LEDGER" hero console (override-proof `bg-[#0b1322]`
      rows — NOT `bg-white/*`, which the `--light` sheet lightens). Pattern strip uses the
      matched visibility/ownership/dependencies/risk/migration_gate PNG set.
- [x] Verify: tsc clean; vite build clean; headless-Chrome screenshots of full page (hero
      console pixel-checked #0b1322; all 9 sections render; 500px-wide layout wraps cleanly).
      Note: headless `--window-size=390` screenshots look clipped because new headless clamps
      the window to ~500px min — sibling pages show the identical artifact; not a page bug.

---

# Master Implementations — Problems_To_Solve_1..6 completion pass (2026-07-10)

## Audit results (platform-wide)
- All ~70 dashboard pages verified WIRED to real backends (mode-driven shared dashboards +
  hooks + scanner intelligence). No fabricated fallbacks found in hooks.
- P1/P2 (trust estate, Visibility→Ownership→Dependencies→Risk→Migration Gate):
  trust-state-discovery.ts derives findings/gate/graph from 16 real tables — COMPLETE.
  ecosystem-supply-chain.ts (dependency map/trust chain/vendor readiness/hybrid lab)
  queries 14 real tables — COMPLETE.
- P5 (key lifecycle): qkms-dashboard.ts on real qkms_keys/rotation/policies/audit — COMPLETE.
- P6 (roadmap/agility): QR engine + migration planner + /dashboard/crypto-agility — COMPLETE.
- Removed orphan empty dir src/app/dashboard/runtime-discovery (referenced nowhere).

## Gaps implemented (all verified 2026-07-10)
- [x] P4: Shor/Grover threat-model decomposition — `threatClassFor` + `threatModel`
      snapshot block in quantum-risk-scoring.ts (Shor-exposed public-key / Grover
      symmetric margin / legacy hash / PQC-protected, each with findings, affected
      assets, share, 7d trend, top assets, urgency + roadmap guidance) and the
      "Quantum Threat Model" section with ThreatModelPanel on the page (defensive
      deep-merge in the hook).
- [x] P3: Trust Path Cost — `trustPathCost` block in tls-telemetry.ts (RTT profile
      from TLS versions, key-exchange compute classes, costliest observed paths as
      relative 0-100 index incl. retry cost, hybrid ML-KEM-768 FIPS-203
      bytes-on-wire outlook, methodology caption) + "Trust Path Cost" section with
      TrustPathCostPanel on the TLS Telemetry page. No fabricated latency.
- [x] Traceability report: Qguard_Wiki/Problem_Solution_Traceability.md.
- [x] Verified: root `tsc --noEmit` exit 0; `vite build` exit 0 (1m 5s).
- [x] RUNTIME verified (live dev server, authenticated tenant, real scan data):
      tools/threat-model-cost-check.ts — 20/20 checks on empty AND populated
      tenants (34 Shor-exposed findings from a real badssl scan → "migrate";
      cost index 100 on the legacy TLS path; RTT profile sums to
      totalConnections; hybrid outlook arithmetic exact). Starter tier 403 /
      Elite 200 confirmed the subscription gateway. Test account restored to
      canonical Starter tier afterwards.

---

# Forward Secrecy "Awaiting prekey material" — permanent fix

## Root causes (verified by code trace)
1. **One-time prekeys are never regenerated.** `ensure_identity` (state.rs) generates 24 once
   per device lifetime; `keys_upload_one_time_prekeys` (keys.rs) returns that same static pool
   forever. Every message send claims one via `claim_messaging_one_time_prekey` (marks
   `consumed_at`). Once all 24 published rows are consumed, the frontend re-upserts the same
   IDs with `ignoreDuplicates: true` → zero new rows → available count is 0 permanently.
2. **Device-count-scaled readiness targets.** QuantumSecurityDashboardPage and
   KeyManagementPage compute `signed target = active devices` and `one-time target =
   devices × 8`. Stale device rows from reinstalls make those targets unattainable
   ("1/3 signed prekeys"). security-score.ts already fixed this with per-device floors
   (SIGNED_PREKEY_MIN=1, ONE_TIME_PREKEY_MIN=16) but the two pages were not aligned.
3. **Replenish threshold below readiness floor + runs once per session.** Bootstrap tops up
   only when available < 8 (floor is 16) and only once per app session
   (`deviceBootstrappedUsers` cache), so depletion while running is never healed.

## Plan
- [x] Rust: `keys_replenish_one_time_prekeys(user_id, needed)` async command — generates
      FRESH one-time prekeys, appends to active pool (cap 96), retires oldest into legacy
      pool (cap 192, still decrypt-capable), persists encrypted key material, audits.
      Registered in lib.rs. Pool-cap logic extracted + unit-tested.
- [x] security-score.ts: exported ONE_TIME_PREKEY_TARGET (24) beside the floors.
- [x] messaging-bootstrap.ts: rewrote ensureOneTimePrekeys — diffs local pool against ALL
      published rows (incl. consumed), uploads unpublished, replenishes remaining deficit
      with fresh keys; threshold aligned to ONE_TIME_PREKEY_MIN (16), tops up to 24. Added
      30-day prune of consumed rows NOT in the local pool (never republishes a consumed
      key). Exported throttled (60s) + deduped ensurePrekeyReadiness.
- [x] use-dashboard-data.ts: fires ensurePrekeyReadiness when inventory is below floors;
      resulting prekey inserts arrive as realtime events and refresh counts.
- [x] QuantumSecurityDashboardPage.tsx + KeyManagementPage.tsx: per-device floor targets
      (no more device-count-scaled 1/3 and 0/24).
- [x] Verify: cargo test 47+2 passed; vitest 17 passed; tsc clean; vite build clean.

## Validation strategy
- cargo check + cargo test in qguard-messaging/src-tauri.
- npm run build (tsc + vite) in qguard-messaging.
- Manual trace: consumed-out pool → bootstrap → fresh prekeys inserted → counts recover.

## Rollback plan
- All changes additive: new command + frontend logic. Revert the two page target lines and
  ensureOneTimePrekeys body to restore prior behavior; no schema changes.

---

# Archive: Q-Shrink Vault Engine (complete)

Done: core engine, vault wiring, dashboard panel, 30-check round-trip test, tsc/vite clean,
adversarial review, magic-collision fix. Future ideas: multi-file dedup UI, WASM Zstd/Brotli,
bucketed padding, QSHRN2 64-bit sections.

---

# Report Accuracy Round 7 (complete — 2026-07-11)

User audit of sample executive report (PDF/HTML) found mismatches; all fixed + verified:
- Improvement column mixed units (+65 / -75% / -38) -> uniform points with % annotation (Pdf/Docx/Ppt).
- Domain risk targets (x0.30) vs programme target (x0.25) -> shared reduction engine + new
  "Target Reconciliation Verified" validation check (now 7 checks).
- Remediation dates (now+3/6/9wk) -> roadmap wave finish dates.
- Risk forecast 36-month glide (51/32/14) contradicted 26-week plan -> schedule-anchored
  scenarios (Expected / 2x-slippage / No-programme baseline).
- HNDL Exposure (raw 54) vs HNDL Risk (calibrated domain 50) disambiguated + terminology entry.
- Advisor complexity Low vs asset profile High reconciled (max of platform + per-asset rule).
- Fabricated "Archived data repositories" driver removed; "Assets Assessed" KPI -> "Inventoried Assets";
  resource-loading hours off-by-one (989 vs 988) fixed; finding counts (24/27/160) labeled;
  85 target tied to CERTIFICATION_READINESS_THRESHOLD and explained in executive summary.
Verified: tsc clean, vite build clean, report-export-smoke 14 formats green, live report-check 7/7 PASS.

---

# Report Accuracy Round 8 - Scale & Pipeline Audit (complete - 2026-07-11)

google.pdf review (different user) confirmed R7 fixes live; new fixes:
- Wave costs now reconcile to the dollar (renormalised ratios + remainder push; validation check added).
- Budget canonicalised to whole labour-hours (normalizeBudgetUsd) - one budget figure everywhere.
- Finding families now catch "Deprecated SSL/TLS Version"/TLSv1/TLSv1.1, No Hybrid/PQC, OIDs -
  "Other Cryptographic Findings" no longer the #1 executive risk.
- Backend exact COUNT queries: tenant-wide inventory counts truthful past row caps (1500/2500...).
- Parallel-workstream timeline model: 13k-component estate plans 171wk x 64 lanes, not 10,969wk;
  small estates numerically identical. Mirrored in scoped recompute; estimates.parallelWorkstreams added.
- Scope truth: totalAssetCount = true inventory count + "top N by risk" disclosure; inline default
  scope replaced by buildReportScope (single source).
- scanner.ts loadScannerTables explicit limits (was silent PostgREST 1000-row default).
- Smoke suite: new XL_SCALE scenario (4,800 assets / 12,000 components) with scale assertions.
Verified: tsc, vite build, smoke 4 scenarios x 7 formats, live report-check 7/7 PASS.

## Android Version of QGuard Messaging (Tauri 2 Android) — 2026-07-11

Goal: production-ready Android app from qguard-messaging/src-tauri sharing the desktop PQC core
(ML-KEM-768/1024 + X25519 hybrid, ML-DSA-65 + Ed25519 hybrid, AES-256-GCM, HKDF-SHA3-256),
with a premium Material-3-style mobile UI per test_images/android-design_*.png.

### Rust / Android platform
- [x] Cargo.toml: gate keyring/updater/process to desktop; add jni + ndk-context on Android
- [x] security/keystore.rs: platform DEK storage — desktop OS keychain, Android Keystore (hardware-backed AES-GCM via JNI)
- [x] state.rs: route device-storage-key through keystore abstraction (desktop format unchanged)
- [x] lib.rs: mobile data dir via app_data_dir(), cfg(desktop) plugin registration
- [x] capabilities: split desktop-only permissions (updater/process) from cross-platform set
- [x] tauri.conf.json: Android minSdkVersion 29 (Android 10+)
- [x] tauri android init → gen/android Gradle project (Android Studio compatible)
- [x] AndroidManifest: CAMERA / RECORD_AUDIO / MODIFY_AUDIO_SETTINGS / POST_NOTIFICATIONS; MainActivity runtime permission requests
- [x] Android icons via tauri icon; splash/status-bar theme (light, purple accents)
- [x] Release signing: upload keystore + keystore.properties + gradle signingConfig

### Mobile UI (premium light theme, purple gradients, floating cards)
- [x] globals.css: responsive (drop 960px min-width on phones), safe-area insets, mobile overrides
- [x] use-mobile.ts hook + MobileShell (gradient header + floating bottom nav: Home/Chats/Vault/Security/Settings, unread badge)
- [x] Mobile splash + 3-slide onboarding (pre-login, matches design language)
- [x] LoginPage mobile polish (rounded card, gradient CTA)
- [x] SecureChatPage: single-pane mobile flow (list ⇄ thread, back button, details hidden)
- [x] UpdateBanner/app-update: no-op on Android (no updater plugin on mobile)

### Verification
- [x] tsc + vite build clean (tsc exit 0; vite built in 38s)
- [x] cargo test (host) — keystore refactor regressions (0 failed) + 17 frontend vitest pass
- [x] Debug APK built + verified: app-arm64-debug.apk 155MB, contains lib/arm64-v8a/libqguard_messaging_lib.so, pkg com.qguard.messaging v1.2.20, minSdk29/target36, all perms
- [~] Release-signed APK: building (release .so LTO compile in progress) via gradlew assembleArm64Release
- [x] Docs: ANDROID.md + docs/{ANDROID_NATIVE_ARCHITECTURE,BUILD_NATIVE,ANDROID_SECURITY}.md
- Windows blocker solved: tauri symlinks .so into jniLibs (needs Dev Mode); no-admin fix = build .so, copy to jniLibs, gradlew assembleArm64Debug -x rustBuildArm64Debug
