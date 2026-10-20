# QGuard Helix Integration and Enterprise Controls — Design

**Date:** 2026-10-20 · **Roadmap:** Phase 10 · **Status:** 10.1 built (same login, §5); 10.2 decided (no archive device); 10.3 role-based admin built; SSO prepared only

---

## 1. 10.3 Role-based admin (shipped)

- **Before:** `src/lib/admin.ts` compared the signed-in email with one compiled-in address. It only decided whether internal panels render; every panel shows the caller's own RLS-scoped rows, so nothing leaked. But changing the admin needed a release, and only one person could be named.
- **Now (migration 041):** `messaging_app_roles(user_id, role ∈ {operator}, note, granted_at)`.
  - RLS allows each user to read **only their own** row. There is no insert, update or delete policy, and those privileges are revoked from `authenticated`, so roles are granted only with the service role. `anon` cannot read the table.
  - The migration carries over the previously hard-coded account, so access is unchanged on deploy.
  - The client (`useIsAdmin`) reads the row once per session and treats "no row, an error, or no table" as no role.
- **Verified:** Postgres 16, 9/9 checks: carry-over, idempotent re-apply, self-read, invisible to others, no self-grant, no change or revoke through the API, anon refused, unknown roles rejected. `admin.test.ts` covers the client.
- **Grant another operator:** `INSERT INTO public.messaging_app_roles (user_id, role, note) SELECT id, 'operator', '<why>' FROM auth.users WHERE lower(email) = lower('<email>');`

## 2. 10.1 Messenger posture and CBOM into Helix (design)

**Verified starting point:** Helix's API server accepts evidence per **user**:

- `POST /connectors/:id/evidence` (`requireUserAuth`, `connector_accounts.user_id`) runs `normalizeEvidence` → `evidenceAllowedByPolicy` → `processEvidenceBatch`.
- `POST /agent/evidence` is for scanner agents.

**What the messenger can publish (real data only):**

- **Per device:** algorithm suite (X25519 + ML-KEM-1024, Ed25519 + ML-DSA-65, HKDF-SHA3-256, AES-256-GCM), KEM combiner, prekey age, app version, and ratchet on or off.
- **Per account:** contact-device protection counts (the existing "Your Contacts' Devices" numbers), relay transport measurement (`transport-evidence.ts`) and verification coverage.

All of this is already computed for the Quantum Security dashboard and the exported security report. **Never** message content, contact identities or conversation metadata.

**Open decisions:**

1. **Identity mapping:** is a messenger account the same Supabase identity as a Helix user? `qguard-messaging` has its own `.env` and could point at a different project. If they differ, the user connects the two explicitly with a Helix connector token.
2. **Tenant:** Helix is multi-tenant. Which organisation does a messenger device report to? The proposal is the organisation of the Helix user who created the connector, chosen when connecting.
3. **Push or pull:** the messenger pushes on change (proposed; it is the only place the device-level facts exist), or Helix pulls with a service key (rejected: it would give Helix read access to messenger tables).

**Proposed flow:**

- In Helix, the user creates a connector of type `qguard_messaging` and copies a one-time token.
- In the messenger, Settings → "Report to QGuard Helix" takes that token and pushes CBOM-style evidence via the connector endpoint.
- The user can see and revoke it from both sides.

## 3. 10.2 Retention, legal hold, compliance export (design)

The relay holds only ciphertext, and only the participants' devices hold keys, so **server-side retention or legal hold cannot capture content**, by design. Options:

- **(a) Metadata retention only:** server-side retention of envelope metadata (who and when, not what), with legal hold freezing deletion of those rows. Achievable now.
- **(b) Escrow device:** an organisation-controlled "archive device" enrolled in every conversation of managed accounts, which receives sealed copies like any other device.
  - It is visible to participants as a device: the verification panel lists it, and the protection badge must say so.
  - This is how compliant E2EE archiving is usually done.
  - It is a **major trust change** and needs a policy decision, clear in-app disclosure, and likely a separate managed-account tier.
- **(c) Endpoint export:** a user-initiated, signed export of their own decrypted history from their device (the history backup of Phase 5 is the key half of this).

**Recommendation:** (a) and (c) now; (b) only with an explicit owner decision, because it changes what "end-to-end" means for managed accounts.

## 4. SSO / SAML (design)

- **Mechanism:** Supabase Auth supports SAML 2.0 SSO (Pro plan, configured with `supabase sso add`), and the client calls `supabase.auth.signInWithSSO({ domain })`.
- **Missing in the app:** the desktop and Android apps currently use email and password only, with no redirect-based sign-in. SSO needs:
  - a deep-link handler (`tauri-plugin-deep-link`) so the IdP redirect returns to the app, using PKCE;
  - an "Organisation sign-in" entry on the login screen that takes the work email's domain.
- **Keys:** SSO governs **who may sign in**, not keys. A new device still enrols its own keys and appears to contacts as a new device, so pins and verification are unchanged.
- **Owner decisions:** the Supabase plan, which IdPs to support first, and whether SSO accounts may also hold a password.

---

## 5. Owner decisions of 2026-10-20 and what was built

### 10.1 Same login: built

- **Login:** both apps use one Supabase project (verified by comparing the project ref in each `.env`), so a messenger account *is* a Helix account. No connector token or pairing is needed.
- **Endpoint:** `POST /api/v1/agent-scanner/integrations/qguard-messaging/sync` (`requireUserAuth`) reads the caller's own `messaging_devices` rows (explicit `user_id` filter, because `req.client` can fall back to the service client).
- **Derivation:** `src/lib/messaging-posture-evidence.ts` turns each active device's **published suite** into evidence rows (`messaging-device-crypto`) — key establishment, signature, message encryption, key derivation — which go through Helix's normal `processEvidenceBatch`.
  - A FIPS 203 device is "X25519 + ML-KEM-1024" and Helix's own parser grades it hybrid.
  - A pre-FIPS Kyber device is reported by its classical half (X25519) with a note, so it is never PQC-ready.
  - Revoked devices are skipped.
  - Nothing but suite metadata is read: no messages, contacts or conversations.
- **Rate limit:** at most one sync per minute per user.
- **UI:** Collector console → Operations → "QGuard Messaging" → *Import messenger devices* (shows device count and last import).
- **Verified:** `tools/messaging-posture-check.ts` 13/13 (run in Deno), including Helix's parser agreeing with each grade; Helix `tsc --noEmit` clean.
- **Not verified:** a live import against the deployed API.

### 10.2 No archive device

The owner decided that an organisation must **not** be able to add an archive or escrow device to members' conversations. Option (b) in §3 is rejected: message content is never retained for organisations. Metadata retention (a) and the user's own export (c) remain open and are not built.

### SSO: prepared only

See `2026-10-20-sso-preparation.md`: Supabase Pro; Microsoft Entra ID first, then Okta, then Google Workspace. Deep-link sign-in is the prerequisite. Nothing is implemented, by the owner's decision.
