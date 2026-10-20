# SSO / SAML — Preparation (not implemented)

**Date:** 2026-10-20 · **Roadmap:** Phase 10.3 · **Owner decision:** prepare SSO for future use; do not implement it now.

This document is the checklist for turning SSO on later. Nothing in the app changes until then. The current sign-in methods (email and password, MFA) stay as they are.

---

## 1. Recommendations

| Question | Recommendation | Why |
| --- | --- | --- |
| Supabase plan | **Pro** (the lowest plan that offers SAML 2.0 SSO); Team or Enterprise if you need SOC 2 reports, SSO into the Supabase dashboard itself, or longer log retention | SAML SSO is a paid Auth feature, billed per monthly active SSO user on top of the plan. Check current pricing before enabling. |
| First identity provider | **Microsoft Entra ID** (Azure AD) | The most common workforce IdP among the regulated organisations Helix targets. |
| Second | **Okta** | The other dominant enterprise IdP; it uses the same SAML configuration shape, so adding it costs little. |
| Third | **Google Workspace** | Common in smaller organisations. Also SAML. |
| Protocol | SAML 2.0 through Supabase Auth (`supabase sso add`) | Supported natively. OIDC enterprise SSO would need a custom provider. |
| Shared login | One Supabase project serves both QGuard Helix and QGuard Messaging (verified: both `.env` files point at the same project). Enabling SSO there enables it for both apps. | This matches the decision that a messenger account is the same login as a Helix account. |

## 2. What SSO changes, and what it doesn't

- **It controls who may sign in.** It does not touch end-to-end keys. A user's new device still creates its own keys and appears to contacts as a new device. Pins, safety numbers and verification are unchanged.
- **Removing someone at the IdP** stops new sign-ins and token refreshes. It does **not** wipe devices that are already signed in. Revoking those stays a Device Trust Center action, or an admin action that calls `revoke_messaging_device`.
- **Recovery keys and history backups** stay the user's own. An organisation that adopts SSO does **not** gain access to message content (owner decision 2026-10-20: no archive device).

## 3. Prerequisites to build first (in order)

1. **Redirect-based sign-in in the apps.** Today both apps use email and password only.
   - Desktop: `tauri-plugin-deep-link` with a registered scheme (for example `qguard-messaging://auth/callback`), and PKCE (`flowType: "pkce"` in the Supabase client).
   - Android: an intent filter for the same scheme, or an App Link on a verified domain.
   - Helix web: a callback route on the existing origin.
2. **An "Organisation sign-in" entry** on both login screens. It takes the work email, extracts the domain, and calls `supabase.auth.signInWithSSO({ domain, options: { redirectTo } })`, then opens the returned URL in the system browser (never in the WebView) and completes the session on the deep link.
3. **Account linking rule:** whether an SSO identity with the same email as an existing password account becomes the same user. Supabase links identities by verified email; decide whether that is allowed for your tenants.
4. **Role mapping:** keep `messaging_app_roles` (migration 041) as the source of truth for operators. Do **not** grant roles from IdP group claims until there is a reviewed mapping table.
5. **Tests:** a SAML test IdP (for example a local `samltest` container or an Entra test tenant). Sign-in, sign-out, a disabled user and an expired assertion must each behave correctly.

## 4. Enabling it (when you decide to)

```bash
# Supabase CLI, logged into the project (Pro plan or higher)
supabase sso add --type saml --project-ref <project-ref> \
  --metadata-url 'https://login.microsoftonline.com/<tenant-id>/federationmetadata/2007-06/federationmetadata.xml' \
  --domains example.com
supabase sso list --project-ref <project-ref>
```

In the IdP:

- **Entity ID / Audience:** `https://<project-ref>.supabase.co/auth/v1/sso/saml/metadata`
- **ACS URL:** `https://<project-ref>.supabase.co/auth/v1/sso/saml/acs`
- **NameID:** the user's email.
- Send an `email` attribute.

Add every app redirect URL (desktop scheme, Android scheme, Helix web callback) to **Auth → URL configuration → Redirect URLs**.

## 5. Placeholders already in place

- The repository-root `.env.example` documents `VITE_SSO_ENABLED` (default `false`). No code reads it yet. It marks where the login screen's SSO entry will be gated, so a build can ship the feature dark.
- This document. Nothing else: there is deliberately no dormant SSO code path to review or keep working.
