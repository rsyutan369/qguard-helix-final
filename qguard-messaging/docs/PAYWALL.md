# QGuard Messaging Subscription Paywall

**Spec:** `Qguard_Wiki/Android_Paywall_Guidelines` · **Date:** 2026-07-15

A STARTER (or higher) subscription unlocks QGuard Messaging. The subscription
belongs to the **account**, not the device: `public.billing_subscriptions` in
Supabase is the single source of truth, written only by server-verified payment
flows, and streamed to every logged-in session in real time.

---

## Architecture

```
Android app ──► Google Play Billing ──► purchase token
                                          │
                                          ▼
                    POST api.qguard.dev/api/v1/play-billing/verify   (Bearer session)
                    — Google Play Developer API (subscriptionsv2)
                    — obfuscatedExternalAccountId == user id  (account binding)
                    — token-reuse rejection (one token = one account)
                    — acknowledge                                     │
Desktop app ──► POST /api/v1/paypal/subscribe ─► PayPal approval URL │
                (existing verified-webhook flow)                      │
                                          ┌───────────────────────────┘
                                          ▼
                     public.billing_subscriptions (+ invoices, audit, notifications)
                                          │  supabase_realtime
              ┌───────────────────────────┼───────────────────────────┐
              ▼                           ▼                           ▼
     Desktop session unlocks     Android session unlocks     any future session
```

Ongoing lifecycle sync:
- **PayPal** → existing `/api/v1/paypal/webhook` (verified, idempotent, retried).
- **Google Play** → `/api/v1/play-billing/rtdn` (Pub/Sub push): RENEWED /
  RECOVERED / CANCELED / ON_HOLD / GRACE / PAUSED / REVOKED / EXPIRED. Every
  RTDN re-fetches the authoritative state from Google before writing.
- **Reconciliation** → existing `/api/v1/paypal/reconcile` (cron) repairs drift.

## Enforcement layers (defense in depth)

1. **UI gate** — `src/components/PaywallGate.tsx` mounted from `App.tsx`:
   without access, premium modules (chat, vault, calls, keys, devices, audit,
   dashboard) never mount; only Subscription + Settings + sign-out remain.
2. **Database (authoritative)** — migration
   `qguard-messaging/supabase/migrations/030_messaging_paywall_enforcement.sql`:
   `qguard_has_messaging_access(uid)` + RESTRICTIVE INSERT policies on
   `messaging_message_envelopes`, `messaging_conversations`,
   `messaging_call_signals`. A tampered client cannot send messages or place
   calls without an access-granting subscription row.
3. **Expiry while logged in** — realtime status flips lock the UI instantly; a
   local boundary timer also re-checks when `current_period_end` (+72 h grace)
   passes, so expiry engages even with realtime briefly down.

Access-granting statuses: `active`, `trial`, `pending_renewal` — identical in
`src/lib/subscription-access.ts` (platform), `src/lib/subscription.ts`
(messaging client), and migration 030 (database).

## Files

| Area | File |
|---|---|
| DB enforcement | `qguard-messaging/supabase/migrations/030_messaging_paywall_enforcement.sql` |
| DB Play ledger | `supabase/play-billing-migration.sql` |
| Play backend | `src/api-server/play-billing.ts` (+ mount in `index.ts`) |
| Client model | `qguard-messaging/src/lib/subscription.ts` (+ tests) |
| Client hook | `qguard-messaging/src/lib/use-subscription.ts` (realtime + boundary timer) |
| UI | `qguard-messaging/src/pages/SubscriptionPage.tsx`, `src/components/PaywallGate.tsx` |
| App wiring | `qguard-messaging/src/App.tsx`, `Sidebar.tsx`, `MobileShell.tsx`, `lib/types.ts` |
| Rust bridge | `qguard-messaging/src-tauri/src/commands/billing.rs` (+ `lib.rs`, `Cargo.toml`) |
| Android | `gen/android/.../com/qguard/messaging/PlayBilling.kt`, `app/build.gradle.kts` (billing-ktx 7.1.1) |

## Setup (operator)

### 1. Database (Supabase SQL Editor, in order)
1. `supabase/billing-subscription-schema.sql` (if not already applied)
2. `supabase/paypal-subscription-migration.sql` (if not already applied)
3. `supabase/play-billing-migration.sql`
4. `qguard-messaging/supabase/migrations/030_messaging_paywall_enforcement.sql`

> ⚠️ Step 4 turns the paywall ON for message/conversation/call inserts.
> Existing accounts without a subscription row lose send/call ability until
> they subscribe. Manual comp grant (also in the migration header):
> ```sql
> INSERT INTO public.billing_subscriptions (user_id, subscription_id, provider, plan, status, billing_cycle)
> VALUES ('<user-uuid>', 'comp_<user-uuid>', 'manual', 'Starter', 'active', 'monthly')
> ON CONFLICT (user_id) DO UPDATE SET plan = EXCLUDED.plan, status = 'active', updated_at = now();
> ```

### 2. Google Play Console
1. Create subscription products (one per tier you sell on Android):
   product id `qguard_starter` (and optionally `qguard_basic`, `qguard_pro`,
   `qguard_elite`) with base plans `monthly` and `yearly`.
2. Create a Google Cloud service account, grant it **Financial data** +
   **Manage orders** access in Play Console → API access.
3. Monetization setup → Real-time developer notifications: create a Pub/Sub
   topic, add a **push** subscription to
   `https://api.qguard.dev/api/v1/play-billing/rtdn?token=<PLAY_RTDN_TOKEN>`.

### 3. API server env (api.qguard.dev deployment)
```
GOOGLE_PLAY_PACKAGE_NAME=com.qguard.messaging
GOOGLE_PLAY_SERVICE_ACCOUNT_JSON={"client_email":"...","private_key":"..."}   # or GOOGLE_PLAY_SA_EMAIL + GOOGLE_PLAY_SA_PRIVATE_KEY
PLAY_RTDN_TOKEN=<long random secret>
# optional product-id overrides (default qguard_<tier>):
# PLAY_PRODUCT_STARTER=... PLAY_PRODUCT_BASIC=... PLAY_PRODUCT_PRO=... PLAY_PRODUCT_ELITE=...
```
PayPal env (`PAYPAL_CLIENT_ID`, `PAYPAL_SECRET_KEY`, `PAYPAL_WEBHOOK_ID`,
`PAYPAL_PLAN_*`, `APP_ORIGIN`) is unchanged from the existing pricing flow.

### 4. Messaging app env (optional)
```
VITE_BILLING_API_ORIGIN=https://api.qguard.dev   # default; override for staging
```

## User flows

- **New user**: install → register → login → paywall (plans grid) → pay
  (Google Play on Android / PayPal browser checkout on desktop) → backend
  verifies + activates → realtime unlocks → dashboard.
- **Existing subscriber login**: entitlement loads before the shell renders —
  no paywall, no re-purchase prompt, on either platform.
- **Cross-platform**: purchase on Android → desktop session unlocks live (and
  vice versa). One account, one subscription.
- **Expiry/cancel/payment-failure while logged in**: realtime status flip →
  premium modules unmount immediately, expiration banner + Subscription page.
- **Restore purchases**: Android re-queries Google Play and re-verifies tokens
  server-side; desktop re-syncs the account subscription. Reinstalls and new
  devices unlock via login + restore.
- **Upgrade**: PayPal `revise` (in-place, prorated) or Play
  `SubscriptionUpdateParams` (CHARGE_PRORATED_PRICE) — never a second
  subscription.

## Security properties

- No client-side trust: activation happens only after PayPal webhook
  verification or Google Play Developer API validation.
- Account binding: Play purchases carry `obfuscatedAccountId` = Supabase user
  id; the server rejects mismatches (409 `ACCOUNT_MISMATCH`).
- Replay/duplicate defense: one purchase token activates exactly one account
  (409 `TOKEN_ALREADY_CLAIMED`); PayPal/RTDN events are idempotent by ledger
  (`paypal_webhook_events` / `play_webhook_events`); raw Play tokens are never
  persisted (SHA-256 hashes only).
- Server-side lockout: RLS RESTRICTIVE policies stop sends/calls regardless of
  client state; JWT (Supabase session) authenticates every billing API call.
- Auditability: `billing_audit_events` + webhook ledgers record every
  activation, sync, and state change.

## Testing checklist (requires deployed API + store setup)

- [ ] New Android user purchase (Play sandbox/license testers) → unlock
- [ ] Desktop login after Android purchase → unlocked without prompt
- [ ] New desktop user purchase (PayPal sandbox) → unlock
- [ ] Android login after desktop purchase → unlocked without prompt
- [ ] RTDN test notification (Play Console button) → 200
- [ ] Renewal (Play test renewals are accelerated) → invoice row + dates move
- [ ] Cancel on Play / in-app PayPal cancel → status syncs, access until period end
- [ ] Expiry → both sessions lock live, banner shown
- [ ] Payment failure (Play "decline" test card) → grace then lock
- [ ] Restore purchases after reinstall
- [ ] Tampered client: direct INSERT into messaging_message_envelopes without
      subscription → RLS rejects
- [ ] /verify with another account's token → 409
