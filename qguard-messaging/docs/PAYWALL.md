# QGuard Subscriptions — Google Play Billing, PayPal, Entitlements

**Spec:** `Qguard_Wiki/GooglePlay_Billing` (2026-11-12) · supersedes `Qguard_Wiki/Android_Paywall_Guidelines`
**Last updated:** 2026-11-12

## Commercial rules (owner decisions 2026-11-12)

| Rule | Decision |
|---|---|
| Tiers | Starter, Basic, Pro, Elite — **all paid**, strict ladder (each includes every lower tier) |
| Free tier / free trial / intro offer | None |
| Prices (USD list) | Starter $1 / $12 · Basic $5 / $60 · Pro $20 / $240 · Elite $150 / $1,800 |
| Annual pricing | Fixed yearly charges listed below |
| Money-back guarantee | None (legal and Google Play refund rights still apply; refunds/revocations are processed) |
| Subscriptions per account | One. Plan changes replace it in place (Play `SubscriptionUpdateParams`, PayPal `revise`) |
| Cancellation | Access continues to the verified paid-through date |
| Android purchases | **Google Play Billing only** inside the Play-distributed app — no PayPal fallback |
| Web / desktop purchases | PayPal (live) |
| Authority | Backend only: Google Play Developer API / PayPal → `billing_subscriptions` → `user_entitlements` |

Single sources of truth in code: `src/lib/billing/plan-pricing.ts` (prices),
`supabase/functions/billing/entitlements.ts` (entitlement keys per tier, mirrored
by `subscription_entitlement_catalog`), `supabase/functions/billing/logic.ts`
(Play products, state mapping, access rule). `tools/billing-edge-check.ts`
asserts that the SQL seed, the web route gating, the client catalog and the
backend agree.

## Architecture

```
Android app (Tauri + React)
  │ GET /api/v1/subscriptions/me ──► playAccountId = SHA-256(user id)   (no PII to Google)
  │ PlayBilling.kt (Billing Library 8.3.0): ProductDetails (localized price), base-plan offer only
  │ launchBillingFlow(obfuscatedAccountId = playAccountId)
  ▼
Google Play ──► purchase token
  │ POST /api/v1/subscriptions/verify   (Supabase JWT; identity from the JWT, never the body)
  ▼
billing service (supabase/functions/billing — Edge Function; the same play-service.ts
                 is mounted by Express at /api/v1/subscriptions for self-hosting)
  1. purchases.subscriptionsv2.get   (package path = GOOGLE_PLAY_PACKAGE_NAME)
  2. product must be one of the 8 qh_* products; binding must equal the caller
  3. token fingerprint (SHA-256) must not belong to another account (DB unique index)
  4. replaced/linked tokens never overwrite the newer plan
  5. upsert billing_subscriptions (token sealed with AES-256-GCM) ──trigger──► user_entitlements
  6. invoice at Google's recurringPrice (test purchases recorded at $0)
  7. acknowledge AFTER durable recording (retried by reconcile if it fails)
  ▼
Supabase Realtime (billing_subscriptions, billing_invoices, user_entitlements)
  ──► every signed-in device (desktop + Android) unlocks/locks live

Google Play RTDN ──► Pub/Sub push (OIDC) ──► POST /api/v1/webhooks/google-play/rtdn
  inbox row persisted first (play_webhook_events) ─► re-query Google ─► same apply path
  failures: 5xx → Pub/Sub retry; reconcile sweep replays; dead_letter after 8 attempts

Desktop/web ──► POST /api/v1/paypal/subscribe ─► PayPal approval ─► confirm + webhook ─► same tables
```

### Enforcement layers

1. **Database (authoritative):** `qguard_has_messaging_access(uid)` backs the RESTRICTIVE
   insert policies on messages, conversations and call signals (migration 030, redefined in
   `supabase/google-play-billing-v2.sql`). `qguard_has_entitlement(uid, key)` is the
   server-side gate for any protected operation. Clients cannot write
   `billing_subscriptions`, `user_entitlements` or the audit trail (RLS + grants; verified live).
2. **Access rule** (identical in SQL `qguard_subscription_access_until`, `logic.ts rowGrantsAccess`,
   `qguard-messaging/src/lib/subscription.ts`, `src/lib/subscription-access.ts`):
   status `active` or `pending_renewal` (Play grace period) and the period end not passed by more
   than the provider tolerance — **1 h for Google Play** (Google moves `expiryTime` itself; this only
   covers notification latency), 72 h for PayPal (renewal-webhook lag). `trial` grants nothing.
3. **Time without events:** `qguard_sweep_expired_entitlements()` (pg_cron, every 5 min) withdraws
   entitlements whose access ended; `qguard_expire_cancelled_subscriptions()` (every 10 min) ends
   PayPal cancellations at period end; the reconcile sweep re-queries Google for Play rows near or
   past expiry, unacknowledged, or not verified for 24 h.
4. **UI gate:** `PaywallGate` + `useSubscription` (realtime + period-boundary timer). Presentation only.

Subscription expiry never deletes local Quantum Vault data, the account, or billing history.

## Google Play products (Play Console)

Eight subscription products, **one base plan each, no offers** (the app only ever buys the
base-plan offer — `offerId == null` — so a promotional offer created by mistake is never sold):

| Product ID | Base plan | Qguard USD list price |
|---|---|---:|
| `qh_starter_monthly` | monthly (P1M, auto-renewing) | $1 |
| `qh_starter_yearly` | yearly (P1Y, auto-renewing) | $12 |
| `qh_basic_monthly` | monthly | $8 |
| `qh_basic_yearly` | yearly | $60 |
| `qh_pro_monthly` | monthly | $30 |
| `qh_pro_yearly` | yearly | $240 |
| `qh_elite_monthly` | monthly | $199 |
| `qh_elite_yearly` | yearly | $1,800 |

The table shows Qguard list prices. Set and verify actual regional base plan prices in Play Console. Android uses the price returned by Google Play when available.

Product IDs cannot be reused once deleted. If one must change, set
`PLAY_PRODUCT_<TIER>_<MONTHLY|YEARLY>` on the billing service; the app reads the mapping from
`/api/v1/subscriptions/catalog` (no app release needed). The previous `qguard_<tier>` convention is
retired; purchases of unknown products are rejected.

## Operator setup — what must be done outside the code

### Done (2026-11-12, verified)
- `supabase/google-play-billing-v2.sql` applied to `iqtofyaekpiniswleakt` (16 products, 33 entitlement
  keys, entitlements backfilled for the 4 comp accounts, cron jobs, realtime publication).
- `billing` Edge Function **v3** deployed (verify_jwt = false; every user route verifies the JWT itself).
- Live checks: `npx tsx tools/billing-edge-check.ts --live` (54/54) and
  `npx tsx tools/billing-e2e-live-check.ts` (14/14: real session, realtime grant + expiry, RLS, cleanup).

### Still required (blocking real Google Play sales)
1. **Purchase-token encryption key** — a new 32-byte key must be stored as the Edge Function secret
   `PLAY_TOKEN_ENCRYPTION_KEY` (and in the Express env). Without it purchases still verify, but tokens
   are not retained, so the reconcile sweep cannot re-query Google. Generate once, never rotate without
   re-encrypting: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`.
2. **Play Console**: create the 8 products above (no trial, no intro offer), activate them, add
   license testers, publish an internal-testing build containing Billing Library 8.
3. **Google Cloud**: enable *Google Play Android Developer API*; create a dedicated service account;
   in Play Console → Users and permissions, invite it with **View financial data** and **Manage orders
   and subscriptions** only. Store its JSON as `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON` and set
   `GOOGLE_PLAY_PACKAGE_NAME=com.qguard.messaging`. `/health` then reports `playVerification: true`
   and the Android app starts offering purchases.
4. **RTDN**: create Pub/Sub topic; grant `google-play-developer-notifications@system.gserviceaccount.com`
   *Pub/Sub Publisher* on it; create a **push** subscription to
   `https://iqtofyaekpiniswleakt.supabase.co/functions/v1/billing/api/v1/webhooks/google-play/rtdn`
   with **authentication enabled** (a dedicated push service account, audience = that URL), a
   dead-letter topic, and retry policy. Set `PLAY_RTDN_AUDIENCE` (the audience) and
   `PLAY_RTDN_SERVICE_ACCOUNT` (the push SA email). Optionally also append `?token=` and set
   `PLAY_RTDN_TOKEN`. Then Play Console → Monetization setup → topic name → *Send test notification*.
5. **PayPal**: monthly prices dropped (Basic $8→$5, Pro $30→$20, Elite $199→$150). Yearly prices are
   unchanged ($60/$240/$1,800). Reprice the three monthly plans with `tools/paypal-update-pricing.ts`
   (there are no paying PayPal subscribers today — only comp grants).
6. **Release**: upload the rebuilt AAB (`src-tauri/release/QguardMessaging-release.aab`) — bump the
   version first if 1.5.0 was already uploaded.
7. **Legal**: the Refund Policy and Terms no longer offer a money-back guarantee; review, update
   `SITE.effectiveDate`, and announce per the policy's change clause.

## Files

| Area | File |
|---|---|
| Migration | `supabase/google-play-billing-v2.sql` (after the files listed in its header) |
| Shared rules | `supabase/functions/billing/logic.ts`, `entitlements.ts` |
| Service (verify, RTDN, reconcile, subscription API) | `supabase/functions/billing/play-service.ts` |
| Edge Function routes | `supabase/functions/billing/index.ts` |
| Express mounts | `src/api-server/subscriptions.ts`, `src/api-server/play-billing.ts` (legacy aliases) |
| Admin dashboard | Revenue Intelligence → Subscriptions → *Billing operations* (`src/lib/billing/billing-ops.ts`) |
| Android bridge | `gen/android/.../PlayBilling.kt` (Billing Library 8.3.0, non-ktx), `src-tauri/src/commands/billing.rs` |
| Client | `src/lib/play-billing.ts`, `billing-api.ts`, `subscription.ts`, `use-subscription.ts`, `pages/SubscriptionPage.tsx` |
| Checks | `tools/billing-edge-check.ts [--live]`, `tools/billing-e2e-live-check.ts`, `tools/revenue-intelligence-check.ts` |

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/subscriptions/catalog?platform=google_play\|paypal` | public | Products, list prices, tier entitlements, Play product map |
| GET | `/api/v1/subscriptions/me` | JWT | Verified subscription, access, entitlements, `playAccountId` |
| GET | `/api/v1/subscriptions/entitlements` | JWT | Effective entitlement keys |
| GET | `/api/v1/subscriptions/history` | JWT | Invoices + lifecycle events |
| POST | `/api/v1/subscriptions/verify` | JWT | Verify one Play purchase token (rate-limited 20/min/account) |
| POST | `/api/v1/subscriptions/restore` | JWT | Re-verify up to 10 tokens from this device |
| POST | `/api/v1/webhooks/google-play/rtdn` | Pub/Sub OIDC and/or shared secret | RTDN |
| POST | `/api/v1/paypal/subscribe` · `/confirm` · `/webhook` · `/reconcile` | JWT / PayPal sig / secret | PayPal (web/desktop) |

`/api/v1/play-billing/verify` and `/rtdn` remain as aliases for older builds.

## Testing checklist (needs the Play setup above + a test device)

- [ ] Each of the 8 products: purchase → verify → unlock on Android and desktop live
- [ ] User cancels the purchase sheet → no change; pending payment → "pending", no access
- [ ] Restore purchases after reinstall / on a second device
- [ ] Token from another account → 409 `TOKEN_ALREADY_CLAIMED`; wrong product → 400
- [ ] Upgrade Starter→Pro and downgrade Pro→Basic (in place; old token's EXPIRED does not lock)
- [ ] Cancel in Play → "canceled and will remain active until …"; expiry → locked live
- [ ] Grace period, account hold (Play test cards), recovery
- [ ] Refund / revoke from Play Console → invoice refunded, access revoked
- [ ] RTDN test notification → 200; forged push → 401
