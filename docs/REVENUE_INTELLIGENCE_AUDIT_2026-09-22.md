# Revenue Intelligence — Production Readiness Audit (2026-09-22)

Scope: `/dashboard/revenue-intelligence` and its five sub-pages, per
`Qguard_Wiki/Revenue_Intelligence_Audit`, traced UI → hook → API → service →
Supabase → webhooks/SSE → audit trail → Admin UI / User UI.
Environment: local dev (`:3000`) against Supabase project `xsbdlahuecadzfajlvis`
(3 QA subscriptions, 0 invoices, 4 accounts at audit time).

## Executive summary

- **Status: production-ready for the application layer.** The `billing` Edge
  Function was redeployed as v3 on 2026-09-22 after approval; one hosting step remains (below). All 43 live/offline checks and 40 render checks pass.
- **Critical findings (fixed and applied):** any signed-in user could grant
  themselves Elite by editing their own subscription row or profile tier; the
  dashboard reported $39 MRR / $468 ARR from three unpaid QA accounts.
- **Open deployment step:** the Express `/api/v1` — which serves this dashboard —
  is not hosted in production (qguardhelix.com is static Cloudflare Pages).

## Issues found

| # | Sev | Area | Root cause | Fix | Verified by |
|---|---|---|---|---|---|
| 1 | Critical | DB / RLS | `billing_subscriptions_insert_own` / `_update_own` let a user write plan+status | Policies dropped (`billing-integrity-hardening.sql`, applied) | live probe: update → 0 rows, insert → error (was `ALLOWED rows=1`) |
| 2 | Critical | billing.ts | `ensureSubscription` INSERTed an **active** row from user-writable `profiles.tier` on GET | No insert on read; missing row = `incomplete` | live: GET /billing creates nothing; cancel → 409 |
| 3 | Critical | DB | `profiles_update_own` allowed tier/account_status/permissions/quota edits | `trg_profiles_protect_managed_columns` (42501) | live: tier write refused, name edit allowed |
| 4 | Critical | Model | QA/comp/admin-granted rows counted as MRR ($39 fabricated) | Provider/manual/complimentary classification; MRR = provider-billed only | offline QA control; live MRR = independent recompute (0) |
| 5 | High | API | `.limit(5000/10000/20000)` capped at PostgREST max_rows 1000 — silent undercount | `.range()` paging on `id`, dedupe, ceiling disclosure | code + coverage block in snapshot |
| 6 | High | Play billing | Invoice `upsert(onConflict)` on partial index (42P10) swallowed → no Play revenue ever | select-then-insert; keeps original payment date | code review (no Play traffic in env) |
| 7 | High | Webhooks | Failed payments never recorded → success rate could not fall | `failedPaymentInvoiceRow` (Edge + Express) | offline logic checks |
| 8 | High | Audit | User billing actions audited with user token → RLS-rejected, error ignored; webhooks wrote no payment/refund/status audit | Service-client audit, logged failures; `BILLING_AUDIT` vocabulary | live: rows land; offline writer/reader contract |
| 9 | High | Admin | Admin wrote `approved`/`inactive`/`canceled` → CHECK violation; Approve/Deactivate/Cancel always failed | DB status vocabulary | live `--mutate`: deactivate→suspended→activate |
| 10 | High | Admin | Admin could change plan/period of PayPal-billed subs (desync from charges) | 409 `PROVIDER_MANAGED`; PayPal cancel fails closed | live `--mutate`: 409 and 502 with row unchanged |
| 11 | High | Admin ↔ Revenue | Two MRR formulas; admin 7-day revenue read null columns (always 0) | Shared `subscriptionMrrCents`, `invoiceAmountCents` | live: admin MRR == revenue MRR |
| 12 | High | UI | Loading/error states rendered `$0.00` KPIs as real; SSE errors ignored; export failures silent | Skeleton, error+Retry, stale banner, export toast | 40 render checks |
| 13 | High | Model | Server-local windows vs UTC timeline; USD+EUR summed; partial refunds counted in full at payment date | UTC, per-currency exclusion, refund-at-refund-time | offline fixture (UTC boundary, refunds, EUR) |
| 14 | High | Forecast | Partial month in regression; partial-month growth compounded; projections shown at "insufficient history" | Completed months only, ≥3 to project, retention model, labelled assumptions, backtest | offline positive + negative controls |
| 15 | Medium | Model | Health filled unmeasured inputs with 0/100 | Weight redistribution; `measuredWeightPct` | offline |
| 16 | Medium | SSE | No cache (N tabs × 10 s × full build); close handler after first await (timer leak); token never re-checked | 5 s single-flight cache, change-only push, `revenue-reauth`, 6-stream cap | live SSE check |
| 17 | Medium | Export | Exports used the 200-row snapshot; CSV formula injection possible | Full-model exports, `csvCell` guard, BOM, 30/min | live + offline |
| 18 | Medium | Webhooks | Duplicate side effects on concurrent redelivery; refund redelivery could re-flip | Claim ledger (`status/claimed_at/attempts/last_error`), refunds by id, no overwrite of recorded sales | offline claim decisions |
| 19 | Medium | UI | No sort/pagination, no customer detail, 200-row caps undisclosed | Sortable/paginated tables, customer drawer (`/customers/:id`, audited), ledger-limit notes | render + live |
| 20 | Medium | Realtime | `billing_notifications` not in `supabase_realtime` → User UI alerts needed reload | Added to publication | SQL verification |
| 21 | Low | Admin | "↑ 0% vs last month" with no baseline; label misnamed invoice growth as MRR growth | null + honest label | code |
| 22 | Low | Nav | Home "Business Impact" linked non-owners to an owner-only page | Owner-only link; layout owner gate | code |

## Feature audit matrix

| Feature | Frontend | Backend | Database | Realtime | Audit log | Security | Status |
|---|---|---|---|---|---|---|---|
| Executive KPIs / trends | PASS | PASS | PASS | PASS (SSE) | n/a | PASS | PASS |
| Revenue analytics / windows | PASS | PASS | PASS | PASS | n/a | PASS | PASS |
| Subscription analytics / ledger | PASS | PASS | PASS | PASS | PASS (plan changes) | PASS | PASS |
| Customer analytics / drawer | PASS | PASS | PASS | PASS | PASS (`revenue.customer.viewed`) | PASS | PASS |
| Payment analytics / ledger | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| Forecast / scenarios / backtest | PASS | PASS | n/a | PASS | n/a | PASS | PASS (no history yet in env) |
| Exports (5 × CSV/JSON) | PASS | PASS | PASS | n/a | PASS (`revenue.export`) | PASS | PASS |
| PayPal webhook (Edge, production) | n/a | PASS (v3 live) | PASS | n/a | PASS | PASS | PASS (signed-event path awaits first real PayPal event) |
| Google Play invoices | n/a | PASS (code) | PASS | n/a | PASS | PASS | NEEDS VERIFICATION (no Play traffic) |
| Admin subscription actions → User UI | PASS | PASS | PASS | PASS | PASS | PASS | PASS (live `--mutate`) |
| User billing actions | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

## Data consistency

Ten invariants are computed on every build and shown in every page footer;
all pass live. Admin > Plans & Billing MRR and access-granting count equal
Revenue Intelligence (asserted live, and during `--mutate` with a provider row).

## Remaining actions

1. DONE — `billing` v3 deployed (`npx supabase functions deploy billing --no-verify-jwt --use-api`);
   live check 18/18, clean boots, claim protocol proven on the live schema. The
   pre-audit v2 source was downloaded for rollback before deploying.
2. Host the Express API (`src/api-server/standalone.ts`) for production.
3. Follow-ups — all completed 2026-09-22:
   - **Type errors:** `tsc --noEmit` 11 -> 0. Admin security donuts read `label`
     but received `role`/`status` (blank legends); dead fake-telemetry hook
     `src/hooks/useRealtimeStream.ts` (Math.random logs/metrics) deleted.
   - **Access role:** `profiles.role` is read by Copilot RBAC; Settings let users
     type it (an admin-restricted auditor could type "admin"). Now read-only in
     Settings, dropped from `PUT /api/v1/profile`, protected by the trigger.
   - **Cancellation (owner decision: access until period end):** shared
     `cancellationPatch` keeps the row access-granting with
     `cancel_at_period_end`; `public.qguard_expire_cancelled_subscriptions()`
     (pg_cron `*/10`) ends it, audits `subscription.access_ended` and notifies.
     Edge Function v4 deployed; churn is dated at the period end.
   - **SECURITY DEFINER hardening** (`supabase/security-definer-hardening.sql`):
     closed three real holes (anyone could reset another user's messaging
     defaults; anon could plant security-log events for any user; any user could
     read another's messaging-subscription status) plus membership/contact
     oracles, without breaking RLS: a rolled-back dry run compared 70
     user x table visibility cells before/after (0 changes). anon-executable
     definer functions 28 -> 10 (intentional), authenticated 45 -> 32, mutable
     search_path 19 -> 0.

## Evidence

```
npx tsx tools/revenue-intelligence-check.ts --live --mutate   # 48/48
npx tsx tools/revenue-intelligence-render-check.ts            # 40/40
npx tsx tools/billing-edge-check.ts --live                    # 18/18 (Edge Function v4)
npx tsx tools/security-definer-check.ts                       # 7/7
npx tsc --noEmit -p tsconfig.json                             # 0 errors (was 11)
vite build                                                    # succeeds
```
