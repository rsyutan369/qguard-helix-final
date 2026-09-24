# Revenue Intelligence™ Dashboard

**Spec:** `Qguard_Wiki/Revenue_Intelligence_Dashboard` (2026-07-15) ·
**Audit:** `Qguard_Wiki/Revenue_Intelligence_Audit` (2026-09-22)
**Access:** OWNER-ONLY (no subscription tier unlocks it). Enforced by the API on
every request, by `RevenueIntelligenceLayout`, and by `DashboardLayout`.

An executive command center for revenue, subscriptions, customers, payments and
forecasting, computed live from the platform's own billing records.

## Pages

| Route | Shows |
|---|---|
| `/dashboard/revenue-intelligence` | Net revenue, MRR, ARR, paying customers, completed-month growth, health (measured weight shown), 12-month trend, MRR by plan, live activity, alerts, provider revenue, UTC windows, forecast preview, plan performance |
| `/revenue` | Gross / refunds / net, MoM (completed months) + month-to-date, timeline, by plan / provider / currency (non-USD excluded, never summed), monthly table with failed payments + reconstructed month-end MRR |
| `/subscriptions` | Status board (sums to total), billed vs manual vs complimentary, renewal intent, 30-day churn with its base, completed upgrades/downgrades, MRR by plan, sortable/paginated/filterable ledger |
| `/customers` | Registered vs paying vs lapsed, ARPU, LTV (null when churn is 0 or unmeasured), segments, customer ledger; **any row opens the customer drawer** |
| `/payments` | Collected / failed / refunded / pending, success rate over attempts, outcome donut, provider revenue, ledger with transaction ids and refunds |
| `/forecast` | Actual vs month-to-date vs forecast (separate series), MRR scenarios, projection table, measured/derived/assumption inputs, backtest (MAPE), methodology, Report Center, notification center |

Every page shows a loading skeleton (never zeros), a first-load error with
Retry, a stale-data banner on later failures, coverage/currency/excluded-row
disclosures, and a footer stating currency, timezone, build time and the
cross-page reconciliation result.

## Accounting rules (`src/lib/billing/revenue-model.ts`)

1. **MRR = provider-billed** (PayPal, Google Play, Stripe, Apple) subscriptions in
   an access-granting status (`active`/`trial`/`pending_renewal`), priced by the
   contracted `amount_cents` else the catalog (`PLAN_PRICING`), annual ÷ 12, USD.
   `manual_test`/comp/bootstrap rows are **complimentary**; rows with no provider
   (Admin console) are **manual** — both are counted and disclosed, never MRR.
2. **Cash** comes from `billing_invoices`. Paid and refunded rows are "collected";
   a refund is recognised at `metadata.refundedAt` for `metadata.refundedCents`
   (partial refunds supported). Failed rows hold the attempted amount and are in
   no revenue figure.
3. **USD only** in totals; other currencies are listed under Revenue by Currency.
4. **UTC** for every window and month.
5. **Unmeasured is null.** Health redistributes weight over measured components.
6. **Forecast** uses completed months only (≥3 to project), a retention model for
   MRR (`MRR × (1 − churn) + new MRR`), labelled scenario multipliers, and a
   one-step backtest.
7. **Cancellation keeps paid access until `current_period_end`** (owner
   decision 2026-09-22). The row stays access-granting with
   `cancel_at_period_end = true` (counted in MRR and in "MRR at risk") until
   `public.qguard_expire_cancelled_subscriptions()` — pg_cron every 10 minutes —
   moves it to `cancelled`; churn is dated at the period end.
8. **Reconciliation**: ten invariants (MRR by plan = MRR, provider/plan revenue =
   gross, customer ledger = net, 12-month timeline = trailing window, status board
   = total, …) are computed on every build and shown in every page footer.

Admin > Plans & Billing uses `subscriptionMrrCents` from the same module, so both
screens publish one MRR (asserted live).

## API — `src/api-server/revenue.ts` at `/api/v1/revenue`

| Route | Notes |
|---|---|
| `GET /snapshot[?fresh=1]` | Model with ledgers bounded to 500 rows; `ledgerTotals` states the full counts |
| `GET /stream?token=` | SSE: `revenue-connected`, `revenue-snapshot` (on change), `revenue-heartbeat`, `revenue-error`, `revenue-reauth` (token expired). Max 6 per owner |
| `GET /export?report=summary\|revenue\|subscriptions\|customers\|payments&format=csv\|json` | FULL dataset, UTF-8 BOM, formula-injection neutralised, `no-store`, 30/min |
| `GET /customers/:userId` | One customer's subscription, invoices, billing trail, notifications (UUID-validated, 120/min) |

- Reads page through PostgREST in 1000-row pages up to explicit ceilings and
  report `coverage.truncatedTables` / `unavailableTables`.
- One model build per 5 s, single-flight, shared by snapshot, stream and export.
- Only `/stream` accepts a query token (EventSource cannot send headers); it is
  re-verified every tick.
- Audited to `admin_audit_events`: `revenue.access_denied`, `revenue.export`,
  `revenue.customer.viewed`, `revenue.stream.connected`.

## Where the data comes from

| Writer | Writes |
|---|---|
| `supabase/functions/billing` (production) + `src/api-server/paypal.ts` (self-hosted twin), shared rules in `supabase/functions/billing/logic.ts` | Claim-before-side-effects webhook ledger; subscriptions; paid, **failed** and **refunded** invoices; `billing_audit_events` (`subscription.*`, `payment.*`); customer notifications |
| `src/api-server/play-billing.ts` | Play subscriptions; invoices (catalog list price, disclosed) |
| `src/api-server/billing.ts` | Customer cancel / auto-renew (service client, user-pinned); checkout/revise requests |
| `src/api-server/admin.ts` | Admin subscription changes + the customer's billing trail and notification |

Users cannot write `billing_subscriptions` or platform-managed profile columns
(`supabase/billing-integrity-hardening.sql`).

## Verification

```bash
npx tsx tools/revenue-intelligence-check.ts --live --mutate   # 48 checks (offline + live + Admin->User flow + cancellation via Edge + Express)
npx tsx tools/security-definer-check.ts                       # 7 live Data API probes
npx tsx tools/revenue-intelligence-render-check.ts            # 40 static renders of every page state
npx tsx tools/billing-edge-check.ts                           # Edge Function logic
```
