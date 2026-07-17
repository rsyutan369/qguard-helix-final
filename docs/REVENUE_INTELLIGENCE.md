# Revenue Intelligence™ Dashboard

**Spec:** `Qguard_Wiki/Revenue_Intelligence_Dashboard` · **Date:** 2026-07-15
**Access:** OWNER-ONLY (same rule as Owner Administrator — no subscription tier
unlocks it; enforced in the shell AND on every API request).

An enterprise executive command center consolidating revenue, subscriptions,
customers, payments, forecasting, alerts, and reports — computed live from the
platform's REAL billing evidence so external provider dashboards (PayPal,
Google Play Console) are no longer needed for daily monitoring.

## Where

- **Sidebar:** SYSTEM → Owner Administrator, then the **Revenue Intelligence**
  section directly below it (owner accounts only).
- **Routes:** `/dashboard/revenue-intelligence` (+ `/revenue`, `/subscriptions`,
  `/customers`, `/payments`, `/forecast`).

## Pages

| Page | What it shows |
|---|---|
| Executive Overview | KPI hero (Total Revenue, MRR, ARR, Active Subscribers, Net, Lifetime), 12-month revenue trend, revenue-by-plan donut + churn/LTV/ARPU, live activity feed, alerts, provider ranking, revenue summary (today→all-time), subscription health score, forecast preview, plan performance strip |
| Revenue Analytics | Gross/net/refunded KPIs, MoM growth, timeline chart + monthly table, revenue by plan / provider / currency, period windows |
| Subscription Analytics | Status board (active/trial/renewing/failed/…), renewal rate, churn/retention, upgrades/downgrades (30d), MRR & subscribers by plan, searchable/filterable subscriber roster |
| Customer Analytics | Users vs customers vs active, new (30d) + growth, ARPU, LTV, segments (trial/enterprise/individual/cancelled), retention, customer ledger ranked by lifetime revenue |
| Payment Analytics | Success/failed/refund/pending counts, success-rate ring, average payment, outcome donut, provider revenue, full searchable payment ledger |
| Forecast & Reports | 6-month revenue/MRR/ARR/subscriber projections with confidence grade + disclosed methodology, projection table, Report Center (CSV/Excel + JSON exports ×5), notification center, forecast-input transparency |

## Data sources (all real — no fabricated metrics)

`billing_subscriptions`, `billing_invoices`, `billing_notifications`,
`billing_audit_events`, `profiles` — the same tables the verified PayPal
webhook and Google Play verify/RTDN flows write. MRR/ARR are normalized from
the plan catalog (`PLAN_PRICING`); cash figures come from invoices.

Metrics with **no evidence source yet** are shown as explicit *data gaps*
(geography, CAC/burn/EBITDA, DAU/sessions, Stripe/Apple) with integration
guidance — never simulated numbers. The forecast is a least-squares linear
trend of actual invoiced net revenue, labeled with its confidence.

## Architecture

- **Backend:** `src/api-server/revenue.ts` mounted at `/api/v1/revenue`
  (`requireOwner`: Supabase JWT + owner-email allowlist; service-role reads).
  - `GET /snapshot` — full aggregation (single typed contract)
  - `GET /stream` — SSE, full snapshot every 10 s + heartbeat (query-token auth
    because EventSource cannot send headers, mirroring `/api/v1/admin/stream`)
  - `GET /export?report=summary|revenue|subscriptions|customers|payments&format=csv|json`
- **Frontend:** `src/app/dashboard/revenue-intelligence/` — `_shared.tsx`
  (snapshot types, `useRevenueIntelligence` hook, `RevenueShell` owner guard +
  subnav, ECharts option builders, shared panels/tables) + 6 pages. Reuses the
  proven `quantum-readiness/_shared` primitives (Panel/MetricCard/Donut/BarList).
- **Realtime:** the owner SSE stream is the live channel (client-side Supabase
  realtime cannot see other users' billing rows under RLS). No manual refresh
  needed; the UI shows Live/Reconnecting state.
- **API-ready:** every JSON export and the snapshot endpoint share stable
  schemas for external integrations.

## Verification (2026-07-15)

- `tsc --noEmit`: 0 errors · `vite build`: clean
- Live smoke test (standalone API): `/snapshot`, `/stream`-style token, and
  `/export` all answer **401 UNAUTHORIZED** without an owner token — gating
  confirmed end-to-end. Owner data path exercises on first authenticated open.
