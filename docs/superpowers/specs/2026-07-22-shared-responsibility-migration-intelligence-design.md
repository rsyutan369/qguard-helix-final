# Shared Responsibility Quantum Migration Intelligence Engine™ — Design & Plan

Date: 2026-07-22
Source guide: `Qguard_Wiki/Quantum_Migration_Intelligence-Engine`
Status: Approved — implementing.

## Mission

Evolve QGuard Helix from a "vulnerable / not vulnerable" scanner into an enterprise
**Quantum Migration Decision Platform**. Every cryptographic finding must answer:
who owns it, can the customer fix it, if not who can, what is the migration
dependency, and what is the recommended action — surfaced consistently across the
scanner, dashboards, Sophia, reporting, certification, migration planner, and the
readiness score.

## Approved decisions

1. **Provider attribution = evidence-derived + confidence.** No outbound network
   probing. Attribution is derived only from existing tenant data (asset metadata,
   `connector_accounts`, scanner evidence hostnames, `target.provider`) matched
   against a fingerprint catalog. Unknown ⇒ low confidence, honest "unattributed"
   flag, defaults to Customer domain. (Consistent with the Constitution's
   evidence-driven / no-fabricated-data rule.) Catalog is shaped so live probing
   can raise confidence later without changing the model.
2. **Placement = flagship top-level page `/dashboard/migration-intelligence`
   PLUS an Executive Command Center strip, gated at Basic+.**

## Architecture

### Single source of truth — pure isomorphic module `src/lib/shared-responsibility/`
No DB, no Express. Importable by scanner, quantum-readiness, the new router,
reporting, and (via a server tool) Sophia.

- `types.ts` — `ResponsibilityDomain` (`customer|provider|ecosystem`) and the
  normalized `OwnershipFinding` (domain, ownerType, responsibleParty,
  remediationDomain, customerActionable `yes|no|partial`, providerDependency,
  ecosystemDependency, migrationDependencyStatus
  `ready|blocked|waiting_provider|waiting_browser|waiting_vendor|waiting_hardware|waiting_standards`,
  actionability, priority, businessImpact, migrationComplexity, estimatedEffort,
  estimatedTimeline, dependencyChain[], edgeOrigin?, confidence{overall, ownership,
  actionability, providerAttribution}, attribution{providerId, method, reason},
  evidence[], references[]). Plus the aggregate `SharedResponsibilityIntelligence`.
- `provider-catalog.ts` — fingerprint catalog: CDNs/edge (Cloudflare, CloudFront,
  ACM, ALB/ELB, Azure Front Door / App Gateway, GCP LB, Fastly, Akamai, Imperva,
  F5), hosting (Netlify, Vercel, GitHub Pages, Firebase, DigitalOcean, Fly.io,
  Render, Railway, CF Pages/Workers), SaaS (Okta, M365, Slack, Zoom, Stripe,
  PayPal, Twilio, SendGrid, Salesforce, Azure SQL, Cloud SQL), ecosystem
  (Chrome/Firefox/Safari, Windows/Android/iOS/Linux, OpenSSL/LibreSSL, Java, .NET,
  PKCS#11, smart cards). Each: id, name, domain, category, fingerprints
  {hostname, cname, header, targetType, connectorProvider}, pqRoadmapStatus,
  customerInfluence, reference.
- `provider-attribution.ts` — `attributeProvider(input, context)` → {providerId,
  domain, confidence, method, reason}. Evidence-only. Honest unattributed state.
- `tls-intelligence.ts` — `classifyEdgeVsOrigin()` — never conflates Edge TLS
  (provider-managed) with Origin TLS (customer-controlled).
- `dependency-graph.ts` — `buildDependencyChain()` + migration-dependency status.
- `classify.ts` — actionability + business-impact + effort/timeline engine;
  reconciles with the existing `RemediationModel.authority` (backward compatible).
- `rollup.ts` — `buildSharedResponsibility(inputs)` → per-domain counts, matrix
  rows, tri-part readiness (overall/customer/provider/ecosystem), blockers,
  actionable-vs-waiting, 7-wave roadmap, widget payloads.
- `index.ts` — barrel.

### Backend
- `src/api-server/migration-intelligence.ts` mounted at
  `/api/v1/migration-intelligence` (own 15s single-flight cache, tenant-scoped,
  Basic+ gate). Endpoints `/`, `/matrix`, `/finding/:id`, `/waves`, `/stream` (SSE).
  Adapts `buildSnapshot` + `buildScannerIntelligence` + raw `connector_accounts`
  into the pure module.
- `buildSnapshot` gains a `sharedResponsibility` block (tri-part readiness + domain
  counts) so QR pages, Executive, Reporting, Certification, Migration inherit
  consistent scores by construction.

### Frontend
- `/dashboard/migration-intelligence` flagship page + components (widgets, pie,
  stacked severity-per-responsibility bar, Shared Responsibility Matrix, Edge-vs-
  Origin panel, dependency graph, tri-part gauges). Premium enterprise design.
- `src/hooks/use-migration-intelligence.ts` + nav entry (Basic+).
- Executive Command Center Shared Responsibility strip.

### Cross-platform integrations (all read the identical model)
- Scanner — tag findings with detected provider + adjust ownership.
- Sophia — `explain_finding_ownership` tool + knowledge ("Why can't I fix this?").
- Reporting — "Shared Responsibility Assessment" section (schema + evidence +
  template + exporters).
- Certification — score only unresolved customer-controlled findings; never
  penalize for provider/ecosystem lag.
- Migration Planner — 7-wave dependency-ordered roadmap.
- Readiness score — tri-part (Overall/Customer/Provider/Ecosystem).

### Verification
- `tools/migration-intelligence-check.ts` (platform `*-check.ts` convention).
- `tsc` + build clean.

## Guarantees
Evidence-driven only (unknowns labeled, never guessed); backward compatible
(existing API fields preserved, ownership metadata added); one normalized model
consumed everywhere.
