# Task — Retire 3 redundant dashboard pages

Retire and fully unwire:

1. `/dashboard/quantum-readiness/command-center`
2. `/dashboard/quantum-readiness/executive`
3. `/dashboard/vulnerabilities`

Nothing else may break. Every inbound link must land on the surviving surface
that owns the same ground — no dead links, no 404s, no orphaned API.

## Successor map (why each target)

| Retired | Successor | Rationale |
|---|---|---|
| `quantum-readiness/command-center` | `/dashboard/quantum-readiness` | Same `useQuantumReadiness` snapshot, same scores/inventory/telemetry. The Overview already renders the KPI ring set the Command Center duplicated. |
| `quantum-readiness/executive` | `/dashboard/quantum-readiness/ai-executive-advisor` | The surviving board-ready, evidence-grounded executive surface. |
| `vulnerabilities` | `/dashboard/quantum-readiness/risk-analysis` | Owns the Remediation Priority Queue + Critical/High findings evidence table — the finding-triage ground the Vulnerability Center held. |

Old paths keep working via `<Navigate replace>` — the same convention already
used for the retired `quantum-readiness/digital-twin` route in `App.tsx`.

## Execution

### Files deleted
- [x] `src/app/dashboard/quantum-readiness/command-center/` (page.tsx)
- [x] `src/app/dashboard/quantum-readiness/executive/` (page.tsx)
- [x] `src/app/dashboard/vulnerabilities/` (page.tsx, VulnerabilityCenter.tsx)
- [x] `src/hooks/use-vulnerabilities.ts` (sole consumer deleted)
- [x] `src/api-server/vulnerability-center.ts` (sole mount removed)
- [x] `src/lib/vulnerabilities/vulnerability-intelligence.ts` (sole consumers deleted)
- [x] `tools/vulnerability-center-check.ts` (checks a retired engine)

### Routing
- [x] `src/App.tsx` — drop 3 imports, replace 3 routes with `Navigate` redirects

### Navigation / module registries
- [x] `dashboard_layout/DashboardLayout.tsx` — 3 sidebar entries
- [x] `quantum-readiness/page.tsx` — `MODULES` x2 + Command Center header button
- [x] `quantum-readiness/_shared.tsx` — `QR_PAGES` subnav x2
- [x] `quantum-readiness-assessment/_shared.tsx` — marketing footer x2
- [x] `api-server/copilot-knowledge.ts` — Sophia `MODULE_REGISTRY` paths repointed
      (ids kept: `quantum_readiness` / `executive` are referenced by intent routing)

### Inbound links repointed
- [x] `cbom_explorer/CbomExplorer.tsx` x2
- [x] `drift_detection/DriftDetection.tsx` x3 (incl. prose)
- [x] `dashboard/page.tsx`, `TelemetryFeatures.tsx`, `trust-state-discovery`
- [x] `quantum-risk-scoring/QuantumRiskScoring.tsx`
- [x] `security_events_panel/SecurityEventsPanel.tsx`, `_components/executive/{ThreatIntel,ThreatTimeline}.tsx`
- [x] `quantum-readiness/risk-analysis/page.tsx`
- [x] `docs/page.tsx` x6
- [x] `lib/governance/{catalog,controls,evidence}.ts`, `lib/governance/intelligence.ts` (surface names)
- [x] `lib/trust-fabric/intelligence.ts`
- [x] `lib/telemetry-pipeline/intelligence.ts` (feed names)
- [x] `api-server/dashboard-executive.ts` x2, `api-server/dashboard.ts` x2

### Backend
- [x] `api-server/index.ts` — import + `app.use` mount
- [x] `api-server/subscription-guard.ts` — Pro prefix + comment
- [x] `lib/subscription-access.ts` — Pro prefix
- [x] `api-server/dashboard.ts` — remove the legacy `GET /vulnerabilities` (289
      lines) and `GET /vulnerabilities/stream` handlers. Both were SHADOWED by
      the mount above them; deleting the mount alone would have silently
      resurrected a superseded endpoint.
- [x] remove the 13 helpers orphaned by that deletion (`canonicalVulnerabilityRows`,
      `vulnerability{Status,Type,Title,RootCause,ScanTarget,EvidenceLabel,ExposureLevel,RemediationBase,RemediationHref}`,
      `assetTypeLabel`, `fingerprintPart`, `startOfDayMs`). The 3 helpers already
      dead at HEAD (`getMigrationProgress`, `isMissingRpc`, `safeLatestScanAt`)
      were left alone — not caused by this change.

### Docs
- [x] `Qguard_Wiki/Quantum_Readiness` — retirement notes on the two retired sections

## Verification — evidence

- [x] `npx tsc --noEmit` — 7 errors remain, all in files untouched since HEAD
      (`admin/page.tsx`, `revenue-intelligence/customers`, `settings`, `vault`,
      `cyberscore-section-hero`, `useRealtimeStream`, `tools/remediation-check`).
      Zero errors in any file this change touched.
- [x] `npm run build` — succeeds (built in 21.93s).
- [x] grep: zero live references to the three retired paths anywhere in the repo
      outside the three `Navigate` redirects and this file.
- [x] Browser (fresh dev server, demo Elite session):
      - `/dashboard/vulnerabilities` → `/dashboard/quantum-readiness/risk-analysis` ("Quantum Risk Analysis")
      - `/dashboard/quantum-readiness/command-center` → `/dashboard/quantum-readiness` ("Quantum Readiness Assessment Engine™")
      - `/dashboard/quantum-readiness/executive` → `/dashboard/quantum-readiness/ai-executive-advisor`
      - QR subnav + Overview module grid: 8 modules, no retired entries
      - `/dashboard`, `/dashboard/quantum-risk-scoring`, `/dashboard/cbom`,
        `/dashboard/quantum-readiness/risk-analysis` all render; zero retired
        hrefs in the DOM; CBOM's button reads "Open Quantum Readiness".
      - Console: only a favicon 404 and Supabase realtime 402 (project over
        quota) — no module-resolution or React errors.
- [x] API (demo token): `dashboard/health`, `dashboard/activity`, `dashboard/drift`,
      `quantum-readiness`, `dashboard/executive` all 200 with valid payloads —
      `dashboard.ts` is healthy after the 289-line removal.
      `/api/v1/dashboard/vulnerabilities` no longer resolves to a handler
      (it answers exactly like any unknown `/api/v1/dashboard/*` path).
