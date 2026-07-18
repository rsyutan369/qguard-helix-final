# Live Migration Operations — Premium Redesign

`/dashboard/live-migration` (`src/app/dashboard/live_migration_ops/LiveMigrationOps.tsx`)
redesigned to an enterprise-grade, premium experience aligned with the Agent
Collector Console, Quantum Readiness and Quantum Certification surfaces — while
keeping (and proving) all real-time wiring.

## What changed

- **Visual re-theme**: the gold `#d4af37` theme (121 refs) swept to premium
  cyan glassmorphism (`#22d3ee`); `GLASS`/`INNER` panel tokens modernized to
  `rounded-2xl border-white/10 bg-white/[0.03] backdrop-blur-xl`; header
  softened from mono-uppercase-gold to the clean cyan style used across the
  redesigned modules. The whole page now reads as one system with the agent
  console and certification pages.
- **New real-time Certification Readiness band** (below the WorkflowRail):
  directly answers "are my assets remediated and am I eligible for the Quantum
  Trust Certification?" It shows the live certification-readiness ring
  (44.8% on the reference tenant), eligible/not-eligible status, the
  certification-criteria detail, and three lifecycle cells — **Quantum-Secure
  Assets** (validated/monitored), **In Remediation** (being upgraded now),
  **Tracked Assets** — plus "View Certification" and "Remediation Roadmap"
  CTAs. It is powered by `useMigrationWorkflow` (the SAME engine that drives the
  workflow rail, Quantum Readiness and the Certification page), so the number
  can never disagree across modules.

## Real-time data flow (unchanged, verified)

The page's data layer was already strong and is preserved intact:

- REST snapshot `GET /api/v1/migration/live` (+ `?planId`).
- **SSE** `GET /api/v1/migration/live/stream` → `migration-update` frames.
- **Supabase realtime** on 9 tables (migration_jobs/plans/events/execution/
  telemetry/validation_logs/execution_queues/pqc_scan_results/crypto_exposures)
  with a debounced refetch.
- Monotonic snapshot guard (never lets an older `generatedAt` overwrite newer).
- Job actions (pause/resume/retry/rollback), bulk actions, CSV/JSON export.
- The added cert band consumes `useMigrationWorkflow` (60s refresh; server
  30s per-tenant cache), keeping it in-sync with QR/Certification.

The migration jobs execute real PQC upgrades on vulnerable assets (TLS→hybrid
ML-KEM, certs→ML-DSA, key rotation, etc. — see the agent/patcher pipeline),
and the telemetry (TLS handshakes, certificate replacements, key rotations,
PQC validations) streams live so users watch assets become quantum-secure.

## Enterprise enhancement band (additive — `Live_Migration_Enhancements`)

Per `Qguard_Wiki/Live_Migration_Enhancements`, an additive business-outcome
band was added above the existing operations surface (nothing removed — the
header, metric cards, telemetry, jobs list, log terminal and action bar all
remain). New component: `_enhancements.tsx` (self-contained prop contracts);
all props derived in the page from the REAL live snapshot + workflow (data
honest — unmeasurable values render "—", never fabricated).

Sections added:
- **Quantum Migration Progress hero** — "Quantum Ready" ring + % migrated bar +
  migrated/remaining/ETA + 6 outcome cells (Quantum Secure / In Progress /
  Remaining / Needs Attention / Migration Speed / Est. Completion).
- **Executive Outcomes** — 10 KPIs (Assets Protected, Vulnerabilities
  Eliminated, Success Rate, Quantum Readiness, Critical Systems, Certificates
  Upgraded, Key Rotations, Audit Readiness, Compliance, Active Migrations).
- **Cryptographic Upgrade — Before → After** — real job `fromAlgo→toAlgo`
  transitions when present, else the canonical PQC upgrade paths (RSA-2048→
  ML-KEM-768, TLS 1.2→TLS 1.3 Hybrid, ECC→ML-DSA-65, SHA-1→SHA3-512,
  AES-128→AES-256-GCM) with FIPS labels and animated arrows.
- **AI Migration Advisor** — deterministic, evidence-grounded: remaining/
  findings headline, recommendation (agent-deploy vs sequence-and-schedule),
  evidence bullets, suggested maintenance window (next Saturday 02:00),
  residual-risk band (LOW/MODERATE/ELEVATED), est. effort, roadmap link.
- **The Migration Story** strip — Assets Found → Quantum Risks → Migrating →
  Upgraded → Validated → Certified.
- **Certification Progress** checklist — TLS/Certificates/Keys/Validation/
  Compatibility/Overall status from real migration telemetry + readiness bar.
- **Final Success celebration** — appears at 100% + eligible: "Enterprise
  Successfully Upgraded" + Download Certificate.

Better terminology (Active Migrations, In Progress, Needs Attention,
Successfully Protected) is used in the new sections; existing sections
untouched.

## Verification (2026-07-17)

- `tsc --noEmit` clean; `vite build` clean.
- Authenticated headless render (Elite/owner) confirmed the premium theme, the
  Certification Readiness band (44.8% / Not Yet Eligible / lifecycle cells /
  CTAs), the 4 metric cards, Real-Time Telemetry, Activity Feed, Migration Jobs,
  Migration Log terminal, and the sticky action bar — with footer showing
  **"SSE connected" + "Realtime SUBSCRIBED"**.
- Backend real-time check: `migration/live` 200 (7 telemetry keys),
  `migration-workflow` 200 (certReadiness 44.8%, 4 lifecycle stages), and the
  SSE stream emitted a live frame. No API changes.
- Access: Live Migration is a Pro+ module (Basic sees the upgrade gate) —
  unchanged.
