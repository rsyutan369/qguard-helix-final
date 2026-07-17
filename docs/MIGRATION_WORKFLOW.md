# Post-Quantum Migration Workflow™ (state-driven lifecycle layer)

Implements `Qguard_Wiki/Enhance_Quantum_Remediation_Migration_Workflow`: the
platform's ten workflow modules operate as ONE state-driven lifecycle instead
of independent dashboards —

```
Discovery → CBOM → Assessment → Risk Prioritization → AI Remediation →
Migration Planning → Approval → Live Migration → Validation →
Continuous Monitoring → Quantum Trust Certification
```

Every stage status is **derived from the same live evidence** the individual
modules render, so status indicators can never disagree between pages.

---

## Components

| Piece | Path |
| --- | --- |
| Workflow engine | `src/api-server/migration-workflow.ts` — `GET /api/v1/migration-workflow` (Basic+; 30s per-user cache) |
| Contract types | `src/types/migration-workflow.ts` |
| Hook | `src/hooks/use-migration-workflow.ts` (fetch + 60s refresh; hides on error) |
| Shared UI | `src/components/workflow/WorkflowRail.tsx` — 11-stage stepper + next-best-action chip; `tone="dark"` or `"adaptive"` |
| Approval workflow | `migration-planner.ts`: `GET/POST /api/v1/migration-planner/plans` + `POST /plans/:id/approval`; `ApprovalWorkflowPanel` in `MigrationPlanner.tsx` |
| Live checks | `npx tsx tools/workflow-live-check.ts` |

## Where the WorkflowRail is embedded (10 modules)

Scanner (`discovery`) · Assets (`discovery`, adaptive) · CBOM Explorer
(`cbom`, adaptive) · Risk Analysis (`risk`) · Harvest Now (`risk`, adaptive) ·
Quantum Remediation (`remediation`) · Crypto Agility (`remediation`) ·
Migration Planner (`planning`) · Live Migration Ops (`execution`) ·
Quantum Certification (`certification`).

Each rail stage links to the module that owns it; the "Next:" chip deep-links
to the single best next action (computed from the Q-REMEDY plan, plan
approvals, running jobs and certificate state).

## Stage derivation (evidence sources)

- **Discovery / CBOM / Assessment / Risk** — asset + component counts, QR
  scores and graded findings from the remediation evidence assembly
  (`assembleEvidence`, exported from `quantum-remediation.ts`).
- **Remediation** — Q-REMEDY plan (open/total actions, queue mix,
  certification readiness %).
- **Planning / Approval** — real `migration_plans` rows. Submitting from the
  planner creates `status='pending_approval'`; approve/reject stamps
  `metadata.approval = {decision, decidedBy, decidedAt, reason}` and sets
  `status` to `approved`/`rejected`. **No new tables.**
- **Execution / Validation** — `migration_jobs` + `migration_validation_logs`.
- **Monitoring** — runtime telemetry presence (never "completes" by design).
- **Certification** — `quantum_trust_certificates` (active → complete,
  suspended → blocked) else live eligibility from the remediation plan.

Per-asset lifecycle states (top 200 by risk) map each asset to
remediation/execution/validation/monitoring with migration status, validation
status and certification impact — the Assets page merges these into its
**Lifecycle** column by asset name.

## Module enhancements shipped with this layer

- **Migration Planner** — real approval workflow (submit → approve/reject with
  reason + approver stamp). Root-cause fix: `migration_plans` has **no `name`
  column**; the old `select('id, name, …')` errored silently in `safeRows`, so
  the 9-stage "Approve" stage never saw plans. Display names now live in
  `metadata.name` and the select is fixed.
- **Risk Analysis** — Risk Heat Map (top exposure-graph assets × Overall Risk /
  Crypto Posture / Internet Exposure / Environment; every cell hover shows its
  evidence basis).
- **Assets** — Lifecycle column (stage chip + open actions / validation status
  + certification impact) fed by the workflow engine.
- **Quantum Remediation** — Automation Opportunities banner (counts automatable
  playbook actions → Live Migration Ops CTA).
- **Deep-link fixes** — remediation playbook routes corrected to real pages
  (`/dashboard/runtime-crypto-intel`, `/dashboard/vendor-pqc-readiness`,
  `/dashboard/qkms/overview`).

## Verification (2026-07-16)

- `tsc --noEmit` clean, `vite build` clean, `tools/remediation-check.ts` 46/46.
- `tools/workflow-live-check.ts` (real tenant): 401 unauth; 11 canonical
  stages; bounded progress; overall 50%→68% as approval/execution completed;
  next-action = the live #1 remediation; cached second call <1s; approval
  round-trip (submit 201 → approve 200 with approver stamp → listed → invalid
  decision 400).
- Authenticated headless-Chrome render of the Migration Planner: rail (11
  stages + Next chip), Approval Workflow panel with the approved plan, and the
  9-stage Approve card now Complete.

Restart the dev server after pulling — Vite mounts new Express routes at start.
