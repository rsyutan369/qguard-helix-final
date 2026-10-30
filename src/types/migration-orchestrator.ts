/**
 * PQC orchestration contract — the payload of /api/v1/migration-orchestrator.
 *
 * The vocabulary is defined ONCE, beside the pure derivation that produces it
 * (`src/lib/migration/orchestration-model.ts`), and re-exported here so the
 * pages, the hook and the router share one type rather than parallel copies.
 *
 * The previous contract published a scheduler that nothing enforced
 * (`maxConcurrentPerTenant`, `workerCapacity: 64`, lease TTLs), a "scale tier",
 * and per-cycle reclaim/retry/dead-letter counts describing writes the GET
 * handler itself performed. All of that is gone: every field below is a
 * projection of recorded job, plan, validation, event and agent rows.
 */
export type {
  OrchestrationEvent,
  OrchestrationJob,
  OrchestrationMetrics,
  OrchestrationPhase,
  OrchestrationPlan,
  OrchestrationSnapshot,
  PathCheck,
  SourceState,
  VerificationState,
} from '@/lib/migration/orchestration-model'
export { ORCHESTRATION_PHASES, PHASE_LABEL, VERIFICATION_LABEL } from '@/lib/migration/orchestration-model'
