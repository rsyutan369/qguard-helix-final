/**
 * Migration Orchestrator™ — massive-scale scheduling + real-time metrics.
 *
 * The orchestrator is the scheduling brain that coordinates thousands of
 * migration jobs across many stateless workers (the agents/patchers) on a
 * durable Postgres-backed queue. Every metric is derived from REAL
 * migration_jobs / validation / agent data — nothing is fabricated; values with
 * no measured source are reported as null/"—".
 */

export type OrchestratorJobPhase =
  | 'blocked'      // dependencies not yet satisfied
  | 'queued'       // ready to be leased by a worker
  | 'leased'       // claimed by a worker (distributed lock held)
  | 'running'      // executing on a worker
  | 'validating'   // post-change validation in progress
  | 'completed'    // succeeded
  | 'retrying'     // failed, in exponential backoff before re-queue
  | 'failed'       // failed, awaiting decision
  | 'rolled_back'  // restored from snapshot
  | 'dead_letter'  // exhausted retries — quarantined, isolated from other jobs
  | 'paused';

export interface SchedulerConfig {
  maxConcurrentPerTenant: number;   // back-pressure / rate limit
  leaseSeconds: number;             // distributed-lock lease TTL
  baseBackoffSeconds: number;       // exponential-backoff base
  maxRetries: number;               // before dead-letter
  workerCapacity: number;           // logical worker slots (agents × slots)
}

export interface OrchestratorMetrics {
  // Job counts (real, from migration_jobs)
  total: number;
  blocked: number;
  queued: number;
  leased: number;
  running: number;
  validating: number;
  completed: number;
  retrying: number;
  failed: number;
  rolledBack: number;
  deadLetter: number;
  paused: number;
  // Progress
  assetsUpgraded: number;
  assetsRemaining: number;
  overallProgressPct: number;
  validationProgressPct: number;
  // Performance (measured)
  throughputPerMin: number | null;      // assets completed / minute (windowed)
  avgDurationSeconds: number | null;    // mean completed duration
  queueDepth: number;
  inFlight: number;
  workerUtilizationPct: number;         // inFlight / capacity
  activeWorkers: number;                // distinct agents holding leases
  // Reliability
  reclaimedLeases: number;              // node-failure recovery this cycle
  retriesScheduled: number;
  deadLetteredThisCycle: number;
  // Health (real, from scanner_agents / connector_accounts)
  agentsOnline: number;
  agentsDegraded: number;
  agentsOffline: number;
  connectorsHealthy: number;
  connectorsTotal: number;
  // Infra telemetry — only when an agent reports it; else null (honest)
  agentCpuPct: number | null;
  agentMemoryPct: number | null;
  networkLatencyMs: number | null;
}

export interface OrchestratorThroughputPoint {
  label: string;
  completed: number;
}

export interface OrchestratorSnapshot {
  generatedAt: string;
  hasData: boolean;
  config: SchedulerConfig;
  metrics: OrchestratorMetrics;
  throughput: OrchestratorThroughputPoint[];
  priorityQueue: Array<{ id: string; asset: string; priority: number; phase: OrchestratorJobPhase; retryCount: number; leaseWorker: string | null; blockedBy: number }>;
  agents: Array<{ id: string; name: string; status: string; lastSeenAt: string | null; leasedJobs: number }>;
  scaleTier: string;                    // "1–10", "10–100", … "100,000+"
}
