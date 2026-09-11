/**
 * Quantum Simulation Range — engine barrel.
 *
 * Three provenance tiers, and every number the UI prints belongs to exactly one:
 *
 *   PUBLISHED  nist-standards.ts, classical-crypto.ts
 *              A standards document, an IANA registry or a named paper says this.
 *
 *   MODEL      resource-estimator.ts, grover.ts, mosca.ts
 *              Output of a named model whose published anchor points it reproduces.
 *
 *   MEASURED   shor.ts, pqc-live.ts, tls-evidence.ts
 *              Computed in the visitor's browser during this session.
 *
 * Consumers import from here so the internals can move.
 */

export {
  CITATIONS,
  ML_KEM_SETS,
  ML_DSA_SETS,
  SLH_DSA_SETS,
  PQC_SETS,
  PENDING_STANDARDS,
  NIST_SECURITY_CATEGORY,
  TRANSITION_MILESTONES,
  TLS_NAMED_GROUPS,
  TLS13_CIPHER_SUITES,
  milestoneClock,
  nextMilestone,
  namedGroup,
  pqcSet,
  pqcSetsForCategory,
  formatBytes,
  type Provenance,
  type Citation,
  type CitationKey,
  type PqcParameterSet,
  type PqcFamily,
  type PqcRole,
  type PendingStandard,
  type TransitionMilestone,
  type MilestoneClock,
  type MilestoneSeverity,
  type NamedGroup,
  type GroupKind,
  type StandardStatus,
} from './nist-standards';

export {
  CLASSICAL_PRIMITIVES,
  GROVER_REALITY,
  primitive,
  primitivesByVerdict,
  gnfsCostBits,
  shorCostBits,
  ecdlpClassicalCostBits,
  ecdlpQuantumCostBits,
  complexityCurve,
  type ClassicalPrimitive,
  type QuantumAttack,
  type QuantumVerdict,
  type PrimitiveRole,
  type ComplexityPoint,
} from './classical-crypto';

export {
  ANCHOR_HARDWARE,
  REPORTED_DEVICES,
  estimateRsa,
  estimateEcc,
  rsaLogicalCost,
  eccLogicalCost,
  logicalErrorRate,
  chooseCodeDistance,
  verifyAnchors,
  formatDuration,
  formatCount,
  type EstimatorModel,
  type HardwareAssumptions,
  type LogicalCost,
  type ResourceEstimate,
  type AnchorCheck,
} from './resource-estimator';

export {
  StateVector,
  SHOR_TARGETS,
  SHOR_DEFAULT_MAX_QUBITS,
  runShor,
  runShorUntilSuccess,
  simulationWall,
  continuedFractionConvergents,
  classicalOrder,
  modPow,
  gcd,
  isPrime,
  type ShorOptions,
  type ShorResult,
  type ShorStage,
  type ShorPeak,
  type Convergent,
  type SimulationWall,
} from './shor';

export {
  NIST_MAXDEPTH,
  groverEvolution,
  groverFeasibility,
  type GroverEvolution,
  type GroverFeasibility,
} from './grover';

export {
  SHELF_LIFE_PRESETS,
  crqcEstimates,
  evaluateMosca,
  type MoscaInputs,
  type MoscaResult,
  type MoscaVerdict,
  type ShelfLifePreset,
  type CrqcEstimate,
} from './mosca';

export {
  buildClientHello,
  harvestFootprint,
  toHexRows,
  toHex,
  tls13KeySchedule,
  transcriptHash,
  type HandshakeEvidence,
  type ClientHelloOptions,
  type ByteField,
  type HexRow,
  type HarvestRecord,
  type KeyScheduleResult,
  type ScheduleStep,
} from './tls-evidence';

export {
  LIVE_KEM_IDS,
  LIVE_SIGNER_IDS,
  runKemExchange,
  runSignature,
  benchmarkPqc,
  verifyAgainstStandard,
  hybridKeyShare,
  type KemExchange,
  type SignatureRun,
  type BenchmarkRow,
  type SizeCheck,
  type ConformanceResult,
} from './pqc-live';

export {
  ATTACK_CHAIN,
  SCENARIO_CRYPTO,
  stageByOrdinal,
  scenarioCrypto,
  scenarioPrimitive,
  type AttackStage,
  type EvidenceSurface,
  type ScenarioCryptoProfile,
} from './attack-chain';
