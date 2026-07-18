// Sophia — QGuard Helix AI Security Copilot™ shared contract.
//
// Imported by BOTH the Express gateway/engine (src/api-server/copilot*.ts)
// and the frontend (hook + chat UI), so the streamed answer schema stays in
// lock-step across the stack. Keep this file dependency-free.

/** RBAC roles the copilot understands (per AI_CoPilot_Multi-Tenant_Isolation). */
export type CopilotRole =
  | 'owner'
  | 'infrastructure_admin'
  | 'security_analyst'
  | 'executive'
  | 'auditor'

/** What a role may do through copilot tools. */
export interface RoleCapabilities {
  read: boolean
  /** May prepare/approve operational actions (remediation, snapshots, rollback). */
  operate: boolean
  /** May read audit / compliance evidence surfaces. */
  audit: boolean
  /** May read executive / business-risk surfaces. */
  executive: boolean
}

/** Intents the detection layer classifies questions into. */
export type CopilotIntent =
  | 'asset_status'
  | 'migration_status'
  | 'remediation'
  | 'risk_analysis'
  | 'certification'
  | 'reports'
  | 'compliance'
  | 'pki'
  | 'tls'
  | 'ssh'
  | 'cbom'
  | 'scanner'
  | 'exposure_graph'
  | 'telemetry'
  | 'threat_intelligence'
  | 'executive_dashboard'
  | 'harvest_now'
  | 'quantum_readiness'
  | 'snapshots_rollback'
  | 'platform_help'

/** Specialist agents behind the coordinator. */
export type CopilotAgentId =
  | 'asset_intelligence'
  | 'migration_advisor'
  | 'pki_expert'
  | 'risk_analyst'
  | 'compliance_advisor'
  | 'executive_advisor'
  | 'telemetry_agent'
  | 'threat_intelligence'
  | 'coordinator'

export type CopilotRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'

/** A single piece of supporting evidence — always from live tenant data. */
export interface CopilotEvidence {
  /** Owning platform module (e.g. "Scanner", "Exposure Graph"). */
  module: string
  /** Short label ("Vulnerable components"). */
  label: string
  /** The observed value ("15", "ML-KEM adoption 42%"). */
  value: string
  /** Optional expanded detail line. */
  detail?: string
  /** Dashboard deep link backing the evidence. */
  deepLink?: string
  /** When the underlying data was generated/observed (ISO). */
  observedAt?: string
}

export interface CopilotRecommendation {
  title: string
  detail: string
  priority: 'immediate' | 'high' | 'medium' | 'low'
  /** Standards backing the recommendation (e.g. "FIPS 203", "CNSA 2.0"). */
  standards: string[]
  deepLink?: string
}

export interface CopilotNextAction {
  label: string
  path: string
  reason: string
}

export interface CopilotRelatedPage {
  label: string
  path: string
}

export type CopilotToolStatus = 'ok' | 'empty' | 'error' | 'denied'

/** Summary of one tool execution — shown in the reasoning timeline. */
export interface CopilotToolRun {
  tool: string
  module: string
  status: CopilotToolStatus
  ms: number
  /** Row/record count the tool observed (when meaningful). */
  rows?: number
  note?: string
}

export interface CopilotConfidence {
  /** 0–100. Derived from evidence coverage + tool success + data freshness. */
  score: number
  basis: string
}

export interface CopilotRisk {
  level: CopilotRiskLevel
  /** 0–100 when a numeric score backs the level. */
  score?: number
  drivers: string[]
}

/**
 * How Sophia answered:
 *  - `investigate` — full cross-module deep investigation (consultative question)
 *  - `direct`      — focused lookup answered from one/few modules
 */
export type CopilotAnswerMode = 'investigate' | 'direct'

/** What Sophia inferred the user actually wants (deep context awareness). */
export type CopilotObjectiveKind =
  | 'guidance'
  | 'prioritization'
  | 'executive'
  | 'gap_analysis'
  | 'explain'
  | 'status'
  | 'help'

/** One ordered step of a dependency-safe migration strategy. */
export interface MigrationStep {
  order: number
  title: string
  /** WHY this step is here / at this position. */
  rationale: string
  /** What breaks if this is done out of order (optional). */
  breaksIf?: string
  deepLink?: string
}

export interface CopilotProactiveFinding {
  severity: CopilotRiskLevel
  text: string
  module?: string
  deepLink?: string
}

/** Risk trajectory: what the posture is now vs. after the recommended work. */
export interface CopilotRiskOutlook {
  before: CopilotRiskLevel
  after: CopilotRiskLevel
  detail: string
}

/** Ordered, dependency-aware migration strategy. */
export interface CopilotMigrationStrategy {
  steps: MigrationStep[]
  estimatedEffortPct?: number
  estimatedTimeline?: string
}

/** The structured, evidence-based answer every copilot response follows. */
export interface CopilotAnswer {
  id: string
  intents: CopilotIntent[]
  agents: CopilotAgentId[]
  summary: string
  reasoning: string[]
  evidence: CopilotEvidence[]
  recommendations: CopilotRecommendation[]
  risk: CopilotRisk
  nextActions: CopilotNextAction[]
  relatedPages: CopilotRelatedPage[]
  standards: string[]
  confidence: CopilotConfidence
  toolRuns: CopilotToolRun[]
  followUps: string[]
  /** Set when the question was blocked (RBAC / sanitizer) — summary explains. */
  blocked?: 'rbac' | 'prompt_injection' | 'rate_limit'
  generatedAt: string

  /* ---- Deep-reasoning fields (present on investigate-mode answers) ---- */
  mode?: CopilotAnswerMode
  objectiveKind?: CopilotObjectiveKind
  /** Plain-language statement of what Sophia understood the user wants. */
  objective?: string
  /** The correlated, evidence-backed key findings. */
  keyFindings?: string[]
  /** Root cause of the situation (for gap/explain questions). */
  rootCause?: string
  /** Business impact of the situation / recommended work. */
  businessImpact?: string
  /** Deeper technical analysis bullets. */
  technicalAnalysis?: string[]
  /** Dependency-safe migration order with per-step rationale + breakage. */
  migrationStrategy?: CopilotMigrationStrategy
  /** Dependency chain highlights (trust chains, roots, third parties). */
  dependencies?: string[]
  /** What could break during the recommended change. */
  potentialBreakages?: string[]
  /** Snapshot / rollback guidance before high-risk operations. */
  rollbackStrategy?: string
  /** Risk trajectory now → after remediation. */
  riskOutlook?: CopilotRiskOutlook
  /** Compliance frameworks the recommended work aligns to, with why. */
  complianceAlignment?: string[]
  /** Things Sophia noticed while investigating (unprompted but important). */
  proactiveFindings?: CopilotProactiveFinding[]
}

/** Reasoning stages streamed while the coordinator works. */
export type CopilotStage =
  | 'thinking'
  | 'intent'
  | 'expanding'
  | 'planning'
  | 'investigating'
  | 'reading'
  | 'correlating'
  | 'analyzing'
  | 'reasoning'
  | 'generating'
  | 'done'

export type CopilotStreamEvent =
  | { type: 'stage'; stage: CopilotStage; label: string }
  | { type: 'tool'; run: CopilotToolRun }
  | { type: 'answer'; answer: CopilotAnswer }
  | { type: 'error'; message: string }
  | { type: 'done' }

export interface CopilotMessage {
  id: string
  conversationId: string
  role: 'user' | 'assistant'
  content: string
  /** Present on assistant messages — the full structured answer. */
  answer?: CopilotAnswer
  createdAt: string
}

export interface CopilotConversation {
  id: string
  title: string
  pinned: boolean
  messageCount: number
  createdAt: string
  updatedAt: string
}

/** Tenant/session context every request inherits — never cross-tenant. */
export interface CopilotContext {
  userId: string
  email: string
  tenantLabel: string
  role: CopilotRole
  roleLabel: string
  tier: string
  capabilities: RoleCapabilities
  /** Whether conversation persistence (copilot_* tables) is available. */
  persistence: 'database' | 'memory'
}

export interface CopilotInsight {
  id: string
  severity: CopilotRiskLevel
  title: string
  detail: string
  deepLink: string
  module: string
  evidence: string
}

export interface CopilotSuggestion {
  text: string
  intent: CopilotIntent
}

/** Rolling per-conversation memory used to resolve follow-up questions. */
export interface CopilotMemoryState {
  focusIntents: CopilotIntent[]
  focusAssets: string[]
  focusEntity?: string
  lastSummary?: string
  currentPage?: string
  turns: number
}

export const EMPTY_MEMORY: CopilotMemoryState = {
  focusIntents: [],
  focusAssets: [],
  turns: 0,
}
