import { z } from 'zod';

/**
 * QGuard Helix Enterprise Reporting Engine™ — unified report model.
 *
 * `EnterpriseAssessmentReport` is the single source of truth every exporter
 * (PDF / DOCX / XLSX / CSV / JSON / HTML / PPTX) consumes. It is assembled
 * exclusively from real assessment evidence/telemetry — see ReportEvidence.ts.
 * Missing evidence is represented explicitly (`Evidence Not Available`); findings
 * are never fabricated.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const REPORT_KINDS = ['executive', 'technical', 'compliance', 'migration'] as const;
export type ReportKind = (typeof REPORT_KINDS)[number];

export const REPORT_FORMATS = ['pdf', 'docx', 'xlsx', 'csv', 'json', 'html', 'pptx'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export const EVIDENCE_UNAVAILABLE = 'Evidence Not Available';

export const findingSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: z.enum(SEVERITIES),
  evidence: z.string(),
  affectedAssets: z.array(z.string()),
  recommendation: z.string(),
  remediationPlan: z.string(),
  source: z.string().default('QGuard Helix'),
  detectedAt: z.string().nullable().optional(),
  // Actionable enrichment (Enhancement #1)
  currentState: z.string().default(EVIDENCE_UNAVAILABLE),
  recommendedState: z.string().default(EVIDENCE_UNAVAILABLE),
  businessImpact: z.string().default(EVIDENCE_UNAVAILABLE),
  technicalImpact: z.string().default(EVIDENCE_UNAVAILABLE),
  migrationComplexity: z.enum(['Low', 'Medium', 'High']).default('Medium'),
  dependencies: z.array(z.string()).default([]),
  owner: z.string().default('Security Engineering'),
  targetDate: z.string().default(EVIDENCE_UNAVAILABLE),
  validation: z.string().default(EVIDENCE_UNAVAILABLE),
  riskReductionPct: z.number().default(0),
  estimatedCostUsd: z.number().default(0),
  estimatedEffort: z.string().default(EVIDENCE_UNAVAILABLE),
});
export type ReportFinding = z.infer<typeof findingSchema>;

/* ---- Board-level program sections (Report Enhancement 1 & 2) ---- */

// I2#8 — Top Business Risks (board language, evidence-driven)
export const businessRiskSchema = z.object({ risk: z.string(), level: z.string(), driver: z.string() });
export type BusinessRisk = z.infer<typeof businessRiskSchema>;

export const executiveBlockSchema = z.object({
  currentReadiness: z.number(),
  targetReadiness: z.number(),
  currentRisk: z.number(),
  targetRisk: z.number(),
  currentHndl: z.number(),
  targetHndl: z.number(),
  estimatedDurationWeeks: z.number(),
  estimatedCostUsd: z.number(),
  expectedRiskReductionPct: z.number(),
  expectedComplianceImprovementPct: z.number(),
  quantumExposureWindow: z.string(),
  topRisks: z.array(z.string()),
  topActions: z.array(z.string()),
  // I2#8 — board-language business risks (Internet-facing TLS, HNDL, …)
  topBusinessRisks: z.array(businessRiskSchema).default([]),
  executiveRecommendation: z.string(),
});
export type ExecutiveBlock = z.infer<typeof executiveBlockSchema>;

export const businessImpactSchema = z.object({
  customerFacingSystems: z.number(),
  missionCriticalSystems: z.number(),
  revenueImpact: z.string(),
  operationalImpact: z.string(),
  complianceImpact: z.string(),
  reputationalImpact: z.string(),
  financialImpact: z.string(),
  thirdPartyDependencies: z.number(),
  hndlExposure: z.string(),
  quantumExposureWindow: z.string(),
});
export type BusinessImpact = z.infer<typeof businessImpactSchema>;

export const readinessDomainSchema = z.object({
  domain: z.string(),
  score: z.number(),
  targetScore: z.number().default(0),
  targetRationale: z.string().default(EVIDENCE_UNAVAILABLE),
  riskLevel: z.string(),
  owner: z.string(),
  actions: z.string(),
});
export type ReadinessDomain = z.infer<typeof readinessDomainSchema>;

export const migrationAdvisorSchema = z.object({
  recommendation: z.string(),
  reason: z.string(),
  affectedAssets: z.array(z.string()),
  riskReductionPct: z.number(),
  costUsd: z.number(),
  timelineWeeks: z.number(),
  complexity: z.string(),
  successProbabilityPct: z.number(),
  confidencePct: z.number(),
});
export type MigrationAdvisor = z.infer<typeof migrationAdvisorSchema>;

export const migrationWaveSchema = z.object({
  wave: z.number(),
  name: z.string(),
  assets: z.array(z.string()),
  owner: z.string(),
  durationWeeks: z.number(),
  costUsd: z.number(),
  dependencies: z.array(z.string()),
  riskReductionPct: z.number(),
  status: z.string(),
  priority: z.string(),
});
export type MigrationWave = z.infer<typeof migrationWaveSchema>;

export const playbookStageSchema = z.object({
  wave: z.string(),
  prerequisites: z.string(),
  preparation: z.string(),
  execution: z.string(),
  rollback: z.string(),
  validation: z.string(),
  successCriteria: z.string(),
});
export type PlaybookStage = z.infer<typeof playbookStageSchema>;

export const riskCategorySchema = z.object({
  category: z.string(),
  currentScore: z.number(),
  targetScore: z.number(),
  reductionPotentialPct: z.number(),
});
export type RiskCategory = z.infer<typeof riskCategorySchema>;

export const hndlCategorySchema = z.object({
  category: z.string(),
  retention: z.string(),
  currentProtection: z.string(),
  hndlRisk: z.string(),
  recommendedProtection: z.string(),
});
export type HndlCategory = z.infer<typeof hndlCategorySchema>;

export const costLineSchema = z.object({ category: z.string(), costUsd: z.number() });
export const costForecastSchema = z.object({
  lines: z.array(costLineSchema),
  totalUsd: z.number(),
  projectedRiskReductionValueUsd: z.number(),
});
export type CostForecast = z.infer<typeof costForecastSchema>;

export const riskForecastSchema = z.object({
  currentRisk: z.number(),
  targetRisk: z.number(),
  reductionPct: z.number(),
  residualRisk: z.number(),
  month12: z.number(),
  month24: z.number(),
  month36: z.number(),
});
export type RiskForecast = z.infer<typeof riskForecastSchema>;

export const governanceRoleSchema = z.object({ role: z.string(), owner: z.string(), responsibility: z.string() });
export type GovernanceRole = z.infer<typeof governanceRoleSchema>;

export const remediationItemSchema = z.object({
  priority: z.number(),
  action: z.string(),
  owner: z.string(),
  affectedAssets: z.array(z.string()),
  costUsd: z.number(),
  effort: z.string(),
  riskReductionPct: z.number(),
  targetDate: z.string(),
  status: z.string(),
  dependencies: z.array(z.string()),
  validation: z.string(),
});
export type RemediationItem = z.infer<typeof remediationItemSchema>;

export const dependencyChainSchema = z.object({ path: z.string(), blastRadius: z.number(), complexity: z.string() });

/* ---- Report Intelligence sections (Reports_Enhancements_3) ---- */

// Phase 1 — Risk Scoring Transparency Engine™
// `contribution` = absolute weighted contribution (DomainRisk × Weight); the
// overall score is Σ(contribution), so an auditor can reconstruct it by hand.
export const riskWeightSchema = z.object({ domain: z.string(), weightPct: z.number(), score: z.number(), contribution: z.number(), contributionPct: z.number() });
export const riskMethodologySchema = z.object({
  formula: z.string(),
  overall: z.number(),
  weights: z.array(riskWeightSchema),
  topDriver: z.string(),
  explanation: z.string(),
});
export type RiskMethodology = z.infer<typeof riskMethodologySchema>;

// Phase 2 — AI Recommendation Validation Engine™
export const advisorValidationSchema = z.object({
  primaryExposureDomain: z.string(),
  topContributingFindings: z.array(z.string()),
  topContributingAssets: z.array(z.string()),
  expectedRiskReductionPct: z.number(),
  confidencePct: z.number(),
  why: z.string(),
});
export type AdvisorValidation = z.infer<typeof advisorValidationSchema>;

// Phase 3 — Cost Forecast Intelligence™
export const costLineDetailSchema = z.object({ category: z.string(), hours: z.number(), engineers: z.number(), rateUsd: z.number(), costUsd: z.number(), formula: z.string() });
export const costBreakdownSchema = z.object({ blendedRateUsd: z.number(), totalHours: z.number(), totalUsd: z.number(), lines: z.array(costLineDetailSchema) });
export type CostBreakdown = z.infer<typeof costBreakdownSchema>;

// Phase 5 — Asset Criticality Engine™
export const assetCriticalitySchema = z.object({
  asset: z.string(),
  businessCriticality: z.string(),
  operationalCriticality: z.string(),
  customerFacing: z.boolean(),
  internetFacing: z.boolean(),
  revenueImpact: z.string(),
  complianceScope: z.array(z.string()),
  dataSensitivity: z.string(),
});
export type AssetCriticality = z.infer<typeof assetCriticalitySchema>;

// Phase 6 — Business Impact Intelligence™ (reasons)
export const impactReasonSchema = z.object({ dimension: z.string(), level: z.string(), reason: z.string(), evidence: z.array(z.string()).default([]) });
export type ImpactReason = z.infer<typeof impactReasonSchema>;

// Phase 7 — Finding Deduplication Engine™
export const findingGroupSchema = z.object({ title: z.string(), occurrences: z.number(), affectedAssets: z.number(), evidence: z.array(z.string()), impact: z.enum(SEVERITIES) });
export type FindingGroup = z.infer<typeof findingGroupSchema>;

// Phase 8 — Migration Confidence Scoring™
export const confidenceFactorSchema = z.object({ label: z.string(), coveragePct: z.number() });
export const migrationConfidenceSchema = z.object({ overallPct: z.number(), factors: z.array(confidenceFactorSchema) });
export type MigrationConfidence = z.infer<typeof migrationConfidenceSchema>;

// Phase 9 — Evidence Confidence Scoring™
export const evidenceConfidenceSchema = z.object({ source: z.string(), coveragePct: z.number(), completenessPct: z.number(), freshness: z.string(), confidencePct: z.number(), note: z.string() });
export type EvidenceConfidence = z.infer<typeof evidenceConfidenceSchema>;

// Phase 10 — Executive Decision Center™
export const executiveDecisionSchema = z.object({ decision: z.string(), type: z.string(), rationale: z.string(), owner: z.string() });
export type ExecutiveDecision = z.infer<typeof executiveDecisionSchema>;

// Phase 11 — Enterprise Remediation Playbook™
export const playbookDetailSchema = z.object({
  finding: z.string(),
  currentState: z.string(),
  targetState: z.string(),
  prerequisites: z.array(z.string()),
  dependencies: z.array(z.string()),
  executionSteps: z.array(z.string()),
  validationSteps: z.array(z.string()),
  rollbackSteps: z.array(z.string()),
  successCriteria: z.array(z.string()),
});
export type PlaybookDetail = z.infer<typeof playbookDetailSchema>;

// Phase 12 — Migration Simulation Engine™
export const waveSimulationSchema = z.object({ label: z.string(), readinessFrom: z.number(), readinessTo: z.number(), riskFrom: z.number(), riskTo: z.number(), costUsd: z.number(), timelineWeeks: z.number(), confidencePct: z.number() });
export type WaveSimulation = z.infer<typeof waveSimulationSchema>;

// Phase 13 — Enterprise Governance gates
export const governanceGateSchema = z.object({ gate: z.string(), owner: z.string(), criteria: z.string() });
export type GovernanceGate = z.infer<typeof governanceGateSchema>;

// Phase 14 — Report Explainability Requirements™
export const explainabilitySchema = z.object({ metric: z.string(), what: z.string(), how: z.string(), evidence: z.string(), why: z.string(), action: z.string() });
export type Explainability = z.infer<typeof explainabilitySchema>;

export const kpiSchema = z.object({
  label: z.string(),
  value: z.union([z.string(), z.number()]),
  unit: z.string().optional(),
  level: z.string().optional(),
  tone: z.enum(['critical', 'high', 'medium', 'low', 'good', 'neutral']).default('neutral'),
});
export type ReportKpi = z.infer<typeof kpiSchema>;

export const tableSchema = z.object({
  title: z.string(),
  columns: z.array(z.string()),
  rows: z.array(z.array(z.union([z.string(), z.number()]))),
});
export type ReportTable = z.infer<typeof tableSchema>;

export const complianceMappingSchema = z.object({
  framework: z.string(),
  control: z.string(),
  status: z.enum(['aligned', 'partial', 'gap', 'not-assessed']),
  detail: z.string(),
  // I2#7 — dynamic gap tracking: Current / Target / Gap / Progress per framework
  currentPct: z.number().default(0),
  targetPct: z.number().default(0),
  gapPct: z.number().default(0),
  progressPct: z.number().default(0),
});
export type ComplianceMapping = z.infer<typeof complianceMappingSchema>;

export const roadmapPhaseSchema = z.object({
  phase: z.string(),
  description: z.string(),
  status: z.string(),
  effortWeeks: z.number(),
  // Program-management enrichment (#8)
  startDate: z.string().default(EVIDENCE_UNAVAILABLE),
  endDate: z.string().default(EVIDENCE_UNAVAILABLE),
  milestone: z.string().default(''),
  gate: z.string().default(''),
  criticalPath: z.boolean().default(false),
  slackWeeks: z.number().default(0),
});
export type RoadmapPhase = z.infer<typeof roadmapPhaseSchema>;

// #9 — Executive Risk Acceptance register
export const riskAcceptanceSchema = z.object({
  risk: z.string(),
  decision: z.enum(['Mitigate', 'Accept', 'Transfer', 'Defer']),
  owner: z.string(),
  rationale: z.string(),
  residualRisk: z.string(),
  reviewDate: z.string().default(EVIDENCE_UNAVAILABLE),
});
export type RiskAcceptance = z.infer<typeof riskAcceptanceSchema>;

// #10 — Asset-Level Readiness
export const assetReadinessSchema = z.object({
  asset: z.string(),
  readiness: z.number(),
  risk: z.number(),
  posture: z.string(),
  internetFacing: z.boolean(),
  primaryDriver: z.string(),
  owner: z.string(),
});
export type AssetReadiness = z.infer<typeof assetReadinessSchema>;

// Architectural — Decision Traceability (Evidence → … → Approval)
export const decisionChainStepSchema = z.object({ stage: z.string(), detail: z.string() });
export const decisionChainSchema = z.object({ headline: z.string(), steps: z.array(decisionChainStepSchema) });
export type DecisionChain = z.infer<typeof decisionChainSchema>;

/* ---- Improvements_02 — enterprise-grade report intelligence ---- */

// I2#1/#3 — Readiness Scoring Methodology™: the exact readiness formula with a
// per-factor Weight × Score = Contribution table. Unmeasured factors (e.g.
// runtime visibility with zero runtime telemetry) are marked `measured: false`,
// excluded from the blend and the remaining weights renormalised — the score is
// fully auditable and never contradicts the evidence dashboard.
export const readinessFactorContributionSchema = z.object({
  factor: z.string(),
  weightPct: z.number(),
  score: z.union([z.number(), z.string()]), // number, or 'Not Measured'
  contribution: z.number(),
  measured: z.boolean().default(true),
  basis: z.string().default(''),
});
export const readinessMethodologySchema = z.object({
  formula: z.string(),
  overall: z.number(),
  factors: z.array(readinessFactorContributionSchema),
  explanation: z.string(),
});
export type ReadinessMethodology = z.infer<typeof readinessMethodologySchema>;

// I2#4 — Executive ROI & Value Intelligence™
export const roiLineSchema = z.object({ metric: z.string(), value: z.string(), basis: z.string() });
export const roiAnalysisSchema = z.object({
  investmentUsd: z.number(),
  expectedRiskReductionPct: z.number(),
  riskAvoidanceUsd: z.number(),
  netBenefitUsd: z.number(),
  roiMultiple: z.number(),
  paybackNarrative: z.string(),
  lines: z.array(roiLineSchema),
});
export type RoiAnalysis = z.infer<typeof roiAnalysisSchema>;

// I2#5 — Migration Resource Loading™ (per-team allocation)
export const resourceLoadSchema = z.object({
  team: z.string(),
  waves: z.string(),
  hours: z.number(),
  engineers: z.number(),
  windowWeeks: z.number(),
  allocationPct: z.number(),
  basis: z.string().default(''),
});
export type ResourceLoad = z.infer<typeof resourceLoadSchema>;

// I2#6 — Asset Intelligence Profile™ (deep per-asset crypto posture)
export const assetIntelligenceSchema = z.object({
  asset: z.string(),
  assetType: z.string().default(EVIDENCE_UNAVAILABLE),
  environment: z.string().default(EVIDENCE_UNAVAILABLE),
  ownerDepartment: z.string().default(EVIDENCE_UNAVAILABLE),
  certificates: z.string().default(EVIDENCE_UNAVAILABLE),
  tlsVersion: z.string().default(EVIDENCE_UNAVAILABLE),
  algorithms: z.array(z.string()).default([]),
  keySizes: z.array(z.string()).default([]),
  cryptoLibraries: z.string().default(EVIDENCE_UNAVAILABLE),
  dependencies: z.array(z.string()).default([]),
  pqcReadinessPct: z.number().default(0),
  migrationComplexity: z.string().default('Medium'),
  estimatedHours: z.number().default(0),
});
export type AssetIntelligence = z.infer<typeof assetIntelligenceSchema>;

// I2#9 — Industry Benchmarking™ (peer values are modeled reference points)
export const benchmarkRowSchema = z.object({ cohort: z.string(), readiness: z.number(), delta: z.number(), source: z.string() });
export const benchmarkingSchema = z.object({ rows: z.array(benchmarkRowSchema), percentileNarrative: z.string(), note: z.string() });
export type Benchmarking = z.infer<typeof benchmarkingSchema>;

// I2#10 — Report Validation™ (self-verified arithmetic/consistency badge)
export const validationCheckSchema = z.object({ check: z.string(), status: z.enum(['pass', 'fail']), detail: z.string() });
export const reportValidationSchema = z.object({ overall: z.enum(['PASS', 'FAIL']), checks: z.array(validationCheckSchema), note: z.string().default('') });
export type ReportValidation = z.infer<typeof reportValidationSchema>;

// I2#11 — Quantum Readiness Index™ (strategic pillars behind the single score)
export const readinessPillarSchema = z.object({
  pillar: z.string(),
  score: z.union([z.number(), z.string()]), // number, or 'Not Measured'
  weightPct: z.number(),
  contribution: z.number(),
  measured: z.boolean().default(true),
  driver: z.string().default(''),
});
export const readinessIndexSchema = z.object({ overall: z.number(), pillars: z.array(readinessPillarSchema), note: z.string() });
export type ReadinessIndex = z.infer<typeof readinessIndexSchema>;

// I2#12 — Policy-driven PQC algorithm profiles (no hard-coded universal target)
export const cryptoPolicyProfileSchema = z.object({
  profile: z.string(),
  keyEstablishment: z.string(),
  digitalSignature: z.string(),
  certificateChain: z.string(),
  symmetric: z.string(),
  hash: z.string(),
  guidance: z.string(),
});
export const cryptoPolicySchema = z.object({ activeProfile: z.string(), profiles: z.array(cryptoPolicyProfileSchema), note: z.string() });
export type CryptoPolicy = z.infer<typeof cryptoPolicySchema>;

// I2#2 — Terminology & Definitions (Assets vs Components etc.)
export const definitionSchema = z.object({ term: z.string(), definition: z.string() });
export type ReportDefinition = z.infer<typeof definitionSchema>;

export const brandingSchema = z.object({
  companyName: z.string().default('QGuard Helix'),
  companyLogo: z.string().nullable().default(null), // data URL or storage URL
  businessUnit: z.string().default(''),
  reportOwner: z.string().default(''),
  reviewer: z.string().default(''),
  classification: z.string().default('CONFIDENTIAL'),
  reportVersion: z.string().default('1.0'),
  customNotes: z.string().default(''),
});
export type ReportBranding = z.infer<typeof brandingSchema>;

export const chartImageSchema = z.object({
  key: z.string(),
  title: z.string(),
  dataUrl: z.string(), // PNG data URL for embedding
});
export type ReportChartImage = z.infer<typeof chartImageSchema>;

export const reportMetaSchema = z.object({
  id: z.string(),
  kind: z.enum(REPORT_KINDS),
  title: z.string(),
  generatedAt: z.string(),
  generatedBy: z.string(),
  version: z.string(),
  tenantScoped: z.boolean().default(true),
  sourceGeneratedAt: z.string().nullable(),
});
export type ReportMeta = z.infer<typeof reportMetaSchema>;

export const integritySchema = z.object({
  algorithm: z.string(), // SHA3-256
  hash: z.string(),
  signedAt: z.string(),
  verificationToken: z.string().optional(),
});
export type ReportIntegrity = z.infer<typeof integritySchema>;

export const enterpriseAssessmentReportSchema = z.object({
  meta: reportMetaSchema,
  branding: brandingSchema,
  executiveSummary: z.string(),
  executiveBlock: executiveBlockSchema,
  kpis: z.array(kpiSchema),
  businessImpact: businessImpactSchema,
  readinessDomains: z.array(readinessDomainSchema),
  migrationAdvisor: migrationAdvisorSchema,
  migrationReadiness: z.array(z.object({ category: z.string(), score: z.number(), recommendation: z.string() })),
  migrationWaves: z.array(migrationWaveSchema),
  dependencyAnalysis: z.object({ chains: z.array(dependencyChainSchema), failurePoints: z.array(z.string()), summary: z.string() }),
  riskCategories: z.array(riskCategorySchema),
  // Report Intelligence (Reports_Enhancements_3)
  riskMethodology: riskMethodologySchema,
  advisorValidation: advisorValidationSchema,
  costBreakdown: costBreakdownSchema,
  assetCriticality: z.array(assetCriticalitySchema),
  impactReasons: z.array(impactReasonSchema),
  findingGroups: z.array(findingGroupSchema),
  migrationConfidence: migrationConfidenceSchema,
  evidenceConfidence: z.array(evidenceConfidenceSchema),
  executiveDecisions: z.array(executiveDecisionSchema),
  playbookDetail: z.array(playbookDetailSchema),
  waveSimulation: z.array(waveSimulationSchema),
  governanceGates: z.array(governanceGateSchema),
  explainability: z.array(explainabilitySchema),
  // Improvements_01
  riskAcceptance: z.array(riskAcceptanceSchema),
  assetReadiness: z.array(assetReadinessSchema),
  decisionChain: decisionChainSchema,
  // Improvements_02 — defaults keep previously-saved report JSON parseable
  readinessMethodology: readinessMethodologySchema.default({ formula: '', overall: 0, factors: [], explanation: EVIDENCE_UNAVAILABLE }),
  readinessIndex: readinessIndexSchema.default({ overall: 0, pillars: [], note: EVIDENCE_UNAVAILABLE }),
  roiAnalysis: roiAnalysisSchema.default({ investmentUsd: 0, expectedRiskReductionPct: 0, riskAvoidanceUsd: 0, netBenefitUsd: 0, roiMultiple: 0, paybackNarrative: EVIDENCE_UNAVAILABLE, lines: [] }),
  resourceLoading: z.array(resourceLoadSchema).default([]),
  assetIntelligence: z.array(assetIntelligenceSchema).default([]),
  benchmarking: benchmarkingSchema.default({ rows: [], percentileNarrative: EVIDENCE_UNAVAILABLE, note: '' }),
  reportValidation: reportValidationSchema.default({ overall: 'FAIL', checks: [], note: 'Validation not executed for this report version.' }),
  cryptoPolicy: cryptoPolicySchema.default({ activeProfile: '', profiles: [], note: '' }),
  definitions: z.array(definitionSchema).default([]),
  findings: z.array(findingSchema),
  assets: tableSchema,
  certificates: tableSchema,
  keys: tableSchema,
  tlsEndpoints: tableSchema,
  cbom: tableSchema,
  hndl: z.object({ summary: z.string(), table: tableSchema, categories: z.array(hndlCategorySchema) }),
  trustRelationships: tableSchema,
  pqcReadiness: z.object({ summary: z.string(), table: tableSchema }),
  compliance: z.array(complianceMappingSchema),
  remediationProgram: z.array(remediationItemSchema),
  roadmap: z.array(roadmapPhaseSchema),
  playbook: z.array(playbookStageSchema),
  costForecast: costForecastSchema,
  riskForecast: riskForecastSchema,
  governance: z.array(governanceRoleSchema),
  remediation: tableSchema,
  evidence: z.object({ sources: z.array(z.string()), notes: z.string() }),
  charts: z.array(chartImageSchema),
  integrity: integritySchema.optional(),
});
export type EnterpriseAssessmentReport = z.infer<typeof enterpriseAssessmentReportSchema>;

export function severityRank(severity: Severity): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[severity] ?? 0;
}

export function normalizeSeverity(value: string): Severity {
  const v = (value || '').toLowerCase();
  if (v.includes('critical')) return 'critical';
  if (v.includes('high')) return 'high';
  if (v.includes('medium') || v.includes('moderate')) return 'medium';
  if (v.includes('low')) return 'low';
  return 'info';
}
