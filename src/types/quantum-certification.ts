/**
 * Quantum Trust Certification Engine™ — shared frontend/backend contract.
 *
 * Every field is evidence-driven: values originate from the live Quantum
 * Readiness snapshot (buildSnapshot) and the validated enterprise report model
 * (buildReportModel), never asserted. The canonical signed payload persisted
 * with each certificate is the integrity source of truth for verification.
 */

export type CertificationLevel = 'bronze' | 'silver' | 'gold' | 'platinum' | 'diamond';
export type CertificateStatus = 'active' | 'suspended' | 'revoked' | 'expired' | 'superseded';

export const LEVEL_LABELS: Record<CertificationLevel, string> = {
  bronze: 'Initial Readiness',
  silver: 'Hybrid PQC Implemented',
  gold: 'Enterprise Quantum Secure',
  platinum: 'Advanced Quantum Trust',
  diamond: 'Continuous Quantum Trust Certified',
};

export const LEVEL_ORDER: CertificationLevel[] = ['bronze', 'silver', 'gold', 'platinum', 'diamond'];

export interface EligibilityCheck {
  id: string;
  criterion: string;
  required: string;
  actual: string;
  met: boolean;
  severity: 'required' | 'advisory';
  evidence: string;
  remediation: string;
}

export interface CertificationPolicy {
  minReadiness: number;
  maxCriticalFindings: number;
  maxHndlRisk: number;
  maxResidualRisk: number;
  minConfidence: number;
  minPqcAdoption: number;
  maxVulnerableComponents: number;
  maxExpiredCertificates: number;
  disallowedAlgorithms: string[];
  validityDays: number;
}

export interface EligibilityResult {
  /**
   * All required criteria met — the estate is CERTIFICATION-grade (Silver+).
   * Distinct from `issuable`: this is the claim "quantum secure".
   */
  eligible: boolean;
  /**
   * Enough measured evidence exists to state a baseline posture, so a Bronze
   * "Initial Readiness" attestation can be issued. Bronze does NOT assert the
   * estate is quantum-safe — it records what was measured, including the gaps.
   */
  issuable: boolean;
  evaluatedAt: string;
  hasData: boolean;
  requiredTotal: number;
  requiredMet: number;
  trustScore: number; // 0–1000 Quantum Trust Score™
  level: CertificationLevel | null;
  levelLabel: string;
  checks: EligibilityCheck[];
  recommendations: Array<{ title: string; detail: string; severity: string; route: string }>;
  policy: CertificationPolicy;
}

export interface CertificateAlgorithm {
  category: string;
  algorithm: string;
  standard: string;
  verified: boolean;
  evidence: string;
}

export interface CertificateAsset {
  name: string;
  type: string;
  environment: string;
  posture: string;
  riskScore: number;
  internetFacing: boolean;
}

export interface CertificateSignature {
  algorithm: string; // ML-DSA-65 (FIPS 204)
  signatureHex: string;
  publicKeyHex: string;
  keyId: string;
  certificateHash: string; // SHA3-256 hex of the canonical payload
  signedAt: string;
  chain: Array<{ role: string; name: string; algorithm: string }>;
}

export interface QuantumTrustCertificate {
  certificateId: string; // QTH-YYYY-NNNNNN
  organization: string;
  organizationLogo: string | null;
  status: CertificateStatus;
  level: CertificationLevel;
  levelLabel: string;
  /**
   * True only when every required criterion was met at issuance (Silver+).
   * A Bronze baseline attestation is `false` — it must never be presented as
   * a quantum-secure certification. Carried inside the ML-DSA-65-signed
   * canonical payload, so it is tamper-evident on the public verify portal.
   */
  certified: boolean;
  /** Criteria met at issuance, e.g. 3 of 10 — printed on the artifact. */
  criteriaMet: number;
  criteriaTotal: number;
  trustScore: number;
  overallReadiness: number;
  quantumRisk: number;
  hndlRisk: number;
  residualRisk: number;
  residualRiskLevel: string;
  assessmentConfidence: number;
  pqcAdoption: number;
  issuedAt: string;
  expiresAt: string;
  assessmentId: string;
  assessmentVersion: string;
  scope: string[];
  cryptoStack: CertificateAlgorithm[];
  certifiedAssets: CertificateAsset[];
  certificateHash: string;
  verificationUrl: string;
  signature: CertificateSignature | null;
  renewedFrom: string | null;
  suspendedReason: string | null;
  revokedReason: string | null;
  lastValidatedAt: string | null;
}

export interface CertificateHistoryEvent {
  id: string;
  certificateId: string;
  event: string;
  detail: string;
  actor: string;
  createdAt: string;
}

export interface CertificateNotification {
  id: string;
  certificateId: string;
  kind: string;
  message: string;
  read: boolean;
  createdAt: string;
}

export interface CertificationAdvisor {
  headline: string;
  verdict: 'certified' | 'eligible' | 'not_eligible' | 'no_evidence';
  explanation: string[];
  businessImpact: string[];
  nextSteps: Array<{ title: string; detail: string; route: string }>;
}

/** Full payload served by GET /api/v1/quantum-certification. */
export interface CertificationDashboard {
  generatedAt: string;
  hasData: boolean;
  eligibility: EligibilityResult;
  certificate: QuantumTrustCertificate | null; // latest non-superseded certificate
  certificates: QuantumTrustCertificate[]; // full history (newest first, no heavy fields)
  history: CertificateHistoryEvent[];
  notifications: CertificateNotification[];
  verificationActivity: Array<{ certificateId: string; result: string; lookupBy: string; createdAt: string }>;
  downloads: Array<{ certificateId: string; format: string; createdAt: string }>;
  trend: Array<{ label: string; trustScore: number; readiness: number }>;
  renewal: { expiresAt: string | null; daysRemaining: number | null; autoRenewEligible: boolean };
  advisor: CertificationAdvisor;
  issuer: { name: string; keyId: string; algorithm: string; publicKeyHex: string } | null;
  schemaReady: boolean; // false until quantum-certification-schema.sql has been applied
}

/** Public verification portal payload — non-sensitive fields only. */
export interface PublicCertificateVerification {
  found: boolean;
  certificateId: string;
  organization: string;
  status: CertificateStatus | 'not_found';
  statusDetail: string;
  level: CertificationLevel | null;
  levelLabel: string;
  /**
   * False for a Bronze baseline attestation. The public portal MUST surface
   * this — a third party reading a verification page has to be able to tell a
   * measured baseline from a quantum-secure certification.
   */
  certified: boolean;
  criteriaMet: number;
  criteriaTotal: number;
  trustScore: number;
  overallReadiness: number;
  pqcAdoption: number;
  residualRiskLevel: string;
  issuedAt: string | null;
  expiresAt: string | null;
  assessmentVersion: string;
  certificateHash: string;
  signatureAlgorithm: string;
  signatureValid: boolean | null;
  integrityValid: boolean | null;
  lastValidatedAt: string | null;
  certifiedAlgorithms: Array<{ category: string; algorithm: string; standard: string }>;
  verifiedAt: string;
}
