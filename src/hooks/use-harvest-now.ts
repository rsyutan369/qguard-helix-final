'use client';

import { useLiveResource, type LiveLoadState } from './use-live-resource';

/* ------------------------------------------------------------------ */
/* Types — the HNDL contract from /api/v1/harvest-now                 */
/* ------------------------------------------------------------------ */
export type LoadState = LiveLoadState;
export type CryptoClass = 'vulnerable' | 'hybrid' | 'safe' | 'unknown';

export interface HndlBanner {
  threatLevel: string;
  hndlExposureScore: number;
  hndlExposureLevel: string;
  criticalFindings: number;
  quantumExposureWindow: string;
  estimatedFutureDecryptableTb: number;
  migrationDeadlineYear: number;
  yearsToDeadline: number;
  headline: string;
}

export interface ExposureTier {
  id: string;
  label: string;
  kind: string;
  total: number;
  vulnerable: number;
  cryptoClass: CryptoClass;
  detail: string;
}

export interface ExposureNode {
  id: string;
  label: string;
  type: string;
  environment: string;
  riskScore: number;
  cryptoClass: CryptoClass;
  internetFacing: boolean;
  algorithms: string[];
  affectedDataDetail: string;
  migrationPlan: string;
}

export interface TheaterAssetRef {
  name: string;
  posture: string;
  riskScore: number;
  internetFacing: boolean;
}

export interface TheaterRegion {
  key: string;
  region: string;
  label: string;
  lat: number;
  lon: number;
  x: number;
  y: number;
  assets: number;
  vulnerableAssets: number;
  avgRisk: number;
  internetFacing?: number;
  cloudProviders: string[];
  topAssets?: TheaterAssetRef[];
  severity: string;
}

export interface TheaterAnchor {
  id: string;
  name: string;
  country: string | null;
  countryLabel: string | null;
  lat: number | null;
  lon: number | null;
  x: number | null;
  y: number | null;
  certificates: number;
  assets: string[];
  quantumSafe: boolean;
  algorithms: string[];
}

export interface TheaterAssetLink {
  from: string;
  to: string;
  kind: string;
  count: number;
  vulnerable: boolean;
}

export interface TheaterTrustLink {
  asset: string;
  siteKey: string | null;
  anchorId: string;
  vulnerable: boolean;
}

export interface TheaterUnlocatedAsset extends TheaterAssetRef {
  type: string;
}

export interface TheaterMapModel {
  sites: TheaterRegion[];
  anchors: TheaterAnchor[];
  assetLinks: TheaterAssetLink[];
  trustLinks: TheaterTrustLink[];
  unlocated: TheaterUnlocatedAsset[];
  unlocatedTotal: number;
  internetFacing: number;
  latRange: { max: number; min: number };
}

export const EMPTY_THEATER_MAP: TheaterMapModel = {
  sites: [], anchors: [], assetLinks: [], trustLinks: [], unlocated: [], unlocatedTotal: 0, internetFacing: 0, latRange: { max: 78, min: -56 },
};

export interface HarvestValueRow {
  key: string;
  label: string;
  inScope: boolean;
  assetCount: number;
  /** null = category not present in the estate, so it was NOT scored. */
  exposureScore: number | null;
  confidentialityLifetimeYears: number;
  confidentialityLabel: string;
  adversaryInterestScore: number | null;
  estimatedFutureValue: string;
  regulation: string;
}

export interface ShelfLifeRow {
  dataType: string;
  retentionRequirement: string;
  confidentialityYears: number;
  dataExpiresYear: number;
  quantumRiskWindow: string;
  exceedsCrqc: boolean;
  inScope: boolean;
  assetCount: number;
}

export interface BreakTimelineYear {
  year: number;
  projectedRisk: number;
  milestone: string;
  critical: boolean;
}

export interface ForwardSecrecy {
  coveragePct: number;
  /** COMPONENT counts — key-agreement observations, not assets. */
  assetsProtected: number;
  assetsUnprotected: number;
  totalTransport: number;
  componentsMeasured?: number;
  /** Bulk ciphers, hashes and policy records: no key agreement to assess. */
  componentsNotApplicable?: number;
  assetsWithPfs?: number;
  assetsWithoutPfs?: number;
  runtimeLegacyEvents?: number;
  nonPfsBreakdown: Array<{ type: string; count: number }>;
  topUnprotected: Array<{ asset: string; algorithm: string; protocol: string; reason: string }>;
  hasEvidence: boolean;
  /** States the population measured, so coverage is auditable. */
  basis?: string;
}

export interface ExposureMatrixRow {
  algorithm: string;
  /** cipher-suite | key-exchange | signature | certificate | symmetric | hash */
  kind?: string;
  assetCount: number;
  instanceCount: number;
  businessCriticality: string;
  exposure: string;
  cryptoClass: CryptoClass;
  migrationPriority: string;
  priorityRank: number;
  internetFacing: boolean;
}

export interface CapturedDataLine {
  key: string;
  label: string;
  /** MEASURED count of the unit (hosts, vault files, assets). */
  unit: number;
  /** What `unit` counts, singular. */
  unitLabel?: string;
  /** Published planning assumption per unit — NOT a measurement. */
  perUnitGb?: number;
  gb: number;
  tb: number;
}

export interface MigrationReadiness {
  readinessScore: number;
  readinessLevel: string;
  pqcReady: number;
  hybridReady: number;
  legacyOnly: number;
  /** Assets nothing has been measured on yet. */
  notAssessed?: number;
  migrationBlocked: number;
  migrationInProgress: number;
  migrationCompleted: number;
  pqcAdoptionPct: number;
  recommendation: string;
}

export interface AdversaryInterestRow {
  key: string;
  sector: string;
  /** null when the estate holds no assets in this sector — not scored. */
  interestScore: number | null;
  level: string;
  assetsInSector: number;
  inScope: boolean;
}

export interface ThreatActorRow {
  key: string;
  actor: string;
  interestScore: number;
  level: string;
  /** The estate's harvest-exposed assets — what such an actor COULD collect, not observed targeting. */
  targetedAssets: string[];
  targetedAssetCount: number;
  motivation: string;
  /** How the modelled relevance was derived. */
  basis?: string;
}

export interface IntelligenceFeedItem {
  id: string;
  date: string;
  source: string;
  category: string;
  title: string;
  detail: string;
  impact: string;
}

export interface TopFindingRow {
  id: string;
  asset: string;
  algorithm: string;
  severity: string;
  dataLifetimeYears: number;
  dataLifetimeLabel: string;
  riskWindow: string;
  exceedsCrqc: boolean;
  migrationPriority: string;
  environment: string;
  detectedAt: string | null;
}

export interface RemediationAction {
  key: string;
  label: string;
  /** Count of `unit`s the action changes (named for history; not always assets). */
  affectedAssets: number;
  unit?: string;
  riskReductionPct: number;
  effort: string;
  completion: string;
  href: string;
  requires: string;
  inScope: boolean;
}

export interface HndlIntelligence {
  generatedAt: string | null;
  lastScanAt: string | null;
  hasData: boolean;
  connected: boolean;
  banner: HndlBanner;
  exposureGraph: { tiers: ExposureTier[]; nodes: ExposureNode[]; edges: Array<{ source: string; target: string; type: string }>; legend: { safe: string; hybrid: string; vulnerable: string } };
  theater: { regions: TheaterRegion[]; totalRegions: number; highValueTargets: number; summary: string; map?: TheaterMapModel };
  harvestValue: HarvestValueRow[];
  shelfLife: ShelfLifeRow[];
  breakTimeline: {
    currentYear: number; crqcYear: number; migrationDeadlineYear: number; migrationCompletionYear: number;
    yearsRemaining: number; currentRisk: number; projectedRiskAtCrqc: number; years: BreakTimelineYear[];
  };
  forwardSecrecy: ForwardSecrecy;
  exposureMatrix: ExposureMatrixRow[];
  capturedData: { lines: CapturedDataLine[]; totalTb: number; totalGb: number; hasEvidence: boolean; basis?: string };
  futureDecryptable: {
    totalDataAtRiskTb: number; projectedDecryptableTb: number; highValueDataPct: number;
    criticalConfidentialAssets: number; vulnerableSharePct: number; trend: Array<{ label: string; decryptableTb: number }>; hasEvidence: boolean;
  };
  migrationReadiness: MigrationReadiness;
  adversaryInterest: AdversaryInterestRow[];
  threatActors: ThreatActorRow[];
  intelligenceFeed: IntelligenceFeedItem[];
  topFindings: TopFindingRow[];
  remediationCenter: RemediationAction[];
  scores: { hndlRisk: number; hndlRiskLevel: string; quantumRisk: number; quantumReadiness: number; cryptoExposure: number; pqcAdoption: number };
  inventory: {
    assetsAssessed: number; quantumVulnerableAssets: number; vulnerableComponents: number; cryptoComponents: number;
    certificatesAnalyzed: number; keysDiscovered: number; domainsScanned: number; dataRepositories: number;
  };
  evidence: { sources: string[]; note: string };
}

export const EMPTY_HNDL: HndlIntelligence = {
  generatedAt: null,
  lastScanAt: null,
  hasData: false,
  connected: false,
  banner: { threatLevel: 'Unknown', hndlExposureScore: 0, hndlExposureLevel: 'Minimal', criticalFindings: 0, quantumExposureWindow: 'Evidence Not Available', estimatedFutureDecryptableTb: 0, migrationDeadlineYear: 2030, yearsToDeadline: 0, headline: '' },
  exposureGraph: { tiers: [], nodes: [], edges: [], legend: { safe: 'Quantum Safe', hybrid: 'Hybrid', vulnerable: 'Vulnerable' } },
  theater: { regions: [], totalRegions: 0, highValueTargets: 0, summary: '' },
  harvestValue: [],
  shelfLife: [],
  breakTimeline: { currentYear: new Date().getFullYear(), crqcYear: 2030, migrationDeadlineYear: 2029, migrationCompletionYear: 2029, yearsRemaining: 0, currentRisk: 0, projectedRiskAtCrqc: 0, years: [] },
  forwardSecrecy: { coveragePct: 0, assetsProtected: 0, assetsUnprotected: 0, totalTransport: 0, componentsMeasured: 0, componentsNotApplicable: 0, assetsWithPfs: 0, assetsWithoutPfs: 0, runtimeLegacyEvents: 0, nonPfsBreakdown: [], topUnprotected: [], hasEvidence: false, basis: '' },
  exposureMatrix: [],
  capturedData: { lines: [], totalTb: 0, totalGb: 0, hasEvidence: false },
  futureDecryptable: { totalDataAtRiskTb: 0, projectedDecryptableTb: 0, highValueDataPct: 0, criticalConfidentialAssets: 0, vulnerableSharePct: 0, trend: [], hasEvidence: false },
  migrationReadiness: { readinessScore: 0, readinessLevel: 'Not Started', pqcReady: 0, hybridReady: 0, legacyOnly: 0, migrationBlocked: 0, migrationInProgress: 0, migrationCompleted: 0, pqcAdoptionPct: 0, recommendation: '' },
  adversaryInterest: [],
  threatActors: [],
  intelligenceFeed: [],
  topFindings: [],
  remediationCenter: [],
  scores: { hndlRisk: 0, hndlRiskLevel: 'Minimal', quantumRisk: 0, quantumReadiness: 0, cryptoExposure: 0, pqcAdoption: 0 },
  inventory: { assetsAssessed: 0, quantumVulnerableAssets: 0, vulnerableComponents: 0, cryptoComponents: 0, certificatesAnalyzed: 0, keysDiscovered: 0, domainsScanned: 0, dataRepositories: 0 },
  evidence: { sources: [], note: '' },
};

const REALTIME_TABLES = [
  'assets', 'pqc_scan_results', 'pqc_scan_sessions', 'crypto_inventory', 'crypto_exposures',
  'certificates', 'generated_keys', 'runtime_crypto_events', 'migration_jobs',
] as const;

/**
 * useHarvestNow — the enterprise HNDL intelligence model, live over its
 * fingerprinted stream (see use-live-resource.ts; the bearer token travels in
 * the Authorization header, never the URL). Every value is tenant-scoped data
 * derived from scanned assets, CBOM, certificates and runtime crypto telemetry.
 */
export function useHarvestNow() {
  const live = useLiveResource<HndlIntelligence>({
    url: '/api/v1/harvest-now',
    streamUrl: '/api/v1/harvest-now/stream',
    event: 'hndl-intelligence',
    empty: EMPTY_HNDL,
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'hndl',
  });
  return { data: live.data, state: live.state, error: live.error, sseConnected: live.sseConnected, lastVerifiedAt: live.lastVerifiedAt, refresh: live.refresh };
}
