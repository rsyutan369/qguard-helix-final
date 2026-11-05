'use client';

import { useMemo } from 'react';
import { buildReportModel, normalizeAssetKey } from '@/services/reporting/ReportEvidence';
import { brandingSchema, type EnterpriseAssessmentReport, type MigrationWave } from '@/services/reporting/schemas/ReportSchema';
import type { QuantumReadinessSnapshot } from './_shared';

/**
 * Shared advisor intelligence (AI Executive Advisor™ / AI Migration Advisor™).
 *
 * Both advisor pages consume the SAME unified enterprise report model the
 * Report Center exports (buildReportModel in src/services/reporting/
 * ReportEvidence.ts) instead of hand-rolling their own logic. That gives the
 * advisors, the dashboards and the generated reports one voice:
 *
 *  - every figure is evidence-derived (or explicitly `Evidence Not Available`)
 *  - risk decomposition, waves, costs, ROI and confidence all reconcile —
 *    the model self-validates (reportValidation badge is computed, not asserted)
 *  - the advisor can never contradict the report a customer downloads
 */

const ADVISOR_BRANDING = brandingSchema.parse({});

export function useAdvisorModel(snapshot: QuantumReadinessSnapshot, generatedBy: string): EnterpriseAssessmentReport {
  return useMemo(
    () => buildReportModel(snapshot, ADVISOR_BRANDING, 'executive', generatedBy || 'QGuard Helix'),
    [snapshot, generatedBy],
  );
}

/** Which wave an asset is sequenced into (by wave membership, else risk band). */
export function waveForAsset(assetName: string, riskScore: number, waves: MigrationWave[]): number {
  const key = normalizeAssetKey(assetName);
  for (const wave of waves) {
    if (wave.assets.some((a) => normalizeAssetKey(a) === key)) return wave.wave;
  }
  if (riskScore >= 70) return 1;
  if (riskScore >= 40) return Math.min(2, waves.length || 2);
  return Math.min(3, waves.length || 3);
}

/* ------------------------------------------------------------------ */
/* Migration handoff — AI Migration Advisor → Migration Planner /      */
/* Sandbox. The payload is the engine-generated roadmap so the target  */
/* page receives exactly what the advisor displayed.                   */
/* ------------------------------------------------------------------ */

export const MIGRATION_HANDOFF_KEY = 'qg-migration-handoff';

export interface MigrationHandoff {
  source: 'ai-migration-advisor';
  generatedAt: string;
  generatedBy: string;
  recommendation: string;
  reason: string;
  confidencePct: number;
  scores: QuantumReadinessSnapshot['scores'];
  estimates: QuantumReadinessSnapshot['estimates'];
  waves: EnterpriseAssessmentReport['migrationWaves'];
  readinessProgression: EnterpriseAssessmentReport['readinessProgression'];
  dependencyAnalysis: EnterpriseAssessmentReport['dependencyAnalysis'];
  assetPrioritization: Array<{ asset: string; wave: number; risk: number; readiness: number; criticality: string; pqcStatus: string; hndlExposure: string; primaryDriver: string; owner: string }>;
  rollbackStrategy: Array<{ finding: string; rollbackSteps: string[]; rollbackDuration: string; estimatedDowntime: string; maintenanceWindow: string; validationOwner: string; automationStatus: string; slaImpact: string }>;
  cryptoPolicyProfile: EnterpriseAssessmentReport['cryptoPolicy']['profiles'][number] | null;
  confidenceSummary: EnterpriseAssessmentReport['confidenceSummary'];
}

export function buildMigrationHandoff(snapshot: QuantumReadinessSnapshot, model: EnterpriseAssessmentReport, generatedBy: string): MigrationHandoff {
  const active = model.cryptoPolicy.profiles.find((p) => p.profile === model.cryptoPolicy.activeProfile) || null;
  return {
    source: 'ai-migration-advisor',
    generatedAt: new Date().toISOString(),
    generatedBy,
    recommendation: model.migrationAdvisor.recommendation,
    reason: model.migrationAdvisor.reason,
    confidencePct: model.migrationAdvisor.confidencePct,
    scores: snapshot.scores,
    estimates: snapshot.estimates,
    waves: model.migrationWaves,
    readinessProgression: model.readinessProgression,
    dependencyAnalysis: model.dependencyAnalysis,
    assetPrioritization: model.assetReadiness.map((a) => ({
      asset: a.asset,
      wave: waveForAsset(a.asset, a.risk, model.migrationWaves),
      risk: a.risk,
      readiness: a.readiness,
      criticality: a.criticality,
      pqcStatus: a.pqcStatus,
      hndlExposure: a.hndlExposure,
      primaryDriver: a.primaryDriver,
      owner: a.owner,
    })),
    rollbackStrategy: model.playbookDetail.map((p) => ({
      finding: p.finding,
      rollbackSteps: p.rollbackSteps,
      rollbackDuration: p.rollbackDuration,
      estimatedDowntime: p.estimatedDowntime,
      maintenanceWindow: p.maintenanceWindow,
      validationOwner: p.validationOwner,
      automationStatus: p.automationStatus,
      slaImpact: p.slaImpact,
    })),
    cryptoPolicyProfile: active,
    confidenceSummary: model.confidenceSummary,
  };
}

/**
 * The handoff carries a tenant's asset names and migration waves, so it is
 * keyed by USER. Under one shared key, the next account signed in on the same
 * browser opened Migration Planner or Sandbox on the previous account's
 * roadmap for up to 7 days.
 */
function handoffKey(userId: string): string {
  return `${MIGRATION_HANDOFF_KEY}:${userId}`;
}

export function writeMigrationHandoff(handoff: MigrationHandoff, userId: string | null | undefined): boolean {
  if (!userId) return false;
  try {
    localStorage.setItem(handoffKey(userId), JSON.stringify(handoff));
    return true;
  } catch {
    return false;
  }
}

export function readMigrationHandoff(userId: string | null | undefined): MigrationHandoff | null {
  try {
    // The pre-keyed entry cannot be attributed to an account: discard it.
    localStorage.removeItem(MIGRATION_HANDOFF_KEY);
  } catch {
    /* ignore */
  }
  if (!userId) return null;
  try {
    const raw = localStorage.getItem(handoffKey(userId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as MigrationHandoff;
    if (parsed?.source !== 'ai-migration-advisor' || !Array.isArray(parsed.waves)) return null;
    // Stale handoffs (older than 7 days) are ignored — the roadmap should be
    // regenerated from fresh evidence rather than executed from an old plan.
    if (Date.now() - new Date(parsed.generatedAt).getTime() > 7 * 24 * 60 * 60 * 1000) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function clearMigrationHandoff(userId: string | null | undefined): void {
  if (!userId) return;
  try {
    localStorage.removeItem(handoffKey(userId));
  } catch {
    /* ignore */
  }
}
