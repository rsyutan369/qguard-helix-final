import type { AssetDossier } from '@/hooks/use-migration-assets';

export const LAB_PRIMITIVES = [
  'ML-KEM-768', 'ML-KEM-1024', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128f', 'AES-256-GCM', 'SHA3-256', 'HKDF-SHA3-256',
] as const;
export const LAB_TLS_GROUPS = ['X25519MLKEM768', 'SecP384r1MLKEM1024'] as const;
export const LAB_TLS_CERTIFICATES = ['ecdsa', 'ml-dsa-65', 'ml-dsa-87'] as const;
export type LabPrimitive = typeof LAB_PRIMITIVES[number];
export type LabTlsGroup = typeof LAB_TLS_GROUPS[number];
export const LAB_BASELINE = 'Recorded configuration';
export type LabConfiguration = {
  primitives: LabPrimitive[];
  testDetected: boolean;
  tlsGroups: LabTlsGroup[];
  compareTlsBaseline: boolean;
  analysis: boolean;
};
export type LabAsset = Pick<AssetDossier,
  'id' | 'name' | 'type' | 'hostname' | 'environment' | 'owner' | 'hasEvidence' | 'postureLabel' | 'riskLevel' | 'riskScore' |
  'hndlLevel' | 'hndlScore' | 'discoveredAt' | 'lastEvidenceAt' | 'migrationStatus' | 'algorithms' | 'certificates' |
  'tlsConfiguration' | 'findings' | 'vulnerableComponentCount' | 'dependencies' | 'recommendations' | 'compatibility'>;
export type LabResult = {
  level: 'execution' | 'emulation' | 'analysis';
  profile: string;
  operation: string;
  status: 'passed' | 'failed' | 'warning' | 'unsupported' | 'not_tested' | 'estimated';
  detail: string;
  measures?: Array<{ name: string; value: number; unit: 'ms' | 'bytes' }>;
  issues?: Array<{ severity: 'high' | 'medium' | 'info'; component: string; explanation: string; impact: string; remediation: string; blocks: boolean }>;
  provider?: string;
  observedAt: string;
};
export type LabRun = {
  id: string;
  asset_id: string | null;
  source_plan_id: string | null;
  attached_plan_id: string | null;
  attached_at: string | null;
  configuration: LabConfiguration;
  asset_snapshot: LabAsset;
  status: 'queued' | 'running' | 'cancelling' | 'finished' | 'failed' | 'cancelled';
  current_operation: string;
  results: LabResult[];
  planned_checks: number;
  logs: Array<{ at: string; message: string }>;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  cleanup_status: 'pending' | 'released' | 'interrupted';
  updated_at: string;
};
export type LabCapabilities = {
  provider: string;
  worker: boolean;
  primitives: Record<LabPrimitive, boolean>;
  tlsGroups: Record<LabTlsGroup, boolean>;
  tlsCertificates: Record<LabTlsGroup, Record<typeof LAB_TLS_CERTIFICATES[number], boolean>>;
};

export function tlsCertificateFor(configuration: LabConfiguration): typeof LAB_TLS_CERTIFICATES[number] {
  const signature = configuration.primitives.find((name) => name === 'ML-DSA-65' || name === 'ML-DSA-87');
  return signature === 'ML-DSA-65' ? 'ml-dsa-65' : signature === 'ML-DSA-87' ? 'ml-dsa-87' : 'ecdsa';
}

export const LAB_LEVELS = {
  execution: { label: 'Level 1 · Cryptographic execution', scope: 'Measured operations on ephemeral lab keys and fixed test data.' },
  emulation: { label: 'Level 2 · Environment emulation', scope: 'Observed protocol behavior in an in-memory TLS harness using a generated certificate.' },
  analysis: { label: 'Level 3 · Analytical simulation', scope: 'Estimated migration considerations from recorded asset evidence.' },
} as const;

export function labReadiness(run: LabRun) {
  const proposed = run.results.filter((result) => result.level !== 'analysis' && result.profile !== LAB_BASELINE);
  const passed = proposed.filter((result) => result.status === 'passed');
  const tls = proposed.some((result) => result.level === 'emulation' && result.status === 'passed');
  const requiresTls = run.configuration.tlsGroups.length > 0 || run.asset_snapshot.tlsConfiguration.protocols.some((p) => /tls|ssl/i.test(p));
  if (run.status === 'failed' || proposed.some((result) => result.status === 'failed')) {
    return { label: 'Not ready', reason: 'Review the recorded failure and rerun the affected profile after remediation.' };
  }
  if (run.status !== 'finished' || !passed.length) {
    return { label: 'Insufficient test evidence', reason: 'A completed execution or emulation check is required to evaluate the proposal.' };
  }
  if (proposed.some((result) => result.status === 'unsupported' || result.status === 'not_tested')) {
    return { label: 'Requires remediation', reason: 'One or more selected profiles could not be exercised. Review provider and configuration requirements.' };
  }
  if ((requiresTls && !tls) || run.asset_snapshot.dependencies.length > 0 ||
    run.results.some((result) => result.issues?.some((issue) => issue.blocks))) {
    return { label: 'Ready with conditions', reason: 'Lab checks passed for the measured scope. Validate remaining protocols, dependencies or configuration gaps before a rollout.' };
  }
  return { label: 'Ready for migration planning', reason: 'All selected proposed checks passed. Confirm the actual deployment providers, certificates and peer compatibility during change planning.' };
}
