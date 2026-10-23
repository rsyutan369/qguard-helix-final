import { useCallback, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { useLiveResource, type LiveLoadState } from './use-live-resource';
import type { CertificationDashboard, EligibilityResult, QuantumTrustCertificate } from '@/types/quantum-certification';

/**
 * useQuantumCertification — live Quantum Trust Certification Engine™ state.
 *
 * The tenant-scoped certification dashboard from /api/v1/quantum-certification,
 * live over its fingerprinted stream (see use-live-resource.ts) plus Supabase
 * realtime on the certificate lifecycle tables, and exposes
 * the certificate lifecycle actions (issue / renew / suspend / revoke /
 * reinstate / download-event). Every value is evidence-driven — eligibility is
 * computed server-side from the live Quantum Readiness snapshot and the
 * self-validated enterprise report model.
 */

export type LoadState = LiveLoadState;

/** Upper bound for a certificate lifecycle action before the UI reports failure. */
const ACTION_TIMEOUT_MS = 120_000;

export const EMPTY_ELIGIBILITY: EligibilityResult = {
  eligible: false,
  issuable: false,
  evaluatedAt: '',
  hasData: false,
  requiredTotal: 0,
  requiredMet: 0,
  trustScore: 0,
  level: null,
  levelLabel: 'Not Eligible',
  checks: [],
  recommendations: [],
  policy: {
    minReadiness: 90,
    maxCriticalFindings: 0,
    maxHndlRisk: 25,
    maxResidualRisk: 25,
    minConfidence: 95,
    minPqcAdoption: 85,
    maxVulnerableComponents: 0,
    maxExpiredCertificates: 0,
    disallowedAlgorithms: [],
    validityDays: 365,
  },
};

export const EMPTY_CERTIFICATION: CertificationDashboard = {
  generatedAt: '',
  hasData: false,
  eligibility: EMPTY_ELIGIBILITY,
  certificate: null,
  certificates: [],
  history: [],
  notifications: [],
  verificationActivity: [],
  downloads: [],
  trend: [],
  renewal: { expiresAt: null, daysRemaining: null, autoRenewEligible: false },
  advisor: { headline: '', verdict: 'no_evidence', explanation: [], businessImpact: [], nextSteps: [] },
  issuer: null,
  schemaReady: true,
};

interface ActionResult {
  ok: boolean;
  message?: string;
  code?: string;
  eligibility?: EligibilityResult;
  certificate?: QuantumTrustCertificate;
}

const REALTIME_TABLES = ['quantum_trust_certificates', 'certificate_history', 'certificate_notifications'] as const;

export function useQuantumCertification() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [busy, setBusy] = useState(false);
  const live = useLiveResource<CertificationDashboard>({
    url: '/api/v1/quantum-certification',
    streamUrl: '/api/v1/quantum-certification/stream',
    event: 'certification-update',
    empty: EMPTY_CERTIFICATION,
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'qtc',
  });
  const { data, state, error, sseConnected, lastVerifiedAt, refresh } = live;

  const post = useCallback(
    async (path: string, body?: unknown): Promise<ActionResult> => {
      if (!token) return { ok: false, message: 'Not authenticated' };
      setBusy(true);
      // A lifecycle action must never leave the button spinning forever. Issue
      // is the slowest call in the engine (full evidence rebuild + ML-DSA-65
      // signing, and a cold server module graph on the first call after a
      // restart), so the budget is generous — but it is finite, and a timeout
      // surfaces a real error instead of an indefinite "Issuing…".
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), ACTION_TIMEOUT_MS);
      try {
        const response = await fetch(`/api/v1/quantum-certification${path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: body ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          return {
            ok: false,
            message: payload?.error?.message || `HTTP ${response.status}`,
            code: payload?.error?.code,
            eligibility: payload?.error?.eligibility,
          };
        }
        // The certificate is already issued and persisted at this point, so the
        // dashboard refresh must not hold the button hostage — it runs in the
        // background and the caller reports success immediately.
        void refresh();
        return { ok: true, certificate: payload.data };
      } catch (err) {
        if (controller.signal.aborted) {
          return {
            ok: false,
            message: `The server did not respond within ${Math.round(ACTION_TIMEOUT_MS / 1000)}s. The certificate may still have been issued — refresh before retrying.`,
          };
        }
        return { ok: false, message: err instanceof Error ? err.message : 'Request failed' };
      } finally {
        clearTimeout(timeout);
        setBusy(false);
      }
    },
    [token, refresh],
  );

  const issueCertificate = useCallback(
    (organization: string, organizationLogo?: string | null) => post('/issue', { organization, organizationLogo: organizationLogo || undefined }),
    [post],
  );
  const renewCertificate = useCallback((certificateId: string) => post(`/${encodeURIComponent(certificateId)}/renew`), [post]);
  const suspendCertificate = useCallback((certificateId: string, reason: string) => post(`/${encodeURIComponent(certificateId)}/suspend`, { reason }), [post]);
  const revokeCertificate = useCallback((certificateId: string, reason: string) => post(`/${encodeURIComponent(certificateId)}/revoke`, { reason }), [post]);
  const reinstateCertificate = useCallback((certificateId: string) => post(`/${encodeURIComponent(certificateId)}/reinstate`), [post]);
  const recordDownload = useCallback((certificateId: string, format: string) => post(`/${encodeURIComponent(certificateId)}/download-event`, { format }), [post]);

  const fetchPackage = useCallback(
    async (certificateId: string): Promise<Record<string, unknown> | null> => {
      if (!token) return null;
      try {
        const response = await fetch(`/api/v1/quantum-certification/${encodeURIComponent(certificateId)}/package`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) return null;
        return payload.data as Record<string, unknown>;
      } catch {
        return null;
      }
    },
    [token],
  );

  return {
    data,
    state,
    error,
    sseConnected,
    lastVerifiedAt,
    busy,
    refresh,
    issueCertificate,
    renewCertificate,
    suspendCertificate,
    revokeCertificate,
    reinstateCertificate,
    recordDownload,
    fetchPackage,
  };
}
