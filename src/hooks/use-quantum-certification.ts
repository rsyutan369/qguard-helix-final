import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type { CertificationDashboard, EligibilityResult, QuantumTrustCertificate } from '@/types/quantum-certification';

/**
 * useQuantumCertification — live Quantum Trust Certification Engine™ state.
 *
 * Fetches the tenant-scoped certification dashboard from
 * /api/v1/quantum-certification, keeps it live via a header-authenticated SSE
 * stream + Supabase realtime on the certificate lifecycle tables, and exposes
 * the certificate lifecycle actions (issue / renew / suspend / revoke /
 * reinstate / download-event). Every value is evidence-driven — eligibility is
 * computed server-side from the live Quantum Readiness snapshot and the
 * self-validated enterprise report model.
 */

export type LoadState = 'loading' | 'success' | 'error';

export const EMPTY_ELIGIBILITY: EligibilityResult = {
  eligible: false,
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

const REALTIME_TABLES = ['quantum_trust_certificates', 'certificate_history', 'certificate_notifications'];

export function useQuantumCertification() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [data, setData] = useState<CertificationDashboard>(EMPTY_CERTIFICATION);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const apply = useCallback((next: Partial<CertificationDashboard> | null) => {
    setData({ ...EMPTY_CERTIFICATION, ...(next || {}) });
  }, []);

  const refresh = useCallback(async () => {
    if (!token) {
      apply(EMPTY_CERTIFICATION);
      setState('success');
      return;
    }
    setState((current) => (current === 'success' ? current : 'loading'));
    try {
      const response = await fetch('/api/v1/quantum-certification', {
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      apply(payload.data || {});
      setState('success');
      setError(null);
    } catch (err) {
      console.error('Quantum certification load failed:', err);
      setError(err instanceof Error ? err.message : 'Unable to load certification engine');
      setState('error');
    }
  }, [token, apply]);

  const queueRefresh = useCallback(() => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = null;
      void refresh();
    }, 400);
  }, [refresh]);

  useEffect(() => () => { if (refreshTimer.current) clearTimeout(refreshTimer.current); }, []);

  useEffect(() => {
    if (!token || !user) {
      apply(EMPTY_CERTIFICATION);
      setState('success');
      return;
    }
    void refresh();
  }, [token, user, refresh, apply]);

  // Header-authenticated SSE (token never in URL — mirrors useHarvestNow).
  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    let retry: ReturnType<typeof setTimeout> | undefined;
    let cancelled = false;

    const parseFrame = (frame: string) => {
      let eventName = 'message';
      const dataLines: string[] = [];
      for (const line of frame.split('\n')) {
        if (line.startsWith('event:')) eventName = line.slice(6).trim();
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''));
      }
      if (eventName === 'certification-update' && dataLines.length) {
        try {
          apply(JSON.parse(dataLines.join('\n')));
          setState('success');
          setError(null);
        } catch {
          /* ignore malformed frame */
        }
      }
    };

    const connect = async () => {
      try {
        const response = await fetch('/api/v1/quantum-certification/stream', {
          headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error(`SSE ${response.status}`);
        setSseConnected(true);
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let boundary = buffer.indexOf('\n\n');
          while (boundary !== -1) {
            parseFrame(buffer.slice(0, boundary));
            buffer = buffer.slice(boundary + 2);
            boundary = buffer.indexOf('\n\n');
          }
        }
        throw new Error('stream ended');
      } catch {
        if (cancelled || controller.signal.aborted) return;
        setSseConnected(false);
        if (retry) clearTimeout(retry);
        retry = setTimeout(() => void connect(), 10000);
      }
    };

    void connect();
    return () => {
      cancelled = true;
      controller.abort();
      if (retry) clearTimeout(retry);
      setSseConnected(false);
    };
  }, [token, apply]);

  // Supabase realtime — refresh on any certificate lifecycle mutation.
  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`qtc-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
        .subscribe(),
    );
    return () => { for (const channel of channels) supabase.removeChannel(channel); };
  }, [user, queueRefresh]);

  const post = useCallback(
    async (path: string, body?: unknown): Promise<ActionResult> => {
      if (!token) return { ok: false, message: 'Not authenticated' };
      setBusy(true);
      try {
        const response = await fetch(`/api/v1/quantum-certification${path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: body ? JSON.stringify(body) : undefined,
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
        await refresh();
        return { ok: true, certificate: payload.data };
      } catch (err) {
        return { ok: false, message: err instanceof Error ? err.message : 'Request failed' };
      } finally {
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
