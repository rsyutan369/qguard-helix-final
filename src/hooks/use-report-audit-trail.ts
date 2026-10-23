'use client';

import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';

/**
 * Tenant-scoped report / executive-advisory audit trail, persisted to
 * `audit_logs` through /api/v1/reports/history and /api/v1/reports/advisories.
 * Replaces the browser-local history the Report Center and AI Executive
 * Advisor kept (shared by every account on a browser, lost on another device).
 */

export interface ReportAuditEntry {
  id: string;
  action: string;
  createdAt: string;
  reportId?: string;
  kind?: string;
  format?: string;
  title?: string;
  version?: string;
  scope?: string;
  integrityHash?: string;
  generatedAt?: string;
  generatedBy?: string;
  advisoryId?: string;
  readiness?: number | null;
  risk?: number | null;
  validation?: 'PASS' | 'FAIL';
  assessmentAt?: string | null;
  actor?: string;
}

export function useReportAuditTrail(type: 'report' | 'advisory') {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [entries, setEntries] = useState<ReportAuditEntry[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const response = await fetch(`/api/v1/reports/history?type=${type}`, { headers: { Authorization: `Bearer ${token}` } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      setEntries(Array.isArray(payload.data) ? payload.data : []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Audit trail unavailable');
    } finally {
      setLoaded(true);
    }
  }, [token, type]);

  const hasToken = Boolean(token);
  useEffect(() => {
    setEntries([]);
    setLoaded(false);
    void load();
    // Reload when the signed-in tenant changes (or first gets a token), not on
    // every hourly token rotation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id, type, hasToken]);

  const record = useCallback(
    async (body: Record<string, unknown>): Promise<ReportAuditEntry | null> => {
      if (!token) return null;
      const path = type === 'report' ? '/api/v1/reports/history' : '/api/v1/reports/advisories';
      try {
        const response = await fetch(path, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(body),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        const entry = payload.data as ReportAuditEntry;
        setEntries((current) => [entry, ...current].slice(0, 60));
        setError(null);
        return entry;
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Audit record failed');
        return null;
      }
    },
    [token, type],
  );

  return { entries, loaded, error, record, reload: load };
}
