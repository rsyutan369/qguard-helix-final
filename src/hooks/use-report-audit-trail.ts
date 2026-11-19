'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';

/**
 * Report captures are written by the generation API. Advisory activity
 * continues to be recorded in the authenticated audit log.
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
  const owner = session?.user.id === user?.id ? user?.id : undefined;
  const activeScope = owner && token ? `${owner}:${type}` : undefined;
  const scopeRef = useRef(activeScope);
  scopeRef.current = activeScope;

  const load = useCallback(async () => {
    if (!token || !activeScope) return;
    try {
      const response = await fetch(`/api/v1/reports/history?type=${type}`, { headers: { Authorization: `Bearer ${token}` } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      if (scopeRef.current !== activeScope) return;
      setEntries(Array.isArray(payload.data) ? payload.data : []);
      setError(null);
    } catch (err) {
      if (scopeRef.current === activeScope) setError(err instanceof Error ? err.message : 'Audit trail unavailable');
    } finally {
      if (scopeRef.current === activeScope) setLoaded(true);
    }
  }, [token, type, activeScope]);

  useEffect(() => {
    setEntries([]);
    setLoaded(false);
    setError(null);
    void load();
    // Reload when the signed-in tenant changes (or first gets a token), not on
    // every hourly token rotation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeScope]);

  const record = useCallback(
    async (body: Record<string, unknown>): Promise<ReportAuditEntry | null> => {
      if (!token || !activeScope || type !== 'advisory') return null;
      try {
        const response = await fetch('/api/v1/reports/advisories', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(body),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (scopeRef.current !== activeScope) return null;
        const entry = payload.data as ReportAuditEntry;
        setEntries((current) => [entry, ...current].slice(0, 60));
        setError(null);
        return entry;
      } catch (err) {
        if (scopeRef.current === activeScope) setError(err instanceof Error ? err.message : 'Audit record failed');
        return null;
      }
    },
    [token, type, activeScope],
  );

  return { entries, loaded, error, record, reload: load };
}
