import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import type { MigrationWorkflowState } from '@/types/migration-workflow';

/**
 * useMigrationWorkflow — platform-wide Post-Quantum Migration Workflow™ state.
 *
 * Backs the WorkflowRail embedded across the workflow dashboards. The server
 * caches the computed state per user (30s TTL), so the rail stays cheap even
 * when many pages mount it; the hook refreshes every 60s to track progress.
 */

export type WorkflowLoadState = 'loading' | 'success' | 'error';

const REFRESH_MS = 60_000;

export function useMigrationWorkflow() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [workflow, setWorkflow] = useState<MigrationWorkflowState | null>(null);
  const [state, setState] = useState<WorkflowLoadState>('loading');

  const refresh = useCallback(async () => {
    if (!token) {
      setWorkflow(null);
      setState('success');
      return;
    }
    try {
      const response = await fetch('/api/v1/migration-workflow', {
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      setWorkflow(payload.data || null);
      setState('success');
    } catch {
      // The rail is an auxiliary overlay — it hides on error rather than
      // breaking the page that embeds it.
      setState('error');
    }
  }, [token]);

  useEffect(() => {
    void refresh();
    const interval = setInterval(() => void refresh(), REFRESH_MS);
    return () => clearInterval(interval);
  }, [refresh]);

  return { workflow, state, refresh };
}
