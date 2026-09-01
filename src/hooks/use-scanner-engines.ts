'use client';

/**
 * Live scanner engine registry + knowledge-base disclosure (§61, §85).
 *
 * Reads `/api/v1/exposure/engines` and `/api/v1/exposure/capabilities`, both
 * anonymous, so the Local and Dev panels can show what the scanner ACTUALLY is
 * — which engines are healthy right now, what version each one is, and how many
 * algorithms, rules and standards the classification is drawn from.
 *
 * §61 is the reason this is a fetch and not a constant: the UI must not report
 * an engine as healthy unless the backend says it is. A hard-coded green list
 * looks identical to a working one right up to the moment an engine breaks,
 * which is the only moment it matters.
 *
 * A failed fetch leaves `engines` empty and records the error. The panel then
 * renders nothing rather than a reassuring placeholder, because "we could not
 * ask" and "everything is fine" are different answers.
 */

import React from 'react';
import type { EngineHealthRow, KnowledgeBaseBadge } from '@/components/exposure/ScannerIntelligence';
import type { ScanMode } from '@/lib/scanner/exposure/types';

interface EnginesResponse {
  data?: {
    engines?: Array<{
      id: string;
      label: string;
      capabilityLabel?: string;
      capability?: string;
      health?: string;
      healthDetail?: string;
      version?: string;
      ruleSetVersion?: string;
      minTier?: string | null;
    }>;
  };
}

interface CapabilitiesResponse {
  data?: {
    knowledgeBase?: {
      version?: string;
      ruleSetVersion?: string;
      algorithms?: { total?: number };
      scannerRules?: { total?: number };
      standards?: { total?: number };
    };
  };
}

export interface UseScannerEnginesResult {
  engines: EngineHealthRow[];
  knowledgeBase: KnowledgeBaseBadge | null;
  loading: boolean;
  error: string | null;
}

export function useScannerEngines(mode: ScanMode): UseScannerEnginesResult {
  const [engines, setEngines] = React.useState<EngineHealthRow[]>([]);
  const [knowledgeBase, setKnowledgeBase] = React.useState<KnowledgeBaseBadge | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    const load = async () => {
      try {
        const [enginesResponse, capabilitiesResponse] = await Promise.all([
          fetch(`/api/v1/exposure/engines?mode=${encodeURIComponent(mode)}`),
          fetch('/api/v1/exposure/capabilities'),
        ]);

        if (!enginesResponse.ok) throw new Error(`Engine registry returned ${enginesResponse.status}.`);

        const enginesBody = (await enginesResponse.json()) as EnginesResponse;
        const capabilitiesBody = capabilitiesResponse.ok
          ? ((await capabilitiesResponse.json()) as CapabilitiesResponse)
          : null;

        if (cancelled) return;

        setEngines(
          (enginesBody.data?.engines ?? []).map((entry) => ({
            id: entry.id,
            label: entry.label,
            capability: entry.capabilityLabel ?? entry.capability ?? 'engine',
            /* Absent health is `unavailable`, never `healthy`. An engine the
               registry could not describe has not been shown to work. */
            health: entry.health ?? 'unavailable',
            healthDetail: entry.healthDetail ?? 'The registry returned no health for this engine.',
            version: entry.version,
            ruleSetVersion: entry.ruleSetVersion,
            minTier: entry.minTier ?? null,
          })),
        );

        const kb = capabilitiesBody?.data?.knowledgeBase;
        setKnowledgeBase(
          kb
            ? {
                version: kb.version ?? 'unknown',
                ruleSetVersion: kb.ruleSetVersion ?? 'unknown',
                algorithms: kb.algorithms?.total ?? 0,
                rules: kb.scannerRules?.total ?? 0,
                standards: kb.standards?.total ?? 0,
              }
            : null,
        );
      } catch (caught) {
        if (cancelled) return;
        setEngines([]);
        setKnowledgeBase(null);
        setError((caught as Error).message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [mode]);

  return { engines, knowledgeBase, loading, error };
}
