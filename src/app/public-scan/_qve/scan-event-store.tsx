/**
 * Quantum Visualization Engine™ — Scan Event Store + Node State Manager.
 *
 * A reducer over the {@link ScanEvent} stream. Every visual in the engine reads
 * from this one snapshot, which is what keeps the core, beams, nodes, score ring
 * and timeline from ever disagreeing with each other.
 *
 * Scoped to a React context rather than a module-level singleton on purpose: two
 * mounted engines (or a Fast-Refresh remount) must not share or leak state.
 */
'use client';

import React from 'react';
import {
  isAlertSeverity,
  maxSeverity,
  type QveNode,
  type QveNodeKey,
  type QveNodeState,
  type QveState,
  type QveTimelineEntry,
  type ScanEvent,
  type ScanEventSeverity,
} from './types';

/* ------------------------------------------------------------- node catalog - */

interface NodeBlueprint {
  key: QveNodeKey;
  title: string;
  /** Verdict shown before any evidence exists. */
  idleVerdict: string;
  idleLines: string[];
}

export const QVE_NODE_BLUEPRINTS: readonly NodeBlueprint[] = [
  {
    key: 'dns',
    title: 'DNS & CAA',
    idleVerdict: 'Standby',
    idleLines: ['Awaiting resolution', 'CAA policy unread'],
  },
  {
    key: 'tls',
    title: 'TLS & Protocols',
    idleVerdict: 'Standby',
    idleLines: ['Handshake not started', 'Protocols unprobed'],
  },
  {
    key: 'certificate',
    title: 'Certificates',
    idleVerdict: 'Standby',
    idleLines: ['Chain not collected', 'Trust unverified'],
  },
  {
    key: 'headers',
    title: 'HTTP Headers',
    idleVerdict: 'Standby',
    idleLines: ['Origin not queried', 'Controls unread'],
  },
  {
    key: 'ocsp',
    title: 'OCSP & Revocation',
    idleVerdict: 'Standby',
    idleLines: ['Stapling unknown', 'CT logs unread'],
  },
  {
    key: 'quantum',
    title: 'Quantum Readiness',
    idleVerdict: 'Standby',
    idleLines: ['Key groups unprobed', 'PQ exposure unscored'],
  },
] as const;

/** Left column / right column split, matching the reference hero. */
export const QVE_LEFT_NODES: readonly QveNodeKey[] = ['dns', 'tls', 'certificate'];
export const QVE_RIGHT_NODES: readonly QveNodeKey[] = ['headers', 'ocsp', 'quantum'];

function idleNode(blueprint: NodeBlueprint): QveNode {
  return {
    key: blueprint.key,
    title: blueprint.title,
    state: 'idle',
    verdict: blueprint.idleVerdict,
    lines: [...blueprint.idleLines],
    progress: 0,
    severity: 'none',
    updatedAt: 0,
    postQuantum: false,
  };
}

function idleNodes(): Record<QveNodeKey, QveNode> {
  return QVE_NODE_BLUEPRINTS.reduce(
    (accumulator, blueprint) => {
      accumulator[blueprint.key] = idleNode(blueprint);
      return accumulator;
    },
    {} as Record<QveNodeKey, QveNode>,
  );
}

export function initialQveState(): QveState {
  return {
    run: 'idle',
    startedAt: null,
    progress: 0,
    grade: null,
    gradeColor: null,
    score: 0,
    postQuantumScore: 0,
    quantumDetected: false,
    peakSeverity: 'none',
    nodes: idleNodes(),
    events: [],
    timeline: [],
    tick: 0,
    asset: null,
    errorMessage: null,
  };
}

/* -------------------------------------------------------------------- clock - */

function formatClock(elapsedMs: number): string {
  const total = Math.max(0, Math.round(elapsedMs / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

/* ------------------------------------------------------------------ actions - */

export type QveAction =
  | { type: 'ingest'; event: ScanEvent }
  | {
      type: 'settle';
      grade: string | null;
      gradeColor: string | null;
      score: number;
      postQuantumScore: number;
    }
  | { type: 'reset' };

/** Which node state an event's status implies. */
function nodeStateFor(status: ScanEvent['status']): QveNodeState {
  switch (status) {
    case 'running':
      return 'scanning';
    case 'pass':
      return 'pass';
    case 'warning':
      return 'warning';
    case 'critical':
      return 'critical';
    case 'failed':
      return 'failed';
    default:
      return 'scanning';
  }
}

/**
 * A node never regresses from a settled verdict back to `scanning` because a
 * later informational event was routed to it — evidence events arrive after the
 * lifecycle event that completed the node, and flickering the card back to a
 * spinner would misreport the scan.
 */
function mergeNodeState(current: QveNodeState, incoming: QveNodeState): QveNodeState {
  const settled: QveNodeState[] = ['pass', 'warning', 'critical', 'failed'];
  if (settled.includes(current) && incoming === 'scanning') return current;
  // Once a node is critical or failed, an informational pass must not hide it.
  if ((current === 'critical' || current === 'failed') && incoming === 'pass') return current;
  if (current === 'warning' && incoming === 'pass') return current;
  return incoming;
}

const TIMELINE_MAX = 40;
const EVENTS_MAX = 160;

/** Events that carry no node verdict and only belong on the timeline. */
const LIFECYCLE_TYPES = new Set<ScanEvent['type']>(['SCAN_STARTED', 'SCAN_COMPLETED', 'ERROR']);

export function qveReducer(state: QveState, action: QveAction): QveState {
  switch (action.type) {
    case 'reset':
      return initialQveState();

    case 'settle':
      return {
        ...state,
        grade: action.grade,
        gradeColor: action.gradeColor,
        score: action.score,
        postQuantumScore: action.postQuantumScore,
      };

    case 'ingest': {
      const event = action.event;

      // SCAN_STARTED resets the engine so a second scan cannot inherit the
      // first one's verdicts.
      if (event.type === 'SCAN_STARTED') {
        return {
          ...initialQveState(),
          run: 'scanning',
          startedAt: event.timestamp,
          asset: event.asset ?? null,
          events: [event],
          tick: 1,
          timeline: [
            {
              id: event.id,
              clock: '00:00',
              label: 'Assessment started',
              status: 'running',
              severity: 'info',
              detail: event.asset ?? undefined,
            },
          ],
        };
      }

      const startedAt = state.startedAt ?? event.timestamp;
      const nodes = { ...state.nodes };

      if (event.category !== 'scan' && !LIFECYCLE_TYPES.has(event.type)) {
        const current = nodes[event.category];
        if (current) {
          const incomingState = nodeStateFor(event.status);
          const nextLines = event.finding
            ? [event.finding, ...current.lines.filter((line) => line !== event.finding)].slice(0, 2)
            : current.lines;
          nodes[event.category] = {
            ...current,
            state: mergeNodeState(current.state, incomingState),
            verdict: typeof event.details?.verdict === 'string' ? event.details.verdict : current.verdict,
            lines:
              current.state === 'idle' && event.status === 'running'
                ? [event.finding ?? 'Probing…']
                : nextLines,
            progress:
              typeof event.details?.nodeProgress === 'number'
                ? Math.max(current.progress, event.details.nodeProgress)
                : event.status === 'running'
                  ? Math.max(current.progress, 35)
                  : 100,
            severity: maxSeverity(current.severity, event.severity),
            updatedAt: event.timestamp,
            postQuantum: current.postQuantum || event.details?.postQuantum === true,
          };
        }
      }

      const timelineEntry: QveTimelineEntry | null = event.details?.timeline === false
        ? null
        : {
            id: event.id,
            clock: formatClock(event.timestamp - startedAt),
            label: (typeof event.details?.timelineLabel === 'string'
              ? event.details.timelineLabel
              : event.finding) ?? event.type.replace(/_/g, ' ').toLowerCase(),
            status: event.status,
            severity: event.severity,
            detail: typeof event.details?.timelineDetail === 'string' ? event.details.timelineDetail : undefined,
          };

      const run: QveState['run'] =
        event.type === 'SCAN_COMPLETED'
          ? 'complete'
          : event.type === 'ERROR'
            ? 'error'
            : state.run === 'idle'
              ? 'scanning'
              : state.run;

      return {
        ...state,
        run,
        startedAt,
        progress: Math.max(state.progress, Math.min(100, Math.round(event.progress))),
        quantumDetected: state.quantumDetected || event.details?.postQuantum === true,
        peakSeverity: maxSeverity(state.peakSeverity, event.severity),
        nodes,
        events: [...state.events, event].slice(-EVENTS_MAX),
        timeline: timelineEntry ? [...state.timeline, timelineEntry].slice(-TIMELINE_MAX) : state.timeline,
        tick: state.tick + 1,
        asset: event.asset ?? state.asset,
        errorMessage: event.type === 'ERROR' ? (event.finding ?? 'Assessment failed') : state.errorMessage,
      };
    }

    default:
      return state;
  }
}

/* ------------------------------------------------------------------ context - */

interface QveStore {
  state: QveState;
  dispatch: React.Dispatch<QveAction>;
}

const QveContext = React.createContext<QveStore | null>(null);

export function QveProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = React.useReducer(qveReducer, undefined, initialQveState);
  const value = React.useMemo(() => ({ state, dispatch }), [state, dispatch]);
  return <QveContext.Provider value={value}>{children}</QveContext.Provider>;
}

export function useQve(): QveStore {
  const store = React.useContext(QveContext);
  if (!store) throw new Error('useQve must be used inside <QveProvider>');
  return store;
}

/** Narrow selector so leaf visuals do not re-render on unrelated state churn. */
export function useQveState(): QveState {
  return useQve().state;
}

/**
 * The most recent event whose severity warrants the core's alert treatment.
 * Returns null once a newer non-alert event supersedes it, so the alert does
 * not stick after the scan moves on.
 */
export function useLatestAlert(): ScanEvent | null {
  const { events } = useQveState();
  return React.useMemo(() => {
    for (let index = events.length - 1; index >= 0; index -= 1) {
      const event = events[index];
      if (isAlertSeverity(event.severity)) return event;
    }
    return null;
  }, [events]);
}

export function severityOfNodes(nodes: Record<QveNodeKey, QveNode>): ScanEventSeverity {
  return Object.values(nodes).reduce<ScanEventSeverity>(
    (worst, node) => maxSeverity(worst, node.severity),
    'none',
  );
}
