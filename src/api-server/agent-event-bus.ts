/**
 * Qguard Helix — agent realtime event bus.
 *
 * A tiny in-process publish/subscribe ring shared by the two routers that
 * observe agent lifecycle transitions (agent-scanner owns heartbeats, evidence
 * and remediation; agent-installer owns deployment, commands and the SSE
 * stream). Keeping the bus in its own module means neither router has to import
 * the other, so there is no import cycle.
 *
 * The ring buffer backs `Last-Event-ID` replay (spec §28): a browser that
 * reconnects resumes from the last id it saw instead of silently missing
 * transitions. It is a delivery optimisation only — every consumer also holds a
 * snapshot source of truth, so losing the buffer (process restart) degrades to
 * "the next snapshot corrects it", never to wrong state.
 */

import type { AgentEventName } from '@/lib/agent-installer/agent-release'

export interface AgentBusEvent {
  id: number
  userId: string
  name: AgentEventName
  agentId: string | null
  payload: Record<string, unknown>
  at: string
}

const EVENT_BUFFER_SIZE = 500

// Survive Vite dev-server module reloads: a fresh module instance would otherwise
// orphan every live SSE subscriber registered against the previous one.
const globalScope = globalThis as unknown as {
  __qguard_agent_event_bus__?: {
    buffer: AgentBusEvent[]
    sequence: number
    subscribers: Set<{ userId: string; flush: () => void }>
  }
}

const bus =
  globalScope.__qguard_agent_event_bus__ ||
  (globalScope.__qguard_agent_event_bus__ = { buffer: [], sequence: 0, subscribers: new Set() })

export function publishAgentEvent(
  userId: string,
  name: AgentEventName,
  agentId: string | null,
  payload: Record<string, unknown> = {},
) {
  if (!userId) return
  bus.sequence += 1
  bus.buffer.push({ id: bus.sequence, userId, name, agentId, payload, at: new Date().toISOString() })
  if (bus.buffer.length > EVENT_BUFFER_SIZE) {
    bus.buffer.splice(0, bus.buffer.length - EVENT_BUFFER_SIZE)
  }
  for (const subscriber of bus.subscribers) {
    if (subscriber.userId !== userId) continue
    try {
      subscriber.flush()
    } catch {
      // A broken pipe on one subscriber must not stop delivery to the others.
    }
  }
}

/** Events newer than `cursor` for this tenant, in order. */
export function eventsSince(userId: string, cursor: number): AgentBusEvent[] {
  return bus.buffer.filter((event) => event.id > cursor && event.userId === userId)
}

export function subscribe(userId: string, flush: () => void) {
  const subscriber = { userId, flush }
  bus.subscribers.add(subscriber)
  return () => bus.subscribers.delete(subscriber)
}

export function busStats() {
  return { buffered: bus.buffer.length, sequence: bus.sequence, subscribers: bus.subscribers.size }
}
