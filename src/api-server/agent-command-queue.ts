/**
 * The agent command channel — one implementation, three callers.
 *
 * Commands live in `scanner_agents.metadata.commandQueue` (a bounded queue on
 * the agent's own row) rather than a parallel jobs table, so tenant isolation is
 * structural: an agent can only ever read the queue hanging off its own record.
 *
 * This module used to be private to `agent-installer.ts`. Migration Snapshot
 * Management needs the same channel to dispatch a rollback, and a second copy of
 * "append to metadata.commandQueue" would be a second place for the bound, the
 * de-duplication rule and the revoked-agent refusal to drift apart. It is
 * therefore lifted here and both routers import it.
 *
 * Lifecycle, unchanged:
 *   queued → delivered (GET /agent/policy hands it out)
 *          → running   (agent acks)
 *          → completed | failed  (agent acks; moves to commandHistory)
 */

import { randomUUID } from 'node:crypto'
import type { SupabaseClient } from '@supabase/supabase-js'
import { updateTenantRow } from './tenant-row-update'
import {
  MAX_COMMAND_HISTORY,
  MAX_QUEUED_COMMANDS,
  type AgentCommand,
  type AgentCommandType,
} from '@/lib/agent-installer/agent-release'

export function isMissingAgentTable(error: any): boolean {
  const text = `${error?.code || ''} ${error?.message || ''}`.toLowerCase()
  return (
    text.includes('42p01') ||
    text.includes('pgrst205') ||
    text.includes('does not exist') ||
    text.includes('could not find the table')
  )
}

export function commandQueue(agent: any): AgentCommand[] {
  const raw = agent?.metadata?.commandQueue
  return Array.isArray(raw) ? (raw as AgentCommand[]) : []
}

export function commandHistory(agent: any): AgentCommand[] {
  const raw = agent?.metadata?.commandHistory
  return Array.isArray(raw) ? (raw as AgentCommand[]) : []
}

/** A command is "outstanding" while it has not reached a terminal state. */
export function isPendingCommand(item: AgentCommand | undefined | null): boolean {
  return item?.status === 'queued' || item?.status === 'delivered' || item?.status === 'running'
}

export async function persistCommandState(
  client: SupabaseClient | null,
  agentId: string,
  agent: any,
  queue: AgentCommand[],
  history: AgentCommand[],
): Promise<void> {
  if (!client) {
    agent.metadata = { ...agent.metadata, commandQueue: queue.slice(0, MAX_QUEUED_COMMANDS), commandHistory: history.slice(0, MAX_COMMAND_HISTORY) }
    return
  }
  await updateTenantRow(client, 'scanner_agents', agent.user_id, agentId, (fresh) => ({
    metadata: { ...fresh.metadata, commandQueue: queue.slice(0, MAX_QUEUED_COMMANDS), commandHistory: history.slice(0, MAX_COMMAND_HISTORY) },
  }))
}

/*
 * A single shape rather than a discriminated union: this project compiles with
 * `strict` off, where narrowing a union on a boolean literal discriminant is
 * not reliable, and a refusal that fails to typecheck at the call site is a
 * refusal someone will be tempted to cast away.
 */
export interface EnqueueOutcome {
  ok: boolean
  command: AgentCommand | null
  deduplicated: boolean
  status: number
  code: string
  message: string
}

function refused(status: number, code: string, message: string): EnqueueOutcome {
  return { ok: false, command: null, deduplicated: false, status, code, message }
}

export interface EnqueueOptions {
  /** Payload handed verbatim to the agent. */
  payload?: Record<string, unknown>
  /** User id recorded on the command for audit. */
  requestedBy: string
  /**
   * How to decide an identical command is already pending.
   *
   * Default: one pending command of a given TYPE is enough — re-queuing "scan"
   * five times would just make the agent scan five times in a row. A rollback,
   * by contrast, is per-snapshot: two rollbacks of two different snapshots are
   * two distinct pieces of work, so those callers pass a discriminator.
   */
  dedupeKey?: (command: AgentCommand) => string | null
}

/**
 * Append a command to an agent's queue.
 *
 * Refuses a revoked agent and a full queue; returns the existing command rather
 * than a duplicate when one is already pending. It does NOT check role or
 * entitlement — the caller does, because what counts as an authorised command
 * differs by route (see `MUTATING_COMMAND_TYPES`).
 */
export async function enqueueAgentCommand(
  client: SupabaseClient | null,
  agent: any,
  type: AgentCommandType,
  options: EnqueueOptions,
): Promise<EnqueueOutcome> {
  // Re-evaluate deduplication and queue capacity against the version we commit,
  // so simultaneous requests cannot enqueue twice or overwrite another command.
  if (client && agent) {
    let outcome: EnqueueOutcome = refused(500, 'COMMAND_QUEUE_FAILED', 'Command could not be queued')
    try {
      await updateTenantRow(client, 'scanner_agents', agent.user_id, agent.id, (fresh) => {
        if (fresh.revoked_at || fresh.status === 'revoked') { outcome = refused(409, 'AGENT_REVOKED', 'Revoked agents cannot accept commands'); return null }
        const queue = commandQueue(fresh)
        const keyOf = options.dedupeKey || ((item: AgentCommand) => item.type)
        const wanted = keyOf({ type, payload: options.payload } as AgentCommand)
        const duplicate = queue.find((item) => isPendingCommand(item) && item.type === type && keyOf(item) === wanted)
        if (duplicate) { outcome = { ok: true, command: duplicate, deduplicated: true, status: 200, code: 'OK', message: '' }; return null }
        if (queue.filter(isPendingCommand).length >= MAX_QUEUED_COMMANDS) { outcome = refused(429, 'COMMAND_QUEUE_FULL', 'This agent already has the maximum number of pending commands'); return null }
        const command: AgentCommand = { id: randomUUID(), type, queuedAt: new Date().toISOString(), requestedBy: options.requestedBy, payload: options.payload || {}, status: 'queued', deliveredAt: null, completedAt: null, result: null, error: null }
        outcome = { ok: true, command, deduplicated: false, status: 200, code: 'OK', message: '' }
        return { metadata: { ...fresh.metadata, commandQueue: [command, ...queue], commandHistory: commandHistory(fresh) } }
      })
      return outcome
    } catch (error) { return refused(503, 'COMMAND_QUEUE_FAILED', (error as Error).message) }
  }
  if (!agent) {
    return refused(404, 'AGENT_NOT_FOUND', 'Agent not found for this tenant')
  }
  if (agent.revoked_at || agent.status === 'revoked') {
    return refused(409, 'AGENT_REVOKED', 'Revoked agents cannot accept commands')
  }

  const queue = commandQueue(agent)
  if (queue.filter(isPendingCommand).length >= MAX_QUEUED_COMMANDS) {
    return refused(429, 'COMMAND_QUEUE_FULL', 'This agent already has the maximum number of pending commands')
  }

  const keyOf = options.dedupeKey || ((command: AgentCommand) => command.type)
  const wanted = keyOf({ type, payload: options.payload } as AgentCommand)
  const duplicate = queue.find((item) => isPendingCommand(item) && item.type === type && keyOf(item) === wanted)
  if (duplicate) return { ok: true, command: duplicate, deduplicated: true, status: 200, code: 'OK', message: '' }

  const command: AgentCommand = {
    id: randomUUID(),
    type,
    queuedAt: new Date().toISOString(),
    requestedBy: options.requestedBy,
    payload: options.payload || {},
    status: 'queued',
    deliveredAt: null,
    completedAt: null,
    result: null,
    error: null,
  }

  try {
    await persistCommandState(client, agent.id, agent, [command, ...queue], commandHistory(agent))
  } catch (error) {
    return refused(500, 'COMMAND_QUEUE_FAILED', (error as Error).message)
  }
  return { ok: true, command, deduplicated: false, status: 200, code: 'OK', message: '' }
}
