// Sophia — AI Gateway (/api/v1/copilot).
//
// The single entry point for the AI Security Copilot™:
//   auth → tenant/RBAC context → rate limiting → prompt sanitation → the
//   multi-agent engine → streamed (SSE) or JSON structured answers, plus
//   conversation persistence, proactive insights, suggestions and context.
//
// Tenant isolation: every request derives a ToolContext from the caller's own
// RLS auth client + user id — tools cannot see other tenants by construction.
// Conversations persist to copilot_* tables (RLS: auth.uid() = user_id, see
// supabase/sophia-copilot-schema.sql) with a bounded in-memory fallback until
// the schema is applied, so the copilot works out of the box.

import { Router, type NextFunction, type Request, type Response } from 'express'
import { createAuthClient, getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { isOwnerEmail } from '@/lib/admin-access'
import { resolveEntitlement } from './subscription-guard'
import {
  ROLE_CAPABILITIES,
  ROLE_LABELS,
  normalizeRole,
  sanitizePrompt,
  suggestionsForPage,
} from './copilot-knowledge'
import { setToolAuditSink, type ToolContext } from './copilot-tools'
import { buildInsights, runCopilotQuery, type PriorFigures, type QueryOutcome } from './copilot-engine'
import { EMPTY_MEMORY, type CopilotAnswer, type CopilotContext, type CopilotConversation, type CopilotMemoryState, type CopilotMessage, type CopilotRole, type CopilotStreamEvent } from '@/types/copilot'

const router = Router()

const CONVERSATIONS_TABLE = 'copilot_conversations'
const MESSAGES_TABLE = 'copilot_messages'

/* ------------------------------------------------------------------ */
/* Auth + tenant context                                               */
/* ------------------------------------------------------------------ */

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
  copilotCtx?: ToolContext
  copilotRole?: CopilotRole
  copilotTier?: string
}

function str(v: unknown): string { return typeof v === 'string' ? v : v == null ? '' : String(v) }
function rec(v: unknown): Record<string, unknown> { return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {} }

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const queryToken = typeof req.query.token === 'string' ? req.query.token : null
  const token = getToken(req) || queryToken
  if (!token) {
    res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    return
  }
  const user = await getServerUser(token)
  if (!user) {
    res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
    return
  }
  const client = createAuthClient(token)
  if (!client) {
    res.status(503).json({ error: { code: 'CONFIG_ERROR', message: 'Supabase is not configured' } })
    return
  }

  const authed = req as AuthedRequest
  authed.user = user
  authed.token = token

  // Role: owner bypass, else profiles.role; no role / unknown role = read-only
  // security_analyst (DEFAULT_COPILOT_ROLE). Elevated roles are assigned by the owner.
  const owner = isOwnerEmail(user.email)
  let profileRole: unknown = null
  try {
    const { data } = await client.from('profiles').select('role, tier').eq('id', user.id).maybeSingle()
    profileRole = data?.role ?? null
  } catch { /* role stays default */ }
  const role = normalizeRole(profileRole, owner)

  let tier = 'none'
  try {
    const entitlement = await resolveEntitlement(user.id, user.email, token)
    tier = entitlement.tier
  } catch { /* tier display only — API gating happens in subscriptionGateway */ }

  authed.copilotRole = role
  authed.copilotTier = tier
  authed.copilotCtx = {
    token,
    userId: user.id,
    email: user.email || '',
    role,
    tier,
    client,
  }
  next()
}

router.use(requireAuth)

/* ------------------------------------------------------------------ */
/* Rate limiting — per-tenant token bucket                             */
/* ------------------------------------------------------------------ */

const RATE_WINDOW_MS = 5 * 60 * 1000
const RATE_MAX_PER_WINDOW = 40
const BURST_WINDOW_MS = 20 * 1000
const BURST_MAX = 8

interface RateState { window: number[]; burst: number[] }
const rateState = new Map<string, RateState>()

export function checkChatRateLimit(userId: string, now = Date.now()): { allowed: boolean; retryAfterSec: number } {
  const state = rateState.get(userId) || { window: [], burst: [] }
  state.window = state.window.filter((t) => now - t < RATE_WINDOW_MS)
  state.burst = state.burst.filter((t) => now - t < BURST_WINDOW_MS)
  if (state.burst.length >= BURST_MAX) {
    rateState.set(userId, state)
    return { allowed: false, retryAfterSec: Math.ceil((BURST_WINDOW_MS - (now - state.burst[0])) / 1000) || 1 }
  }
  if (state.window.length >= RATE_MAX_PER_WINDOW) {
    rateState.set(userId, state)
    return { allowed: false, retryAfterSec: Math.ceil((RATE_WINDOW_MS - (now - state.window[0])) / 1000) || 1 }
  }
  state.window.push(now)
  state.burst.push(now)
  rateState.set(userId, state)
  if (rateState.size > 2000) {
    for (const [key, value] of rateState) {
      if (!value.window.length) rateState.delete(key)
    }
  }
  return { allowed: true, retryAfterSec: 0 }
}

/* ------------------------------------------------------------------ */
/* Audit logging                                                       */
/* ------------------------------------------------------------------ */

async function recordAudit(userId: string, action: string, details: Record<string, unknown>) {
  try {
    const db = getServiceClient()
    if (!db) return
    await db.from('audit_logs').insert({ user_id: userId, action, entity_type: 'copilot', details })
  } catch { /* audit must never break the request */ }
}

// Tool-level audit events (prepared actions, RBAC denials) flow through here.
setToolAuditSink((entry) => { void recordAudit(entry.userId, entry.action, entry.detail) })

/* ------------------------------------------------------------------ */
/* Conversation persistence (Supabase) with in-memory fallback         */
/* ------------------------------------------------------------------ */

interface MemoryConversationStore {
  conversations: Map<string, CopilotConversation>
  messages: Map<string, CopilotMessage[]>
}
const memoryStores = new Map<string, MemoryConversationStore>()
let schemaMissing = false

function memoryStoreFor(userId: string): MemoryConversationStore {
  let store = memoryStores.get(userId)
  if (!store) {
    store = { conversations: new Map(), messages: new Map() }
    memoryStores.set(userId, store)
    if (memoryStores.size > 500) {
      const firstKey = memoryStores.keys().next().value
      if (firstKey) memoryStores.delete(firstKey)
    }
  }
  return store
}

function isMissingTable(error: unknown): boolean {
  const m = str((error as { message?: string })?.message || error)
  return /relation .* does not exist|Could not find the table|schema cache/i.test(m)
}

function mapConversation(row: Record<string, unknown>): CopilotConversation {
  return {
    id: str(row.id),
    title: str(row.title) || 'Conversation',
    pinned: row.pinned === true,
    messageCount: Number(row.message_count) || 0,
    createdAt: str(row.created_at),
    updatedAt: str(row.updated_at),
  }
}

function mapMessage(row: Record<string, unknown>): CopilotMessage {
  return {
    id: str(row.id),
    conversationId: str(row.conversation_id),
    role: str(row.role) === 'assistant' ? 'assistant' : 'user',
    content: str(row.content),
    answer: row.answer ? (row.answer as CopilotAnswer) : undefined,
    createdAt: str(row.created_at),
  }
}

let fallbackIdCounter = 0
function fallbackId(prefix: string): string {
  fallbackIdCounter += 1
  return `${prefix}-${Date.now().toString(36)}-${fallbackIdCounter.toString(36)}`
}

async function listConversations(ctx: ToolContext): Promise<CopilotConversation[]> {
  if (!schemaMissing) {
    try {
      const { data, error } = await ctx.client
        .from(CONVERSATIONS_TABLE)
        .select('id, title, pinned, message_count, created_at, updated_at')
        .eq('user_id', ctx.userId)
        .order('updated_at', { ascending: false })
        .limit(60)
      if (error) { if (isMissingTable(error)) schemaMissing = true; else return [] }
      else return (data || []).map(mapConversation)
    } catch { /* fall through to memory */ }
  }
  const store = memoryStoreFor(ctx.userId)
  return [...store.conversations.values()].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
}

async function createConversation(ctx: ToolContext, title: string): Promise<CopilotConversation> {
  const now = new Date().toISOString()
  if (!schemaMissing) {
    try {
      const { data, error } = await ctx.client
        .from(CONVERSATIONS_TABLE)
        .insert({ user_id: ctx.userId, title: title.slice(0, 140) || 'Conversation', pinned: false, message_count: 0 })
        .select('id, title, pinned, message_count, created_at, updated_at')
        .single()
      if (error) { if (isMissingTable(error)) schemaMissing = true; else throw error }
      else return mapConversation(data)
    } catch (error) {
      if (!schemaMissing && !isMissingTable(error)) console.warn('[copilot] createConversation fell back to memory:', (error as Error)?.message)
      schemaMissing = schemaMissing || isMissingTable(error)
    }
  }
  const conversation: CopilotConversation = { id: fallbackId('conv'), title: title.slice(0, 140) || 'Conversation', pinned: false, messageCount: 0, createdAt: now, updatedAt: now }
  const store = memoryStoreFor(ctx.userId)
  store.conversations.set(conversation.id, conversation)
  store.messages.set(conversation.id, [])
  if (store.conversations.size > 25) {
    const oldest = [...store.conversations.values()].sort((a, b) => a.updatedAt.localeCompare(b.updatedAt))[0]
    if (oldest && !oldest.pinned) { store.conversations.delete(oldest.id); store.messages.delete(oldest.id) }
  }
  return conversation
}

async function getConversation(ctx: ToolContext, id: string): Promise<CopilotConversation | null> {
  if (!schemaMissing) {
    try {
      const { data, error } = await ctx.client
        .from(CONVERSATIONS_TABLE)
        .select('id, title, pinned, message_count, created_at, updated_at')
        .eq('user_id', ctx.userId)
        .eq('id', id)
        .maybeSingle()
      if (error) { if (isMissingTable(error)) schemaMissing = true }
      else if (data) return mapConversation(data)
      else if (!schemaMissing) return null
    } catch { /* fall through */ }
  }
  return memoryStoreFor(ctx.userId).conversations.get(id) || null
}

async function listMessages(ctx: ToolContext, conversationId: string): Promise<CopilotMessage[]> {
  if (!schemaMissing) {
    try {
      const { data, error } = await ctx.client
        .from(MESSAGES_TABLE)
        .select('id, conversation_id, role, content, answer, created_at')
        .eq('user_id', ctx.userId)
        .eq('conversation_id', conversationId)
        .order('created_at', { ascending: true })
        .limit(200)
      if (error) { if (isMissingTable(error)) schemaMissing = true }
      else return (data || []).map(mapMessage)
    } catch { /* fall through */ }
  }
  return memoryStoreFor(ctx.userId).messages.get(conversationId) || []
}

async function appendMessage(ctx: ToolContext, conversationId: string, role: 'user' | 'assistant', content: string, answer?: CopilotAnswer): Promise<CopilotMessage> {
  const now = new Date().toISOString()
  if (!schemaMissing) {
    try {
      const { data, error } = await ctx.client
        .from(MESSAGES_TABLE)
        .insert({ user_id: ctx.userId, conversation_id: conversationId, role, content: content.slice(0, 8000), answer: answer ?? null })
        .select('id, conversation_id, role, content, answer, created_at')
        .single()
      if (error) { if (isMissingTable(error)) schemaMissing = true; else throw error }
      else {
        await ctx.client
          .from(CONVERSATIONS_TABLE)
          .update({ updated_at: now, message_count: (await listMessages(ctx, conversationId)).length })
          .eq('user_id', ctx.userId)
          .eq('id', conversationId)
        return mapMessage(data)
      }
    } catch (error) {
      schemaMissing = schemaMissing || isMissingTable(error)
    }
  }
  const message: CopilotMessage = { id: fallbackId('msg'), conversationId, role, content: content.slice(0, 8000), answer, createdAt: now }
  const store = memoryStoreFor(ctx.userId)
  const list = store.messages.get(conversationId) || []
  list.push(message)
  if (list.length > 200) list.splice(0, list.length - 200)
  store.messages.set(conversationId, list)
  const conversation = store.conversations.get(conversationId)
  if (conversation) {
    conversation.updatedAt = now
    conversation.messageCount = list.length
  }
  return message
}

/*
 * Longitudinal memory — the figures Sophia previously reported to THIS tenant.
 * Every answer persists its measured figures inside the stored answer JSON, so
 * the history is the conversation store itself: no second store, no model
 * training, nothing inferred. Only the JSON sub-path is selected, so this stays
 * cheap however large the stored answers are.
 */
async function loadPriorFigures(ctx: ToolContext): Promise<PriorFigures> {
  const prior: PriorFigures = {}
  const absorb = (figures: unknown, at: string) => {
    if (!Array.isArray(figures)) return
    for (const f of figures as Array<Record<string, unknown>>) {
      const key = str(f.key)
      const value = Number(f.value)
      // Rows arrive newest-first; the first reading of a key is the latest.
      if (key && Number.isFinite(value) && !prior[key]) prior[key] = { value, at }
    }
  }
  if (!schemaMissing) {
    try {
      const { data, error } = await ctx.client
        .from(MESSAGES_TABLE)
        .select('created_at, figures:answer->figures')
        .eq('user_id', ctx.userId)
        .eq('role', 'assistant')
        .order('created_at', { ascending: false })
        .limit(60)
      if (!error) {
        for (const row of (data || []) as Array<Record<string, unknown>>) absorb(row.figures, str(row.created_at))
        return prior
      }
      if (isMissingTable(error)) schemaMissing = true
    } catch { /* fall through to the in-memory store */ }
  }
  const store = memoryStoreFor(ctx.userId)
  const answers = [...store.messages.values()].flat()
    .filter((m) => m.role === 'assistant' && m.answer?.figures)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  for (const m of answers) absorb(m.answer?.figures, m.createdAt)
  return prior
}

/* Per-conversation follow-up memory (in-process, bounded). */
const conversationMemory = new Map<string, CopilotMemoryState>()
function memoryFor(conversationId: string): CopilotMemoryState {
  return conversationMemory.get(conversationId) || { ...EMPTY_MEMORY }
}
function saveMemory(conversationId: string, memory: CopilotMemoryState) {
  conversationMemory.set(conversationId, memory)
  if (conversationMemory.size > 2000) {
    const firstKey = conversationMemory.keys().next().value
    if (firstKey) conversationMemory.delete(firstKey)
  }
}

/* ------------------------------------------------------------------ */
/* Context / suggestions / insights / health                           */
/* ------------------------------------------------------------------ */

router.get('/context', async (req: Request, res: Response) => {
  const { copilotCtx, copilotRole, copilotTier, user } = req as AuthedRequest
  const role = copilotRole || 'security_analyst'
  const email = user?.email || ''
  const context: CopilotContext = {
    userId: user!.id,
    email,
    tenantLabel: email.split('@')[1] || 'Your organization',
    role,
    roleLabel: ROLE_LABELS[role],
    tier: copilotTier || 'none',
    capabilities: ROLE_CAPABILITIES[role],
    persistence: schemaMissing ? 'memory' : 'database',
  }
  // Probe persistence once so the flag is accurate before the first chat.
  if (!schemaMissing) {
    try {
      const { error } = await copilotCtx!.client.from(CONVERSATIONS_TABLE).select('id', { count: 'exact', head: true }).eq('user_id', user!.id)
      if (error && isMissingTable(error)) { schemaMissing = true; context.persistence = 'memory' }
    } catch { /* leave as-is */ }
  }
  res.json({ data: context })
})

router.get('/suggestions', (req: Request, res: Response) => {
  const page = typeof req.query.page === 'string' ? req.query.page : undefined
  res.json({ data: { suggestions: suggestionsForPage(page) } })
})

router.get('/insights', async (req: Request, res: Response) => {
  try {
    const { copilotCtx } = req as AuthedRequest
    const insights = await buildInsights(copilotCtx!)
    res.json({ data: { insights, generatedAt: new Date().toISOString() } })
  } catch (error) {
    console.error('[copilot] insights failed:', error)
    res.status(500).json({ error: { code: 'INSIGHTS_ERROR', message: 'Unable to build insights' } })
  }
})

router.get('/health', (_req: Request, res: Response) => {
  res.json({
    data: {
      status: 'operational',
      engine: 'sophia-multi-agent-v2',
      components: {
        gateway: 'operational',
        intentDetection: 'operational',
        topicSpecialists: 'operational',
        entityLinking: 'operational',
        longitudinalMemory: schemaMissing ? 'memory-fallback' : 'database',
        planner: 'operational',
        toolOrchestrator: 'operational',
        agents: 'operational',
        streaming: 'operational',
        conversationStore: schemaMissing ? 'memory-fallback' : 'database',
      },
      timestamp: new Date().toISOString(),
    },
  })
})

/* ------------------------------------------------------------------ */
/* Conversations CRUD                                                  */
/* ------------------------------------------------------------------ */

router.get('/conversations', async (req: Request, res: Response) => {
  const { copilotCtx } = req as AuthedRequest
  res.json({ data: { conversations: await listConversations(copilotCtx!), persistence: schemaMissing ? 'memory' : 'database' } })
})

router.post('/conversations', async (req: Request, res: Response) => {
  const { copilotCtx } = req as AuthedRequest
  const title = str(rec(req.body).title)
  const conversation = await createConversation(copilotCtx!, title || 'New conversation')
  await recordAudit(copilotCtx!.userId, 'copilot.conversation.created', { conversationId: conversation.id })
  res.status(201).json({ data: conversation })
})

router.get('/conversations/search', async (req: Request, res: Response) => {
  const { copilotCtx } = req as AuthedRequest
  const q = (typeof req.query.q === 'string' ? req.query.q : '').trim().toLowerCase().slice(0, 80)
  if (!q) {
    res.json({ data: { results: [] } })
    return
  }
  const conversations = await listConversations(copilotCtx!)
  const results: Array<{ conversation: CopilotConversation; match: string }> = []
  for (const conversation of conversations) {
    if (conversation.title.toLowerCase().includes(q)) {
      results.push({ conversation, match: conversation.title })
      continue
    }
    const messages = await listMessages(copilotCtx!, conversation.id)
    const hit = messages.find((m) => m.content.toLowerCase().includes(q))
    if (hit) results.push({ conversation, match: hit.content.slice(0, 140) })
    if (results.length >= 15) break
  }
  res.json({ data: { results } })
})

router.get('/conversations/:id', async (req: Request, res: Response) => {
  const { copilotCtx } = req as AuthedRequest
  const conversation = await getConversation(copilotCtx!, req.params.id)
  if (!conversation) {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Conversation not found' } })
    return
  }
  const messages = await listMessages(copilotCtx!, conversation.id)
  res.json({ data: { conversation, messages } })
})

router.patch('/conversations/:id', async (req: Request, res: Response) => {
  const { copilotCtx } = req as AuthedRequest
  const conversation = await getConversation(copilotCtx!, req.params.id)
  if (!conversation) {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Conversation not found' } })
    return
  }
  const body = rec(req.body)
  const updates: Record<string, unknown> = {}
  if (typeof body.pinned === 'boolean') updates.pinned = body.pinned
  if (str(body.title)) updates.title = str(body.title).slice(0, 140)
  if (!schemaMissing) {
    try {
      await copilotCtx!.client.from(CONVERSATIONS_TABLE).update({ ...updates, updated_at: new Date().toISOString() }).eq('user_id', copilotCtx!.userId).eq('id', conversation.id)
    } catch { /* memory path below still applies */ }
  }
  const store = memoryStoreFor(copilotCtx!.userId)
  const inMemory = store.conversations.get(conversation.id)
  if (inMemory) Object.assign(inMemory, { pinned: typeof body.pinned === 'boolean' ? body.pinned : inMemory.pinned, title: str(body.title) || inMemory.title })
  res.json({ data: { ...conversation, ...updates } })
})

router.delete('/conversations/:id', async (req: Request, res: Response) => {
  const { copilotCtx } = req as AuthedRequest
  const conversation = await getConversation(copilotCtx!, req.params.id)
  if (!conversation) {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Conversation not found' } })
    return
  }
  if (!schemaMissing) {
    try {
      await copilotCtx!.client.from(MESSAGES_TABLE).delete().eq('user_id', copilotCtx!.userId).eq('conversation_id', conversation.id)
      await copilotCtx!.client.from(CONVERSATIONS_TABLE).delete().eq('user_id', copilotCtx!.userId).eq('id', conversation.id)
    } catch { /* memory cleanup below */ }
  }
  const store = memoryStoreFor(copilotCtx!.userId)
  store.conversations.delete(conversation.id)
  store.messages.delete(conversation.id)
  conversationMemory.delete(conversation.id)
  await recordAudit(copilotCtx!.userId, 'copilot.conversation.deleted', { conversationId: conversation.id })
  res.json({ data: { deleted: true } })
})

router.get('/conversations/:id/export', async (req: Request, res: Response) => {
  const { copilotCtx } = req as AuthedRequest
  const conversation = await getConversation(copilotCtx!, req.params.id)
  if (!conversation) {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Conversation not found' } })
    return
  }
  const messages = await listMessages(copilotCtx!, conversation.id)
  await recordAudit(copilotCtx!.userId, 'copilot.conversation.exported', { conversationId: conversation.id, messages: messages.length })
  res.json({ data: { conversation, messages, exportedAt: new Date().toISOString(), platform: 'QGuard Helix — Sophia AI Security Copilot™' } })
})

/* ------------------------------------------------------------------ */
/* Feedback — a rating on one answer, recorded to the audit trail      */
/* ------------------------------------------------------------------ */

router.post('/feedback', async (req: Request, res: Response) => {
  const { copilotCtx } = req as AuthedRequest
  const body = rec(req.body)
  const answerId = str(body.answerId).trim()
  const rating = str(body.rating)
  // Validated server-side: ids are opaque, bounded strings; the rating is an
  // enum; the note is length-capped. Nothing here is interpreted or executed.
  if (!/^[\w.:-]{1,80}$/.test(answerId) || (rating !== 'up' && rating !== 'down')) {
    res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'answerId and rating (up | down) are required' } })
    return
  }
  const conversationId = str(body.conversationId).slice(0, 80) || null
  await recordAudit(copilotCtx!.userId, 'copilot.feedback', {
    answerId,
    conversationId,
    rating,
    focus: str(body.focus).slice(0, 40) || null,
    note: str(body.note).slice(0, 500) || null,
  })
  res.status(201).json({ data: { recorded: true } })
})

/* ------------------------------------------------------------------ */
/* Chat — JSON + SSE streaming                                         */
/* ------------------------------------------------------------------ */

router.post('/chat', async (req: Request, res: Response) => {
  const { copilotCtx, user } = req as AuthedRequest
  const ctx = copilotCtx!
  const body = rec(req.body)
  const rawMessage = str(body.message)
  const page = str(body.page)
  const wantsStream = req.query.stream === '1' || String(req.headers.accept || '').includes('text/event-stream') || body.stream === true

  if (!rawMessage.trim()) {
    res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'A message is required' } })
    return
  }

  const rate = checkChatRateLimit(ctx.userId)
  if (!rate.allowed) {
    await recordAudit(ctx.userId, 'copilot.chat.rate_limited', { retryAfterSec: rate.retryAfterSec })
    res.status(429).json({ error: { code: 'RATE_LIMITED', message: `Too many copilot requests — retry in ${rate.retryAfterSec}s`, retryAfterSec: rate.retryAfterSec } })
    return
  }

  // Resolve (or create) the conversation.
  let conversationId = str(body.conversationId)
  let conversation = conversationId ? await getConversation(ctx, conversationId) : null
  if (!conversation) {
    conversation = await createConversation(ctx, rawMessage.slice(0, 60))
    conversationId = conversation.id
  }

  const sanitized = sanitizePrompt(rawMessage)
  await appendMessage(ctx, conversationId, 'user', sanitized.text || rawMessage.slice(0, 2000))
  await recordAudit(ctx.userId, 'copilot.chat.query', {
    conversationId,
    page: page || null,
    blocked: sanitized.blocked,
    reasons: sanitized.reasons,
    length: rawMessage.length,
  })

  const memory = { ...memoryFor(conversationId), currentPage: page || undefined }
  const priorFigures = await loadPriorFigures(ctx).catch(() => ({} as PriorFigures))

  // Learning from use, honestly: a question no specialist could ground is
  // recorded (tenant's own audit trail) so coverage gaps are visible and can be
  // closed — Sophia never "learns" by inventing an answer.
  const recordGap = (outcome: QueryOutcome) => {
    if (!outcome.knowledgeGap || sanitized.blocked) return
    void recordAudit(ctx.userId, 'copilot.knowledge_gap', {
      conversationId,
      question: sanitized.text.slice(0, 240),
      intents: outcome.answer.intents,
      grounding: outcome.answer.grounding || null,
    })
  }

  if (wantsStream) {
    res.status(200)
    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache, no-transform')
    res.setHeader('Connection', 'keep-alive')
    res.setHeader('X-Accel-Buffering', 'no')
    res.flushHeaders?.()
    const send = (event: CopilotStreamEvent) => {
      try { res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`) } catch { /* client gone */ }
    }
    send({ type: 'stage', stage: 'thinking', label: 'Connected to Sophia' })
    const heartbeat = setInterval(() => { try { res.write(': keep-alive\n\n') } catch { /* noop */ } }, 15_000)
    try {
      const outcome = await runCopilotQuery(ctx, rawMessage, memory, send, undefined, { priorFigures })
      saveMemory(conversationId, outcome.memory)
      recordGap(outcome)
      await appendMessage(ctx, conversationId, 'assistant', outcome.answer.summary, outcome.answer)
      res.write(`event: meta\ndata: ${JSON.stringify({ type: 'meta', conversationId })}\n\n`)
    } catch (error) {
      console.error('[copilot] chat stream failed:', error)
      send({ type: 'error', message: 'Sophia hit an internal error while building the answer.' })
    } finally {
      clearInterval(heartbeat)
      res.end()
    }
    return
  }

  try {
    const events: CopilotStreamEvent[] = []
    const outcome = await runCopilotQuery(ctx, rawMessage, memory, (event) => events.push(event), undefined, { priorFigures })
    saveMemory(conversationId, outcome.memory)
    recordGap(outcome)
    await appendMessage(ctx, conversationId, 'assistant', outcome.answer.summary, outcome.answer)
    res.json({ data: { conversationId, answer: outcome.answer, stages: events.filter((e) => e.type === 'stage') } })
  } catch (error) {
    console.error('[copilot] chat failed:', error)
    res.status(500).json({ error: { code: 'COPILOT_ERROR', message: 'Sophia was unable to answer — please retry' } })
  }

  void user // authed context is fully carried by ctx
})

export default router
