/**
 * Offline verification for Sophia's bring-your-own-key model layer.
 *
 * No network, no Supabase: provider HTTP is served by a stubbed global fetch
 * that records every request and replays each provider's real SSE shape.
 * Asserts the security + correctness invariants:
 *   - key sealing: AES-256-GCM round trip, AAD binds user + provider, tamper fails,
 *     production refuses to derive a sealing key without COPILOT_BYOK_SECRET
 *   - input validation: closed endpoint allowlist, bounded model ids and keys
 *   - plan gating: Pro and Elite only
 *   - redaction of secret-shaped strings before the evidence pack leaves
 *   - grounding check: invented figures flagged, evidence / standards figures pass
 *   - adapters: Anthropic + OpenAI-compatible request shape, streaming deltas,
 *     usage, refusal / truncation, HTTP error mapping with the key scrubbed
 *   - composeNarrative end-to-end, including a failed call leaving a clean error
 *   - connection store: one active engine, public status never carries the key
 *
 *   npx tsx tools/copilot-byok-check.ts
 */

// Sealing secret for the run; the store must use the in-memory path.
process.env.COPILOT_BYOK_SECRET = 'offline-check-secret-0123456789-abcdefghijklmnop'
for (const k of ['SUPABASE_URL', 'VITE_SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_FALLBACK_URL', 'SUPABASE_FALLBACK_SERVICE_ROLE_KEY']) delete process.env[k]

import {
  buildEvidencePack,
  byokEntitled,
  callModel,
  checkGrounding,
  composeNarrative,
  connectionAfterUse,
  encryptionMode,
  extractFigures,
  getActiveConnection,
  historyForModel,
  keyHintOf,
  listConnections,
  LlmError,
  NARRATIVE_SYSTEM_PROMPT,
  openApiKey,
  publicStatus,
  redactSecrets,
  saveConnection,
  sealApiKey,
  setActiveProvider,
  deleteConnection,
  validateConnectionInput,
  type LlmConnection,
} from '../src/api-server/copilot-llm'
import { COPILOT_LLM_PROVIDERS, endpointSpec, providerSpec } from '../src/lib/copilot-llm-catalog'
import type { CopilotAnswer, CopilotMessage } from '../src/types/copilot'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}
function section(title: string) { console.log(`\n${title}`) }

/* ------------------------------------------------------------------ */
/* fetch stub                                                          */
/* ------------------------------------------------------------------ */

interface Recorded { url: string; headers: Record<string, string>; body: Record<string, unknown> }
const recorded: Recorded[] = []
let reply: (req: Recorded) => Response = () => new Response('unset', { status: 500 })

function sse(frames: string[]): Response {
  const encoder = new TextEncoder()
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      // Split frames across chunk boundaries (including mid-CRLF) to exercise the parser.
      const all = frames.join('')
      const mid = Math.floor(all.length / 2)
      controller.enqueue(encoder.encode(all.slice(0, mid)))
      controller.enqueue(encoder.encode(all.slice(mid)))
      controller.close()
    },
  })
  return new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } })
}
const anthropicFrame = (event: string, data: unknown) => `event: ${event}\r\ndata: ${JSON.stringify(data)}\r\n\r\n`
const openAiFrame = (data: unknown) => `data: ${typeof data === 'string' ? data : JSON.stringify(data)}\n\n`

globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries((init?.headers || {}) as Record<string, string>)) headers[k.toLowerCase()] = v
  const req: Recorded = { url: String(input), headers, body: JSON.parse(String(init?.body || '{}')) }
  recorded.push(req)
  return reply(req)
}) as typeof fetch

/* ------------------------------------------------------------------ */
/* Fixtures                                                            */
/* ------------------------------------------------------------------ */

const answer: CopilotAnswer = {
  id: 'ans-1',
  intents: ['asset_status'],
  agents: ['asset_intelligence'],
  summary: '12 of 40 assets still use RSA-2048 key exchange; quantum readiness is 59.4%.',
  reasoning: [],
  evidence: [
    { module: 'Assets & CBOM', label: 'Vulnerable assets', value: '12', detail: 'api.example.com uses RSA-2048', observedAt: '2026-10-26T10:00:00Z', deepLink: '/dashboard/assets' },
    { module: 'Quantum Readiness', label: 'Readiness', value: '59.4%', detail: 'debug token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl' },
  ],
  recommendations: [{ title: 'Adopt X25519+ML-KEM-768', detail: 'Hybrid key establishment on api.example.com', priority: 'high', standards: ['FIPS 203'] }],
  risk: { level: 'high', score: 72, drivers: ['RSA key exchange'] },
  nextActions: [{ label: 'Plan migration', path: '/dashboard/migration_planner', reason: 'Sequence the 12 assets' }],
  relatedPages: [],
  standards: ['FIPS 203'],
  confidence: { score: 81, basis: 'focused' },
  toolRuns: [{ tool: 'getAssetRegister', module: 'assets', source: 'Assets & CBOM', status: 'ok', ms: 12, rows: 40 }],
  followUps: [],
  generatedAt: '2026-10-27T00:00:00Z',
  figures: [{ key: 'assets.total', label: 'Assets', value: 40, better: 'neutral', source: 'Assets & CBOM' }],
  entities: [{
    title: 'Vulnerable assets', unit: 'asset', source: 'Assets & CBOM', total: 12,
    columns: [{ key: 'name', label: 'Asset' }, { key: 'algo', label: 'Algorithm' }],
    rows: [{ cells: { name: 'api.example.com', algo: 'RSA-2048' } }, { cells: { name: 'vpn.example.com', algo: 'password=hunter2secret' } }],
  }],
}

const USER = '11111111-1111-1111-1111-111111111111'
const OTHER = '22222222-2222-2222-2222-222222222222'
const KEY = 'sk-ant-api03-offlinecheckkey-ABCDEFGHIJKLMNOPQRSTUVWX'

function connection(provider: LlmConnection['provider'], overrides: Partial<LlmConnection> = {}): LlmConnection {
  const spec = providerSpec(provider)!
  return {
    provider,
    model: spec.endpoints[0].models[0].id,
    endpoint: spec.endpoints[0].id,
    keyEnvelope: sealApiKey(KEY, USER, provider),
    keyHint: keyHintOf(KEY),
    isActive: false,
    status: 'verified',
    lastVerifiedAt: null,
    lastError: null,
    lastUsedAt: null,
    requestCount: 0,
    inputTokens: 0,
    outputTokens: 0,
    consentAt: '2026-10-27T00:00:00Z',
    updatedAt: '2026-10-27T00:00:00Z',
    ...overrides,
  }
}

async function main() {
  /* ---------------------------------------------------------------- */
  section('Key sealing (AES-256-GCM, HKDF-SHA3-256)')
  assert(encryptionMode() === 'dedicated', 'dedicated secret is used when COPILOT_BYOK_SECRET is set')
  const envelope = sealApiKey(KEY, USER, 'anthropic')
  assert(envelope.startsWith('v1.d.') && envelope.split('.').length === 5, 'envelope is versioned v1.<mode>.<iv>.<tag>.<ct>')
  assert(!envelope.includes(KEY) && !envelope.includes('offlinecheck'), 'envelope contains no plaintext')
  assert(sealApiKey(KEY, USER, 'anthropic') !== envelope, 'fresh IV per seal (ciphertexts differ)')
  assert(openApiKey(envelope, USER, 'anthropic') === KEY, 'round trip opens to the original key')
  const opens = (fn: () => string) => { try { fn(); return true } catch (e) { return !(e instanceof LlmError) } }
  assert(!opens(() => openApiKey(envelope, OTHER, 'anthropic')), 'AAD: another user cannot open the ciphertext')
  assert(!opens(() => openApiKey(envelope, USER, 'openai')), 'AAD: the ciphertext does not open under another provider')
  const parts = envelope.split('.')
  const flipped = parts[4].startsWith('A') ? `B${parts[4].slice(1)}` : `A${parts[4].slice(1)}`
  assert(!opens(() => openApiKey([...parts.slice(0, 4), flipped].join('.'), USER, 'anthropic')), 'tampered ciphertext fails the GCM tag')
  const savedSecret = process.env.COPILOT_BYOK_SECRET
  const savedEnv = process.env.NODE_ENV
  delete process.env.COPILOT_BYOK_SECRET
  process.env.SUPABASE_SERVICE_ROLE_KEY = 'service-role-for-derived-mode-check'
  process.env.NODE_ENV = 'production'
  assert(encryptionMode() === 'unavailable', 'production without COPILOT_BYOK_SECRET → BYOK unavailable (no derived key)')
  process.env.NODE_ENV = 'development'
  assert(encryptionMode() === 'derived', 'development falls back to a derived sealing key')
  assert(!opens(() => openApiKey(envelope, USER, 'anthropic')), 'a key sealed under the dedicated secret is refused in derived mode')
  process.env.COPILOT_BYOK_SECRET = savedSecret
  process.env.NODE_ENV = savedEnv
  delete process.env.SUPABASE_SERVICE_ROLE_KEY
  assert(encryptionMode() === 'dedicated', 'restored dedicated mode')

  /* ---------------------------------------------------------------- */
  section('Input validation + plan gating')
  assert(!!validateConnectionInput('anthropic', { model: 'claude-opus-5-5', apiKey: KEY }).value, 'valid Anthropic input accepted')
  assert(!validateConnectionInput('kimi', { model: 'kimi-k2-0905-preview', endpoint: 'http://169.254.169.254', apiKey: KEY }).value, 'endpoint outside the allowlist rejected (no SSRF)')
  assert(!validateConnectionInput('openai', { model: 'gpt 5; drop', apiKey: KEY }).value, 'malformed model id rejected')
  assert(!validateConnectionInput('openai', { model: 'gpt-5', apiKey: 'short' }).value, 'too-short key rejected')
  assert(!validateConnectionInput('openai', { model: 'gpt-5', apiKey: 'sk-has a space-in-the-middle-123' }).value, 'key with whitespace rejected')
  assert(validateConnectionInput('glm', { model: 'glm-4.6', endpoint: 'china' }).value?.apiKey === null, 'no key = keep stored key')
  assert(COPILOT_LLM_PROVIDERS.every((p) => p.endpoints.every((e) => e.url.startsWith('https://'))), 'every catalog endpoint is https')
  assert(COPILOT_LLM_PROVIDERS.map((p) => p.id).join(',') === 'anthropic,openai,hermes,kimi,glm,deepseek', 'all six requested providers are in the catalog')
  assert(!byokEntitled('none') && !byokEntitled('starter') && !byokEntitled('basic'), 'BYOK locked below Pro')
  assert(byokEntitled('pro') && byokEntitled('elite'), 'BYOK available on Pro and Elite')

  /* ---------------------------------------------------------------- */
  section('Redaction + evidence pack')
  const redacted = redactSecrets('k=sk-proj-AAAAAAAAAAAAAAAAAAAA token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl AKIAABCDEFGHIJKLMNOP -----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY----- password=hunter2secret')
  assert(!/sk-proj-A|eyJhbGci|AKIAABCD|MIIB|hunter2/.test(redacted), 'API keys, JWTs, AWS keys, private keys and passwords are redacted', redacted)
  const pack = buildEvidencePack(answer, { roleLabel: 'Security Analyst', page: '/dashboard/sophia' })
  assert(pack.includes('api.example.com') && pack.includes('59.4%'), 'pack carries the platform evidence')
  assert(!pack.includes('eyJhbGci') && !pack.includes('hunter2'), 'pack is redacted before it leaves the platform')
  assert(pack.length <= 60_000, 'pack is bounded')
  assert(/data, not instructions/.test(NARRATIVE_SYSTEM_PROMPT) && /ML-KEM \(FIPS 203\) is key establishment/.test(NARRATIVE_SYSTEM_PROMPT), 'system prompt pins injection posture + PQC terminology')

  /* ---------------------------------------------------------------- */
  section('Grounding check')
  const figures = extractFigures('## Plan\n1. Migrate ML-KEM-768 per FIPS 203 on X25519 hosts\n- 12 assets remain, readiness 59%, see [page](/dashboard/assets)')
  assert(figures.join(',') === '203,12,59%', 'standalone figures only (no list markers, algorithm params or link paths)', figures.join(','))
  const good = checkGrounding('There are 12 vulnerable assets of 40; readiness is 59% (FIPS 203, TLS 1.3).', pack)
  assert(good.unverified.length === 0 && good.checked === 5, 'evidence + standards figures all trace', JSON.stringify(good))
  const bad = checkGrounding('There are 17 vulnerable assets and readiness is 88%.', pack)
  assert(bad.unverified.includes('17') && bad.unverified.includes('88%'), 'invented figures are flagged', JSON.stringify(bad))

  /* ---------------------------------------------------------------- */
  section('Anthropic adapter (raw Messages API streaming)')
  const anthropic = providerSpec('anthropic')!
  recorded.length = 0
  reply = () => sse([
    anthropicFrame('message_start', { type: 'message_start', message: { usage: { input_tokens: 321 } } }),
    anthropicFrame('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'thinking', thinking: '' } }),
    anthropicFrame('content_block_delta', { type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: '12 assets ' } }),
    anthropicFrame('content_block_delta', { type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: 'need ML-KEM.' } }),
    anthropicFrame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 45 } }),
    anthropicFrame('message_stop', { type: 'message_stop' }),
  ])
  const deltas: string[] = []
  const ac = new AbortController()
  const aRes = await callModel({ spec: anthropic, endpoint: endpointSpec(anthropic, 'global'), model: 'claude-opus-5-5', apiKey: KEY, system: 'sys', messages: [{ role: 'user', content: 'q' }], maxTokens: 16000, signal: ac.signal, onDelta: (d) => deltas.push(d) })
  const aReq = recorded[0]
  assert(aReq.url === 'https://api.anthropic.com/v1/messages', 'calls the allowlisted Anthropic endpoint')
  assert(aReq.headers['x-api-key'] === KEY && aReq.headers['anthropic-version'] === '2023-06-01', 'x-api-key + anthropic-version headers')
  assert(aReq.body.stream === true && aReq.body.system === 'sys' && aReq.body.max_tokens === 16000, 'streaming request with system + max_tokens')
  assert(!('temperature' in aReq.body) && !('thinking' in aReq.body), 'no sampling params / thinking config sent (rejected by current models)')
  assert(aReq.body.fallbacks === 'default' && aReq.headers['anthropic-beta'] === 'server-side-fallback-2026-07-01', 'refusal fallbacks enabled for Opus 5.5')
  assert(aRes.content === '12 assets need ML-KEM.' && deltas.length === 2, 'text deltas streamed and assembled (thinking blocks ignored)')
  assert(aRes.usage.inputTokens === 321 && aRes.usage.outputTokens === 45 && aRes.stopReason === 'end_turn', 'usage + stop reason captured')
  recorded.length = 0
  await callModel({ spec: anthropic, endpoint: endpointSpec(anthropic, 'global'), model: 'claude-haiku-5-5', apiKey: KEY, system: 's', messages: [{ role: 'user', content: 'q' }], maxTokens: 10, signal: ac.signal }).catch(() => null)
  assert(!('fallbacks' in recorded[0].body) && !recorded[0].headers['anthropic-beta'], 'no fallbacks param for Haiku 5.5 (unsupported)')
  reply = () => sse([anthropicFrame('message_delta', { type: 'message_delta', delta: { stop_reason: 'refusal' }, usage: { output_tokens: 0 } })])
  const refused = await callModel({ spec: anthropic, endpoint: endpointSpec(anthropic, 'global'), model: 'claude-opus-5-5', apiKey: KEY, system: 's', messages: [{ role: 'user', content: 'q' }], maxTokens: 10, signal: ac.signal })
  assert(refused.refused, 'stop_reason refusal is surfaced')
  reply = () => new Response(JSON.stringify({ type: 'error', error: { type: 'authentication_error', message: `invalid x-api-key ${KEY}` } }), { status: 401 })
  let authErr: LlmError | null = null
  try { await callModel({ spec: anthropic, endpoint: endpointSpec(anthropic, 'global'), model: 'claude-opus-5-5', apiKey: KEY, system: 's', messages: [{ role: 'user', content: 'q' }], maxTokens: 10, signal: ac.signal }) } catch (e) { authErr = e as LlmError }
  assert(authErr?.kind === 'auth', '401 maps to auth error')
  assert(!!authErr && !authErr.message.includes(KEY), 'provider error text never echoes the key', authErr?.message)

  /* ---------------------------------------------------------------- */
  section('OpenAI-compatible adapters (OpenAI, Hermes, Kimi, GLM, DeepSeek)')
  for (const spec of COPILOT_LLM_PROVIDERS.filter((p) => p.protocol === 'openai')) {
    for (const ep of spec.endpoints) {
      recorded.length = 0
      reply = () => sse([
        openAiFrame({ choices: [{ delta: { role: 'assistant', reasoning_content: 'hidden chain' } }] }),
        openAiFrame({ choices: [{ delta: { content: 'Rotate ' } }] }),
        openAiFrame({ choices: [{ delta: { content: '12 certs.' }, finish_reason: 'stop' }] }),
        openAiFrame({ choices: [], usage: { prompt_tokens: 100, completion_tokens: 7 } }),
        openAiFrame('[DONE]'),
      ])
      const model = ep.models[0].id
      const r = await callModel({ spec, endpoint: ep, model, apiKey: KEY, system: 'sys', messages: [{ role: 'user', content: 'q' }], maxTokens: spec.maxOutputTokens, signal: ac.signal })
      const req = recorded[0]
      const tokenField = spec.id === 'openai' ? 'max_completion_tokens' : 'max_tokens'
      const ok = req.url === ep.url
        && req.headers.authorization === `Bearer ${KEY}`
        && (req.body.messages as Array<{ role: string }>)[0].role === 'system'
        && req.body[tokenField] === spec.maxOutputTokens
        && !('temperature' in req.body)
        && r.content === 'Rotate 12 certs.'
        && r.usage.outputTokens === 7
      assert(ok, `${spec.label} · ${ep.id}: request shape, ${tokenField}, streamed content (reasoning hidden), usage`)
    }
  }
  const openai = providerSpec('openai')!
  reply = () => new Response(JSON.stringify({ error: { message: 'The model `gpt-9` does not exist' } }), { status: 404 })
  let nf: LlmError | null = null
  try { await callModel({ spec: openai, endpoint: openai.endpoints[0], model: 'gpt-9', apiKey: KEY, system: 's', messages: [{ role: 'user', content: 'q' }], maxTokens: 10, signal: ac.signal }) } catch (e) { nf = e as LlmError }
  assert(nf?.kind === 'not_found' && /does not exist/.test(nf.message), '404 maps to not_found with the provider’s reason')
  reply = () => sse([openAiFrame({ choices: [{ delta: { content: 'partial' }, finish_reason: 'length' }] }), openAiFrame('[DONE]')])
  const capped = await callModel({ spec: openai, endpoint: openai.endpoints[0], model: 'gpt-5', apiKey: KEY, system: 's', messages: [{ role: 'user', content: 'q' }], maxTokens: 10, signal: ac.signal })
  assert(capped.stopReason === 'length', 'token-cap stop reason captured')

  /* ---------------------------------------------------------------- */
  section('composeNarrative end to end')
  recorded.length = 0
  reply = () => sse([
    anthropicFrame('message_start', { type: 'message_start', message: { usage: { input_tokens: 900 } } }),
    anthropicFrame('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '12 of 40 assets need X25519+ML-KEM-768. Readiness is 59%. About 77 hosts are exposed.' } }),
    anthropicFrame('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 30 } }),
    anthropicFrame('message_stop', { type: 'message_stop' }),
  ])
  const history: CopilotMessage[] = [
    { id: 'a0', conversationId: 'c', role: 'assistant', content: 'orphan', createdAt: '' },
    { id: 'u1', conversationId: 'c', role: 'user', content: 'Am I quantum ready?', createdAt: '' },
    { id: 'a1', conversationId: 'c', role: 'assistant', content: 'Readiness 59.4%', createdAt: '' },
  ]
  assert(historyForModel(history)[0].role === 'user', 'history handed to the model starts with a user turn')
  const started: string[] = []
  const streamed: string[] = []
  const narrative = await composeNarrative({
    userId: USER, connection: connection('anthropic', { isActive: true }), question: 'Which assets should I migrate first?', answer, history,
    roleLabel: 'Security Analyst', page: '/dashboard/sophia', onStart: (m) => started.push(m.model), onDelta: (d) => streamed.push(d),
  })
  const sent = recorded[0].body as { system: string; messages: Array<{ role: string; content: string }> }
  const last = sent.messages[sent.messages.length - 1]
  assert(started[0] === 'claude-opus-5-5' && streamed.length === 1, 'start + delta callbacks fire')
  assert(sent.system === NARRATIVE_SYSTEM_PROMPT, 'grounding system prompt sent')
  assert(last.role === 'user' && last.content.includes('<platform_evidence>') && last.content.includes('api.example.com'), 'question + evidence pack are the final user turn')
  assert(!JSON.stringify(sent).includes('hunter2') && !JSON.stringify(sent).includes(KEY), 'no secrets or the key in the request body')
  assert(narrative.status === 'complete' && narrative.usage?.inputTokens === 900, 'narrative complete with usage')
  assert(narrative.grounding.unverified.join(',') === '77', 'the one invented figure (77) is flagged; evidence figures pass', JSON.stringify(narrative.grounding))

  reply = () => new Response('{"error":{"message":"invalid api key"}}', { status: 401 })
  const failed = await composeNarrative({ userId: USER, connection: connection('anthropic'), question: 'q', answer, history: [], roleLabel: 'Security Analyst' })
  assert(failed.status === 'error' && /rejected the API key/.test(failed.error || ''), 'auth failure → error narrative (platform answer unaffected)')
  const wrongUser = await composeNarrative({ userId: OTHER, connection: connection('anthropic'), question: 'q', answer, history: [], roleLabel: 'Security Analyst' })
  assert(wrongUser.status === 'error' && /re-enter/.test(wrongUser.error || ''), 'a connection sealed for another user cannot be used')

  const afterAuth = connectionAfterUse(connection('anthropic'), failed)
  assert(afterAuth.status === 'invalid' && afterAuth.requestCount === 1, 'rejected key marks the connection invalid')
  const afterOk = connectionAfterUse(connection('anthropic', { status: 'error', lastError: 'x' }), narrative)
  assert(afterOk.status === 'verified' && afterOk.lastError === null && afterOk.inputTokens === 900 && afterOk.outputTokens === 30, 'successful use verifies + accumulates tokens')

  /* ---------------------------------------------------------------- */
  section('Connection store (memory fallback) + public status')
  await saveConnection(USER, connection('anthropic'))
  await saveConnection(USER, connection('deepseek'))
  await saveConnection(OTHER, connection('openai'))
  await setActiveProvider(USER, 'anthropic')
  await setActiveProvider(USER, 'deepseek')
  const mine = await listConnections(USER)
  assert(mine.filter((c) => c.isActive).length === 1 && (await getActiveConnection(USER))?.provider === 'deepseek', 'exactly one active engine per user')
  assert((await listConnections(OTHER)).every((c) => c.provider === 'openai'), 'connections are per user (no cross-tenant rows)')
  await setActiveProvider(USER, null)
  assert(!(await getActiveConnection(USER)), 'deactivate → platform engine only')
  const status = publicStatus(providerSpec('anthropic')!, mine.find((c) => c.provider === 'anthropic')!)
  const statusJson = JSON.stringify(status)
  assert(!statusJson.includes(KEY) && !statusJson.includes('v1.d.') && status.keyHint === KEY.slice(-4), 'public status carries only a 4-char hint — never the key or envelope')
  await deleteConnection(USER, 'anthropic')
  assert(!(await listConnections(USER)).some((c) => c.provider === 'anthropic'), 'disconnect deletes the stored key')

  console.log(`\n${failures === 0 ? 'ALL BYOK CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
