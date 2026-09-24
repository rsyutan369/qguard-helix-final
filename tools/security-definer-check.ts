/**
 * Live proof for supabase/security-definer-hardening.sql, through the public
 * Data API exactly as an attacker or the apps would call it.
 *
 *   npx tsx tools/security-definer-check.ts
 *
 * Uses real sessions (admin magic link -> verifyOtp, no passwords) for a
 * conversation member, another member, and an outsider, plus the anon key.
 * Read-only apart from ensure_messaging_defaults on the caller's OWN row,
 * which is idempotent (ON CONFLICT DO UPDATE with the same values).
 */
import 'dotenv/config'
import assert from 'node:assert/strict'
import { createClient, type SupabaseClient } from '@supabase/supabase-js'

const URL_ = process.env.VITE_SUPABASE_URL || ''
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const ANON = process.env.VITE_SUPABASE_ANON_KEY || ''
if (!URL_ || !SERVICE || !ANON) throw new Error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY')

const admin = createClient(URL_, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } })
const anon = createClient(URL_, ANON, { auth: { persistSession: false, autoRefreshToken: false } })

const results: Array<{ name: string; ok: boolean; detail?: string }> = []
async function check(name: string, fn: () => Promise<void>) {
  try {
    await fn()
    results.push({ name, ok: true })
  } catch (error) {
    results.push({ name, ok: false, detail: error instanceof Error ? error.message : String(error) })
  }
}

async function clientFor(userId: string): Promise<SupabaseClient> {
  const { data: user } = await admin.auth.admin.getUserById(userId)
  const email = user?.user?.email
  if (!email) throw new Error(`no email for ${userId}`)
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (error) throw error
  // A throwaway client: verifyOtp SIGNS IN the client it runs on, and doing it
  // on the shared `anon` client silently turned every later "anon" probe into
  // an authenticated call (caught by this very check on its first run).
  const signIn = createClient(URL_, ANON, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data, error: otpError } = await signIn.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpError || !data.session) throw otpError || new Error('no session')
  return createClient(URL_, ANON, { global: { headers: { Authorization: `Bearer ${data.session.access_token}` } }, auth: { persistSession: false } })
}

// 42501 = no EXECUTE / guard refusal; PGRST202 = not exposed as an RPC at all
// (PostgREST never exposes trigger functions).
const denied = (error: { code?: string; message?: string } | null) =>
  Boolean(error && (error.code === '42501' || error.code === 'PGRST202' || /permission denied|may only initialise/i.test(error.message || '')))

async function main() {
  const { data: members } = await admin.from('messaging_conversation_members').select('conversation_id,user_id').is('revoked_at', null)
  const byConversation = new Map<string, string[]>()
  for (const row of members || []) byConversation.set(row.conversation_id, [...(byConversation.get(row.conversation_id) || []), row.user_id])
  const pair = [...byConversation.entries()].find(([, users]) => new Set(users).size >= 2)
  if (!pair) throw new Error('need a conversation with two members')
  const [conversationId, users] = pair
  const [a, b] = [...new Set(users)]
  const { data: profiles } = await admin.from('profiles').select('id')
  const x = (profiles || []).map((row) => row.id).find((id) => !users.includes(id))
  if (!x) throw new Error('need a user outside the conversation')
  const { data: contact } = await admin.from('messaging_contacts').select('owner_user_id,contact_user_id').eq('trust_state', 'added').limit(1).maybeSingle()

  const asA = await clientFor(a)
  const asX = await clientFor(x)

  await check('anon cannot call maintenance / trigger / token functions', async () => {
    for (const [fn, args] of [
      ['cleanup_expired_vault_sessions', {}],
      ['prune_expired_messaging_call_signals', {}],
      ['generate_secure_token', { length: 8 }],
      ['requesting_user_id', {}],
      ['qguard_set_updated_at', {}],
    ] as const) {
      const { error } = await anon.rpc(fn, args as Record<string, unknown>)
      assert.ok(denied(error), `${fn}: anon was not refused (${error?.code} ${error?.message})`)
    }
  })

  await check('anon cannot reset any user\'s messaging defaults (was: allowed)', async () => {
    const { error } = await anon.rpc('ensure_messaging_defaults', { p_user_id: a })
    assert.ok(denied(error), `anon: ${error?.code} ${error?.message}`)
  })

  await check('a user cannot reset ANOTHER user\'s messaging defaults; their own still works', async () => {
    const { error: other } = await asA.rpc('ensure_messaging_defaults', { p_user_id: b })
    assert.ok(denied(other), `other: ${other?.code} ${other?.message}`)
    const { error: self } = await asA.rpc('ensure_messaging_defaults', { p_user_id: a })
    assert.equal(self, null, `self: ${self?.message}`)
  })

  await check('membership oracle closed for outsiders, intact for members (message send path)', async () => {
    const { data: outsider } = await asX.rpc('is_messaging_conversation_member', { p_conversation_id: conversationId, p_user_id: b })
    assert.equal(outsider, false, 'outsider learned another user\'s membership')
    const { data: member } = await asA.rpc('is_messaging_conversation_member', { p_conversation_id: conversationId, p_user_id: b })
    assert.equal(member, true, 'a member must still be able to check a peer (envelope insert policy)')
  })

  await check('subscription oracle closed: nobody reads another user\'s messaging access', async () => {
    const { data: other } = await asX.rpc('qguard_has_messaging_access', { uid: a })
    assert.equal(other, false)
    const { data: own } = await asA.rpc('qguard_has_messaging_access', { uid: a })
    const { data: truth } = await admin.rpc('qguard_has_messaging_access', { uid: a })
    assert.equal(own, truth, 'own answer must equal the service-role truth')
  })

  if (contact && ![contact.owner_user_id, contact.contact_user_id].includes(x)) {
    await check('contact oracle closed for a third party', async () => {
      const { data } = await asX.rpc('is_messaging_contact', { p_owner_user_id: contact.owner_user_id, p_contact_user_id: contact.contact_user_id })
      assert.equal(data, false)
    })
  }

  await check('RLS through REST: a member still sees the conversation roster; an outsider sees none of it', async () => {
    const { data: seen, error } = await asA.from('messaging_conversation_members').select('user_id').eq('conversation_id', conversationId)
    assert.equal(error, null, error?.message)
    assert.ok((seen || []).length >= 2, `member saw ${(seen || []).length} rows`)
    const { data: outsider } = await asX.from('messaging_conversation_members').select('user_id').eq('conversation_id', conversationId)
    assert.equal((outsider || []).length, 0)
  })

  await check('signed-in users keep the functions their app paths need', async () => {
    const { error: token } = await asA.rpc('generate_secure_token', { length: 8 })
    assert.equal(token, null, `generate_secure_token (vault_shared_links.token default): ${token?.message}`)
    const { error: prune } = await asA.rpc('prune_expired_messaging_typing_indicators')
    assert.equal(prune, null, `prune_expired_messaging_typing_indicators: ${prune?.message}`)
  })

  let failed = 0
  for (const result of results) {
    console.log(`${result.ok ? 'PASS' : 'FAIL'}  ${result.name}${result.detail ? `\n      ${result.detail}` : ''}`)
    if (!result.ok) failed += 1
  }
  console.log(`\n${results.length - failed}/${results.length} checks passed`)
  process.exit(failed ? 1 : 0)
}

void main().catch((error) => {
  console.error(error)
  process.exit(1)
})
