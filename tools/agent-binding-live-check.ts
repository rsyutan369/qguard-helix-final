/**
 * Agent asset binding — offline model checks, then a live end-to-end proof.
 *
 * A binding decides WHERE an agent's findings are filed: under an existing
 * tenant asset, under a target created for the purpose (application, folder,
 * file, profile …), or — unbound — under each discovered host/file/package.
 *
 *  1. THE MODEL (src/lib/agent-installer/agent-binding.ts) — positive and
 *     negative controls on request parsing and on reading a stored binding.
 *  2. THE SERVER, read at source level — enrolment and rebinding resolve
 *     through one tenant-scoped path, and both upload routes re-verify the
 *     binding before filing anything under it.
 *  3. LIVE — enrols real agents against the dev server, runs the SHIPPED agent
 *     bundle (tools/qguard-agent/dist/qguard-agent.cjs) over a real lab, and
 *     asserts on what reached the database: `bound` files every finding under
 *     the target, `grouped` parents the discovered assets to it, a deleted
 *     target falls back to discovery and is reported stale, and another
 *     tenant's asset can never be bound.
 *
 * Needs the dev server on :3000, OpenSSL 3.5+ and ssh-keygen on PATH.
 *   npx tsx tools/agent-binding-live-check.ts            (offline + live)
 *   npx tsx tools/agent-binding-live-check.ts --offline  (model + source only)
 *
 * Every row the live half creates belongs to the test tenant and is removed
 * again at the end; audit-log rows are left in place, as audit rows should be.
 */
import { createClient } from '@supabase/supabase-js'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import { buildLab } from './agent-lab'
import {
  agentBindingFromMetadata,
  bindingStamp,
  parseBindingRequest,
} from '../src/lib/agent-installer/agent-binding'

const BASE = process.env.QGUARD_TEST_BASE || 'http://localhost:3000'
const OWNER_EMAIL = process.env.QGUARD_TEST_EMAIL || 'zachmatthew369@gmail.com'
const RUNTIME = path.resolve('tools/qguard-agent/dist/qguard-agent.cjs')
const OFFLINE_ONLY = process.argv.includes('--offline')

let passed = 0
const failures: string[] = []
function check(name: string, condition: boolean, detail = '') {
  if (condition) passed += 1
  else failures.push(`${name}${detail ? ` — ${detail}` : ''}`)
  console.log(`  ${condition ? 'PASS' : 'FAIL'}  ${name}${!condition && detail ? ` — ${detail}` : ''}`)
}
const read = (file: string) => fs.readFileSync(path.resolve(file), 'utf8')

/* ─────────────────────────────────────────────────────────── 1. model ── */
function modelChecks() {
  console.log('\n[1] Binding model')
  const none = parseBindingRequest(undefined)
  check('absent binding is open discovery, not an error', none.ok && none.value.mode === 'none')
  const legacy = parseBindingRequest(undefined, 'a1b2c3d4-0000-4000-8000-000000000001')
  check('legacy metadata.assetId reads as an existing binding', legacy.ok && legacy.value.mode === 'existing' && legacy.value.attribution === 'bound')
  check('a malformed legacy asset id is refused', !parseBindingRequest(undefined, "x'; drop table assets;--").ok)
  check('existing without an asset id is refused', !parseBindingRequest({ mode: 'existing' }).ok)
  check('an unknown mode is refused', !parseBindingRequest({ mode: 'everything' }).ok)
  check('an unknown attribution is refused', !parseBindingRequest({ mode: 'existing', assetId: 'abc', attribution: 'merge' }).ok)
  check('an unknown kind is refused', !parseBindingRequest({ mode: 'new', name: 'X', kind: 'galaxy' }).ok)
  check('a folder without a path is refused', !parseBindingRequest({ mode: 'new', name: 'Nginx', kind: 'folder' }).ok)
  check('a name with control characters is refused', !parseBindingRequest({ mode: 'new', name: 'bad\u0000name', kind: 'application' }).ok)
  check('a 121-character name is refused', !parseBindingRequest({ mode: 'new', name: 'n'.repeat(121), kind: 'application' }).ok)
  check('an empty name is refused', !parseBindingRequest({ mode: 'new', name: '   ', kind: 'application' }).ok)
  const folder = parseBindingRequest({ mode: 'new', name: '  Nginx config ', kind: 'folder', path: ' /etc/nginx ', attribution: 'grouped' })
  check(
    'a folder target is accepted, trimmed, and keeps its path and attribution',
    folder.ok && folder.value.mode === 'new' && folder.value.name === 'Nginx config' && folder.value.path === '/etc/nginx' && folder.value.attribution === 'grouped',
  )
  const app = parseBindingRequest({ mode: 'new', name: 'Payments API', kind: 'application', path: '/ignored' })
  check('a path is dropped for kinds that do not take one', app.ok && app.value.mode === 'new' && app.value.path === null)

  check('no stored binding reads as null', agentBindingFromMetadata({ environment: 'prod' }) === null)
  const old = agentBindingFromMetadata({ assetId: 'abc', assetName: 'Legacy', assetType: 'server' })
  check('a pre-binding agent (assetId only) reads as a bound binding', old?.assetId === 'abc' && old.attribution === 'bound' && old.kind === 'server')
  const stored = agentBindingFromMetadata({ assetId: 'abc', binding: { assetId: 'abc', assetName: 'Profile A', kind: 'profile', attribution: 'grouped', createdForBinding: true } })
  check('a stored binding round-trips', stored?.kind === 'profile' && stored.attribution === 'grouped' && stored.createdForBinding === true)
  const stamp = bindingStamp(stored!, 'agent-1', '/etc/ssl/a.pem')
  check('a finding stamp records the target, the agent and what was observed', stamp.assetId === 'abc' && stamp.agentId === 'agent-1' && stamp.discoveredTarget === '/etc/ssl/a.pem')
}

/* ────────────────────────────────────────────────────────── 2. source ── */
function sourceChecks() {
  console.log('\n[2] Server wiring (source level)')
  const src = read('src/api-server/agent-scanner.ts')
  const enrol = src.slice(src.indexOf("router.post('/agents/enroll'"), src.indexOf("router.get('/agents',"))
  check('enrolment parses the binding with the shared model', /parseBindingRequest\(req\.body\?\.binding, req\.body\?\.metadata\?\.assetId\)/.test(enrol))
  check('enrolment resolves the binding before inserting the agent', enrol.indexOf('resolveBindingTarget(') > -1 && enrol.indexOf('resolveBindingTarget(') < enrol.indexOf("from('scanner_agents').insert"))
  check('enrolment removes a created target if the agent insert fails', /createdAssetId[\s\S]{0,200}from\('assets'\)\.delete\(\)/.test(enrol))
  const resolver = src.slice(src.indexOf('async function resolveBindingTarget'), src.indexOf('async function verifiedAgentBinding'))
  check('existing-asset lookup is tenant-scoped', /\.eq\('id', request\.assetId\)\s*\.eq\('user_id', userId\)/.test(resolver))
  check('a taken name is refused with 409, not duplicated', /BINDING_NAME_EXISTS/.test(resolver) && /status: 409/.test(resolver))
  const verifier = src.slice(src.indexOf('async function verifiedAgentBinding'), src.indexOf('function bindingMetadata'))
  check('upload-time verification is scoped to the agent\'s tenant', /\.eq\('user_id', agent\.user_id\)/.test(verifier))
  const evidenceRoute = src.slice(src.indexOf("router.post('/agent/evidence'"), src.indexOf("router.get('/agent/remediation/jobs'"))
  const runtimeRoute = src.slice(src.indexOf("router.post('/agent/runtime-events'"), src.indexOf("router.post('/agent/evidence'"))
  check('/agent/evidence re-verifies the binding and passes it to the pipeline', /verifiedAgentBinding\(client, agent\)/.test(evidenceRoute) && /binding,\s*\}\)/.test(evidenceRoute))
  check('/agent/runtime-events re-verifies the binding and passes it to the pipeline', /verifiedAgentBinding\(client, agent\)/.test(runtimeRoute) && /binding: runtimeBinding\.binding/.test(runtimeRoute))
  const rebind = src.slice(src.indexOf("router.put('/agents/:id/binding'"), src.indexOf("router.put('/agents/:id/policy'"))
  check('rebinding is ownership-checked', /\.eq\('id', req\.params\.id\)\s*\.eq\('user_id', user\.id\)/.test(rebind))
  check('rebinding is audit-logged with previous and next', /recordAgentAudit[\s\S]*previous,[\s\S]*next: resolution\.binding/.test(rebind))
  check('findings carry the binding they were filed under', /binding: binding \? bindingStamp\(binding, evidenceMatch\?\.agentId, assetName\) : null/.test(src))
}

/* ──────────────────────────────────────────────────────────── 3. live ── */
type Api = { status: number; body: any } // eslint-disable-line @typescript-eslint/no-explicit-any

async function live() {
  console.log(`\n[3] Live — ${BASE}`)
  const env = Object.fromEntries(
    fs.readFileSync(path.resolve('.env'), 'utf8')
      .split(/\r?\n/)
      .filter((line) => line.includes('=') && !line.startsWith('#'))
      .map((line) => {
        const i = line.indexOf('=')
        return [line.slice(0, i).trim(), line.slice(i + 1).trim().replace(/^["']|["']$/g, '')]
      }),
  )
  const admin = createClient(env.VITE_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
  const anon = createClient(env.VITE_SUPABASE_URL, env.VITE_SUPABASE_ANON_KEY, { auth: { persistSession: false } })

  let token = ''
  let userId = ''
  for (let attempt = 1; attempt <= 4 && !token; attempt += 1) {
    const { data: link, error: linkError } = await admin.auth.admin.generateLink({ type: 'magiclink', email: OWNER_EMAIL })
    const { data: verified, error: verifyError } = link?.properties?.hashed_token
      ? await anon.auth.verifyOtp({ type: 'magiclink', token_hash: link.properties.hashed_token })
      : { data: null, error: linkError }
    if (verified?.session) {
      token = verified.session.access_token
      userId = verified.user!.id
    } else {
      console.log(`  (session attempt ${attempt} failed: ${verifyError?.message || linkError?.message || 'no session'})`)
      await new Promise((r) => setTimeout(r, 2000 * attempt))
    }
  }
  if (!token) throw new Error('Could not mint a session for the test tenant')

  const api = async (p: string, init: RequestInit = {}): Promise<Api> => {
    const res = await fetch(`${BASE}${p}`, { ...init, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(init.headers || {}) } })
    const text = await res.text()
    let body: any = null // eslint-disable-line @typescript-eslint/no-explicit-any
    try { body = text ? JSON.parse(text) : null } catch { body = { raw: text.slice(0, 300) } }
    return { status: res.status, body }
  }

  const startedAt = new Date().toISOString()
  const stamp = Date.now().toString(36)
  const lab = fs.mkdtempSync(path.join(os.tmpdir(), 'qguard-binding-lab-'))
  buildLab(lab)
  const agentIds: string[] = []
  const agentNames: string[] = []
  const createdAssetIds: string[] = []

  const enrol = async (name: string, binding: unknown): Promise<Api & { id?: string; agentToken?: string }> => {
    const res = await api('/api/v1/agent-scanner/agents/enroll', {
      method: 'POST',
      body: JSON.stringify({
        name,
        role: 'scanner',
        environment: 'lab',
        hostname: os.hostname(),
        platform: `${os.platform()} ${os.arch()}`,
        version: '1.5.5',
        metadata: { role: 'scanner', environment: 'lab', source: 'agent-binding-live-check' },
        policy: { enabled: true, intervalSeconds: 60, scanTypes: ['certificates', 'pki', 'configs', 'libraries', 'packages', 'ssh'], allowedPaths: [lab], allowedTargets: [] },
        binding,
      }),
    })
    const id = res.body?.data?.agent?.id as string | undefined
    if (id) { agentIds.push(id); agentNames.push(name) }
    return { ...res, id, agentToken: res.body?.data?.enrollment?.agentToken }
  }
  const runAgent = (agentId: string, agentToken: string) => new Promise<{ code: number | null; err: string }>((resolve) => {
    const child = spawn(process.execPath, [RUNTIME, 'scan'], {
      env: {
        ...process.env,
        QGUARD_API_URL: BASE,
        QGUARD_AGENT_ID: agentId,
        QGUARD_AGENT_TOKEN: agentToken,
        QGUARD_AGENT_ROLE: 'scanner',
        QGUARD_NATIVE_RUNTIME_ENABLED: 'false',
        QGUARD_ENABLE_REMEDIATION: 'false',
        QGUARD_ENABLE_CONFIG_PATCHES: 'false',
        QGUARD_ENABLE_MIGRATION: 'false',
      },
      timeout: 240_000,
    })
    let err = ''
    child.stderr.on('data', (c) => { err += c })
    child.on('close', (code) => resolve({ code, err }))
  })
  const agentRow = async (id: string) => (await admin.from('scanner_agents').select('metadata').eq('id', id).single()).data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const inventoryOf = async (agentId: string) => ((await admin.from('crypto_inventory').select('id, asset_id, metadata').eq('user_id', userId).eq('metadata->evidenceRecord->>agentId', agentId)).data || []) as any[]

  try {
    /* ── refusals ── */
    console.log('\n  refusals')
    const missing = await enrol(`binding-missing-${stamp}`, { mode: 'existing', assetId: randomUUID() })
    check('binding to a non-existent asset is refused (404) and creates no agent', missing.status === 404 && missing.body?.error?.code === 'ASSET_NOT_FOUND' && !missing.id, `HTTP ${missing.status}`)
    const { data: foreign } = await admin.from('assets').select('id').neq('user_id', userId).limit(1).maybeSingle()
    if (foreign?.id) {
      const cross = await enrol(`binding-foreign-${stamp}`, { mode: 'existing', assetId: foreign.id })
      check('binding to ANOTHER tenant\'s asset is refused (404) — no tenant leakage', cross.status === 404 && !cross.id, `HTTP ${cross.status}`)
    } else {
      console.log('  (no foreign-tenant asset exists to test cross-tenant binding against)')
    }
    const noPath = await enrol(`binding-nopath-${stamp}`, { mode: 'new', name: `nopath-${stamp}`, kind: 'folder' })
    check('a folder target without a path is refused (400)', noPath.status === 400 && noPath.body?.error?.code === 'BINDING_INVALID' && !noPath.id, `HTTP ${noPath.status}`)
    const { data: noPathAsset } = await admin.from('assets').select('id').eq('user_id', userId).eq('name', `nopath-${stamp}`)
    check('a refused binding creates no asset', (noPathAsset || []).length === 0)

    /* ── bound: create a folder target ── */
    console.log('\n  bound — new folder target')
    const targetName = `Binding Check Folder ${stamp}`
    const a = await enrol(`binding-bound-${stamp}`, { mode: 'new', name: targetName, kind: 'folder', path: lab, owner: 'QA', attribution: 'bound' })
    check('enrolment with a new folder target succeeds', a.status === 200 && Boolean(a.id), `HTTP ${a.status} ${JSON.stringify(a.body?.error || '')}`)
    const { data: target } = await admin.from('assets').select('*').eq('user_id', userId).eq('name', targetName).maybeSingle()
    if (target?.id) createdAssetIds.push(target.id)
    check('the target asset was created in THIS tenant with its kind and path', target?.user_id === userId && target?.type === 'folder' && target?.metadata?.bindingPath === lab && target?.service_owner === 'QA')
    const aMeta = a.id ? (await agentRow(a.id))?.metadata : null
    check(
      'the agent records the server-resolved binding (and the legacy assetId in step)',
      aMeta?.binding?.assetId === target?.id && aMeta?.assetId === target?.id && aMeta?.binding?.attribution === 'bound' && aMeta?.binding?.createdForBinding === true,
    )

    const dup = await enrol(`binding-dup-${stamp}`, { mode: 'new', name: targetName, kind: 'application' })
    check('a taken target name is refused (409) and points at the existing asset', dup.status === 409 && dup.body?.error?.code === 'BINDING_NAME_EXISTS' && dup.body?.error?.detail?.asset?.id === target?.id && !dup.id, `HTTP ${dup.status}`)

    /* ── grouped: bind a second agent to the same target ── */
    const b = await enrol(`binding-grouped-${stamp}`, { mode: 'existing', assetId: target?.id, attribution: 'grouped' })
    check('a second agent binds to the existing target as grouped', b.status === 200 && Boolean(b.id))
    const bMeta = b.id ? (await agentRow(b.id))?.metadata : null
    check('the grouped binding is recorded as not created by it', bMeta?.binding?.attribution === 'grouped' && bMeta?.binding?.createdForBinding === false)

    const picker = await api('/api/v1/agent-installer/assets')
    const listed = (picker.body?.data?.assets || []).find((x: { id: string }) => x.id === target?.id)
    check('the asset picker lists the target with its kind, path and both agents', listed?.binding_kind === 'folder' && listed?.binding_path === lab && listed?.agents?.length === 2)

    /* ── run the shipped agent: bound ── */
    const runA = await runAgent(a.id!, a.agentToken!)
    check('the shipped agent completed a bound scan', runA.code === 0, `exit ${runA.code} ${runA.err.slice(0, 300)}`)
    const { data: evA } = await admin.from('scanner_evidence').select('asset_name, raw_evidence').eq('agent_id', a.id!)
    check('the bound agent uploaded evidence', (evA || []).length > 0, `${(evA || []).length} rows`)
    check('every evidence row records the binding it arrived under', (evA || []).every((r) => r.raw_evidence?.binding?.assetId === target?.id))
    const invA = await inventoryOf(a.id!)
    console.log(`        ${invA.length} CBOM rows from the bound agent`)
    check('the bound agent produced CBOM findings', invA.length > 0)
    check('EVERY bound finding is filed under the target asset', invA.length > 0 && invA.every((r) => r.asset_id === target?.id), JSON.stringify([...new Set(invA.map((r) => r.asset_id))]))
    check('each bound finding keeps what was actually observed', invA.every((r) => r.metadata?.binding?.assetId === target?.id && typeof r.metadata?.discoveredTarget === 'string' && r.metadata.discoveredTarget.length > 0))
    const { data: strayA } = await admin.from('assets').select('id').eq('user_id', userId).eq('metadata->>source', `agent:binding-bound-${stamp}`)
    check('the bound agent created NO per-target assets', (strayA || []).length === 0, `${(strayA || []).length} created`)
    const { data: expA } = await admin.from('crypto_exposures').select('asset_id').eq('user_id', userId).eq('metadata->evidenceRecord->>agentId', a.id!)
    check('exposures are filed under the target too', (expA || []).length > 0 && (expA || []).every((r) => r.asset_id === target?.id), `${(expA || []).length} exposures`)
    const { data: alertsA } = await admin.from('scanner_alerts').select('title').eq('agent_id', a.id!)
    check('alerts name the target', (alertsA || []).length > 0 && (alertsA || []).every((r) => String(r.title).includes(targetName)), `${(alertsA || []).length} alerts`)
    const { data: certsA } = await admin.from('certificates').select('asset_id').eq('user_id', userId).eq('metadata->>agentId', a.id!)
    check('certificates are linked to the target', (certsA || []).length > 0 && (certsA || []).every((r) => r.asset_id === target?.id), `${(certsA || []).length} certificates`)
    const { data: refreshed } = await admin.from('assets').select('criticality, metadata').eq('id', target!.id).single()
    const rb = refreshed?.metadata?.agentBinding
    const risk = refreshed?.metadata?.riskScore
    check('the target records its roll-up (targets observed, worst risk, last evidence)', rb?.targetCount > 0 && typeof rb?.worstTargetRisk === 'number' && Boolean(refreshed?.metadata?.last_scanned_at))
    check('the target\'s risk is the worst current risk of its targets', risk === rb?.worstTargetRisk && risk === Math.max(...(Object.values(rb?.targetRisk || {}) as number[])))
    const expectedCriticality = risk >= 80 ? 'critical' : risk >= 60 ? 'high' : risk >= 40 ? 'medium' : 'low'
    check('the target\'s criticality follows that risk', refreshed?.criticality === expectedCriticality, `${refreshed?.criticality} for risk ${risk}`)

    /* ── run the shipped agent: grouped ── */
    const runB = await runAgent(b.id!, b.agentToken!)
    check('the shipped agent completed a grouped scan', runB.code === 0, `exit ${runB.code} ${runB.err.slice(0, 300)}`)
    const invB = await inventoryOf(b.id!)
    check('the grouped agent produced CBOM findings', invB.length > 0)
    const { data: children } = await admin.from('assets').select('id, metadata, created_at').eq('user_id', userId).eq('metadata->>parentAssetId', target!.id)
    check('discovered assets are parented to the target', (children || []).length > 0 && (children || []).every((c) => c.metadata?.boundAgentId === b.id && c.metadata?.parentAssetName === targetName))
    check('grouped findings stay on their own assets', invB.some((r) => r.asset_id !== target?.id) && invB.every((r) => r.metadata?.binding?.attribution === 'grouped'))
    const { data: afterB } = await admin.from('assets').select('metadata').eq('id', target!.id).single()
    check('the target lists its grouped children', (afterB?.metadata?.agentBinding?.childAssetIds || []).length > 0)

    /* ── rebind ── */
    console.log('\n  rebind')
    if (foreign?.id) {
      const crossRebind = await api(`/api/v1/agent-scanner/agents/${a.id}/binding`, { method: 'PUT', body: JSON.stringify({ binding: { mode: 'existing', assetId: foreign.id } }) })
      check('rebinding to another tenant\'s asset is refused (404)', crossRebind.status === 404)
    }
    const ghost = await api(`/api/v1/agent-scanner/agents/${randomUUID()}/binding`, { method: 'PUT', body: JSON.stringify({ binding: { mode: 'none' } }) })
    check('rebinding an agent this tenant does not own is refused (404)', ghost.status === 404)
    const unbind = await api(`/api/v1/agent-scanner/agents/${a.id}/binding`, { method: 'PUT', body: JSON.stringify({ binding: { mode: 'none' } }) })
    const unboundMeta = (await agentRow(a.id!))?.metadata
    check('unbinding clears the binding and the legacy assetId', unbind.status === 200 && unboundMeta?.binding === null && unboundMeta?.assetId === null)
    const { data: audit } = await admin.from('audit_logs').select('details').eq('user_id', userId).eq('action', 'scanner_agent_binding_removed').eq('entity_id', a.id!)
    check('the unbind is audit-logged with the previous binding', (audit || []).some((r) => r.details?.previous?.assetId === target?.id))
    const invAAfter = await inventoryOf(a.id!)
    check('findings filed before the unbind stay filed under the target', invAAfter.filter((r) => r.asset_id === target?.id).length === invA.length)

    /* ── stale: target deleted after binding ── */
    console.log('\n  stale binding')
    const staleName = `Binding Check Stale ${stamp}`
    const c = await enrol(`binding-stale-${stamp}`, { mode: 'new', name: staleName, kind: 'application' })
    const staleId = c.id ? (await agentRow(c.id))?.metadata?.binding?.assetId : null
    check('a third agent binds to a new application target', c.status === 200 && Boolean(staleId))
    if (staleId) await admin.from('assets').delete().eq('id', staleId).eq('user_id', userId)
    const runC = await runAgent(c.id!, c.agentToken!)
    check('the shipped agent still completes when its target was deleted', runC.code === 0, `exit ${runC.code} ${runC.err.slice(0, 300)}`)
    const invC = await inventoryOf(c.id!)
    check('nothing is filed under the deleted target', invC.length > 0 && invC.every((r) => r.asset_id !== staleId))
    const { data: staleBeat } = await admin.from('agent_heartbeats').select('telemetry').eq('agent_id', c.id!).eq('status', 'binding_stale')
    check('the stale binding is reported on the agent\'s heartbeat trail', (staleBeat || []).some((r) => r.telemetry?.boundAssetId === staleId))
  } finally {
    console.log('\n  cleanup')
    for (const agentId of agentIds) {
      for (const table of ['crypto_inventory', 'pqc_scan_results', 'crypto_exposures']) {
        await admin.from(table).delete().eq('user_id', userId).eq('metadata->evidenceRecord->>agentId', agentId)
      }
      await admin.from('certificates').delete().eq('user_id', userId).eq('metadata->>agentId', agentId)
      for (const table of ['scanner_alerts', 'scanner_evidence', 'agent_heartbeats', 'scanner_agent_policies', 'runtime_crypto_events']) {
        await admin.from(table).delete().eq('user_id', userId).eq('agent_id', agentId)
      }
    }
    for (const name of agentNames) {
      for (const label of [`agent:${name}`, `agent-runtime:${name}`]) {
        await admin.from('pqc_scan_sessions').delete().eq('user_id', userId).eq('metadata->>sourceLabel', label)
        // Assets this run discovered (never older ones it merely updated).
        await admin.from('assets').delete().eq('user_id', userId).eq('metadata->>source', label).gte('created_at', startedAt)
      }
    }
    for (const id of createdAssetIds) {
      await admin.from('assets').delete().eq('user_id', userId).eq('metadata->>parentAssetId', id).gte('created_at', startedAt)
      await admin.from('assets').delete().eq('id', id).eq('user_id', userId)
    }
    if (agentIds.length) await admin.from('scanner_agents').delete().eq('user_id', userId).in('id', agentIds)
    fs.rmSync(lab, { recursive: true, force: true })
    console.log(`        removed ${agentIds.length} agents, ${createdAssetIds.length} target(s) and their rows`)
    const leftovers: string[] = []
    for (const agentId of agentIds) {
      const { count: inv } = await admin.from('crypto_inventory').select('id', { count: 'exact', head: true }).eq('user_id', userId).eq('metadata->evidenceRecord->>agentId', agentId)
      const { count: ev } = await admin.from('scanner_evidence').select('id', { count: 'exact', head: true }).eq('agent_id', agentId)
      if (inv || ev) leftovers.push(`${agentId}: ${inv} CBOM, ${ev} evidence`)
    }
    const { count: assetsLeft } = await admin.from('assets').select('id', { count: 'exact', head: true }).eq('user_id', userId).gte('created_at', startedAt)
    check('cleanup left no rows behind in the test tenant', leftovers.length === 0 && !assetsLeft, `${leftovers.join('; ')} · ${assetsLeft} new assets`)
  }
}

async function main() {
  modelChecks()
  sourceChecks()
  if (!OFFLINE_ONLY) await live()
  console.log(`\n${passed} passed, ${failures.length} failed`)
  if (failures.length) {
    for (const failure of failures) console.log(`  ✗ ${failure}`)
    process.exit(1)
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
