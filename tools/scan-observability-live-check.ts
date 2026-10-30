/**
 * Browser → command → real local agent scan → persisted inventory → receipt.
 * Creates isolated QA tenants through normal admin provisioning, signs in with
 * passwords, and deletes those tenants afterwards. Never impersonates a user.
 * Needs the dev server, Chrome and playwright-core in the QA scratch folder.
 * Run: npx tsx tools/scan-observability-live-check.ts
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import { randomUUID, generateKeyPairSync } from 'node:crypto'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { pathToFileURL } from 'node:url'

const BASE = process.env.QGUARD_TEST_BASE || 'http://localhost:3000'
const OUT = path.resolve('artifacts/scan-flow-qa')
const admin = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
const users: string[] = []
const results: string[] = []
const check = (ok: unknown, message: string) => { if (!ok) throw new Error(message); results.push(message); console.log(`PASS ${message}`) }
let browser: any
let qaPage: any
let activeChild: ReturnType<typeof spawn> | null = null
let lab: string | null = null

async function tenant() {
  const email = `scan-qa-${randomUUID()}@example.test`
  const password = randomUUID() + '!Qa9'
  const created = await admin.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { full_name: 'Isolated scan QA', qa_fixture: true } })
  if (created.error || !created.data.user) throw new Error(`QA tenant provisioning failed: ${created.error?.message}`)
  const id = created.data.user.id
  users.push(id)
  const sub = await admin.from('billing_subscriptions').insert({ user_id: id, subscription_id: `qa-${randomUUID()}`, plan: 'Pro', status: 'trial', metadata: { qa_fixture: true } })
  if (sub.error) throw new Error(`QA trial provisioning failed: ${sub.error.message}`)
  const auth = createClient(process.env.VITE_SUPABASE_URL!, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const signed = await auth.auth.signInWithPassword({ email, password })
  if (signed.error || !signed.data.session) throw new Error('Normal QA sign-in failed')
  return { id, session: signed.data.session, auth }
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true })
  const owner = await tenant()
  const other = await tenant()
  const request = async (endpoint: string, init: RequestInit = {}, token = owner.session.access_token) => {
    const response = await fetch(`${BASE}${endpoint}`, { ...init, signal: AbortSignal.timeout(60_000), headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...init.headers } })
    const body = await response.json()
    return { status: response.status, body }
  }
  lab = fs.mkdtempSync(path.join(os.tmpdir(), 'qguard-scan-observability-'))
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 })
  fs.writeFileSync(path.join(lab, 'qa-rsa.key'), key.privateKey.export({ type: 'pkcs8', format: 'pem' }))
  fs.writeFileSync(path.join(lab, 'qa-rsa-public.pem'), key.publicKey.export({ type: 'spki', format: 'pem' }))
  fs.writeFileSync(path.join(lab, 'nginx.conf'), 'ssl_protocols TLSv1 TLSv1.2;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n')
  fs.writeFileSync(path.join(lab, 'package.json'), JSON.stringify({ name: 'isolated-crypto-qa', dependencies: { 'node-forge': '1.0.0' } }))
  const enrolled = await request('/api/v1/agent-scanner/agents/enroll', { method: 'POST', body: JSON.stringify({
    name: 'QA Windows collector', role: 'collector', hostname: os.hostname(), platform: os.platform(), version: '1.6.1', environment: 'lab',
    metadata: { role: 'collector', source: 'isolated-scan-observability-qa', qa_fixture: true },
    policy: { enabled: true, intervalSeconds: 60, allowedPaths: [lab], allowedTargets: [], scanTypes: ['certificates', 'pki', 'configs', 'libraries', 'packages', 'ssh'], alertThreshold: 'moderate' },
  }) })
  const agentId = enrolled.body?.data?.agent?.id
  const agentToken = enrolled.body?.data?.enrollment?.agentToken
  check(enrolled.status === 200 && agentId && agentToken, 'isolated collector enrolled with a scoped local test lab')

  const playwright = await import(pathToFileURL(path.join(OUT, 'runtime/node_modules/playwright-core/index.mjs')).href)
  browser = await playwright.chromium.launch({ channel: 'chrome', headless: true })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1100 }, reducedMotion: 'reduce' })
  const authKey = `sb-${new URL(process.env.VITE_SUPABASE_URL!).hostname.split('.')[0]}-auth-token`
  await context.addInitScript(({ key, session }: any) => { if (!localStorage.getItem(key)) localStorage.setItem(key, JSON.stringify(session)); localStorage.setItem('qguard-theme-mode-v1', 'dark') }, { key: authKey, session: owner.session })
  const page = await context.newPage()
  qaPage = page
  const pageErrors: string[] = []
  page.on('pageerror', (error: Error) => pageErrors.push(error.message))
  await page.goto(`${BASE}/downloads`, { waitUntil: 'domcontentloaded', timeout: 90_000 })
  const row = page.getByRole('row').filter({ hasText: 'QA Windows collector' })
  await row.waitFor({ timeout: 60_000 })
  const scanButton = row.getByRole('button', { name: /scan/i })
  await scanButton.click()
  await page.waitForURL(/dashboard\/live-migration\?.*commandId=/, { timeout: 30_000 })
  const firstCommand = new URL(page.url()).searchParams.get('commandId')!
  check(new URL(page.url()).searchParams.get('agentId') === agentId && new URL(page.url()).hash === '#agent-workflow', 'Downloads Scan redirects to the selected command and workflow panel')
  const panel = page.getByRole('region', { name: 'Requested scan progress' })
  await panel.getByRole('heading', { name: 'Queued', exact: true }).waitFor({ timeout: 30_000 })
  check(true, 'queued command renders honestly before the agent runs')
  await page.screenshot({ path: path.join(OUT, 'queued.png'), fullPage: false })

  const unauth = await fetch(`${BASE}/api/v1/agent-installer/agents/${agentId}/scan-status?commandId=${firstCommand}`)
  check(unauth.status === 401, 'scan receipt rejects unauthenticated reads')
  const foreign = await request(`/api/v1/agent-installer/agents/${agentId}/scan-status?commandId=${firstCommand}`, {}, other.session.access_token)
  check(foreign.status === 404, 'another tenant cannot read this agent’s scan receipt')
  const duplicate = await request(`/api/v1/agent-installer/agents/${agentId}/scan`, { method: 'POST' })
  check(duplicate.body.data?.command?.id === firstCommand, 'repeated clicks reuse the pending command')

  const runAgent = async () => {
    const child = spawn(process.execPath, [path.resolve('tools/qguard-agent/dist/qguard-agent.cjs'), 'scan'], {
      env: { ...process.env, QGUARD_API_URL: BASE, QGUARD_ENVIRONMENT: 'development', QGUARD_AGENT_ROLE: 'collector', QGUARD_AGENT_ID: agentId, QGUARD_AGENT_TOKEN: agentToken, QGUARD_TENANT_ID: owner.id, QGUARD_STATE_DIR: path.join(lab!, 'agent-state'), QGUARD_NATIVE_RUNTIME_ENABLED: 'false', QGUARD_ENABLE_REMEDIATION: 'false', QGUARD_ENABLE_CONFIG_PATCHES: 'false', QGUARD_ENABLE_MIGRATION: 'false' },
      windowsHide: true, timeout: 240_000,
    })
    activeChild = child
    let out = '', err = ''
    child.stdout.on('data', (chunk) => { out += chunk })
    child.stderr.on('data', (chunk) => { err += chunk })
    const code = await new Promise((resolve, reject) => { child.on('error', reject); child.on('close', resolve) })
    activeChild = null
    check(code === 0, `real local agent scan exits successfully${code === 0 ? '' : `: ${err.slice(-500)} ${out.slice(-500)}`}`)
  }
  await runAgent()
  await panel.getByRole('heading', { name: 'Completed', exact: true }).waitFor({ timeout: 60_000 })
  const tracked = await request(`/api/v1/agent-installer/agents/${agentId}/scan-status?commandId=${firstCommand}`)
  check(tracked.body.data?.state === 'completed' && tracked.body.data.acceptedCount > 0, 'completed receipt records actual accepted evidence')
  const { data: assets, error: assetError } = await admin.from('assets').select('id, metadata').eq('user_id', owner.id)
  check(!assetError && assets?.some((asset) => asset.metadata?.scanSources?.some((source: any) => source.agentId === agentId && source.kind === 'windows-device')), 'real scan materializes tenant assets with Windows agent provenance')
  await page.screenshot({ path: path.join(OUT, 'completed.png'), fullPage: false })
  await page.reload({ waitUntil: 'domcontentloaded' })
  await page.getByRole('region', { name: 'Requested scan progress' }).getByRole('heading', { name: 'Completed', exact: true }).waitFor({ timeout: 60_000 })
  check(true, 'completed command survives a browser reload')

  // A real new cycle must never reset the first command’s receipt.
  await runAgent()
  const stable = await request(`/api/v1/agent-installer/agents/${agentId}/scan-status?commandId=${firstCommand}`)
  check(stable.body.data?.completedAt === tracked.body.data?.completedAt && stable.body.data?.state === 'completed', 'a later real scan cannot reset an earlier requested scan outcome')
  await page.getByRole('link', { name: /View collected assets/ }).click()
  await page.waitForURL(/dashboard\/assets\?agentId=/)
  await page.getByLabel('Discovery source').waitFor({ timeout: 60_000 })
  await page.getByRole('table').getByText('Windows device', { exact: true }).first().waitFor({ timeout: 60_000 })
  check(new URL(page.url()).searchParams.get('agentId') === agentId, 'result link opens live Assets & CBOM filtered to the actual agent')
  await page.screenshot({ path: path.join(OUT, 'assets.png'), fullPage: false })
  await page.getByLabel('Discovery source').selectOption('cloud')
  await page.getByText(/No assets match/i).waitFor({ timeout: 15_000 })
  check(true, 'source filter excludes assets of another discovery kind')

  await page.goto(`${BASE}/dashboard/agents?view=collectors`, { waitUntil: 'domcontentloaded' })
  await page.getByText('QA Windows collector', { exact: true }).first().click({ timeout: 60_000 })
  await page.getByRole('button', { name: 'Scan authorized scope', exact: true }).click({ timeout: 30_000 })
  await page.waitForURL(/dashboard\/live-migration\?.*commandId=/, { timeout: 30_000 })
  check(new URL(page.url()).searchParams.get('agentId') === agentId, 'collector drawer queues a real command and redirects to its progress panel')
  await page.goto(`${BASE}/downloads`, { waitUntil: 'domcontentloaded' })
  await page.getByRole('row').filter({ hasText: 'QA Windows collector' }).getByRole('button', { name: 'Open agent, generate installer' }).click({ timeout: 60_000 })
  await page.getByRole('button', { name: 'Run scan', exact: true }).click({ timeout: 30_000 })
  await page.waitForURL(/dashboard\/live-migration\?.*commandId=/, { timeout: 30_000 })
  check(new URL(page.url()).searchParams.get('agentId') === agentId, 'Downloads detail drawer also redirects to the exact queued scan')
  await page.setViewportSize({ width: 390, height: 844 })
  await page.reload({ waitUntil: 'domcontentloaded' })
  await page.getByRole('region', { name: 'Requested scan progress' }).getByRole('heading', { name: 'Queued', exact: true }).waitFor({ timeout: 30_000 })
  const headingTop = await page.getByRole('region', { name: 'Requested scan progress' }).getByRole('heading', { name: 'Queued', exact: true }).boundingBox()
  check(headingTop && headingTop.y >= 64, 'mobile scan heading remains visible below the fixed navigation bar')
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)
  check(!overflow, 'requested scan view fits a mobile viewport without horizontal page overflow')
  await page.screenshot({ path: path.join(OUT, 'mobile.png'), fullPage: false })
  check(pageErrors.length === 0, `browser has no unhandled JavaScript errors${pageErrors.length ? `: ${pageErrors.join('; ')}` : ''}`)
  fs.writeFileSync(path.join(OUT, 'verification.json'), JSON.stringify({ verifiedAt: new Date().toISOString(), results }, null, 2))
  await owner.auth.auth.signOut({ scope: 'local' })
  await other.auth.auth.signOut({ scope: 'local' })
}

try { await main() }
catch (error) {
  console.error(error instanceof Error ? error.message : error)
  if (qaPage) {
    await qaPage.screenshot({ path: path.join(OUT, 'failure.png'), fullPage: false }).catch(() => undefined)
    console.error('Browser location:', new URL(qaPage.url()).pathname)
  }
  process.exitCode = 1
}
finally {
  activeChild?.kill()
  if (browser) await browser.close()
  for (const id of users) {
    const removed = await admin.auth.admin.deleteUser(id)
    if (removed.error) { console.error(`QA tenant cleanup failed: ${removed.error.message}`); process.exitCode = 1 }
  }
  // Resolve and check the generated lab path before recursive deletion.
  if (lab && path.dirname(path.resolve(lab)) === path.resolve(os.tmpdir()) && path.basename(lab).startsWith('qguard-scan-observability-')) fs.rmSync(lab, { recursive: true, force: true })
  console.log(`Live scan observability verification: ${results.length} checks; isolated test tenants removed.`)
}
