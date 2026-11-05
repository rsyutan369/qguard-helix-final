/**
 * Real PowerShell installers + agent processes against an isolated local server.
 * Scheduler, ACL and PowerShell HTTP cmdlets are test adapters. HTTP traffic and
 * Node agent processes are real; no host SYSTEM task is touched.
 */
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { generateInstaller, type InstallerContext } from '../src/lib/agent-installer/installer-templates'
import { AGENT_VERSION } from '../src/lib/agent-installer/agent-release'
import { createNonceStore, supportedAlgorithms, verifyRequest, type BoundKeys } from '../src/lib/agent-installer/agent-request-signing'

if (process.platform !== 'win32') throw new Error('This regression check requires Windows PowerShell 5.1')
const scanner = '11111111-1111-4111-8111-111111111111'
const collector = '22222222-2222-4222-8222-222222222222'
const runtime = readFileSync('tools/qguard-agent/dist/qguard-agent.cjs')
const state = new Map<string, { connected: boolean; runtimeLaunchId: string | null; key: BoundKeys | null }>(
  [scanner, collector].map((id) => [id, { connected: false, runtimeLaunchId: null, key: null }]),
)
const nonceSeen = createNonceStore()
let signed = 0
const server = createServer(async (req, res) => {
  const reply = (code: number, body: unknown) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)) }
  try {
    const id = String(req.headers['x-qguard-agent-id'] || '')
    const agent = state.get(id)
    const token = id === scanner ? 'scanner-fixture-token' : 'collector-fixture-token'
    if (!agent || req.headers['x-qguard-agent-token'] !== token) return reply(401, { error: { message: 'fixture credential refused' } })
    const buffers: Buffer[] = []
    for await (const chunk of req) buffers.push(Buffer.from(chunk))
    const raw = Buffer.concat(buffers)
    if (req.url?.startsWith('/api/v1/agent-scanner/')) {
      const result = verifyRequest({ method: req.method!, originalUrl: req.url!, agentId: id, headers: req.headers as Record<string, string>, rawBody: raw, bound: agent.key, nonceSeen, verifiable: supportedAlgorithms() })
      assert.ok(result.ok, result.failure)
      if (!agent.key) agent.key = result.presentedKeys || null
      signed++
    }
    if (req.url?.endsWith('/runtime')) { res.writeHead(200, { 'Content-Type': 'application/javascript' }); return void res.end(runtime) }
    if (req.url?.endsWith('/installation-event')) return reply(200, { data: { accepted: true } })
    if (req.url?.endsWith('/self')) return reply(200, { data: { ...agent, key: undefined, connectionState: agent.connected ? 'Connected' : 'Waiting', lastSeenAt: agent.connected ? new Date().toISOString() : null } })
    if (req.url?.endsWith('/agent/policy')) return reply(200, { data: { policy: { enabled: false, intervalSeconds: 30, allowedPaths: [], allowedTargets: [], scanTypes: [] }, commands: [] } })
    if (req.url?.endsWith('/agent/heartbeat')) {
      const payload = JSON.parse(raw.toString())
      agent.connected = true
      agent.runtimeLaunchId = payload.telemetry?.process?.launchId || null
      return reply(200, { data: { accepted: true } })
    }
    reply(404, { error: { message: 'unknown fixture route' } })
  } catch (error) { reply(500, { error: { message: (error as Error).message } }) }
})
await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
const address = server.address()
assert.ok(address && typeof address !== 'string')
const base = `http://127.0.0.1:${address.port}`
const dir = mkdtempSync(path.join(os.tmpdir(), 'qguard windows startup '))
try {
  copyFileSync('tools/qguard-agent/dist/qguard-agent.cjs', path.join(dir, 'qguard-agent.cjs'))
  writeFileSync(path.join(dir, 'http-client.cjs'), `
const fs = require('node:fs');
(async () => {
  const input = JSON.parse(fs.readFileSync(0, 'utf8').replace(/^\\uFEFF/, ''));
  const headers = input.headers || {};
  if (input.contentType) headers['content-type'] = input.contentType;
  const response = await fetch(input.uri, { method: input.method.toUpperCase(), headers, body: input.body || undefined, redirect: 'error', signal: AbortSignal.timeout(input.timeout * 1000) });
  if (!response.ok) throw new Error('Fixture HTTP ' + response.status + ': ' + await response.text());
  if (input.outFile) { fs.writeFileSync(input.outFile, Buffer.from(await response.arrayBuffer())); console.log('{}'); }
  else console.log(await response.text());
})().catch(error => { console.error(error.message); process.exit(1); });
`)
  for (const [name, id, role] of [['scanner', scanner, 'scanner'], ['collector', collector, 'collector']] as const) {
    const context: InstallerContext = {
      apiUrl: base, tenantId: 'startup-fixture-tenant', agentId: id, agentToken: `${name}-fixture-token`, agentName: name, role,
      environment: 'lab', controlPlaneEnvironment: 'development', version: AGENT_VERSION,
      runtimeSha256: createHash('sha256').update(runtime).digest('hex'),
      policy: { intervalSeconds: 30, allowedPaths: [], allowedTargets: [], scanTypes: [], alertThreshold: 'moderate' },
      remediationEnabled: false, migrationEnabled: false, generatedAt: new Date().toISOString(), generatedBy: 'isolated-windows-startup-check',
    }
    const original = generateInstaller('windows', context).content
    // Only the test copy skips elevation. Scheduler/ACL calls resolve to local
    // harness functions; the production artifact retains its elevation check.
    const guard = 'if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))'
    assert.ok(original.includes(guard))
    writeFileSync(path.join(dir, `${name}.ps1`), original.replace(guard, 'if ($false)'))
  }
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('QGUARD_')))
  const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'tools/agent-installer-tests/windows-startup-harness.ps1', '-FixtureRoot', dir, '-BaseUrl', base, '-ScannerId', scanner, '-CollectorId', collector], { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.on('data', (chunk) => process.stdout.write(chunk))
  child.stderr.on('data', (chunk) => process.stderr.write(chunk))
  const exit = await new Promise<number | null>((resolve, reject) => { child.on('error', reject); child.on('close', resolve) })
  assert.equal(exit, 0, 'PowerShell startup harness failed')
  assert.ok(signed >= 8, `Expected policy and heartbeat requests from four real process starts; got ${signed}`)
  console.log(`PASS ${signed} actual agent requests verified cryptographically; no production data or tasks touched`)
} finally {
  server.closeAllConnections()
  await new Promise<void>((resolve) => server.close(() => resolve()))
  rmSync(dir, { recursive: true, force: true })
}
