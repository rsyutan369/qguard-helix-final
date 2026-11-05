/** Offline regression checks for configuration isolation, diagnostics, and install status. */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { generateInstaller, type InstallerContext } from '../src/lib/agent-installer/installer-templates'
import { installationAttention } from '../src/lib/agent-installer/installation-status'
import { configureAgentLog, loadAgentConfig } from './qguard-agent/runtime-bootstrap'

let passed = 0
function check(name: string, run: () => void) { run(); console.log(`PASS ${name}`); passed++ }
const dir = mkdtempSync(path.join(os.tmpdir(), 'qguard-startup-'))
const one = path.join(dir, 'collector.env')
const two = path.join(dir, 'scanner with spaces.env')
writeFileSync(one, 'QGUARD_AGENT_ID=collector\nQGUARD_AGENT_TOKEN=collector-secret\n')
writeFileSync(two, 'QGUARD_AGENT_ID=scanner\nQGUARD_AGENT_TOKEN=scanner-secret\nIGNORED_OTHER_VAR=bad\n')
try {
  check('explicit config selects Scanner independently of legacy/env config', () => {
    const env = { QGUARD_CONFIG: one } as NodeJS.ProcessEnv
    assert.equal(loadAgentConfig(['watch', '--config', two], env), two)
    assert.equal(env.QGUARD_AGENT_ID, 'scanner')
    assert.equal(env.QGUARD_AGENT_TOKEN, 'scanner-secret')
    assert.equal(env.IGNORED_OTHER_VAR, undefined)
  })
  check('each process loads its own identity; explicit environment override preserved', () => {
    const collector: NodeJS.ProcessEnv = {}
    const scanner: NodeJS.ProcessEnv = { QGUARD_AGENT_TOKEN: 'override' }
    loadAgentConfig(['watch', '--config', one], collector)
    loadAgentConfig(['watch', '--config', two], scanner)
    assert.equal(collector.QGUARD_AGENT_ID, 'collector')
    assert.equal(scanner.QGUARD_AGENT_ID, 'scanner')
    assert.equal(scanner.QGUARD_AGENT_TOKEN, 'override')
  })
  check('missing explicit config fails closed instead of using another agent', () => {
    assert.throws(() => loadAgentConfig(['watch', '--config', path.join(dir, 'missing.env')], { QGUARD_CONFIG: one }), /Cannot read selected/)
    assert.throws(() => loadAgentConfig(['watch', '--config'], {}), /requires an absolute/)
    assert.throws(() => loadAgentConfig(['watch', '--config', 'relative.env'], {}), /must be absolute/)
  })
  check('startup log persists errors, redacts tokens, and rotates at 2 MiB', () => {
    const log = path.join(dir, 'agent.log')
    const original = { log: console.log, info: console.info, warn: console.warn, error: console.error }
    try {
      configureAgentLog({ QGUARD_LOG_FILE: log, QGUARD_AGENT_TOKEN: 'fixture-secret' })
      console.error('startup request failed: %s', 'fixture-secret')
      assert.match(readFileSync(log, 'utf8'), /ERROR startup request failed: \[REDACTED\]/)
      assert.ok(!readFileSync(log, 'utf8').includes('fixture-secret'))
      writeFileSync(log, 'x'.repeat(2 * 1024 * 1024))
      console.warn('rotation check')
      assert.equal(readFileSync(`${log}.1`, 'utf8').length, 2 * 1024 * 1024)
      assert.ok(readFileSync(log, 'utf8').length < 200)
    } finally { Object.assign(console, original) }
  })
  const now = Date.now()
  const event = (phase: string, age: number, message: string | null = null) => ({ at: new Date(now - age).toISOString(), phase, status: `install:${phase}`, message })
  check('task Running without heartbeat becomes Needs attention after two minutes', () => {
    assert.equal(installationAttention([event('service_started', 121_000)], false, now)?.kind, 'delayed')
    assert.equal(installationAttention([event('service_started', 10_000)], false, now), null)
  })
  check('reported failures surface; a new installation clears older failures', () => {
    assert.equal(installationAttention([event('failed', 10_000, 'startup error')], false, now)?.message, 'startup error')
    assert.equal(installationAttention([event('failed', 20_000), event('installation_started', 1000)], false, now), null)
    assert.equal(installationAttention([event('failed', 10_000)], true, now), null)
  })
  const context: InstallerContext = {
    apiUrl: 'http://127.0.0.1:3000', tenantId: 'fixture-tenant', agentId: '11111111-1111-4111-8111-111111111111',
    agentToken: 'fixture-token', agentName: 'Scanner fixture', role: 'scanner', environment: 'lab', controlPlaneEnvironment: 'development',
    version: '1.6.2', runtimeSha256: 'a'.repeat(64), generatedAt: new Date().toISOString(), generatedBy: 'offline-startup-check',
    remediationEnabled: false, migrationEnabled: false,
    policy: { intervalSeconds: 30, allowedTargets: [], allowedPaths: ['C:\\Scan Lab'], scanTypes: ['certificates'], alertThreshold: 'moderate' },
  }
  const script = generateInstaller('windows', context).content
  check('generated Windows installer uses isolated task/config, preserves keys, and requires this launch heartbeat', () => {
    assert.ok(script.includes('QGuardHelix\\Agents'))
    assert.ok(script.includes('QGuardHelixAgent-$AgentSlot'))
    assert.ok(script.includes('watch --config'))
    assert.ok(script.indexOf('Stop-AgentTask $TaskName', script.indexOf('# --- 3.')) < script.indexOf('Move-Item -Force -LiteralPath $TempRuntime'))
    assert.ok(script.includes('Copy-Item -LiteralPath $LegacyKey -Destination $SigningKey'))
    assert.ok(script.includes('$status.data.runtimeLaunchId -eq $LaunchId'))
    assert.ok(script.includes("Report-Phase 'failed' \"Heartbeat verification failed:"))
    assert.ok(!script.includes("$taskState -eq 'Running' -or $taskState -eq 'Ready'"))
    assert.ok(script.includes('IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'))
  })
  if (process.platform === 'win32') check('Windows PowerShell 5.1 parses the generated installer', () => {
    const file = path.join(dir, 'installer.ps1')
    writeFileSync(file, script)
    const parse = "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:QGUARD_PARSE_FILE,[ref]$null,[ref]$e); if($e.Count){$e | ForEach-Object { $_.Message }; exit 1}"
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', parse], { env: { ...process.env, QGUARD_PARSE_FILE: file }, stdio: 'pipe' })
  })
  console.log(`${passed} startup checks passed`)
} finally { rmSync(dir, { recursive: true, force: true }) }
