/**
 * Agent scope and write-authority — offline verification.
 *
 * Proves that what an operator selects in the Agent Center is what an agent
 * does, at every layer that decides it:
 *
 *  1. THE MODEL (src/lib/agent-installer/agent-scope.ts) — write authority is
 *     opt-in, migration implies remediation, the Scanner cannot hold runtime
 *     collectors, target parsing matches the runtime, and the scope contract
 *     refuses configurations that would collect nothing.
 *  2. THE SERVER, read at source level — enrolment derives capabilities from
 *     the authorisation, the per-poll write gate reads it, the installer bakes
 *     the host switch from it, and policy edits are ownership-checked and
 *     clamped. A refactor that drops one of these fails here.
 *  3. THE SHIPPED RUNTIME — tools/qguard-agent/dist/qguard-agent.cjs, run
 *     against a real lab folder with a local recording control plane, must
 *     collect only the surfaces selected and must drop runtime collectors
 *     from a Scanner whatever policy it is handed.
 *
 * Run: npx tsx tools/agent-scope-check.ts   (build the runtime first:
 *      npm run agent:release)
 */

import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import {
  AGENT_SCAN_MODULES,
  CONFIG_EVIDENCE_SURFACE,
  LOCAL_PROFILE_TO_AGENT_PRESET,
  agentPathIssue,
  authorityFromRequest,
  authorizedCapabilities,
  clampAgentScanTypes,
  configEvidenceInScope,
  matchScanPreset,
  parseAgentTarget,
  planAgentScope,
  presetForLocalProfile,
  resolveScanPreset,
  resolveWriteAuthority,
} from '../src/lib/agent-installer/agent-scope'
import { AGENT_ROLES } from '../src/lib/agent-installer/agent-release'
import { BASIC_AGENT_SCAN_TYPES, PRO_AGENT_SCAN_TYPES, agentScanTypesForTier } from '../src/lib/subscription-access'
import { profilesForMode } from '../src/lib/scanner/exposure/profiles'

let passed = 0
const failures: string[] = []
function check(label: string, condition: boolean, detail = ''): void {
  if (condition) passed += 1
  else failures.push(`${label}${detail ? ` — ${detail}` : ''}`)
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${!condition && detail ? ` — ${detail}` : ''}`)
}
function section(title: string): void {
  console.log(`\n── ${title}`)
}
const read = (file: string) => fs.readFileSync(path.resolve(file), 'utf8')

/* ═══════════════════════════════════════════════════════════════ 1. model ═ */

function modelChecks() {
  section('Write authority is opt-in, never granted by the role alone')
  for (const role of ['collector', 'scanner'] as const) {
    const auth = authorityFromRequest(role, { remediationAuthorized: true, migrationAuthorized: true })
    check(`${role}: authorisation requested → still read-only`, !auth.remediation && !auth.migration)
    const caps = authorizedCapabilities(role, auth)
    check(`${role}: persisted capabilities carry no write flag`, caps.remediation === false && caps.migration === false && !caps.config_patches)
  }
  const patcherNone = authorityFromRequest('patcher', {})
  check('patcher with nothing ticked → no write authority', !patcherNone.remediation && !patcherNone.migration)
  const patcherCaps = authorizedCapabilities('patcher', patcherNone)
  check('patcher unauthorised → remediation/config_patches false in capabilities', patcherCaps.remediation === false && patcherCaps.config_patches === false)
  check('patcher: the string "true" is not authorisation', !authorityFromRequest('patcher', { remediationAuthorized: 'true' }).remediation)
  const patcherYes = authorityFromRequest('patcher', { remediationAuthorized: true, migrationAuthorized: true })
  check('patcher authorised → remediation only (a Patcher never migrates)', patcherYes.remediation && !patcherYes.migration)
  check('patcher authorised → capabilities remediation + config_patches', authorizedCapabilities('patcher', patcherYes).remediation === true && authorizedCapabilities('patcher', patcherYes).config_patches === true)
  check('operator: migration without remediation → neither', (() => { const a = authorityFromRequest('operator', { migrationAuthorized: true }); return !a.remediation && !a.migration })())
  check('operator: both ticked → both', (() => { const a = authorityFromRequest('operator', { remediationAuthorized: true, migrationAuthorized: true }); return a.remediation && a.migration })())

  section('Persisted authority resolves honestly, including pre-fix rows')
  check('legacy patcher row (caps copied from role, operator ticked nothing) → not authorised',
    !resolveWriteAuthority('patcher', { remediation: true, config_patches: true }, { remediationAuthorized: false }).remediation)
  check('patcher row with caps true and no recorded decision → authorised (older enrolment path)',
    resolveWriteAuthority('patcher', { remediation: true }, {}).remediation)
  check('patcher row with caps false → not authorised', !resolveWriteAuthority('patcher', { remediation: false }, { remediationAuthorized: true }).remediation)
  check('collector row carrying remediation:true → still not authorised', !resolveWriteAuthority('collector', { remediation: true, migration: true }, { remediationAuthorized: true }).remediation)
  check('operator migration requires remediation on the row too',
    !resolveWriteAuthority('operator', { remediation: false, migration: true }, { migrationAuthorized: true }).migration)
  check('missing capabilities (column not selected) → not authorised', !resolveWriteAuthority('patcher', null, { remediationAuthorized: true }).remediation)

  section('Role ceiling on scan modules')
  const scannerClamp = clampAgentScanTypes('scanner', ['tls', 'runtime', 'ebpf', 'configs'], null)
  check('scanner: runtime / ebpf removed and reported', scannerClamp.deniedByRole.join() === 'runtime,ebpf' && scannerClamp.allowed.join() === 'tls,configs', JSON.stringify(scannerClamp))
  check('collector: runtime kept', clampAgentScanTypes('collector', ['runtime'], null).allowed.includes('runtime'))
  const planClamp = clampAgentScanTypes('collector', ['tls', 'kubernetes', 'vpn'], agentScanTypesForTier('basic'))
  check('basic plan: Pro surfaces removed and reported', planClamp.deniedByPlan.join() === 'kubernetes,vpn' && planClamp.allowed.join() === 'tls')
  check('junk and duplicates are dropped', (() => { const c = clampAgentScanTypes('collector', ['TLS', 'tls', 'rm -rf', 42, ''], null); return c.allowed.join() === 'tls' && c.rejected.length === 2 })())

  section('Target parsing matches the runtime')
  const t = (value: string) => { const p = parseAgentTarget(value); return p ? `${p.type}:${p.host}:${p.port}` : 'null' }
  check('host:443 → TLS', t('api.example.com:443') === 'tls:api.example.com:443')
  check('bare host → TLS 443', t('api.example.com') === 'tls:api.example.com:443')
  check('https://host → TLS 443', t('https://api.example.com') === 'tls:api.example.com:443')
  check('http://host:8443 → TLS 8443', t('http://api.example.com:8443') === 'tls:api.example.com:8443')
  check('ssh://host → SSH 22', t('ssh://build-01.internal') === 'ssh:build-01.internal:22')
  check('host:22 → SSH', t('10.0.0.5:22') === 'ssh:10.0.0.5:22')
  check('a path is not a target', t('/etc/nginx') === 'null')
  check('a non-numeric port is refused, not probed as NaN', t('host:abc') === 'null', t('host:abc'))
  check('a host with spaces or punctuation is refused', t('not a target!') === 'null' && t('tls://bad host:443') === 'null', `${t('not a target!')} / ${t('tls://bad host:443')}`)
  check('an out-of-range port is refused', t('api.example.com:70000') === 'null')
  check('IPv6 literal accepted', t('[2001:db8::1]:8443') === 'tls:[2001:db8::1]:8443', t('[2001:db8::1]:8443'))
  check('IPv4 accepted', t('192.168.1.10:443') === 'tls:192.168.1.10:443')

  section('Allowed-path hygiene')
  check('absolute POSIX path ok', agentPathIssue('/etc/nginx') === null)
  check('absolute Windows path ok', agentPathIssue('C:\\ProgramData\\nginx') === null)
  check('UNC path ok', agentPathIssue('\\\\fs01\\configs') === null)
  check('relative path flagged', agentPathIssue('etc/nginx') === 'relative')
  check('~ flagged (the agent never expands it)', agentPathIssue('~/app') === 'home-shorthand')
  check('a target in the paths list flagged', agentPathIssue('api.example.com:443') === 'looks-like-target' && agentPathIssue('https://x.y') === 'looks-like-target')

  section('Surface modules select configuration by surface')
  const only = (types: string[]) => new Set(types)
  check('configs keeps every surface and generic config', configEvidenceInScope('vpn-crypto-profile', only(['configs'])) && configEvidenceInScope('config-reference', only(['configs'])))
  check('kubernetes only → kubernetes config kept', configEvidenceInScope('kubernetes-crypto-policy', only(['kubernetes'])))
  check('kubernetes only → VPN config dropped', !configEvidenceInScope('vpn-crypto-profile', only(['kubernetes'])))
  check('kubernetes only → generic config dropped', !configEvidenceInScope('config-reference', only(['kubernetes'])))
  const agentSource = read('tools/qguard-agent/agent.ts')
  const unknownEvidence = Object.keys(CONFIG_EVIDENCE_SURFACE).filter((type) => !agentSource.includes(`'${type}'`))
  check('every mapped evidence type is one the runtime emits', unknownEvidence.length === 0, unknownEvidence.join(', '))
  const planned = new Set([...BASIC_AGENT_SCAN_TYPES, ...PRO_AGENT_SCAN_TYPES])
  const unplannable = AGENT_SCAN_MODULES.map((module) => module.id).filter((id) => !planned.has(id))
  check('every wizard module is in some plan (none is permanently locked)', unplannable.length === 0, unplannable.join(', '))

  section('The scope contract refuses configurations that collect nothing')
  const idle = planAgentScope({ role: 'collector', scanTypes: ['tls'], allowedTargets: [], allowedPaths: [] })
  check('TLS with no targets → idle, nothing collected, blocked', idle.modules.find((m) => m.id === 'tls')?.state === 'idle' && idle.collectsNothing && idle.blockers.length > 0)
  const runtimeOnly = planAgentScope({ role: 'collector', scanTypes: ['runtime'], allowedTargets: [], allowedPaths: [] })
  check('runtime needs no scope entry → active', runtimeOnly.modules.find((m) => m.id === 'runtime')?.state === 'active' && !runtimeOnly.collectsNothing)
  const scannerRuntime = planAgentScope({ role: 'scanner', scanTypes: ['runtime'], allowedTargets: [], allowedPaths: [] })
  check('scanner: runtime shown as role-excluded', scannerRuntime.modules.find((m) => m.id === 'runtime')?.state === 'role-excluded')
  const via = planAgentScope({ role: 'collector', scanTypes: ['configs'], allowedTargets: [], allowedPaths: ['/etc'] })
  check('surface off but configs on → "via Config files", not "off"', via.modules.find((m) => m.id === 'vpn')?.state === 'via-configs')
  const writeNoPath = planAgentScope({ role: 'patcher', scanTypes: ['tls'], allowedTargets: ['a.example:443'], allowedPaths: [], remediationAuthorized: true })
  check('patcher authorised with no path → blocked (writes are path-scoped)', writeNoPath.blockers.some((b) => /path/.test(b)))
  const readOnly = planAgentScope({ role: 'patcher', scanTypes: ['configs'], allowedTargets: [], allowedPaths: ['/etc'], remediationAuthorized: false })
  check('patcher unauthorised → contract says read-only', readOnly.wont.some((line) => /read-only/.test(line)) && !readOnly.authority.remediation)
  const locked = planAgentScope({ role: 'collector', scanTypes: ['tls'], allowedTargets: ['a:443'], allowedPaths: [], planPermitted: agentScanTypesForTier('basic') })
  check('basic plan: surfaces shown plan-locked', locked.modules.find((m) => m.id === 'kubernetes')?.state === 'plan-locked')

  section('Presets and the Local assessment hand-off')
  const localIds = profilesForMode('local').map((profile) => profile.id)
  const unmapped = localIds.filter((id) => !(id in LOCAL_PROFILE_TO_AGENT_PRESET))
  check('every Local assessment profile maps to an agent preset', unmapped.length === 0, unmapped.join(', '))
  check('supply-chain profile → libraries & dependencies preset', presetForLocalProfile('supply-chain') === 'supply-chain')
  check('scanner + runtime preset → runtime excluded, reported', resolveScanPreset('runtime', 'scanner', null).excluded.some((e) => e.id === 'runtime' && e.reason === 'role'))
  for (const role of AGENT_ROLES) {
    const modules = resolveScanPreset('role-default', role.id, null).modules
    check(`${role.label}: role default preset is non-empty and round-trips`, modules.length > 0 && matchScanPreset(modules, role.id, null) !== 'custom')
  }
}

/* ═════════════════════════════════════════════════════════ 2. server source ═ */

function sourceChecks() {
  section('Server enforcement points (source level)')
  const scanner = read('src/api-server/agent-scanner.ts')
  const enroll = scanner.slice(scanner.indexOf("router.post('/agents/enroll'"), scanner.indexOf("router.get('/agents'"))
  check('enrolment derives capabilities from the authorisation', /authorizedCapabilities\(resolvedRole, authority\)/.test(enroll))
  check('enrolment no longer spreads caller capabilities', !/\.\.\.\(typeof req\.body\?\.capabilities === 'object'/.test(enroll))
  check('enrolment records strict authority booleans', /remediationAuthorized: authority\.remediation/.test(enroll))
  check('enrolment applies the role ceiling', /clampPolicyScanTypes\(/.test(enroll))

  const policyPut = scanner.slice(scanner.indexOf("router.put('/agents/:id/policy'"), scanner.indexOf("router.put('/agents/:id/authority'"))
  check('policy edit 404s an agent the caller does not own', /AGENT_NOT_FOUND/.test(policyPut) && /\.eq\('user_id', user\.id\)/.test(policyPut))
  check('policy edit clamps to role and plan', /clampPolicyScanTypes\(/.test(policyPut))
  check('policy edit is audited', /scanner_agent_policy_updated/.test(policyPut))
  check('authority endpoint exists and re-checks the plan on grant', /router\.put\('\/agents\/:id\/authority'/.test(scanner) && /granting[\s\S]{0,200}decideAgentRole/.test(scanner))
  check('agent policy pull re-applies the role ceiling', /forRole\(/.test(scanner))

  const entitlement = read('src/api-server/agent-entitlement.ts')
  check('per-poll write gate reads the recorded authority', /resolveWriteAuthority\(role, agent\.capabilities, agent\.metadata\)/.test(entitlement))
  const installer = read('src/api-server/agent-installer.ts')
  check('installer host switch comes from recorded authority', /remediationEnabled: writeAuthority\.remediation/.test(installer) && /migrationEnabled: writeAuthority\.migration/.test(installer))
  const snapshots = read('src/api-server/migration-snapshots.ts')
  check('rollback executor lookup selects capabilities (else every rollback is refused)', /metadata, capabilities, user_id/.test(snapshots))
  const runtime = read('tools/qguard-agent/agent.ts')
  check('runtime uses the shared target parser', /return parseAgentTarget\(raw\)/.test(runtime))
  check('runtime applies the role ceiling', /clampAgentScanTypes\(AGENT_ROLE, policy\.scanTypes, null\)/.test(runtime))
  check('runtime filters configuration by surface', /configEvidenceInScope\(row\.evidenceType, scanTypes\)/.test(runtime))
}

/* ═══════════════════════════════════════════════════════ 3. shipped runtime ═ */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = Record<string, any>

async function runtimeChecks() {
  section('Shipped runtime honours the module selection')
  const bundle = path.resolve('tools/qguard-agent/dist/qguard-agent.cjs')
  if (!fs.existsSync(bundle)) {
    check('runtime bundle exists (run npm run agent:release)', false)
    return
  }
  const manifest = JSON.parse(read('tools/qguard-agent/dist/manifest.json'))
  const { AGENT_VERSION } = await import('../src/lib/agent-installer/agent-release')
  check(`bundle is the current build (${AGENT_VERSION})`, manifest.version === AGENT_VERSION, `manifest ${manifest.version}`)

  /* Fixed, digits-only directory name: the configuration classifier reads
     the whole path, and a random suffix could spell a surface keyword. */
  const lab = path.join(os.tmpdir(), `qguard-scoperun-${process.pid}`)
  fs.rmSync(lab, { recursive: true, force: true })
  fs.mkdirSync(path.join(lab, 'kube'), { recursive: true })
  fs.mkdirSync(path.join(lab, 'vpn'), { recursive: true })
  fs.mkdirSync(path.join(lab, 'app'), { recursive: true })
  fs.writeFileSync(path.join(lab, 'kube', 'ingress.yaml'), 'metadata:\n  annotations:\n    nginx.ingress.kubernetes.io/ssl-protocols: TLSv1.2\n')
  fs.writeFileSync(path.join(lab, 'vpn', 'client.ovpn'), 'cipher AES-256-GCM\ntls-version-min 1.2\n')
  fs.writeFileSync(path.join(lab, 'app', 'app.conf'), 'ssl_protocols TLSv1.2 TLSv1.3;\n')

  let policy: Json = {}
  let migrationJob: Json | null = null
  const evidence: Json[] = []
  const telemetry: Json[] = []
  const migrationReports: Json[] = []
  const recorder = http.createServer((req, res) => {
    let body = ''
    req.on('data', (chunk) => { body += chunk })
    req.on('end', () => {
      const url = req.url || ''
      const reply = (data: unknown) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ data })) }
      const parsed = (() => { try { return JSON.parse(body || '{}') } catch { return {} } })()
      if (url.endsWith('/agent/policy')) return reply({ policy, commands: [] })
      if (url.endsWith('/agent/evidence')) { evidence.push(...(parsed.evidence || [])); return reply({ evidenceCount: (parsed.evidence || []).length }) }
      if (url.endsWith('/agent/telemetry')) { telemetry.push(parsed); return reply({ accepted: true }) }
      if (url.endsWith('/agent/remediation/jobs')) return reply({ jobs: migrationJob ? [migrationJob] : [] })
      if (url.includes('/agent/remediation/jobs/')) {
        migrationReports.push(parsed)
        return reply({ accepted: true })
      }
      return reply({ accepted: true })
    })
  })
  await new Promise<void>((resolve) => recorder.listen(0, '127.0.0.1', () => resolve()))
  const port = (recorder.address() as { port: number }).port

  const run = (role: string, scanTypes: string[]) => {
    evidence.length = 0
    telemetry.length = 0
    policy = { enabled: true, intervalSeconds: 60, allowedTargets: [], allowedPaths: [lab], scanTypes, alertThreshold: 'moderate' }
    return new Promise<number | null>((resolve) => {
      const child = spawn(process.execPath, [bundle, 'scan'], {
        env: {
          ...process.env,
          QGUARD_API_URL: `http://localhost:${port}`,
          QGUARD_AGENT_ID: 'scope-check',
          QGUARD_AGENT_TOKEN: 'scope-check-token',
          QGUARD_AGENT_ROLE: role,
          QGUARD_ENVIRONMENT: 'lab',
          QGUARD_STATE_DIR: path.join(lab, 'state'),
          QGUARD_NATIVE_RUNTIME_ENABLED: 'false',
          QGUARD_ENABLE_REMEDIATION: migrationJob ? 'true' : 'false',
          QGUARD_ENABLE_CONFIG_PATCHES: 'false',
          QGUARD_ENABLE_MIGRATION: migrationJob ? 'true' : 'false',
        },
        timeout: 120_000,
      })
      child.stdout.resume()
      child.stderr.resume()
      child.on('close', (code) => resolve(code))
    })
  }
  const configTypes = () => [...new Set(evidence.filter((row) => /policy|profile|config-reference/.test(row.evidenceType)).map((row) => row.evidenceType))].sort()

  try {
    check('collector [configs] completes', (await run('collector', ['configs'])) === 0)
    const all = configTypes()
    check('configs → kubernetes, VPN and generic configuration all collected',
      all.includes('kubernetes-crypto-policy') && all.includes('vpn-crypto-profile') && all.includes('config-reference'), all.join(', '))

    check('collector [kubernetes] completes', (await run('collector', ['kubernetes'])) === 0)
    const kube = configTypes()
    check('kubernetes only → only Kubernetes configuration collected (previously: nothing)', kube.length > 0 && kube.every((type) => type === 'kubernetes-crypto-policy'), kube.join(', ') || 'none')

    check('collector [vpn] completes', (await run('collector', ['vpn'])) === 0)
    const vpn = configTypes()
    check('vpn only → only VPN profiles collected', vpn.length > 0 && vpn.every((type) => type === 'vpn-crypto-profile'), vpn.join(', ') || 'none')

    check('scanner [runtime, configs] completes', (await run('scanner', ['runtime', 'configs'])) === 0)
    const started = telemetry.find((row) => row.eventType === 'agent_scan_started')
    const ran = (started?.metadata?.scanTypes || []) as string[]
    check('scanner handed runtime by its policy → runs without it', ran.includes('configs') && !ran.includes('runtime'), JSON.stringify(ran))

    const emptyConfig = path.join(lab, 'app', 'empty.conf')
    fs.writeFileSync(emptyConfig, '')
    migrationJob = {
      id: 'scoped-validation', name: 'Selected asset', jobType: 'pqc_migration',
      adapter: 'local_configuration', target: 'tls://127.0.0.1:1',
      filePath: emptyConfig,
    }
    check('migration operator handles an unavailable validation target', (await run('operator', ['configs'])) === 0)
    const precheck = migrationReports.find((row) => row.eventType === 'agent-remediation-precheck')
    check('migration blocks an endpoint outside policy, even with a selected file in policy',
      precheck?.metadata?.probeFailure === 'The job endpoint is outside the agent policy.')
    check('a file with no readable configuration cannot produce passing validation',
      precheck?.validation?.passed === false && !migrationReports.some((row) => row.status === 'completed'))
  } finally {
    recorder.close()
    fs.rmSync(lab, { recursive: true, force: true })
  }
}

async function main() {
  console.log('\nAgent scope & write-authority check')
  modelChecks()
  sourceChecks()
  await runtimeChecks()
  console.log(`\n${failures.length === 0 ? `✓ ${passed} checks passed` : `✗ ${failures.length} failed, ${passed} passed`}`)
  for (const failure of failures) console.log(`   - ${failure}`)
  process.exitCode = failures.length === 0 ? 0 : 1
}

main().catch((error) => {
  console.error('agent scope check crashed:', error?.stack || error)
  process.exitCode = 1
})
