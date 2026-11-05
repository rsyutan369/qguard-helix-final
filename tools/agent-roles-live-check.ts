/**
 * Live proof that each agent TYPE does what its definition says.
 *
 *   Collector  — discovers and collects cryptographic assets, configurations,
 *                certificates, key metadata, dependencies, protocols, identities.
 *   Scanner    — analyses collected evidence and accurately identifies
 *                quantum-vulnerable algorithms, certificates, protocols, configs.
 *   Patcher    — performs only explicitly approved remediation on authorised paths.
 *   Operator   — executes only approved migration jobs and live migration operations.
 *
 * Nothing here is a fixture. It builds a real lab — OpenSSL-issued RSA, ECDSA and
 * ML-DSA-65 certificates, real private keys (one encrypted), a JWKS, SAML
 * metadata, config files, a package manifest, an SSH key — and two live local TLS
 * servers, one accepting only the hybrid X25519MLKEM768 group and one only
 * classical X25519. It then runs the SHIPPED agent bundle
 * (tools/qguard-agent/dist/qguard-agent.cjs) once per role, with the exact
 * environment the installers write, and asserts on what reached the database.
 *
 * Needs the dev server on :3000, OpenSSL 3.5+ and ssh-keygen on PATH.
 *   npx tsx tools/agent-roles-live-check.ts
 *
 * Every row it creates belongs to the test tenant; run tools/platform-reset.ts
 * --user <id> --apply afterwards to return that tenant to an empty estate.
 */
import { createClient } from '@supabase/supabase-js'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { buildLab, sha256File, startTlsServer } from './agent-lab'

const BASE = process.env.QGUARD_TEST_BASE || 'http://localhost:3000'
const OWNER_EMAIL = process.env.QGUARD_TEST_EMAIL || 'zachmatthew369@gmail.com'
const RUNTIME = path.resolve('tools/qguard-agent/dist/qguard-agent.cjs')

const env = Object.fromEntries(
  fs.readFileSync(new URL('../.env', import.meta.url), 'utf8')
    .split(/\r?\n/)
    .filter((line) => line.includes('=') && !line.startsWith('#'))
    .map((line) => {
      const i = line.indexOf('=')
      return [line.slice(0, i).trim(), line.slice(i + 1).trim().replace(/^["']|["']$/g, '')]
    }),
)
const admin = createClient(env.VITE_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
const anon = createClient(env.VITE_SUPABASE_URL, env.VITE_SUPABASE_ANON_KEY, { auth: { persistSession: false } })

let passed = 0
let failed = 0
const failures: string[] = []
function check(name: string, condition: boolean, detail = '') {
  if (condition) { passed += 1; console.log(`  PASS  ${name}`) }
  else { failed += 1; failures.push(`${name}${detail ? ` — ${detail}` : ''}`); console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`) }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function api(p: string, token: string, init: any = {}) {
  const res = await fetch(`${BASE}${p}`, { ...init, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(init.headers || {}) } })
  const text = await res.text()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let body: any = null
  try { body = text ? JSON.parse(text) : null } catch { body = { raw: text.slice(0, 300) } }
  return { status: res.status, body }
}

/* ────────────────────────────────────────────────────────── agents ── */

const ROLE_ENV: Record<string, Record<string, string>> = {
  collector: { QGUARD_ENABLE_REMEDIATION: 'false', QGUARD_ENABLE_CONFIG_PATCHES: 'false', QGUARD_ENABLE_MIGRATION: 'false' },
  scanner: { QGUARD_ENABLE_REMEDIATION: 'false', QGUARD_ENABLE_CONFIG_PATCHES: 'false', QGUARD_ENABLE_MIGRATION: 'false' },
  patcher: { QGUARD_ENABLE_REMEDIATION: 'true', QGUARD_ENABLE_CONFIG_PATCHES: 'true', QGUARD_ENABLE_MIGRATION: 'false' },
  operator: { QGUARD_ENABLE_REMEDIATION: 'true', QGUARD_ENABLE_CONFIG_PATCHES: 'true', QGUARD_ENABLE_MIGRATION: 'true' },
}

async function enrol(token: string, role: string, policy: Record<string, unknown>, assetId?: string) {
  const res = await api('/api/v1/agent-scanner/agents/enroll', token, {
    method: 'POST',
    body: JSON.stringify({
      name: `roles-${role}-${Date.now()}`,
      hostname: os.hostname(),
      platform: `${os.platform()} ${os.arch()}`,
      version: '1.5.5',
      /* Write roles are read-only until the operator authorises them. */
      remediationAuthorized: role === 'patcher' || role === 'operator',
      migrationAuthorized: role === 'operator',
      metadata: { role, environment: 'lab', ...(assetId ? { assetId } : {}) },
      policy: { enabled: true, intervalSeconds: 60, ...policy },
    }),
  })
  return { status: res.status, id: res.body?.data?.agent?.id as string, token: res.body?.data?.enrollment?.agentToken as string, body: res.body }
}

function runAgent(role: string, agentId: string, agentToken: string): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [RUNTIME, 'scan'], {
      env: {
        ...process.env,
        QGUARD_API_URL: BASE,
        QGUARD_AGENT_ID: agentId,
        QGUARD_AGENT_TOKEN: agentToken,
        QGUARD_AGENT_ROLE: role,
        QGUARD_NATIVE_RUNTIME_ENABLED: 'false',
        ...ROLE_ENV[role],
      },
      timeout: 240_000,
    })
    let out = ''
    let err = ''
    child.stdout.on('data', (c) => { out += c })
    child.stderr.on('data', (c) => { err += c })
    child.on('close', (code) => resolve({ code, out, err }))
  })
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const raw = (row: any) => (row?.raw_evidence || {}) as Record<string, any>

async function main() {
  /* Session minting occasionally fails transiently (auth rate limit, network
     blip). Retry, and name the error instead of crashing on a null. */
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

  const lab = fs.mkdtempSync(path.join(os.tmpdir(), 'qguard-roles-lab-'))
  console.log(`\nQGuard agent roles live check — ${BASE}\n  lab: ${lab}\n`)
  buildLab(lab)
  const hybridServer = await startTlsServer(lab, 'X25519MLKEM768', 'pki/rsa2048.crt', 'keys/rsa2048.key')
  const classicalServer = await startTlsServer(lab, 'X25519', 'pki/ecdsa-leaf.crt', 'keys/ecdsa-leaf.key')
  const hybridPort = (hybridServer.address() as { port: number }).port
  const classicalPort = (classicalServer.address() as { port: number }).port
  const targets = [`tls://127.0.0.1:${hybridPort}`, `tls://127.0.0.1:${classicalPort}`]

  try {
    /* ============================================================ COLLECTOR */
    console.log('[1] COLLECTOR discovers and collects')
    const collector = await enrol(token, 'collector', {
      scanTypes: ['tls', 'certificates', 'pki', 'ssh', 'packages', 'configs', 'libraries'],
      allowedPaths: [lab],
      allowedTargets: targets,
    })
    check('collector enrols', Boolean(collector.id), `HTTP ${collector.status}`)
    const collectorRun = await runAgent('collector', collector.id, collector.token)
    check('the shipped agent bundle completed a collector scan', collectorRun.code === 0, `exit ${collectorRun.code} ${collectorRun.err.slice(0, 300)}`)

    const { data: ev } = await admin.from('scanner_evidence').select('*').eq('agent_id', collector.id)
    const evidence = ev || []
    const byType = (t: string) => evidence.filter((row) => row.evidence_type === t)
    console.log(`        ${evidence.length} evidence rows: ${[...new Set(evidence.map((r) => r.evidence_type))].join(', ')}`)

    const certFiles = byType('certificate-file')
    check('certificates on disk: RSA-2048 collected', certFiles.some((r) => r.observed_algorithm === 'RSA-2048' && /lab-rsa/.test(raw(r).subject)))
    check('certificates on disk: ML-DSA-65 collected', certFiles.some((r) => r.observed_algorithm === 'ML-DSA-65' && raw(r).signatureAlgorithm === 'ML-DSA-65'))
    check(
      'an ECDSA leaf issued by an "RSA"-named CA is recorded as ECDSA, not RSA',
      certFiles.some((r) => r.observed_algorithm === 'ECDSA-P256' && /RSA/.test(String(raw(r).issuer))),
    )
    check('a certificate BUNDLE yields every certificate in it', certFiles.filter((r) => /chain\.pem$/.test(r.file_path || '')).length === 2)
    check('certificates carry signature algorithm, validity and fingerprint', certFiles.every((r) => raw(r).signatureAlgorithm && raw(r).validTo && r.certificate_fingerprint))

    const keyFiles = byType('key-file')
    check('key metadata: RSA-2048 private key identified', keyFiles.some((r) => r.observed_algorithm === 'RSA-2048' && raw(r).keyKind === 'private' && raw(r).readable === true))
    check('key metadata: P-384 private key identified', keyFiles.some((r) => r.observed_algorithm === 'ECDSA-P384'))
    check('key metadata: ML-DSA-65 private key identified', keyFiles.some((r) => r.observed_algorithm === 'ML-DSA-65'))
    check(
      'an ENCRYPTED key is recorded as unreadable, never guessed',
      keyFiles.some((r) => raw(r).encrypted === true && raw(r).readable === false && /not readable/.test(r.observed_algorithm)),
    )
    const rsaCert = certFiles.find((r) => r.observed_algorithm === 'RSA-2048' && /lab-rsa/.test(raw(r).subject))
    check(
      'a private key is matched to its certificate by public-key fingerprint',
      Boolean(rsaCert) && keyFiles.some((r) => raw(r).publicKeyFingerprintSha256 === raw(rsaCert).publicKeyFingerprintSha256),
    )
    const allRaw = JSON.stringify(evidence.map((r) => r.raw_evidence))
    check('NO private key material left the host', !/PRIVATE KEY-----|"d"\s*:|MII[A-Za-z0-9+/]{40}/.test(allRaw))

    const jwks = byType('jwt-algorithm').filter((r) => raw(r).identity === 'JWKS')
    check('identities: JWKS RS256 key collected with its real modulus size', jwks.some((r) => r.observed_algorithm === 'RS256' && Number(r.key_size) === 2048))
    check('identities: JWKS ES384 key collected', jwks.some((r) => r.observed_algorithm === 'ES384'))
    check(
      'identities: SAML IdP signing certificate collected with its entity',
      certFiles.some((r) => raw(r).identity?.protocol === 'SAML' && /idp\.lab\.qguard\.test/.test(raw(r).identity?.entityId || '')),
    )
    check('identities: SAML signature method collected', byType('config-reference').some((r) => raw(r).identity?.protocol === 'SAML' && /RSA/i.test(r.observed_algorithm)))

    const kex = byType('tls-key-exchange')
    check(
      'protocols: the HYBRID endpoint is measured as X25519MLKEM768',
      kex.some((r) => Number(r.port) === hybridPort && r.observed_algorithm === 'X25519MLKEM768' && raw(r).keyExchangeClass === 'hybrid-post-quantum'),
      JSON.stringify(kex.map((r) => [r.port, r.observed_algorithm])),
    )
    check(
      'protocols: the CLASSICAL endpoint is measured as X25519',
      kex.some((r) => Number(r.port) === classicalPort && r.observed_algorithm === 'X25519' && raw(r).keyExchangeClass === 'classical'),
    )
    check('protocols: TLS certificates and versions from the live handshakes', byType('tls-certificate').length >= 2 && byType('tls-protocol').length >= 2)
    check('configurations: X25519 group and TLS 1.2 found in config files', byType('config-reference').some((r) => r.observed_algorithm === 'X25519') && byType('config-reference').some((r) => r.observed_algorithm === 'TLS-1.2'))
    check('dependencies: crypto libraries recorded as availability (low confidence)', byType('crypto-library').some((r) => /forge/i.test(r.observed_algorithm) && r.confidence === 'low'))
    check('SSH: public key collected', byType('ssh-metadata').length + evidence.filter((r) => /id_ed25519\.pub$/.test(r.file_path || '')).length > 0)
    check('a JWKS is not ALSO re-read as a generic config file (no double count)', !evidence.some((r) => /jwks\.json$/.test(r.file_path || '') && r.evidence_type === 'config-reference'))

    /* ============================================================== SCANNER */
    console.log('\n[2] SCANNER analyses and accurately identifies')
    /* docs/AGENT_COEXISTENCE.md: every role on one host is assigned the SAME
       asset. The Collector's first upload created this host's device profile;
       without this the Scanner gets a second profile for the same machine and
       the host's findings split across two assets. */
    const { data: collectorRow } = await admin.from('scanner_agents').select('metadata').eq('id', collector.id).single()
    const hostAssetId = String(collectorRow?.metadata?.deviceProfileAssetId || '')
    check('the collector created this host\'s device-profile asset', Boolean(hostAssetId), hostAssetId || 'none')
    const scanner = await enrol(token, 'scanner', {
      scanTypes: ['tls', 'certificates', 'pki', 'ssh', 'packages', 'configs', 'libraries'],
      allowedPaths: [lab],
      allowedTargets: targets,
    }, hostAssetId)
    check('scanner enrols assigned to the host asset', Boolean(scanner.id))
    const scannerRun = await runAgent('scanner', scanner.id, scanner.token)
    check('the shipped agent bundle completed a scanner scan', scannerRun.code === 0, `exit ${scannerRun.code}`)

    const { data: inv } = await admin.from('crypto_inventory').select('*').eq('user_id', userId)
    const scannerRows = (inv || []).filter((r) => r.metadata?.evidenceRecord?.agentId === scanner.id)
    const pqRows = (inv || []).filter((r) => r.metadata?.evidenceRecord?.agentId === scanner.id && r.metadata?.pqcReady === true)
    const find = (pred: (r: Record<string, any>) => boolean) => scannerRows.find(pred)
    console.log(`        ${scannerRows.length} inventory rows from the scanner`)

    const ecdsaRow = find((r) => r.metadata?.evidenceRecord?.evidenceType === 'certificate-file' && r.algorithm === 'ECDSA-P256')
    check('ECDSA-P256 certificate classified quantum-VULNERABLE as ECDSA (not RSA)', Boolean(ecdsaRow) && ecdsaRow!.is_vulnerable === true && ecdsaRow!.is_quantum_safe === false)
    check('no RSA row was invented from the CA name on the ECDSA certificate', !scannerRows.some((r) => /ecdsa-leaf|chain/.test(r.metadata?.evidenceRecord?.filePath || '') && /^RSA/.test(r.algorithm) && /lab-ecdsa/.test(JSON.stringify(r.metadata?.evidenceRecord?.rawEvidence || {}))))
    check('ML-DSA-65 certificate classified post-quantum SAFE', (inv || []).some((r) => r.metadata?.evidenceRecord?.agentId === scanner.id && r.algorithm === 'ML-DSA-65' && r.is_quantum_safe === true))
    check('ML-DSA-65 has NO vulnerable row', !scannerRows.some((r) => r.algorithm === 'ML-DSA-65' && r.is_vulnerable === true))
    check(
      'hybrid X25519MLKEM768 endpoint classified quantum-SAFE (hybrid)',
      pqRows.some((r) => r.algorithm === 'X25519MLKEM768' && Number(r.metadata?.evidenceRecord?.port) === hybridPort),
    )
    check(
      'hybrid endpoint has NO classical X25519 vulnerability row',
      !scannerRows.some((r) => r.algorithm === 'X25519' && Number(r.metadata?.evidenceRecord?.port) === hybridPort),
    )
    check(
      'classical X25519 endpoint classified quantum-VULNERABLE',
      scannerRows.some((r) => r.algorithm === 'X25519' && Number(r.metadata?.evidenceRecord?.port) === classicalPort && r.is_vulnerable === true),
    )
    check('RSA-2048 certificate classified quantum-VULNERABLE', scannerRows.some((r) => r.algorithm === 'RSA-2048' && r.is_vulnerable === true))
    check('JWT RS256 signing key classified quantum-VULNERABLE', scannerRows.some((r) => r.algorithm === 'RS256' && r.is_vulnerable === true))
    /* The device profile registers every observed component, so a library or an unreadable key may appear
       as an UNCLASSIFIED component (observationOnly). What must never happen is a finding: a verdict. */
    const isFinding = (r: Record<string, any>) => r.metadata?.observationOnly !== true || r.is_vulnerable === true || r.is_quantum_safe === true
    check('dependencies produce NO algorithm finding (availability is not use)', !scannerRows.some((r) => /forge|jsonwebtoken/i.test(r.algorithm) && isFinding(r)))
    check('an encrypted key produces NO finding', !scannerRows.some((r) => /not readable/i.test(r.algorithm) && isFinding(r)))

    const { data: exposures } = await admin.from('crypto_exposures').select('detected_value').eq('user_id', userId)
    check('no quantum exposure recorded for a safe or post-quantum primitive', !(exposures || []).some((e) => /ML-DSA|MLKEM|AES-256|SHA-256|HMAC/i.test(String(e.detected_value))))
    const { data: certs } = await admin.from('certificates').select('algorithm, is_quantum_safe, metadata').eq('user_id', userId)
    check('certificates from disk reach the Certificate/PKI inventory', (certs || []).some((c) => c.metadata?.evidenceType === 'certificate-file'))

    /* ============================================================== PATCHER */
    console.log('\n[3] PATCHER changes only approved work on authorised paths')
    /* docs/AGENT_COEXISTENCE.md: every role on a host is assigned the SAME asset —
       a file path alone cannot prove which machine a job is for. The Scanner's
       findings live in its device profile, so that is the asset the writers serve. */
    const { data: scannerRow } = await admin.from('scanner_agents').select('metadata').eq('id', scanner.id).single()
    check('the scanner files into the same host asset (no second profile)', scannerRow?.metadata?.assetId === hostAssetId && !scannerRow?.metadata?.deviceProfileAssetId, JSON.stringify({ assetId: scannerRow?.metadata?.assetId, profile: scannerRow?.metadata?.deviceProfileAssetId }))

    // A writer assigned to a DIFFERENT asset must decline — and say so where Live Migration can show it.
    const strayPatcher = await enrol(token, 'patcher', {
      scanTypes: ['configs', 'tls'],
      allowedPaths: [path.join(lab, 'app')],
      allowedTargets: [],
    })
    const patcher = await enrol(token, 'patcher', {
      scanTypes: ['configs', 'tls'],
      allowedPaths: [path.join(lab, 'app')], // migrate/ is deliberately OUTSIDE its scope
      allowedTargets: [],
    }, hostAssetId)
    check('patcher enrols assigned to the host asset', Boolean(patcher.id))

    // Real product flow: Harvest Now queues remediation from the scanner's findings.
    const { data: results } = await admin.from('pqc_scan_results').select('id, algorithm, metadata').eq('user_id', userId)
    // Exact path in THIS run's lab: an earlier run's findings for the same relative file must not be reused.
    const findingFor = (file: string) => (results || []).find((r) => r.algorithm === 'X25519' && String(r.metadata?.evidenceRecord?.filePath || '') === path.join(lab, file))
    const appFinding = findingFor(path.join('app', 'tls.conf'))
    const edgeFinding = findingFor(path.join('migrate', 'edge.conf'))
    check('the scanner produced the X25519 findings Harvest Now queues from', Boolean(appFinding && edgeFinding))

    const queueFor = async (findingId: string) => {
      const r = await api('/api/v1/dashboard/pqc-orchestration/hndl-remediation', token, { method: 'POST', body: JSON.stringify({ findingId }) })
      const { data: jobs } = await admin.from('migration_jobs').select('*').eq('user_id', userId).contains('metadata', { hndlFindingId: findingId })
      return { status: r.status, job: (jobs || [])[0] }
    }
    const appJob = (await queueFor(appFinding!.id)).job
    const edgeJob = (await queueFor(edgeFinding!.id)).job
    check('Harvest Now queued the remediation jobs', Boolean(appJob && edgeJob))
    check('the queued job NAMES the file the finding was observed in', String(appJob?.metadata?.filePath || '').endsWith(path.join('app', 'tls.conf')), String(appJob?.metadata?.filePath))

    const appFile = path.join(lab, 'app', 'tls.conf')
    const edgeFile = path.join(lab, 'migrate', 'edge.conf')
    const appBefore = sha256File(appFile)
    const edgeBefore = sha256File(edgeFile)

    await runAgent('patcher', patcher.id, patcher.token)
    check('UNAPPROVED: the patcher did not touch the file', sha256File(appFile) === appBefore)
    const { data: appJobPre } = await admin.from('migration_jobs').select('status, metadata').eq('id', appJob.id).single()
    check('UNAPPROVED: the job was not claimed', !appJobPre?.metadata?.assignedAgentId, JSON.stringify(appJobPre?.metadata?.dispatchBlock || null))

    for (const job of [appJob, edgeJob]) {
      const approve = await api(`/api/v1/migration/jobs/${job.id}/action`, token, { method: 'POST', body: JSON.stringify({ action: 'approve', reason: 'roles live check' }) })
      check(`operator approval recorded for ${path.basename(job.metadata.filePath)}`, approve.status === 200, `HTTP ${approve.status}`)
    }

    await runAgent('patcher', strayPatcher.id, strayPatcher.token)
    check('WRONG ASSET: a patcher assigned elsewhere did not touch the file', sha256File(appFile) === appBefore)
    const { data: strayView } = await admin.from('migration_jobs').select('status, metadata').eq('id', appJob.id).single()
    const strayRefusal = strayView?.metadata?.executorRefusals?.[strayPatcher.id]
    check('WRONG ASSET: the job was not claimed', strayView?.status === 'queued' && !strayView?.metadata?.assignedAgentId, String(strayView?.status))
    check('WRONG ASSET: the refusal is recorded under that agent, naming the asset mismatch', strayRefusal?.kind === 'out-of-scope' && /assigned to/.test(String(strayRefusal?.reason)), JSON.stringify(strayRefusal || null).slice(0, 240))
    check('APPROVAL: the stale "awaiting approval" note was withdrawn once approved', strayView?.metadata?.dispatchBlock?.kind !== 'not-approved', JSON.stringify(strayView?.metadata?.dispatchBlock || null).slice(0, 160))
    const liveView = await api('/api/v1/migration/live', token)
    const liveAppJob = (liveView.body?.data?.jobs || []).find((job: any) => job.id === appJob.id)
    check('LIVE MIGRATION: the API explains why the approved job is waiting', /declined this job/.test(String(liveAppJob?.dispatchBlock?.reason || '')), String(liveAppJob?.dispatchBlock?.reason || 'no dispatchBlock').slice(0, 240))

    const patchRun = await runAgent('patcher', patcher.id, patcher.token)
    const appAfter = fs.readFileSync(appFile, 'utf8')
    check('APPROVED + IN SCOPE: the patcher changed the file to hybrid ML-KEM', /X25519MLKEM768/.test(appAfter), appAfter.replace(/\n/g, ' | ') + ' // ' + patchRun.out.split('\n').filter((l) => /remediation|Remediation/.test(l)).slice(-3).join(' / '))
    check('APPROVED + IN SCOPE: TLS floor raised to 1.3', /TLSv1\.3/.test(appAfter))
    check('a backup of the original was taken before the change', fs.readdirSync(path.join(lab, 'app')).some((f) => f.startsWith('tls.conf.qguard-backup-')))
    const { data: appJobPost } = await admin.from('migration_jobs').select('status, metadata').eq('id', appJob.id).single()
    check('the job VALIDATED and completed (a correct hybrid patch passes re-scan)', appJobPost?.status === 'completed', `${appJobPost?.status} ${JSON.stringify(appJobPost?.metadata?.lastValidation || {}).slice(0, 200)}`)
    const { data: appSnap } = await admin.from('migration_snapshots').select('*').eq('migration_job_id', appJob.id).eq('trigger', 'pre_migration')
    check('a pre-change snapshot exists for the patched job', (appSnap || []).length === 1)
    check('the snapshot holds the agent’s undo record', appSnap?.[0]?.metadata?.execution?.kind === 'agent-config' && appSnap?.[0]?.metadata?.execution?.beforeHash === appBefore)

    check('OUT OF SCOPE: the approved edge.conf job was NOT applied', sha256File(edgeFile) === edgeBefore)
    const { data: edgePost } = await admin.from('migration_jobs').select('metadata').eq('id', edgeJob.id).single()
    const edgeRefusal = edgePost?.metadata?.executorRefusals?.[patcher.id]
    check('OUT OF SCOPE: the refusal names scope', edgeRefusal?.kind === 'out-of-scope' && /outside this agent/.test(String(edgeRefusal?.reason)), JSON.stringify(edgeRefusal || edgePost?.metadata?.dispatchBlock || null).slice(0, 240))
    check('the claimed job carries no leftover refusals', Object.keys(appJobPost?.metadata?.executorRefusals || {}).length === 0)
    await api('/api/v1/migration/jobs/actions', token, { method: 'POST', body: JSON.stringify({ action: 'cancel', jobIds: [edgeJob.id] }) })

    /* ============================================================= OPERATOR */
    console.log('\n[4] MIGRATION OPERATOR executes only approved migration jobs')
    const operator = await enrol(token, 'operator', {
      scanTypes: ['configs', 'tls'],
      allowedPaths: [path.join(lab, 'migrate')],
      allowedTargets: [],
    }, hostAssetId)
    check('operator enrols', Boolean(operator.id), `HTTP ${operator.status}`)

    const gatewayFile = path.join(lab, 'migrate', 'gateway.conf')
    const gatewayBefore = sha256File(gatewayFile)
    const gatewayOriginal = fs.readFileSync(gatewayFile, 'utf8')
    const planId = crypto.randomUUID()
    await admin.from('migration_plans').insert({ id: planId, user_id: userId, status: 'pending_approval', selected_asset_ids: [], configuration: { source: 'roles-live-check' }, metadata: { planId, name: 'Lab gateway hybrid cutover' } })
    const planJobId = crypto.randomUUID()
    await admin.from('migration_jobs').insert({
      id: planJobId, user_id: userId, asset_id: hostAssetId, name: 'PQC Migration: lab gateway', job_type: 'protocol_upgrade', status: 'queued',
      target_algorithm: 'X25519MLKEM768', strategy: 'X25519 → X25519MLKEM768', progress: 0,
      metadata: { planId, source: 'migration-planner', filePath: gatewayFile, assetName: 'lab-gateway' },
    })

    await runAgent('operator', operator.id, operator.token)
    check('UNAPPROVED PLAN: the operator did not touch the gateway', sha256File(gatewayFile) === gatewayBefore)

    const approval = await api(`/api/v1/migration-planner/plans/${planId}/approval`, token, { method: 'POST', body: JSON.stringify({ decision: 'approve', reason: 'lab change window' }) })
    check('plan approved through the Migration Planner approval API', approval.status === 200, `HTTP ${approval.status} ${JSON.stringify(approval.body?.error || '')}`)

    await runAgent('patcher', patcher.id, patcher.token)
    check('ROLE: a Patcher cannot execute the approved migration cutover', sha256File(gatewayFile) === gatewayBefore)

    const opRun = await runAgent('operator', operator.id, operator.token)
    const gatewayAfter = fs.readFileSync(gatewayFile, 'utf8')
    check('APPROVED: the Migration Operator executed the cutover', /X25519MLKEM768/.test(gatewayAfter), gatewayAfter.replace(/\n/g, ' | ') + ' // ' + opRun.out.split('\n').filter((l) => /emediation/.test(l)).slice(-2).join(' / '))
    const { data: planJob } = await admin.from('migration_jobs').select('status').eq('id', planJobId).single()
    check('the migration job validated and completed', planJob?.status === 'completed', String(planJob?.status))

    // Live rollback of the migration, executed by the operator agent itself.
    const { data: gwSnap } = await admin.from('migration_snapshots').select('snapshot_id').eq('migration_job_id', planJobId).eq('trigger', 'pre_migration').single()
    const restore = await api(`/api/v1/migration-snapshots/${encodeURIComponent(gwSnap!.snapshot_id)}/restore`, token, { method: 'POST', body: JSON.stringify({ reason: 'roles live check rollback' }) })
    check('rollback dispatched to the operator agent', restore.body?.data?.disposition === 'dispatched', String(restore.body?.data?.message || JSON.stringify(restore.body)).slice(0, 200))
    await runAgent('operator', operator.id, operator.token)
    check('ROLLBACK: the original configuration is back, byte for byte', fs.readFileSync(gatewayFile, 'utf8') === gatewayOriginal)
    const { data: gwSnapAfter } = await admin.from('migration_snapshots').select('status').eq('migration_job_id', planJobId).eq('trigger', 'pre_migration').single()
    check('ROLLBACK: the snapshot reads restored only after the agent verified it', gwSnapAfter?.status === 'restored', String(gwSnapAfter?.status))
    const { data: planJobRb } = await admin.from('migration_jobs').select('status').eq('id', planJobId).single()
    check('ROLLBACK: the migration job reads rolled_back', planJobRb?.status === 'rolled_back', String(planJobRb?.status))
  } finally {
    hybridServer.close()
    classicalServer.close()
    fs.rmSync(lab, { recursive: true, force: true })
  }

  console.log(`\n=== ${passed} passed, ${failed} failed ===`)
  if (failures.length) console.log('\n' + failures.map((f) => `  - ${f}`).join('\n') + '\n')
  process.exitCode = failed === 0 ? 0 : 1
}

main().catch((error) => {
  console.error('\nroles live check crashed:', error?.stack || error?.message || error)
  process.exitCode = 1
})
