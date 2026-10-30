/**
 * Agent transport security — offline verification (AGENT_SECURITY.md).
 *
 *   npx tsx tools/agent-transport-security-check.ts
 *
 * [1] Request signing: every tamper, replay, downgrade and forgery the scheme
 *     exists to stop is refused, and the legitimate request still passes
 *     (each refusal has its positive control).
 * [2] Generated installers: HTTPS-only + TLS 1.2 floor, no redirect following,
 *     control-plane environment stamped, persistent owner-only key storage.
 * [3] Server plaintext gate: agent credentials over HTTP are refused (426),
 *     never redirected, and a spoofed Host header earns no exemption.
 * [4] The BUILT agent (tools/qguard-agent/dist) against local test servers:
 *     signs what it sends, refuses redirects, refuses weakened TLS, persists
 *     its key. Run `npm run agent:release` first.
 */
import { spawn } from 'node:child_process'
import { createServer, type IncomingMessage, type Server } from 'node:http'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  SIGNATURE_HEADERS,
  createNonceStore,
  generateAgentKeyPair,
  signRequest,
  supportedAlgorithms,
  verifyRequest,
  type AgentKeyPair,
  type BoundKeys,
} from '../src/lib/agent-installer/agent-request-signing'
import { generateInstaller, type InstallerContext } from '../src/lib/agent-installer/installer-templates'
import { enforceHttps } from '../src/api-server/runtime/http-baseline'

let failures = 0
let skipped = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}
function skip(label: string, why: string) {
  console.log(`  - SKIPPED ${label} — ${why}`)
  skipped += 1
}

const ALGORITHMS = supportedAlgorithms()
const HYBRID = ALGORITHMS.includes('ml-dsa-65')
const AGENT = '7d3c2b1a-0000-4000-8000-000000000001'
const URL_PATH = 'https://api.example.com/api/v1/agent-scanner/agent/heartbeat'
const BODY = JSON.stringify({ status: 'active', telemetry: { memory: { usedPercent: 42 } } })

const keysFor = (algorithms: typeof ALGORITHMS) => algorithms.map((algorithm) => generateAgentKeyPair(algorithm))
const boundFrom = (keys: AgentKeyPair[]): BoundKeys => Object.fromEntries(keys.map((key) => [key.algorithm, key.publicKeyDer.toString('base64')]))

function check(input: {
  headers: Record<string, string>
  body?: string | null
  method?: string
  url?: string
  agentId?: string
  bound?: BoundKeys | null
  verifiable?: typeof ALGORITHMS
  nonceSeen?: ReturnType<typeof createNonceStore>
  now?: number
}) {
  return verifyRequest({
    method: input.method || 'POST',
    originalUrl: input.url || '/api/v1/agent-scanner/agent/heartbeat',
    agentId: input.agentId || AGENT,
    headers: input.headers,
    rawBody: input.body === undefined ? Buffer.from(BODY) : input.body === null ? null : Buffer.from(input.body),
    bound: input.bound ?? null,
    verifiable: input.verifiable || ALGORITHMS,
    nonceSeen: input.nonceSeen || createNonceStore(),
    now: input.now,
  })
}

/* ------------------------------------------------------------------ */
console.log(`\n[1] Request signing (runtime algorithms: ${ALGORITHMS.join(' + ')})`)
{
  const keys = keysFor(ALGORITHMS)
  const sign = (overrides: Partial<Parameters<typeof signRequest>[0]> = {}) =>
    signRequest({ method: 'POST', url: URL_PATH, agentId: AGENT, body: BODY, keys, ...overrides })

  const ok = check({ headers: sign() })
  assert(ok.ok && ok.algorithms?.length === ALGORITHMS.length, `valid request verifies with every algorithm (${ALGORITHMS.join(', ')})`, ok.failure)
  assert(Object.keys(ok.presentedKeys || {}).length === ALGORITHMS.length, 'first request yields the keys to bind')
  if (HYBRID) assert(ok.algorithms?.includes('ml-dsa-65') === true, 'hybrid: ML-DSA-65 (FIPS 204) signature verified alongside Ed25519')
  else skip('hybrid ML-DSA-65 verification', 'this Node runtime has no ML-DSA')

  const tampered = check({ headers: sign(), body: BODY.replace('42', '43') })
  assert(!tampered.ok && tampered.failure === 'digest-mismatch', 'one changed byte in the body → refused (digest mismatch)', tampered.failure)

  // An attacker who also rewrites the digest header still cannot re-sign.
  const rewritten = { ...sign() }
  const alteredBody = BODY.replace('42', '43')
  rewritten[SIGNATURE_HEADERS.contentDigest] = (await import('../src/lib/agent-installer/agent-request-signing')).sha3Hex(alteredBody)
  const reDigested = check({ headers: rewritten, body: alteredBody })
  assert(!reDigested.ok && reDigested.failure === 'bad-signature', 'altered body + recomputed digest → refused (signature covers the digest)', reDigested.failure)

  const wrongPath = check({ headers: sign(), url: '/api/v1/agent-scanner/agent/evidence' })
  assert(!wrongPath.ok && wrongPath.failure === 'bad-signature', 'signed for /heartbeat, sent to /evidence → refused', wrongPath.failure)
  const wrongMethod = check({ headers: sign(), method: 'PUT' })
  assert(!wrongMethod.ok && wrongMethod.failure === 'bad-signature', 'method changed → refused', wrongMethod.failure)
  const otherAgent = check({ headers: sign(), agentId: '7d3c2b1a-0000-4000-8000-000000000002' })
  assert(!otherAgent.ok && otherAgent.failure === 'bad-signature', 'signature of agent A presented as agent B → refused', otherAgent.failure)
  const outside = check({ headers: sign(), url: '/health' })
  assert(!outside.ok && outside.failure === 'path-mismatch', 'path outside /api/v1 → refused')
  const proxied = check({ headers: sign(), url: '/edge/api/v1/agent-scanner/agent/heartbeat' })
  assert(proxied.ok, 'positive control: a reverse-proxy mount prefix in front of /api/v1 still verifies', proxied.failure)

  const stale = check({ headers: sign({ now: Date.now() - 6 * 60_000 }) })
  const future = check({ headers: sign({ now: Date.now() + 6 * 60_000 }) })
  const edge = check({ headers: sign({ now: Date.now() - 4 * 60_000 }) })
  assert(!stale.ok && stale.failure === 'stale' && !future.ok && future.failure === 'stale', 'timestamp 6 min old / 6 min ahead → refused')
  assert(edge.ok, 'positive control: 4 min clock skew is accepted')

  const store = createNonceStore()
  const once = sign()
  const first = check({ headers: once, nonceSeen: store })
  const replay = check({ headers: once, nonceSeen: store })
  assert(first.ok && !replay.ok && replay.failure === 'replayed', 'exact replay of an accepted request → refused', replay.failure)

  // A forgery must not be able to burn a legitimate nonce.
  const burnStore = createNonceStore()
  const legit = sign()
  const forged = { ...legit, [SIGNATURE_HEADERS.signature('ed25519')]: Buffer.alloc(64, 1).toString('base64') }
  const forgedResult = check({ headers: forged, nonceSeen: burnStore })
  const afterForgery = check({ headers: legit, nonceSeen: burnStore })
  assert(!forgedResult.ok && afterForgery.ok, 'a forged request with a stolen nonce does not lock out the real one')

  const attacker = keysFor(ALGORITHMS)
  const forgedByKey = check({ headers: signRequest({ method: 'POST', url: URL_PATH, agentId: AGENT, body: BODY, keys: attacker }), bound: boundFrom(keys) })
  assert(!forgedByKey.ok && forgedByKey.failure === 'key-mismatch', 'token holder signing with their OWN key against a bound agent → refused', forgedByKey.failure)
  const boundOk = check({ headers: sign(), bound: boundFrom(keys) })
  assert(boundOk.ok, 'positive control: the bound key is accepted')

  if (HYBRID) {
    const edOnly = keys.filter((key) => key.algorithm === 'ed25519')
    const downgrade = check({ headers: signRequest({ method: 'POST', url: URL_PATH, agentId: AGENT, body: BODY, keys: edOnly }), bound: boundFrom(keys) })
    assert(!downgrade.ok && downgrade.failure === 'missing-bound-algorithm', 'stripping the ML-DSA half from a hybrid-bound agent → refused (no downgrade)', downgrade.failure)
    const mlOnly = keys.filter((key) => key.algorithm === 'ml-dsa-65')
    const pqOnly = check({ headers: signRequest({ method: 'POST', url: URL_PATH, agentId: AGENT, body: BODY, keys: mlOnly }) })
    assert(!pqOnly.ok, 'ML-DSA alone without Ed25519 → refused (Ed25519 is the floor)')
    const legacyServer = check({ headers: sign(), verifiable: ['ed25519'] })
    assert(legacyServer.ok && !legacyServer.presentedKeys?.['ml-dsa-65'], 'a control plane that cannot verify ML-DSA never binds it')
    const upgrade = check({ headers: sign(), bound: boundFrom(edOnly) })
    assert(upgrade.ok && Boolean(upgrade.presentedKeys?.['ml-dsa-65']), 'agent gaining ML-DSA while still signing with the bound Ed25519 key → accepted, extendable')
  }

  const unsigned = check({ headers: {} })
  assert(!unsigned.ok && unsigned.failure === 'unsigned', 'no signature headers → reported as unsigned (the server refuses it once bound)')
  const confused = { ...sign(), [SIGNATURE_HEADERS.publicKey('ed25519')]: HYBRID ? keys.find((key) => key.algorithm === 'ml-dsa-65')!.publicKeyDer.toString('base64') : 'AAAA' }
  const confusion = check({ headers: confused })
  assert(!confusion.ok && confusion.failure === 'bad-public-key', 'a key of another type under the Ed25519 header → refused (no algorithm confusion)', confusion.failure)
  const get = signRequest({ method: 'GET', url: 'https://api.example.com/api/v1/agent-scanner/agent/policy', agentId: AGENT, body: null, keys })
  assert(check({ headers: get, method: 'GET', url: '/api/v1/agent-scanner/agent/policy', body: null }).ok, 'GET with no body verifies (empty-body digest)')
}

/* ------------------------------------------------------------------ */
console.log('\n[2] Generated installers')
{
  const base: InstallerContext = {
    apiUrl: 'https://api.qguardhelix.com',
    tenantId: '11111111-2222-4333-8444-555555555555',
    agentId: AGENT,
    agentToken: 'qga_' + 'A'.repeat(43),
    agentName: 'edge-01',
    role: 'collector',
    environment: 'production',
    controlPlaneEnvironment: 'production',
    version: '1.6.0',
    runtimeSha256: 'a'.repeat(64),
    policy: { intervalSeconds: 60, allowedTargets: [], allowedPaths: [], scanTypes: [], alertThreshold: 'moderate' },
    remediationEnabled: false,
    migrationEnabled: false,
    generatedAt: '2026-10-28T00:00:00Z',
    generatedBy: 'check',
  }
  const out = (platform: Parameters<typeof generateInstaller>[0], overrides: Partial<InstallerContext> = {}) => generateInstaller(platform, { ...base, ...overrides }).content

  const linux = out('linux')
  const curls = linux.split('\n').filter((line) => /^\s*(RESPONSE="\$\()?curl /.test(line))
  assert(curls.length >= 3 && curls.every((line) => line.includes("--proto '=https' --tlsv1.2")), `every curl is HTTPS-only with a TLS 1.2 floor (${curls.length})`)
  assert(curls.every((line) => !/\s-[a-zA-Z]*L/.test(line)), 'no curl follows redirects (-L) with the token header')
  assert(/^QGUARD_ENVIRONMENT=production$/m.test(linux), 'control-plane environment stamped (QGUARD_ENVIRONMENT=production)')
  assert(linux.includes('QGUARD_STATE_DIR=/var/lib/qguard-agent') && linux.includes('install -d -m 0700 -o root -g root /var/lib/qguard-agent') && linux.includes('StateDirectory=qguard-agent'), 'persistent 0700 root key directory + systemd StateDirectory')
  const devLinux = out('linux', { apiUrl: 'http://localhost:3000', controlPlaneEnvironment: 'development' })
  assert(!devLinux.includes('--proto') && /^QGUARD_ENVIRONMENT=development$/m.test(devLinux), 'positive control: a development plaintext installer still works (no https lock)')
  assert(/^QGUARD_ENVIRONMENT=development$/m.test(out('linux', { controlPlaneEnvironment: undefined })), 'missing control-plane environment defaults to development, never upgraded silently')

  for (const platform of ['windows', 'powershell'] as const) {
    const script = out(platform)
    const floor = script.indexOf('[Net.ServicePointManager]::SecurityProtocol')
    const firstRequest = script.search(/Invoke-(WebRequest|RestMethod)/)
    const calls = script.split('\n').filter((line) => /Invoke-(WebRequest|RestMethod)/.test(line))
    assert(floor !== -1 && floor < firstRequest, `${platform}: TLS 1.2 floor set before the first request`)
    assert(calls.length > 0 && calls.every((line) => line.includes('-MaximumRedirection 0')), `${platform}: every web call refuses redirects (${calls.length})`)
    assert(/QGUARD_ENVIRONMENT\s*=?\s*'?production/.test(script), `${platform}: control-plane environment stamped`)
  }
  const windows = out('windows')
  assert(windows.includes('$StateDir') && windows.includes("'ContainerInherit,ObjectInherit'") && windows.includes('SetAccessRuleProtection($true, $false)'), 'windows: key directory ACL is SYSTEM + Administrators, inherited by new files')
  assert(out('powershell').includes("Join-Path $env:LOCALAPPDATA 'QGuardHelix\\Agent\\state'"), 'portable: keys kept in the user profile, not world-readable ProgramData')

  for (const platform of ['docker', 'kubernetes'] as const) {
    const manifest = out(platform)
    assert(!/\bwget\b/.test(manifest), `${platform}: no BusyBox wget (unverifiable TLS, follows redirects)`)
    assert(manifest.includes("redirect: 'error'") && manifest.includes('AbortSignal.timeout') && manifest.includes("startsWith('https://')"), `${platform}: runtime fetched with verified TLS, no redirects, HTTPS required, timeout`)
    assert(manifest.includes('QGUARD_STATE_DIR: "/var/lib/qguard-agent"') && manifest.includes('QGUARD_ENVIRONMENT: "production"'), `${platform}: state dir + control-plane environment`)
  }
  const fetchScript = out('docker').split("<<'QGUARD_FETCH_EOF'")[1].split('QGUARD_FETCH_EOF')[0]
  assert(!fetchScript.includes('$'), 'compose: embedded fetch script has no "$" for Compose to interpolate')
  assert(out('docker').includes('qguard-agent-state:/var/lib/qguard-agent') && /^volumes:\n {2}qguard-agent-state:/m.test(out('docker')), 'compose: named volume persists the signing key')
  const k8s = out('kubernetes')
  assert(k8s.includes('kind: PersistentVolumeClaim') && k8s.includes('claimName: qguard-agent-state') && k8s.includes('fsGroupChangePolicy: "OnRootMismatch"'), 'kubernetes: PVC-backed key storage; fsGroup never re-chmods the 0600 key')
  assert(out('cloud-init').includes("--proto '=https' --tlsv1.2"), 'cloud-init inherits the hardened Linux installer')

  const sources = ['src/lib/agent-installer/installer-templates.ts', 'tools/qguard-agent/agent.ts', 'src/lib/agent-installer/agent-request-signing.ts'].map((file) => readFileSync(file, 'utf8')).join('\n')
  assert(!/node -e\b/.test(sources), '§69 sweep: no `node -e` in agent or installer sources')
  // Assignments only (code, env files, YAML) — the agent's refusal message names the variable on purpose.
  const generated = (['linux', 'windows', 'powershell', 'docker', 'kubernetes', 'cloud-init'] as const).map((platform) => out(platform)).join('\n')
  const disablesVerification = /process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=(?!=)|^\s*(\$env:)?NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]|rejectUnauthorized:\s*false[^\n]*control/m
  assert(!disablesVerification.test(sources) && !disablesVerification.test(generated), '§69 sweep: nothing sets NODE_TLS_REJECT_UNAUTHORIZED, in sources or generated installers')
  assert(disablesVerification.test('process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"') && disablesVerification.test('NODE_TLS_REJECT_UNAUTHORIZED=0'), 'negative control: the sweep does catch an assignment')
  const requestJson = readFileSync('tools/qguard-agent/agent.ts', 'utf8').split('async function requestJson')[1].split('\n}\n')[0]
  assert(requestJson.includes("redirect: 'error'") && requestJson.includes('AbortSignal.timeout') && requestJson.includes('signRequest(') && !requestJson.includes('rejectUnauthorized'), 'agent control-plane client: no redirects, timeout, signed, certificate verification untouched')
}

/* ------------------------------------------------------------------ */
console.log('\n[3] Server plaintext gate (enforceHttps)')
{
  const run = (headers: Record<string, string>, peer = '203.0.113.9', method = 'POST') => {
    const outcome = { status: 0, redirected: false, next: false, code: '' }
    const req = { method, headers, secure: false, protocol: 'http', originalUrl: '/api/v1/agent-scanner/agent/heartbeat', socket: { remoteAddress: peer } } as never
    const res = {
      status(code: number) { outcome.status = code; return this },
      json(body: { error?: { code?: string } }) { outcome.code = body?.error?.code || ''; return this },
      redirect(code: number) { outcome.status = code; outcome.redirected = true },
    } as never
    enforceHttps(req, res, () => { outcome.next = true })
    return outcome
  }
  const previous = process.env.NODE_ENV
  process.env.NODE_ENV = 'production'
  const agentHeaders = { host: 'api.qguardhelix.com', 'x-qguard-agent-id': AGENT, 'x-qguard-agent-token': 'qga_x' }
  const plainPost = run(agentHeaders)
  const plainGet = run(agentHeaders, '203.0.113.9', 'GET')
  assert(plainPost.status === 426 && plainPost.code === 'AGENT_HTTPS_REQUIRED', 'agent POST over plaintext → 426 AGENT_HTTPS_REQUIRED')
  assert(plainGet.status === 426 && !plainGet.redirected, 'agent GET over plaintext → 426, NOT a redirect that invites a retry')
  const spoofed = run({ ...agentHeaders, host: 'localhost' })
  assert(spoofed.status === 426, 'spoofed "Host: localhost" from a remote peer earns no exemption')
  assert(run({ ...agentHeaders, host: 'localhost' }, '127.0.0.1').next, 'positive control: genuine loopback (local Host AND loopback peer) passes')
  assert(run({ ...agentHeaders, 'x-forwarded-proto': 'https' }).next, 'positive control: TLS-terminated request (X-Forwarded-Proto: https) passes')
  const browser = run({ host: 'api.qguardhelix.com' }, '203.0.113.9', 'GET')
  assert(browser.redirected && browser.status === 308, 'unchanged: a browser GET without agent credentials is still redirected (308)')
  process.env.NODE_ENV = 'development'
  assert(run(agentHeaders).next, 'development control plane: plaintext stays usable for local work')
  process.env.NODE_ENV = previous
}

/* ------------------------------------------------------------------ */
console.log('\n[4] Built agent runtime against local test servers')
{
  const runtime = path.resolve('tools/qguard-agent/dist/qguard-agent.cjs')
  if (!existsSync(runtime)) {
    skip('built-agent checks', 'run `npm run agent:release` first')
  } else {
    const version = readFileSync(runtime, 'utf8').match(/1\.\d+\.\d+/)?.[0]
    const work = mkdtempSync(path.join(tmpdir(), 'qg-transport-'))
    const stateDir = path.join(work, 'state')

    const listen = (handler: (req: IncomingMessage, body: Buffer) => [number, Record<string, string>, string]) =>
      new Promise<{ server: Server; port: number; seen: Array<{ req: IncomingMessage; body: Buffer }> }>((resolve) => {
        const seen: Array<{ req: IncomingMessage; body: Buffer }> = []
        const server = createServer((req, res) => {
          const chunks: Buffer[] = []
          req.on('data', (chunk) => chunks.push(chunk))
          req.on('end', () => {
            const body = Buffer.concat(chunks)
            seen.push({ req, body })
            const [status, headers, text] = handler(req, body)
            res.writeHead(status, { 'content-type': 'application/json', ...headers })
            res.end(text)
          })
        })
        server.listen(0, '127.0.0.1', () => resolve({ server, port: (server.address() as { port: number }).port, seen }))
      })

    const runAgent = (env: Record<string, string>, ms = 12_000) =>
      new Promise<{ code: number | null; output: string }>((resolve) => {
        const child = spawn(process.execPath, [runtime, 'scan'], {
          cwd: work,
          env: {
            PATH: process.env.PATH || '',
            SystemRoot: process.env.SystemRoot || '',
            QGUARD_CONFIG: path.join(work, 'no-config.env'),
            QGUARD_AGENT_ID: AGENT,
            QGUARD_AGENT_TOKEN: 'qga_' + 'B'.repeat(43),
            QGUARD_STATE_DIR: stateDir,
            QGUARD_ENVIRONMENT: 'development',
            ...env,
          },
        })
        let output = ''
        child.stdout.on('data', (chunk) => { output += chunk })
        child.stderr.on('data', (chunk) => { output += chunk })
        const timer = setTimeout(() => child.kill(), ms)
        child.on('exit', (code) => { clearTimeout(timer); resolve({ code, output }) })
      })

    const policy = JSON.stringify({ data: { policy: { enabled: false, intervalSeconds: 60, allowedTargets: [], allowedPaths: [], scanTypes: [] }, commands: [] } })
    const recorder = await listen(() => [200, {}, policy])
    const first = await runAgent({ QGUARD_API_URL: `http://127.0.0.1:${recorder.port}` })
    const signedHits = recorder.seen.filter((hit) => hit.req.headers[SIGNATURE_HEADERS.scheme] === 'qgs1')
    assert(recorder.seen.length > 0 && signedHits.length === recorder.seen.length, `agent v${version}: every request it sent was signed (${signedHits.length}/${recorder.seen.length})`, recorder.seen.length ? '' : first.output.slice(-300))
    const verdicts = recorder.seen.map((hit) => verifyRequest({
      method: hit.req.method || 'GET',
      originalUrl: hit.req.url || '',
      agentId: AGENT,
      headers: hit.req.headers as Record<string, string>,
      rawBody: hit.body,
      bound: null,
      verifiable: ALGORITHMS,
      nonceSeen: createNonceStore(),
    }))
    assert(verdicts.length > 0 && verdicts.every((verdict) => verdict.ok), 'the control-plane verifier accepts exactly what the agent sent', verdicts.find((verdict) => !verdict.ok)?.failure)
    assert(verdicts.every((verdict) => verdict.algorithms?.length === ALGORITHMS.length), `agent signs with ${ALGORITHMS.join(' + ')} on this runtime`)
    const keyFiles = existsSync(stateDir) ? readdirSync(stateDir).filter((name) => name.startsWith('signing-keys-')) : []
    assert(keyFiles.length === 1, 'signing keys persisted in QGUARD_STATE_DIR', keyFiles.join(','))
    if (keyFiles.length && process.platform !== 'win32') {
      assert((statSync(path.join(stateDir, keyFiles[0])).mode & 0o077) === 0, 'key file is owner-only (0600)')
    } else if (keyFiles.length) {
      skip('key file mode 0600', 'POSIX permissions; on Windows the installer ACLs the state directory')
    }
    const firstKey = recorder.seen[0]?.req.headers[SIGNATURE_HEADERS.publicKey('ed25519')]
    recorder.seen.length = 0
    await runAgent({ QGUARD_API_URL: `http://127.0.0.1:${recorder.port}` })
    assert(Boolean(firstKey) && recorder.seen[0]?.req.headers[SIGNATURE_HEADERS.publicKey('ed25519')] === firstKey, 'second run presents the SAME key (binding survives restarts)')
    recorder.server.close()

    // Redirect: the target must never see the token.
    const target = await listen(() => [200, {}, policy])
    const redirector = await listen(() => [302, { location: `http://127.0.0.1:${target.port}/api/v1/agent-scanner/agent/policy` }, '{}'])
    const redirected = await runAgent({ QGUARD_API_URL: `http://127.0.0.1:${redirector.port}` })
    assert(redirector.seen.length > 0 && target.seen.length === 0, 'a redirect is refused — the redirect target never receives the agent token', `target hits: ${target.seen.length}`)
    assert(/redirect/i.test(redirected.output), 'the refusal names the redirect', redirected.output.split('\n').find((line) => /redirect/i.test(line))?.trim())
    target.server.close()
    redirector.server.close()

    const insecure = await runAgent({ QGUARD_API_URL: 'https://api.example.com', QGUARD_ENVIRONMENT: 'production', NODE_TLS_REJECT_UNAUTHORIZED: '0' })
    assert(insecure.code === 78 && /NODE_TLS_REJECT_UNAUTHORIZED/.test(insecure.output), 'NODE_TLS_REJECT_UNAUTHORIZED=0 → refuses to start (exit 78), nothing sent')
    const lowered = await runAgent({ QGUARD_API_URL: 'https://api.example.com', QGUARD_ENVIRONMENT: 'production', NODE_OPTIONS: '--tls-min-v1.0' })
    assert(lowered.code === 78 && /TLS floor/.test(lowered.output), 'TLS floor lowered to 1.0 → refuses to start (exit 78)')
    const plaintextProd = await runAgent({ QGUARD_API_URL: 'http://api.example.com', QGUARD_ENVIRONMENT: 'production' })
    assert(plaintextProd.code === 78, 'production + plaintext control plane → refuses to start (existing gate still wired)')
    rmSync(work, { recursive: true, force: true })
  }
}

console.log(`\n${failures ? `✗ ${failures} check(s) failed` : '✓ agent transport security holds'}${skipped ? ` (${skipped} skipped)` : ''}\n`)
process.exit(failures ? 1 : 0)
