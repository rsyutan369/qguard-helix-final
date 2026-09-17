/**
 * The COLLECTOR, proven with the shipped agent binary and no database.
 *
 * Runs tools/qguard-agent/dist/qguard-agent.cjs — the bundle installers ship —
 * as a Collector against the real lab (tools/agent-lab.ts): OpenSSL-issued
 * certificates, real private keys, a JWKS, SAML metadata, config files, a
 * package manifest, an SSH key and two live TLS servers (hybrid X25519MLKEM768
 * only / classical X25519 only).
 *
 * The control plane is a local RECORDER: it serves the agent's policy and
 * captures, verbatim, every evidence batch the agent uploads. Nothing about what
 * the agent collects is simulated — the recorder only stands in for the network
 * endpoint, so this check proves collection even when no Supabase project is
 * reachable. The database-backed half (Scanner inventory, Patcher, Operator) is
 * proven by tools/agent-roles-live-check.ts.
 *
 *   npx tsx tools/agent-collector-offline-check.ts
 *   QGUARD_CHECK_VERBOSE=1 npx tsx tools/agent-collector-offline-check.ts
 */
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { buildLab, startTlsServer } from './agent-lab'

const RUNTIME = path.resolve('tools/qguard-agent/dist/qguard-agent.cjs')
const NL = '\n'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Evidence = Record<string, any>

async function main() {
  const lab = fs.mkdtempSync(path.join(os.tmpdir(), 'qguard-collector-lab-'))
  buildLab(lab)
  const hybridServer = await startTlsServer(lab, 'X25519MLKEM768', 'pki/rsa2048.crt', 'keys/rsa2048.key')
  const classicalServer = await startTlsServer(lab, 'X25519', 'pki/ecdsa-leaf.crt', 'keys/ecdsa-leaf.key')
  const hybridPort = (hybridServer.address() as { port: number }).port
  const classicalPort = (classicalServer.address() as { port: number }).port

  const uploaded: Evidence[] = []
  const requests: string[] = []
  const policy = {
    enabled: true,
    intervalSeconds: 60,
    allowedTargets: [`tls://127.0.0.1:${hybridPort}`, `tls://127.0.0.1:${classicalPort}`],
    allowedPaths: [lab],
    scanTypes: ['tls', 'certificates', 'pki', 'ssh', 'packages', 'configs', 'libraries'],
    alertThreshold: 'moderate',
  }
  const recorder = http.createServer((req, res) => {
    let body = ''
    req.on('data', (chunk) => { body += chunk })
    req.on('end', () => {
      const url = req.url || ''
      requests.push(`${req.method} ${url}`)
      const reply = (data: unknown) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ data })) }
      if (url.endsWith('/agent/policy')) return reply({ policy, commands: [] })
      if (url.endsWith('/agent/evidence')) {
        const parsed = JSON.parse(body || '{}')
        uploaded.push(...(parsed.evidence || []))
        return reply({ evidenceCount: (parsed.evidence || []).length })
      }
      if (url.includes('/agent/remediation/jobs')) return reply({ jobs: [] })
      return reply({ accepted: true })
    })
  })
  await new Promise<void>((resolve) => recorder.listen(0, '127.0.0.1', () => resolve()))
  const recorderPort = (recorder.address() as { port: number }).port

  console.log(`${NL}Collector offline check — shipped bundle against the real lab${NL}  lab: ${lab}${NL}`)
  try {
    const run = await new Promise<{ code: number | null; out: string; err: string }>((resolve) => {
      const child = spawn(process.execPath, [RUNTIME, 'scan'], {
        env: {
          ...process.env,
          QGUARD_API_URL: `http://localhost:${recorderPort}`,
          QGUARD_AGENT_ID: 'offline-collector',
          QGUARD_AGENT_TOKEN: 'offline-token',
          QGUARD_AGENT_ROLE: 'collector',
          QGUARD_NATIVE_RUNTIME_ENABLED: 'false',
          QGUARD_ENABLE_REMEDIATION: 'false',
          QGUARD_ENABLE_CONFIG_PATCHES: 'false',
          QGUARD_ENABLE_MIGRATION: 'false',
        },
        timeout: 240_000,
      })
      let out = ''
      let err = ''
      child.stdout.on('data', (c) => { out += c })
      child.stderr.on('data', (c) => { err += c })
      child.on('close', (code) => resolve({ code, out, err }))
    })
    assert(run.code === 0, 'the shipped agent completed a collector scan', `exit ${run.code}`)
    if (process.env.QGUARD_CHECK_VERBOSE || uploaded.length === 0) {
      const indent = (text: string, limit = 60) => text.split(NL).filter(Boolean).slice(0, limit).map((line) => `    ${line}`).join(NL)
      console.log(`  --- agent stdout ---${NL}${indent(run.out)}`)
      if (run.err.trim()) console.log(`  --- agent stderr ---${NL}${indent(run.err, 12)}`)
      console.log(`  --- recorder saw ---${NL}${[...new Set(requests)].map((r) => `    ${r}`).join(NL)}`)
    }

    const byType = (t: string) => uploaded.filter((e) => e.evidenceType === t)
    const raw = (e: Evidence) => (e.rawEvidence || {}) as Evidence
    console.log(`  (${uploaded.length} evidence items uploaded: ${[...new Set(uploaded.map((e) => e.evidenceType))].join(', ')})${NL}`)

    console.log('[certificates]')
    const certs = byType('certificate-file')
    assert(certs.some((e) => e.observedAlgorithm === 'RSA-2048' && /lab-rsa/.test(raw(e).subject)), 'RSA-2048 certificate on disk')
    assert(certs.some((e) => e.observedAlgorithm === 'ML-DSA-65' && raw(e).signatureAlgorithm === 'ML-DSA-65'), 'ML-DSA-65 certificate on disk, with its signature algorithm')
    assert(certs.some((e) => e.observedAlgorithm === 'ECDSA-P256' && /RSA/.test(String(raw(e).issuer))), 'ECDSA leaf under an "RSA"-named CA is recorded as ECDSA')
    assert(certs.filter((e) => /chain\.pem$/.test(e.filePath || '')).length === 2, 'a two-certificate bundle yields both certificates')
    assert(certs.length > 0 && certs.every((e) => raw(e).validTo && e.certificateFingerprint && raw(e).publicKeyFingerprintSha256), 'every certificate carries validity, fingerprint and public-key fingerprint')

    console.log(`${NL}[key metadata]`)
    const keys = byType('key-file')
    assert(keys.some((e) => e.observedAlgorithm === 'RSA-2048' && raw(e).keyKind === 'private' && raw(e).readable), 'RSA-2048 private key identified')
    assert(keys.some((e) => e.observedAlgorithm === 'ECDSA-P384'), 'P-384 private key identified')
    assert(keys.some((e) => e.observedAlgorithm === 'ML-DSA-65'), 'ML-DSA-65 private key identified')
    assert(keys.some((e) => raw(e).encrypted && !raw(e).readable && /not readable/.test(e.observedAlgorithm)), 'encrypted key recorded as unreadable, not guessed')
    const rsaCert = certs.find((e) => e.observedAlgorithm === 'RSA-2048' && /lab-rsa/.test(raw(e).subject))
    assert(Boolean(rsaCert) && keys.some((e) => raw(e).publicKeyFingerprintSha256 === raw(rsaCert!).publicKeyFingerprintSha256), 'private key matched to its certificate by public-key fingerprint')
    const wire = JSON.stringify(uploaded)
    assert(uploaded.length > 0 && !/PRIVATE KEY-----/.test(wire), 'no PEM private key block was uploaded')
    assert(keys.length > 0 && !keys.some((e) => Object.keys(raw(e)).some((k) => /^(d|p|q|dp|dq|qi|privateKey|key)$/i.test(k))), 'no private key parameter was uploaded')

    console.log(`${NL}[identities]`)
    const jwks = byType('jwt-algorithm').filter((e) => raw(e).identity === 'JWKS')
    assert(jwks.some((e) => e.observedAlgorithm === 'RS256' && e.keySize === 2048), 'JWKS RS256 key with its real 2048-bit modulus')
    assert(jwks.some((e) => e.observedAlgorithm === 'ES384' && e.keySize === 384), 'JWKS ES384 key')
    assert(jwks.length > 0 && jwks.every((e) => raw(e).containsPrivateParameters === false), 'public JWKS correctly reported as containing no private parameters')
    assert(certs.some((e) => raw(e).identity?.protocol === 'SAML' && /idp\.lab\.qguard\.test/.test(raw(e).identity?.entityId || '')), 'SAML IdP signing certificate with its entity ID')
    assert(byType('config-reference').some((e) => raw(e).identity?.protocol === 'SAML' && e.observedAlgorithm === 'sha256WithRSAEncryption'), 'SAML signature method')
    assert(uploaded.length > 0 && !uploaded.some((e) => /jwks\.json$|idp-metadata\.xml$/.test(e.filePath || '') && e.evidenceType === 'config-reference' && raw(e).identity === undefined), 'identity files are not double-read by the generic config scanner')

    console.log(`${NL}[protocols]`)
    const kex = byType('tls-key-exchange')
    assert(kex.some((e) => e.port === hybridPort && e.observedAlgorithm === 'X25519MLKEM768' && raw(e).keyExchangeClass === 'hybrid-post-quantum'), 'hybrid-only endpoint measured as X25519MLKEM768', JSON.stringify(kex.map((e) => [e.port, e.observedAlgorithm])))
    assert(kex.some((e) => e.port === classicalPort && e.observedAlgorithm === 'X25519' && raw(e).keyExchangeClass === 'classical'), 'classical-only endpoint measured as X25519')
    assert(kex.length > 0 && kex.every((e) => Array.isArray(raw(e).probes) && raw(e).method === 'single-group TLS handshake'), 'each key-exchange verdict carries the handshakes that proved it')
    assert(byType('tls-certificate').length === 2 && byType('tls-protocol').length === 2 && byType('tls-protocol').every((e) => e.observedAlgorithm === 'TLS-1.3'), 'live handshake certificates and TLS 1.3 recorded')

    console.log(`${NL}[configurations, dependencies, SSH]`)
    const configs = byType('config-reference')
    assert(configs.some((e) => e.observedAlgorithm === 'X25519' && /tls\.conf$/.test(e.filePath)), 'X25519 group found in tls.conf')
    assert(configs.some((e) => e.observedAlgorithm === 'TLS-1.2'), 'TLS 1.2 floor found in config')
    assert(byType('crypto-library').some((e) => /forge/i.test(e.observedAlgorithm) && e.confidence === 'low'), 'node-forge recorded as availability, low confidence')
    assert(uploaded.some((e) => /id_ed25519\.pub$/.test(e.filePath || '')), 'SSH public key collected')
  } finally {
    recorder.close()
    hybridServer.close()
    classicalServer.close()
    fs.rmSync(lab, { recursive: true, force: true })
  }

  console.log(`${NL}${failures === 0 ? 'PASS' : `FAIL (${failures})`} — collector offline check${NL}`)
  process.exitCode = failures === 0 ? 0 : 1
}

main().catch((error) => {
  console.error('collector offline check crashed:', error?.stack || error)
  process.exitCode = 1
})
