import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { analyzeLabProposal, buildLabTasks, labCapabilities, runLabWorker } from '../src/api-server/sandbox-lab-engine'
import { LAB_BASELINE, LAB_PRIMITIVES, LAB_TLS_GROUPS, labReadiness, type LabAsset, type LabConfiguration, type LabResult, type LabRun } from '../src/lib/migration/sandbox-lab'

const asset: LabAsset = {
  id: 'b4b7d496-8a83-4ae1-b74a-250e16ddbd01', name: 'Local lab fixture', hostname: 'example.invalid', type: 'TLS endpoint',
  environment: 'test', owner: 'Local fixture', hasEvidence: true, postureLabel: 'Quantum vulnerable', riskScore: 70, riskLevel: 'high',
  hndlLevel: 'high', hndlScore: 75, discoveredAt: null, lastEvidenceAt: null, migrationStatus: 'Not started', vulnerableComponentCount: 1,
  algorithms: [{ algorithm: 'RSA-2048', category: 'signature', classification: 'vulnerable', keySizes: [2048], instances: 1, protocols: ['TLS 1.2'], target: 'ML-DSA-65', standard: 'FIPS 204', rationale: 'Signature replacement', severity: 'high' }],
  certificates: [{ id: 'test-certificate', name: 'Synthetic certificate record', algorithm: 'RSA-2048', keySize: 2048, issuer: 'Fixture', notAfter: null, daysToExpiry: null, quantumSafe: false, status: 'active' }],
  tlsConfiguration: { protocols: ['TLS 1.2'], cipherSuites: [], keyExchange: ['X25519'], summary: 'Recorded settings', forwardSecrecy: '' },
  findings: [], dependencies: [], recommendations: [], compatibility: { level: 'Review', score: 50, notes: [] },
}
const config: LabConfiguration = {
  primitives: ['ML-DSA-65', 'ML-KEM-768', 'AES-256-GCM', 'SHA3-256'],
  tlsGroups: ['X25519MLKEM768', 'SecP384r1MLKEM1024'], testDetected: true, compareTlsBaseline: true, analysis: true,
}

async function main() {
  const source = readFileSync('supabase/sandbox-lab-schema.sql', 'utf8')
  assert.match(source, /enable row level security/)
  assert.match(source, /revoke all .* from public, anon, authenticated/)
  assert.match(source, /grant select .* to authenticated/)
  assert.match(source, /using \(auth\.uid\(\) = user_id\)/)
  assert.match(source, /unique index .*one_live_run_per_user/)
  console.log('PASS schema contract isolates tenant reads and reserves evidence writes to service role')

  const capability = await labCapabilities()
  assert.equal(capability.worker, true)
  if (Number(process.versions.node.split('.')[0]) >= 24 && process.versions.openssl.startsWith('3.5')) {
    for (const profile of LAB_PRIMITIVES) assert.equal(capability.primitives[profile], true, profile)
    for (const group of LAB_TLS_GROUPS) assert.equal(capability.tlsGroups[group], true, group)
  }
  console.log('Provider verified by executing each offered check:', capability.provider)

  const supported = { ...config, primitives: config.primitives.filter((p) => capability.primitives[p]), tlsGroups: config.tlsGroups.filter((g) => capability.tlsGroups[g]) }
  const prepared = buildLabTasks(asset, supported)
  assert.equal(prepared.results.length, 0)
  const results: LabResult[] = []
  let operations = 0
  await runLabWorker({ tasks: prepared.tasks }, (frame) => {
    if (frame.type === 'operation') operations++
    if (frame.type === 'result') results.push(frame.data)
  })
  assert.equal(results.length, prepared.tasks.length)
  assert.equal(operations, prepared.tasks.length)
  for (const result of results) {
    assert.equal(result.status, 'passed', `${result.profile}: ${result.detail}`)
    assert(result.measures?.every((metric) => Number.isFinite(metric.value) && metric.value >= 0))
    assert(result.provider?.includes('OpenSSL'))
    console.log(`PASS ${result.level} | ${result.profile} | ${result.operation} | ${result.measures?.slice(0, 3).map((m) => `${m.name} ${m.value} ${m.unit}`).join(', ')}`)
  }
  const missing = buildLabTasks({ ...asset, certificates: [], tlsConfiguration: { ...asset.tlsConfiguration, keyExchange: [] } }, supported)
  assert(missing.results.some((result) => result.level === 'emulation' && result.status === 'not_tested'))
  assert(!missing.tasks.some((task) => task.level === 'emulation' && task.profile === LAB_BASELINE))

  const extra = LAB_PRIMITIVES.filter((p) => capability.primitives[p] && !config.primitives.includes(p))
  await runLabWorker({ tasks: buildLabTasks(asset, { ...config, primitives: extra, tlsGroups: [], testDetected: false, compareTlsBaseline: false }).tasks }, (frame) => {
    if (frame.type !== 'result') return
    assert.equal(frame.data.status, 'passed', frame.data.detail)
    console.log(`PASS execution | ${frame.data.profile}`)
  })
  const serialization = JSON.stringify(results)
  assert(!/-----BEGIN|privateKey|sharedKey|test-only.*secret/i.test(serialization))
  console.log('PASS results contain measurements and provenance without key material')

  const analysis = analyzeLabProposal(asset, config)
  const run = { status: 'finished', asset_snapshot: asset, configuration: config, results: [analysis] } as LabRun
  assert.equal(labReadiness(run).label, 'Insufficient test evidence')
  assert.equal(analysis.status, 'estimated')
  assert.equal(analysis.measures, undefined)
  assert.equal(labReadiness({ ...run, results }).label, 'Ready for migration planning')
  assert.equal(labReadiness({ ...run, results: [...results, analysis] }).label, 'Ready with conditions')
  assert.equal(labReadiness({ ...run, results: [...results, { ...results[0], profile: 'Proposed fixture', status: 'failed' }] }).label, 'Not ready')
  console.log('PASS analytical, execution, and emulation evidence remain distinct in readiness')

  await assert.rejects(runLabWorker({ probe: true }, () => {}, undefined, 1), /wall-clock limit/)
  const cancelled = new AbortController()
  await assert.rejects(runLabWorker({ tasks: prepared.tasks }, (frame) => {
    if (frame.type === 'operation') cancelled.abort()
  }, cancelled.signal), /cancelled/)
  console.log('PASS parent enforces worker timeout and cancellation')
}

void main().catch((error) => { console.error(error); process.exitCode = 1 })
