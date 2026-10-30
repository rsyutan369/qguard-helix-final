/**
 * PQAuth™ identity pipeline — offline end-to-end check.
 *
 *     npx tsx tools/pqauth-identity-check.ts
 *
 * Drives the REAL chain the seven PQAuth pages depend on, with no network and
 * no database:
 *
 *   discovery parser  →  identityReportToRows (what is persisted)
 *                     →  buildIdentityModel  (what every page renders)
 *
 * Each section guards a defect found by the 2026-10-28 deep audit on live
 * tenants:
 *
 *   A. Nothing was ever persisted: the identity tables existed and stayed empty.
 *   B. Timeouts were recorded as "unparseable", reading as proof of absence.
 *   C. Probe targets must be the tenant's authorized, public hosts (SSRF guard).
 *   D. Discovery must separate found / no-identity / incomplete / failed.
 *   E. The trust graph drew a hard-coded edge chain; edges now need evidence.
 *   F. Token "size impact" compared whole-token sizes to signature sizes and
 *      labelled crypto-inventory rows ("NIST PQC Deadline") as tokens.
 *   G. Compatibility must answer the five questions and never send a
 *      signature workload to ML-KEM.
 *   H. Migration "complete" must not mean validated; sandbox jobs are not
 *      production progress; ML-KEM targets on signature workloads are flagged.
 *   I. The Digital Twin labels simulations and reports sync honestly.
 *   J. Readiness is null, not 0 or 100, when nothing was classified.
 */

import { assembleIdentityDiscovery, type RawProbe } from '../src/lib/scanner/identity/identity-discovery'
import { describeFetchError, probeOutcome, type IdentityProbeReport } from '../src/lib/scanner/identity/identity-probe'
import { identityReportToRows } from '../src/lib/pqauth/identity-persistence'
import {
  algorithmRole,
  assetProbeTarget,
  base64urlLength,
  buildIdentityModel,
  checkTargetRole,
  classifyHostRun,
  PQC_SIZES,
  signatureBytesFor,
  type IdentityModelInput,
} from '../src/lib/pqauth/identity-model'
import type { PQAuthProbeRecord } from '../src/types/pqauth-dashboard'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

const NOW = Date.parse('2026-10-28T12:00:00Z')
const AT = '2026-10-28T11:00:00.000Z'
const USER = '00000000-0000-4000-8000-000000000001'
const APP_ASSET = '00000000-0000-4000-8000-0000000000a1'
const IDP_ASSET = '00000000-0000-4000-8000-0000000000a2'
const RUN = '00000000-0000-4000-8000-0000000000f1'

/* A 2048-bit RSA modulus is 256 bytes → 342 base64url chars. */
const N_2048 = 'A'.repeat(342)
const PRIVATE_EXPONENT = 'PRIVATE-EXPONENT-MUST-NEVER-BE-STORED'

/* ---- Fixture: a relying app (app.acme.test) whose discovery document names
 *      an external IdP, plus the IdP itself (login.acme-idp.test). ---------- */
function report(host: string, issuer: string, opts: { jwks?: boolean; extraProbes?: RawProbe[] } = {}): IdentityProbeReport {
  const jwksUri = `https://keys.acme-idp.test/${host}/jwks`
  const raw: RawProbe[] = [
    {
      url: `https://${host}/.well-known/openid-configuration`,
      method: 'oidc-discovery',
      httpStatus: 200,
      observedAt: AT,
      body: {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: 'http://insecure.acme-idp.test/userinfo',
        jwks_uri: jwksUri,
        id_token_signing_alg_values_supported: ['RS256', 'ES256'],
        id_token_encryption_alg_values_supported: ['RSA-OAEP-256'],
        scopes_supported: ['openid'],
      },
    },
    { url: `https://${host}/.well-known/oauth-authorization-server`, method: 'oauth-as-metadata', httpStatus: 404, observedAt: AT, body: null },
    ...(opts.extraProbes ?? []),
  ]
  if (opts.jwks !== false) {
    raw.push({
      url: jwksUri,
      method: 'jwks',
      httpStatus: 200,
      observedAt: AT,
      body: {
        keys: [
          // A hostile JWKS that leaks a private exponent: it must never be stored.
          { kty: 'RSA', kid: 'rsa-1', use: 'sig', alg: 'RS256', n: N_2048, e: 'AQAB', d: PRIVATE_EXPONENT },
          { kty: 'EC', kid: 'ec-1', use: 'sig', alg: 'ES256', crv: 'P-256', x: 'x', y: 'y' },
          { kty: 'oct', kid: 'hmac-1', alg: 'HS256' },
        ],
      },
    })
  }
  const result = assembleIdentityDiscovery(raw)
  return {
    ...result,
    host,
    probes: raw.map((p) => ({
      url: p.url,
      method: p.method,
      httpStatus: p.httpStatus,
      outcome: p.body ? 'found' : p.httpStatus === null ? 'error' : 'not-found',
      detail: null,
      observedAt: p.observedAt,
    })),
  }
}

/* Simulate the database: give each written row an id, as Postgres would. */
let seq = 0
const id = (prefix: string) => `${prefix}-${String(++seq).padStart(4, '0')}`
function persist(writes: ReturnType<typeof identityReportToRows>[]) {
  const providers: any[] = []
  const keys: any[] = []
  const trust: any[] = []
  const probes: any[] = []
  for (const write of writes) {
    probes.push(...write.probes.map((p) => ({ id: id('probe'), ...p })))
    for (const provider of write.providers) {
      const existing = providers.find((p) => p.issuer === provider.row.issuer)
      const row = existing ?? { id: id('prov'), first_seen_at: AT }
      Object.assign(row, provider.row)
      if (!existing) providers.push(row)
      for (const key of provider.keys) {
        const prior = keys.find((k) => k.provider_id === row.id && k.key_id === key.key_id)
        if (prior) Object.assign(prior, key)
        else keys.push({ id: id('key'), first_seen_at: AT, provider_id: row.id, ...key })
      }
      if (provider.declaredTrust) trust.push({ id: id('rel'), target_provider_id: row.id, ...provider.declaredTrust })
    }
  }
  return { providers, keys, trust, probes }
}

const assets = [
  { id: APP_ASSET, name: 'app.acme.test', type: 'web_application', metadata: { authorized_target: 'https://app.acme.test/' }, updated_at: AT },
  { id: IDP_ASSET, name: 'login.acme-idp.test', type: 'web_application', metadata: { authorized_target: 'https://login.acme-idp.test/' }, updated_at: AT },
]

const appWrite = identityReportToRows(report('app.acme.test', 'https://login.acme-idp.test'), { userId: USER, assetId: APP_ASSET, assetHost: 'app.acme.test', runId: RUN, observedAt: AT })
const idpWrite = identityReportToRows(report('login.acme-idp.test', 'https://login.acme-idp.test'), { userId: USER, assetId: IDP_ASSET, assetHost: 'login.acme-idp.test', runId: RUN, observedAt: AT })
const db = persist([appWrite, idpWrite])

function baseInput(overrides: Partial<IdentityModelInput> = {}): IdentityModelInput {
  return {
    now: NOW,
    assets,
    providers: db.providers,
    signingKeys: db.keys,
    trustRelationships: db.trust,
    probes: db.probes,
    assetRelationships: [],
    certificates: [],
    migrationJobs: [],
    runtimeEvents: [],
    activeRun: null,
    ...overrides,
  }
}

/* ------------------------------------------------------------------ */
console.log('\nA. Discovery output is persisted — and only public metadata')
{
  assert(appWrite.probes.length === 3, 'every probe is written, including the 404 miss', `${appWrite.probes.length} probe rows`)
  assert(appWrite.probes.every((p) => p.scan_session_id === RUN && p.user_id === USER), 'probe rows carry the run id and the tenant id')
  assert(db.providers.length === 1, 'the same issuer reached from two assets is ONE provider (upsert on user_id, issuer)', `${db.providers.length}`)
  const idp = db.providers[0]
  assert(idp.asset_id === IDP_ASSET, 'the provider is linked to the asset that SERVES it, not to a relying app', String(idp.asset_id))
  assert(appWrite.providers[0].row.asset_id === undefined, 'a relying app never overwrites the IdP asset link')
  assert(appWrite.providers[0].declaredTrust?.confidence === 'declared' && appWrite.providers[0].declaredTrust?.relationship_type === 'TRUSTS', 'the relying app gets a DECLARED TRUSTS edge to the external issuer')
  assert(idpWrite.providers[0].declaredTrust === null, 'a provider served from its own host gets no self-trust edge')
  assert(db.keys.length === 3, 'one key row per published JWKS key', `${db.keys.length}`)
  const serialized = JSON.stringify([appWrite, idpWrite])
  assert(!serialized.includes(PRIVATE_EXPONENT), 'a private exponent present in a hostile JWKS is NEVER persisted')
  assert(!/"(d|p|q|dp|dq|qi|n)":/.test(serialized), 'no raw JWK key-material member (n, d, p, q, …) is written')
}

/* ------------------------------------------------------------------ */
console.log('\nB. A probe that got no response is an error, not "unparseable"')
{
  assert(probeOutcome({ status: null, body: null, error: 'Probe timed out' }) === 'error', 'timeout → error')
  assert(probeOutcome({ status: 200, body: null, error: 'Response was HTML, not a JSON discovery document' }) === 'unparseable', 'HTML 200 → unparseable')
  assert(probeOutcome({ status: 404, body: null, error: null }) === 'not-found', '404 → not-found')
  assert(probeOutcome({ status: 200, body: { issuer: 'x' }, error: null }) === 'found', 'parsed document → found')
  // Live finding (2026-10-28): undici says only "fetch failed"; the cause is on error.cause.
  const expired = Object.assign(new TypeError('fetch failed'), { cause: { code: 'CERT_HAS_EXPIRED' } })
  assert(describeFetchError(expired) === 'TLS certificate has expired', 'an expired-certificate failure is reported as such, not "fetch failed"', describeFetchError(expired))
  assert(describeFetchError(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } })) === 'DNS lookup failed', 'DNS failure is named')
  assert(/^Network error \(EWEIRD\)$/.test(describeFetchError(Object.assign(new TypeError('fetch failed'), { cause: { code: 'EWEIRD' } }))), 'an unmapped cause code is still surfaced')
}

/* ------------------------------------------------------------------ */
console.log('\nC. Only authorized public hosts are probe targets')
{
  const t = (metadata: Record<string, unknown>, name = 'x') => assetProbeTarget({ name, metadata })
  assert(t({ authorized_target: 'https://stripe.com/au' }).host === 'stripe.com' && t({ authorized_target: 'https://stripe.com/au' }).eligible, 'authorized_target URL → its hostname, eligible')
  assert(t({ host: 'cloudflare.com', target: 'TLS://cloudflare.com:443' }).host === 'cloudflare.com', 'metadata host is used when there is no authorized target')
  assert(!t({}, '10.0.0.5').eligible && /IP-literal/.test(t({}, '10.0.0.5').reason), 'an IP literal is refused with an explicit reason', t({}, '10.0.0.5').reason)
  assert(!t({ authorized_target: 'https://metadata.google.internal/' }).eligible, 'an internal host is refused by the SSRF guard', t({ authorized_target: 'https://metadata.google.internal/' }).reason)
  assert(!t({ host: 'localhost' }, 'localhost').eligible, 'localhost is refused')
  assert(!t({ host: null, target: null }, 'qguard-e2e-OKyfv1').eligible, 'an asset with no hostname is not probed', t({ host: null }, 'qguard-e2e-OKyfv1').reason)
}

/* ------------------------------------------------------------------ */
console.log('\nD. Every host run gets an honest verdict')
{
  const p = (method: string, outcome: PQAuthProbeRecord['outcome'], detail: string | null = null): PQAuthProbeRecord =>
    ({ id: method, url: `https://h.test/${method}`, method, httpStatus: outcome === 'error' ? null : outcome === 'found' ? 200 : 404, outcome, detail, observedAt: AT })
  assert(classifyHostRun([p('oidc-discovery', 'not-found'), p('saml-metadata', 'not-found')]).result === 'no-identity', 'all 404s → no-identity (proof of absence)')
  assert(classifyHostRun([p('oidc-discovery', 'unparseable', 'Response was HTML, not a JSON discovery document'), p('saml-metadata', 'not-found')]).result === 'no-identity', 'a catch-all HTML page is absence, not a provider')
  assert(classifyHostRun([p('oidc-discovery', 'error', 'Probe timed out'), p('saml-metadata', 'error', 'Probe timed out')]).result === 'failed', 'every probe errored → failed')
  const partial = classifyHostRun([p('oidc-discovery', 'error', 'Probe timed out'), p('saml-metadata', 'not-found')])
  assert(partial.result === 'incomplete' && /not proven/.test(partial.explanation), 'some probes errored → incomplete, and absence is "not proven"', partial.explanation)
  assert(classifyHostRun([p('oidc-discovery', 'found'), p('jwks', 'error', 'Probe timed out')]).result === 'incomplete', 'metadata found but JWKS unread → incomplete')
  assert(classifyHostRun([p('oidc-discovery', 'found'), p('jwks', 'found')]).result === 'identity-found', 'metadata + JWKS → identity-found')
  // Live finding: a 403 is a refusal, not proof of absence.
  const deniedProbe = (method: string): PQAuthProbeRecord => ({ ...p(method, 'unparseable', 'Access denied (HTTP 403) — presence not determined'), httpStatus: 403 })
  assert(classifyHostRun([deniedProbe('oidc-discovery'), p('saml-metadata', 'not-found')]).result === 'incomplete', 'a refused OIDC discovery probe → incomplete (presence not determined)')
  const samlDenied = classifyHostRun([p('oidc-discovery', 'not-found'), p('oauth-as-metadata', 'not-found'), deniedProbe('saml-metadata')])
  assert(samlDenied.result === 'no-identity' && /cannot be ruled out/.test(samlDenied.explanation), 'a refused SAML path is no-identity WITH a stated caveat', samlDenied.explanation)
}

/* ------------------------------------------------------------------ */
console.log('\nE. The trust graph contains only evidenced nodes and edges')
{
  const empty = buildIdentityModel(baseInput({ providers: [], signingKeys: [], trustRelationships: [], probes: [] }))
  assert(empty.graph.nodes.length === 0 && empty.graph.edges.length === 0, 'no identity records → an empty graph, not a template graph')

  // The live regression: crypto rows whose text contains "entra" / "f5" hashes.
  const lure = buildIdentityModel(baseInput({
    providers: [], signingKeys: [], trustRelationships: [], probes: [],
    assets: [{ id: APP_ASSET, name: 'central-billing', type: 'app', metadata: { fingerprint: 'f5a1f5b2' } }],
    certificates: [{ id: 'c1', asset_id: APP_ASSET, algorithm: 'RSA', name: 'Entra-like central cert' }],
  }))
  assert(lure.providers.length === 0, '"central" / "f5…" text no longer creates Microsoft Entra ID or F5 providers')

  const model = buildIdentityModel(baseInput())
  const nodeIds = new Set(model.graph.nodes.map((n) => n.id))
  assert(model.graph.edges.every((e) => nodeIds.has(e.from) && nodeIds.has(e.to)), 'every edge joins two nodes that exist')
  assert(model.graph.edges.every((e) => e.evidence && e.sourceTable), 'every edge cites its evidence and source table')
  const kinds = new Set(model.graph.edges.map((e) => `${e.type}:${e.confidence}`))
  assert(kinds.has('TRUSTS:declared'), 'the relying app → IdP edge is DECLARED (from the published document)')
  assert(kinds.has('SIGNS_WITH:observed') && kinds.has('PUBLISHES:observed'), 'JWKS keys and the hosting asset are OBSERVED edges')
  const dangling = buildIdentityModel(baseInput({ trustRelationships: [{ id: 'r-x', source_asset_id: '00000000-0000-4000-8000-00000000dead', target_provider_id: db.providers[0].id, relationship_type: 'TRUSTS', confidence: 'declared', evidence: 'x' }] }))
  assert(dangling.graph.edges.some((e) => e.confidence === 'unresolved'), 'a relationship to an asset missing from inventory is UNRESOLVED, not drawn as verified')
}

/* ------------------------------------------------------------------ */
console.log('\nF. Token intelligence uses signature sizes, from signing keys only')
{
  assert(signatureBytesFor('RS256', 'RSA', 2048, null) === 256, 'RS256 / RSA-2048 signature = 256 B')
  assert(signatureBytesFor('ES256', 'EC', 256, 'P-256') === 64 && signatureBytesFor('ES384', 'EC', 384, 'P-384') === 96 && signatureBytesFor('ES512', 'EC', 521, 'P-521') === 132, 'ES256/384/512 = 64/96/132 B')
  assert(signatureBytesFor(null, 'RSA', null, null) === null, 'an RSA key with no published modulus size is null, not a guessed 256')
  assert(signatureBytesFor('ML-DSA-65', 'AKP', null, null) === 3309, 'ML-DSA-65 = 3,309 B (FIPS 204)')
  const model = buildIdentityModel(baseInput())
  const rsa = model.tokens.projections.find((p) => p.currentAlgorithm === 'RS256')
  assert(Boolean(rsa) && rsa!.targetAlgorithm === 'ML-DSA-65' && rsa!.targetSignatureBytes === 3309, 'RS256 projects to ML-DSA-65 at 3,309 B')
  assert(rsa?.encodedDeltaBytes === base64urlLength(3309) - base64urlLength(256), 'JWS growth = base64url(3309) − base64url(256)', `${rsa?.encodedDeltaBytes} B`)
  assert(!model.tokens.projections.some((p) => /HS256|oct/i.test(p.currentAlgorithm)), 'HMAC (symmetric) is never projected as Shor-vulnerable')
  assert(model.tokens.keys.every((k) => k.id && k.sourceUrl), 'every key cites the JWKS URL it was read from')

  // Rotation: a key absent from the newest JWKS read is "no longer published".
  const rotated = buildIdentityModel(baseInput({ signingKeys: db.keys.map((k, i) => (i === 0 ? { ...k, last_seen_at: '2026-09-01T00:00:00Z' } : k)) }))
  assert(rotated.tokens.keys.filter((k) => k.lifecycle === 'no-longer-published').length === 1, 'a rotated-out key is marked no-longer-published')
  assert(rotated.readiness.vulnerableKeys === model.readiness.vulnerableKeys - 1, 'a rotated-out key no longer counts against readiness')
}

/* ------------------------------------------------------------------ */
console.log('\nG. Compatibility answers the five questions with the right primitive')
{
  const model = buildIdentityModel(baseInput())
  const row = model.compatibility.rows[0]
  assert(row.cells['token-signing'].status === 'unsupported', 'classical JWKS keys → token signing unsupported', row.cells['token-signing'].summary)
  assert(row.cells['token-encryption'].status === 'unsupported', 'RSA-OAEP JWE → token encryption unsupported')
  assert(row.cells.transport.status === 'unsupported', 'an http:// userinfo endpoint → transport unsupported')
  assert(row.cells['host-certificate'].status === 'not-verified', 'no certificate recorded → NOT VERIFIED, never a pass')
  assert(model.compatibility.issues.every((i) => [i.component, i.issue, i.why, i.cause, i.remediation].every((s) => s && s.length > 10)), 'every issue answers what / issue / why / cause / remediation')
  const signing = model.compatibility.issues.find((i) => i.dimension === 'token-signing')!
  assert(/ML-DSA/.test(signing.remediation) && /ML-KEM does not apply/.test(signing.remediation), 'signature remediation targets ML-DSA and states ML-KEM does not apply')
  const jwe = model.compatibility.issues.find((i) => i.dimension === 'token-encryption')!
  assert(/ML-KEM-768/.test(jwe.remediation), 'JWE key management remediation targets ML-KEM-768 (key establishment)')
  const none = buildIdentityModel(baseInput({ providers: db.providers.map((p) => ({ ...p, signing_algorithms_supported: ['RS256', 'none'] })) }))
  assert(none.compatibility.issues[0].severity === 'critical' && none.nextActions[0].priority === 'critical', 'alg "none" is the top, critical issue and the first next action')
}

/* ------------------------------------------------------------------ */
console.log('\nH. Migration status is earned, not submitted')
{
  assert(algorithmRole('X25519 + ML-KEM-768') === 'kem' && algorithmRole('ML-DSA-65') === 'signature' && algorithmRole('RS256') === 'signature', 'algorithm roles are recognised')
  assert(checkTargetRole('cert_transition', null, 'X25519 + ML-KEM-768').ok === false, 'a certificate transition targeting ML-KEM is flagged (ML-KEM cannot sign)')
  assert(checkTargetRole('token_signing', 'RS256', 'ML-DSA-65').ok === true, 'RS256 → ML-DSA-65 passes the role check')
  assert(checkTargetRole('tls', 'ECDHE', 'ML-DSA-65').ok === false, 'key establishment targeting a signature scheme is flagged')

  const job = (over: Record<string, unknown>) => ({ id: id('job'), user_id: USER, asset_id: IDP_ASSET, name: 'IdP signing', job_type: 'token_signing', status: 'completed', target_algorithm: 'ML-DSA-65', metadata: { sourceAlgorithm: 'RS256' }, completed_at: '2026-10-27T00:00:00Z', updated_at: '2026-10-27T00:00:00Z', ...over })

  // Discovery (AT = 2026-10-28T11:00) ran AFTER completion and still saw RSA.
  const regressed = buildIdentityModel(baseInput({ migrationJobs: [job({})] }))
  assert(regressed.migration.jobs[0].state === 'completed' && regressed.migration.jobs[0].validation.status === 'regressed', 'completed + re-discovery still classical → completed/REGRESSED, never validated')
  assert(regressed.migration.gates.find((g) => g.id === 'validate')!.status === 'blocked', 'the Validate gate is blocked by a regression')

  const awaiting = buildIdentityModel(baseInput({ migrationJobs: [job({ completed_at: '2026-10-28T11:30:00Z', updated_at: '2026-10-28T11:30:00Z' })] }))
  assert(awaiting.migration.jobs[0].validation.status === 'awaiting-rediscovery' && awaiting.migration.counts.validated === 0, 'completed after the last discovery → awaiting re-discovery, 0 validated')

  const pqcProviders = db.providers.map((p) => ({ ...p, quantum_class: 'safe' }))
  const validated = buildIdentityModel(baseInput({ providers: pqcProviders, migrationJobs: [job({})] }))
  assert(validated.migration.jobs[0].state === 'validated', 'completed + later discovery observing PQC signing → VALIDATED')

  const sandbox = buildIdentityModel(baseInput({ migrationJobs: [job({ job_type: 'sandbox_compatibility_test', metadata: { sandboxMode: true } })] }))
  assert(sandbox.migration.jobs[0].simulation && Object.values(sandbox.migration.counts).every((n) => n === 0), 'a sandbox job is flagged simulation and excluded from production counts')

  const elsewhere = buildIdentityModel(baseInput({ migrationJobs: [job({ asset_id: '00000000-0000-4000-8000-0000000000ff' })] }))
  assert(elsewhere.migration.jobs.length === 0 && elsewhere.migration.tenantJobCount === 1, 'a job on a non-identity asset is not counted as identity migration')
}

/* ------------------------------------------------------------------ */
console.log('\nI. The Digital Twin reports sync honestly and labels simulations')
{
  const never = buildIdentityModel(baseInput({ providers: [], signingKeys: [], trustRelationships: [], probes: [] }))
  assert(never.twin.sync.status === 'never-synced', 'no discovery → never-synced')
  const emptyRun = buildIdentityModel(baseInput({ providers: [], signingKeys: [], trustRelationships: [] }))
  assert(emptyRun.twin.sync.status === 'in-sync' && !/every modelled provider/i.test(emptyRun.twin.sync.detail), 'a current run with no providers says the twin is empty — not "every provider matches"', emptyRun.twin.sync.detail)
  // Live finding: one host with an expired certificate could not be read, yet the twin said "in sync".
  const failedHost = buildIdentityModel(baseInput({
    providers: [], signingKeys: [], trustRelationships: [],
    probes: [{ id: 'pf', asset_id: APP_ASSET, scan_session_id: RUN, probe_url: 'https://app.acme.test/.well-known/openid-configuration', method: 'oidc-discovery', http_status: null, outcome: 'error', detail: 'TLS certificate has expired', observed_at: AT }],
  }))
  assert(failedHost.twin.sync.status === 'partial' && /app\.acme\.test/.test(failedHost.twin.sync.detail), 'an unreadable host makes the twin PARTIAL, naming the host', failedHost.twin.sync.detail)
  assert(/fix the host's TLS certificate/.test(failedHost.discovery.hosts[0].explanation), 'a TLS failure tells the operator to fix the certificate')
  const stale = buildIdentityModel(baseInput({ now: NOW + 10 * 24 * 3600 * 1000 }))
  assert(stale.twin.sync.status === 'stale', 'newest observation older than 7 days → stale')
  const model = buildIdentityModel(baseInput())
  const mldsa = model.twin.scenarios.find((s) => s.id === 'ml-dsa-65')!
  assert(mldsa.applicable && mldsa.totals.keys === 2, 'ML-DSA-65 scenario covers the 2 classical signing keys (not the HMAC key)', `${mldsa.totals.keys}`)
  assert(mldsa.impacts[0].deltaBytes === base64urlLength(PQC_SIZES['ML-DSA-65'].signature) - base64urlLength(256), 'scenario delta is derived from the largest current signature (RSA-2048)')
  assert(model.twin.scenarios.every((s) => s.inputs.length > 0), 'every scenario lists the inputs it was computed from')
  const jwe = model.twin.scenarios.find((s) => s.id === 'ml-kem-jwe')!
  assert(jwe.applicable && /key establishment/.test(jwe.description), 'the ML-KEM scenario applies to JWE key management only')
  const noJwe = buildIdentityModel(baseInput({ providers: db.providers.map((p) => ({ ...p, key_encryption_algorithms_supported: [] })) }))
  assert(!noJwe.twin.scenarios.find((s) => s.id === 'ml-kem-jwe')!.applicable, 'without classical JWE the ML-KEM scenario is not applicable')
}

/* ------------------------------------------------------------------ */
console.log('\nJ. Readiness and next actions')
{
  const none = buildIdentityModel(baseInput({ providers: [], signingKeys: [], trustRelationships: [], probes: [] }))
  assert(none.readiness.coverage === null, 'no classified key → coverage null (renders "—"), not 0 or 100')
  assert(none.nextActions[0].id === 'run-discovery', 'eligible assets and no run → "Run identity discovery" first', none.nextActions[0].title)
  const model = buildIdentityModel(baseInput())
  assert(model.readiness.coverage === 0 && model.readiness.vulnerableKeys === 2 && model.readiness.unknownKeys === 1, 'RS256 + ES256 vulnerable, HS256 unknown → 0% coverage over 2 classified keys', JSON.stringify(model.readiness))
}

console.log(failures === 0 ? '\n✓ PQAUTH IDENTITY PIPELINE IS EVIDENCE-HONEST\n' : `\n✗ ${failures} CHECK(S) FAILED\n`)
process.exit(failures === 0 ? 0 : 1)
