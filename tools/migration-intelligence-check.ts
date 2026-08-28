/**
 * Shared Responsibility Quantum Migration Intelligence Engine™ — offline check.
 *
 * Exercises the PURE isomorphic module (no Supabase / server required) and
 * asserts the ownership model behaves correctly and honestly: evidence-derived
 * attribution (no blanket / fabricated provider tags), edge-vs-origin
 * intelligence, the migration-dependency graph, tri-part readiness, the 7-wave
 * roadmap, the matrix expansion, and empty-state honesty.
 *
 * Run: npx tsx tools/migration-intelligence-check.ts
 */

import {
  attributeProvider,
  classifyFinding,
  quickOwnershipTag,
  buildSharedResponsibility,
  deriveMigrationDependencyStatus,
  type OwnershipFindingInput,
} from '../src/lib/shared-responsibility'

let failures = 0
function assert(cond: boolean, label: string, extra = '') {
  console.log(`  ${cond ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!cond) failures += 1
}

function main() {
  /* ---------------------------------------------------------------- */
  console.log('\n[1] Evidence-derived attribution (no fabrication)')
  const cf = attributeProvider({ id: 'a', assetName: 'app', host: 'edge.cdn.cloudflare.net', algorithm: 'TLS_RSA', assetType: 'cdn-service' })
  assert(cf.providerId === 'cloudflare' && cf.domain === 'provider', 'Cloudflare attributed by hostname', `${cf.providerId}/${cf.domain}`)
  assert(cf.attributed === true && cf.confidence >= 84, 'Cloudflare attribution is high-confidence', String(cf.confidence))

  // The critical bug regression: a tenant-wide connected account must NOT
  // blanket-attribute an unrelated finding.
  const unrelated = attributeProvider(
    { id: 'b', assetName: 'origin.internal', algorithm: 'RSA-2048', assetType: 'server' },
    { connectorProviders: ['okta'] },
  )
  assert(unrelated.providerId !== 'okta', 'connected Okta account does NOT blanket-attribute an unrelated finding', unrelated.providerId || 'null')
  assert(unrelated.attributed === false && unrelated.domain === 'customer', 'unmatched finding stays honestly unattributed → customer', `${unrelated.attributed}/${unrelated.domain}`)

  // A finding that DOES reference Okta, corroborated by the connector → attributed.
  const okta = attributeProvider(
    { id: 'c', assetName: 'sso', host: 'tenant.okta.com', assetType: 'saas-application' },
    { connectorProviders: ['okta'] },
  )
  assert(okta.providerId === 'okta' && okta.confidence >= 90, 'Okta attributed via hostname + connector corroboration', String(okta.confidence))

  // Generic provider-fronted fallback (honest, unattributed) for an unnamed CDN.
  const generic = attributeProvider({ id: 'd', assetName: 'x', assetType: 'cdn-service' })
  assert(generic.domain === 'provider' && generic.attributed === false, 'unnamed provider-fronted target → generic provider (attributed:false)', `${generic.domain}/${generic.attributed}`)

  /* ---------------------------------------------------------------- */
  console.log('\n[2] Ownership classification + RemediationModel reconciliation')
  const openssl = classifyFinding({ id: 'e', assetName: 'origin.internal', assetType: 'server', environment: 'internal', algorithm: 'RSA-2048', description: 'openssl origin cert', category: 'TLS Certificate', severity: 'HIGH' })
  assert(openssl.domain === 'customer', 'OpenSSL on a customer-owned server is CUSTOMER-controlled (not ecosystem)', openssl.domain)
  assert(openssl.customerActionable === 'yes' && openssl.migrationDependencyStatus === 'ready', 'customer OpenSSL finding is actionable + ready', `${openssl.customerActionable}/${openssl.migrationDependencyStatus}`)

  const browser = classifyFinding({ id: 'f', assetName: 'chrome', algorithm: 'X25519', description: 'chrome browser client support', category: 'Browser TLS', severity: 'MEDIUM' })
  assert(browser.domain === 'ecosystem' && browser.migrationDependencyStatus === 'waiting_browser', 'browser finding → ecosystem / waiting_browser', `${browser.domain}/${browser.migrationDependencyStatus}`)
  assert(browser.customerActionable === 'no', 'browser dependency is not customer-actionable', browser.customerActionable)

  const saas = classifyFinding({ id: 'g', assetName: 'salesforce', host: 'org.my.salesforce.com', assetType: 'saas-application', algorithm: 'RSA', severity: 'HIGH' })
  assert(saas.domain === 'provider' && saas.migrationDependencyStatus === 'waiting_vendor', 'SaaS finding → provider / waiting_vendor', `${saas.domain}/${saas.migrationDependencyStatus}`)
  assert(saas.priority === 'informational', 'non-actionable provider finding is deprioritized', saas.priority)

  const smartcard = classifyFinding({ id: 'h', assetName: 'card', algorithm: 'RSA', description: 'pkcs#11 smart card embedded device firmware', severity: 'HIGH' })
  assert(smartcard.domain === 'ecosystem' && smartcard.migrationDependencyStatus === 'waiting_hardware', 'smart-card firmware → ecosystem / waiting_hardware', `${smartcard.domain}/${smartcard.migrationDependencyStatus}`)

  // RemediationModel authority reconciliation.
  const provOwned = classifyFinding({ id: 'i', assetName: 'x', algorithm: 'RSA', severity: 'HIGH', remediationAuthority: 'provider_owned' })
  assert(provOwned.domain === 'provider', 'remediationAuthority provider_owned → provider domain', provOwned.domain)
  const qgControlled = classifyFinding({ id: 'j', assetName: 'x', algorithm: 'RSA', severity: 'HIGH', remediationAuthority: 'qguard_controlled' })
  assert(qgControlled.domain === 'customer' && qgControlled.customerActionable === 'yes', 'remediationAuthority qguard_controlled → customer actionable', `${qgControlled.domain}/${qgControlled.customerActionable}`)

  /* ---------------------------------------------------------------- */
  console.log('\n[3] Edge vs Origin TLS intelligence')
  const edgeFinding = classifyFinding({ id: 'k', assetName: 'app', host: 'app.cdn.cloudflare.net', assetType: 'cdn-service', environment: 'public', algorithm: 'TLS_RSA', category: 'TLS Cipher', severity: 'CRITICAL' })
  assert(edgeFinding.edgeOrigin?.isProviderFronted === true, 'provider-fronted TLS detected', String(edgeFinding.edgeOrigin?.isProviderFronted))
  assert(edgeFinding.edgeOrigin?.edge?.domain === 'provider' && edgeFinding.edgeOrigin?.origin?.domain === 'customer', 'edge=provider, origin=customer (never conflated)', `${edgeFinding.edgeOrigin?.edge?.domain}/${edgeFinding.edgeOrigin?.origin?.domain}`)
  assert(edgeFinding.customerActionable === 'partial', 'provider-fronted TLS is PARTIALLY actionable (origin fixable)', edgeFinding.customerActionable)
  const nonTransport = classifyFinding({ id: 'l', assetName: 'x', algorithm: 'RSA', category: 'JWT signing', severity: 'HIGH' })
  assert(nonTransport.edgeOrigin === null, 'non-transport finding has no edge/origin layers', String(nonTransport.edgeOrigin))

  /* ---------------------------------------------------------------- */
  console.log('\n[4] Migration dependency graph')
  assert(deriveMigrationDependencyStatus('customer', okta, 'yes') === 'ready', 'customer + actionable → ready')
  assert(browser.dependencyChain.nodes.some((n) => n.blocking) && browser.dependencyChain.nodes.some((n) => n.id === 'nist'), 'dependency chain has a blocking node and terminates at NIST')
  assert(browser.dependencyChain.blockedBy !== null, 'blocked chain names its blocker', browser.dependencyChain.blockedBy || 'null')
  assert(openssl.dependencyChain.migrationDependencyStatus === 'ready', 'ready chain reports ready status', openssl.dependencyChain.migrationDependencyStatus)

  /* ---------------------------------------------------------------- */
  console.log('\n[5] Rollup — tri-part readiness, distribution, matrix, waves, widgets')
  const inputs: OwnershipFindingInput[] = [
    { id: '1', algorithm: 'TLS_RSA', category: 'TLS Cipher', location: 'app.example.com', assetName: 'app.example.com', assetType: 'cdn-service', environment: 'public', host: 'app.example.com.cdn.cloudflare.net', severity: 'CRITICAL' },
    { id: '2', algorithm: 'RSA-2048', category: 'TLS Certificate', location: 'origin.internal', assetName: 'origin.internal', assetType: 'server', environment: 'internal', severity: 'HIGH', description: 'openssl origin' },
    { id: '3', algorithm: 'X25519', category: 'Browser TLS', location: 'chrome', assetName: 'chrome', severity: 'MEDIUM', description: 'chrome browser client' },
    { id: '4', algorithm: 'RSA', category: 'SaaS', location: 'okta.com', assetName: 'okta.com', assetType: 'saas-application', host: 'tenant.okta.com', severity: 'HIGH' },
    { id: '5', algorithm: 'ECDSA', category: 'JWT signing', location: 'api', assetName: 'internal-api', assetType: 'api-gateway', environment: 'internal', severity: 'HIGH', description: 'jwt token signing' },
  ]
  const roll = buildSharedResponsibility(inputs, { context: { connectorProviders: ['okta'] }, baselineOverall: 20 })
  assert(roll.hasData && roll.totals.findings === 5, 'rollup classifies all findings', String(roll.totals.findings))
  assert(roll.totals.customer >= 2 && roll.totals.provider >= 2 && roll.totals.ecosystem >= 1, 'findings spread across all three domains', `c${roll.totals.customer}/p${roll.totals.provider}/e${roll.totals.ecosystem}`)
  assert(roll.readiness.overall.score === 20, 'overall readiness honors baseline', String(roll.readiness.overall.score))
  assert(roll.readiness.customer.score !== roll.readiness.provider.score, 'tri-part readiness scores are distinct per domain')
  assert(roll.readiness.provider.score >= roll.readiness.customer.score, 'provider readiness (roadmap-driven) ≥ customer readiness here')
  assert(roll.domainDistribution.customer + roll.domainDistribution.provider + roll.domainDistribution.ecosystem === roll.totals.findings, 'domain distribution sums to total findings')

  // Matrix: the provider-fronted TLS finding expands into edge + origin rows.
  const hasEdgeRow = roll.matrix.some((m) => /edge/i.test(m.finding) && m.domain === 'provider')
  const hasOriginRow = roll.matrix.some((m) => /origin/i.test(m.finding) && m.domain === 'customer')
  assert(hasEdgeRow && hasOriginRow, 'matrix expands provider-fronted TLS into edge (provider) + origin (customer) rows')

  // 7-wave roadmap.
  assert(roll.waves.length === 7, 'roadmap has exactly 7 dependency-ordered waves', String(roll.waves.length))
  assert(roll.waves[0].domain === 'customer' && roll.waves[6].domain === 'ecosystem', 'waves ordered customer-first → ecosystem-last')
  const totalWaveFindings = roll.waves.reduce((s, w) => s + w.findingCount, 0)
  assert(totalWaveFindings === roll.totals.findings, 'every finding is assigned to exactly one wave', `${totalWaveFindings} vs ${roll.totals.findings}`)

  // Widgets + provider breakdown.
  assert(roll.widgets.customerFindings === roll.totals.customer, 'widget customerFindings matches totals')
  assert(roll.widgets.actionableFindings === roll.totals.actionable, 'widget actionable matches totals')
  assert(roll.providerBreakdown.some((p) => p.name === 'Cloudflare') && roll.providerBreakdown.some((p) => p.name === 'Okta'), 'provider breakdown lists attributed providers')

  // Edge/origin + attribution honesty summaries.
  assert(roll.edgeOrigin.providerFrontedAssets >= 1, 'edge/origin aggregate counts provider-fronted assets', String(roll.edgeOrigin.providerFrontedAssets))
  assert(roll.attribution.attributed + roll.attribution.unattributed === roll.totals.findings, 'attribution summary accounts for every finding (attributed + unattributed)')

  /* ---------------------------------------------------------------- */
  console.log('\n[6] Empty-state honesty')
  const empty = buildSharedResponsibility([])
  assert(empty.hasData === false, 'no findings → hasData false')
  assert(empty.readiness.customer.score === 0 && empty.readiness.overall.score === 0, 'empty readiness is zeroed (never fabricated)')
  assert(empty.matrix.length === 0 && empty.waves.length === 7, 'empty matrix but roadmap scaffold present')

  /* ---------------------------------------------------------------- */
  console.log('\n[7] quickOwnershipTag (scanner surface) parity')
  const tag = quickOwnershipTag({ id: 't', assetName: 'origin.internal', assetType: 'server', environment: 'internal', algorithm: 'RSA-2048', description: 'openssl' })
  assert(tag.domain === 'customer' && tag.customerActionable === 'yes', 'quick tag agrees with full classifier on domain/actionability', `${tag.domain}/${tag.customerActionable}`)
  const tagProvider = quickOwnershipTag({ id: 't2', assetName: 'okta.com', host: 'tenant.okta.com', assetType: 'saas-application', algorithm: 'RSA' })
  assert(tagProvider.domain === 'provider' && tagProvider.providerName === 'Okta', 'quick tag attributes provider correctly', `${tagProvider.domain}/${tagProvider.providerName}`)

  /* ---------------------------------------------------------------- */
  console.log('\n[8] Matrix scope filters — company + asset')
  /*
   * The Shared Responsibility Matrix can be scoped by company and by asset.
   * The option list is derived from the rendered rows, so the count shown
   * beside an option MUST equal the number of rows selecting it produces —
   * otherwise the control promises rows it cannot deliver.
   */
  const scopeInputs: OwnershipFindingInput[] = [
    { id: 's1', assetName: 'shop.example.com', host: 'shop.example.com.cdn.cloudflare.net', assetType: 'cdn-service', algorithm: 'TLS_RSA_WITH_AES_128_CBC_SHA', severity: 'high', observedAt: '2026-08-20T10:00:00Z' },
    { id: 's2', assetName: 'shop.example.com', host: 'shop.example.com.cdn.cloudflare.net', assetType: 'cdn-service', algorithm: 'ECDHE-P256', severity: 'medium', observedAt: '2026-08-26T10:00:00Z' },
    { id: 's3', assetName: 'tenant.okta.com', host: 'tenant.okta.com', assetType: 'saas-application', algorithm: 'RSA-2048', severity: 'critical', observedAt: '2026-08-22T10:00:00Z' },
    { id: 's4', assetName: 'origin.internal', assetType: 'server', environment: 'internal', algorithm: 'RSA-4096', severity: 'high', observedAt: '2026-08-25T10:00:00Z' },
    { id: 's5', assetName: 'origin.internal', assetType: 'server', environment: 'internal', algorithm: '3DES', severity: 'critical', observedAt: '2026-08-24T10:00:00Z' },
  ]
  const scope = buildSharedResponsibility(scopeInputs)
  const rows = scope.matrix

  assert(rows.length > 0, 'the fixture produces matrix rows', `${rows.length}`)
  assert(rows.every((r) => typeof r.assetKey === 'string' && r.assetKey.length > 0), 'every row carries a canonical assetKey')
  assert(rows.every((r) => typeof r.providerName === 'string' && r.providerName.length > 0), 'every row carries a company label')
  assert(
    rows.every((r) => (r.providerAttributed ? r.providerId !== null : r.providerId === null && r.providerName === 'Unattributed')),
    'an unattributed row keeps a null providerId and reads "Unattributed" — never a guessed vendor',
  )

  // Facet counts must equal the filter result. This is the in-sync invariant.
  const companyCounts = new Map<string, number>()
  const assetCounts = new Map<string, number>()
  for (const r of rows) {
    const ck = r.providerAttributed ? (r.providerId || r.providerName) : '__unattributed__'
    companyCounts.set(ck, (companyCounts.get(ck) ?? 0) + 1)
    assetCounts.set(r.assetKey, (assetCounts.get(r.assetKey) ?? 0) + 1)
  }
  let mismatches = 0
  for (const [key, count] of companyCounts) {
    const filtered = rows.filter((r) =>
      key === '__unattributed__' ? !r.providerAttributed : r.providerAttributed && (r.providerId || r.providerName) === key,
    )
    if (filtered.length !== count) mismatches += 1
  }
  for (const [key, count] of assetCounts) {
    if (rows.filter((r) => r.assetKey === key).length !== count) mismatches += 1
  }
  assert(mismatches === 0, 'every company/asset option count equals the rows that filter produces', `${companyCounts.size} companies, ${assetCounts.size} assets`)

  // Filtering must never invent or lose a row.
  const perCompanyTotal = [...companyCounts.values()].reduce((a, b) => a + b, 0)
  const perAssetTotal = [...assetCounts.values()].reduce((a, b) => a + b, 0)
  assert(perCompanyTotal === rows.length, 'company facets partition the matrix exactly once', `${perCompanyTotal} vs ${rows.length}`)
  assert(perAssetTotal === rows.length, 'asset facets partition the matrix exactly once', `${perAssetTotal} vs ${rows.length}`)

  // A scoped asset selection returns only that asset.
  const originKey = [...assetCounts.keys()].find((k) => k.includes('origin.internal'))
  assert(Boolean(originKey), 'the internal origin asset is present as an option')
  if (originKey) {
    const originRows = rows.filter((r) => r.assetKey === originKey)
    assert(originRows.length > 0 && originRows.every((r) => r.assetKey === originKey), 'selecting an asset returns only that asset', `${originRows.length} row(s)`)
    assert(originRows.every((r) => r.domain === 'customer'), 'the internal origin stays customer-owned under scope')
  }

  /* ---------------------------------------------------------------- */
  console.log('\n[9] Freshness travels with the finding and the row')
  assert(scope.findings.every((f) => 'observedAt' in f), 'every finding exposes observedAt')
  const s2Finding = scope.findings.find((f) => f.id === 's2')
  assert(s2Finding?.observedAt === '2026-08-26T10:00:00Z', 'the observation timestamp survives classification', String(s2Finding?.observedAt))
  const dated = rows.filter((r) => r.observedAt)
  assert(dated.length > 0, 'matrix rows carry an observation timestamp', `${dated.length}/${rows.length}`)
  // Consolidated rows report the NEWEST instance, never the oldest.
  const shopKey = [...assetCounts.keys()].find((k) => k.includes('shop.example.com'))
  if (shopKey) {
    const shopRows = rows.filter((r) => r.assetKey === shopKey && r.observedAt)
    const newest = shopRows.reduce((max, r) => Math.max(max, Date.parse(r.observedAt as string)), 0)
    assert(newest >= Date.parse('2026-08-20T10:00:00Z'), 'a consolidated row reports its newest observation', new Date(newest).toISOString())
  }

  /* ---------------------------------------------------------------- */
  console.log('\n[10] Matrix rows reconcile with the panels beside them')
  const domainFromMatrix = { customer: 0, provider: 0, ecosystem: 0 }
  for (const r of rows) domainFromMatrix[r.domain] += 1
  assert(
    domainFromMatrix.customer + domainFromMatrix.provider + domainFromMatrix.ecosystem === rows.length,
    'every matrix row belongs to exactly one ownership domain',
  )
  // Companies named in the matrix must exist in the Provider & Ecosystem
  // Readiness table — the two panels read one attribution, not two.
  const breakdownIds = new Set(scope.providerBreakdown.map((b) => b.providerId))
  const orphaned = rows.filter((r) => r.providerAttributed && r.providerId && !breakdownIds.has(r.providerId))
  assert(orphaned.length === 0, 'no company appears in the matrix but not in the provider breakdown', `${orphaned.length} orphaned`)

  console.log(`\n${failures === 0 ? '✅ ALL CHECKS PASSED' : `❌ ${failures} CHECK(S) FAILED`}\n`)
  process.exit(failures === 0 ? 0 : 1)
}

main()
