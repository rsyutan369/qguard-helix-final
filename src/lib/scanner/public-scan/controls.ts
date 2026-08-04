/**
 * QGuard Helix — Public Quantum Exposure Assessment™
 * Control evaluation: the single source of truth for every assessed control.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The Executive Summary, Encryption Score decomposition, Public Attack Surface,
 * Public Findings and Executive Recommendations panels all describe the same
 * controls. When each panel evaluated its own status, the same control could
 * legitimately read "Pass" in one card and "Fail" in another after an unrelated
 * edit. Every panel is now a projection of the array this file returns, so
 * agreement between panels is a property of the architecture, not something a
 * reviewer has to re-verify by eye.
 *
 * Rules that hold for every control here:
 *  • `score: null` means "not observable", never "zero". Unobservable controls
 *    are dropped from the score and their weight is redistributed.
 *  • `status: 'Unknown'` is used whenever the probe could not answer. A failed
 *    measurement is never rendered as a failed control.
 *  • Weights of the scored controls sum to exactly 100.
 */

import type { ControlState, PublicScanEvidence } from './types'

/** Scored dimensions and their weights. Must sum to 100. */
export const CONTROL_WEIGHTS = {
  'tls-version': 18,
  'cipher-suite': 15,
  'certificate-algorithm': 15,
  'forward-secrecy': 14,
  hsts: 10,
  'dns-caa': 8,
  'http-security': 8,
  'certificate-lifetime': 6,
  'ocsp-stapling': 3,
  'certificate-transparency': 3,
} as const

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)))

/**
 * Human-readable key exchange. Node reports `unknown` for every TLS 1.3
 * endpoint (it does not expose the negotiated group), so the named-group probe
 * fills the gap and TLS 1.3's guarantee is the fallback.
 */
export function resolveKeyExchange(evidence: PublicScanEvidence): string {
  const { keyAgreement, tls } = evidence
  if (keyAgreement.primaryGroup) {
    return keyAgreement.hybridGroups.length
      ? `Hybrid ECDHE + ML-KEM (${keyAgreement.primaryGroup})`
      : `ECDHE (${keyAgreement.primaryGroup})`
  }
  const raw = tls?.keyExchange ?? ''
  if (raw && raw !== 'unknown') return raw
  if (tls?.tlsVersion === 'TLSv1.3') return 'ECDHE (TLS 1.3 ephemeral)'
  return 'unknown'
}

/**
 * Forward secrecy as observed, WITH the caveat that changes the verdict.
 *
 * TLS 1.3 removes every static key-transport suite from the protocol, so a
 * completed 1.3 handshake *is* proof of forward secrecy regardless of what Node
 * reports for the ephemeral key.
 *
 * The caveat lives here rather than in the control so every consumer gets the
 * same sentence. The Live Handshake panel reads `basis` directly, and while the
 * caveat was applied only inside the control, the handshake step told the reader
 * "every session key is forward secret" on the same report where the Findings
 * table said Partial. One function, one answer.
 *
 * `caveated` is exposed separately so a caller can still tell the difference
 * between "no forward secrecy at all" and "forward secrecy except on the legacy
 * suites this endpoint also accepts" — they are not the same failure.
 */
export function resolveForwardSecrecy(evidence: PublicScanEvidence): {
  enabled: boolean
  caveated: boolean
  basis: string
} {
  const { tls, keyAgreement } = evidence
  // A static-RSA suite carries no ephemeral key at all, so accepting one means
  // some negotiable sessions have no forward secrecy however good the default is.
  const staticRsa = evidence.cipherSuites.some((suite) => suite.category === 'rsa-kex')
  const caveat =
    ' However, static-RSA key-transport suites are also accepted, and sessions negotiated with those suites have no forward secrecy at all.'

  const settle = (basis: string) => ({
    enabled: true,
    caveated: staticRsa,
    basis: staticRsa ? `${basis}${caveat}` : basis,
  })

  if (tls?.tlsVersion === 'TLSv1.3' || tls?.supportedProtocols.includes('TLSv1.3')) {
    return settle('TLS 1.3 mandates ephemeral (EC)DHE — every session key is forward secret.')
  }
  if (keyAgreement.forwardSecrecy) return settle(keyAgreement.forwardSecrecyBasis)
  if (/ecdhe|dhe|x25519|ffdhe/i.test(tls?.keyExchange ?? '')) {
    return settle(`Ephemeral key agreement negotiated: ${tls?.keyExchange}.`)
  }
  return { enabled: false, caveated: false, basis: 'No ephemeral key agreement observed at the edge.' }
}

/** Symmetric key length taken from the negotiated suite name. */
export function symmetricStrength(cipherSuite: string | undefined): number | null {
  if (!cipherSuite) return null
  if (/_256_|AES256|CHACHA20/i.test(cipherSuite)) return 256
  if (/_128_|AES128/i.test(cipherSuite)) return 128
  return null
}

type Draft = Omit<ControlState, 'weight'> & { weight?: number }

function control(draft: Draft): ControlState {
  const weight = draft.weight ?? CONTROL_WEIGHTS[draft.key as keyof typeof CONTROL_WEIGHTS] ?? 0
  return { ...draft, weight }
}

/**
 * Evaluate every control against the collected edge evidence.
 * Order is the display order of the Public Findings table before severity sort.
 */
export function buildControlStates(evidence: PublicScanEvidence): ControlState[] {
  const { tls, certificate, certificateExtras, cipherSuites, dns, http, keyAgreement } = evidence
  const states: ControlState[] = []

  /* ── Inventory rows (reported, not scored) ─────────────────────────────── */

  states.push(
    control({
      key: 'internet-facing',
      control: 'Internet Exposure',
      shortLabel: 'Internet Facing',
      status: dns.addressCount > 0 ? 'Healthy' : 'Unknown',
      severity: 'SAFE',
      value: dns.addressCount > 0 ? 'Yes' : 'No',
      finding: `${dns.addressCount} public address${dns.addressCount === 1 ? '' : 'es'}`,
      evidence: dns.addresses.length ? dns.addresses.slice(0, 4).join(', ') : dns.error || 'No records',
      businessImpact: 'Defines the surface reachable by any Internet client.',
      quantumImpact: 'Every exposed endpoint is a harvest-now collection point.',
      nextStep: 'Confirm this matches your intended external footprint.',
      score: null,
      weight: 0,
      observed: `${dns.addressCount} address(es) via ${dns.resolvedVia}`,
      detail: 'Public A / AAAA records resolved for the scanned host',
      inAttackSurface: true,
      isInventory: true,
      inFindings: false,
    }),
    control({
      key: 'tls-service',
      control: 'TLS Service',
      shortLabel: 'TLS Service',
      status: tls ? 'Healthy' : 'Unknown',
      severity: 'SAFE',
      value: tls ? `HTTPS (${evidence.port})` : 'None',
      finding: tls ? `TLS reachable on port ${evidence.port}` : 'No TLS service reachable',
      evidence: `Assessed endpoint: ${evidence.port}/tcp`,
      businessImpact: 'The endpoint terminating TLS for this name.',
      quantumImpact: 'This terminator is where hybrid key agreement is enabled.',
      nextStep: 'Apply PQ configuration at this terminator first.',
      score: null,
      weight: 0,
      observed: `port ${evidence.port}`,
      detail: 'TLS listener assessed by this scan',
      inAttackSurface: true,
      isInventory: true,
      inFindings: false,
    }),
    control({
      key: 'certificate-chain',
      control: 'Certificate Chain',
      shortLabel: 'Certificate Chain',
      status: certificateExtras ? 'Healthy' : 'Unknown',
      severity: 'SAFE',
      value: certificateExtras ? `${certificateExtras.chainDepth} certs` : 'Unknown',
      finding: certificateExtras ? `${certificateExtras.chainDepth} certificates presented` : 'Chain unavailable',
      evidence: certificateExtras
        ? `Leaf plus ${Math.max(0, certificateExtras.chainDepth - 1)} intermediate(s)`
        : 'Chain metadata unavailable',
      businessImpact: 'Each chain certificate is a separate PQ migration item.',
      quantumImpact: 'Every link is signed with a classical algorithm today.',
      nextStep: 'Track chain certificates in the migration inventory.',
      score: null,
      weight: 0,
      observed: certificateExtras ? `${certificateExtras.chainDepth} certificates` : 'not observed',
      detail: 'Certificates the server presents (leaf + intermediates)',
      inAttackSurface: true,
      isInventory: true,
      inFindings: false,
    }),
    control({
      key: 'covered-names',
      control: 'Names Covered',
      shortLabel: 'Names Covered',
      status: certificateExtras ? 'Healthy' : 'Unknown',
      severity: 'SAFE',
      value: certificateExtras ? String(certificateExtras.sanCount) : 'Unknown',
      finding: certificateExtras ? `${certificateExtras.sanCount} DNS names` : 'SANs unavailable',
      evidence: certificateExtras?.subjectAltNames.slice(0, 6).join(', ') || 'not observed',
      businessImpact: 'Names sharing this certificate share its migration event.',
      quantumImpact: 'All covered names inherit the leaf key’s quantum exposure.',
      nextStep: 'Confirm every covered name is still in use.',
      score: null,
      weight: 0,
      observed: certificateExtras ? `${certificateExtras.sanCount} SAN entries` : 'not observed',
      detail: `DNS names on the served certificate${certificateExtras?.isWildcard ? ' (includes a wildcard)' : ''}`,
      inAttackSurface: true,
      isInventory: true,
      inFindings: false,
    }),
  )

  /* ── TLS version ───────────────────────────────────────────────────────── */

  const protocols = tls?.supportedProtocols ?? []
  const legacy = protocols.filter((protocol) => protocol === 'TLSv1' || protocol === 'TLSv1.1')
  const hasTls13 = protocols.includes('TLSv1.3')
  const hasTls12 = protocols.includes('TLSv1.2')
  const best = hasTls13 ? 'TLS 1.3' : hasTls12 ? 'TLS 1.2' : protocols[0] || 'none'

  let tlsScore: number | null = null
  if (tls) {
    if (hasTls13 && !legacy.length) tlsScore = 100
    else if (hasTls13 && legacy.length) tlsScore = 60
    else if (hasTls12 && !legacy.length) tlsScore = 80
    else if (hasTls12) tlsScore = 45
    else tlsScore = 20
  }

  states.push(
    control({
      key: 'tls-version',
      control: 'TLS Version',
      shortLabel: 'TLS Version',
      status: !tls ? 'Unknown' : legacy.length ? 'Critical' : hasTls13 ? 'Healthy' : 'Warning',
      severity: !tls ? 'LOW' : legacy.length ? 'HIGH' : hasTls13 ? 'SAFE' : 'MEDIUM',
      value: !tls ? 'Unknown' : legacy.length ? `${best} + legacy` : best,
      finding: !tls
        ? 'Could not be determined'
        : legacy.length
          ? `${best} with legacy ${legacy.join(', ')}`
          : `${best} Detected`,
      evidence: protocols.length ? `Negotiable protocols: ${protocols.join(', ')}` : 'Handshake did not complete',
      businessImpact: legacy.length
        ? 'Deprecated protocols fail modern audits and enable downgrade attacks.'
        : 'Supports modern encryption standards.',
      quantumImpact: 'Classical key exchange remains recoverable by Shor’s algorithm regardless of version.',
      nextStep: legacy.length ? 'Disable TLS 1.0/1.1 and plan hybrid TLS rollout.' : 'Plan hybrid TLS rollout.',
      score: tlsScore,
      observed: protocols.length ? protocols.join(', ') : 'not observed',
      detail: legacy.length
        ? 'Deprecated TLS 1.0/1.1 still negotiable at the edge.'
        : hasTls13
          ? 'Modern TLS 1.3 offered, legacy protocols refused.'
          : 'TLS 1.3 not offered on the public endpoint.',
      inAttackSurface: true,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── Cipher suite ──────────────────────────────────────────────────────── */

  const staticRsa = cipherSuites.some((suite) => suite.category === 'rsa-kex')
  const weakSuites = cipherSuites.filter((s) => s.riskLevel === 'CRITICAL' || s.riskLevel === 'HIGH')
  const bits = symmetricStrength(tls?.cipherSuite)
  const groverMargin = bits ? bits / 2 : null

  let cipherScore: number | null = null
  if (tls?.cipherSuite) {
    cipherScore = 100
    if (staticRsa) cipherScore -= 35
    if (weakSuites.length) cipherScore -= Math.min(40, weakSuites.length * 12)
    // Grover halves symmetric strength: a 128-bit AEAD leaves a 64-bit
    // post-quantum margin, which is not "quantum-safe" and must cost points.
    if (bits === 128) cipherScore -= 15
    cipherScore = clamp(cipherScore)
  }

  states.push(
    control({
      key: 'cipher-suite',
      control: 'Cipher Suite',
      shortLabel: 'Cipher Suite',
      status: !tls?.cipherSuite ? 'Unknown' : staticRsa ? 'Critical' : bits === 128 ? 'Warning' : 'Healthy',
      severity: !tls?.cipherSuite ? 'LOW' : staticRsa ? 'HIGH' : bits === 128 ? 'LOW' : 'SAFE',
      // The compact value must not read as positive when the verdict is not:
      // a 256-bit AEAD alongside accepted static-RSA suites is still Weak.
      value: !tls?.cipherSuite
        ? 'Unknown'
        : staticRsa
          ? 'Static RSA accepted'
          : bits
            ? `${bits}-bit AEAD`
            : 'Negotiated',
      finding: tls?.cipherSuite || 'Could not be determined',
      evidence: tls?.cipherSuite
        ? `Negotiated: ${tls.cipherSuite}${staticRsa ? ' — static RSA suites also accepted' : ''}`
        : 'Handshake did not complete',
      businessImpact: staticRsa
        ? 'Static RSA key transport removes forward secrecy for those sessions.'
        : 'Strong authenticated encryption and performance.',
      quantumImpact: groverMargin
        ? `Grover halves symmetric strength: ${bits}-bit leaves a ${groverMargin}-bit post-quantum margin${groverMargin < 128 ? ' — below the 128-bit target' : ''}.`
        : 'Symmetric strength could not be determined from the negotiated suite.',
      nextStep: staticRsa
        ? 'Remove static-RSA suites and keep AEAD only.'
        : bits === 128
          ? 'Prefer 256-bit AEAD suites to retain a 128-bit post-quantum margin.'
          : 'Maintain 256-bit AEAD and enable PQ key agreement.',
      score: cipherScore,
      observed: tls?.cipherSuite || 'not observed',
      detail: staticRsa
        ? 'Static RSA key transport accepted — no forward secrecy on those suites.'
        : 'AEAD suite negotiated with ephemeral key agreement.',
      inAttackSurface: true,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── Certificate algorithm + chain trust (one dimension, two rows) ─────── */

  const trusted = certificateExtras?.chainTrusted ?? null
  let certScore: number | null = null
  if (certificate) {
    certScore = 100
    if (certificate.isExpired) certScore -= 70
    if (certificate.isSelfSigned) certScore -= 45
    if (trusted === false && !certificate.isSelfSigned) certScore -= 40
    const sigAlg = certificate.signatureAlgorithm.toLowerCase()
    if (sigAlg.includes('sha1') || sigAlg.includes('md5')) certScore -= 45
    if (certificate.publicKeyAlgorithm.toLowerCase().includes('rsa') && certificate.publicKeySize < 2048) {
      certScore -= 40
    }
    certScore = clamp(certScore)
  }

  // Emitted unconditionally. A control that could not be observed reports
  // Unknown with a null score; omitting the row entirely would silently drop
  // its weight and break the "weights sum to 100" contract the score
  // decomposition publishes.
  const rsaWeak = Boolean(
    certificate?.publicKeyAlgorithm.toLowerCase().includes('rsa') && certificate.publicKeySize < 2048,
  )
  states.push(
    control({
      key: 'certificate-algorithm',
      control: 'Certificate Algorithm',
      shortLabel: 'Certificate Algorithm',
      status: !certificate ? 'Unknown' : rsaWeak || certificate.isExpired ? 'Critical' : 'Warning',
      severity: !certificate ? 'LOW' : rsaWeak || certificate.isExpired ? 'CRITICAL' : 'MEDIUM',
      value: certificate?.publicKeyAlgorithm ?? 'Unknown',
      finding: certificate?.publicKeyAlgorithm ?? 'Could not be determined',
      evidence: certificate
        ? `${certificate.publicKeyAlgorithm} · ${certificate.publicKeySize}-bit · signed with ${certificate.signatureAlgorithm}`
        : 'No certificate could be read from the endpoint',
      businessImpact: !certificate
        ? 'The served certificate could not be read during this scan.'
        : rsaWeak
          ? 'Key size below current classical guidance.'
          : 'Good performance and widely supported.',
      quantumImpact: 'Vulnerable to Shor’s algorithm — the private key is recoverable by a CRQC.',
      nextStep: 'Migrate to hybrid PQC certificates (FIPS 204 signature alongside the classical key).',
      score: certScore,
      observed: certificate
        ? `${certificate.publicKeyAlgorithm} / ${certificate.signatureAlgorithm}`
        : 'not observed',
      detail: !certificate
        ? 'No certificate was presented, so this dimension is not scored.'
        : certificate.isExpired
          ? 'Served certificate is expired.'
          : 'Certificate key and signature algorithms within current classical guidance.',
      inAttackSurface: false,
      isInventory: false,
      inFindings: true,
    }),
  )

  const issuer = certificate?.issuer.O || certificate?.issuer.CN || 'Unknown issuer'
  states.push(
    control({
      key: 'certificate-issuer',
      control: 'Certificate Issuer',
      shortLabel: 'Chain Trust',
      status: !certificate
        ? 'Unknown'
        : certificate.isSelfSigned
          ? 'Critical'
          : trusted === null
            ? 'Unknown'
            : trusted
              ? 'Healthy'
              : 'Critical',
      severity: certificate?.isSelfSigned || trusted === false ? 'HIGH' : trusted === null ? 'LOW' : 'SAFE',
      value: !certificate
        ? 'Unknown'
        : certificate.isSelfSigned
          ? 'Self-signed'
          : trusted === null
            ? 'Unknown'
            : trusted
              ? 'Pass'
              : 'Fail',
      finding: certificate ? issuer : 'Could not be determined',
      evidence:
        trusted === false && certificateExtras?.trustError
          ? `Issuer: ${issuer} — verification failed: ${certificateExtras.trustError}`
          : certificate
            ? `Issuer: ${issuer}${trusted ? ' — chain verified against the public root store' : ''}`
            : 'No certificate chain was presented',
      businessImpact: !certificate
        ? 'The certificate chain could not be read during this scan.'
        : certificate.isSelfSigned
          ? 'Self-signed certificate — clients cannot establish trust.'
          : trusted === false
            ? 'Chain does not validate against the public root store — clients will warn or refuse.'
            : trusted === null
              ? 'Chain validation could not be performed during this scan.'
              : 'Chain validates against the public root store.',
      quantumImpact: 'CA signing is classical; issuance must move to FIPS 204 signatures.',
      nextStep: 'Adopt a PQ-ready CA roadmap and track issuer PQC timelines.',
      // Scored inside certificate-algorithm — one dimension, so the two rows
      // can never disagree about the same underlying trust result.
      score: null,
      weight: 0,
      observed: certificate ? issuer : 'not observed',
      detail: 'Verified with Node chain validation against the public root store',
      inAttackSurface: true,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── Certificate lifetime ──────────────────────────────────────────────── */

  const daysRemaining = certificateExtras?.daysRemaining ?? 0
  const validityDays = certificateExtras?.validityDays ?? 0
  const expiring = daysRemaining <= 30
  let lifecycleScore: number | null = null
  if (certificateExtras) {
    lifecycleScore = 0
    if (validityDays > 0 && validityDays <= 100) lifecycleScore += 60
    else if (validityDays <= 200) lifecycleScore += 45
    else if (validityDays <= 400) lifecycleScore += 30
    else lifecycleScore += 15
    if (daysRemaining > 30) lifecycleScore += 40
    else if (daysRemaining > 14) lifecycleScore += 20
    lifecycleScore = clamp(lifecycleScore)
  }

  states.push(
    control({
      key: 'certificate-lifetime',
      control: 'Certificate Lifetime',
      shortLabel: 'Certificate Lifetime',
      status: !certificateExtras
        ? 'Unknown'
        : certificate?.isExpired
          ? 'Critical'
          : expiring
            ? 'Warning'
            : 'Healthy',
      severity: !certificateExtras ? 'LOW' : certificate?.isExpired ? 'CRITICAL' : expiring ? 'MEDIUM' : 'SAFE',
      value: certificateExtras ? `${daysRemaining}d left` : 'Unknown',
      finding: certificateExtras ? `${daysRemaining} days remaining` : 'Could not be determined',
      evidence: certificateExtras
        ? `${validityDays}-day issued lifetime, ${daysRemaining} days remaining`
        : 'Certificate validity dates unavailable',
      businessImpact: !certificateExtras
        ? 'Certificate validity could not be read during this scan.'
        : certificate?.isExpired
          ? 'Expired certificate — clients will refuse the connection.'
          : expiring
            ? 'Renewal window is close; outages are possible.'
            : 'Good certificate lifecycle hygiene.',
      quantumImpact: 'Shorter lifetimes make a PQ algorithm rollover a routine renewal.',
      nextStep: certificate?.isExpired ? 'Reissue immediately.' : 'Maintain automated renewal.',
      score: lifecycleScore,
      observed: certificateExtras
        ? `${validityDays}-day lifetime, ${daysRemaining} days remaining`
        : 'not observed',
      detail: !certificateExtras
        ? 'Validity dates unavailable, so this dimension is not scored.'
        : validityDays <= 100
          ? 'Short-lived certificates indicate automated issuance and rotation.'
          : 'Longer certificate lifetimes slow crypto-agility during a PQC migration.',
      inAttackSurface: false,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── Forward secrecy ───────────────────────────────────────────────────── */

  const fs = resolveForwardSecrecy(evidence)
  const kex = resolveKeyExchange(evidence)

  states.push(
    control({
      key: 'forward-secrecy',
      control: 'Forward Secrecy',
      shortLabel: 'Key Exchange',
      status: !tls ? 'Unknown' : fs.enabled ? (staticRsa ? 'Warning' : 'Healthy') : 'Critical',
      severity: !tls ? 'LOW' : fs.enabled ? 'SAFE' : 'HIGH',
      value: keyAgreement.hybridGroups.length ? 'Hybrid PQ' : kex.split(' (')[0] || 'Unknown',
      finding: !tls
        ? 'Could not be determined'
        : fs.enabled
          ? staticRsa
            ? `Partial — ${kex} on modern suites, none on static RSA`
            : `Enabled (${kex})`
          : 'Not observed',
      evidence: fs.basis,
      businessImpact: !fs.enabled
        ? 'A single server-key compromise decrypts all recorded traffic.'
        : staticRsa
          ? 'Sessions negotiated with the accepted static-RSA suites can be decrypted later from the server key alone.'
          : 'Protects past sessions from later key compromise.',
      quantumImpact: keyAgreement.hybridGroups.length
        ? 'Hybrid ML-KEM extends forward secrecy against a future quantum adversary.'
        : 'Classical forward secrecy alone does not stop harvest-now-decrypt-later.',
      nextStep: !fs.enabled
        ? 'Require ephemeral (EC)DHE on every accepted cipher suite.'
        : staticRsa
          ? 'Remove the static-RSA key-transport suites so every accepted suite is ephemeral.'
          : keyAgreement.hybridGroups.length
            ? 'Keep the hybrid group enabled and extend it to internal services.'
            : 'Migrate to hybrid PQ key exchange (X25519MLKEM768).',
      score: tls ? (fs.enabled ? (staticRsa ? 70 : 100) : 0) : null,
      observed: kex,
      detail: fs.basis,
      inAttackSurface: true,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── Post-quantum key agreement (feeds the PQ score, not the classical) ── */

  const hybrid = keyAgreement.hybridGroups
  // Standalone ML-KEM: real post-quantum key agreement, but with no classical
  // hedge. It never counts as hybrid deployment — it is stated separately so an
  // endpoint offering it is not reported as having nothing.
  const pureKem = keyAgreement.pureKemGroups ?? []
  // Hybrid ML-KEM is only reachable on an endpoint that negotiates TLS 1.3.
  const hybridReachable = evidence.engines?.tls?.data?.hybridProbed ?? true
  states.push(
    control({
      key: 'pq-key-agreement',
      control: 'Post-Quantum Key Agreement',
      shortLabel: 'Post-Quantum Key Agreement',
      status: !keyAgreement.probed ? 'Unknown' : hybrid.length ? 'Healthy' : 'Not Supported',
      severity: !keyAgreement.probed ? 'LOW' : hybrid.length ? 'SAFE' : 'HIGH',
      value: !keyAgreement.probed ? 'Unknown' : hybrid.length ? 'Pass' : 'Fail',
      finding: !keyAgreement.probed
        ? 'Could not be determined'
        : hybrid.length
          ? hybrid.join(', ')
          : pureKem.length
            ? `Standalone ${pureKem.join(', ')} only — no hybrid group`
            : 'No hybrid PQ group accepted',
      // When the endpoint has no TLS 1.3, hybrid ML-KEM is not merely absent —
      // it is unreachable, because those groups exist only in the TLS 1.3
      // key_share. Saying so is far more useful than "no group accepted".
      evidence: !keyAgreement.probed
        ? 'Named-group probe did not run'
        : !hybridReachable
          ? 'Endpoint does not negotiate TLS 1.3, where ML-KEM groups are defined — hybrid PQ is unreachable until TLS 1.3 is enabled'
          : [
              `Named-group probe accepted: ${[...hybrid, ...pureKem, ...keyAgreement.classicalGroups].join(', ') || 'none'}`,
              pureKem.length && !hybrid.length
                ? `Standalone ML-KEM (${pureKem.join(', ')}) is accepted, but without a classical hedge it is not counted as hybrid deployment.`
                : '',
            ]
              .filter(Boolean)
              .join(' · '),
      businessImpact: hybrid.length
        ? 'New sessions are already protected against harvest-now-decrypt-later.'
        : 'Traffic captured today can be decrypted once a quantum computer exists.',
      quantumImpact: hybrid.length
        ? 'ML-KEM (FIPS 203) key encapsulation resists Shor’s algorithm.'
        : 'Key agreement is fully recoverable by Shor’s algorithm.',
      nextStep: hybrid.length
        ? 'Extend hybrid coverage to internal services and machine identities.'
        : !hybridReachable
          ? 'Enable TLS 1.3 first — it is the prerequisite for any hybrid ML-KEM group.'
          : 'Enable X25519MLKEM768 — supported by current TLS stacks and CDNs.',
      // Scored by the post-quantum model, not the classical weighted mean.
      score: null,
      weight: 0,
      observed: hybrid.join(', ') || (hybridReachable ? 'none accepted' : 'TLS 1.3 not supported'),
      // States the RESULT, not the method. The previous wording — "Hybrid
      // ML-KEM groups accepted when offered in isolation under a TLS 1.3
      // floor" — described how the probe works and read, next to a Fail dot,
      // as though groups had been accepted.
      detail: !keyAgreement.probed
        ? 'Named-group probe did not run, so hybrid support is Unknown'
        : !hybridReachable
          ? 'ML-KEM groups exist only in the TLS 1.3 key_share; this endpoint does not negotiate TLS 1.3'
          : hybrid.length
            ? `Hybrid ML-KEM accepted: ${hybrid.join(', ')} — each confirmed by offering it in isolation`
            : pureKem.length
              ? `Only standalone ML-KEM accepted (${pureKem.join(', ')}); no hybrid ECDHE + ML-KEM group was offered`
              : 'No hybrid ML-KEM group was accepted when each was offered in isolation',
      inAttackSurface: true,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── HSTS ──────────────────────────────────────────────────────────────── */

  const hsts = http.headers.find((header) => header.name === 'strict-transport-security')

  /**
   * HSTS graded on its DIRECTIVES, not as a binary.
   *
   * The control used to collapse everything into secure / present / absent, so
   * every non-perfect policy produced the same "Enable HSTS with
   * includeSubDomains and preload" line — including for endpoints that already
   * had both. Two things that made that wrong:
   *
   *  • `preload` is not a universal best practice. Submission is effectively
   *    irreversible on browser timescales, and the preload list only accepts
   *    REGISTRABLE DOMAINS — recommending it for `api.example.com` is advice
   *    that cannot be followed. `preloadBlockers` already knows this.
   *  • max-age is a spectrum. A 300-second policy and an 11-month policy are
   *    materially different risks and deserve different scores.
   *
   * `analyzeHsts` already computes max-age, includeSubDomains, preload and
   * preload eligibility with its blockers; this control now reads them instead
   * of re-deriving a yes/no.
   */
  const hstsDetail = evidence.engines?.http?.data?.hsts
  const ONE_YEAR = 31_536_000
  const maxAge = hstsDetail?.maxAge ?? 0
  const includeSubDomains = hstsDetail?.includeSubDomains ?? false
  const preloaded = hstsDetail?.preload ?? false
  // Only suggest preload when the name is actually eligible to be submitted.
  const preloadPossible =
    Boolean(hstsDetail) && !hstsDetail!.preloadBlockers.some((blocker) => /registrable domains/.test(blocker))

  const hstsGaps: string[] = []
  if (maxAge > 0 && maxAge < ONE_YEAR) {
    hstsGaps.push(`raise max-age to 31536000 (currently ${maxAge}s ≈ ${Math.round(maxAge / 86_400)}d)`)
  }
  if (!includeSubDomains) hstsGaps.push('add includeSubDomains')
  if (!preloaded && preloadPossible && maxAge >= ONE_YEAR && includeSubDomains) {
    hstsGaps.push('optionally submit to the preload list once you are certain every subdomain is HTTPS-only')
  }

  // Graduated: absent is a real failure, a short max-age is proportionally
  // weaker, and a full-year policy with subdomain coverage is a pass whether or
  // not it is preloaded.
  const hstsScore = !http.reachable
    ? null
    : !hstsDetail?.present
      ? 0
      : maxAge >= ONE_YEAR && includeSubDomains
        ? preloaded
          ? 100
          : 95
        : maxAge >= ONE_YEAR
          ? 75
          : maxAge >= 86_400 * 30
            ? 55
            : maxAge > 0
              ? 30
              : 10

  const hstsHealthy = (hstsScore ?? 0) >= 95

  states.push(
    control({
      key: 'hsts',
      control: 'HSTS',
      shortLabel: 'HSTS',
      status: !http.reachable
        ? 'Unknown'
        : !hstsDetail?.present
          ? 'Not Supported'
          : hstsHealthy
            ? 'Healthy'
            : 'Warning',
      severity: !http.reachable
        ? 'LOW'
        : !hstsDetail?.present
          ? 'MEDIUM'
          : hstsHealthy
            ? 'SAFE'
            : maxAge < 86_400 * 30
              ? 'MEDIUM'
              : 'LOW',
      value: !http.reachable
        ? 'Unknown'
        : !hstsDetail?.present
          ? 'Fail'
          : hstsHealthy
            ? 'Pass'
            : 'Partial',
      finding: !http.reachable
        ? 'Could not be determined'
        : !hstsDetail?.present
          ? 'Not enabled'
          : hstsHealthy
            ? `Enforced${preloaded ? ' and preloaded' : ''} · ${Math.round(maxAge / 86_400)}d max-age with includeSubDomains`
            : `${Math.round(maxAge / 86_400)}d max-age${includeSubDomains ? ' with includeSubDomains' : ', no includeSubDomains'}`,
      evidence: !http.reachable
        ? http.error || 'HTTP origin unreachable'
        : hsts?.value
          ? `Strict-Transport-Security: ${hsts.value}`
          : 'Header absent',
      businessImpact: !http.reachable
        ? 'The HTTP origin did not respond, so transport headers could not be read.'
        : !hstsDetail?.present
          ? 'Users can be downgraded to plaintext on first contact.'
          : hstsHealthy
            ? 'Protects against protocol downgrade attacks.'
            : !includeSubDomains
              ? 'Subdomains are not covered, so a downgrade path remains on every name below this one.'
              : 'The policy expires sooner than a year, narrowing the window in which returning users are protected.',
      quantumImpact: 'No direct quantum risk; narrows the downgrade path during a hybrid rollout.',
      nextStep: !http.reachable
        ? 'Re-run the assessment when the origin is reachable.'
        : !hstsDetail?.present
          ? 'Send Strict-Transport-Security with max-age=31536000; includeSubDomains.'
          : hstsGaps.length
            ? `${hstsGaps[0].charAt(0).toUpperCase()}${hstsGaps[0].slice(1)}.`
            : 'Continue monitoring.',
      score: hstsScore,
      observed: hsts?.value || (http.reachable ? 'absent' : 'origin unreachable'),
      detail: !hstsDetail?.present
        ? 'No enforced HTTPS policy at the edge.'
        : hstsHealthy
          ? `Long-lived HSTS policy enforces HTTPS on subsequent visits${preloaded ? ', and the name is submitted for preloading' : ''}.`
          : hstsGaps.join('; ') || 'HSTS policy present.',
      inAttackSurface: true,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── OCSP stapling + responder liveness ────────────────────────────────── */

  // The scan makes a real request to the advertised responder, so revocation is
  // assessed on TWO facts rather than one. They are genuinely different:
  //   stapled          the server hands clients a fresh response itself
  //   responder alive  clients that have to ask the CA get an answer
  // A certificate that neither staples NOR has a live responder leaves every
  // soft-failing client with no revocation checking at all — strictly worse
  // than "not stapled", and previously reported identically to it.
  const responderState = certificateExtras?.ocspResponderState ?? 'not-probed'
  const responderDead = responderState === 'unreachable'
  /**
   * NO RESPONDER IS NOT A FAILURE.
   *
   * Stapling is impossible without an OCSP responder in the certificate's AIA
   * extension, and the modern CA trend is deliberately away from OCSP: Let's
   * Encrypt retired its responders in 2025, and Cloudflare, Google and others
   * have followed, relying on short-lived certificates plus Certificate
   * Transparency for the same assurance. Marking those endpoints "Not stapled"
   * scored a current best practice as a weakness and generated a remediation
   * step the operator physically cannot perform.
   *
   * So the control reports `Not Applicable` — the same "no verdict" state the
   * model already uses for anything unmeasurable. `score: null` drops the
   * dimension and redistributes its 5% weight, exactly as it does for an
   * unqueryable CAA RRset.
   */
  const ocspAdvertised = Boolean(certificateExtras?.ocspUri)
  const ocspApplicable = Boolean(certificateExtras) && ocspAdvertised
  const shortLived = (certificateExtras?.validityDays ?? 0) > 0 && (certificateExtras?.validityDays ?? 0) <= 100
  const ctLogged = Boolean(certificateExtras?.signedCertificateTimestamps)

  const noResponderExplanation = [
    'OCSP stapling is unavailable because the certificate does not advertise an OCSP responder.',
    shortLived && ctLogged
      ? `This deployment relies on short-lived certificates (${certificateExtras?.validityDays}-day lifetime) and Certificate Transparency (${certificateExtras?.sctCount} SCTs) instead — a current best practice, not a gap.`
      : shortLived
        ? `This deployment relies on short-lived certificates (${certificateExtras?.validityDays}-day lifetime) instead.`
        : 'Modern deployments may rely on short-lived certificates and Certificate Transparency instead.',
  ].join(' ')

  const ocspEvidence = !certificateExtras
    ? 'Certificate probe did not complete'
    : ocspAdvertised
      ? `AIA OCSP: ${certificateExtras.ocspUri} — ${certificateExtras.ocspResponderDetail ?? 'responder not probed'}`
      : // The full explanation goes in `evidence`, not just `detail`: the Findings
        // table renders evidence as text, whereas `detail` only reaches the
        // Attack Surface as a hover tooltip. A reader who sees "Not applicable"
        // has to be told why without hunting for it.
        noResponderExplanation

  states.push(
    control({
      key: 'ocsp-stapling',
      control: 'OCSP Stapling',
      shortLabel: 'OCSP Stapling',
      status: !certificateExtras
        ? 'Unknown'
        : !ocspApplicable
          ? 'Not Applicable'
          : certificateExtras.ocspStapled
            ? 'Healthy'
            : responderDead
              ? 'Critical'
              : 'Warning',
      severity: !certificateExtras || !ocspApplicable
        ? 'SAFE'
        : certificateExtras.ocspStapled
          ? 'SAFE'
          : responderDead
            ? 'HIGH'
            : 'LOW',
      // Not stapling is a Partial verdict, so the value says so rather than
      // showing a harder "Fail" than the status it carries.
      value: !certificateExtras
        ? 'Unknown'
        : !ocspApplicable
          ? 'Not applicable'
          : certificateExtras.ocspStapled
            ? 'Pass'
            : responderDead
              ? 'No revocation path'
              : 'Not stapled',
      finding: !certificateExtras
        ? 'Could not be determined'
        : !ocspApplicable
          ? 'No OCSP responder advertised'
          : certificateExtras.ocspStapled
            ? 'Enabled'
            : responderDead
              ? 'Not stapled, and the advertised responder did not answer'
              : 'Not stapled',
      evidence: ocspEvidence,
      businessImpact: !ocspApplicable
        ? 'No impact — revocation assurance comes from certificate lifetime and CT for this deployment.'
        : certificateExtras?.ocspStapled
          ? 'Improves validation latency and privacy.'
          : responderDead
            ? 'Neither stapled nor reachable: clients that soft-fail revocation are not checking revocation for this endpoint at all.'
            : 'Clients must contact the CA, leaking browsing metadata and adding latency.',
      quantumImpact: ocspApplicable
        ? 'OCSP responses are classically signed and will need PQ re-anchoring.'
        : 'No OCSP signing chain to re-anchor for this deployment.',
      nextStep: !ocspApplicable
        ? 'No action — stapling is not possible, and is not required, without a responder.'
        : certificateExtras?.ocspStapled
          ? 'Continue monitoring.'
          : responderDead
            ? 'Enable OCSP stapling and raise the unreachable responder with your CA.'
            : 'Enable OCSP stapling at the TLS terminator.',
      // `null` when inapplicable: the weight is redistributed rather than the
      // endpoint being penalised for a responder its CA no longer operates.
      score: !ocspApplicable ? null : certificateExtras!.ocspStapled ? 100 : responderDead ? 10 : 40,
      observed: !certificateExtras
        ? 'certificate unavailable'
        : !ocspAdvertised
          ? 'no responder advertised'
          : certificateExtras.ocspStapled
            ? 'stapled'
            : responderState === 'reachable'
              ? 'not stapled, responder reachable'
              : responderDead
                ? 'not stapled, responder unreachable'
                : 'not stapled',
      detail: !certificateExtras
        ? 'Revocation status stapled to the handshake'
        : !ocspAdvertised
          ? noResponderExplanation
          : certificateExtras.ocspStapled
            ? 'Revocation response stapled to the handshake — no CA round-trip needed.'
            : responderDead
              ? 'No staple, and a live request to the advertised responder went unanswered.'
              : responderState === 'reachable'
                ? 'No staple; clients must reach the CA, which answered when probed.'
                : 'No revocation response stapled to the handshake.',
      inAttackSurface: true,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── Certificate Transparency ──────────────────────────────────────────── */

  states.push(
    control({
      key: 'certificate-transparency',
      control: 'Certificate Transparency',
      shortLabel: 'Certificate Transparency',
      status: !certificateExtras
        ? 'Unknown'
        : certificateExtras.signedCertificateTimestamps
          ? 'Healthy'
          : 'Warning',
      severity: !certificateExtras ? 'LOW' : certificateExtras.signedCertificateTimestamps ? 'SAFE' : 'LOW',
      value: !certificateExtras
        ? 'Unknown'
        : certificateExtras.signedCertificateTimestamps
          ? `${certificateExtras.sctCount} SCT${certificateExtras.sctCount === 1 ? '' : 's'}`
          : 'No SCTs',
      finding: !certificateExtras
        ? 'Could not be determined'
        : certificateExtras.signedCertificateTimestamps
          ? `${certificateExtras.sctCount} SCT${certificateExtras.sctCount === 1 ? '' : 's'} embedded`
          : 'No SCTs observed',
      evidence: `Embedded SCT extension: ${certificateExtras?.signedCertificateTimestamps ? 'present' : 'absent'}`,
      businessImpact: certificateExtras?.signedCertificateTimestamps
        ? 'Mis-issuance is publicly auditable.'
        : 'Mis-issued certificates would not be publicly detectable.',
      quantumImpact: 'CT log signatures are classical and will need PQ re-anchoring.',
      nextStep: 'Monitor CT logs for unexpected issuance under this domain.',
      score: !certificateExtras ? null : certificateExtras.signedCertificateTimestamps ? 100 : 0,
      observed: certificateExtras?.signedCertificateTimestamps
        ? `${certificateExtras.sctCount} SCTs`
        : 'none observed',
      detail: 'Signed Certificate Timestamps embedded in the leaf certificate',
      inAttackSurface: true,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── DNS CAA ───────────────────────────────────────────────────────────── */

  states.push(
    control({
      key: 'dns-caa',
      control: 'DNS Security (CAA)',
      shortLabel: 'DNS Security (CAA)',
      status: !dns.caaQueryable ? 'Unknown' : dns.caaPresent ? 'Healthy' : 'Not Supported',
      severity: !dns.caaQueryable ? 'LOW' : dns.caaPresent ? 'SAFE' : 'MEDIUM',
      value: !dns.caaQueryable ? 'Unknown' : dns.caaPresent ? 'Pass' : 'Fail',
      finding: !dns.caaQueryable
        ? 'Could not be determined'
        : dns.caaPresent
          ? 'CAA policy published'
          : 'No CAA records',
      evidence: !dns.caaQueryable
        ? 'CAA query did not return an authoritative answer'
        : dns.caaPresent
          ? dns.caaRecords.join(' | ')
          : 'No CAA RRset at the name or its registrable domain',
      businessImpact: !dns.caaQueryable
        ? 'CAA issuance policy could not be read from this vantage point.'
        : dns.caaPresent
          ? 'Restricts which authorities may issue for this domain.'
          : 'Any public CA may issue certificates for this domain.',
      quantumImpact: 'Controls which CA will issue your future PQ certificates.',
      nextStep: !dns.caaQueryable
        ? 'Verify CAA directly with your DNS provider.'
        : dns.caaPresent
          ? 'Continue monitoring.'
          : 'Publish CAA records for the approved authorities.',
      score: !dns.caaQueryable ? null : dns.caaPresent ? 100 : 0,
      observed: dns.caaQueryable
        ? dns.caaPresent
          ? dns.caaRecords.join(' | ')
          : 'no CAA records published'
        : 'CAA query unavailable from this vantage point',
      detail: !dns.caaQueryable
        ? 'The CAA RRset could not be queried, so issuance policy is Unknown — not scored.'
        : 'CAA restricts which authorities may issue for this name.',
      inAttackSurface: true,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── HTTP transport headers (aggregate) ────────────────────────────────── */

  // HSTS is scored as its own control. Headers whose protection is delivered by
  // another header (X-Frame-Options under a restrictive CSP frame-ancestors)
  // are dropped from BOTH sides of the ratio — the same "inapplicable is not a
  // failure" rule the score model uses everywhere else.
  const otherHeaders = http.headers.filter(
    (header) => header.name !== 'strict-transport-security' && header.applicable !== false,
  )
  const supersededHeaders = http.headers.filter((header) => header.applicable === false)
  const hardened = otherHeaders.filter((header) => header.secure).length
  const missingRequired = otherHeaders.filter((header) => header.required && !header.secure)

  states.push(
    control({
      key: 'http-security',
      control: 'HTTP Security Headers',
      shortLabel: 'HTTP Headers',
      status: !http.reachable
        ? 'Unknown'
        : missingRequired.length
          ? 'Warning'
          : hardened === otherHeaders.length
            ? 'Healthy'
            : 'Warning',
      severity: !http.reachable ? 'LOW' : missingRequired.length ? 'MEDIUM' : 'SAFE',
      value: http.reachable ? `${hardened}/${otherHeaders.length}` : 'Unknown',
      finding: http.reachable
        ? `${hardened} of ${otherHeaders.length} transport headers hardened`
        : 'Could not be determined',
      evidence: http.reachable
        ? [
            missingRequired.length
              ? `Missing or weak: ${missingRequired.map((header) => header.name).join(', ')}`
              : 'All assessed transport headers present and hardened',
            // The exemption is stated, never silent — a reader must be able to
            // see why a header they know is absent was not counted against them.
            ...supersededHeaders.map(
              (header) => `${header.name} not required — superseded by ${header.supersededBy}`,
            ),
          ].join(' · ')
        : http.error || 'HTTP origin unreachable',
      businessImpact: missingRequired.length
        ? 'Missing transport controls widen the in-page attack surface.'
        : 'Transport-security headers are configured.',
      quantumImpact: 'No direct quantum risk.',
      nextStep: missingRequired.length
        ? `Add: ${missingRequired.map((header) => header.name).join(', ')}.`
        : 'Continue monitoring.',
      score: !http.reachable ? null : otherHeaders.length ? clamp((hardened / otherHeaders.length) * 100) : null,
      observed: http.reachable
        ? `${hardened}/${otherHeaders.length} transport headers hardened`
        : 'origin unreachable',
      detail: supersededHeaders.length
        ? `Transport-layer response headers observed on the public origin; ${supersededHeaders.length} header(s) exempt as superseded.`
        : 'Transport-layer response headers observed on the public origin',
      inAttackSurface: false,
      isInventory: false,
      inFindings: true,
    }),
  )

  /* ── Engine-module controls ────────────────────────────────────────────── */
  // These come from the Public Scan Intelligence Engine modules and were not
  // observable before it existed. They follow the same rules: measured verdicts
  // only, `Unknown` when a probe could not answer.
  states.push(...engineControls(evidence))

  return states
}

/**
 * Controls contributed by the DNS, TLS and HTTP intelligence engines.
 * All are reported (findings + attack surface) but unscored: the classical
 * score model's ten weighted dimensions already sum to 100, and re-weighting
 * it would silently change every historical grade.
 */
function engineControls(evidence: PublicScanEvidence): ControlState[] {
  const bundle = evidence.engines
  if (!bundle) return []

  const dns = bundle.dns.data
  const tls = bundle.tls.data
  const http = bundle.http.data
  const cert = bundle.certificate.data
  const crypto = bundle.crypto.data
  const states: ControlState[] = []

  const reported = (draft: Omit<ControlState, 'weight' | 'score' | 'isInventory'>): ControlState => ({
    ...draft,
    score: null,
    weight: 0,
    isInventory: false,
  })

  // ── DNSSEC ───────────────────────────────────────────────────────────────
  states.push(
    reported({
      key: 'dnssec',
      control: 'DNSSEC',
      shortLabel: 'DNSSEC',
      status: !dns.dnssecQueryable ? 'Unknown' : dns.dnssecSigned ? 'Healthy' : 'Not Supported',
      severity: !dns.dnssecQueryable ? 'LOW' : dns.dnssecSigned ? 'SAFE' : 'MEDIUM',
      value: !dns.dnssecQueryable ? 'Unknown' : dns.dnssecSigned ? 'Signed' : 'Unsigned',
      finding: !dns.dnssecQueryable
        ? 'Could not be determined'
        : dns.dnssecSigned
          ? `Zone signed${dns.dnssecValidated ? ' and resolver-validated' : ''}`
          : 'Zone is not DNSSEC-signed',
      evidence: !dns.dnssecQueryable
        ? 'DNSKEY query returned no authoritative answer'
        : `DNSKEY ${dns.dnssecSigned ? 'present' : 'absent'} · AD bit ${dns.dnssecValidated ? 'set' : 'unset'}`,
      businessImpact: dns.dnssecSigned
        ? 'DNS answers are cryptographically authenticated against spoofing.'
        : 'DNS answers can be spoofed on-path, redirecting users before TLS begins.',
      quantumImpact: 'DNSSEC signatures are classical (RSA/ECDSA) and will need PQ re-anchoring.',
      nextStep: dns.dnssecSigned ? 'Continue monitoring key rollovers.' : 'Enable DNSSEC signing with your DNS provider.',
      observed: dns.dnssecSigned ? 'DNSKEY present' : 'no DNSKEY',
      detail: 'Zone signing verified via DNSKEY lookup and the resolver AD bit',
      inAttackSurface: true,
      inFindings: true,
    }),
  )

  // ── Email authentication (SPF / DMARC) ───────────────────────────────────
  // Not Applicable when the domain publishes no MX: a domain that does not
  // receive mail is not failing an email-authentication control.
  const receivesMail = dns.mailExchangers.length > 0
  const emailPolicies = [dns.spf, dns.dmarc].filter(Boolean).length
  states.push(
    reported({
      key: 'email-authentication',
      control: 'Email Authentication (SPF/DMARC)',
      shortLabel: 'Email Auth',
      status: !receivesMail
        ? 'Not Applicable'
        : emailPolicies === 2
          ? 'Healthy'
          : emailPolicies === 1
            ? 'Warning'
            : 'Not Supported',
      severity: !receivesMail ? 'SAFE' : emailPolicies === 2 ? 'SAFE' : emailPolicies === 1 ? 'LOW' : 'MEDIUM',
      value: !receivesMail ? 'N/A' : emailPolicies === 2 ? 'Pass' : emailPolicies === 1 ? 'Partial' : 'Absent',
      finding: !receivesMail
        ? 'Domain publishes no MX records'
        : [dns.spf ? 'SPF' : null, dns.dmarc ? 'DMARC' : null].filter(Boolean).join(' + ') || 'Neither SPF nor DMARC',
      evidence: [
        dns.spf ? `SPF: ${dns.spf.slice(0, 90)}` : 'no SPF record',
        dns.dmarc ? `DMARC: ${dns.dmarc.slice(0, 90)}` : 'no DMARC record',
        dns.dkimSelectorsFound.length ? `DKIM selectors: ${dns.dkimSelectorsFound.join(', ')}` : '',
      ]
        .filter(Boolean)
        .join(' · '),
      businessImpact: !receivesMail
        ? 'No mail is delivered to this domain, so sender policies do not apply.'
        : emailPolicies === 2
          ? 'Sender policies are published, limiting spoofing of this domain.'
          : 'Missing sender policy lets attackers spoof mail from this domain.',
      quantumImpact: 'DKIM signatures are classical RSA/Ed25519 and will need PQ replacement.',
      nextStep: !receivesMail
        ? 'No action required.'
        : emailPolicies === 2
          ? 'Continue monitoring policy alignment.'
          : 'Publish the missing SPF and/or DMARC records.',
      observed: `${emailPolicies}/2 policies published`,
      detail: 'SPF and DMARC records resolved from public DNS',
      inAttackSurface: false,
      inFindings: true,
    }),
  )

  // ── ALPN / HTTP2 ─────────────────────────────────────────────────────────
  states.push(
    reported({
      key: 'alpn',
      control: 'ALPN Negotiation',
      shortLabel: 'ALPN',
      status: !tls.handshake ? 'Unknown' : tls.alpn ? 'Healthy' : 'Not Supported',
      severity: 'SAFE',
      value: tls.alpn ?? (tls.handshake ? 'Not negotiated' : 'Unknown'),
      finding: tls.alpn ? `${tls.alpn} negotiated` : tls.handshake ? 'No ALPN protocol selected' : 'Could not be determined',
      evidence: `Offered ${tls.alpnOffered.join(', ')} · selected ${tls.alpn ?? 'none'}`,
      businessImpact: tls.http2
        ? 'HTTP/2 negotiated over ALPN — modern transport in use.'
        : 'No ALPN protocol selected; the endpoint falls back to HTTP/1.1.',
      quantumImpact: 'ALPN carries no key material and is unaffected by quantum attack.',
      nextStep: tls.alpn ? 'Continue monitoring.' : 'Enable ALPN and HTTP/2 at the terminator.',
      observed: tls.alpn ?? 'none',
      detail: 'Application-Layer Protocol Negotiation extension in the TLS handshake',
      inAttackSurface: true,
      inFindings: true,
    }),
  )

  // ── Hostname coverage ────────────────────────────────────────────────────
  if (cert.hostnameMatches !== null) {
    states.push(
      reported({
        key: 'hostname-coverage',
        control: 'Hostname Coverage',
        shortLabel: 'Hostname Match',
        status: cert.hostnameMatches ? 'Healthy' : 'Critical',
        severity: cert.hostnameMatches ? 'SAFE' : 'CRITICAL',
        value: cert.hostnameMatches ? 'Pass' : 'Fail',
        finding: cert.hostnameMatches
          ? 'Certificate covers the scanned name'
          : 'Certificate does not cover the scanned name',
        evidence: `Scanned ${bundle.host} against ${cert.sanCount} SAN entr${cert.sanCount === 1 ? 'y' : 'ies'}`,
        businessImpact: cert.hostnameMatches
          ? 'Clients accept the certificate for this hostname.'
          : 'Every browser will show a name-mismatch error and refuse the connection.',
        quantumImpact: 'No direct quantum risk.',
        nextStep: cert.hostnameMatches ? 'Continue monitoring.' : 'Reissue with the correct subjectAltName entries.',
        observed: cert.hostnameMatches ? 'name matched' : 'name not covered',
        detail: 'RFC 6125 hostname matching against subjectAltName',
        inAttackSurface: false,
        inFindings: true,
      }),
    )
  }

  // ── Quantum Risk Engine verdict ──────────────────────────────────────────
  if (crypto.riskFactors.length) {
    const worst = crypto.riskFactors.find((factor) => factor.impact === 'Critical') ?? crypto.riskFactors[0]
    states.push(
      reported({
        key: 'quantum-risk',
        control: 'Quantum Risk',
        shortLabel: 'Quantum Risk',
        status:
          crypto.quantumRisk === 'Low'
            ? 'Healthy'
            : crypto.quantumRisk === 'Medium'
              ? 'Warning'
              : 'Critical',
        severity:
          crypto.quantumRisk === 'Critical' ? 'CRITICAL' : crypto.quantumRisk === 'High' ? 'HIGH' : crypto.quantumRisk === 'Medium' ? 'MEDIUM' : 'SAFE',
        value: crypto.quantumRisk,
        finding: `${crypto.quantumRisk} — ${worst.factor}`,
        evidence: crypto.riskFactors
          .map((factor) => `${factor.factor}: ${factor.observed} [${factor.impact}]`)
          .join(' · '),
        businessImpact: worst.explanation,
        quantumImpact: `Worst observed factor: ${worst.factor} (${worst.impact}).`,
        nextStep: crypto.migrationTargets[0]
          ? `Adopt ${crypto.migrationTargets[0].name} (${crypto.migrationTargets[0].standard}).`
          : 'Maintain the current post-quantum posture.',
        observed: `${crypto.riskFactors.length} risk factor(s) evaluated`,
        detail: 'Quantum Risk Engine — worst-factor verdict across observed primitives',
        inAttackSurface: true,
        inFindings: true,
      }),
    )
  }

  // ── Infrastructure fingerprint (inventory) ───────────────────────────────
  const infra = [http.fingerprint.cdn, http.fingerprint.waf, http.fingerprint.cloudProvider]
    .filter(Boolean)
    .join(' · ')
  if (http.reachable) {
    states.push({
      ...reported({
        key: 'infrastructure',
        control: 'Edge Infrastructure',
        shortLabel: 'Edge Infrastructure',
        status: 'Healthy',
        severity: 'SAFE',
        value: http.fingerprint.cdn ?? http.fingerprint.reverseProxy ?? http.fingerprint.server ?? 'Direct',
        finding: infra || http.fingerprint.server || 'No CDN or WAF signature',
        evidence: http.fingerprint.signals.length
          ? `Signature headers: ${http.fingerprint.signals.join(', ')}`
          : `Server header: ${http.fingerprint.server ?? 'absent'}`,
        businessImpact: http.fingerprint.cdn
          ? 'A CDN terminates TLS, so PQ configuration is applied at the provider.'
          : 'TLS is terminated at the origin; PQ configuration applies there.',
        quantumImpact: 'The terminating layer is where hybrid key agreement must be enabled.',
        nextStep: http.fingerprint.cdn
          ? `Enable hybrid PQ key exchange in the ${http.fingerprint.cdn} configuration.`
          : 'Enable hybrid PQ key exchange at the origin TLS terminator.',
        observed: infra || http.fingerprint.server || 'no signature',
        detail: 'CDN, WAF and cloud provider inferred from response-header signatures',
        inAttackSurface: true,
        inFindings: false,
      }),
      isInventory: true,
    })
  }

  return states
}

/** Look up a single control. Used by the recommendation builder. */
export function findControl(states: ControlState[], key: string): ControlState | undefined {
  return states.find((state) => state.key === key)
}
