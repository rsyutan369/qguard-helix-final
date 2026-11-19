/**
 * Real Time Scanning — the observation processor.
 *
 * Turns what the EXISTING scanner engines measured for one target into graph
 * events: nodes, relationships, evidence and findings. Nothing here probes the
 * network and nothing here invents a value — every field is copied from
 * `executeWebScan`'s structured evidence (edge intelligence, TLS handshake,
 * certificate parser) or from its own findings.
 *
 * Relationship rules (Live Scanning guideline §9):
 * • An endpoint PRESENTING a certificate is directly observed.
 * • A certificate→CA link is `validated` only when the certificate parser's
 *   `checkIssued` + signature verification under the issuer's key passed; a
 *   failed check is `failed`; no DER means the link rests on the issuer NAME
 *   alone and is drawn `inferred` (dashed).
 * • CHAIN_VALIDATED_TO records the runtime's path result against its store.
 *   The runtime does not identify the exact trust anchor.
 * • A self-signed certificate is never promoted to a trusted root.
 * • CDN / edge vendors attributed from response headers are `inferred`.
 *
 * Server-side only (imports the crypto knowledge base classifier).
 */

import { classify } from '@/lib/crypto/knowledge-base'
import type { CertificateIntelligence, HttpIntelligence } from '@/lib/scanner/public-scan/engines'
import type { EdgeIntelligence } from '@/lib/scanner/web-scanner/edge-intelligence-model'
import type {
  CertificateChainEntry, CertificateInfo, TlsAnalysisResult, WebScanCompleteResult, WebScanFinding,
} from '@/lib/scanner/web-scanner/types'
import {
  FINDING_TYPE_LABEL, POLICY_ID, POLICY_VERSION, classifyEngineFinding, engineFindingTitle, findingKey, statusForFinding, worseStatus,
  type EngineThreat, type FindingAnchor,
} from './policy'
import type {
  ActivityLine, EdgeRisk, EdgeVerification, EvidenceSource, ExposureClass, FindingType, LiveEdge, LiveEvent,
  LiveEventPayload, LiveEventType, LiveEvidence, LiveFinding, LiveNode, NodeKind, NodeStatus, RelationshipType, Severity,
} from './types'

export const SCANNER_NODE_ID = 'scanner:helix'
export const TRUST_STORE_NODE_ID = 'truststore:platform-default'
export const PARSER_VERSION = 'qguard-web-scanner/certificate-parser@2026.11'

export interface ObserverSink {
  emit(type: LiveEventType, payload: LiveEventPayload, activity: ActivityLine | null, entityId: string | null): LiveEvent
  hash(value: unknown): string
  now(): string
  getNode(id: string): LiveNode | undefined
  getFinding(id: string): LiveFinding | undefined
  getEdge(id: string): LiveEdge | undefined
}

export interface InventoryContext {
  assetId: string
  name: string | null
  owner: string | null
  environment: string | null
  criticality: string | null
}

export interface TargetContext {
  scanId: string
  /** Normalized target string, e.g. `example.com` or `example.com:8443`. */
  target: string
  host: string
  port: number
  expiringWithinDays: number
  inventory: InventoryContext | null
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

const MAX_ADDRESS_NODES = 4

function cnOf(dn: string | Record<string, string> | null | undefined): string {
  if (!dn) return 'Unknown subject'
  if (typeof dn !== 'string') return dn.CN || dn.O || Object.values(dn)[0] || 'Unknown subject'
  const cn = /CN=([^,]+)/.exec(dn)?.[1]
  const o = /O=([^,]+)/.exec(dn)?.[1]
  return (cn || o || dn).trim()
}

function orgOf(dn: string | Record<string, string> | null | undefined): string | null {
  if (!dn) return null
  if (typeof dn !== 'string') return dn.O || null
  return /O=([^,]+)/.exec(dn)?.[1]?.trim() || null
}

function dnString(dn: Record<string, string> | string | null | undefined): string {
  if (!dn) return 'unknown'
  if (typeof dn === 'string') return dn
  return Object.entries(dn).map(([key, value]) => `${key}=${value}`).join(', ') || 'unknown'
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 64) || 'unknown'
}

function fpId(fingerprint: string): string {
  return fingerprint.replace(/:/g, '').toLowerCase()
}

function normalizeAlg(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '')
}

function daysUntil(iso: string | undefined, nowMs: number): number | null {
  if (!iso) return null
  const t = new Date(iso).getTime()
  if (!Number.isFinite(t)) return null
  return Math.floor((t - nowMs) / 86_400_000)
}

type AlgorithmRole = 'public-key' | 'signature' | 'key-establishment'

const ROLE_LABEL: Record<AlgorithmRole, string> = {
  'public-key': 'Public-key algorithm',
  signature: 'Certificate signature algorithm',
  'key-establishment': 'TLS key establishment',
}

type PqClass = 'classical' | 'pqc' | 'hybrid' | 'unknown'

/* ------------------------------------------------------------------ */
/* the per-target observer                                             */
/* ------------------------------------------------------------------ */

export class TargetObserver {
  readonly assetId: string
  readonly endpointId: string
  private leafId: string | null = null
  private kexId: string | null = null
  private appId: string | null = null
  private transportDrawn = false
  /** Algorithm node ids observed for this target, by normalized label. */
  private algorithms = new Map<string, string>()
  /** Worst status raised by findings, per node of THIS target. */
  private raised = new Map<string, NodeStatus>()
  private findingIds = new Set<string>()
  private componentIds = new Set<string>()

  constructor(private readonly sink: ObserverSink, private readonly ctx: TargetContext) {
    this.assetId = `asset:${ctx.host}`
    this.endpointId = `endpoint:${ctx.host}:${ctx.port}`
  }

  measuredComponents(): LiveNode[] {
    return [...this.componentIds].flatMap((id) => {
      const node = this.sink.getNode(id)
      return node ? [node] : []
    })
  }

  /* ----------------------------- primitives ----------------------------- */

  private evidence(
    sourceType: EvidenceSource, engine: string, validationResult: string, observed: Record<string, unknown>, sourceEndpoint?: string,
  ): LiveEvidence {
    const ev: LiveEvidence = {
      id: `ev:${this.sink.hash({ sourceType, target: this.ctx.target, observed }).slice(0, 20)}`,
      sourceType,
      scanId: this.ctx.scanId,
      observedAt: this.sink.now(),
      sourceEndpoint: sourceEndpoint ?? `${this.ctx.host}:${this.ctx.port}`,
      engine,
      validationResult,
      observed,
      contentHash: this.sink.hash(observed),
    }
    this.sink.emit('evidence.recorded', { evidence: ev }, null, ev.id)
    return ev
  }

  private node(
    type: LiveEventType, kind: NodeKind, id: string, label: string, status: NodeStatus,
    data: Record<string, unknown>, evidenceIds: string[], activity: ActivityLine | null, sublabel?: string,
  ): LiveNode {
    const existing = this.sink.getNode(id)
    // Shared nodes (CAs, algorithms, vendors) are seen by several targets: a
    // later target never downgrades a status another target established.
    const merged = existing && existing.status !== 'active' && status !== 'active' ? worseStatus(existing.status, status) : status
    const node: LiveNode = {
      id, kind, label, sublabel, status: merged,
      targets: [this.ctx.target],
      observedAt: this.sink.now(),
      firstSeq: 0, lastSeq: 0,
      evidenceIds,
      data,
    }
    this.sink.emit(type, { node }, activity, id)
    return node
  }

  private edge(
    source: string, target: string, type: RelationshipType, verification: EdgeVerification,
    evidence: LiveEvidence | null, basis: string, risk: EdgeRisk = 'none', confidence: number | null = null,
  ): void {
    const id = `${type}:${source}->${target}`
    const existing = this.sink.getEdge(id)
    const edge: LiveEdge = {
      id, source, target, type, verification, risk,
      evidenceSource: evidence ? `${evidence.engine} (${evidence.sourceType})` : 'scanner',
      evidenceId: evidence?.id ?? null,
      observedAt: this.sink.now(),
      confidence,
      scanId: this.ctx.scanId,
      basis,
      firstSeq: 0, lastSeq: 0,
    }
    this.sink.emit(existing ? 'relationship.updated' : 'relationship.created', { edge }, null, id)
  }

  /* ----------------------------- stage 1: discovery ----------------------------- */

  discovered(addresses: string[]): void {
    const { host, target } = this.ctx
    const isIp = /^[\d.]+$|:/.test(host) && !/[a-z]/i.test(host.replace(/[a-f]/gi, ''))
    const ev = this.evidence('dns-resolution', 'safe-dns.verifyPublicHost', addresses.length
      ? `${addresses.length} public address(es); no private or reserved answers`
      : 'Literal address target', { host, addresses }, host)
    const inv = this.ctx.inventory
    const invEv = inv
      ? this.evidence('inventory-record', 'assets table', 'Matched by exact hostname in tenant inventory', {
        assetId: inv.assetId, name: inv.name, owner: inv.owner, environment: inv.environment, criticality: inv.criticality,
      }, host)
      : null

    this.node('asset.discovered', 'asset', this.assetId, host, 'active', {
      assetType: isIp ? 'IP address' : 'Domain',
      target,
      port: this.ctx.port,
      addresses,
      owner: inv?.owner ?? null,
      environment: inv?.environment ?? null,
      criticality: inv?.criticality ?? null,
      inventoryAssetId: inv?.assetId ?? null,
      scanStatus: 'scanning',
      lastObserved: this.sink.now(),
    }, [ev.id, ...(invEv ? [invEv.id] : [])], {
      title: 'New asset discovered',
      detail: `${host} resolved to ${addresses.length ? addresses.slice(0, 3).join(', ') : 'a literal address'}${addresses.length > 3 ? ` +${addresses.length - 3}` : ''}`,
      entityId: this.assetId, target,
    }, isIp ? 'IP address' : 'Domain')
    this.edge(SCANNER_NODE_ID, this.assetId, 'SCANNED_BY', 'observed', ev, 'Target accepted into this authorized scan scope and probed by the Helix scanner.')

    for (const address of addresses.slice(0, MAX_ADDRESS_NODES)) {
      if (address === host) continue
      const id = `ip:${address}`
      this.node('asset.discovered', 'address', id, address, 'observed', {
        family: address.includes(':') ? 'IPv6' : 'IPv4', resolvedFrom: host,
      }, [ev.id], null, address.includes(':') ? 'IPv6 address' : 'IPv4 address')
      this.edge(this.assetId, id, 'RESOLVES_TO', 'observed', ev, `DNS answer for ${host} during this scan.`)
    }
  }

  /* ----------------------------- stage 2: transport + PKI ----------------------------- */

  edgeEvidence(intelligence: EdgeIntelligence | null, handshake: TlsAnalysisResult | null, error: string | null, certificate: CertificateInfo | null = null): void {
    if (!intelligence && !handshake && !certificate) {
      if (!this.sink.getNode(this.endpointId)) this.endpointFailed(error || 'The public-edge engine returned no evidence for this endpoint.')
      return
    }
    this.drawTransport(intelligence, handshake, certificate)
  }

  certificateEvidence({ certificate, chainTrusted, trustError, hostnameMatches, subjectAltNames, sanCount, ocspStapled, signedCertificateTimestamps }: CertificateIntelligence): void {
    if (!certificate || this.leafId) return
    const ev = this.evidence('tls-handshake', PARSER_VERSION, 'Certificate received by the certificate probe', { fingerprint: certificate.fingerprint })
    if (!this.sink.getNode(this.endpointId)) this.node('asset.discovered', 'endpoint', this.endpointId, `${this.ctx.host}:${this.ctx.port}`,
      chainTrusted === false ? 'critical' : 'observed', { handshake: 'completed', chainTrusted, trustError, hostnameMatches }, [ev.id], null, 'TLS endpoint')
    this.edge(this.assetId, this.endpointId, 'HOSTS_SERVICE', 'observed', ev, 'The TLS certificate probe received a certificate from this endpoint.')
    this.drawCertificates(certificate, { trustError, hostnameMatches, subjectAltNames, sanCount, ocspStapled, sctPresent: signedCertificateTimestamps }, chainTrusted, null)
  }

  httpEvidence(http: HttpIntelligence): void {
    if (!http.reachable || this.appId) return
    // The actual connection may have followed a redirect. Attach the HTTP
    // evidence to the scanned asset until an endpoint has been measured.
    const source = this.sink.getNode(this.endpointId) ? this.endpointId : this.assetId
    this.drawRelying(http, source)
  }

  /** Fallback when the edge phase produced no handshake but the TLS analyzer did. */
  tlsEvidence(tls: TlsAnalysisResult | null): void {
    if (!tls) return
    if (!this.transportDrawn || this.sink.getNode(this.endpointId)?.data.handshake !== 'completed') {
      this.drawTransport(null, tls)
    } else if (!this.leafId && tls.peerCertificate) {
      this.drawCertificates(tls.peerCertificate, null, null, null)
    }
  }

  private endpointFailed(reason: string): void {
    const ev = this.evidence('tls-handshake', 'edge-intelligence/transport', `No handshake completed: ${reason}`, { error: reason })
    this.node('asset.updated', 'endpoint', this.endpointId, `${this.ctx.host}:${this.ctx.port}`, 'failed', {
      handshake: 'failed', error: reason, chainTrusted: null, sni: this.ctx.host,
    }, [ev.id], {
      title: 'TLS endpoint unreachable', detail: reason, severity: 'medium', entityId: this.endpointId, target: this.ctx.target,
    }, 'TLS endpoint')
    this.edge(this.assetId, this.endpointId, 'HOSTS_SERVICE', 'failed', ev, 'Connection attempted; no TLS handshake completed, so nothing behind this endpoint was observed.')
  }

  private drawTransport(intel: EdgeIntelligence | null, handshake: TlsAnalysisResult | null, certificate: CertificateInfo | null = null): void {
    this.transportDrawn = true
    const { host, port, target } = this.ctx
    const transport = intel?.transport ?? null
    const certSurface = intel?.certificate.probed ? intel.certificate : null
    const chainTrusted = certSurface ? certSurface.chainTrusted : null
    const protocol = transport?.negotiatedProtocol ?? handshake?.tlsVersion
    const tlsVersion = protocol && protocol.toLowerCase() !== 'unknown' ? protocol : null
    const cipher = transport?.negotiatedCipher ?? handshake?.cipherSuite ?? null
    const handshakeOk = Boolean(tlsVersion || handshake || certificate)

    const tlsEv = this.evidence('tls-handshake', 'edge-intelligence/transport', handshakeOk ? 'Handshake completed' : 'Handshake did not complete', {
      sni: host, tlsVersion, cipher, keyExchangeLabel: transport?.keyExchange ?? handshake?.keyExchange ?? null,
      supportedProtocols: transport?.supportedProtocols ?? handshake?.supportedProtocols ?? [],
      legacyProtocols: transport?.legacyProtocols ?? [], alpn: transport?.alpn ?? null,
      forwardSecrecy: transport?.forwardSecrecy ?? null, staticRsaAccepted: transport?.staticRsaAccepted ?? null,
      handshakeMs: transport?.handshakeMs ?? null,
    })

    const verdict = intel?.quantum.vulnerability ?? 'Unknown'
    let endpointStatus: NodeStatus = 'observed'
    if (!handshakeOk) endpointStatus = 'failed'
    else if (chainTrusted === false) endpointStatus = 'critical'
    else if (verdict === 'Quantum-safe' || verdict === 'Hybrid-protected') endpointStatus = 'validated'
    else if (verdict === 'Unknown') endpointStatus = 'unknown'
    else endpointStatus = 'exposure'
    this.raise(this.endpointId, endpointStatus)

    this.node('asset.discovered', 'endpoint', this.endpointId, `${host}:${port}`, endpointStatus, {
      handshake: handshakeOk ? 'completed' : 'failed', sni: host, tlsVersion, cipher,
      supportedProtocols: transport?.supportedProtocols ?? handshake?.supportedProtocols ?? [],
      legacyProtocols: transport?.legacyProtocols ?? [], alpn: transport?.alpn ?? null,
      forwardSecrecy: transport?.forwardSecrecy ?? null, staticRsaAccepted: transport?.staticRsaAccepted ?? null,
      handshakeMs: transport?.handshakeMs ?? null, chainTrusted, trustError: certSurface?.trustError ?? null,
      hostnameMatches: certSurface?.hostnameMatches ?? null, ocspStapled: certSurface?.ocspStapled ?? null,
      sctPresent: certSurface?.sctPresent ?? null, quantumVerdict: verdict,
      quantumReason: intel?.quantum.vulnerabilityReason ?? 'Edge intelligence did not complete — no quantum verdict.',
      postQuantumReadiness: intel?.quantum.postQuantumReadiness ?? null,
    }, [tlsEv.id], {
        title: 'TLS endpoint assessed',
      detail: [tlsVersion, cipher, transport?.handshakeMs != null ? `${transport.handshakeMs} ms` : null].filter(Boolean).join(' · ') || 'Handshake details unavailable',
      entityId: this.endpointId, target,
    }, 'TLS endpoint')
    this.edge(this.assetId, this.endpointId, 'HOSTS_SERVICE', handshakeOk ? 'observed' : 'failed', tlsEv, handshakeOk
      ? `TLS service answered on port ${port} with SNI ${host}.`
      : `The scanner could not confirm a TLS handshake on port ${port} with SNI ${host}.`)

    const cert = certificate ?? handshake?.peerCertificate ?? null
    // Path and hostname checks describe the certificate returned by that probe.
    const matchingSurface = !certSurface?.fingerprintSha256 || cert?.fingerprint === certSurface.fingerprintSha256 ? certSurface : null
    if (cert && !this.leafId) this.drawCertificates(cert, matchingSurface, matchingSurface?.chainTrusted ?? null, intel)
    if (intel) this.drawKeyEstablishment(intel, handshake)
    else if (handshake) this.drawKeyEstablishmentFromHandshake(handshake)
    if (intel?.http.probed && !this.appId) this.drawRelying(intel.http, this.endpointId)
    if (intel) this.evaluateEdgePolicy(cert, matchingSurface, intel)
  }

  private drawCertificates(
    cert: CertificateInfo, surface: Pick<EdgeIntelligence['certificate'], 'trustError' | 'hostnameMatches' | 'subjectAltNames' | 'sanCount' | 'ocspStapled' | 'sctPresent'> | null, chainTrusted: boolean | null, intel: EdgeIntelligence | null,
  ): void {
    const { host, target } = this.ctx
    const now = Date.now()
    const leafFp = cert.fingerprint || this.sink.hash({ s: cert.subject, i: cert.issuer, n: cert.serialNumber })
    this.leafId = `cert:${fpId(leafFp)}`
    const chain = cert.chain ?? []
    const daysRemaining = daysUntil(cert.validTo, now)
    const validation = chainTrusted === true
      ? 'Path validated against the platform trust store (Node.js / OpenSSL bundled roots)'
      : chainTrusted === false
        ? `Path validation failed: ${surface?.trustError || 'reason not reported'}`
      : 'Runtime path validation result was not recorded'

    const chainEv = this.evidence('certificate-chain', PARSER_VERSION, validation, {
      leaf: {
        subject: dnString(cert.subject), issuer: dnString(cert.issuer), fingerprintSha256: cert.fingerprint,
        serialNumber: cert.serialNumber, notBefore: cert.validFrom, notAfter: cert.validTo,
        publicKey: cert.publicKeyAlgorithm, publicKeySize: cert.publicKeySize, signatureAlgorithm: cert.signatureAlgorithm,
        signatureOid: cert.signatureOid, selfSigned: cert.isSelfSigned,
      },
      chain: chain.map((entry, index) => ({
        position: index, subject: entry.subject, issuer: entry.issuer, fingerprintSha256: entry.fingerprint256 ?? null,
        signatureAlgorithm: entry.signatureAlgorithm, publicKey: entry.publicKeyAlgorithm, notAfter: entry.validTo,
        signatureVerifiedByNext: entry.signatureVerifiedByNext ?? null, selfSignatureValid: entry.selfSignatureValid ?? null,
      })),
      chainTrusted, trustError: surface?.trustError ?? null, hostnameMatches: surface?.hostnameMatches ?? null,
      subjectAltNames: surface?.subjectAltNames?.slice(0, 50) ?? [],
    })

    let leafStatus: NodeStatus = 'observed'
    if (cert.isExpired || chainTrusted === false || surface?.hostnameMatches === false) leafStatus = 'critical'
    else if (chainTrusted === true) leafStatus = 'validated'
    this.raise(this.leafId, leafStatus)

    const san = surface?.subjectAltNames ?? []
    this.node('certificate.discovered', 'certificate', this.leafId, cnOf(cert.subject) || san[0] || host, leafStatus, {
      role: 'Leaf (end-entity) certificate',
      subject: dnString(cert.subject), subjectAltNames: san.slice(0, 50), sanCount: surface?.sanCount ?? san.length,
      issuer: dnString(cert.issuer), fingerprint: cert.fingerprint, serialNumber: cert.serialNumber,
      validFrom: cert.validFrom, validTo: cert.validTo, daysRemaining,
      expirationStatus: cert.isExpired ? 'Expired' : daysRemaining != null && daysRemaining <= this.ctx.expiringWithinDays ? 'Expiring soon' : 'Valid period',
      publicKeyAlgorithm: cert.publicKeyAlgorithm, publicKeySize: cert.publicKeySize,
      signatureAlgorithm: cert.signatureAlgorithm, signatureOid: cert.signatureOid, selfSigned: cert.isSelfSigned,
      chainTrusted, trustError: surface?.trustError ?? null, hostnameMatches: surface?.hostnameMatches ?? null,
      validation, chainDepth: chain.length, ocspStapled: surface?.ocspStapled ?? null, sctPresent: surface?.sctPresent ?? null,
    }, [chainEv.id], {
      title: 'Certificate retrieved from endpoint',
      detail: `${cnOf(cert.subject)} · issued by ${cnOf(cert.issuer)} · ${cert.isExpired ? 'EXPIRED' : `expires ${cert.validTo}`}`,
      entityId: this.leafId, target,
    }, `Issued by ${cnOf(cert.issuer)}`)
    this.edge(this.endpointId, this.leafId, 'PRESENTS_CERTIFICATE', 'observed', chainEv,
      `Presented by ${host}:${this.ctx.port} in the TLS handshake (SNI ${host}).`, leafStatus === 'critical' ? 'critical' : 'none')

    if (cert.isExpired) {
      this.policyFinding({
        ruleId: 'LIVE-PKI-005', type: 'CERTIFICATE_EXPIRED', severity: 'critical', exposure: 'invalid-cryptography',
        anchors: [this.leafId, this.endpointId], title: 'Certificate expired',
        description: `The certificate presented by ${host}:${this.ctx.port} expired on ${cert.validTo}.`,
        observed: { notAfter: cert.validTo, fingerprint: cert.fingerprint },
        remediation: 'Renew and deploy the certificate immediately. Verify the served certificate, intermediate chain and hostname from a client, then rescan.',
        standards: ['RFC 5280 §4.1.2.5 (validity)'],
      })
    }

    // Public key + signature of the leaf.
    this.algorithm('public-key', cert.publicKeyAlgorithm, cert.publicKeySize, this.leafId, 'USES_PUBLIC_KEY_ALGORITHM', chainEv)
    if (cert.signatureAlgorithm && cert.signatureAlgorithm !== 'unknown') {
      this.algorithm('signature', cert.signatureAlgorithm, null, this.leafId, 'USES_SIGNATURE_ALGORITHM', chainEv)
    }

    // CA certificates presented above the leaf.
    const caIds: string[] = []
    for (let index = 1; index < chain.length; index++) {
      const entry = chain[index]
      const id = this.caId(entry)
      caIds.push(id)
      const selfIssued = entry.subject === entry.issuer
      const caType = selfIssued ? 'Self-issued CA certificate' : 'Presented CA certificate'
      const status: NodeStatus = entry.isExpired ? 'critical' : 'observed'
      this.node('asset.discovered', 'ca', id, cnOf(entry.subject), status, {
        caType, subject: entry.subject, issuer: entry.issuer, fingerprint: entry.fingerprint256 ?? null,
        serialNumber: entry.serialNumber ?? null, validTo: entry.validTo, publicKeyAlgorithm: entry.publicKeyAlgorithm,
        publicKeySize: entry.publicKeySize, signatureAlgorithm: entry.signatureAlgorithm,
        selfSignatureValid: entry.selfSignatureValid ?? null,
        validationStatus: 'Presented by the endpoint. See the leaf for the runtime path result.',
        identityBasis: entry.fingerprint256 ? 'SHA-256 fingerprint of the presented CA certificate' : 'Subject + public-key parameters (DER unavailable)',
      }, [chainEv.id], null, caType)
      if (entry.publicKeyAlgorithm && entry.publicKeyAlgorithm !== 'unknown') {
        this.algorithm('public-key', entry.publicKeyAlgorithm, entry.publicKeySize, id, 'USES_PUBLIC_KEY_ALGORITHM', chainEv)
      }
      if (entry.signatureAlgorithm && entry.signatureAlgorithm !== 'unknown') {
        this.algorithm('signature', entry.signatureAlgorithm, null, id, 'USES_SIGNATURE_ALGORITHM', chainEv)
      }
      const orgName = orgOf(entry.subject)
      if (orgName && index === 1) {
        const vendorId = `vendor:${slug(orgName)}`
        this.node('asset.discovered', 'vendor', vendorId, orgName, 'observed', {
          vendorRole: 'Organization named in CA certificate', basis: 'Certificate subject O= attribute',
        }, [chainEv.id], null, 'CA organization')
        this.edge(id, vendorId, 'MANAGED_BY_VENDOR', 'inferred', chainEv, `The presented CA certificate names this organization (${entry.subject}). Operational ownership was not independently verified.`)
      }
    }

    // Issuer links — signature-verified only.
    const ids = [this.leafId, ...caIds]
    for (let index = 0; index < ids.length - 1; index++) {
      const entry = chain[index] as CertificateChainEntry | undefined
      const verified = entry?.signatureVerifiedByNext
      const verification: EdgeVerification = verified === true ? 'validated' : verified === false ? 'failed' : 'inferred'
      const basis = verified === true
        ? 'checkIssued matched and the signature verified under the issuer’s public key.'
        : verified === false
          ? 'The presented issuer did NOT verify this certificate’s signature.'
          : 'Issuer name only — signature could not be verified (DER unavailable). Not proof of issuance.'
      this.edge(ids[index], ids[index + 1], index === 0 ? 'ISSUED_BY' : 'SIGNED_BY', verification, chainEv, basis,
        verification === 'failed' ? 'critical' : 'none')
    }

    if (chain.length > 1) {
      this.sink.emit('scan.progress', { progress: { stage: 'Certificate chain validation', message: validation, target } }, {
        title: 'Certificate chain validation completed',
        detail: `${chain.length} certificate(s) · ${chainTrusted === true ? 'trusted path' : chainTrusted === false ? `failed — ${surface?.trustError ?? 'unknown reason'}` : 'not validated'}`,
        severity: chainTrusted === true ? 'validated' : chainTrusted === false ? 'high' : undefined,
        entityId: this.leafId, target,
      }, this.leafId)
    }

    // Trust anchor + store — only on a validated path, never for a bare self-signed leaf.
    if (chainTrusted === true) {
      this.node('asset.discovered', 'trust-store', TRUST_STORE_NODE_ID, 'Platform trust store', 'validated', {
        store: 'Node.js / OpenSSL bundled root store', policy: 'platform-default',
        note: 'Validation is against the scanner runtime’s bundled roots; a tenant trust store is not configured.',
      }, [chainEv.id], null, 'Trust store')
      this.edge(this.leafId, TRUST_STORE_NODE_ID, 'CHAIN_VALIDATED_TO', 'validated', chainEv,
        'The scanner runtime accepted the certificate path. The trust anchor used by the runtime was not identified.')
    }

    this.sink.emit('certificate.analyzed', {
      node: { ...this.sink.getNode(this.leafId)!, data: { ...this.sink.getNode(this.leafId)!.data, analyzed: true } },
    }, null, this.leafId)
    void intel
  }

  private caId(entry: CertificateChainEntry): string {
    if (entry.fingerprint256) return `ca:${fpId(entry.fingerprint256)}`
    return `ca:${this.sink.hash({ s: entry.subject, k: entry.publicKeyAlgorithm, n: entry.publicKeySize }).slice(0, 24)}`
  }

  private algorithm(
    role: AlgorithmRole, label: string, keySize: number | null, fromId: string, relation: RelationshipType,
    ev: LiveEvidence, override?: { cls: PqClass; status: NodeStatus; rationale: string; params?: string },
  ): string {
    const id = `alg:${role}:${slug(label)}`
    let cls: PqClass
    let status: NodeStatus
    let rationale: string
    let migrationTarget: string | null = null
    let family: string | null = null
    if (override) {
      ;({ cls, status, rationale } = override)
      migrationTarget = cls === 'classical'
        ? 'Hybrid X25519MLKEM768 (ML-KEM, FIPS 203)'
        : cls === 'hybrid' || cls === 'pqc' ? 'None required — post-quantum key establishment measured' : null
    } else {
      const result = classify({
        algorithm: role === 'signature' ? label.replace(/withrsaencryption$/i, 'withRSA') : label,
        keySize: keySize && keySize > 0 ? keySize : null,
        declaredRole: role === 'public-key' ? 'certificate-public-key' : 'certificate-signature',
        protocol: 'TLS',
      })
      family = result.algorithm?.family ?? null
      rationale = result.quantumRationale
      migrationTarget = result.migrationTarget ?? (role === 'public-key' || role === 'signature' ? 'ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)' : null)
      switch (result.quantumStatus) {
        case 'PQC_STANDARDIZED': cls = 'pqc'; status = 'validated'; break
        case 'HYBRID': cls = 'hybrid'; status = 'validated'; break
        case 'QUANTUM_VULNERABLE': cls = 'classical'; status = 'exposure'; break
        case 'QUANTUM_RESISTANT':
        case 'NOT_APPLICABLE': cls = 'classical'; status = 'observed'; break
        default: cls = 'unknown'; status = 'unknown'
      }
      if (result.classicalSecurity === 'BROKEN') status = 'critical'
    }
    const pqLabel = cls === 'pqc' ? 'Post-quantum' : cls === 'hybrid' ? 'Hybrid' : cls === 'classical' ? 'Classical' : 'Unknown'
    if (!/^unknown(?:\s|$)/i.test(label)) this.componentIds.add(id)
    this.node('algorithm.detected', 'algorithm', id, label, status, {
      role: ROLE_LABEL[role], roleKey: role, family, keySize, parameters: override?.params ?? (keySize ? `${keySize}-bit` : null),
      classification: pqLabel, quantumExposure: rationale,
      policyResult: status === 'exposure' ? 'Migration required (quantum-vulnerable)' : status === 'critical' ? 'Fails policy (classically broken)' : status === 'validated' ? 'Meets PQC policy' : status === 'unknown' ? 'Not classified' : 'No quantum exposure for this role',
      migrationTarget,
    }, [ev.id], this.algorithms.has(normalizeAlg(label)) ? null : {
      title: `${label} ${role === 'key-establishment' ? 'key establishment measured' : role === 'signature' ? 'signature dependency found' : 'public key identified'}`,
      detail: `${ROLE_LABEL[role]} · ${pqLabel}${status === 'exposure' ? ' · quantum-vulnerable' : ''}`,
      severity: status === 'validated' ? 'validated' : undefined,
      entityId: id, target: this.ctx.target,
    }, `${ROLE_LABEL[role]} · ${pqLabel}`)
    this.algorithms.set(normalizeAlg(label), id)
    this.edge(fromId, id, relation, 'observed', ev,
      `${ROLE_LABEL[role]} parsed from ${relation === 'NEGOTIATED_KEY_ESTABLISHMENT' ? 'named-group probing of the handshake' : 'the certificate DER'}.`,
      status === 'exposure' ? 'exposure' : status === 'critical' ? 'critical' : 'none')
    return id
  }

  private drawKeyEstablishment(intel: EdgeIntelligence, handshake: TlsAnalysisResult | null): void {
    const pq = intel.pqKeyAgreement
    const ev = this.evidence('named-group-probe', 'edge-intelligence/pq-key-agreement', pq.probed
      ? `${pq.handshakes} handshake(s) — ${pq.value}` : 'Named-group probing did not run', {
      probed: pq.probed, primaryGroup: pq.primaryGroup, hybridGroups: pq.hybridGroups, pureKemGroups: pq.pureKemGroups,
      classicalGroups: pq.classicalGroups, kemParameterSets: pq.kemParameterSets, handshakes: pq.handshakes,
      inconclusiveGroups: pq.inconclusiveGroups, hybridGroupsSettled: pq.hybridGroupsSettled ?? null, confidence: pq.confidence,
      transportKeyExchange: intel.transport.keyExchange,
    })
    if (pq.probed && pq.hybridGroups.length) {
      this.kexId = this.algorithm('key-establishment', pq.hybridGroups.find((group) => group === pq.primaryGroup) ?? pq.hybridGroups[0], null, this.endpointId, 'NEGOTIATED_KEY_ESTABLISHMENT', ev, {
        cls: 'hybrid', status: 'validated', params: [pq.classicalComponent, pq.postQuantumComponent].filter(Boolean).join(' + '),
        rationale: `Hybrid ML-KEM key agreement measured: accepted when offered in isolation across ${pq.handshakes} handshake(s).`,
      })
    } else if (pq.probed && pq.pureKemGroups.length) {
      this.kexId = this.algorithm('key-establishment', pq.pureKemGroups[0], null, this.endpointId, 'NEGOTIATED_KEY_ESTABLISHMENT', ev, {
        cls: 'pqc', status: 'validated', params: pq.kemParameterSets.join(', '),
        rationale: 'Standalone ML-KEM accepted — post-quantum, without a classical hedge.',
      })
    } else {
      const settled = pq.probed && (pq.hybridGroupsSettled?.length ?? 0) > 0
      const label = [pq.primaryGroup, pq.classicalGroups[0], intel.transport.keyExchange, handshake?.keyExchange]
        .find((value) => value && !/^\s*(unknown(?: key exchange)?|n\/?a|none|unavailable)\s*$/i.test(value))
      if (label) this.kexId = this.algorithm('key-establishment', label, null, this.endpointId, 'NEGOTIATED_KEY_ESTABLISHMENT', ev, {
        cls: 'classical',
        status: 'exposure',
        params: pq.classicalGroups.slice(0, 4).join(', ') || undefined,
        rationale: settled
          ? 'Classical key establishment: every hybrid ML-KEM group was offered in isolation and refused. Recorded sessions are harvest-now-decrypt-later exposed.'
          : 'Classical key establishment observed; hybrid ML-KEM support did not settle on this run, so no post-quantum claim is made either way.',
      })
    }
    if (intel.transport.staticRsaAccepted) {
      this.algorithm('key-establishment', 'RSA key transport', null, this.endpointId, 'NEGOTIATED_KEY_ESTABLISHMENT', ev, {
        cls: 'classical', status: 'critical',
        rationale: 'Static RSA key transport is accepted: no forward secrecy and quantum-recoverable session keys.',
      })
    }
  }

  private drawKeyEstablishmentFromHandshake(handshake: TlsAnalysisResult): void {
    const ev = this.evidence('tls-handshake', 'web-scanner/tls-analyzer', 'Socket-reported key exchange (named groups not probed)', {
      keyExchange: handshake.keyExchange, negotiatedCurve: handshake.negotiatedCurve,
    })
    const label = handshake.negotiatedCurve || handshake.keyExchange || 'Unknown key exchange'
    this.kexId = this.algorithm('key-establishment', label, null, this.endpointId, 'NEGOTIATED_KEY_ESTABLISHMENT', ev, {
      cls: 'unknown', status: 'unknown',
      rationale: 'Named-group probing did not run, so hybrid ML-KEM support is unknown (not assumed absent).',
    })
  }

  private drawRelying(http: Pick<EdgeIntelligence['http'], 'reachable' | 'statusCode' | 'httpVersion' | 'fingerprint' | 'error' | 'finalUrl'> & { hsts: Pick<HttpIntelligence['hsts'], 'raw' | 'present'> }, source: string): void {
    const observedUrl = http.finalUrl && URL.canParse(http.finalUrl) ? new URL(http.finalUrl) : null
    const sameEndpoint = observedUrl?.protocol === 'https:' && observedUrl.hostname === this.ctx.host &&
      Number(observedUrl.port || 443) === this.ctx.port
    const attributionSource = sameEndpoint ? source : this.assetId
    const httpEv = this.evidence('http-response', 'edge-intelligence/http', http.reachable ? `HTTP ${http.statusCode ?? '?'} over ${http.httpVersion ?? 'HTTP'}` : `Not reachable: ${http.error ?? 'no response'}`, {
      finalUrl: http.finalUrl ?? null,
      statusCode: http.statusCode, httpVersion: http.httpVersion, server: http.fingerprint.server, poweredBy: http.fingerprint.poweredBy,
      cdn: http.fingerprint.cdn, waf: http.fingerprint.waf, cloudProvider: http.fingerprint.cloudProvider,
      reverseProxy: http.fingerprint.reverseProxy, signals: http.fingerprint.signals, hsts: http.hsts.raw,
    })
    if (http.reachable) {
      this.appId = observedUrl ? `app:${observedUrl.origin}` : `app:${this.ctx.host}:${this.ctx.port}`
      const inv = this.ctx.inventory
      this.node('asset.discovered', 'application', this.appId, (sameEndpoint && inv?.name) || observedUrl?.origin || this.ctx.host, 'observed', {
        finalUrl: http.finalUrl ?? null, appType: 'HTTP service', statusCode: http.statusCode, httpVersion: http.httpVersion,
        server: http.fingerprint.server, poweredBy: http.fingerprint.poweredBy, hsts: http.hsts.present,
        owner: sameEndpoint ? inv?.owner ?? null : null,
        environment: sameEndpoint ? inv?.environment ?? null : null,
        criticality: sameEndpoint ? inv?.criticality ?? null : null,
        dependencyType: sameEndpoint ? 'HTTP response from the scanned endpoint' : 'HTTP response obtained while scanning this target',
      }, [httpEv.id], null, `HTTP ${http.statusCode ?? '—'}${http.fingerprint.server ? ` · ${http.fingerprint.server}` : ''}`)
      this.edge(attributionSource, this.appId, sameEndpoint ? 'SERVES_APPLICATION' : 'HTTP_RESPONSE_FROM', 'observed', httpEv,
        sameEndpoint ? 'An HTTP response was received over TLS from the scanned endpoint.'
          : 'An HTTP response was received during the scan. Serving or dependency ownership for the scanned endpoint was not established.')
    }
    const vendors: Array<[string | null, string]> = [
      [http.fingerprint.cdn, 'CDN / edge network'], [http.fingerprint.waf, 'Web application firewall'],
      [http.fingerprint.cloudProvider, 'Cloud provider'], [http.fingerprint.reverseProxy, 'Reverse proxy'],
    ]
    const seen = new Set<string>()
    for (const [name, role] of vendors) {
      if (!name || seen.has(name.toLowerCase())) continue
      seen.add(name.toLowerCase())
      const id = `vendor:${slug(name)}`
      this.node('asset.discovered', 'vendor', id, name, 'observed', {
        vendorRole: role, basis: 'Attributed from HTTP response headers', signals: http.fingerprint.signals.slice(0, 8),
      }, [httpEv.id], {
        title: 'Vendor signal detected', detail: `${name} (${role}) inferred from headers${observedUrl ? ` at ${observedUrl.origin}` : ''}`, entityId: id, target: this.ctx.target,
      }, role)
      this.edge(sameEndpoint ? source : this.appId ?? attributionSource, id, 'BACKED_BY', 'inferred', httpEv,
        `Inferred from response headers${observedUrl ? ` at ${observedUrl.origin}` : ''} (${http.fingerprint.signals.slice(0, 3).join(', ') || 'fingerprint'}). Provider ownership, TLS termination and supply-chain exposure are unverified.`)
    }
  }

  /* ----------------------------- live PKI policy ----------------------------- */

  private evaluateEdgePolicy(cert: CertificateInfo | null, surface: EdgeIntelligence['certificate'] | null, intel: EdgeIntelligence): void {
    const leaf = this.leafId ?? this.endpointId
    if (cert && surface?.chainTrusted === false) {
      const reason = surface.trustError || 'unknown reason'
      const untrusted = /SELF_SIGNED|UNABLE_TO_GET_ISSUER|UNABLE_TO_VERIFY_LEAF|self.signed|unable to get/i.test(reason)
      if (!/EXPIRED/i.test(reason)) {
        this.policyFinding({
          ruleId: untrusted ? 'LIVE-PKI-002' : 'LIVE-PKI-001',
          type: untrusted ? 'UNTRUSTED_CERTIFICATE_AUTHORITY' : 'CERTIFICATE_CHAIN_INVALID',
          severity: 'high', exposure: 'misconfiguration', anchors: [leaf, this.endpointId],
          title: untrusted ? 'Certificate does not chain to a trusted CA' : 'Certificate chain failed validation',
          description: `Trust-store path validation for ${this.ctx.host}:${this.ctx.port} failed: ${reason}. Clients that validate certificates will reject or warn on this endpoint.`,
          observed: { trustError: reason, issuer: dnString(cert.issuer), selfSigned: String(cert.isSelfSigned) },
          remediation: untrusted
            ? 'Serve a certificate from a publicly trusted CA (or distribute the private root to every relying client) and include the full intermediate chain.'
            : 'Serve the complete, correctly ordered chain and replace any certificate whose signature does not verify.',
          standards: ['RFC 5280 §6 (path validation)'],
        })
      }
    }
    if (surface?.hostnameMatches === false) {
      this.policyFinding({
        ruleId: 'LIVE-PKI-003', type: 'HOSTNAME_VALIDATION_FAILED', severity: 'high', exposure: 'misconfiguration',
        anchors: [leaf, this.endpointId],
        title: 'Certificate does not cover the scanned hostname',
        description: `${this.ctx.host} is not among the certificate's names (${surface.subjectAltNames.slice(0, 5).join(', ') || 'no SAN'}).`,
        observed: { host: this.ctx.host, subjectAltNames: surface.subjectAltNames.slice(0, 10).join(', ') },
        remediation: 'Reissue the certificate with this hostname in the subjectAltName extension, or correct the SNI routing.',
        standards: ['RFC 6125'],
      })
    }
    const days = daysUntil(cert?.validTo, Date.now())
    if (cert && !cert.isExpired && days != null && days >= 0 && days <= this.ctx.expiringWithinDays) {
      this.policyFinding({
        ruleId: 'LIVE-PKI-004', type: 'CERTIFICATE_EXPIRING', severity: days <= 7 ? 'high' : 'medium', exposure: 'misconfiguration',
        anchors: [leaf], title: `Certificate expires in ${days} day(s)`,
        description: `The certificate served by ${this.ctx.host} expires on ${cert.validTo}. Renewal is also the cheapest moment to plan the ML-DSA migration.`,
        observed: { notAfter: cert.validTo, daysRemaining: String(days), thresholdDays: String(this.ctx.expiringWithinDays) },
        remediation: 'Renew before expiry and automate renewal (ACME).', standards: ['CA/B Forum Baseline Requirements'],
      })
    }
    const pq = intel.pqKeyAgreement
    const kemMeasured = pq.probed && (pq.hybridGroups.length > 0 || pq.pureKemGroups.length > 0)
    const settled = pq.probed && (pq.hybridGroupsSettled?.length ?? 0) > 0
    if (!kemMeasured && !settled) {
      this.policyFinding({
        ruleId: 'LIVE-PQC-001', type: 'PQC_READINESS_UNKNOWN', severity: 'low', exposure: 'unknown-migration-status',
        anchors: [this.kexId ?? this.endpointId],
        title: 'Post-quantum key establishment not determined',
        description: pq.probed
          ? 'Hybrid ML-KEM named groups were probed but did not settle (throttled, inconclusive or untestable). This is not evidence that PQC is unsupported.'
          : 'Named-group probing did not run, so hybrid ML-KEM support is unknown.',
        observed: { probed: String(pq.probed), handshakes: String(pq.handshakes), inconclusive: pq.inconclusiveGroups.join(', ') || 'none' },
        remediation: 'Rescan this endpoint; if it stays inconclusive, verify ML-KEM support with the endpoint owner.',
        standards: ['NIST FIPS 203 (ML-KEM)'],
      })
    }
    const vendor = intel.http.fingerprint.cdn || intel.http.fingerprint.reverseProxy
    const responseUrl = intel.http.finalUrl
    const response = responseUrl && URL.canParse(responseUrl) ? new URL(responseUrl) : null
    const sameOrigin = response?.protocol === 'https:' && response.hostname === this.ctx.host && Number(response.port || 443) === this.ctx.port
    if (vendor && sameOrigin && this.kexId && !kemMeasured && settled) {
      this.policyFinding({
        ruleId: 'LIVE-VEN-001', type: 'VENDOR_MIGRATION_DEPENDENCY', severity: 'info', exposure: 'unknown-migration-status',
        anchors: [`vendor:${slug(vendor)}`, this.kexId ?? this.endpointId],
        title: `Key-establishment migration may depend on ${vendor}`,
        description: `Classical key establishment was measured on ${this.ctx.host}, and the edge is attributed (from response headers) to ${vendor}. Enabling hybrid ML-KEM may be a setting owned by that vendor relationship. This does not assert the vendor lacks PQC support.`,
        observed: { vendor, attribution: 'response headers' },
        remediation: `Confirm with ${vendor} whether hybrid X25519MLKEM768 can be enabled for this property.`,
        standards: ['NIST FIPS 203 (ML-KEM)'],
      })
    }
  }

  private policyFinding(spec: {
    ruleId: string; type: FindingType; severity: Severity; exposure: ExposureClass; anchors: string[]; title: string
    description: string; observed: Record<string, string>; remediation: string; standards: string[]
  }): void {
    const ev = this.evidence('policy-evaluation', `${POLICY_ID}@${POLICY_VERSION}`, `${spec.ruleId} triggered`, spec.observed)
    this.upsertFinding({
      key: findingKey({ type: spec.type, algorithm: spec.ruleId, severity: spec.severity, scope: this.ctx.target }),
      ruleId: spec.ruleId, ruleVersion: POLICY_VERSION, type: spec.type, title: spec.title, description: spec.description,
      severity: spec.severity, exposure: spec.exposure, anchors: spec.anchors.filter((id) => this.sink.getNode(id)),
      evidence: ev, observed: spec.observed, remediation: spec.remediation, standards: spec.standards, sourceModule: 'live-policy',
    })
  }

  /* ----------------------------- stage 3: engine findings ----------------------------- */

  engineFinding(finding: WebScanFinding): void {
    const threat = finding.threatLevel as EngineThreat
    const ev = this.evidence('scanner-finding', `web-scanner/${finding.phase}`, `${finding.threatLevel} — ${finding.category}`, {
      phase: finding.phase, category: finding.category, algorithm: finding.algorithm, location: finding.location,
      threatLevel: finding.threatLevel, description: finding.description, quantumBreakTime: finding.quantumBreakTime,
      classicalBreakTime: finding.classicalBreakTime, oid: finding.oid ?? null,
    }, finding.location)

    if (threat === 'SAFE') {
      // A measured pass is evidence on the node it describes, not a finding.
      this.sink.emit('scan.progress', { progress: { stage: finding.phase, message: finding.algorithm, target: this.ctx.target } }, {
        title: `Validated: ${finding.algorithm}`, detail: `${finding.category} · ${finding.location}`, severity: 'validated',
        entityId: this.kexId && /key/i.test(finding.category) ? this.kexId : this.endpointId, target: this.ctx.target,
      }, null)
      return
    }

    const cls = classifyEngineFinding({ phase: finding.phase, category: finding.category, algorithm: finding.algorithm, threatLevel: threat })
    if (cls.type === 'CRYPTO_POSTURE' && cls.severity === 'info' && /^tlsv?1\.[23]$/i.test(finding.algorithm)) return
    // The parsed leaf already produced this finding with its exact identity
    // and validity date. Keep the engine evidence without a duplicate card.
    if (cls.type === 'CERTIFICATE_EXPIRED' && this.leafId && this.sink.getNode(this.leafId)?.data.expirationStatus === 'Expired') return
    const anchor = this.anchorFor(cls.anchor)
    const anchors = [anchor]
    const needle = normalizeAlg(finding.algorithm)
    if (needle.length >= 3) {
      for (const [label, id] of this.algorithms) {
        if (label.length >= 3 && (needle.includes(label) || label.includes(needle)) && !anchors.includes(id)) anchors.push(id)
      }
    }
    this.upsertFinding({
      key: findingKey({
        type: cls.type, algorithm: finding.algorithm, severity: cls.severity,
        scope: cls.type === 'CERTIFICATE_EXPIRED'
          ? `${this.ctx.target}|${this.leafId ?? anchor}`
          : `${this.ctx.target}|${finding.phase}|${finding.category}|${finding.location}`,
      }),
      ruleId: `ENGINE:${finding.phase}:${finding.category}`, ruleVersion: 'web-scanner',
      type: cls.type, title: engineFindingTitle(cls.type, finding.category, finding.algorithm), description: finding.description,
      severity: cls.severity, exposure: cls.exposure, anchors, evidence: ev,
      observed: { [`${this.ctx.target}`]: `${finding.algorithm} @ ${finding.location}` },
      remediation: finding.recommendation, standards: finding.pqcRecommendation ? [String((finding.pqcRecommendation as { standard?: string }).standard ?? '')].filter(Boolean) : [],
      sourceModule: `web-scanner/${finding.phase}`,
    })
  }

  private anchorFor(anchor: FindingAnchor): string {
    switch (anchor) {
      case 'certificate': return this.leafId ?? (this.transportDrawn ? this.endpointId : this.assetId)
      case 'key-establishment': return this.kexId ?? (this.transportDrawn ? this.endpointId : this.assetId)
      case 'endpoint': return this.sink.getNode(this.endpointId) ? this.endpointId : this.assetId
      case 'application': return this.appId ?? (this.sink.getNode(this.endpointId) ? this.endpointId : this.assetId)
      default: return this.assetId
    }
  }

  private upsertFinding(spec: {
    key: string; ruleId: string; ruleVersion: string; type: FindingType; title: string; description: string; severity: Severity
    exposure: ExposureClass; anchors: string[]; evidence: LiveEvidence; observed: Record<string, string>; remediation: string
    standards: string[]; sourceModule: string
  }): void {
    const id = `finding:${this.sink.hash(spec.key).slice(0, 16)}`
    const existing = this.sink.getFinding(id)
    const now = this.sink.now()
    const finding: LiveFinding = {
      id, ruleId: spec.ruleId, ruleVersion: spec.ruleVersion, type: spec.type, title: spec.title,
      description: existing?.description ?? spec.description, severity: spec.severity, exposure: spec.exposure,
      affectedNodeIds: [...new Set([...(existing?.affectedNodeIds ?? []), ...spec.anchors])],
      affectedTargets: [...new Set([...(existing?.affectedTargets ?? []), this.ctx.target])],
      evidenceIds: [...new Set([...(existing?.evidenceIds ?? []), spec.evidence.id])],
      observed: { ...(existing?.observed ?? {}), ...spec.observed },
      detectedAt: existing?.detectedAt ?? now, firstSeen: existing?.firstSeen ?? now, lastSeen: now,
      status: spec.exposure === 'unknown-migration-status' ? 'unknown' : 'open',
      remediation: spec.remediation, standards: spec.standards, sourceModule: spec.sourceModule,
    }
    const status = statusForFinding(spec.severity, spec.exposure)
    const findingNode: LiveNode = {
      id, kind: 'finding', label: spec.title, sublabel: `${spec.severity.toUpperCase()} · ${finding.affectedTargets.length} target(s)`,
      status, targets: [this.ctx.target], observedAt: now, firstSeq: 0, lastSeq: 0, evidenceIds: [spec.evidence.id],
      data: { findingId: id, severity: spec.severity, exposure: spec.exposure, type: spec.type, affectedCount: finding.affectedNodeIds.length },
    }
    this.sink.emit(existing ? 'finding.updated' : 'finding.created', { finding, node: findingNode }, existing && this.findingIds.has(id) ? null : {
      title: spec.exposure === 'quantum-migration' ? 'Quantum migration exposure detected' : FINDING_TYPE_LABEL[spec.type],
      detail: spec.title, severity: spec.severity, entityId: id, target: this.ctx.target,
    }, id)
    this.findingIds.add(id)
    const risk: EdgeRisk = status === 'critical' ? 'critical' : status === 'exposure' ? 'exposure' : 'none'
    for (const anchor of spec.anchors) {
      this.edge(anchor, id, spec.exposure === 'quantum-migration' ? 'REQUIRES_MIGRATION' : 'AFFECTED_BY_FINDING', 'observed', spec.evidence,
        `${spec.sourceModule} raised ${spec.ruleId} against this entity.`, risk)
      // Raise target-owned nodes only; shared algorithm/CA status is intrinsic.
      if (anchor === this.assetId || anchor === this.endpointId || anchor === this.leafId || anchor === this.appId) {
        this.raiseAndEmit(anchor, status)
      }
    }
  }

  private raise(id: string, status: NodeStatus): NodeStatus {
    const current = this.raised.get(id)
    const next = current ? worseStatus(current, status) : status
    this.raised.set(id, next)
    return next
  }

  private raiseAndEmit(id: string, status: NodeStatus): void {
    if (status === 'observed' || status === 'validated') return
    const node = this.sink.getNode(id)
    if (!node) return
    const next = this.raise(id, status)
    // An asset still scanning is finalized in completed(); unchanged nodes are not re-sent.
    if (node.status === 'active' || node.status === next) return
    this.sink.emit('asset.updated', { node: { ...node, status: next } }, null, id)
  }

  /* ----------------------------- stage 4: terminal ----------------------------- */

  completed(result: WebScanCompleteResult | null, error: string | null): void {
    const node = this.sink.getNode(this.assetId)
    if (!node) return
    const endpoint = this.sink.getNode(this.endpointId)
    const handshakeFailed = !endpoint || endpoint.data.handshake === 'failed'
    const transportMissing = !endpoint?.data.tlsVersion
    let status: NodeStatus
    if (!result) status = 'failed'
    else if (handshakeFailed || transportMissing || error) status = 'unknown'
    else status = this.raised.get(this.assetId) ?? 'observed'
    // Roll up the target's worst finding so the asset reads its exposure.
    for (const id of [this.endpointId, this.leafId, this.kexId, this.appId]) {
      if (!id) continue
      const raised = this.raised.get(id)
      if (raised && (raised === 'critical' || raised === 'exposure')) status = worseStatus(status, raised)
    }
    this.sink.emit('asset.updated', {
      node: {
        ...node, status,
        data: {
          ...node.data,
          scanStatus: !result ? 'failed' : handshakeFailed || transportMissing || error ? 'incomplete' : 'completed',
          error: error ?? (transportMissing ? 'The protocol probe did not report a negotiated TLS version. Observed certificate and application evidence is retained.' : null),
          riskScore: error || transportMissing ? null : result?.overallRiskScore ?? null, riskLevel: error || transportMissing ? null : result?.riskLevel ?? null,
          quantumReadinessScore: error || transportMissing ? null : result?.quantumReadinessScore ?? null, quantumReadinessLevel: error || transportMissing ? null : result?.quantumReadinessLevel ?? null,
          durationMs: result?.scanDuration ?? null, engineFindings: result?.totalFindings ?? null,
          lastObserved: this.sink.now(),
        },
      },
    }, {
      title: result && (error || transportMissing) ? 'Target analysis incomplete' : result ? 'Scan worker completed target analysis' : 'Target analysis failed',
      detail: result && !error
        ? `${this.ctx.target} · ${result.totalFindings} engine finding(s)${transportMissing ? ' · TLS protocol unmeasured' : ` · risk ${result.overallRiskScore}/100`}`
        : `${this.ctx.target} · ${error ?? 'unknown error'}`,
      severity: result && !error ? (handshakeFailed || transportMissing ? 'medium' : undefined) : 'high',
      entityId: this.assetId, target: this.ctx.target,
    }, this.assetId)
  }
}

