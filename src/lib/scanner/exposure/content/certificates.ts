/**
 * Certificate & Key Material Engine — v3 (§22, §23, §24, §31).
 *
 * WHAT CHANGED IN v3
 *
 * v2 read the SubjectPublicKeyInfo and reported one algorithm per certificate.
 * §23 requires two:
 *
 *   "Separate Certificate Public Key Algorithm from Certificate Signature
 *    Algorithm. Both must be recorded independently."
 *
 * They belong to different parties. A subscriber can re-key their subject
 * algorithm at will; the signature algorithm is the CA's decision and often the
 * real migration blocker. A single field cannot express "our key is ready, our
 * issuer is not", which is the most common real state of a PQC migration.
 *
 * The DER parsing now lives in `lib/crypto/certificate-intelligence.ts` so the
 * Web scanner's live-handshake path and this file-based path share one parser
 * and one set of verdicts — a certificate assessed from disk and the same
 * certificate assessed over TLS produce identical findings.
 */

import {
  assessCertificate,
  assessChain,
  decodeBase64,
  parseCertificate,
  parsePemBundle,
  type CertificateAssessment,
  type ParsedCertificate,
} from '@/lib/crypto/certificate-intelligence';
import { KNOWLEDGE_BASE_VERSION, RULE_SET_VERSION, citeStandard, classify } from '@/lib/crypto/knowledge-base';
import type { CryptoRole, FindingSeverity, QuantumStatus } from '../types';
import type { EngineContext, EngineResult, ExposureEngine } from '../engine-contract';
import { buildEvidence, buildFinding, completed } from '../engine-contract';

/* ─────────────────────────────────────────────────────────── model bridging ─ */

function toExposureQuantum(status: string): QuantumStatus {
  switch (status) {
    case 'QUANTUM_VULNERABLE': return 'vulnerable';
    case 'PQC_STANDARDIZED': return 'pqc';
    case 'HYBRID': return 'hybrid';
    case 'QUANTUM_RESISTANT': return 'resistant';
    case 'NOT_APPLICABLE': return 'not-applicable';
    default: return 'unknown';
  }
}

/* ══════════════════════════════════════════════════════════ SSH key parsing ═ */

const SSH_KEY_TYPES: Record<string, { algorithm: string; bits?: number }> = {
  'ssh-rsa': { algorithm: 'RSA' },
  'rsa-sha2-256': { algorithm: 'RSA' },
  'rsa-sha2-512': { algorithm: 'RSA' },
  'ssh-dss': { algorithm: 'DSA', bits: 1024 },
  'ssh-ed25519': { algorithm: 'Ed25519', bits: 256 },
  'ssh-ed448': { algorithm: 'Ed448', bits: 448 },
  'ecdsa-sha2-nistp256': { algorithm: 'ECDSA', bits: 256 },
  'ecdsa-sha2-nistp384': { algorithm: 'ECDSA', bits: 384 },
  'ecdsa-sha2-nistp521': { algorithm: 'ECDSA', bits: 521 },
  'sk-ssh-ed25519@openssh.com': { algorithm: 'Ed25519', bits: 256 },
  'sk-ecdsa-sha2-nistp256@openssh.com': { algorithm: 'ECDSA', bits: 256 },
};

/**
 * RSA modulus size from an OpenSSH wire-format public key.
 *
 * Format: uint32 len | "ssh-rsa" | uint32 len | e | uint32 len | n
 */
export function sshRsaBits(blob: Uint8Array): number | null {
  const readUint32 = (offset: number): number | null =>
    offset + 4 <= blob.length
      ? ((blob[offset] << 24) | (blob[offset + 1] << 16) | (blob[offset + 2] << 8) | blob[offset + 3]) >>> 0
      : null;

  const typeLength = readUint32(0);
  if (typeLength === null || typeLength > 64) return null;
  let cursor = 4 + typeLength;
  const exponentLength = readUint32(cursor);
  if (exponentLength === null || exponentLength > 8) return null;
  cursor += 4 + exponentLength;
  const modulusLength = readUint32(cursor);
  if (modulusLength === null || modulusLength > 2048) return null;
  const leadingZero = blob[cursor + 4] === 0 ? 1 : 0;
  return (modulusLength - leadingZero) * 8;
}

/* ────────────────────────────────────────────────────────────── the engine ── */

const PRIVATE_KEY_BLOCK = /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g;

export const certificateEngine: ExposureEngine = {
  descriptor: {
    id: 'certificate-material',
    label: 'Certificates & Key Material',
    description:
      'Parses X.509 certificates and OpenSSH keys, recording the subject public key and the issuer signature algorithm as separate facts, with chain, validity, key-usage and quantum analysis.',
    mode: 'local',
    layer: 'certificate',
    capability: 'certificates',
    dependsOn: ['file-discovery'],
    weight: 8,
    privacySensitive: true,
  },

  appliesTo(context) {
    const has = context.workspace.files.some(
      (file) =>
        file.content &&
        (file.classification === 'certificate' ||
          file.classification === 'key-material' ||
          /-----BEGIN |^ssh-(rsa|dss|ed25519)|^ecdsa-sha2/m.test(file.content)),
    );
    return has
      ? { applicable: true }
      : { applicable: false, reason: 'No certificate or key material was found in scope.' };
  },

  async execute(context: EngineContext): Promise<EngineResult> {
    const files = context.workspace.files.filter(
      (file) =>
        file.content &&
        !context.isExcluded(file.path) &&
        /-----BEGIN |^ssh-(rsa|dss|ed25519)|^ecdsa-sha2/m.test(file.content),
    );

    const findings: ReturnType<typeof buildFinding>[] = [];
    let certificates = 0;
    let processed = 0;
    const inventory: Array<Record<string, unknown>> = [];

    for (const file of files) {
      if (context.isCancelled()) break;
      processed += 1;
      context.report(`Parsing ${file.path}`, { done: processed, total: files.length, unit: 'files' });

      const content = file.content as string;

      /* ── private key blocks ─────────────────────────────────────────── */
      PRIVATE_KEY_BLOCK.lastIndex = 0;
      let keyBlock: RegExpExecArray | null;
      while ((keyBlock = PRIVATE_KEY_BLOCK.exec(content)) !== null) {
        const label = (keyBlock[1] ?? '').trim();
        const lineNumber = content.slice(0, keyBlock.index).split('\n').length;
        const algorithm = label === 'RSA' ? 'RSA' : label === 'EC' ? 'ECDSA' : label === 'DSA' ? 'DSA' : null;

        /* An unlabelled PKCS#8 block carries its algorithm inside the DER, and
           this engine deliberately does NOT decode a private key body to find
           out. The secret engine reports the exposure; the algorithm stays
           unknown rather than guessed. */
        const classification = algorithm
          ? classify({ algorithm, declaredRole: 'digital-signature', context: `private key in ${file.path}` })
          : null;

        findings.push(
          buildFinding({
            scanId: context.scanId,
            engineId: 'certificate-material',
            mode: context.mode,
            layer: 'certificate',
            category: 'Key Material',
            subcategory: `${label || 'PKCS#8'} private key`,
            title: algorithm
              ? `${classification?.canonicalName} private key present in ${file.path}`
              : `Private key present in ${file.path}`,
            description: [
              `A ${label ? `${label} ` : ''}private key block is present. Its body was NOT decoded and is not stored anywhere in this platform.`,
              classification?.quantumRationale ?? 'The key algorithm is inside the encoded body, which this engine does not read, so no quantum verdict is published for it.',
            ].join(' '),
            severity: 'high',
            confidence: 'high',
            detection: 'observed',
            algorithm: algorithm ?? undefined,
            canonicalAlgorithm: classification?.canonicalName,
            role: 'signature',
            quantumStatus: classification ? toExposureQuantum(classification.quantumStatus) : 'unknown',
            quantumRationale: classification?.quantumRationale,
            recommendation: classification?.migrationTarget
              ? `Plan migration to ${classification.migrationTarget} when this key is next rotated. Rotate it now regardless — a key in a scanned filesystem should be treated as disclosed.`
              : 'Treat this key as disclosed and rotate it.',
            evidence: [
              buildEvidence({
                summary: `${label || 'PKCS#8'} private key block at ${file.path}:${lineNumber}. Body redacted and never decoded.`,
                file: file.path,
                line: lineNumber,
                snippet: `-----BEGIN ${label ? `${label} ` : ''}PRIVATE KEY----- [REDACTED]`,
                ruleId: 'cert-private-key-block',
                localOnly: context.mode === 'local',
                attributes: { engineVersion: '3.0.0', knowledgeBaseVersion: KNOWLEDGE_BASE_VERSION },
              }),
            ],
            identity: `${file.path}|private-key|${lineNumber}`,
          }),
        );
      }

      /* ── certificates and public keys ───────────────────────────────── */
      const bundle = parsePemBundle(content);
      const chain: ParsedCertificate[] = [];

      for (const entry of bundle) {
        certificates += 1;

        if (!entry.certificate.parsed) {
          context.notAssessed(
            `Certificate at ${file.path}:${entry.line}`,
            entry.certificate.undetermined.length
              ? `The DER could not be fully read: ${entry.certificate.undetermined.join('; ')}.`
              : 'The DER structure did not expose the fields this parser reads, so no verdict is published for it.',
          );
          continue;
        }

        if (!entry.certificate.barePublicKey) chain.push(entry.certificate);

        const assessment = assessCertificate(entry.certificate);
        inventory.push(summariseForInventory(file.path, entry.line, assessment));
        findings.push(...certificateFindings(context, file.path, entry.line, entry.label, assessment));
      }

      /* ── chain-level assessment (§22) ───────────────────────────────── */
      if (chain.length > 1) {
        const chainAssessment = assessChain(chain);
        for (const finding of chainAssessment.findings) {
          findings.push(
            buildFinding({
              scanId: context.scanId,
              engineId: 'certificate-material',
              mode: context.mode,
              layer: 'certificate',
              category: 'Certificate Chain',
              subcategory: 'Chain integrity',
              title: `${finding.title} — ${file.path}`,
              description: finding.detail,
              severity: finding.severity,
              confidence: 'high',
              detection: 'observed',
              quantumStatus: 'not-applicable',
              evidence: [
                buildEvidence({
                  summary: `Chain of ${chainAssessment.depth} certificates in ${file.path}; reaches a self-signed root: ${chainAssessment.reachesRoot}.`,
                  file: file.path,
                  ruleId: finding.ruleId,
                  localOnly: context.mode === 'local',
                  attributes: {
                    chainDepth: chainAssessment.depth,
                    reachesRoot: chainAssessment.reachesRoot,
                    engineVersion: '3.0.0',
                    ruleSetVersion: RULE_SET_VERSION,
                  },
                }),
              ],
              identity: `${file.path}|chain|${finding.ruleId}`,
            }),
          );
        }
      }

      /* ── OpenSSH public keys (§31) ──────────────────────────────────── */
      const lines = content.split('\n');
      for (let index = 0; index < lines.length; index += 1) {
        const match = lines[index].match(
          /^\s*((?:ssh|rsa|ecdsa|sk)-[a-z0-9@.-]+)\s+([A-Za-z0-9+/=]{40,})(?:\s+(\S+))?/,
        );
        if (!match) continue;
        const type = SSH_KEY_TYPES[match[1]];
        if (!type) continue;

        let bits = type.bits ?? null;
        if (type.algorithm === 'RSA') {
          const blob = decodeBase64(match[2]);
          if (blob) bits = sshRsaBits(blob);
        }

        const classification = classify({
          algorithm: type.algorithm,
          keySize: bits,
          declaredRole: 'authentication',
          context: `OpenSSH ${match[1]} key in ${file.path}`,
        });

        const isAuthorizedKeys = /authorized_keys/i.test(file.path);
        const severity: FindingSeverity =
          classification.classicalSecurity === 'BROKEN'
            ? 'high'
            : classification.quantumStatus === 'QUANTUM_VULNERABLE'
              ? 'medium'
              : 'info';

        findings.push(
          buildFinding({
            scanId: context.scanId,
            engineId: 'certificate-material',
            mode: context.mode,
            layer: 'identity',
            category: 'SSH Key',
            subcategory: match[1],
            title: `${classification.canonicalName}${bits ? `-${bits}` : ''} SSH key in ${file.path}`,
            description: [
              `An OpenSSH ${match[1]} public key${match[3] ? ` (${match[3]})` : ''}.`,
              classification.classicalRationale,
              classification.quantumRationale,
              isAuthorizedKeys
                ? 'This is an authorized_keys entry, so it grants standing access to this account.'
                : '',
            ].filter(Boolean).join(' '),
            severity,
            confidence: 'high',
            detection: 'observed',
            algorithm: type.algorithm,
            canonicalAlgorithm: classification.canonicalName,
            keySize: bits,
            role: 'authentication',
            quantumStatus: toExposureQuantum(classification.quantumStatus),
            quantumRationale: classification.quantumRationale,
            recommendation: classification.migrationTarget
              ? `Plan for ${classification.migrationTarget} once OpenSSH supports post-quantum host and user keys. OpenSSH already offers hybrid KEY EXCHANGE (sntrup761x25519), which addresses the harvest-now risk to session traffic ahead of the key material itself.`
              : undefined,
            evidence: [
              buildEvidence({
                summary: `${match[1]} key at ${file.path}:${index + 1}`,
                file: file.path,
                line: index + 1,
                snippet: `${match[1]} [REDACTED]${match[3] ? ` ${match[3]}` : ''}`,
                ruleId: 'QGH-SSH-002',
                localOnly: context.mode === 'local',
                attributes: {
                  keyType: match[1],
                  keySize: bits ?? 0,
                  authorizedKeys: isAuthorizedKeys,
                  engineVersion: '3.0.0',
                  knowledgeBaseVersion: KNOWLEDGE_BASE_VERSION,
                },
              }),
            ],
            identity: `${file.path}|ssh-key|${index}|${type.algorithm}`,
            migration:
              classification.quantumStatus === 'QUANTUM_VULNERABLE'
                ? { candidate: true, target: classification.migrationTarget, priority: classification.migrationPriority ?? 'P3', complexity: 'medium' }
                : { candidate: false },
          }),
        );
      }
    }

    for (const finding of findings) context.emit(finding);
    context.workspace.meta.certificateInventory = inventory;

    return completed(findings, { certificates }, { certificates, inventory: inventory.length, engineVersion: '3.0.0' });
  },
};

/* ─────────────────────────────────────────────────── finding construction ─── */

/**
 * Build findings from one certificate assessment.
 *
 * The public key and the signature produce SEPARATE findings, because they are
 * separate facts with separate owners (§23). Merging them is exactly what the
 * specification forbids.
 */
function certificateFindings(
  context: EngineContext,
  path: string,
  line: number,
  label: string,
  assessment: CertificateAssessment,
): ReturnType<typeof buildFinding>[] {
  const out: ReturnType<typeof buildFinding>[] = [];
  const { certificate, publicKeyClassification, signatureClassification } = assessment;

  const subject = certificate.subject ?? certificate.subjectAltNames[0] ?? label.toLowerCase();
  const commonAttributes = {
    subject: certificate.subject ?? '',
    issuer: certificate.issuer ?? '',
    serialNumber: certificate.serialNumber ?? '',
    notBefore: certificate.notBefore ?? '',
    notAfter: certificate.notAfter ?? '',
    purpose: assessment.inferredPurpose,
    isCa: certificate.isCa ?? false,
    sanCount: certificate.subjectAltNames.length,
    engineVersion: '3.0.0',
    knowledgeBaseVersion: KNOWLEDGE_BASE_VERSION,
    ruleSetVersion: RULE_SET_VERSION,
  };

  /* ── the SUBJECT public key ───────────────────────────────────────────── */
  if (publicKeyClassification) {
    const severity: FindingSeverity =
      publicKeyClassification.classicalSecurity === 'BROKEN'
        ? 'critical'
        : publicKeyClassification.quantumStatus === 'QUANTUM_VULNERABLE'
          ? certificate.isCa
            ? 'critical'
            : 'high'
          : 'info';

    out.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'certificate-material',
        mode: context.mode,
        layer: 'certificate',
        category: 'Certificate Public Key',
        subcategory: publicKeyClassification.canonicalName,
        title: `${publicKeyClassification.canonicalName}${certificate.publicKey.keySize ? `-${certificate.publicKey.keySize}` : ''} subject key — ${subject}`,
        description: [
          `Certificate public key: ${publicKeyClassification.canonicalName}${certificate.publicKey.keySize ? ` (${certificate.publicKey.keySize} bits)` : ''}${certificate.publicKey.curve ? ` on ${certificate.publicKey.curve.canonicalName}` : ''}. Purpose: ${assessment.inferredPurpose}.`,
          publicKeyClassification.classicalRationale,
          publicKeyClassification.quantumRationale,
          /* The distinction §23 exists for, stated on every certificate. */
          certificate.signature.algorithm
            ? `This is the SUBJECT key and is a separate fact from the signature algorithm the issuer used (${certificate.signature.algorithm}${certificate.signature.hash ? `-${certificate.signature.hash}` : ''}); the two are held by different parties and migrate independently.`
            : '',
        ].filter(Boolean).join(' '),
        severity,
        confidence: 'high',
        detection: 'observed',
        algorithm: certificate.publicKey.algorithm ?? undefined,
        canonicalAlgorithm: publicKeyClassification.canonicalName,
        keySize: certificate.publicKey.keySize,
        role: 'certificate',
        quantumStatus: toExposureQuantum(publicKeyClassification.quantumStatus),
        quantumRationale: publicKeyClassification.quantumRationale,
        recommendation: publicKeyClassification.migrationTarget
          ? `Re-issue with ${publicKeyClassification.migrationTarget} once the issuing CA supports it. Automated issuance turns this into a configuration change rather than a project.`
          : undefined,
        references: publicKeyClassification.standards.map(citeStandard),
        evidence: [
          buildEvidence({
            summary: `SubjectPublicKeyInfo parsed from ${path}:${line} — ${publicKeyClassification.canonicalName}${certificate.publicKey.keySize ? `, ${certificate.publicKey.keySize} bits` : ''}.`,
            file: path,
            line,
            ruleId: 'QGH-CERT-002',
            localOnly: context.mode === 'local',
            attributes: {
              ...commonAttributes,
              publicKeyAlgorithm: certificate.publicKey.algorithm ?? '',
              publicKeyOid: certificate.publicKey.oid ?? '',
              curve: certificate.publicKey.curve?.canonicalName ?? '',
              keyUsage: certificate.keyUsage.join(','),
              extendedKeyUsage: certificate.extendedKeyUsage.join(','),
            },
          }),
        ],
        identity: `${path}|cert-pubkey|${line}|${certificate.serialNumber ?? subject}`,
        migration:
          publicKeyClassification.quantumStatus === 'QUANTUM_VULNERABLE'
            ? {
                candidate: true,
                target: publicKeyClassification.migrationTarget,
                priority: publicKeyClassification.migrationPriority ?? 'P2',
                complexity: 'low',
              }
            : { candidate: false },
      }),
    );
  }

  /* ── the ISSUER signature ─────────────────────────────────────────────── */
  if (signatureClassification && !certificate.barePublicKey) {
    const brokenHash = certificate.signature.hash === 'SHA-1' || certificate.signature.hash === 'MD5';
    const severity: FindingSeverity = brokenHash
      ? 'critical'
      : signatureClassification.quantumStatus === 'QUANTUM_VULNERABLE'
        ? 'medium'
        : 'info';

    out.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'certificate-material',
        mode: context.mode,
        layer: 'certificate',
        category: 'Certificate Signature',
        subcategory: `${certificate.signature.algorithm}${certificate.signature.hash ? `-${certificate.signature.hash}` : ''}`,
        title: `Signed with ${certificate.signature.algorithm}${certificate.signature.hash ? `-${certificate.signature.hash}` : ''} — ${subject}`,
        description: [
          `The ISSUER (${certificate.issuer ?? 'unnamed'}) signed this certificate using ${certificate.signature.algorithm}${certificate.signature.hash ? ` with ${certificate.signature.hash}` : ''}.`,
          brokenHash
            ? `${certificate.signature.hash} collisions are practical, so this signature provides no real integrity guarantee. Remediation requires re-issuance BY THE CA — it is not something the subscriber can fix by re-keying.`
            : signatureClassification.quantumRationale,
          'This is recorded separately from the subject public key because the two are different keys held by different parties.',
        ].filter(Boolean).join(' '),
        severity,
        confidence: 'high',
        detection: 'observed',
        algorithm: certificate.signature.algorithm ?? undefined,
        canonicalAlgorithm: signatureClassification.canonicalName,
        role: 'certificate',
        quantumStatus: toExposureQuantum(signatureClassification.quantumStatus),
        quantumRationale: signatureClassification.quantumRationale,
        recommendation: brokenHash
          ? 'Request re-issuance from the CA with a SHA-256 or stronger signature.'
          : signatureClassification.migrationTarget
            ? `The issuing chain will need ${signatureClassification.migrationTarget}; track your CA's post-quantum roadmap.`
            : undefined,
        references: signatureClassification.standards.map(citeStandard),
        evidence: [
          buildEvidence({
            summary: `signatureAlgorithm parsed from ${path}:${line} — OID ${certificate.signature.oid ?? 'unknown'}.`,
            file: path,
            line,
            ruleId: brokenHash ? 'QGH-CERT-001' : 'QGH-CERT-002',
            localOnly: context.mode === 'local',
            attributes: {
              ...commonAttributes,
              signatureAlgorithm: certificate.signature.algorithm ?? '',
              signatureHash: certificate.signature.hash ?? '',
              signatureOid: certificate.signature.oid ?? '',
            },
          }),
        ],
        identity: `${path}|cert-signature|${line}|${certificate.serialNumber ?? subject}`,
      }),
    );
  }

  /* ── validity, self-signed, key-usage consistency ─────────────────────── */
  for (const finding of assessment.findings) {
    /* The public-key and signature findings above already cover these two. */
    if (finding.ruleId === 'QGH-CERT-002' && finding.title.includes('public key is')) continue;
    if (finding.ruleId === 'QGH-CERT-001') continue;

    out.push(
      buildFinding({
        scanId: context.scanId,
        engineId: 'certificate-material',
        mode: context.mode,
        layer: 'certificate',
        category: 'Certificate',
        subcategory: 'Validity and usage',
        title: `${finding.title} — ${subject}`,
        description: finding.detail,
        severity: finding.severity,
        confidence: 'high',
        detection: 'observed',
        role: 'certificate',
        quantumStatus: 'not-applicable',
        evidence: [
          buildEvidence({
            summary: `${finding.title} for the certificate at ${path}:${line}.`,
            file: path,
            line,
            ruleId: finding.ruleId,
            localOnly: context.mode === 'local',
            attributes: { ...commonAttributes, daysUntilExpiry: assessment.daysUntilExpiry ?? 0 },
          }),
        ],
        identity: `${path}|cert-${finding.ruleId}|${line}|${certificate.serialNumber ?? subject}`,
      }),
    );
  }

  return out;
}

/**
 * The inventory row other modules read (§50, §88).
 *
 * Both algorithms are present, which is what lets the Certificate Inventory
 * report show "subject RSA-2048 / issuer ECDSA-SHA256" rather than one merged
 * and misleading value.
 */
function summariseForInventory(path: string, line: number, assessment: CertificateAssessment): Record<string, unknown> {
  const { certificate } = assessment;
  return {
    file: path,
    line,
    subject: certificate.subject,
    issuer: certificate.issuer,
    serialNumber: certificate.serialNumber,
    notBefore: certificate.notBefore,
    notAfter: certificate.notAfter,
    daysUntilExpiry: assessment.daysUntilExpiry,
    purpose: assessment.inferredPurpose,
    isCa: certificate.isCa,
    selfSigned: certificate.selfSigned,
    subjectAltNames: certificate.subjectAltNames.slice(0, 20),
    publicKey: {
      algorithm: certificate.publicKey.algorithm,
      keySize: certificate.publicKey.keySize,
      curve: certificate.publicKey.curve?.canonicalName ?? null,
      quantumStatus: assessment.publicKeyClassification?.quantumStatus ?? 'UNKNOWN',
    },
    signature: {
      algorithm: certificate.signature.algorithm,
      hash: certificate.signature.hash,
      quantumStatus: assessment.signatureClassification?.quantumStatus ?? 'UNKNOWN',
    },
    undetermined: certificate.undetermined,
  };
}

/* Re-exported so the existing callers of these helpers keep working. */
export { decodeBase64, parseCertificate, parsePemBundle };
export type { ParsedCertificate };
