/**
 * Certificate Intelligence Engine™ (§22, §23, §24).
 *
 * §23 states the requirement this module exists for:
 *
 *   "Separate Certificate Public Key Algorithm from Certificate Signature
 *    Algorithm. Both must be recorded independently. Do not report
 *    'Certificate = ECDSA' without distinguishing these fields."
 *
 * They are genuinely different keys held by different parties. A certificate
 * whose subject key is RSA-2048 may be signed by an issuer using ECDSA-P384,
 * and the two have different owners, different rotation schedules and different
 * migration paths. Collapsing them loses the ability to say which half is the
 * problem — and in a PQC migration the issuer's algorithm is often the blocker
 * even when the subscriber is ready.
 *
 * The parser is a bounded DER walk. It reads the fields the assessment needs
 * and skips the rest; it never allocates from an attacker-controlled length,
 * and every malformed structure yields `null` rather than an exception (§69).
 */

import {
  classify,
  findCurve,
  type CryptoClassification,
  type CurveDefinition,
} from './knowledge-base';

/* ═════════════════════════════════════════════════════════════ DER reading ══ */

interface DerNode {
  tag: number;
  headerLength: number;
  length: number;
  contentStart: number;
  end: number;
}

/** Read one TLV header. Returns null on anything malformed or out of bounds. */
function readHeader(bytes: Uint8Array, offset: number): DerNode | null {
  if (offset + 2 > bytes.length) return null;
  const tag = bytes[offset];
  let cursor = offset + 1;
  let length = bytes[cursor];
  cursor += 1;

  if (length & 0x80) {
    const count = length & 0x7f;
    /* An indefinite length (0x80) or a >4-byte length is either BER or an
       attack. Refusing both is what keeps the walk bounded (§69). */
    if (count === 0 || count > 4 || cursor + count > bytes.length) return null;
    length = 0;
    for (let index = 0; index < count; index += 1) length = (length << 8) | bytes[cursor + index];
    cursor += count;
  }

  if (length < 0 || cursor + length > bytes.length) return null;
  return { tag, headerLength: cursor - offset, length, contentStart: cursor, end: cursor + length };
}

function decodeOid(bytes: Uint8Array, start: number, length: number): string {
  if (length === 0) return '';
  const parts: number[] = [];
  const first = bytes[start];
  parts.push(Math.floor(first / 40), first % 40);
  let value = 0;
  for (let index = 1; index < length; index += 1) {
    const byte = bytes[start + index];
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

/** Decode a DER time (UTCTime or GeneralizedTime) to an ISO string. */
function decodeTime(bytes: Uint8Array, node: DerNode): string | null {
  const text = latin1(bytes, node.contentStart, node.length);
  // UTCTime: YYMMDDHHMMSSZ. GeneralizedTime: YYYYMMDDHHMMSSZ.
  const utc = text.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/);
  if (utc && node.tag === 0x17) {
    const year = Number(utc[1]);
    /* RFC 5280: values 50-99 are 19xx, 00-49 are 20xx. */
    const fullYear = year >= 50 ? 1900 + year : 2000 + year;
    return `${fullYear}-${utc[2]}-${utc[3]}T${utc[4]}:${utc[5]}:${utc[6] ?? '00'}Z`;
  }
  const generalized = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/);
  if (generalized) {
    return `${generalized[1]}-${generalized[2]}-${generalized[3]}T${generalized[4]}:${generalized[5]}:${generalized[6] ?? '00'}Z`;
  }
  return null;
}

function latin1(bytes: Uint8Array, start: number, length: number): string {
  let out = '';
  for (let index = 0; index < length; index += 1) out += String.fromCharCode(bytes[start + index]);
  return out;
}

/* ═══════════════════════════════════════════════════════════════ OID tables ═ */

/** Public-key algorithm OIDs (SubjectPublicKeyInfo.algorithm). */
const PUBLIC_KEY_OIDS: Record<string, string> = {
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.113549.1.1.10': 'RSA-PSS',
  '1.2.840.10045.2.1': 'ECDSA',
  '1.2.840.10040.4.1': 'DSA',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
  '1.3.101.110': 'X25519',
  '1.3.101.111': 'X448',
  '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
  '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
  '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
  '2.16.840.1.101.3.4.4.1': 'ML-KEM-512',
  '2.16.840.1.101.3.4.4.2': 'ML-KEM-768',
  '2.16.840.1.101.3.4.4.3': 'ML-KEM-1024',
};

/**
 * Signature algorithm OIDs, decomposed into (signature algorithm, digest).
 *
 * The decomposition matters: `sha1WithRSAEncryption` is an RSA signature with a
 * BROKEN digest, which is a completely different finding from an RSA signature
 * with SHA-256. One OID carries both facts and they must be reported apart.
 */
const SIGNATURE_OIDS: Record<string, { algorithm: string; hash: string | null }> = {
  '1.2.840.113549.1.1.4': { algorithm: 'RSA', hash: 'MD5' },
  '1.2.840.113549.1.1.5': { algorithm: 'RSA', hash: 'SHA-1' },
  '1.2.840.113549.1.1.11': { algorithm: 'RSA', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { algorithm: 'RSA', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { algorithm: 'RSA', hash: 'SHA-512' },
  '1.2.840.113549.1.1.14': { algorithm: 'RSA', hash: 'SHA-224' },
  '1.2.840.113549.1.1.10': { algorithm: 'RSA-PSS', hash: null },
  '1.2.840.10045.4.1': { algorithm: 'ECDSA', hash: 'SHA-1' },
  '1.2.840.10045.4.3.1': { algorithm: 'ECDSA', hash: 'SHA-224' },
  '1.2.840.10045.4.3.2': { algorithm: 'ECDSA', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { algorithm: 'ECDSA', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { algorithm: 'ECDSA', hash: 'SHA-512' },
  '1.2.840.10040.4.3': { algorithm: 'DSA', hash: 'SHA-1' },
  '2.16.840.1.101.3.4.3.2': { algorithm: 'DSA', hash: 'SHA-256' },
  '1.3.101.112': { algorithm: 'Ed25519', hash: 'SHA-512' },
  '1.3.101.113': { algorithm: 'Ed448', hash: 'SHAKE256' },
  '2.16.840.1.101.3.4.3.17': { algorithm: 'ML-DSA-44', hash: null },
  '2.16.840.1.101.3.4.3.18': { algorithm: 'ML-DSA-65', hash: null },
  '2.16.840.1.101.3.4.3.19': { algorithm: 'ML-DSA-87', hash: null },
};

/** Extension OIDs read for key usage and SAN. */
const EXT_KEY_USAGE = '2.5.29.15';
const EXT_SUBJECT_ALT_NAME = '2.5.29.17';
const EXT_BASIC_CONSTRAINTS = '2.5.29.19';
const EXT_EXT_KEY_USAGE = '2.5.29.37';

const KEY_USAGE_BITS = [
  'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
  'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly',
];

const EXTENDED_KEY_USAGE_OIDS: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
  '1.3.6.1.5.5.7.3.8': 'timeStamping',
  '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
};

/** Distinguished-name attribute OIDs worth surfacing. */
const DN_OIDS: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
};

/* ═══════════════════════════════════════════════════════════ parsed shape ══ */

export interface ParsedCertificate {
  /** True when the DER walk found the structures it expected. */
  parsed: boolean;
  /** Set when the artefact was a bare SubjectPublicKeyInfo, not a certificate. */
  barePublicKey: boolean;

  /* §23: the two algorithm fields, kept apart. */
  publicKey: {
    algorithm: string | null;
    keySize: number | null;
    curve: CurveDefinition | null;
    oid: string | null;
  };
  signature: {
    algorithm: string | null;
    hash: string | null;
    oid: string | null;
  };

  serialNumber: string | null;
  subject: string | null;
  issuer: string | null;
  notBefore: string | null;
  notAfter: string | null;
  subjectAltNames: string[];
  keyUsage: string[];
  extendedKeyUsage: string[];
  isCa: boolean | null;
  selfSigned: boolean | null;
  version: number | null;

  /** Everything the parser could not establish, named (§90). */
  undetermined: string[];
}

function emptyCertificate(): ParsedCertificate {
  return {
    parsed: false,
    barePublicKey: false,
    publicKey: { algorithm: null, keySize: null, curve: null, oid: null },
    signature: { algorithm: null, hash: null, oid: null },
    serialNumber: null,
    subject: null,
    issuer: null,
    notBefore: null,
    notAfter: null,
    subjectAltNames: [],
    keyUsage: [],
    extendedKeyUsage: [],
    isCa: null,
    selfSigned: null,
    version: null,
    undetermined: [],
  };
}

/* ══════════════════════════════════════════════════════════════ the parser ══ */

/**
 * Parse an X.509 certificate, or a bare SubjectPublicKeyInfo.
 *
 * `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }`
 *
 * The walk is by SHAPE rather than by index, because the optional version tag
 * shifts every subsequent field and an index-based walk silently reads the
 * wrong one on a v1 certificate.
 */
export function parseCertificate(bytes: Uint8Array): ParsedCertificate {
  const result = emptyCertificate();

  const outer = readHeader(bytes, 0);
  if (!outer || outer.tag !== 0x30) {
    result.undetermined.push('the DER did not begin with a SEQUENCE');
    return result;
  }

  /* A `-----BEGIN PUBLIC KEY-----` block is a bare SPKI with no tbsCertificate
     to walk into. Try that shape first so a published public key is parsed
     rather than reported as an unrecognised certificate. */
  if (readSpki(bytes, outer, result)) {
    result.parsed = true;
    result.barePublicKey = true;
    result.undetermined.push('certificate metadata (this artefact is a bare public key, not a certificate)');
    return result;
  }

  const tbs = readHeader(bytes, outer.contentStart);
  if (!tbs || tbs.tag !== 0x30) {
    result.undetermined.push('the tbsCertificate structure could not be read');
    return result;
  }

  /* ── signatureAlgorithm sits immediately after tbsCertificate ─────────── */
  const sigAlgSeq = readHeader(bytes, tbs.end);
  if (sigAlgSeq && sigAlgSeq.tag === 0x30) {
    const oidNode = readHeader(bytes, sigAlgSeq.contentStart);
    if (oidNode && oidNode.tag === 0x06) {
      const oid = decodeOid(bytes, oidNode.contentStart, oidNode.length);
      result.signature.oid = oid;
      const entry = SIGNATURE_OIDS[oid];
      if (entry) {
        result.signature.algorithm = entry.algorithm;
        result.signature.hash = entry.hash;
      } else {
        result.undetermined.push(`certificate signature algorithm (unrecognised OID ${oid})`);
      }
    }
  } else {
    result.undetermined.push('certificate signature algorithm');
  }

  /* ── walk tbsCertificate by shape ─────────────────────────────────────── */
  let cursor = tbs.contentStart;
  let seenSerial = false;
  let dnCount = 0;
  const distinguishedNames: string[] = [];

  while (cursor < tbs.end) {
    const node = readHeader(bytes, cursor);
    if (!node) break;

    /* [0] EXPLICIT version */
    if (node.tag === 0xa0 && result.version === null) {
      const inner = readHeader(bytes, node.contentStart);
      if (inner && inner.tag === 0x02 && inner.length >= 1) {
        result.version = bytes[inner.contentStart] + 1;
      }
      cursor = node.end;
      continue;
    }

    /* INTEGER serialNumber — the first bare INTEGER in the structure */
    if (node.tag === 0x02 && !seenSerial) {
      seenSerial = true;
      const hex: string[] = [];
      for (let index = 0; index < Math.min(node.length, 20); index += 1) {
        hex.push(bytes[node.contentStart + index].toString(16).padStart(2, '0'));
      }
      result.serialNumber = hex.join(':');
      cursor = node.end;
      continue;
    }

    if (node.tag === 0x30) {
      const inner = readHeader(bytes, node.contentStart);

      /* AlgorithmIdentifier (the inner tbs signature) — skip, it duplicates
         the outer signatureAlgorithm. */
      if (inner && inner.tag === 0x06 && SIGNATURE_OIDS[decodeOid(bytes, inner.contentStart, inner.length)]) {
        cursor = node.end;
        continue;
      }

      /* SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING } */
      if (inner && inner.tag === 0x30 && readSpki(bytes, node, result)) {
        cursor = node.end;
        continue;
      }

      /* Validity: SEQUENCE { Time, Time } */
      if (inner && (inner.tag === 0x17 || inner.tag === 0x18) && result.notBefore === null) {
        result.notBefore = decodeTime(bytes, inner);
        const second = readHeader(bytes, inner.end);
        if (second && (second.tag === 0x17 || second.tag === 0x18)) result.notAfter = decodeTime(bytes, second);
        cursor = node.end;
        continue;
      }

      /* Name: SEQUENCE OF RDN. Issuer comes first, subject second. */
      if (inner && inner.tag === 0x31) {
        const name = readDistinguishedName(bytes, node);
        distinguishedNames.push(name);
        dnCount += 1;
        cursor = node.end;
        continue;
      }
    }

    /* [3] EXPLICIT extensions */
    if (node.tag === 0xa3) {
      readExtensions(bytes, node, result);
      cursor = node.end;
      continue;
    }

    cursor = node.end;
  }

  if (distinguishedNames.length >= 1) result.issuer = distinguishedNames[0] || null;
  if (distinguishedNames.length >= 2) result.subject = distinguishedNames[1] || null;
  if (result.issuer && result.subject) result.selfSigned = result.issuer === result.subject;

  if (!result.publicKey.algorithm) result.undetermined.push('certificate public key algorithm');
  if (!result.notAfter) result.undetermined.push('certificate validity period');
  if (dnCount < 2) result.undetermined.push('certificate subject or issuer');

  result.parsed = Boolean(result.publicKey.algorithm || result.signature.algorithm);
  return result;
}

/**
 * Read a SubjectPublicKeyInfo whose SEQUENCE starts at `node`.
 *
 * Returns false when the node is not an SPKI, which is how the caller tells a
 * bare public key from a full certificate.
 */
function readSpki(bytes: Uint8Array, node: DerNode, result: ParsedCertificate): boolean {
  const algorithmSeq = readHeader(bytes, node.contentStart);
  if (!algorithmSeq || algorithmSeq.tag !== 0x30) return false;

  const oidNode = readHeader(bytes, algorithmSeq.contentStart);
  if (!oidNode || oidNode.tag !== 0x06) return false;

  const oid = decodeOid(bytes, oidNode.contentStart, oidNode.length);
  const algorithm = PUBLIC_KEY_OIDS[oid];
  if (!algorithm) return false;

  const bitString = readHeader(bytes, algorithmSeq.end);
  if (!bitString || bitString.tag !== 0x03) return false;

  result.publicKey.algorithm = algorithm;
  result.publicKey.oid = oid;

  /* Named curve for EC keys — the AlgorithmIdentifier parameter. */
  const parameter = readHeader(bytes, oidNode.contentStart + oidNode.length);
  if (parameter && parameter.tag === 0x06) {
    const curveOid = decodeOid(bytes, parameter.contentStart, parameter.length);
    const curve = findCurve(curveOid);
    if (curve) {
      result.publicKey.curve = curve;
      result.publicKey.keySize = curve.bits;
    } else {
      result.undetermined.push(`named curve (unrecognised OID ${curveOid})`);
    }
  }

  /* RSA modulus length. */
  if (algorithm === 'RSA' || algorithm === 'RSA-PSS') {
    const rsaSeq = readHeader(bytes, bitString.contentStart + 1);
    if (rsaSeq && rsaSeq.tag === 0x30) {
      const modulus = readHeader(bytes, rsaSeq.contentStart);
      if (modulus && modulus.tag === 0x02) {
        /* A leading 0x00 pads a positive INTEGER; it is not key material. */
        const leadingZero = bytes[modulus.contentStart] === 0 ? 1 : 0;
        result.publicKey.keySize = (modulus.length - leadingZero) * 8;
      }
    }
    if (result.publicKey.keySize === null) result.undetermined.push('RSA modulus size');
  }

  /* Edwards and Montgomery keys carry their size in the algorithm itself. */
  if (algorithm === 'Ed25519' || algorithm === 'X25519') result.publicKey.keySize = 256;
  if (algorithm === 'Ed448' || algorithm === 'X448') result.publicKey.keySize = 448;

  return true;
}

function readDistinguishedName(bytes: Uint8Array, node: DerNode): string {
  const parts: string[] = [];
  let cursor = node.contentStart;

  while (cursor < node.end) {
    const rdnSet = readHeader(bytes, cursor);
    if (!rdnSet || rdnSet.tag !== 0x31) break;

    const attribute = readHeader(bytes, rdnSet.contentStart);
    if (attribute && attribute.tag === 0x30) {
      const oidNode = readHeader(bytes, attribute.contentStart);
      if (oidNode && oidNode.tag === 0x06) {
        const oid = decodeOid(bytes, oidNode.contentStart, oidNode.length);
        const label = DN_OIDS[oid];
        const valueNode = readHeader(bytes, oidNode.contentStart + oidNode.length);
        if (label && valueNode && valueNode.length < 256) {
          parts.push(`${label}=${latin1(bytes, valueNode.contentStart, valueNode.length)}`);
        }
      }
    }
    cursor = rdnSet.end;
  }

  return parts.join(', ');
}

function readExtensions(bytes: Uint8Array, node: DerNode, result: ParsedCertificate): void {
  const sequence = readHeader(bytes, node.contentStart);
  if (!sequence || sequence.tag !== 0x30) return;

  let cursor = sequence.contentStart;
  while (cursor < sequence.end) {
    const extension = readHeader(bytes, cursor);
    if (!extension || extension.tag !== 0x30) break;

    const oidNode = readHeader(bytes, extension.contentStart);
    if (!oidNode || oidNode.tag !== 0x06) {
      cursor = extension.end;
      continue;
    }
    const oid = decodeOid(bytes, oidNode.contentStart, oidNode.length);

    /* The value is an OCTET STRING; the critical BOOLEAN may precede it. */
    let valueNode = readHeader(bytes, oidNode.contentStart + oidNode.length);
    if (valueNode && valueNode.tag === 0x01) valueNode = readHeader(bytes, valueNode.end);
    if (!valueNode || valueNode.tag !== 0x04) {
      cursor = extension.end;
      continue;
    }

    const inner = readHeader(bytes, valueNode.contentStart);
    if (!inner) {
      cursor = extension.end;
      continue;
    }

    if (oid === EXT_KEY_USAGE && inner.tag === 0x03 && inner.length >= 2) {
      const unusedBits = bytes[inner.contentStart];
      const bitCount = (inner.length - 1) * 8 - unusedBits;
      for (let bit = 0; bit < Math.min(bitCount, KEY_USAGE_BITS.length); bit += 1) {
        const byte = bytes[inner.contentStart + 1 + Math.floor(bit / 8)];
        if (byte & (0x80 >> bit % 8)) result.keyUsage.push(KEY_USAGE_BITS[bit]);
      }
    }

    if (oid === EXT_SUBJECT_ALT_NAME && inner.tag === 0x30) {
      let sanCursor = inner.contentStart;
      while (sanCursor < inner.end && result.subjectAltNames.length < 200) {
        const entry = readHeader(bytes, sanCursor);
        if (!entry) break;
        /* [2] dNSName, [7] iPAddress, [1] rfc822Name */
        if (entry.tag === 0x82 && entry.length < 256) {
          result.subjectAltNames.push(latin1(bytes, entry.contentStart, entry.length));
        } else if (entry.tag === 0x87 && (entry.length === 4 || entry.length === 16)) {
          const octets: string[] = [];
          for (let index = 0; index < entry.length; index += 1) octets.push(String(bytes[entry.contentStart + index]));
          result.subjectAltNames.push(entry.length === 4 ? octets.join('.') : `[${octets.join(':')}]`);
        }
        sanCursor = entry.end;
      }
    }

    if (oid === EXT_BASIC_CONSTRAINTS && inner.tag === 0x30) {
      const ca = readHeader(bytes, inner.contentStart);
      result.isCa = Boolean(ca && ca.tag === 0x01 && bytes[ca.contentStart] !== 0);
    } else if (oid === EXT_BASIC_CONSTRAINTS) {
      result.isCa = false;
    }

    if (oid === EXT_EXT_KEY_USAGE && inner.tag === 0x30) {
      let ekuCursor = inner.contentStart;
      while (ekuCursor < inner.end) {
        const entry = readHeader(bytes, ekuCursor);
        if (!entry || entry.tag !== 0x06) break;
        const usageOid = decodeOid(bytes, entry.contentStart, entry.length);
        result.extendedKeyUsage.push(EXTENDED_KEY_USAGE_OIDS[usageOid] ?? usageOid);
        ekuCursor = entry.end;
      }
    }

    cursor = extension.end;
  }
}

/* ═══════════════════════════════════════════════════ certificate assessment ═ */

export interface CertificateFinding {
  ruleId: string;
  title: string;
  detail: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface CertificateAssessment {
  certificate: ParsedCertificate;
  /** §23: two independent classifications, never merged. */
  publicKeyClassification: CryptoClassification | null;
  signatureClassification: CryptoClassification | null;
  findings: CertificateFinding[];
  /** Days until expiry; negative when already expired. */
  daysUntilExpiry: number | null;
  /** The role this certificate serves, from its extended key usage. */
  inferredPurpose: string;
}

/**
 * Assess a parsed certificate.
 *
 * The two classifications are produced separately and both are returned, so a
 * caller can render "RSA-2048 subject key, signed with ECDSA-SHA256" — which is
 * what §23 requires and what a single `algorithm` field cannot express.
 */
export function assessCertificate(certificate: ParsedCertificate, now = new Date()): CertificateAssessment {
  const findings: CertificateFinding[] = [];

  /* ── purpose, from extended key usage ─────────────────────────────────── */
  const purposes = certificate.extendedKeyUsage;
  const inferredPurpose = purposes.includes('codeSigning')
    ? 'code signing'
    : purposes.includes('serverAuth')
      ? 'TLS server authentication'
      : purposes.includes('clientAuth')
        ? 'TLS client authentication'
        : certificate.isCa
          ? 'certification authority'
          : purposes.length
            ? purposes.join(', ')
            : 'unspecified';

  /* ── the subject public key (§23) ─────────────────────────────────────── */
  const publicKeyClassification = certificate.publicKey.algorithm
    ? classify({
        algorithm: certificate.publicKey.algorithm,
        keySize: certificate.publicKey.keySize,
        curve: certificate.publicKey.curve?.canonicalName,
        declaredRole: 'certificate-public-key',
        context: `certificate subject public key, purpose: ${inferredPurpose}`,
      })
    : null;

  /* ── the issuer's signature (§23) ─────────────────────────────────────── */
  const signatureClassification = certificate.signature.algorithm
    ? classify({
        algorithm: certificate.signature.algorithm,
        hash: certificate.signature.hash,
        declaredRole: 'certificate-signature',
        context: `certificate signature algorithm, issued by ${certificate.issuer ?? 'an unnamed issuer'}`,
      })
    : null;

  /* ── QGH-CERT-001: SHA-1 signature ────────────────────────────────────── */
  if (certificate.signature.hash === 'SHA-1' || certificate.signature.hash === 'MD5') {
    findings.push({
      ruleId: 'QGH-CERT-001',
      title: `Certificate signed with ${certificate.signature.algorithm}-${certificate.signature.hash}`,
      detail: `The ISSUER signed this certificate using ${certificate.signature.hash}, whose collisions are practical. This is a classical break of the signature and is independent of quantum risk. Note that this is the issuer's choice, not the subscriber's — remediation requires re-issuance by the CA.`,
      severity: 'critical',
    });
  }

  /* ── QGH-CERT-002: quantum-vulnerable public key ──────────────────────── */
  if (publicKeyClassification?.quantumStatus === 'QUANTUM_VULNERABLE') {
    findings.push({
      ruleId: 'QGH-CERT-002',
      title: `Certificate public key is ${publicKeyClassification.canonicalName}${certificate.publicKey.keySize ? `-${certificate.publicKey.keySize}` : ''}`,
      detail: `${publicKeyClassification.quantumRationale} This is the SUBJECT key and is separate from the signature algorithm the issuer used${certificate.signature.algorithm ? ` (${certificate.signature.algorithm}${certificate.signature.hash ? `-${certificate.signature.hash}` : ''})` : ''}.`,
      severity: inferredPurpose === 'certification authority' ? 'critical' : 'high',
    });
  }

  /* ── weak key size (classical, not quantum) ───────────────────────────── */
  if (publicKeyClassification && publicKeyClassification.classicalSecurity === 'BROKEN') {
    findings.push({
      ruleId: 'QGH-CRYPTO-RSA-002',
      title: `Certificate public key is below the classical security floor`,
      detail: publicKeyClassification.classicalRationale,
      severity: 'critical',
    });
  }

  /* ── QGH-CERT-004: validity ───────────────────────────────────────────── */
  let daysUntilExpiry: number | null = null;
  if (certificate.notAfter) {
    const expiry = Date.parse(certificate.notAfter);
    if (Number.isFinite(expiry)) {
      daysUntilExpiry = Math.round((expiry - now.getTime()) / 86_400_000);
      if (daysUntilExpiry < 0) {
        findings.push({
          ruleId: 'QGH-CERT-004',
          title: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago`,
          detail: `notAfter is ${certificate.notAfter}. An expired certificate fails validation for every client that checks it.`,
          severity: 'high',
        });
      } else if (daysUntilExpiry <= 30) {
        findings.push({
          ruleId: 'QGH-CERT-004',
          title: `Certificate expires in ${daysUntilExpiry} days`,
          detail: `notAfter is ${certificate.notAfter}. Confirm the renewal automation will complete before then.`,
          severity: daysUntilExpiry <= 7 ? 'high' : 'medium',
        });
      }
    }
  }
  if (certificate.notBefore) {
    const start = Date.parse(certificate.notBefore);
    if (Number.isFinite(start) && start > now.getTime()) {
      findings.push({
        ruleId: 'QGH-CERT-004',
        title: 'Certificate is not yet valid',
        detail: `notBefore is ${certificate.notBefore}, which is in the future. Check the issuing system's clock.`,
        severity: 'high',
      });
    }
  }

  /* ── long-lived certificate: a harvest-now factor (§78) ───────────────── */
  if (certificate.notBefore && certificate.notAfter) {
    const start = Date.parse(certificate.notBefore);
    const end = Date.parse(certificate.notAfter);
    if (Number.isFinite(start) && Number.isFinite(end)) {
      const lifetimeDays = Math.round((end - start) / 86_400_000);
      if (lifetimeDays > 825 && publicKeyClassification?.quantumStatus === 'QUANTUM_VULNERABLE') {
        findings.push({
          ruleId: 'QGH-CERT-002',
          title: `Long-lived quantum-vulnerable certificate (${Math.round(lifetimeDays / 365)} year lifetime)`,
          detail: `The certificate is valid for ${lifetimeDays} days with a ${publicKeyClassification.canonicalName} key. A long lifetime raises the migration priority: the key remains in service across more of the pre-quantum window, and it cannot be rotated to a post-quantum algorithm without re-issuance.`,
          severity: 'medium',
        });
      }
    }
  }

  /* ── self-signed ──────────────────────────────────────────────────────── */
  if (certificate.selfSigned && !certificate.isCa) {
    findings.push({
      ruleId: 'QGH-CERT-003',
      title: 'Self-signed certificate',
      detail: 'The subject and issuer are identical and the certificate is not a CA. Clients cannot establish a trust path to it, so verification must have been disabled somewhere for it to be usable.',
      severity: 'medium',
    });
  }

  /* ── key usage consistency ────────────────────────────────────────────── */
  if (certificate.keyUsage.length > 0 && certificate.publicKey.algorithm) {
    const signs = certificate.keyUsage.includes('digitalSignature') || certificate.keyUsage.includes('keyCertSign');
    const agrees = certificate.keyUsage.includes('keyAgreement');
    const algorithm = certificate.publicKey.algorithm;

    /* Ed25519 cannot do key agreement; X25519 cannot sign. A certificate that
       claims otherwise is misissued, and the curve is the harder fact. */
    if (agrees && (algorithm === 'Ed25519' || algorithm === 'Ed448')) {
      findings.push({
        ruleId: 'QGH-CRYPTO-ECC-003',
        title: `keyAgreement asserted for an ${algorithm} key`,
        detail: `${algorithm} is a signature algorithm and cannot perform key agreement. The keyUsage extension asserts a capability the key does not have.`,
        severity: 'low',
      });
    }
    if (signs && (algorithm === 'X25519' || algorithm === 'X448')) {
      findings.push({
        ruleId: 'QGH-CRYPTO-ECC-003',
        title: `digitalSignature asserted for an ${algorithm} key`,
        detail: `${algorithm} performs key agreement only and cannot sign.`,
        severity: 'low',
      });
    }
  }

  return {
    certificate,
    publicKeyClassification,
    signatureClassification,
    findings,
    daysUntilExpiry,
    inferredPurpose,
  };
}

/* ══════════════════════════════════════════════════════════════ PEM decode ══ */

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_INDEX = (() => {
  const map = new Int16Array(128).fill(-1);
  for (let index = 0; index < B64_ALPHABET.length; index += 1) map[B64_ALPHABET.charCodeAt(index)] = index;
  return map;
})();

/**
 * Decode standard base64 to bytes.
 *
 * Hand-rolled rather than `atob` or `Buffer` because this module is isomorphic:
 * it runs in the browser worker for LOCAL scans and on the server for DEV ones.
 */
export function decodeBase64(input: string): Uint8Array | null {
  const clean = input.replace(/[\s\r\n]/g, '').replace(/=+$/, '');
  if (!clean) return null;
  const output = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let outIndex = 0;
  let buffer = 0;
  let bits = 0;

  for (let index = 0; index < clean.length; index += 1) {
    const code = clean.charCodeAt(index);
    const value = code < 128 ? B64_INDEX[code] : -1;
    if (value < 0) return null;
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output[outIndex] = (buffer >> bits) & 0xff;
      outIndex += 1;
    }
  }
  return output.subarray(0, outIndex);
}

export const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;

/** Parse every certificate in a PEM bundle, in order (leaf first, by convention). */
export function parsePemBundle(content: string): Array<{ label: string; line: number; certificate: ParsedCertificate }> {
  const out: Array<{ label: string; line: number; certificate: ParsedCertificate }> = [];
  PEM_BLOCK.lastIndex = 0;
  let block: RegExpExecArray | null;

  while ((block = PEM_BLOCK.exec(content)) !== null) {
    const label = block[1];
    if (label !== 'CERTIFICATE' && label !== 'PUBLIC KEY' && label !== 'CERTIFICATE REQUEST') continue;
    const line = content.slice(0, block.index).split('\n').length;
    const der = decodeBase64(block[2]);
    if (!der) continue;
    out.push({ label, line, certificate: parseCertificate(der) });
  }

  return out;
}

/* ════════════════════════════════════════════════════════ chain assessment ══ */

export interface ChainAssessment {
  depth: number;
  /** True when the last certificate is self-signed (a root). */
  reachesRoot: boolean;
  /** The weakest link, which is what actually governs the chain's security. */
  weakestSignature: { index: number; algorithm: string; hash: string | null } | null;
  findings: CertificateFinding[];
}

/**
 * Assess a certificate chain (§22).
 *
 * The governing insight: a chain is only as strong as its WEAKEST signature. A
 * leaf with an ML-DSA key signed by a SHA-1 intermediate is not protected by
 * the leaf's algorithm, and reporting only the leaf hides that.
 */
export function assessChain(chain: ParsedCertificate[]): ChainAssessment {
  const findings: CertificateFinding[] = [];
  let weakest: ChainAssessment['weakestSignature'] = null;

  const hashRank: Record<string, number> = { MD5: 0, 'SHA-1': 1, 'SHA-224': 2, 'SHA-256': 3, 'SHA-384': 4, 'SHA-512': 5, SHAKE256: 5 };

  chain.forEach((certificate, index) => {
    const hash = certificate.signature.hash;
    if (!certificate.signature.algorithm) return;
    const rank = hash ? (hashRank[hash] ?? 3) : 3;
    const currentRank = weakest?.hash ? (hashRank[weakest.hash] ?? 3) : weakest ? 3 : 99;
    if (rank < currentRank) {
      weakest = { index, algorithm: certificate.signature.algorithm, hash };
    }
  });

  const reachesRoot = chain.length > 0 && chain[chain.length - 1].selfSigned === true;

  if (chain.length > 1 && !reachesRoot) {
    findings.push({
      ruleId: 'QGH-PKI-001',
      title: 'Certificate chain does not reach a self-signed root',
      detail: `The presented chain has ${chain.length} certificates and the last is not self-signed. Either an intermediate is missing — which causes validation failures on clients that do not fetch it — or the root is intentionally omitted because it is in the client trust store.`,
      severity: 'low',
    });
  }

  if (weakest !== null) {
    const link = weakest as NonNullable<ChainAssessment['weakestSignature']>;
    if (link.hash === 'SHA-1' || link.hash === 'MD5') {
      findings.push({
        ruleId: 'QGH-CERT-001',
        title: `Chain contains a ${link.hash} signature at position ${link.index}`,
        detail: `A chain is only as strong as its weakest signature. Position ${link.index} is signed with ${link.algorithm}-${link.hash}, so the whole path inherits that weakness regardless of the leaf's own algorithm.`,
        severity: 'critical',
      });
    }
  }

  return { depth: chain.length, reachesRoot, weakestSignature: weakest, findings };
}
