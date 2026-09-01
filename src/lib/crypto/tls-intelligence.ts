/**
 * TLS Intelligence Engine™ (§18, §19, §20, §21).
 *
 * §19 states the requirement precisely:
 *
 *   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 … Do not classify the entire cipher
 *    suite as simply 'vulnerable.' Identify which component creates the quantum
 *    exposure."
 *
 * A cipher suite is four independent cryptographic decisions wearing one name.
 * In the example above the AES-256-GCM bulk cipher is quantum-RESISTANT and the
 * SHA-384 MAC is quantum-resistant; the ECDHE key exchange and the RSA
 * authentication are what a quantum computer breaks. Reporting the suite as
 * "vulnerable" is technically true and operationally useless — it does not say
 * what to change.
 *
 * This module decomposes a suite into its four parts, classifies each
 * independently through the knowledge base, and names the part that carries the
 * exposure.
 *
 * TLS 1.3 is a genuinely different grammar (§20): `TLS_AES_256_GCM_SHA384`
 * names only the AEAD and hash, because the key exchange is negotiated
 * separately through the supported_groups extension. A parser that applies the
 * TLS 1.2 grammar to a 1.3 suite reads "AES" as the key exchange — which is how
 * a hybrid post-quantum endpoint ends up scored as classical.
 */

import { classify, findAlgorithm, findCurve, type CryptoClassification, type CurveDefinition } from './knowledge-base';

/* ══════════════════════════════════════════════════════════ suite anatomy ══ */

export interface SuiteComponent {
  /** The primitive as it appears in the suite name. */
  observed: string;
  classification: CryptoClassification;
}

export interface TlsSuiteAnatomy {
  suite: string;
  /** The TLS version whose grammar was applied. */
  grammar: 'tls13' | 'tls12' | 'unknown';
  keyExchange: SuiteComponent | null;
  authentication: SuiteComponent | null;
  bulk: SuiteComponent | null;
  mac: SuiteComponent | null;
  /**
   * Forward secrecy, or null when the suite does not determine it.
   *
   * `null` is not "no". A TLS 1.3 suite name carries no key exchange, so
   * forward secrecy is determined by the negotiated group, not by the suite —
   * and rendering that null as "not forward secret" is a fabricated verdict.
   */
  forwardSecrecy: boolean | null;
  /**
   * Which component creates the quantum exposure (§19). Empty when none does.
   */
  quantumExposureFrom: Array<'key-exchange' | 'authentication' | 'bulk' | 'mac'>;
  /** One sentence naming the exposure, for the UI. */
  quantumSummary: string;
  /** True when the suite itself is broken or disallowed, classically. */
  classicallyBroken: boolean;
  classicalSummary: string;
}

/* ── vocabularies ────────────────────────────────────────────────────────── */

const KEX_TOKENS: Array<[RegExp, string]> = [
  [/^ECDHE$|^EECDH$/, 'ECDHE'],
  [/^ECDH$/, 'ECDH'],
  [/^DHE$|^EDH$/, 'DHE'],
  [/^DH$/, 'DH'],
  [/^RSA$/, 'RSA'],
  [/^PSK$/, 'PSK'],
  [/^SRP$/, 'SRP'],
  [/^KRB5$/, 'Kerberos'],
];

const AUTH_TOKENS: Array<[RegExp, string]> = [
  [/^RSA$/, 'RSA'],
  [/^ECDSA$/, 'ECDSA'],
  [/^DSS$|^DSA$/, 'DSA'],
  [/^EDDSA$/, 'Ed25519'],
  [/^PSK$/, 'PSK'],
  [/^ANON$/, 'anonymous'],
];

const BULK_TOKENS: Array<[RegExp, string]> = [
  [/CHACHA20[-_]?POLY1305/, 'ChaCha20-Poly1305'],
  [/AES[-_]?256[-_]?GCM/, 'AES-256-GCM'],
  [/AES[-_]?128[-_]?GCM/, 'AES-128-GCM'],
  [/AES[-_]?256[-_]?CCM/, 'AES-256-CCM'],
  [/AES[-_]?128[-_]?CCM/, 'AES-128-CCM'],
  [/AES[-_]?256[-_]?CBC/, 'AES-256-CBC'],
  [/AES[-_]?128[-_]?CBC/, 'AES-128-CBC'],
  [/CAMELLIA[-_]?256/, 'Camellia-256'],
  [/CAMELLIA[-_]?128/, 'Camellia-128'],
  [/AES[-_]?256/, 'AES-256'],
  [/AES[-_]?128/, 'AES-128'],
  [/3DES[-_]?EDE|DES[-_]?EDE3|3DES/, '3DES'],
  [/\bSEED\b/, 'SEED'],
  [/\bIDEA\b/, 'IDEA'],
  [/\bRC4\b/, 'RC4'],
  [/\bDES\b/, 'DES'],
  [/\bNULL\b/, 'NULL'],
];

const MAC_TOKENS: Array<[RegExp, string]> = [
  [/SHA384/, 'SHA-384'],
  [/SHA256/, 'SHA-256'],
  [/SHA512/, 'SHA-512'],
  [/POLY1305/, 'Poly1305'],
  [/\bSHA\b|SHA1/, 'SHA-1'],
  [/\bMD5\b/, 'MD5'],
];

function matchFirst(text: string, table: Array<[RegExp, string]>): string | null {
  for (const [pattern, label] of table) if (pattern.test(text)) return label;
  return null;
}

/**
 * TLS 1.3 suites, by their registered names.
 *
 * Matched by an explicit list rather than by "starts with TLS_AES", because
 * `TLS_RSA_WITH_AES_128_GCM_SHA256` also contains "AES" and is emphatically a
 * TLS 1.2 suite with static RSA key transport and no forward secrecy at all.
 */
const TLS13_SUITES = new Set([
  'TLS_AES_128_GCM_SHA256',
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',
  'TLS_AES_128_CCM_SHA256',
  'TLS_AES_128_CCM_8_SHA256',
]);

/* ══════════════════════════════════════════════════════════ decomposition ══ */

function component(observed: string | null, role: Parameters<typeof classify>[0]['declaredRole'], context: string): SuiteComponent | null {
  if (!observed) return null;
  return {
    observed,
    classification: classify({ algorithm: observed, declaredRole: role, context, protocol: 'TLS' }),
  };
}

/**
 * Decompose a cipher suite name into its independent cryptographic parts.
 *
 * Returns null when the string is not a recognisable suite, rather than
 * guessing — §90 prefers UNKNOWN to a fabricated answer.
 */
export function decomposeSuite(suiteName: string, negotiatedGroup?: string | null): TlsSuiteAnatomy | null {
  const suite = suiteName.trim().toUpperCase().replace(/-/g, '_');
  if (!suite.startsWith('TLS_') && !suite.startsWith('SSL_')) return null;

  const bulkToken = matchFirst(suite, BULK_TOKENS);
  const macToken = matchFirst(suite, MAC_TOKENS);

  /* ── TLS 1.3 grammar (§20) ────────────────────────────────────────────── */
  if (TLS13_SUITES.has(suite) || (!suite.includes('_WITH_') && suite.startsWith('TLS_'))) {
    const group = negotiatedGroup ? classifyGroup(negotiatedGroup) : null;

    const anatomy: TlsSuiteAnatomy = {
      suite: suiteName,
      grammar: 'tls13',
      /* The key exchange is NOT in the suite name. When the caller supplied the
         negotiated group we can name it; otherwise it is genuinely unknown from
         this string alone, and saying so is the honest answer. */
      keyExchange: group
        ? { observed: negotiatedGroup!, classification: group.classification }
        : null,
      authentication: null,
      bulk: component(bulkToken, 'authenticated-encryption', `TLS 1.3 bulk cipher in ${suiteName}`),
      mac: component(macToken, 'integrity', `TLS 1.3 handshake hash in ${suiteName}`),
      /* TLS 1.3 removed every non-ephemeral key exchange, so a completed 1.3
         handshake has forward secrecy by construction. */
      forwardSecrecy: true,
      quantumExposureFrom: [],
      quantumSummary: '',
      classicallyBroken: false,
      classicalSummary: '',
    };

    if (group?.classification.quantumStatus === 'QUANTUM_VULNERABLE') {
      anatomy.quantumExposureFrom.push('key-exchange');
      anatomy.quantumSummary = `The bulk cipher (${bulkToken ?? 'unknown'}) and handshake hash are quantum-resistant. The exposure is the ${negotiatedGroup} key-agreement group, which Shor's algorithm breaks — a recorded handshake can be decrypted retrospectively once a cryptographically relevant quantum computer exists.`;
    } else if (group?.classification.quantumStatus === 'HYBRID' || group?.classification.quantumStatus === 'PQC_STANDARDIZED') {
      anatomy.quantumSummary = `The negotiated group ${negotiatedGroup} is ${group.classification.quantumStatus === 'HYBRID' ? 'hybrid post-quantum' : 'post-quantum'}, and the bulk cipher is quantum-resistant. This handshake has no known quantum exposure.`;
    } else {
      anatomy.quantumSummary = `The bulk cipher (${bulkToken ?? 'unknown'}) is quantum-resistant. TLS 1.3 negotiates its key exchange separately, so the quantum exposure of this connection is determined by the supported_groups extension, which this suite name does not carry.`;
    }

    anatomy.classicalSummary = `TLS 1.3 with ${bulkToken ?? 'an unnamed AEAD'}; all TLS 1.3 suites are AEAD and forward-secret by construction.`;
    return anatomy;
  }

  /* ── TLS 1.2 and earlier grammar (§19) ────────────────────────────────── */
  const withIndex = suite.indexOf('_WITH_');
  if (withIndex < 0) return null;

  const head = suite.slice(4, withIndex);
  const parts = head.split('_').filter(Boolean);

  let kexToken: string | null = null;
  let authToken: string | null = null;

  if (parts.length === 1) {
    /* `TLS_RSA_WITH_...` is RSA KEY TRANSPORT: RSA is both the exchange and the
       authentication, and there is no ephemeral secret. This is the case most
       often mis-read as "ECDHE-like RSA". */
    kexToken = matchFirst(parts[0], KEX_TOKENS);
    authToken = kexToken === 'RSA' ? 'RSA' : matchFirst(parts[0], AUTH_TOKENS);
  } else {
    kexToken = matchFirst(parts[0], KEX_TOKENS);
    authToken = matchFirst(parts.slice(1).join('_'), AUTH_TOKENS) ?? matchFirst(parts[1] ?? '', AUTH_TOKENS);
  }

  const anonymous = head.includes('ANON') || head.includes('_anon');
  const ephemeral = kexToken === 'ECDHE' || kexToken === 'DHE';

  const anatomy: TlsSuiteAnatomy = {
    suite: suiteName,
    grammar: 'tls12',
    keyExchange: component(kexToken, kexToken === 'RSA' ? 'key-transport' : 'key-establishment', `TLS key exchange in ${suiteName}`),
    authentication: anonymous ? null : component(authToken, 'authentication', `TLS server authentication in ${suiteName}`),
    bulk: component(bulkToken, bulkToken?.includes('GCM') || bulkToken?.includes('CCM') || bulkToken?.includes('POLY') ? 'authenticated-encryption' : 'encryption', `TLS bulk cipher in ${suiteName}`),
    mac: component(macToken, 'integrity', `TLS MAC in ${suiteName}`),
    forwardSecrecy: ephemeral,
    quantumExposureFrom: [],
    quantumSummary: '',
    classicallyBroken: false,
    classicalSummary: '',
  };

  /* ── which component carries the quantum exposure (§19) ───────────────── */
  const resistant: string[] = [];
  if (anatomy.keyExchange?.classification.quantumStatus === 'QUANTUM_VULNERABLE') anatomy.quantumExposureFrom.push('key-exchange');
  if (anatomy.authentication?.classification.quantumStatus === 'QUANTUM_VULNERABLE') anatomy.quantumExposureFrom.push('authentication');
  if (anatomy.bulk?.classification.quantumStatus === 'QUANTUM_RESISTANT') resistant.push(anatomy.bulk.observed);
  if (anatomy.mac?.classification.quantumStatus === 'QUANTUM_RESISTANT') resistant.push(anatomy.mac.observed);

  anatomy.quantumSummary = anatomy.quantumExposureFrom.length
    ? `${resistant.length ? `The symmetric components (${resistant.join(', ')}) are quantum-resistant. ` : ''}The exposure is the ${anatomy.quantumExposureFrom
        .map((part) => (part === 'key-exchange' ? `${kexToken} key exchange` : `${authToken} authentication`))
        .join(' and the ')}, which Shor's algorithm breaks.${
        ephemeral
          ? ' Ephemeral key exchange gives forward secrecy against a classical adversary but does NOT protect against harvest-now-decrypt-later: a recorded handshake yields the session key to a future quantum computer.'
          : ''
      }`
    : 'No quantum-vulnerable component was identified in this suite.';

  /* ── classical verdict ────────────────────────────────────────────────── */
  const brokenParts: string[] = [];
  if (bulkToken === 'NULL') brokenParts.push('NULL encryption provides no confidentiality');
  if (bulkToken === 'RC4') brokenParts.push('RC4 keystream biases are practically exploitable (RFC 7465 prohibits it)');
  if (bulkToken === 'DES') brokenParts.push('DES has a 56-bit key and is exhaustively searchable');
  if (bulkToken === '3DES') brokenParts.push('3DES has a 64-bit block and is subject to Sweet32');
  if (macToken === 'MD5') brokenParts.push('MD5 is collision-broken');
  if (anonymous) brokenParts.push('anonymous key exchange provides no authentication, so the channel is trivially interceptable');
  if (!ephemeral && kexToken === 'RSA') brokenParts.push('static RSA key transport provides no forward secrecy, so one compromised private key decrypts every recorded session');

  anatomy.classicallyBroken = brokenParts.length > 0;
  anatomy.classicalSummary = brokenParts.length
    ? brokenParts.join('; ') + '.'
    : `${kexToken ?? 'unknown'} key exchange with ${authToken ?? 'unspecified'} authentication, ${bulkToken ?? 'unknown'} encryption and ${macToken ?? 'unknown'} MAC. No classical break identified.`;

  return anatomy;
}

/* ══════════════════════════════════════════════════════ key-agreement groups ═ */

export interface GroupClassification {
  group: string;
  curve: CurveDefinition | null;
  /** True when the group combines a classical and a post-quantum primitive. */
  hybrid: boolean;
  classification: CryptoClassification;
}

/**
 * Classify a TLS named group (§20, §21).
 *
 * The hybrid names are the part that matters. `X25519MLKEM768` is one group
 * that performs both an X25519 exchange and an ML-KEM-768 encapsulation, and
 * treating it as "X25519" — which a curve lookup alone does — reports the
 * customer's completed post-quantum work as a classical exposure.
 */
export function classifyGroup(groupName: string): GroupClassification {
  const raw = groupName.trim();
  const upper = raw.toUpperCase().replace(/[-_]/g, '');

  const pqcMarker = /MLKEM|KYBER|SNTRUP|BIKE|HQC|FRODO/.test(upper);
  const classicalMarker = /X25519|X448|SECP|P256|P384|P521|FFDHE|BRAINPOOL/.test(upper);
  const hybrid = pqcMarker && classicalMarker;

  if (hybrid) {
    const pqcPart = upper.includes('MLKEM') || upper.includes('KYBER') ? 'ML-KEM' : upper.includes('SNTRUP') ? 'sntrup761' : 'post-quantum KEM';
    const classicalPart = upper.includes('X25519') ? 'X25519' : upper.includes('X448') ? 'X448' : upper.match(/SECP\d+R1|P\d{3}/)?.[0] ?? 'an elliptic curve';
    return {
      group: raw,
      curve: findCurve(classicalPart),
      hybrid: true,
      classification: classify({
        algorithm: pqcPart,
        declaredRole: 'key-establishment',
        protocol: 'TLS',
        hybridPartner: classicalPart,
        context: `TLS named group ${raw}`,
      }),
    };
  }

  if (pqcMarker) {
    return {
      group: raw,
      curve: null,
      hybrid: false,
      classification: classify({
        algorithm: upper.includes('MLKEM') || upper.includes('KYBER') ? 'ML-KEM' : raw,
        declaredRole: 'key-establishment',
        protocol: 'TLS',
        context: `TLS named group ${raw}`,
      }),
    };
  }

  const curve = findCurve(raw);
  if (curve) {
    return {
      group: raw,
      curve,
      hybrid: false,
      classification: classify({
        algorithm: curve.family === 'montgomery' ? 'X25519' : 'ECDH',
        curve: curve.canonicalName,
        declaredRole: 'key-establishment',
        protocol: 'TLS',
        context: `TLS named group ${raw}`,
      }),
    };
  }

  /* Finite-field groups: ffdhe2048 … ffdhe8192. */
  const ffdhe = upper.match(/FFDHE(\d{4})/);
  if (ffdhe) {
    return {
      group: raw,
      curve: null,
      hybrid: false,
      classification: classify({
        algorithm: 'Diffie-Hellman',
        keySize: Number(ffdhe[1]),
        declaredRole: 'key-establishment',
        protocol: 'TLS',
        context: `TLS named group ${raw}`,
      }),
    };
  }

  return {
    group: raw,
    curve: null,
    hybrid: false,
    classification: classify({ algorithm: raw, declaredRole: 'key-establishment', protocol: 'TLS', context: `TLS named group ${raw}` }),
  };
}

/* ══════════════════════════════════════════════════════ protocol assessment ═ */

export interface TlsProtocolAssessment {
  version: string;
  deprecated: boolean;
  /** True when this version can carry a hybrid post-quantum group. */
  pqcCapable: boolean;
  summary: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

/** Assess one offered protocol version (§18). */
export function assessProtocol(version: string): TlsProtocolAssessment {
  const normalised = version.trim().toUpperCase().replace(/\s+/g, '');

  if (/SSLV2|SSL2/.test(normalised)) {
    return { version, deprecated: true, pqcCapable: false, severity: 'critical', summary: 'SSL 2.0 is broken (DROWN) and must not be offered.' };
  }
  if (/SSLV3|SSL3/.test(normalised)) {
    return { version, deprecated: true, pqcCapable: false, severity: 'critical', summary: 'SSL 3.0 is broken (POODLE) and must not be offered.' };
  }
  if (/TLSV?1(\.0)?$/.test(normalised)) {
    return {
      version,
      deprecated: true,
      pqcCapable: false,
      severity: 'high',
      summary: 'TLS 1.0 is deprecated by RFC 8996. It also cannot negotiate a hybrid post-quantum group, so it is a migration blocker as well as a present-tense weakness.',
    };
  }
  if (/TLSV?1\.1/.test(normalised)) {
    return {
      version,
      deprecated: true,
      pqcCapable: false,
      severity: 'high',
      summary: 'TLS 1.1 is deprecated by RFC 8996 and cannot negotiate a hybrid post-quantum group.',
    };
  }
  if (/TLSV?1\.2/.test(normalised)) {
    return {
      version,
      deprecated: false,
      pqcCapable: false,
      severity: 'info',
      summary: 'TLS 1.2 is current and acceptable. Hybrid post-quantum key agreement is only defined for TLS 1.3, so a 1.2-only endpoint cannot adopt it without a protocol upgrade.',
    };
  }
  if (/TLSV?1\.3/.test(normalised)) {
    return {
      version,
      deprecated: false,
      pqcCapable: true,
      severity: 'info',
      summary: 'TLS 1.3 is current and is the prerequisite for hybrid post-quantum key agreement.',
    };
  }

  return { version, deprecated: false, pqcCapable: false, severity: 'info', summary: `Protocol version "${version}" was not recognised, so no verdict is published for it.` };
}

/* ══════════════════════════════════════════════════════ endpoint assessment ═ */

export interface TlsEndpointObservation {
  protocols: string[];
  negotiatedProtocol?: string | null;
  cipherSuites: string[];
  negotiatedSuite?: string | null;
  supportedGroups?: string[];
  negotiatedGroup?: string | null;
  signatureAlgorithms?: string[];
}

export interface TlsEndpointAssessment {
  protocols: TlsProtocolAssessment[];
  suites: TlsSuiteAnatomy[];
  groups: GroupClassification[];
  /** True when the endpoint can negotiate a hybrid post-quantum exchange. */
  hybridCapable: boolean;
  /** True when it actually DID. Configuration is intent; negotiation is fact. */
  hybridNegotiated: boolean;
  /** Which component carries the quantum exposure, across the whole endpoint. */
  quantumExposure: string;
  /** Everything the observation did not determine (§90). */
  undetermined: string[];
}

/**
 * Assess a whole endpoint observation.
 *
 * The distinction the summary turns on: OFFERING a hybrid group and
 * NEGOTIATING one are different facts. A configuration lists intent; a
 * completed handshake is evidence. §46 requires the difference be visible.
 */
export function assessTlsEndpoint(observation: TlsEndpointObservation): TlsEndpointAssessment {
  const undetermined: string[] = [];

  const protocols = observation.protocols.map(assessProtocol);
  const groups = (observation.supportedGroups ?? []).map(classifyGroup);
  const negotiatedGroupClassification = observation.negotiatedGroup ? classifyGroup(observation.negotiatedGroup) : null;

  const suites = observation.cipherSuites
    .map((suite) => decomposeSuite(suite, observation.negotiatedGroup))
    .filter((entry): entry is TlsSuiteAnatomy => entry !== null);

  if (observation.cipherSuites.length > suites.length) {
    undetermined.push(`${observation.cipherSuites.length - suites.length} cipher suite name(s) this parser does not recognise`);
  }
  if (!observation.supportedGroups?.length && !observation.negotiatedGroup) {
    undetermined.push('the key-agreement groups (supported_groups was not observed)');
  }
  if (!observation.negotiatedProtocol) undetermined.push('the negotiated protocol version');

  const hybridCapable = groups.some((group) => group.hybrid);
  const hybridNegotiated = negotiatedGroupClassification?.hybrid === true;

  let quantumExposure: string;
  if (hybridNegotiated) {
    quantumExposure = `The endpoint NEGOTIATED ${observation.negotiatedGroup}, a hybrid post-quantum group. Key agreement on this connection is not exposed to a future quantum computer. Certificate signatures remain classical until the CA ecosystem migrates.`;
  } else if (hybridCapable) {
    quantumExposure = `The endpoint OFFERS a hybrid post-quantum group but did not negotiate one for this connection — the client did not propose it, or preference ordering selected a classical group. Offering is intent; negotiation is what protects the session.`;
  } else if (negotiatedGroupClassification) {
    quantumExposure = `Key agreement used ${observation.negotiatedGroup}, which Shor's algorithm breaks. The symmetric components of the connection are quantum-resistant; the exposure is the key exchange, and it is retrospective — a recorded handshake can be decrypted later.`;
  } else {
    quantumExposure = 'The key-agreement group was not observed, so no quantum verdict is published for this endpoint\'s key exchange.';
  }

  return { protocols, suites, groups, hybridCapable, hybridNegotiated, quantumExposure, undetermined };
}

/* ─────────────────────────────────────────────────────── OpenSSL cipher list ─ */

/**
 * Interpret an OpenSSL cipher-list string.
 *
 * The `!` prefix EXCLUDES — `HIGH:!aNULL:!MD5` permits neither anonymous key
 * exchange nor MD5. A scanner that greps for "MD5" in that string reports the
 * exact opposite of what the configuration says, which is a false positive this
 * codebase has shipped before.
 */
export function parseOpenSslCipherList(list: string): { permitted: string[]; excluded: string[] } {
  const permitted: string[] = [];
  const excluded: string[] = [];

  for (const token of list.split(/[:,\s]+/)) {
    const trimmed = token.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('!') || trimmed.startsWith('-')) excluded.push(trimmed.slice(1));
    else if (trimmed.startsWith('+')) permitted.push(trimmed.slice(1));
    else permitted.push(trimmed);
  }

  return { permitted, excluded };
}

/** True when an OpenSSL cipher list actually permits a token. */
export function cipherListPermits(list: string, token: string): boolean {
  const { permitted, excluded } = parseOpenSslCipherList(list);
  const needle = token.toUpperCase();
  if (excluded.some((entry) => entry.toUpperCase() === needle)) return false;
  return permitted.some((entry) => entry.toUpperCase().includes(needle));
}

/* ────────────────────────────────────────────────────────── SSH algorithms ── */

/**
 * SSH key-exchange and cipher assessment (§31).
 *
 * SSH is worth its own path because its algorithm names are unlike TLS's and
 * because OpenSSH shipped hybrid post-quantum key exchange
 * (`sntrup761x25519-sha512`) years before the TLS ecosystem — an endpoint can
 * be post-quantum for SSH and classical for TLS, and a scanner that only knows
 * TLS names would miss it.
 */
export interface SshAlgorithmAssessment {
  algorithm: string;
  kind: 'kex' | 'cipher' | 'mac' | 'hostkey';
  classification: CryptoClassification;
  weak: boolean;
  reason: string;
}

const WEAK_SSH_KEX = /diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|gss-group1/;
const WEAK_SSH_CIPHER = /3des-cbc|arcfour|blowfish-cbc|cast128-cbc|des-cbc|rijndael-cbc/;
const WEAK_SSH_MAC = /hmac-md5|hmac-sha1-96|hmac-md5-96|umac-64(?!-etm)/;

export function assessSshAlgorithm(name: string, kind: SshAlgorithmAssessment['kind']): SshAlgorithmAssessment {
  const lower = name.trim().toLowerCase();

  /* Hybrid post-quantum SSH key exchange. */
  if (/sntrup761x25519|mlkem768x25519|x25519-kyber/.test(lower)) {
    return {
      algorithm: name,
      kind,
      classification: classify({
        algorithm: lower.includes('sntrup') ? 'sntrup761' : 'ML-KEM',
        declaredRole: 'key-establishment',
        protocol: 'SSH',
        hybridPartner: 'x25519',
        context: `SSH key exchange ${name}`,
      }),
      weak: false,
      reason: 'Hybrid post-quantum key exchange. The session key is protected against a future quantum computer even if the handshake is recorded today.',
    };
  }

  const weak =
    (kind === 'kex' && WEAK_SSH_KEX.test(lower)) ||
    (kind === 'cipher' && WEAK_SSH_CIPHER.test(lower)) ||
    (kind === 'mac' && WEAK_SSH_MAC.test(lower));

  const algorithmName =
    kind === 'kex'
      ? /curve25519/.test(lower) ? 'X25519' : /ecdh/.test(lower) ? 'ECDH' : /diffie-hellman/.test(lower) ? 'Diffie-Hellman' : name
      : kind === 'hostkey'
        ? /ed25519/.test(lower) ? 'Ed25519' : /ecdsa/.test(lower) ? 'ECDSA' : /rsa/.test(lower) ? 'RSA' : /dss|dsa/.test(lower) ? 'DSA' : name
        : kind === 'cipher'
          ? /chacha20/.test(lower) ? 'ChaCha20-Poly1305' : /aes/.test(lower) ? (lower.includes('256') ? 'AES-256' : 'AES-128') : /3des/.test(lower) ? '3DES' : name
          : /sha2-512|sha512/.test(lower) ? 'SHA-512' : /sha2-256|sha256/.test(lower) ? 'SHA-256' : /sha1/.test(lower) ? 'SHA-1' : /md5/.test(lower) ? 'MD5' : name;

  const role = kind === 'kex' ? 'key-establishment' : kind === 'hostkey' ? 'authentication' : kind === 'cipher' ? 'encryption' : 'integrity';

  return {
    algorithm: name,
    kind,
    classification: classify({ algorithm: algorithmName, declaredRole: role, protocol: 'SSH', context: `SSH ${kind} ${name}` }),
    weak,
    reason: weak
      ? kind === 'kex'
        ? 'This key exchange uses SHA-1 or a 1024-bit group, both of which are below current guidance.'
        : kind === 'cipher'
          ? 'This cipher is legacy: a 64-bit block or a broken stream cipher.'
          : 'This MAC uses a broken or truncated digest.'
      : `${algorithmName} is acceptable for ${kind}.`,
  };
}

/** Every group name this module recognises, for capability disclosure. */
export function knownGroupPatterns(): string[] {
  return [
    'x25519', 'x448', 'secp256r1 / P-256', 'secp384r1 / P-384', 'secp521r1 / P-521',
    'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1',
    'ffdhe2048', 'ffdhe3072', 'ffdhe4096', 'ffdhe6144', 'ffdhe8192',
    'X25519MLKEM768 (hybrid)', 'SecP256r1MLKEM768 (hybrid)', 'x25519_kyber768 (hybrid, draft)',
    'sntrup761x25519-sha512 (SSH hybrid)',
  ];
}
