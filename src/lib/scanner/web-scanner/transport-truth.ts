/**
 * Transport truth — ONE reconciled reading of a target's TLS observation.
 *
 * ── The defect this module exists to remove ─────────────────────────────────
 *
 * A single scan of `test.openquantumsafe.org` published all of this at once:
 *
 *   Observed Attack Surface   TLS Version: TLSv1.3
 *   Observed Attack Surface   Forward Secrecy: Not offered          (red)
 *   Cryptographic Intelligence Forward Secrecy: Not observed
 *   Score decomposition       Forward Secrecy: 100 · "ECDHE (TLS 1.3 key_share)"
 *   Post-Quantum Key Agreement Unknown — "No TLS handshake completed"
 *   Observed Algorithms       ECDHE, AES-256-GCM, TLSv1.3 (observed)
 *
 * Three different answers for forward secrecy, and a claim that no handshake
 * completed printed beside the protocol, cipher suite, certificate chain and
 * validity that only a completed handshake can produce.
 *
 * ── Why it happened ─────────────────────────────────────────────────────────
 *
 * Two engines observe the same endpoint:
 *
 *   the SOCKET analyser   one `tls.connect()`. Gets protocol, suite, chain,
 *                         validity. Cannot see the named group, because Node's
 *                         `getEphemeralKeyInfo()` returns `{}` for TLS 1.3.
 *   the EDGE prober       offers each named group in isolation, which costs one
 *                         handshake per group. Slow, and the first to time out.
 *
 * On this target the socket succeeded and the edge prober timed out. Three
 * panels then each did their own fallback arithmetic over the two results, with
 * three different chains — and `EdgeTransport.forwardSecrecy` is a plain
 * `boolean`, so a probe that never ran reported `false`, which reads as "this
 * endpoint has no forward secrecy". That is a fabricated negative: the strongest
 * possible claim, derived from no evidence at all.
 *
 * ── The rule ────────────────────────────────────────────────────────────────
 *
 * Every field here is TRI-STATE. `false` is only ever returned when something
 * was measured and found absent. Not measured is `null`, and carries the reason.
 * Panels render the reason; they never re-derive the verdict.
 *
 * Pure and dependency-free so the API, the dashboards and the check tools all
 * read the same reconciliation.
 */

import type { EdgeIntelligence } from './edge-intelligence';
import { hybridProbeSettled } from './edge-intelligence-model';
import type { MeasuredKeyAgreement } from './edge-intelligence-model';

/**
 * The subset of a TLS observation this module reads.
 *
 * Declared structurally rather than importing `TlsAnalysisResult`, because the
 * dashboard carries its own narrower `TlsAnalysis` (same fields, several
 * optional) and both must be able to call this. Casting one to the other at
 * each call site would defeat the point of having one reconciliation.
 */
export interface TlsObservation {
  tlsVersion?: string | null;
  cipherSuite?: string | null;
  keyExchange?: string | null;
  negotiatedCurve?: string | null;
  ephemeralKeyType?: string | null;
  cipherSuites?: Array<{ name?: string; category?: string }> | null;
  /**
   * Versions the endpoint accepted when each was offered alone.
   *
   * Read for hybrid COVERAGE: a pre-1.3 version the endpoint still accepts is a
   * path no TLS 1.3 hybrid group can reach. The socket analyser probes these
   * per version, so it answers even when the edge prober did not run.
   */
  supportedProtocols?: string[] | null;
}

/* ────────────────────────────────────────────────────── static RSA, once ──── */

/**
 * Is this suite static-RSA key transport?
 *
 * THE ONE PREDICATE. Static RSA is the most consequential fact on the transport
 * surface — such a suite has NO forward secrecy, so recorded sessions become
 * retroactively decryptable the moment the server key falls, and no hybrid key
 * agreement anywhere on the endpoint prevents it. It is therefore stated on
 * three separate panels, and every one of them must count the same suites.
 *
 * They did not. The Observed Attack Surface matched the suite NAME and the
 * parsed category; Transport & Ciphers matched only `keyExchange === 'RSA'`.
 * A suite the analyser named `TLS_RSA_WITH_…` but whose key exchange it left
 * blank was counted on one panel and not the other, so the page read
 * "Static RSA accepted" beside "Static RSA accepted: No".
 *
 * Note what is deliberately NOT here: `/(^|_)RSA_WITH/`. That substring also
 * occurs in `TLS_ECDHE_RSA_WITH_…`, where RSA is the server's AUTHENTICATION
 * and the key exchange is ephemeral ECDHE. Those sessions ARE forward secret.
 */
export function isStaticRsaSuite(suite: {
  name?: string | null;
  standardName?: string | null;
  category?: string | null;
  keyExchange?: string | null;
}): boolean {
  if ((suite.category ?? '').toLowerCase() === 'rsa-kex') return true;
  if (/^RSA$/i.test((suite.keyExchange ?? '').trim())) return true;
  return /^(TLS|SSL)_RSA_WITH/i.test(suite.standardName ?? suite.name ?? '');
}

/** Every static-RSA suite in an offered-suite enumeration. */
export function staticRsaSuites<T extends { name?: string | null; standardName?: string | null; category?: string | null; keyExchange?: string | null }>(
  suites: readonly T[] | null | undefined,
): T[] {
  return (suites ?? []).filter((suite) => isStaticRsaSuite(suite));
}

/* ─────────────────────────────────────────────────────────────── the shape ── */

/** A reading that can be true, false, or genuinely unmeasured. */
export interface Measured<T> {
  /** null = NOT MEASURED. Never a stand-in for a negative finding. */
  value: T | null;
  /** True when an engine actually determined this. */
  measured: boolean;
  /** Which engine established it, or why nothing did. */
  basis: string;
}

export type PqAgreementState =
  | 'hybrid'        // a hybrid group was accepted — measured
  | 'pq-only'       // standalone ML-KEM accepted — measured, no classical hedge
  | 'classical'     // groups were probed and none were post-quantum — measured
  | 'not-measured'; // the probe did not run or did not complete

export interface TransportTruth {
  /** Did ANY engine complete a TLS handshake with this endpoint? */
  handshakeCompleted: boolean;
  /** Which engines completed one — the honest basis for every field below. */
  handshakeSources: Array<'socket' | 'edge'>;
  /** Why no handshake completed. Empty when one did. */
  handshakeFailure: string;

  protocol: Measured<string>;
  cipherSuite: Measured<string>;
  keyExchange: Measured<string>;

  /**
   * Forward secrecy.
   *
   * TLS 1.3 removed every non-ephemeral key exchange from the protocol, so a
   * completed 1.3 handshake is forward secret BY CONSTRUCTION — no probe is
   * needed and none should be waited for. That single fact resolves most of the
   * disagreement this module was written to fix.
   */
  forwardSecrecy: Measured<boolean>;

  /** Static-RSA key transport still accepted, which caps forward secrecy. */
  staticRsaAccepted: Measured<boolean>;

  namedGroupProbed: boolean;
  postQuantum: {
    state: PqAgreementState;
    /** Display label: "Applied", "PQ-only", "Classical only", "Not measured". */
    label: string;
    /** The measured group, when one was established. */
    group: string | null;
    reason: string;
  };

  /**
   * Quantum exposure verdict.
   *
   * `null` when nothing quantum-relevant was observed AND nothing was probed.
   * Note that a completed handshake DOES license a verdict about what it
   * negotiated, even when named-group probing failed — the certificate's public
   * key and the handshake signature are quantum-relevant and were observed.
   *
   * `hybrid-partial` is the state a hybrid endpoint reaches when it ALSO
   * accepts a path the hybrid group does not cover. See
   * {@link TransportTruth.hybridCoverage}.
   */
  quantumVulnerability: Measured<'vulnerable' | 'hybrid' | 'hybrid-partial' | 'resistant'>;

  /**
   * Does the measured hybrid key agreement cover every path this endpoint will
   * accept?
   *
   * THE CONTRADICTION THIS FIELD REMOVES
   * ------------------------------------
   * A hybrid group protects the sessions that USE it. It does nothing for a
   * session an attacker forces onto static RSA key transport or onto TLS 1.0,
   * both of which this same reconciliation already measures — `forwardSecrecy`
   * is capped to "Partial" for exactly that reason. The quantum verdict did not
   * consult either, so one panel published
   *
   *   Forward secrecy      Partial
   *   Static RSA accepted  Yes · 4 suite(s)
   *   Protocols accepted   TLSv1 / TLSv1.1 / TLSv1.2 / TLSv1.3
   *
   * directly above another publishing "Quantum vulnerability: Hybrid-protected"
   * and "Harvest-now exposure: key agreement protected". Both were derived from
   * the same handshake. Recorded traffic on the static-RSA path is decryptable
   * the moment the server key falls, hybrid group or not.
   *
   * `false` means: hybrid measured, and at least one uncovered path measured
   * alongside it. `null` means coverage was not established either way.
   */
  hybridCoverage: Measured<boolean>;

  /** Every reconciliation the module had to make, for the disclosure panel. */
  notes: string[];
}

/* ────────────────────────────────────────────────────────────── helpers ───── */

const TLS13 = /^TLSv?1\.3$/i;

const EPHEMERAL_KEX = /ECDHE|DHE|X25519|X448|ML-?KEM|Kyber|key_share/i;

function unmeasured<T>(basis: string): Measured<T> {
  return { value: null, measured: false, basis };
}

function measured<T>(value: T, basis: string): Measured<T> {
  return { value, measured: true, basis };
}

/* ────────────────────────────────────────────────────────── the reconciler ── */

/**
 * Reconcile the socket analyser and the edge prober into one reading.
 *
 * Ordering matters and is deliberate: a field is taken from whichever engine
 * actually MEASURED it, never from whichever engine is checked first. Where
 * both measured it and they disagree, the disagreement is recorded in `notes`
 * rather than silently resolved — two engines contradicting each other about
 * the same endpoint is a finding in its own right.
 */
export function reconcileTransport(
  tls: TlsObservation | null | undefined,
  edge: EdgeIntelligence | null | undefined,
  kem?: MeasuredKeyAgreement | null,
): TransportTruth {
  const notes: string[] = [];
  const sources: Array<'socket' | 'edge'> = [];

  /* ── did a handshake happen at all? ─────────────────────────────────────── */

  /* The socket analyser only produces a protocol string when `tls.connect()`
     resolved. A default-shaped result with no protocol is a failure, not an
     observation of "unknown". */
  const socketProtocol = tls?.tlsVersion && tls.tlsVersion !== 'unknown' ? tls.tlsVersion : null;
  const socketHandshake = Boolean(socketProtocol);
  if (socketHandshake) sources.push('socket');

  const edgeTransport = edge?.transport ?? null;
  const edgeHandshake = Boolean(edgeTransport?.negotiatedProtocol);
  if (edgeHandshake) sources.push('edge');

  const handshakeCompleted = socketHandshake || edgeHandshake;

  /* The edge prober's own error must not be reported as "no handshake
     completed" when the socket analyser completed one. That message was the
     single most misleading string on the page: it appeared directly beneath a
     negotiated TLS 1.3 suite and a 5-certificate chain. */
  const edgeError = edgeTransport?.error ?? null;
  const handshakeFailure = handshakeCompleted
    ? ''
    : edgeError
      ? `No TLS handshake completed (${edgeError}).`
      : 'No TLS handshake completed.';

  if (socketHandshake && edgeError) {
    notes.push(
      `A TLS handshake completed and was measured, but the named-group probe did not finish (${edgeError}). ` +
        'Protocol, cipher suite and certificate facts below are measured; post-quantum key agreement is not.',
    );
  }

  /* ── protocol / suite / key exchange ────────────────────────────────────── */

  const protocol = socketProtocol
    ? measured(socketProtocol, 'negotiated in the socket handshake')
    : edgeTransport?.negotiatedProtocol
      ? measured(edgeTransport.negotiatedProtocol, 'negotiated in the edge handshake')
      : unmeasured<string>(handshakeFailure || 'No protocol was negotiated.');

  if (
    socketProtocol &&
    edgeTransport?.negotiatedProtocol &&
    socketProtocol.toLowerCase() !== edgeTransport.negotiatedProtocol.toLowerCase()
  ) {
    notes.push(
      `The socket handshake negotiated ${socketProtocol} while the edge handshake negotiated ${edgeTransport.negotiatedProtocol}. ` +
        'The endpoint may be behind a load balancer with mixed configuration.',
    );
  }

  const suiteValue = tls?.cipherSuite && tls.cipherSuite !== 'unknown' ? tls.cipherSuite : edgeTransport?.negotiatedCipher ?? null;
  const cipherSuite = suiteValue
    ? measured(suiteValue, 'negotiated in the handshake')
    : unmeasured<string>(handshakeFailure || 'No cipher suite was negotiated.');

  const kexValue = kem?.kemApplied && kem.group ? kem.group : tls?.keyExchange && tls.keyExchange !== 'unknown' ? tls.keyExchange : edgeTransport?.keyExchange || null;
  const keyExchange = kexValue
    ? measured(kexValue, kem?.kemApplied ? 'measured named group' : 'reported by the handshake')
    : unmeasured<string>(handshakeFailure || 'No key exchange was observed.');

  /* ── forward secrecy ────────────────────────────────────────────────────── */

  const isTls13 = Boolean(protocol.value && TLS13.test(protocol.value));

  const staticRsaSuites = (tls?.cipherSuites ?? []).filter(
    (suite) => suite.category === 'rsa-kex' || /^TLS_RSA_WITH/i.test(suite.name ?? ''),
  );
  const staticRsaAccepted: Measured<boolean> = staticRsaSuites.length > 0
    ? measured(true, `${staticRsaSuites.length} static-RSA key-transport suite(s) enumerated`)
    : edgeTransport?.staticRsaAccepted === true
      ? measured(true, 'the edge probe accepted a static-RSA suite')
      : handshakeCompleted && (tls?.cipherSuites?.length || edgeTransport)
        ? measured(false, 'no static-RSA key-transport suite was accepted')
        : unmeasured<boolean>('Suite enumeration did not run.');

  let forwardSecrecy: Measured<boolean>;
  if (isTls13) {
    /* THE KEY RECONCILIATION. TLS 1.3 removed every static key-transport
       exchange from the protocol; a completed 1.3 handshake is forward secret
       by construction. Waiting on a named-group probe to "confirm" it is what
       produced "Not offered" in red beneath a negotiated TLS 1.3 suite. */
    forwardSecrecy = measured(
      true,
      'TLS 1.3 negotiated — the protocol has no non-ephemeral key exchange, so the session is forward secret by construction.',
    );
  } else if (kem?.kemApplied) {
    forwardSecrecy = measured(true, `measured ephemeral key agreement (${kem.group ?? 'named group'})`);
  } else if (edgeTransport && edgeTransport.negotiatedProtocol) {
    forwardSecrecy = measured(
      edgeTransport.forwardSecrecy === true,
      edgeTransport.forwardSecrecyBasis || 'established by the edge handshake',
    );
  } else if (tls && (tls.ephemeralKeyType || EPHEMERAL_KEX.test(tls.keyExchange || ''))) {
    forwardSecrecy = measured(true, `ephemeral key agreement observed (${tls.keyExchange || tls.ephemeralKeyType})`);
  } else if (handshakeCompleted) {
    forwardSecrecy = measured(false, 'the negotiated suite carries no ephemeral key agreement');
  } else {
    /* Not measured. The old code returned `false` here, which published "this
       endpoint has no forward secrecy" from a timed-out probe. */
    forwardSecrecy = unmeasured<boolean>(handshakeFailure || 'No handshake completed, so forward secrecy was not measured.');
  }

  /* ── named groups and post-quantum key agreement ────────────────────────── */

  const pq = edge?.pqKeyAgreement ?? null;
  const namedGroupProbed = Boolean(pq?.probed);
  /* Did the HYBRID half of that probe produce an answer?
     `probed` covers the group probe as a whole, and the classical groups are
     cheaper and settle first — so a run can enumerate X25519 and P-256 happily
     while every ML-KEM group is throttled into an inconclusive verdict. Reading
     `probed && no hybrid accepted` as "classical only" is what published
     "Every named group the endpoint accepted is classical" for an endpoint
     that answers X25519MLKEM768 on demand. */
  const hybridAnswered = hybridProbeSettled(pq);

  let postQuantum: TransportTruth['postQuantum'];
  if (!namedGroupProbed) {
    postQuantum = {
      state: 'not-measured',
      label: 'Not measured',
      group: null,
      /* Says what actually failed. When a handshake DID complete, it must not
         claim otherwise — that was the original misleading message. */
      reason: handshakeCompleted
        ? `A TLS handshake completed, but named key-agreement groups were not probed${edgeError ? ` (${edgeError})` : ''}. This is "not measured", not "not supported".`
        : `${handshakeFailure} Named-group probing needs a completed handshake, so post-quantum key agreement is "not measured", not "not supported".`,
    };
  } else if (pq!.hybridGroups.length) {
    postQuantum = {
      state: 'hybrid',
      label: 'Applied',
      group: pq!.primaryGroup ?? pq!.hybridGroups[0],
      reason: `Hybrid post-quantum key agreement is live: ${pq!.hybridGroups.join(', ')} accepted when offered in isolation under a TLS 1.3 floor.`,
    };
  } else if (pq!.pureKemGroups.length) {
    postQuantum = {
      state: 'pq-only',
      label: 'PQ-only',
      group: pq!.pureKemGroups[0],
      reason: `Standalone ML-KEM accepted (${pq!.pureKemGroups.join(', ')}) with no classical hedge.`,
    };
  } else if (!hybridAnswered) {
    /* Probing ran and found classical groups, but no hybrid group settled.
       Reported as unmeasured, which routes the verdict below into the branch
       that scopes its claim to the session actually negotiated instead of
       making one about the endpoint's full capability. */
    postQuantum = {
      state: 'not-measured',
      label: 'Not measured',
      group: null,
      reason:
        'Named-group probing ran, but no hybrid ML-KEM group reached a conclusive verdict' +
        `${pq!.hybridGroupsInconclusive?.length ? ` (${pq!.hybridGroupsInconclusive.join(', ')} never settled)` : ''}` +
        '. Group probing opens one handshake per group and is the first thing an endpoint throttles, so post-quantum key agreement is "not measured", not "not supported".',
    };
  } else {
    postQuantum = {
      state: 'classical',
      label: 'Classical only',
      group: pq!.primaryGroup ?? null,
      reason: 'Every hybrid group that settled was refused and every accepted named group was classical; no post-quantum group was accepted.',
    };
  }

  /* ── hybrid coverage ────────────────────────────────────────────────────── */

  /* Which measured facts prove a session can avoid the hybrid group. Both are
     already established above from the same handshake, so consulting them here
     costs nothing and cannot disagree with the rows that display them. */
  const LEGACY_VERSION = /^(?:TLSv1(?:\.[01])?|SSLv[23])$/i;
  const legacyProtocols = Array.from(
    new Set(
      [...(edgeTransport?.legacyProtocols ?? []), ...(tls?.supportedProtocols ?? [])].filter((protocol) =>
        LEGACY_VERSION.test(String(protocol).trim()),
      ),
    ),
  );
  const uncoveredPaths: string[] = [];
  if (staticRsaAccepted.value === true) {
    uncoveredPaths.push('static-RSA key transport is accepted, and RSA key transport carries no ephemeral secret at all');
  }
  if (legacyProtocols.length > 0) {
    uncoveredPaths.push(
      `${legacyProtocols.join(', ')} ${legacyProtocols.length === 1 ? 'is' : 'are'} still accepted, and hybrid groups exist only in TLS 1.3`,
    );
  }

  const hybridCoverage: Measured<boolean> =
    postQuantum.state !== 'hybrid'
      ? unmeasured<boolean>('Coverage is only meaningful once a hybrid group has been measured.')
      : uncoveredPaths.length > 0
        ? measured(false, `The hybrid group does not cover every accepted path: ${uncoveredPaths.join('; ')}.`)
        : staticRsaAccepted.measured
          ? measured(
              true,
              'No static-RSA suite and no pre-1.3 protocol was accepted, so every path measured on this endpoint carries the hybrid key agreement.',
            )
          : unmeasured<boolean>('Suite and protocol enumeration did not run, so alternative paths were not established.');

  if (hybridCoverage.value === false) {
    notes.push(
      'Hybrid post-quantum key agreement was measured, but it does not cover every path this endpoint accepts. ' +
        'Traffic recorded on an uncovered path stays harvestable regardless of the hybrid group.',
    );
  }

  /* ── quantum vulnerability ──────────────────────────────────────────────── */

  /* A completed handshake licenses a verdict even when group probing failed:
     the certificate public key and the handshake signature are quantum-relevant
     and WERE observed. Refusing to say anything in that case is the opposite
     error to fabricating — it withholds a conclusion the evidence supports. */
  let quantumVulnerability: Measured<'vulnerable' | 'hybrid' | 'hybrid-partial' | 'resistant'>;
  if (postQuantum.state === 'hybrid') {
    quantumVulnerability = hybridCoverage.value === false
      ? measured(
          'hybrid-partial',
          `${postQuantum.group} protects sessions that use it, but ${uncoveredPaths.join('; ')}. ` +
            'A session forced onto one of those paths is recorded today and decryptable later, so this endpoint is not harvest-now safe until they are disabled.',
        )
      : measured('hybrid', `${postQuantum.group} protects the session against Shor.`);
  } else if (postQuantum.state === 'pq-only') {
    quantumVulnerability = measured('resistant', `${postQuantum.group} is post-quantum, with no classical hedge.`);
  } else if (postQuantum.state === 'classical') {
    quantumVulnerability = measured(
      'vulnerable',
      'Every hybrid group that settled was refused and every named group the endpoint accepted is classical, so a recorded session is retrospectively decryptable.',
    );
  } else if (handshakeCompleted && keyExchange.measured) {
    /* Group probing failed, but the negotiated key exchange was observed. If it
       is classical, the session that was actually negotiated IS quantum
       vulnerable — that is a measurement, not an inference about the endpoint's
       full capability. The reason says exactly that. */
    const kexIsPq = /ML-?KEM|Kyber/i.test(keyExchange.value ?? '');
    quantumVulnerability = kexIsPq
      ? measured('hybrid', `The negotiated key exchange (${keyExchange.value}) includes a post-quantum primitive.`)
      : measured(
          'vulnerable',
          `The handshake that was negotiated used ${keyExchange.value}, which Shor's algorithm breaks. ` +
            'Whether this endpoint would ALSO accept a post-quantum group was not measured.',
        );
  } else {
    quantumVulnerability = unmeasured<'vulnerable' | 'hybrid' | 'hybrid-partial' | 'resistant'>(
      handshakeFailure || 'Nothing quantum-relevant was observed.',
    );
  }

  return {
    handshakeCompleted,
    handshakeSources: sources,
    handshakeFailure,
    protocol,
    cipherSuite,
    keyExchange,
    forwardSecrecy,
    staticRsaAccepted,
    namedGroupProbed,
    postQuantum,
    quantumVulnerability,
    hybridCoverage,
    notes,
  };
}

/* ─────────────────────────────────────────────────────── display helpers ──── */

/** Tri-state display: the value, or the honest "not measured". */
export function displayMeasured(reading: Measured<boolean>, yes = 'Yes', no = 'No'): string {
  if (!reading.measured || reading.value === null) return 'Not measured';
  return reading.value ? yes : no;
}

/** Forward-secrecy display, accounting for the static-RSA cap. */
export function displayForwardSecrecy(truth: TransportTruth): string {
  if (!truth.forwardSecrecy.measured || truth.forwardSecrecy.value === null) return 'Not measured';
  if (!truth.forwardSecrecy.value) return 'Not offered';
  return truth.staticRsaAccepted.value === true ? 'Partial' : 'Enabled';
}

/**
 * The one-line reconciliation statement for the disclosure panel.
 *
 * Rendered whenever the two engines did not agree or one of them failed, so a
 * reader is told which facts are measured and which are not — rather than
 * being left to notice that two panels disagree.
 */
export function transportReconciliationNote(truth: TransportTruth): string | null {
  if (truth.notes.length === 0) return null;
  return truth.notes.join(' ');
}
