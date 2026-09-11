/**
 * Quantum Simulation Range — byte-accurate TLS 1.3 handshake evidence.
 *
 * WHY THIS EXISTS
 * ---------------
 * "Harvest now, decrypt later" is abstract until you can see the exact bytes an
 * adversary writes to disk. This module builds real TLS 1.3 records — correct
 * record header, correct handshake header, correct extension encoding, real
 * IANA code points — and annotates every field so the UI can render a hex dump
 * that a network engineer would recognise.
 *
 * The important thing the dump shows: the `key_share` extension is sent in
 * cleartext, before any encryption exists. Ephemeral ECDHE gives forward
 * secrecy against key COMPROMISE, but not against a recorder, because the
 * recorder does not need the server's long-term key — it needs to solve the
 * discrete log on the ephemeral share it already has. That is the whole HNDL
 * argument, made in bytes.
 *
 * Reference: RFC 8446 §4.1.2, §4.2.8; draft-ietf-tls-ecdhe-mlkem;
 * IANA TLS Supported Groups registry.
 */

import { expand, extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { TLS13_CIPHER_SUITES, TLS_NAMED_GROUPS, namedGroup, type NamedGroup } from './nist-standards';

/* ═══════════════════════════════════════════════════════════════════════════
   A tiny annotated byte builder
   ═══════════════════════════════════════════════════════════════════════════ */

export interface ByteField {
  label: string;
  offset: number;
  length: number;
  /** Why this field matters to quantum risk. Empty for structural fields. */
  note: string;
  /** Highlight class the UI maps to a colour. */
  emphasis: 'structure' | 'classical' | 'quantum-safe' | 'symmetric' | 'random';
}

class RecordBuilder {
  private bytes: number[] = [];
  readonly fields: ByteField[] = [];

  push(values: ArrayLike<number>, label: string, emphasis: ByteField['emphasis'] = 'structure', note = ''): void {
    const offset = this.bytes.length;
    for (let i = 0; i < values.length; i += 1) this.bytes.push(values[i] & 0xff);
    this.fields.push({ label, offset, length: values.length, note, emphasis });
  }

  u8(value: number, label: string, emphasis: ByteField['emphasis'] = 'structure', note = ''): void {
    this.push([value], label, emphasis, note);
  }

  u16(value: number, label: string, emphasis: ByteField['emphasis'] = 'structure', note = ''): void {
    this.push([(value >> 8) & 0xff, value & 0xff], label, emphasis, note);
  }

  /** Reserve a 2-byte length that is patched once the body is written. */
  reserveU16(): number {
    const at = this.bytes.length;
    this.bytes.push(0, 0);
    return at;
  }

  reserveU24(): number {
    const at = this.bytes.length;
    this.bytes.push(0, 0, 0);
    return at;
  }

  patchU16(at: number): void {
    const length = this.bytes.length - at - 2;
    this.bytes[at] = (length >> 8) & 0xff;
    this.bytes[at + 1] = length & 0xff;
  }

  patchU24(at: number): void {
    const length = this.bytes.length - at - 3;
    this.bytes[at] = (length >> 16) & 0xff;
    this.bytes[at + 1] = (length >> 8) & 0xff;
    this.bytes[at + 2] = length & 0xff;
  }

  get length(): number {
    return this.bytes.length;
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.bytes);
  }
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  const webcrypto = typeof globalThis !== 'undefined' ? (globalThis.crypto as Crypto | undefined) : undefined;
  if (webcrypto?.getRandomValues) {
    webcrypto.getRandomValues(out);
    return out;
  }
  for (let i = 0; i < length; i += 1) out[i] = Math.floor(Math.random() * 256);
  return out;
}

/* ═══════════════════════════════════════════════════════════════════════════
   ClientHello
   ═══════════════════════════════════════════════════════════════════════════ */

export interface HandshakeEvidence {
  /** The complete TLS record, ready to hex-dump. */
  bytes: Uint8Array;
  fields: ByteField[];
  /** The group whose key share this record carries. */
  group: NamedGroup;
  serverName: string;
  /** True when the key share can be solved by a CRQC from the recording alone. */
  harvestable: boolean;
  /** One-line verdict the UI puts above the dump. */
  verdict: string;
}

export interface ClientHelloOptions {
  serverName: string;
  /** IANA code point of the group whose share is offered. */
  groupId: number;
  /**
   * Real key-share bytes. Callers should pass genuine ML-KEM material from
   * `pqc-live.ts` for hybrid groups; when omitted, cryptographically random
   * bytes of the correct length are used so the record is still structurally
   * valid and the correct size.
   */
  keyShare?: Uint8Array;
  /** Cipher suites offered. Defaults to all three TLS 1.3 suites. */
  cipherSuites?: number[];
}

export function buildClientHello(options: ClientHelloOptions): HandshakeEvidence {
  const group = namedGroup(options.groupId) ?? TLS_NAMED_GROUPS[2];
  const suites = options.cipherSuites ?? TLS13_CIPHER_SUITES.map((s) => s.id);
  const keyShare = options.keyShare ?? randomBytes(group.clientShareBytes);

  const b = new RecordBuilder();

  b.u8(0x16, 'record.type = handshake (22)');
  b.u16(0x0303, 'record.legacy_version = 0x0303', 'structure', 'Frozen at TLS 1.2 for middlebox compatibility. The real version is negotiated in an extension.');
  const recordLength = b.reserveU16();

  b.u8(0x01, 'handshake.type = client_hello (1)');
  const handshakeLength = b.reserveU24();

  b.u16(0x0303, 'legacy_version = 0x0303');
  b.push(randomBytes(32), 'random[32]', 'random', 'Client nonce. Contributes entropy to the transcript but no secrecy on its own.');
  b.u8(32, 'legacy_session_id length');
  b.push(randomBytes(32), 'legacy_session_id[32]', 'random', 'Cosmetic in TLS 1.3 — echoed by the server to look like a resumed TLS 1.2 session.');

  b.u16(suites.length * 2, 'cipher_suites length');
  for (const id of suites) {
    const suite = TLS13_CIPHER_SUITES.find((s) => s.id === id);
    b.u16(
      id,
      `cipher_suite 0x${id.toString(16).padStart(4, '0')} — ${suite?.name ?? 'unknown'}`,
      'symmetric',
      suite ? `${suite.aead}, ${suite.keyBits}-bit key. Symmetric: a quantum computer reduces this to ${suite.keyBits / 2} bits via Grover, which is not an attack.` : '',
    );
  }

  b.push([0x01, 0x00], 'legacy_compression_methods = null');

  const extensionsLength = b.reserveU16();

  // server_name (0)
  {
    const name = new TextEncoder().encode(options.serverName);
    b.u16(0x0000, 'ext: server_name (0)');
    b.u16(name.length + 5, 'ext length');
    b.u16(name.length + 3, 'server_name_list length');
    b.u8(0x00, 'name_type = host_name');
    b.u16(name.length, 'host_name length');
    b.push(name, `host_name = "${options.serverName}"`, 'structure', 'Sent in the clear. A passive recorder learns who you are talking to regardless of the cipher suite.');
  }

  // supported_versions (43)
  b.u16(0x002b, 'ext: supported_versions (43)');
  b.u16(3, 'ext length');
  b.u8(2, 'versions length');
  b.u16(0x0304, 'TLS 1.3 (0x0304)', 'structure', 'The real version negotiation.');

  // supported_groups (10)
  {
    const offered = [group.id, ...TLS_NAMED_GROUPS.filter((g) => g.id !== group.id).map((g) => g.id)].slice(0, 4);
    b.u16(0x000a, 'ext: supported_groups (10)');
    b.u16(offered.length * 2 + 2, 'ext length');
    b.u16(offered.length * 2, 'named_group_list length');
    for (const id of offered) {
      const g = namedGroup(id);
      b.u16(
        id,
        `group 0x${id.toString(16).padStart(4, '0')} — ${g?.name ?? 'unknown'}`,
        g?.quantumBroken ? 'classical' : 'quantum-safe',
        g?.note ?? '',
      );
    }
  }

  // key_share (51)
  {
    b.u16(0x0033, 'ext: key_share (51)');
    b.u16(keyShare.length + 6, 'ext length');
    b.u16(keyShare.length + 4, 'client_shares length');
    b.u16(group.id, `KeyShareEntry.group = 0x${group.id.toString(16).padStart(4, '0')} (${group.name})`, group.quantumBroken ? 'classical' : 'quantum-safe', group.note);
    b.u16(keyShare.length, 'key_exchange length');

    if (group.kind === 'hybrid') {
      // draft-ietf-tls-ecdhe-mlkem: for X25519MLKEM768 the ML-KEM key comes
      // first; for the SecP* hybrids the ECDH point comes first.
      const mlKemFirst = group.name.startsWith('X25519');
      const mlKemLength = group.name.includes('MLKEM1024') ? 1568 : 1184;
      const classicalLength = group.clientShareBytes - mlKemLength;
      if (mlKemFirst) {
        b.push(
          keyShare.subarray(0, mlKemLength),
          `ML-KEM encapsulation key [${mlKemLength}]`,
          'quantum-safe',
          'A module-lattice public key. Recovering the shared secret from this requires solving Module-LWE, for which no quantum algorithm is known.',
        );
        b.push(
          keyShare.subarray(mlKemLength),
          `X25519 public key [${classicalLength}]`,
          'classical',
          'Still present, and still breakable by Shor. It is here so the handshake stays safe if a flaw is found in ML-KEM — the hybrid holds if EITHER half holds.',
        );
      } else {
        b.push(keyShare.subarray(0, classicalLength), `ECDH public point [${classicalLength}]`, 'classical', 'Breakable by Shor. Present for defence in depth.');
        b.push(keyShare.subarray(classicalLength), `ML-KEM encapsulation key [${mlKemLength}]`, 'quantum-safe', 'The half that survives a CRQC.');
      }
    } else {
      b.push(
        keyShare,
        `${group.name} public key [${keyShare.length}]`,
        'classical',
        'This is the harvestable field. A recorder stores these bytes today; a CRQC solves the discrete logarithm later and derives the same shared secret the two endpoints derived. Forward secrecy does not help, because the attacker never needed the long-term key.',
      );
    }
  }

  b.patchU16(extensionsLength);
  b.patchU24(handshakeLength);
  b.patchU16(recordLength);

  return {
    bytes: b.finish(),
    fields: b.fields,
    group,
    serverName: options.serverName,
    harvestable: group.quantumBroken,
    verdict: group.quantumBroken
      ? `Harvestable. Every byte needed to recover this session's keys is in this record, and a CRQC can finish the job whenever one exists.`
      : `Not harvestable. The shared secret is protected by ML-KEM; recording the handshake gains an adversary nothing that a quantum computer can unlock.`,
  };
}

/* ═══════════════════════════════════════════════════════════════════════════
   The recorder's view
   ═══════════════════════════════════════════════════════════════════════════ */

export interface HarvestRecord {
  /** Bytes an adversary must store per captured session. */
  bytesPerSession: number;
  /** What they store. */
  contents: string[];
  /** What they still cannot read, and what unlocks it. */
  blocked: string;
  unlockedBy: string;
}

/**
 * What a passive recorder actually keeps. Deliberately small numbers: the point
 * is that harvesting is cheap. A handshake is under 2 KB; a year of a
 * mid-sized enterprise's TLS handshakes fits on a single disk.
 */
export function harvestFootprint(group: NamedGroup, sessionsPerDay: number, years: number): {
  record: HarvestRecord;
  totalBytes: number;
  totalSessions: number;
  storageDescription: string;
} {
  const handshakeBytes = 512 + group.clientShareBytes + group.serverShareBytes;
  const record: HarvestRecord = {
    bytesPerSession: handshakeBytes,
    contents: [
      'ClientHello and ServerHello in full, including both key shares',
      'The server certificate chain, which is sent before encryption begins in TLS 1.2 and encrypted in TLS 1.3',
      'Encrypted application records, kept verbatim',
      'SNI, timing, and volume — metadata that is never encrypted',
    ],
    blocked: group.quantumBroken
      ? 'The application data, for now. Its AES keys derive from the ECDHE shared secret via HKDF.'
      : 'Everything. The ML-KEM shared secret cannot be recovered from the recording.',
    unlockedBy: group.quantumBroken
      ? 'A quantum computer running Shor on the recorded key share. The AES-256 layer is untouched — it does not have to be broken, because the key that produced it is recovered directly.'
      : 'Nothing currently known.',
  };

  const totalSessions = sessionsPerDay * 365 * years;
  const totalBytes = totalSessions * handshakeBytes;

  const storageDescription =
    totalBytes < 1e12
      ? `${(totalBytes / 1e9).toFixed(1)} GB — a USB stick.`
      : totalBytes < 1e15
        ? `${(totalBytes / 1e12).toFixed(1)} TB — a desk drawer of hard drives.`
        : `${(totalBytes / 1e15).toFixed(1)} PB — a single rack.`;

  return { record, totalBytes, totalSessions, storageDescription };
}

/* ═══════════════════════════════════════════════════════════════════════════
   Rendering helpers
   ═══════════════════════════════════════════════════════════════════════════ */

export interface HexRow {
  offset: number;
  /** 16 bytes, or fewer on the final row. */
  bytes: number[];
  /** Field index covering each byte, for per-byte highlighting. */
  fieldIndex: number[];
  ascii: string;
}

export function toHexRows(bytes: Uint8Array, fields: ByteField[], limit = 512): HexRow[] {
  const owner = new Int32Array(bytes.length).fill(-1);
  fields.forEach((field, index) => {
    for (let i = field.offset; i < field.offset + field.length && i < owner.length; i += 1) owner[i] = index;
  });

  const rows: HexRow[] = [];
  const end = Math.min(bytes.length, limit);
  for (let offset = 0; offset < end; offset += 16) {
    const slice = Array.from(bytes.subarray(offset, Math.min(offset + 16, end)));
    rows.push({
      offset,
      bytes: slice,
      fieldIndex: Array.from(owner.subarray(offset, offset + slice.length)),
      ascii: slice.map((v) => (v >= 0x20 && v < 0x7f ? String.fromCharCode(v) : '·')).join(''),
    });
  }
  return rows;
}

export function toHex(bytes: Uint8Array, maxBytes = 32): string {
  return Array.from(bytes.subarray(0, maxBytes))
    .map((v) => v.toString(16).padStart(2, '0'))
    .join(' ');
}

/* ═══════════════════════════════════════════════════════════════════════════
   The TLS 1.3 key schedule, executed
   ═══════════════════════════════════════════════════════════════════════════ */

/**
 * HKDF-Expand-Label (RFC 8446 §7.1).
 *
 *   struct {
 *     uint16 length;
 *     opaque label<7..255>   = "tls13 " + Label;
 *     opaque context<0..255> = Context;
 *   } HkdfLabel;
 */
function expandLabel(secret: Uint8Array, label: string, context: Uint8Array, length: number): Uint8Array {
  const fullLabel = new TextEncoder().encode(`tls13 ${label}`);
  const info = new Uint8Array(2 + 1 + fullLabel.length + 1 + context.length);
  let offset = 0;
  info[offset++] = (length >> 8) & 0xff;
  info[offset++] = length & 0xff;
  info[offset++] = fullLabel.length;
  info.set(fullLabel, offset);
  offset += fullLabel.length;
  info[offset++] = context.length;
  info.set(context, offset);
  return expand(sha256, secret, info, length);
}

/** Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(., ., Transcript-Hash(Messages), 32). */
function deriveSecret(secret: Uint8Array, label: string, transcript: Uint8Array): Uint8Array {
  return expandLabel(secret, label, transcript, 32);
}

export interface ScheduleStep {
  /** Order in the derivation chain. */
  ordinal: number;
  name: string;
  /** The HKDF operation performed, written the way RFC 8446 §7.1 writes it. */
  operation: string;
  /** First bytes of the derived value, for display. */
  value: Uint8Array;
  /** Why an attacker cares about this particular secret. */
  significance: string;
  /** True for the step that consumes the (EC)DHE shared secret. */
  consumesSharedSecret: boolean;
}

export interface KeyScheduleResult {
  steps: ScheduleStep[];
  /** The AEAD key the record layer actually uses. */
  clientWriteKey: Uint8Array;
  clientWriteIv: Uint8Array;
  serverWriteKey: Uint8Array;
  /** Cipher suite these keys are sized for. */
  suite: string;
  /** Milliseconds the whole derivation took in this browser. */
  elapsedMs: number;
}

/**
 * Run the real TLS 1.3 key schedule from a shared secret to the record-layer
 * AEAD keys, using HKDF-SHA-256 exactly as RFC 8446 §7.1 specifies.
 *
 * This is the step that makes the quantum threat concrete. The schedule is
 * deterministic and every input except the shared secret is in the recording:
 * the transcript hash is over messages the recorder captured verbatim. So an
 * adversary who recovers the (EC)DHE shared secret — which is exactly what
 * Shor's algorithm hands them — reproduces these bytes and decrypts the
 * session. The AES-256-GCM layer is never attacked, because it never has to be.
 *
 * @param sharedSecret the (EC)DHE or ML-KEM shared secret
 * @param transcript   Transcript-Hash(ClientHello…ServerHello); a real 32-byte
 *                     SHA-256 digest of the captured handshake bytes
 */
export function tls13KeySchedule(sharedSecret: Uint8Array, transcript: Uint8Array): KeyScheduleResult {
  const started = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const zeros = new Uint8Array(32);
  const empty = sha256(new Uint8Array(0));

  const earlySecret = extract(sha256, zeros, zeros);
  const derivedForHandshake = deriveSecret(earlySecret, 'derived', empty);
  const handshakeSecret = extract(sha256, sharedSecret, derivedForHandshake);
  const clientHandshakeTraffic = deriveSecret(handshakeSecret, 'c hs traffic', transcript);
  const serverHandshakeTraffic = deriveSecret(handshakeSecret, 's hs traffic', transcript);
  const derivedForMaster = deriveSecret(handshakeSecret, 'derived', empty);
  const masterSecret = extract(sha256, zeros, derivedForMaster);
  const clientAppTraffic = deriveSecret(masterSecret, 'c ap traffic', transcript);
  const serverAppTraffic = deriveSecret(masterSecret, 's ap traffic', transcript);

  const clientWriteKey = expandLabel(clientAppTraffic, 'key', new Uint8Array(0), 32);
  const clientWriteIv = expandLabel(clientAppTraffic, 'iv', new Uint8Array(0), 12);
  const serverWriteKey = expandLabel(serverAppTraffic, 'key', new Uint8Array(0), 32);

  const steps: ScheduleStep[] = [
    {
      ordinal: 1,
      name: 'Early Secret',
      operation: 'HKDF-Extract(salt = 0, IKM = 0)',
      value: earlySecret,
      significance: 'Fixed for a session with no pre-shared key. Contains no secret material at all — it is a constant.',
      consumesSharedSecret: false,
    },
    {
      ordinal: 2,
      name: 'Handshake Secret',
      operation: 'HKDF-Extract(salt = Derive-Secret(Early, "derived"), IKM = (EC)DHE shared secret)',
      value: handshakeSecret,
      significance:
        'The only step that consumes secret material. Everything downstream is a deterministic function of this value and the recorded transcript, which is why recovering the shared secret is equivalent to recovering the session.',
      consumesSharedSecret: true,
    },
    {
      ordinal: 3,
      name: 'client handshake traffic secret',
      operation: 'Derive-Secret(Handshake, "c hs traffic", ClientHello…ServerHello)',
      value: clientHandshakeTraffic,
      significance: 'Protects the encrypted extensions, certificate and Finished messages.',
      consumesSharedSecret: false,
    },
    {
      ordinal: 4,
      name: 'server handshake traffic secret',
      operation: 'Derive-Secret(Handshake, "s hs traffic", ClientHello…ServerHello)',
      value: serverHandshakeTraffic,
      significance: 'Decrypts the server certificate — which in TLS 1.3 is encrypted, and in TLS 1.2 was not.',
      consumesSharedSecret: false,
    },
    {
      ordinal: 5,
      name: 'Master Secret',
      operation: 'HKDF-Extract(salt = Derive-Secret(Handshake, "derived"), IKM = 0)',
      value: masterSecret,
      significance: 'Adds no new entropy. It is a re-keying step, not a second secret.',
      consumesSharedSecret: false,
    },
    {
      ordinal: 6,
      name: 'client application traffic secret',
      operation: 'Derive-Secret(Master, "c ap traffic", ClientHello…server Finished)',
      value: clientAppTraffic,
      significance: 'The root of every AEAD key protecting actual application data in this direction.',
      consumesSharedSecret: false,
    },
    {
      ordinal: 7,
      name: 'client_write_key',
      operation: 'HKDF-Expand-Label(c ap traffic, "key", "", 32)',
      value: clientWriteKey,
      significance:
        'The AES-256-GCM key. AES-256 is quantum-safe; it makes no difference here, because the attacker derived the key rather than searching for it.',
      consumesSharedSecret: false,
    },
  ];

  const elapsed = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - started;

  return {
    steps,
    clientWriteKey,
    clientWriteIv,
    serverWriteKey,
    suite: 'TLS_AES_256_GCM_SHA384 key sizes over an HKDF-SHA-256 schedule',
    elapsedMs: elapsed,
  };
}

/** SHA-256 over the captured handshake bytes — a genuine Transcript-Hash input. */
export function transcriptHash(...records: Uint8Array[]): Uint8Array {
  const total = records.reduce((sum, r) => sum + r.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const record of records) {
    joined.set(record, offset);
    offset += record.length;
  }
  return sha256(joined);
}
