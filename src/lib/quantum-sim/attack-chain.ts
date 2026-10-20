/**
 * Quantum Simulation Range — the attack chain, described by mechanism.
 *
 * WHY THIS EXISTS
 * ---------------
 * The page this replaces had six stages named "LEGACY INTERCEPT", "QUANTUM
 * COMPILING", "KEYS COLLAPSE" and so on. Evocative, but they do not say what is
 * happening, so a reader finishes the animation no better able to reason about
 * their own estate.
 *
 * These six stages say what is actually happening at each step, name the
 * mathematical object being manipulated, and declare which engine on this page
 * produces the evidence for that stage. Every stage answers the platform's
 * standing questions: what is affected, why is it risky, how urgent is it, and
 * what should I do next.
 *
 * The chain is deliberately identical across scenarios. A SWIFT interbank link
 * and a satellite downlink fail the same way, because they fail at the same
 * layer — the key agreement. Only the payload and the consequence differ, and
 * those come from the scenario record.
 */

import type { ClassicalPrimitive } from './classical-crypto';
import { primitive } from './classical-crypto';

export type EvidenceSurface =
  /** Annotated TLS 1.3 hex dump of the captured key share. */
  | 'handshake'
  /** Storage arithmetic for the archive. */
  | 'archive'
  /** The live Shor simulator. */
  | 'shor'
  /** Key-schedule walk-through from recovered secret to session keys. */
  | 'key-schedule'
  /** What the plaintext contains, from the scenario record. */
  | 'exposure'
  /** Live ML-KEM exchange and the re-issued handshake. */
  | 'defence';

export interface AttackStage {
  ordinal: number;
  id: string;
  /** Short label for the rail. */
  label: string;
  /** Full title. */
  title: string;
  /** What the adversary does. */
  action: string;
  /** The mathematics, precisely. */
  mechanism: string;
  /** Why this stage is possible at all — the property being exploited. */
  enabler: string;
  /** What stops it. */
  countermeasure: string;
  evidence: EvidenceSurface;
  /** Whether this stage requires a quantum computer to exist. */
  requiresCrqc: boolean;
  /** Tone for the UI: the first two stages are happening today. */
  tense: 'present' | 'future' | 'remedy';
}

export const ATTACK_CHAIN: AttackStage[] = [
  {
    ordinal: 1,
    id: 'record',
    label: 'Record',
    title: 'Capture the key agreement in transit',
    action: 'Mirror traffic at a transit point and keep the handshake records verbatim. No cryptanalysis is attempted and nothing is modified, so there is no anomaly for an IDS to detect.',
    mechanism:
      'The TLS 1.3 ClientHello and ServerHello carry the ephemeral key shares in the clear, because encryption cannot begin until the shared secret exists. Both public values — g^a and g^b, or the two curve points — are therefore on the wire before any protection applies.',
    enabler:
      'Key agreement is a public-value exchange by construction. Forward secrecy protects against later compromise of the long-term key, not against an adversary who records the ephemeral values and solves for them directly.',
    countermeasure:
      'Negotiate a hybrid group. With X25519MLKEM768 the recorded share includes an ML-KEM encapsulation key, and there is no known algorithm — quantum or otherwise — that recovers the secret from it.',
    evidence: 'handshake',
    requiresCrqc: false,
    tense: 'present',
  },
  {
    ordinal: 2,
    id: 'archive',
    label: 'Archive',
    title: 'Store the ciphertext until the mathematics changes',
    action: 'Write the captured sessions to cold storage, indexed by peer, date and protocol. The archive is inert: it has no cryptographic value today.',
    mechanism:
      'A TLS handshake is under two kilobytes. Storage cost is linear in session count and effectively free at national scale, while the value of the archive rises with every year the underlying data must stay confidential.',
    enabler:
      'Asymmetry of cost. Harvesting is cheap now; decryption is expensive later, but paid once, by a party who has already decided the data is worth it.',
    countermeasure:
      'Nothing retroactive. This is the reason the migration deadline is set by data shelf life rather than by the arrival of a quantum computer — see Mosca\'s inequality.',
    evidence: 'archive',
    requiresCrqc: false,
    tense: 'present',
  },
  {
    ordinal: 3,
    id: 'order-finding',
    label: 'Order-find',
    title: "Run Shor's order-finding on the recorded public value",
    action: 'A cryptographically relevant quantum computer prepares a superposition over exponents, computes the modular exponential into an entangled register, and applies an inverse quantum Fourier transform.',
    mechanism:
      'Every measurement outcome that is not close to a multiple of 2^t / r interferes destructively. What survives is a comb of peaks at y ≈ k·2^t / r. Continued fractions on the measured y recover the period r; for RSA that yields the factors, for elliptic curves the discrete logarithm variant yields the private scalar directly.',
    enabler:
      "Periodicity. RSA and every discrete-log system are built on functions with hidden periodic structure, and period-finding is exactly what quantum interference is good at. This is why key-size escalation fails: Shor's cost grows polynomially, not exponentially.",
    countermeasure:
      'Use a hardness assumption with no periodic structure to find. Module-LWE (ML-KEM, ML-DSA) and hash preimage resistance (SLH-DSA) both qualify.',
    evidence: 'shor',
    requiresCrqc: true,
    tense: 'future',
  },
  {
    ordinal: 4,
    id: 'key-recovery',
    label: 'Recover',
    title: 'Derive the session keys the endpoints derived',
    action: 'Reconstruct the shared secret from the recovered private value, then replay the key schedule the two endpoints ran at the time of capture.',
    mechanism:
      'The TLS 1.3 key schedule is deterministic: HKDF-Extract over the shared secret, then HKDF-Expand-Label through handshake and application traffic secrets, with the transcript hash as context. Every input other than the shared secret is in the recording.',
    enabler:
      'The key schedule was designed to be reproducible by both endpoints, so anyone holding the shared secret and the transcript can reproduce it too. That is not a flaw; it is the protocol working as specified.',
    countermeasure:
      'The AEAD layer never has to be broken and cannot help here. AES-256-GCM is quantum-safe, but a quantum-safe cipher keyed by a quantum-broken key agreement inherits the weaker of the two.',
    evidence: 'key-schedule',
    requiresCrqc: true,
    tense: 'future',
  },
  {
    ordinal: 5,
    id: 'exposure',
    label: 'Expose',
    title: 'Decrypt the archive retroactively',
    action: 'Decrypt every stored session belonging to the compromised peer, across the entire history of the archive.',
    mechanism:
      'Each session is decrypted with its own reconstructed traffic key. The work is embarrassingly parallel across sessions once the key agreement for each is solved, and long-lived keys mean one solved key can unlock years of records.',
    enabler:
      'The confidentiality window of the data outlived the confidentiality window of the algorithm protecting it. This is the loss event, and it is dated to the moment of capture, not the moment of decryption.',
    countermeasure:
      'Prioritise by shelf life, not by system criticality. A high-traffic service carrying ephemeral data is a lower HNDL risk than a quiet link carrying material that must stay secret for thirty years.',
    evidence: 'exposure',
    requiresCrqc: true,
    tense: 'future',
  },
  {
    ordinal: 6,
    id: 'migrate',
    label: 'Migrate',
    title: 'Re-establish the channel on FIPS 203 key encapsulation',
    action: 'Re-negotiate with a hybrid group, re-issue certificates under ML-DSA, and re-key the long-lived material.',
    mechanism:
      'ML-KEM encapsulates a 32-byte shared secret to a module-lattice public key. Recovering it requires solving Module Learning With Errors, for which no efficient classical or quantum algorithm is known, and which has no periodic structure for Shor to exploit. The hybrid construction keeps X25519 alongside it, so the session is safe if either component holds.',
    enabler:
      'The migration is a key-agreement change, not a cipher change. AES-256, SHA-384 and the whole record layer stay exactly as they are, which is why the change is tractable.',
    countermeasure:
      'Not applicable — this is the countermeasure. What remains is coverage: the estate is only migrated when every quantum-vulnerable key agreement and signature has been replaced, and evidence for that is what the platform\'s discovery modules produce.',
    evidence: 'defence',
    requiresCrqc: false,
    tense: 'remedy',
  },
];

export function stageByOrdinal(ordinal: number): AttackStage {
  return ATTACK_CHAIN[Math.max(0, Math.min(ordinal - 1, ATTACK_CHAIN.length - 1))];
}

/* ═══════════════════════════════════════════════════════════════════════════
   Scenario binding
   ═══════════════════════════════════════════════════════════════════════════ */

export interface ScenarioCryptoProfile {
  /** Matches the `id` in `src/data/scenario.ts`. */
  scenarioId: string;
  /** The primitive the target actually relies on. */
  primitiveId: string;
  /** The protocol the key agreement happens in. */
  protocol: string;
  /** IANA named group the capture stage should render. */
  groupId: number;
  /** Years the payload must remain confidential — feeds the Mosca panel. */
  shelfLifeYears: number;
  /** Why that shelf life, so the number can be argued with. */
  shelfLifeBasis: string;
  /** Handshakes per day at the target, for the archive arithmetic. */
  sessionsPerDay: number;
  /** Where this fails first. */
  weakestLink: string;
}

/**
 * Each scenario's real cryptographic profile. `shelfLifeYears` is drawn from the
 * retention rule or physical lifetime that governs that data class, never from
 * a dramatic guess — the basis is printed next to it.
 */
export const SCENARIO_CRYPTO: ScenarioCryptoProfile[] = [
  {
    scenarioId: 'hndl',
    primitiveId: 'ecdh-p256',
    protocol: 'TLS 1.2 / TLS 1.3 with ECDHE',
    groupId: 0x001d,
    shelfLifeYears: 25,
    shelfLifeBasis: 'Mixed executive and technical material; the longest-lived component sets the window.',
    sessionsPerDay: 2_500_000,
    weakestLink: 'The ephemeral ECDHE share in every handshake, recorded in the clear.',
  },
  {
    scenarioId: 'rsa-breaking',
    primitiveId: 'rsa-2048',
    protocol: 'X.509 certificate chains and SSH host keys',
    groupId: 0x0017,
    shelfLifeYears: 10,
    shelfLifeBasis: 'Root CA certificates routinely carry 10–20 year validity periods and cannot be rotated quickly.',
    sessionsPerDay: 120_000,
    weakestLink: 'The CA root private key. One recovery forges every certificate beneath it.',
  },
  {
    scenarioId: 'tls-compromise',
    primitiveId: 'ecdh-p256',
    protocol: 'TLS 1.3, X25519 key agreement',
    groupId: 0x001d,
    shelfLifeYears: 10,
    shelfLifeBasis: 'Customer PII stays exploitable long after the session ends.',
    sessionsPerDay: 40_000_000,
    weakestLink: 'X25519 key shares. High volume makes the archive large but cheap.',
  },
  {
    scenarioId: 'swift-financial',
    primitiveId: 'rsa-2048',
    protocol: 'Interbank messaging over mutually authenticated TLS',
    groupId: 0x0017,
    shelfLifeYears: 7,
    shelfLifeBasis: 'A common statutory retention period for financial transaction records; the exact period varies by jurisdiction, typically 5–10 years.',
    sessionsPerDay: 45_000_000,
    weakestLink: 'RSA-2048 signing keys authenticating payment instructions — forgery, not just disclosure.',
  },
  {
    scenarioId: 'infra-scada',
    primitiveId: 'dh-2048',
    protocol: 'IPsec / IEC 62351 over field networks',
    groupId: 0x0017,
    shelfLifeYears: 25,
    shelfLifeBasis: 'Industrial field devices routinely stay deployed for 20–30 years and are rarely re-keyed.',
    sessionsPerDay: 8_000,
    weakestLink: 'Device certificates burned in at manufacture, with no in-field rotation path.',
  },
  {
    scenarioId: 'cloud-breach',
    primitiveId: 'ecdsa-p256',
    protocol: 'Cloud control-plane APIs, request signing and OIDC tokens',
    groupId: 0x001d,
    shelfLifeYears: 10,
    shelfLifeBasis: 'Tenant data and configuration retained for the life of the account.',
    sessionsPerDay: 900_000_000,
    weakestLink: 'The signing key behind IAM assertions. Recovery means minting valid credentials, not reading old ones.',
  },
  {
    scenarioId: 'satellite-comm',
    primitiveId: 'ecdsa-p384',
    protocol: 'Space-ground link with pre-placed key material',
    groupId: 0x0018,
    shelfLifeYears: 40,
    shelfLifeBasis: 'Satellite design life plus the declassification horizon of the traffic it carries.',
    sessionsPerDay: 4_000,
    weakestLink: 'Key material fixed at launch. There is no patch path to orbit.',
  },
  {
    scenarioId: 'genomic-exposure',
    primitiveId: 'rsa-2048',
    protocol: 'Research data transfer and clinical records exchange',
    groupId: 0x0017,
    shelfLifeYears: 100,
    shelfLifeBasis: 'A genome identifies the subject and their blood relatives permanently. It cannot be rotated or revoked.',
    sessionsPerDay: 12_000,
    weakestLink: 'Shelf life, not key strength. This is the worst HNDL profile of any data class.',
  },
  {
    scenarioId: 'ai-theft',
    primitiveId: 'ecdh-p256',
    protocol: 'Model weight distribution over TLS',
    groupId: 0x001d,
    shelfLifeYears: 15,
    shelfLifeBasis: 'Trade-secret protection for model weights lasts as long as the secret holds.',
    sessionsPerDay: 60_000,
    weakestLink: 'Bulk transfers: few sessions, enormous payloads, all recoverable from one solved key.',
  },
  {
    scenarioId: 'pqc-migration',
    primitiveId: 'ecdh-p256',
    protocol: 'Partially migrated estate with hybrid and classical endpoints',
    groupId: 0x11ec,
    shelfLifeYears: 15,
    shelfLifeBasis: 'Mixed estate; the unmigrated remnant sets the exposure.',
    sessionsPerDay: 500_000,
    weakestLink: 'Downgrade. A hybrid-capable client that will still accept a classical group gains nothing until the classical option is removed.',
  },
  {
    scenarioId: 'warfare-scenario',
    primitiveId: 'ecdsa-p384',
    protocol: 'National security systems under CNSA 2.0 transition',
    groupId: 0x0018,
    shelfLifeYears: 75,
    shelfLifeBasis:
      'The long end under E.O. 13526 rather than the typical case: automatic declassification falls at 25 years, with exemptions to 50 and — for confidential human sources and key WMD design concepts — 75 years; anything longer requires ISCAP approval. National security traffic is modelled against that 75-year horizon.',
    sessionsPerDay: 250_000,
    weakestLink: 'Everything transmitted before the CNSA 2.0 exclusive-use deadlines.',
  },
  {
    scenarioId: 'supply-chain',
    primitiveId: 'ecdsa-p256',
    protocol: 'Software and firmware signing',
    groupId: 0x001d,
    shelfLifeYears: 20,
    shelfLifeBasis: 'Firmware signed today is verified by devices still in the field two decades later.',
    sessionsPerDay: 5_000,
    weakestLink:
      'Signature forgery, which is worse than disclosure: a forged update is accepted as genuine, and the verifying device has no way to know. This is why CNSA 2.0 puts software and firmware signing among its earliest deadlines (support by 2025, exclusive use by 2030).',
  },
  {
    scenarioId: 'risk-sandbox',
    primitiveId: 'rsa-2048',
    protocol: 'Side-by-side classical and post-quantum test endpoints',
    groupId: 0x11ec,
    shelfLifeYears: 5,
    shelfLifeBasis: 'Test data only. The short window is the point: a sandbox is where you learn the cost before it matters.',
    sessionsPerDay: 1_000,
    weakestLink:
      'Nothing operational. This scenario measures the migration cost — handshake size, latency, CPU — rather than an attack, and the numbers come from the live benchmark on this page.',
  },
  {
    scenarioId: 'operational-collapse',
    primitiveId: 'rsa-2048',
    protocol: 'PKI, HSM-backed signing and SSO token issuance',
    groupId: 0x0017,
    shelfLifeYears: 10,
    shelfLifeBasis: 'Root and intermediate CA certificates commonly carry 10–20 year validity and cannot be rotated quickly.',
    sessionsPerDay: 3_000_000,
    weakestLink:
      'Availability, not confidentiality. A rushed, unplanned re-key is itself an outage: mass certificate replacement saturates HSMs and breaks every relying party that pinned a key. This is the risk of migrating late rather than early.',
  },
  {
    scenarioId: 'qday-readiness',
    primitiveId: 'ecdh-p256',
    protocol: 'The whole estate, measured on the day the assumption changes',
    groupId: 0x001d,
    shelfLifeYears: 20,
    shelfLifeBasis: 'Estate-wide average across the data classes above; the longest-lived class governs the deadline.',
    sessionsPerDay: 120_000_000,
    weakestLink:
      'Coverage. On Q-Day the question is not whether you started migrating but what fraction finished — and every unmigrated key agreement is retroactively lost, not merely at risk going forward.',
  },
];

export function scenarioCrypto(scenarioId: string): ScenarioCryptoProfile {
  return SCENARIO_CRYPTO.find((s) => s.scenarioId === scenarioId) ?? SCENARIO_CRYPTO[0];
}

export function scenarioPrimitive(scenarioId: string): ClassicalPrimitive | undefined {
  return primitive(scenarioCrypto(scenarioId).primitiveId);
}
