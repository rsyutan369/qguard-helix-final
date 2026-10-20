import { byteaToBytes } from "@/lib/encoding";
import { parseMessageAad } from "@/lib/message-envelope-identity";

/**
 * Shared, plaintext-free views of a `messaging_message_envelopes` row.
 *
 * Secure Chat turns a row into a full envelope for the Rust verifier; the
 * message-key catch-up (see `prekey-hygiene.ts`) needs only the parts that
 * derive the message key. Both must read the row the same way, so the reading
 * lives here once.
 */

export function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export function numberArray(value: unknown): number[] {
  return Array.isArray(value) ? value.map((item) => Number(item) & 0xff) : [];
}

export interface HybridCiphertextPayload {
  x25519_ephemeral_public: number[];
  ml_kem_ciphertext: number[];
  suite: Record<string, unknown>;
}

/** The hybrid KEM ciphertext stored inside a row's `sealed_sender_envelope`. */
export function hybridCiphertextFromSealed(sealed: Record<string, unknown>): HybridCiphertextPayload {
  const hybrid = asRecord(sealed.hybrid_ciphertext);
  return {
    x25519_ephemeral_public: numberArray(hybrid.x25519_ephemeral_public),
    ml_kem_ciphertext: numberArray(hybrid.ml_kem_ciphertext),
    suite: asRecord(hybrid.suite),
  };
}

/**
 * The hybrid ciphertext as the Rust core expects it: `null` when the row has
 * none. An ordinary post-quantum ratchet message carries no encapsulation (its
 * key comes from the session), and handing the core an empty placeholder in
 * its place would fail to decode rather than open.
 */
export function hybridCiphertextForCore(sealed: Record<string, unknown>): HybridCiphertextPayload | null {
  const hybrid = sealed.hybrid_ciphertext;
  if (!hybrid || typeof hybrid !== "object" || Array.isArray(hybrid)) return null;
  return hybridCiphertextFromSealed(sealed);
}

/**
 * A row's post-quantum ratchet header (`sealed_sender_envelope.ratchet`), or
 * undefined for a one-shot envelope. Passed through untouched: the core
 * validates it, and both signatures and the AEAD tag cover it, so a value
 * edited here could only make the envelope fail, never change what it says.
 */
export function ratchetHeaderFromSealed(sealed: Record<string, unknown>): Record<string, unknown> | undefined {
  const header = sealed.ratchet;
  if (!header || typeof header !== "object" || Array.isArray(header)) return undefined;
  return header as Record<string, unknown>;
}

/** Which prekey a row says it was sealed to. */
export function prekeyReferenceFromSealed(sealed: Record<string, unknown>): { prekey_id: string; prekey_kind: string } {
  return {
    prekey_id: String(sealed.prekey_id ?? ""),
    prekey_kind: String(sealed.prekey_kind ?? "signed_prekey"),
  };
}

/** The columns that identify one envelope to the message-key ledger. */
export interface EnvelopeProbeRow {
  id: unknown;
  nonce: unknown;
  auth_tag: unknown;
  aad: unknown;
}

/** Argument shape of the `messaging_message_keys_lookup` command. */
export interface LedgerProbe {
  messageId: string;
  nonce: number[];
  tag: number[];
}

/**
 * The ledger is keyed by the message id the SENDER signed (carried in the AAD),
 * exactly as the decrypt path keys it — not by the row id, which is merely
 * expected to match.
 */
export function ledgerProbeFromRow(row: EnvelopeProbeRow): LedgerProbe {
  const signed = parseMessageAad(row.aad);
  return {
    messageId: signed?.message_id ?? String(row.id),
    nonce: byteaToBytes(row.nonce),
    tag: byteaToBytes(row.auth_tag),
  };
}

/** The columns needed to derive an envelope's message key. */
export interface EnvelopeKeyRow extends EnvelopeProbeRow {
  conversation_id: unknown;
  sender_user_id: unknown;
  recipient_user_id: unknown;
  sender_device_id: unknown;
  recipient_device_id: unknown;
  ratchet_counter: unknown;
  ciphertext: unknown;
  sealed_sender_envelope: unknown;
}

/** Argument shape of the `messaging_cache_envelope_key` command. */
export interface EnvelopeKeyRequest {
  message_id: string;
  conversation_id: string;
  sender_user_id: string;
  recipient_user_id: string;
  sender_device_id: string;
  recipient_device_id: string;
  counter: number;
  envelope: { nonce: number[]; ciphertext: number[]; tag: number[] };
  aad: number[];
  hybrid_ciphertext: HybridCiphertextPayload | null;
  prekey_id: string;
  prekey_kind: string;
  ratchet?: Record<string, unknown>;
}

/**
 * Everything the Rust core needs to re-derive (and prove) one envelope's key,
 * and nothing that would let it be displayed: no signature, no sender keys.
 *
 * Identity fields come from the signed AAD first, for the reason given on
 * `parseMessageAad`; the mutable columns are only the fallback.
 */
export function envelopeKeyRequestFromRow(row: EnvelopeKeyRow): EnvelopeKeyRequest {
  const sealed = asRecord(row.sealed_sender_envelope);
  const signed = parseMessageAad(row.aad);
  const text = (value: unknown) => (value === null || value === undefined ? "" : String(value));
  return {
    message_id: signed?.message_id ?? text(row.id),
    conversation_id: signed?.conversation_id ?? text(row.conversation_id),
    sender_user_id: signed?.sender_user_id ?? text(row.sender_user_id),
    recipient_user_id: signed?.recipient_user_id ?? text(row.recipient_user_id),
    sender_device_id: signed?.sender_device_id ?? text(row.sender_device_id),
    recipient_device_id: signed?.recipient_device_id ?? text(row.recipient_device_id),
    counter: signed?.counter ?? Number(row.ratchet_counter ?? 0),
    envelope: {
      nonce: byteaToBytes(row.nonce),
      ciphertext: byteaToBytes(row.ciphertext),
      tag: byteaToBytes(row.auth_tag),
    },
    aad: byteaToBytes(row.aad),
    hybrid_ciphertext: hybridCiphertextForCore(sealed),
    ...prekeyReferenceFromSealed(sealed),
    ...(ratchetHeaderFromSealed(sealed) ? { ratchet: ratchetHeaderFromSealed(sealed) } : {}),
  };
}
