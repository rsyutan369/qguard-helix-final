import type { SupabaseClient } from "@supabase/supabase-js";
import { callPeerIdentityFromRow } from "@/lib/call-peer-identity";
import type { CallPeerIdentityPayload } from "@/lib/call-targets";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

/**
 * Account sealing key, as seen from the UI (src-tauri/src/commands/account_key.rs,
 * migration 044).
 *
 * A few rows the relay stores are not message content but are only read by the
 * account's own devices: the details of an audit event, crypto telemetry
 * details. They are sealed here with a per-account key the Rust core holds on
 * every one of the user's devices, so a copy of the database shows ciphertext.
 *
 * The core makes, wraps, accepts and uses the key. This module only moves the
 * sealed wraps between the core and the relay table, decides WHEN (who makes the
 * first key, who must be sent one, when to start a new epoch) and gives the
 * pages two calls: `sealJson` and `openRows`.
 *
 * Failure is always "less shown", never "wrong shown": a field this device
 * cannot open yet is reported as unavailable, and a value that cannot be sealed
 * is written as a bare marker — never as plaintext.
 */

export type AccountFieldPurpose = "contact_alias" | "security_event" | "telemetry" | "message_state";

export interface SealedField {
  v: number;
  e: number;
  n: string;
  c: string;
}

export interface SealedEnvelope {
  sealed: SealedField;
}

export interface AccountKeyStatus {
  available: boolean;
  currentEpoch: number | null;
  epochs: number[];
}

export function isSealedEnvelope(value: unknown): value is SealedEnvelope {
  if (!value || typeof value !== "object") return false;
  const sealed = (value as { sealed?: unknown }).sealed;
  if (!sealed || typeof sealed !== "object") return false;
  const field = sealed as Record<string, unknown>;
  return typeof field.v === "number" && typeof field.e === "number" && typeof field.n === "string" && typeof field.c === "string";
}

/* ----------------------------------------------------------- field sealing -- */

export const accountKeyStatus = (): Promise<AccountKeyStatus | null> =>
  isTauriRuntime() ? safeInvoke<AccountKeyStatus>("account_key_status").catch(() => null) : Promise.resolve(null);

/**
 * Seal `value` for a row. Returns null when it cannot be sealed (not the app, or
 * this device has no account key yet) — callers then write a bare marker.
 */
export async function sealJson(purpose: AccountFieldPurpose, context: string, value: unknown): Promise<SealedEnvelope | null> {
  if (!isTauriRuntime()) return null;
  try {
    const sealed = await safeInvoke<SealedField>("account_field_seal", { purpose, context, plaintext: JSON.stringify(value) });
    return { sealed };
  } catch {
    return null;
  }
}

export type OpenedState = "plain" | "opened" | "unavailable";

export interface OpenedValue {
  value: Record<string, unknown> | null;
  state: OpenedState;
}

/**
 * Open a column for many rows at once. A value that is not sealed (a row from
 * before this feature) is returned untouched as `plain`. A sealed one that
 * cannot be opened (no key for its epoch yet, tampered, wrong row) is
 * `unavailable` — a list never fails because of one row.
 */
export async function openValues(
  purpose: AccountFieldPurpose,
  entries: Array<{ context: string; value: unknown }>,
): Promise<OpenedValue[]> {
  const asRecord = (value: unknown): Record<string, unknown> | null =>
    value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;

  const result: OpenedValue[] = entries.map((entry) => ({ value: asRecord(entry.value), state: "plain" as OpenedState }));
  const sealedIndexes: number[] = [];
  entries.forEach((entry, index) => {
    if (isSealedEnvelope(entry.value)) sealedIndexes.push(index);
  });
  if (sealedIndexes.length === 0) return result;

  let opened: Array<string | null> = [];
  if (isTauriRuntime()) {
    try {
      opened = await safeInvoke<Array<string | null>>("account_field_open_many", {
        items: sealedIndexes.map((index) => ({
          purpose,
          context: entries[index].context,
          field: (entries[index].value as SealedEnvelope).sealed,
        })),
      });
    } catch {
      opened = [];
    }
  }
  sealedIndexes.forEach((entryIndex, position) => {
    const text = opened[position];
    let parsed: Record<string, unknown> | null = null;
    if (typeof text === "string") {
      try {
        parsed = asRecord(JSON.parse(text));
      } catch {
        parsed = null;
      }
    }
    result[entryIndex] = parsed ? { value: parsed, state: "opened" } : { value: null, state: "unavailable" };
  });
  return result;
}

/** What an audit event stores when its details could not be sealed. */
export const BARE_DETAILS = { redacted: true } as const;

/** Details for a `messaging_security_events` row: sealed, or a bare marker. */
export async function securityEventDetails(eventHash: string, metadata: Record<string, unknown>): Promise<Record<string, unknown>> {
  const sealed = await sealJson("security_event", eventHash, metadata);
  return sealed ? { sealed: sealed.sealed } : { ...BARE_DETAILS };
}

/** Read back `encrypted_details` for a list of security events. */
export async function openSecurityEventDetails<T extends { event_hash: string; encrypted_details?: Record<string, unknown> | null }>(
  rows: T[],
): Promise<T[]> {
  if (rows.length === 0) return rows;
  const opened = await openValues("security_event", rows.map((row) => ({ context: row.event_hash, value: row.encrypted_details })));
  return rows.map((row, index) => {
    const entry = opened[index];
    if (entry.state === "opened") return { ...row, encrypted_details: entry.value };
    if (entry.state === "unavailable") return { ...row, encrypted_details: { ...BARE_DETAILS, unavailable: true } };
    return row;
  });
}

/** Stage names are not sensitive; this is what the `detail` column carries once the real detail is sealed. */
export function telemetryPlaceholder(stage: string): string {
  return stage.replace(/_/g, " ").slice(0, 80);
}

export interface TelemetryRowLike {
  id: string;
  stage: string;
  detail: string;
  redacted_metadata?: unknown;
}

/** Replace `detail` with the opened real detail wherever the row was sealed. */
export async function openTelemetryDetails<T extends TelemetryRowLike>(rows: T[]): Promise<T[]> {
  if (rows.length === 0) return rows;
  const opened = await openValues("telemetry", rows.map((row) => ({ context: row.id, value: row.redacted_metadata })));
  return rows.map((row, index) => {
    const entry = opened[index];
    if (entry.state === "opened") {
      const detail = typeof entry.value?.detail === "string" ? entry.value.detail : row.detail;
      return { ...row, detail, redacted_metadata: entry.value?.metadata ?? {} };
    }
    if (entry.state === "unavailable") return { ...row, redacted_metadata: {} };
    return row;
  });
}

/* ------------------------------------------------------- key distribution -- */

/** The pure decisions, kept apart from I/O so they can be tested. */

/** Make the first key? Only when no other trusted device exists, or none holds one and this has the lowest id. */
export function shouldBootstrap(input: { selfId: string; trustedIds: string[]; anyWrapRows: boolean }): boolean {
  const others = input.trustedIds.filter((id) => id !== input.selfId);
  if (others.length === 0) return true;
  if (input.anyWrapRows) return false;
  return [input.selfId, ...others].sort()[0] === input.selfId;
}

export interface WrapRowLike {
  from_device_id: string;
  to_device_id: string;
  epoch: number;
  accepted_at: string | null;
}

/** Trusted devices (not this one) that have no wrap at the current epoch yet. */
export function devicesNeedingWrap(input: { selfId: string; trustedIds: string[]; rows: WrapRowLike[]; currentEpoch: number }): string[] {
  const have = new Set(input.rows.filter((row) => row.epoch === input.currentEpoch).map((row) => row.to_device_id));
  return input.trustedIds.filter((id) => id !== input.selfId && !have.has(id));
}

/**
 * A key must be rotated when a device that was handed the CURRENT epoch is no
 * longer trusted. Exactly one device does it: the lowest id among those known
 * to hold the key, so two holders do not each invent an epoch.
 */
export function rotationDue(input: {
  selfId: string;
  trustedIds: string[];
  revokedIds: string[];
  rows: WrapRowLike[];
  currentEpoch: number;
}): boolean {
  const atCurrent = input.rows.filter((row) => row.epoch === input.currentEpoch);
  const revoked = new Set(input.revokedIds);
  if (!atCurrent.some((row) => revoked.has(row.to_device_id))) return false;
  const trusted = new Set(input.trustedIds);
  const holders = new Set<string>([input.selfId]);
  for (const row of atCurrent) {
    if (trusted.has(row.from_device_id)) holders.add(row.from_device_id);
    if (row.accepted_at && trusted.has(row.to_device_id)) holders.add(row.to_device_id);
  }
  return [...holders].sort()[0] === input.selfId;
}

function tableMissing(error: { message?: string } | null | undefined): boolean {
  return /does not exist|schema cache|PGRST205/i.test(error?.message ?? "");
}

interface DeviceRow {
  id: string;
  trust_state?: string | null;
  revoked_at?: string | null;
}

const inFlight = new Map<string, Promise<AccountKeyStatus | null>>();

/**
 * Bring this device's account key up to date: accept a key another of the user's
 * devices sealed to it, make the first key if this device is the one that
 * should, send the key to the user's other trusted devices, and start a new
 * epoch if a device that held the key is gone. Safe to call often; concurrent
 * calls share one pass.
 */
export function syncAccountKey(client: SupabaseClient, userId: string, deviceId: string): Promise<AccountKeyStatus | null> {
  if (!isTauriRuntime()) return Promise.resolve(null);
  const running = inFlight.get(userId);
  if (running) return running;
  const pass = runSync(client, userId, deviceId)
    .catch(() => null)
    .finally(() => inFlight.delete(userId));
  inFlight.set(userId, pass);
  return pass;
}

async function runSync(client: SupabaseClient, userId: string, deviceId: string): Promise<AccountKeyStatus | null> {
  const { data: deviceData, error: deviceError } = await client
    .from("messaging_devices")
    .select("id,user_id,trust_state,revoked_at,x25519_identity_public,mlkem_identity_public,ed25519_identity_public,mldsa_identity_public,identity_signature")
    .eq("user_id", userId);
  if (deviceError) throw deviceError;
  const deviceRows = (deviceData ?? []) as Array<DeviceRow & Record<string, unknown>>;
  const isTrusted = (row: DeviceRow) => !row.revoked_at && (row.trust_state === "trusted" || row.trust_state === "this_device" || row.id === deviceId);
  const trustedIds = deviceRows.filter(isTrusted).map((row) => String(row.id));
  const revokedIds = deviceRows.filter((row) => row.revoked_at || row.trust_state === "revoked").map((row) => String(row.id));
  const identityOf = (id: string): CallPeerIdentityPayload | null => {
    const row = deviceRows.find((candidate) => String(candidate.id) === id);
    return row ? callPeerIdentityFromRow(row) : null;
  };

  const { data: wrapData, error: wrapError } = await client
    .from("messaging_account_key_wraps")
    .select("id,from_device_id,to_device_id,epoch,wrap,accepted_at")
    .eq("user_id", userId);
  const tableReady = !wrapError || !tableMissing(wrapError);
  let wrapRows = ((wrapError ? [] : wrapData) ?? []) as Array<WrapRowLike & { id: string; wrap: unknown }>;

  // 1. Take in a key sealed to this device.
  for (const row of wrapRows) {
    if (String(row.to_device_id) !== deviceId || row.accepted_at) continue;
    const sender = identityOf(String(row.from_device_id));
    if (!sender) continue;
    try {
      await safeInvoke<AccountKeyStatus>("account_key_accept_wrap", { wrap: row.wrap, sender });
      // Delivered: blank the payload so a spent wrap does not sit on the relay.
      await client.from("messaging_account_key_wraps").update({ accepted_at: new Date().toISOString(), wrap: {} }).eq("id", row.id);
      row.accepted_at = new Date().toISOString();
    } catch {
      // Not from a device this device has recorded yet (or a conflict): leave it, try again later.
    }
  }

  let status = await safeInvoke<AccountKeyStatus>("account_key_status");

  // 2. First key.
  if (!status.available && shouldBootstrap({ selfId: deviceId, trustedIds, anyWrapRows: wrapRows.length > 0 })) {
    status = await safeInvoke<AccountKeyStatus>("account_key_bootstrap");
  }
  if (!status.available || status.currentEpoch === null || !tableReady) return status;

  // 3. A device that held the key is gone: start a new epoch it will never get.
  if (rotationDue({ selfId: deviceId, trustedIds, revokedIds, rows: wrapRows, currentEpoch: status.currentEpoch })) {
    status = await safeInvoke<AccountKeyStatus>("account_key_rotate");
  }
  const epoch = status.currentEpoch ?? 1;

  // 4. Send the key to the user's other trusted devices that lack it.
  for (const targetId of devicesNeedingWrap({ selfId: deviceId, trustedIds, rows: wrapRows, currentEpoch: epoch })) {
    const target = identityOf(targetId);
    if (!target) continue;
    try {
      const wrap = await safeInvoke<{ epoch: number }>("account_key_make_wrap", { target });
      const { error } = await client.from("messaging_account_key_wraps").upsert(
        { user_id: userId, from_device_id: deviceId, to_device_id: targetId, epoch: wrap.epoch, wrap, accepted_at: null },
        { onConflict: "to_device_id,epoch" },
      );
      if (!error) wrapRows = [...wrapRows, { id: "", from_device_id: deviceId, to_device_id: targetId, epoch: wrap.epoch, accepted_at: null, wrap }];
    } catch {
      // The core refuses a device it has not recorded as the user's own; that is retried on the next pass.
    }
  }
  return status;
}

/**
 * After the user removes one of their devices: start a new epoch now (rather
 * than at the next hourly pass) so the removed device never receives the key
 * that protects what is written next.
 */
export async function rotateAccountKeyAfterRemoval(client: SupabaseClient, userId: string, deviceId: string): Promise<void> {
  if (!isTauriRuntime()) return;
  try {
    const status = await safeInvoke<AccountKeyStatus>("account_key_status");
    if (!status.available) return;
    await safeInvoke<AccountKeyStatus>("account_key_rotate");
    await syncAccountKey(client, userId, deviceId);
  } catch {
    // Best effort: the next pass notices a revoked device that held the key and rotates.
  }
}
