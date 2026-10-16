import type { SupabaseClient } from "@supabase/supabase-js";
import {
  envelopeKeyRequestFromRow,
  ledgerProbeFromRow,
  type EnvelopeKeyRequest,
  type EnvelopeKeyRow,
  type EnvelopeProbeRow,
  type LedgerProbe,
} from "@/lib/message-envelope-rows";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

/**
 * Prekey hygiene: what gives Secure Chat forward secrecy.
 *
 * Every envelope is sealed to the recipient device's signed prekey, and history
 * is re-read from the relay each time a conversation opens. A device therefore
 * used to keep every prekey it had ever published, which meant one copy of its
 * key file opened every message ever sent to it.
 *
 * Three steps, all decided by the Rust core from the device's real key material
 * (this module only carries rows between the relay and the core):
 *
 *   1. ROTATE   the published signed prekey once it is a day old.
 *   2. CATCH UP the message keys of every envelope still sealed to a retired
 *               prekey, into the device's encrypted message-key ledger — also
 *               for conversations the user has not opened.
 *   3. DESTROY  the retired prekeys whose envelopes are all accounted for.
 *
 * What that buys, exactly: once a retired prekey is destroyed, traffic recorded
 * from its day can no longer be opened with any device prekey. It is forward
 * secrecy per rotation period, not per message — messages sealed to the prekey
 * in use today share it until tomorrow's rotation.
 *
 * No plaintext passes through here: the catch-up command proves a key against
 * its ciphertext inside the core and returns only a status.
 */

/** Mirror of `commands::keys::PrekeyStatus`. */
export interface PrekeyStatus {
  signedPrekeyId: string | null;
  signedPrekeyCreatedAt: string | null;
  signedPrekeyAgeSeconds: number | null;
  rotationIntervalSeconds: number;
  rotationDue: boolean;
  rotationBlocked: boolean;
  retainedSignedPrekeys: number;
  oldestRetiredAt: string | null;
  retiredGraceSeconds: number;
  retiredQuietSeconds: number;
  pastGraceSignedPrekeyIds: string[];
  purgeableSignedPrekeyIds: string[];
  pastGraceOneTimePrekeyIds: string[];
  ledgerAvailable: boolean;
  ledgerEntries: number;
  /** Whether rotation and clean-up are really happening, and the core's words for it. */
  forwardSecrecyHealthy: boolean;
  forwardSecrecySummary: string;
}

/** Mirror of `commands::messaging::EnvelopeKeyOutcome`. */
export interface EnvelopeKeyOutcome {
  status: "cached" | "already_cached" | "unreadable";
  reason: string | null;
}

interface PrekeyPurgeOutcome {
  purgedSignedPrekeyIds: string[];
  purgedOneTimePrekeys: number;
  retainedSignedPrekeys: number;
}

export async function fetchPrekeyStatus(
  userId: string,
  claimedOneTimePrekeyIds: string[] = [],
): Promise<PrekeyStatus> {
  return safeInvoke<PrekeyStatus>("keys_prekey_status", {
    userId,
    claimedOneTimePrekeyIds: claimedOneTimePrekeyIds.length > 0 ? claimedOneTimePrekeyIds : null,
  });
}

/**
 * Replace the signed prekey if it has been the published one for a full
 * rotation period. Returns whether a new one was minted; the caller publishes
 * it (the existing signed-prekey sync does exactly that).
 *
 * Never throws: a rotation that cannot happen now must not stop the device
 * from registering — the current prekey simply stays in use a little longer.
 */
export async function rotateSignedPrekeyIfDue(userId: string): Promise<boolean> {
  if (!isTauriRuntime()) return false;
  try {
    const status = await fetchPrekeyStatus(userId);
    if (!status.rotationDue) return false;
    // `onlyIfDue` makes the core re-check the key's real age, so two passes
    // racing each other cannot mint two prekeys.
    await safeInvoke("keys_rotate_prekeys", { userId, onlyIfDue: true });
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Catch-up
// ---------------------------------------------------------------------------

/** Where the catch-up reads envelopes from and records keys to. */
export interface DrainSource {
  /** One page of live envelopes sealed to any of `prekeyIds`, ordered by id, strictly after `afterId`. */
  listPage(prekeyIds: string[], afterId: string | null, limit: number): Promise<EnvelopeProbeRow[]>;
  /** How many live envelopes are sealed to `prekeyIds` right now. */
  count(prekeyIds: string[]): Promise<number>;
  /** The full rows for these envelope ids. */
  fetchRows(ids: string[]): Promise<EnvelopeKeyRow[]>;
  /** For each probe, whether its key is already in the ledger. */
  lookup(probes: LedgerProbe[]): Promise<boolean[]>;
  /** Derive, prove and record one envelope's key. Rejects when it could not tell. */
  cacheKey(request: EnvelopeKeyRequest): Promise<EnvelopeKeyOutcome>;
}

export interface DrainBudget {
  /** Envelopes that may be listed in one pass. */
  maxScanned: number;
  /** Keys that may be derived in one pass (each is a hybrid decapsulation). */
  maxDerived: number;
  pageSize: number;
  fetchChunk: number;
}

export const DEFAULT_DRAIN_BUDGET: DrainBudget = {
  maxScanned: 6_000,
  maxDerived: 400,
  pageSize: 200,
  fetchChunk: 20,
};

export type DrainStop = "done" | "budget" | "changed_during_scan";

export interface DrainReport {
  /**
   * True only when every live envelope sealed to these prekeys was seen and
   * its key is recorded or it is permanently unreadable. Anything short of
   * that is false, and a prekey must not be destroyed on the strength of it.
   */
  complete: boolean;
  stoppedBecause: DrainStop;
  scanned: number;
  derived: number;
  alreadyRecorded: number;
  unreadable: number;
}

/**
 * Walk every envelope sealed to `prekeyIds` and make sure its message key is in
 * the ledger.
 *
 * Progress is monotonic without a cursor: keys recorded by an earlier pass are
 * skipped by the ledger lookup, so a pass that runs out of budget is simply
 * continued by the next one.
 *
 * Any rejected step propagates. "Could not tell" must never be mistaken for
 * "nothing left to do" — the caller would go on to destroy a prekey.
 */
export async function drainPrekeyBatch(
  prekeyIds: string[],
  source: DrainSource,
  budget: DrainBudget = DEFAULT_DRAIN_BUDGET,
  spent: { scanned: number; derived: number } = { scanned: 0, derived: 0 },
): Promise<DrainReport> {
  const report: DrainReport = {
    complete: false,
    stoppedBecause: "done",
    scanned: 0,
    derived: 0,
    alreadyRecorded: 0,
    unreadable: 0,
  };
  if (prekeyIds.length === 0) return { ...report, complete: true };

  let afterId: string | null = null;
  let vanished = 0;
  for (;;) {
    if (spent.scanned >= budget.maxScanned) return { ...report, stoppedBecause: "budget" };
    const page = await source.listPage(prekeyIds, afterId, budget.pageSize);
    if (page.length === 0) break;
    report.scanned += page.length;
    spent.scanned += page.length;

    const known = await source.lookup(page.map(ledgerProbeFromRow));
    if (known.length !== page.length) {
      throw new Error("message key lookup returned a different number of answers than envelopes");
    }
    const missing = page.filter((_row, index) => !known[index]).map((row) => String(row.id));
    report.alreadyRecorded += page.length - missing.length;

    for (let start = 0; start < missing.length; start += budget.fetchChunk) {
      if (spent.derived >= budget.maxDerived) return { ...report, stoppedBecause: "budget" };
      const chunk = missing.slice(start, start + budget.fetchChunk);
      const rows = await source.fetchRows(chunk);
      // A row listed a moment ago and gone now was deleted in between. The
      // final count below would catch it too; this just says so sooner.
      vanished += chunk.length - rows.length;
      for (const row of rows) {
        const outcome = await source.cacheKey(envelopeKeyRequestFromRow(row));
        spent.derived += 1;
        if (outcome.status === "cached") report.derived += 1;
        else if (outcome.status === "already_cached") report.alreadyRecorded += 1;
        else report.unreadable += 1;
      }
    }

    afterId = String(page[page.length - 1].id);
    if (page.length < budget.pageSize) break;
  }

  // Envelopes can arrive (or be deleted) while the walk is in progress, and a
  // new row's id can sort before the cursor. If what the relay holds now is
  // not exactly what was walked, the walk proves nothing yet.
  const total = await source.count(prekeyIds);
  if (vanished > 0 || total !== report.scanned) {
    return { ...report, stoppedBecause: "changed_during_scan" };
  }
  return { ...report, complete: true };
}

export function chunkIds(ids: string[], size: number): string[][] {
  const chunks: string[][] = [];
  for (let start = 0; start < ids.length; start += Math.max(1, size)) {
    chunks.push(ids.slice(start, start + Math.max(1, size)));
  }
  return chunks;
}

const ENVELOPE_TABLE = "messaging_message_envelopes";
const PREKEY_ID_PATH = "sealed_sender_envelope->>prekey_id";
const PROBE_COLUMNS = "id,nonce,auth_tag,aad";
const KEY_COLUMNS =
  "id,conversation_id,sender_user_id,sender_device_id,recipient_user_id,recipient_device_id,sealed_sender_envelope,ciphertext,nonce,auth_tag,aad,ratchet_counter";

/** The live relay + this device's Rust core. */
export function relayDrainSource(client: SupabaseClient, userId: string): DrainSource {
  return {
    async listPage(prekeyIds, afterId, limit) {
      let query = client
        .from(ENVELOPE_TABLE)
        .select(PROBE_COLUMNS)
        .eq("recipient_user_id", userId)
        .is("deleted_at", null)
        .in(PREKEY_ID_PATH, prekeyIds)
        .order("id", { ascending: true })
        .limit(limit);
      if (afterId) query = query.gt("id", afterId);
      const { data, error } = await query;
      if (error) throw error;
      return (data ?? []) as EnvelopeProbeRow[];
    },
    async count(prekeyIds) {
      const { count, error } = await client
        .from(ENVELOPE_TABLE)
        .select("id", { count: "exact", head: true })
        .eq("recipient_user_id", userId)
        .is("deleted_at", null)
        .in(PREKEY_ID_PATH, prekeyIds);
      if (error) throw error;
      if (typeof count !== "number") throw new Error("the relay did not return an envelope count");
      return count;
    },
    async fetchRows(ids) {
      const { data, error } = await client
        .from(ENVELOPE_TABLE)
        .select(KEY_COLUMNS)
        .eq("recipient_user_id", userId)
        .is("deleted_at", null)
        .in("id", ids);
      if (error) throw error;
      return (data ?? []) as EnvelopeKeyRow[];
    },
    lookup(probes) {
      return safeInvoke<boolean[]>("messaging_message_keys_lookup", { userId, items: probes });
    },
    cacheKey(request) {
      return safeInvoke<EnvelopeKeyOutcome>("messaging_cache_envelope_key", { request });
    },
  };
}

/**
 * One-time prekeys of this device that the relay shows as claimed long enough
 * ago to clean up. Only builds older than this one claim them, so this list
 * shrinks to nothing as peers update. Best effort: an empty list just means no
 * one-time prekey is cleaned up this pass.
 */
async function claimedOneTimePrekeyIds(
  client: SupabaseClient,
  userId: string,
  deviceId: string,
  graceSeconds: number,
): Promise<string[]> {
  try {
    const cutoff = new Date(Date.now() - graceSeconds * 1000).toISOString();
    const { data, error } = await client
      .from("messaging_one_time_prekeys")
      .select("id")
      .eq("user_id", userId)
      .eq("device_id", deviceId)
      .lt("consumed_at", cutoff)
      .order("consumed_at", { ascending: true })
      .limit(200);
    if (error) return [];
    return ((data ?? []) as Array<{ id: unknown }>).map((row) => String(row.id));
  } catch {
    return [];
  }
}

/** How many deleted envelopes one pass reconciles. */
const DELETED_RECONCILE_LIMIT = 1_000;

/**
 * Destroy the recorded keys of messages that were deleted on the relay while
 * this device was not looking. (A deletion seen live is handled on the spot by
 * Secure Chat.) Returns how many keys were destroyed.
 *
 * `sinceIso` bounds the read to deletions after the last pass that completed;
 * without it the newest deletions are checked. Ids the ledger never held are
 * simply not counted, so repeating this is harmless.
 */
export async function forgetDeletedMessageKeys(
  client: SupabaseClient,
  userId: string,
  sinceIso: string | null,
): Promise<number> {
  let query = client
    .from(ENVELOPE_TABLE)
    .select("id")
    .eq("recipient_user_id", userId)
    .not("deleted_at", "is", null)
    .order("deleted_at", { ascending: false })
    .limit(DELETED_RECONCILE_LIMIT);
  if (sinceIso) query = query.gt("deleted_at", sinceIso);
  const { data, error } = await query;
  if (error) throw error;
  const messageIds = ((data ?? []) as Array<{ id: unknown }>).map((row) => String(row.id));
  if (messageIds.length === 0) return 0;
  return safeInvoke<number>("messaging_forget_message_keys", { userId, messageIds });
}

export interface HygieneReport {
  /** Why nothing was done, when nothing was. */
  skipped: "not_desktop" | "ledger_unavailable" | "nothing_retired" | null;
  /** Recorded keys destroyed because their message was deleted on the relay. */
  forgottenDeletedKeys: number;
  drain: DrainReport | null;
  /** Retired prekeys whose envelopes are all accounted for after this pass. */
  drainedPrekeys: number;
  purgedSignedPrekeys: number;
  purgedOneTimePrekeys: number;
  /** Retired signed prekeys still held after this pass. */
  retainedSignedPrekeys: number | null;
}

/** How many prekey ids go into one relay query. */
const DRAIN_BATCH_IDS = 20;

/**
 * One full pass: catch up the keys of everything sealed to retired prekeys that
 * are past their grace period, then ask the core to destroy the ones that are
 * fully accounted for. Rejects if a step could not complete; nothing is
 * destroyed in that case.
 */
export async function runPrekeyHygiene(
  client: SupabaseClient,
  userId: string,
  deviceId: string,
  budget: DrainBudget = DEFAULT_DRAIN_BUDGET,
  deletedSinceIso: string | null = null,
): Promise<HygieneReport> {
  const empty: HygieneReport = {
    skipped: null,
    forgottenDeletedKeys: 0,
    drain: null,
    drainedPrekeys: 0,
    purgedSignedPrekeys: 0,
    purgedOneTimePrekeys: 0,
    retainedSignedPrekeys: null,
  };
  if (!isTauriRuntime()) return { ...empty, skipped: "not_desktop" };

  const first = await fetchPrekeyStatus(userId);
  if (!first.ledgerAvailable) {
    return { ...empty, skipped: "ledger_unavailable", retainedSignedPrekeys: first.retainedSignedPrekeys };
  }
  // Before anything is caught up: a key for a deleted message is the one thing
  // here that should be leaving the ledger rather than entering it.
  empty.forgottenDeletedKeys = await forgetDeletedMessageKeys(client, userId, deletedSinceIso);

  const claimed = await claimedOneTimePrekeyIds(client, userId, deviceId, first.retiredGraceSeconds);
  const status = claimed.length > 0 ? await fetchPrekeyStatus(userId, claimed) : first;

  const signedIds = status.pastGraceSignedPrekeyIds;
  const oneTimeIds = status.pastGraceOneTimePrekeyIds;
  if (signedIds.length === 0 && oneTimeIds.length === 0) {
    return { ...empty, skipped: "nothing_retired", retainedSignedPrekeys: status.retainedSignedPrekeys };
  }

  const source = relayDrainSource(client, userId);
  const spent = { scanned: 0, derived: 0 };
  const total: DrainReport = {
    complete: true,
    stoppedBecause: "done",
    scanned: 0,
    derived: 0,
    alreadyRecorded: 0,
    unreadable: 0,
  };
  const drained = new Set<string>();
  for (const batch of chunkIds([...signedIds, ...oneTimeIds], DRAIN_BATCH_IDS)) {
    const report = await drainPrekeyBatch(batch, source, budget, spent);
    total.scanned += report.scanned;
    total.derived += report.derived;
    total.alreadyRecorded += report.alreadyRecorded;
    total.unreadable += report.unreadable;
    if (report.complete) {
      batch.forEach((id) => drained.add(id));
    } else {
      total.complete = false;
      total.stoppedBecause = report.stoppedBecause;
      // Out of budget: the remaining batches wait for the next pass.
      if (report.stoppedBecause === "budget") break;
    }
  }

  const result: HygieneReport = {
    ...empty,
    drain: total,
    drainedPrekeys: drained.size,
    retainedSignedPrekeys: status.retainedSignedPrekeys,
  };
  if (drained.size === 0) {
    // Still worth saving what this pass recorded.
    await safeInvoke<boolean>("messaging_flush_message_keys", { userId });
    return result;
  }

  // The core re-checks age and quiet period itself and flushes the ledger
  // before destroying anything; this only tells it which prekeys were walked.
  const outcome = await safeInvoke<PrekeyPurgeOutcome>("keys_purge_retired_prekeys", {
    userId,
    drainedSignedPrekeyIds: signedIds.filter((id) => drained.has(id)),
    drainedOneTimePrekeyIds: oneTimeIds.filter((id) => drained.has(id)),
  });
  return {
    ...result,
    purgedSignedPrekeys: outcome.purgedSignedPrekeyIds.length,
    purgedOneTimePrekeys: outcome.purgedOneTimePrekeys,
    retainedSignedPrekeys: outcome.retainedSignedPrekeys,
  };
}

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

/** A finished pass is not repeated sooner than this. */
export const HYGIENE_INTERVAL_MS = 6 * 60 * 60 * 1000;
/** A pass that ran out of budget, or failed, is continued after this. */
export const HYGIENE_RETRY_MS = 15 * 60 * 1000;

const hygieneInFlight = new Map<string, Promise<void>>();
const hygieneNextRun = new Map<string, number>();

function nextRunStorageKey(userId: string, deviceId: string): string {
  return `qguard.prekey-hygiene.next.v1.${userId}.${deviceId}`;
}

function readNextRun(userId: string, deviceId: string): number {
  const remembered = hygieneNextRun.get(`${userId}.${deviceId}`);
  if (remembered !== undefined) return remembered;
  try {
    const stored = Number(window.localStorage.getItem(nextRunStorageKey(userId, deviceId)));
    return Number.isFinite(stored) ? stored : 0;
  } catch {
    return 0;
  }
}

function writeNextRun(userId: string, deviceId: string, at: number): void {
  hygieneNextRun.set(`${userId}.${deviceId}`, at);
  try {
    window.localStorage.setItem(nextRunStorageKey(userId, deviceId), String(at));
  } catch {
    // The in-memory value still throttles this session.
  }
}

const DELETED_RECONCILE_OVERLAP_MS = 60 * 60 * 1000;

function deletedSinceStorageKey(userId: string, deviceId: string): string {
  return `qguard.prekey-hygiene.deleted-since.v1.${userId}.${deviceId}`;
}

function readDeletedSince(userId: string, deviceId: string): string | null {
  try {
    const stored = Number(window.localStorage.getItem(deletedSinceStorageKey(userId, deviceId)));
    return Number.isFinite(stored) && stored > 0 ? new Date(stored).toISOString() : null;
  } catch {
    return null;
  }
}

function writeDeletedSince(userId: string, deviceId: string, at: number): void {
  try {
    window.localStorage.setItem(deletedSinceStorageKey(userId, deviceId), String(at));
  } catch {
    // Without it the next pass just re-checks the newest deletions.
  }
}

/** When the next pass should run, given how this one ended. */
export function nextHygieneDelayMs(report: HygieneReport | null): number {
  if (!report) return HYGIENE_RETRY_MS;
  if (report.skipped === "ledger_unavailable") return HYGIENE_RETRY_MS;
  if (report.drain && !report.drain.complete) return HYGIENE_RETRY_MS;
  return HYGIENE_INTERVAL_MS;
}

/**
 * Start a hygiene pass in the background if one is due. Never throws and never
 * blocks the caller: device registration and message delivery do not wait on
 * it, and a failed pass only postpones the clean-up.
 */
export function schedulePrekeyHygiene(client: SupabaseClient, userId: string, deviceId: string): void {
  if (!isTauriRuntime() || !deviceId) return;
  const slot = `${userId}.${deviceId}`;
  if (hygieneInFlight.has(slot)) return;
  if (Date.now() < readNextRun(userId, deviceId)) return;
  // Claim the slot before the first await so a second trigger backs off even
  // if this pass is slow to start.
  const startedAt = Date.now();
  writeNextRun(userId, deviceId, startedAt + HYGIENE_RETRY_MS);

  const pass = runPrekeyHygiene(client, userId, deviceId, DEFAULT_DRAIN_BUDGET, readDeletedSince(userId, deviceId))
    .then((report) => {
      writeNextRun(userId, deviceId, Date.now() + nextHygieneDelayMs(report));
      // Deletions up to the start of this pass are reconciled; the next one
      // re-reads a little before that so clock skew cannot open a gap.
      if (report.skipped !== "ledger_unavailable" && report.skipped !== "not_desktop") {
        writeDeletedSince(userId, deviceId, startedAt - DELETED_RECONCILE_OVERLAP_MS);
      }
    })
    .catch(() => {
      writeNextRun(userId, deviceId, Date.now() + nextHygieneDelayMs(null));
    })
    .finally(() => {
      hygieneInFlight.delete(slot);
    });
  hygieneInFlight.set(slot, pass);
}
