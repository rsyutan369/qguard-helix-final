/**
 * How the open thread downloads its envelopes.
 *
 * One envelope row is about 27 KB on the wire: its `sealed_sender_envelope`
 * carries an ML-KEM-1024 ciphertext, an ML-DSA-65 signature and the sender's
 * public keys as JSON number arrays. The thread used to select 250 whole rows
 * in one request — roughly 7 MB — under a six-second deadline, and to repeat
 * that on every realtime event. On a phone that request did not finish inside
 * the deadline, so the pane stayed on "Loading encrypted history...".
 *
 * A row's body never changes after it is written (a delete only stamps
 * `deleted_at`, which removes the row from the listing). So the listing and the
 * bodies are fetched separately:
 *
 *   1. the INDEX — ids and addressing only, about 200 bytes a row;
 *   2. the BODIES — only for ids this session has not downloaded yet, in small
 *      chunks, the rows this device can open first.
 *
 * The first chunk paints the thread; a reload after a new message downloads one
 * or two rows instead of all of them.
 */

/** Columns of the listing. Small on purpose: this runs on every reload. */
export const ENVELOPE_INDEX_COLUMNS = "id,recipient_user_id,recipient_device_id,created_at";

/** Rows per body request — about 0.7 MB, which a slow phone link can carry. */
export const ENVELOPE_BODY_CHUNK_ROWS = 24;

export interface EnvelopeIndexEntry {
  id: string;
  recipient_user_id: string;
  recipient_device_id: string | null;
  created_at: string;
}

export function envelopeIndexEntry(row: Record<string, unknown>): EnvelopeIndexEntry {
  return {
    id: String(row.id),
    recipient_user_id: String(row.recipient_user_id),
    recipient_device_id: row.recipient_device_id ? String(row.recipient_device_id) : null,
    created_at: String(row.created_at),
  };
}

export interface LocalRecipient {
  userId: string;
  deviceId: string | null;
}

/**
 * Lower is fetched earlier.
 *
 *   0 — sealed to THIS device: the only copy it is expected to open;
 *   1 — sealed to another device of this account: a fallback candidate;
 *   2 — sealed to someone else: needed for bookkeeping, never for display.
 *
 * A message's copy for this device is therefore always present before any of
 * its other copies, so a partly downloaded thread never tries the wrong copy
 * of a message first.
 */
function fetchTier(entry: EnvelopeIndexEntry, local: LocalRecipient): number {
  if (entry.recipient_user_id !== local.userId) return 2;
  return local.deviceId && entry.recipient_device_id === local.deviceId ? 0 : 1;
}

/**
 * The body requests still needed for `index`, as chunks of ids in the order
 * they should be made. Ids already held are left out.
 */
export function planBodyFetch(
  index: EnvelopeIndexEntry[],
  held: (id: string) => boolean,
  local: LocalRecipient,
  chunkRows: number = ENVELOPE_BODY_CHUNK_ROWS,
): string[][] {
  const missing = index.filter((entry) => !held(entry.id));
  const ordered = missing
    .map((entry) => ({ entry, tier: fetchTier(entry, local) }))
    .sort((left, right) => (
      left.tier - right.tier
      || (left.entry.created_at < right.entry.created_at ? 1 : left.entry.created_at > right.entry.created_at ? -1 : 0)
    ));
  const size = Math.max(1, Math.floor(chunkRows));
  const chunks: string[][] = [];
  for (let start = 0; start < ordered.length; start += size) {
    chunks.push(ordered.slice(start, start + size).map(({ entry }) => entry.id));
  }
  return chunks;
}

/**
 * The envelope bodies already downloaded for ONE conversation.
 *
 * Scoped to a single conversation so the memory it holds is bounded by one
 * page of history: binding it to another conversation drops everything.
 */
export class EnvelopeBodyCache<Row extends { id: string }> {
  private conversationId: string | null = null;
  private rows = new Map<string, Row>();

  /** Point the cache at `conversationId`, emptying it if that is a change. */
  bind(conversationId: string): void {
    if (this.conversationId === conversationId) return;
    this.conversationId = conversationId;
    this.rows = new Map();
  }

  has(id: string): boolean {
    return this.rows.has(id);
  }

  store(conversationId: string, rows: Row[]): void {
    // A body that lands after the user has switched threads belongs to the
    // thread it was fetched for, not the one now bound.
    if (this.conversationId !== conversationId) return;
    for (const row of rows) this.rows.set(row.id, row);
  }

  /**
   * The held rows of `index`, in listing order, and forget every row the
   * listing no longer contains (deleted or expired on the relay).
   */
  resolve(conversationId: string, index: EnvelopeIndexEntry[]): Row[] {
    if (this.conversationId !== conversationId) return [];
    const listed = new Set(index.map((entry) => entry.id));
    for (const id of this.rows.keys()) {
      if (!listed.has(id)) this.rows.delete(id);
    }
    const resolved: Row[] = [];
    for (const entry of index) {
      const row = this.rows.get(entry.id);
      if (row) resolved.push(row);
    }
    return resolved;
  }

  clear(): void {
    this.conversationId = null;
    this.rows = new Map();
  }
}
