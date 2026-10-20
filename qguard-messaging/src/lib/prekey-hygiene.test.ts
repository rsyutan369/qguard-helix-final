import { describe, expect, it } from "vitest";
import { bytesToBytea } from "@/lib/encoding";
import {
  envelopeKeyRequestFromRow,
  ledgerProbeFromRow,
  type EnvelopeKeyRequest,
  type EnvelopeKeyRow,
  type LedgerProbe,
} from "@/lib/message-envelope-rows";
import {
  chunkIds,
  drainPrekeyBatch,
  HYGIENE_INTERVAL_MS,
  HYGIENE_RETRY_MS,
  nextHygieneDelayMs,
  type DrainBudget,
  type DrainSource,
  type EnvelopeKeyOutcome,
  type HygieneReport,
} from "@/lib/prekey-hygiene";

const PREKEY = "0b0f5b56-6f0c-4f0e-9a44-3d0f1a8a1c01";

/** Exactly the layout written by `message_crypto::message_aad` in Rust. */
function aad(messageId: string, recipientDeviceId = "device-b", counter = 0): string {
  const text = ["QGM1", messageId, "conv-1", "user-a", "user-b", "device-a", recipientDeviceId, String(counter)].join("|");
  return bytesToBytea(Array.from(new TextEncoder().encode(text)));
}

function row(index: number, overrides: Partial<EnvelopeKeyRow> = {}): EnvelopeKeyRow {
  const id = `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
  return {
    id,
    conversation_id: "conv-1",
    sender_user_id: "user-a",
    recipient_user_id: "user-b",
    sender_device_id: "device-a",
    recipient_device_id: "device-b",
    ratchet_counter: 0,
    ciphertext: bytesToBytea([index & 0xff, 2, 3]),
    nonce: bytesToBytea(Array.from({ length: 12 }, (_unused, at) => (index + at) & 0xff)),
    auth_tag: bytesToBytea(Array.from({ length: 16 }, (_unused, at) => (index * 7 + at) & 0xff)),
    aad: aad(id),
    sealed_sender_envelope: {
      prekey_id: PREKEY,
      prekey_kind: "signed_prekey",
      hybrid_ciphertext: { x25519_ephemeral_public: [1, 2], ml_kem_ciphertext: [3, 4], suite: { kem_combiner: "QGuard-HybridKEM-v2" } },
    },
    ...overrides,
  };
}

/** An in-memory relay + ledger that behaves like the real pair. */
function fakeSource(rows: EnvelopeKeyRow[], options: {
  recorded?: Set<string>;
  outcome?: (request: EnvelopeKeyRequest) => EnvelopeKeyOutcome | Promise<EnvelopeKeyOutcome>;
  onListPage?: (page: number) => void;
} = {}) {
  const recorded = options.recorded ?? new Set<string>();
  const live = [...rows];
  const calls = { listPage: 0, fetchRows: 0, lookup: 0, cacheKey: [] as string[] };
  const source: DrainSource = {
    async listPage(_prekeyIds, afterId, limit) {
      calls.listPage += 1;
      options.onListPage?.(calls.listPage);
      return live
        .map((item) => ({ id: item.id, nonce: item.nonce, auth_tag: item.auth_tag, aad: item.aad }))
        .sort((left, right) => String(left.id).localeCompare(String(right.id)))
        .filter((item) => afterId === null || String(item.id) > afterId)
        .slice(0, limit);
    },
    async count() {
      return live.length;
    },
    async fetchRows(ids) {
      calls.fetchRows += 1;
      return live.filter((item) => ids.includes(String(item.id)));
    },
    async lookup(probes: LedgerProbe[]) {
      calls.lookup += 1;
      return probes.map((probe) => recorded.has(probe.messageId));
    },
    async cacheKey(request) {
      calls.cacheKey.push(request.message_id);
      const outcome = await (options.outcome?.(request) ?? { status: "cached", reason: null });
      if (outcome.status !== "unreadable") recorded.add(request.message_id);
      return outcome;
    },
  };
  return { source, calls, recorded, live };
}

const SMALL: DrainBudget = { maxScanned: 1_000, maxDerived: 1_000, pageSize: 4, fetchChunk: 3 };

describe("drainPrekeyBatch", () => {
  it("records a key for every envelope and only then reports complete", async () => {
    const rows = Array.from({ length: 10 }, (_unused, index) => row(index + 1));
    const { source, calls, recorded } = fakeSource(rows);

    const report = await drainPrekeyBatch([PREKEY], source, SMALL);

    expect(report).toMatchObject({ complete: true, stoppedBecause: "done", scanned: 10, derived: 10, alreadyRecorded: 0, unreadable: 0 });
    expect(recorded.size).toBe(10);
    // 10 rows at 4 per page: three pages, the last one short.
    expect(calls.listPage).toBe(3);
  });

  it("does not fetch or re-derive envelopes whose key is already recorded", async () => {
    const rows = Array.from({ length: 6 }, (_unused, index) => row(index + 1));
    const recorded = new Set(rows.slice(0, 4).map((item) => String(item.id)));
    const { source, calls } = fakeSource(rows, { recorded });

    const report = await drainPrekeyBatch([PREKEY], source, SMALL);

    expect(report).toMatchObject({ complete: true, scanned: 6, derived: 2, alreadyRecorded: 4 });
    expect(calls.cacheKey).toHaveLength(2);
  });

  it("is complete with nothing to do when no envelope is sealed to the prekeys", async () => {
    const { source, calls } = fakeSource([]);
    const report = await drainPrekeyBatch([PREKEY], source, SMALL);
    expect(report).toMatchObject({ complete: true, scanned: 0, derived: 0 });
    expect(calls.cacheKey).toHaveLength(0);
  });

  it("treats a permanently unreadable envelope as accounted for", async () => {
    const rows = [row(1), row(2), row(3)];
    const { source } = fakeSource(rows, {
      outcome: (request) => request.message_id === String(rows[1].id)
        ? { status: "unreadable", reason: "crypto error: authentication failed" }
        : { status: "cached", reason: null },
    });

    const report = await drainPrekeyBatch([PREKEY], source, SMALL);

    expect(report).toMatchObject({ complete: true, derived: 2, unreadable: 1 });
  });

  it("propagates a failed key derivation instead of calling the walk complete", async () => {
    const rows = [row(1), row(2), row(3)];
    const { source } = fakeSource(rows, {
      outcome: (request) => {
        if (request.message_id === String(rows[1].id)) throw new Error("storage error: keychain unavailable");
        return { status: "cached", reason: null };
      },
    });

    await expect(drainPrekeyBatch([PREKEY], source, SMALL)).rejects.toThrow("keychain unavailable");
  });

  it("stops incomplete when the derivation budget runs out, and the next pass finishes the job", async () => {
    const rows = Array.from({ length: 9 }, (_unused, index) => row(index + 1));
    const { source, recorded } = fakeSource(rows);
    const tight: DrainBudget = { ...SMALL, maxDerived: 4 };

    const first = await drainPrekeyBatch([PREKEY], source, tight);
    expect(first.complete).toBe(false);
    expect(first.stoppedBecause).toBe("budget");
    expect(recorded.size).toBeGreaterThan(0);
    expect(recorded.size).toBeLessThan(9);

    // Nothing is remembered between passes except what the ledger holds.
    let pass = first;
    for (let attempt = 0; attempt < 5 && !pass.complete; attempt += 1) {
      pass = await drainPrekeyBatch([PREKEY], source, tight);
    }
    expect(pass.complete).toBe(true);
    expect(recorded.size).toBe(9);
  });

  it("stops incomplete when the scan budget runs out", async () => {
    const rows = Array.from({ length: 12 }, (_unused, index) => row(index + 1));
    const { source } = fakeSource(rows);
    const report = await drainPrekeyBatch([PREKEY], source, { ...SMALL, maxScanned: 4 });
    expect(report).toMatchObject({ complete: false, stoppedBecause: "budget", scanned: 4 });
  });

  it("shares one budget across batches", async () => {
    const rows = Array.from({ length: 6 }, (_unused, index) => row(index + 1));
    const { source } = fakeSource(rows);
    const spent = { scanned: 0, derived: 0 };
    const budget: DrainBudget = { ...SMALL, maxDerived: 6 };

    const first = await drainPrekeyBatch([PREKEY], source, budget, spent);
    expect(first.complete).toBe(true);
    expect(spent.derived).toBe(6);

    // A second batch finds the budget already used up by the first.
    const second = fakeSource([row(101), row(102)]);
    const report = await drainPrekeyBatch(["another-prekey"], second.source, budget, spent);
    expect(report).toMatchObject({ complete: false, stoppedBecause: "budget", derived: 0 });
  });

  it("is not complete when an envelope arrives behind the cursor during the walk", async () => {
    const rows = Array.from({ length: 8 }, (_unused, index) => row(index + 10));
    const state = fakeSource(rows, {
      onListPage: (page) => {
        // After the first page has been read, a new envelope lands whose id
        // sorts BEFORE everything already walked.
        if (page === 2) state.live.push(row(1));
      },
    });

    const report = await drainPrekeyBatch([PREKEY], state.source, SMALL);

    expect(report.complete).toBe(false);
    expect(report.stoppedBecause).toBe("changed_during_scan");
    // The next pass sees it.
    const retry = await drainPrekeyBatch([PREKEY], state.source, SMALL);
    expect(retry.complete).toBe(true);
    expect(state.recorded.has(String(row(1).id))).toBe(true);
  });

  it("is not complete when an envelope disappears between listing and fetching", async () => {
    const rows = [row(1), row(2), row(3)];
    const state = fakeSource(rows);
    const fetchRows = state.source.fetchRows;
    state.source.fetchRows = async (ids) => {
      state.live.splice(state.live.findIndex((item) => item.id === rows[2].id), 1);
      return fetchRows(ids);
    };

    const report = await drainPrekeyBatch([PREKEY], state.source, SMALL);

    expect(report.complete).toBe(false);
    expect(report.stoppedBecause).toBe("changed_during_scan");
  });

  it("refuses a lookup answer that does not line up with the envelopes asked about", async () => {
    const { source } = fakeSource([row(1), row(2)]);
    source.lookup = async () => [true];
    await expect(drainPrekeyBatch([PREKEY], source, SMALL)).rejects.toThrow("different number of answers");
  });
});

describe("envelope row views", () => {
  it("keys the ledger probe by the signed message id, not the row id", () => {
    const signedId = "11111111-1111-4111-8111-111111111111";
    const probe = ledgerProbeFromRow({ ...row(5), id: "row-id-that-differs", aad: aad(signedId) });
    expect(probe.messageId).toBe(signedId);
    expect(probe.nonce).toHaveLength(12);
    expect(probe.tag).toHaveLength(16);
  });

  it("falls back to the row id when the AAD is unreadable", () => {
    const probe = ledgerProbeFromRow({ ...row(5), aad: null });
    expect(probe.messageId).toBe(String(row(5).id));
  });

  it("builds a key request from the signed fields and carries no signature material", () => {
    // The device columns were nulled by a device clean-up; the AAD still has
    // what the sender signed.
    const request = envelopeKeyRequestFromRow({
      ...row(7, { sender_device_id: null, recipient_device_id: null, ratchet_counter: 99 }),
      aad: aad(String(row(7).id), "device-b", 3),
    });

    expect(request).toMatchObject({
      message_id: String(row(7).id),
      conversation_id: "conv-1",
      sender_user_id: "user-a",
      recipient_user_id: "user-b",
      sender_device_id: "device-a",
      recipient_device_id: "device-b",
      counter: 3,
      prekey_id: PREKEY,
      prekey_kind: "signed_prekey",
    });
    expect(request.hybrid_ciphertext).toEqual({
      x25519_ephemeral_public: [1, 2],
      ml_kem_ciphertext: [3, 4],
      suite: { kem_combiner: "QGuard-HybridKEM-v2" },
    });
    expect(Object.keys(request).sort()).toEqual([
      "aad", "conversation_id", "counter", "envelope", "hybrid_ciphertext", "message_id", "prekey_id",
      "prekey_kind", "recipient_device_id", "recipient_user_id", "sender_device_id", "sender_user_id",
    ]);
  });

  it("defaults the prekey kind for rows written before it was recorded", () => {
    const request = envelopeKeyRequestFromRow(row(8, { sealed_sender_envelope: { prekey_id: PREKEY } }));
    expect(request.prekey_kind).toBe("signed_prekey");
    // No encapsulation on the row: the core is told so (null), never handed
    // an empty placeholder it would fail to decode.
    expect(request.hybrid_ciphertext).toBeNull();
  });

  it("carries a ratchet seed's header, and nothing extra for a one-shot row", () => {
    const header = { v: 1, kind: "init", session: "ab".repeat(16), dh: [1, 2], pn: 0, n: 0 };
    const seeded = envelopeKeyRequestFromRow(row(9, {
      sealed_sender_envelope: {
        prekey_id: PREKEY,
        prekey_kind: "signed_prekey",
        hybrid_ciphertext: { x25519_ephemeral_public: [1], ml_kem_ciphertext: [2], suite: {} },
        ratchet: header,
      },
    }));
    expect(seeded.ratchet).toEqual(header);
    expect(seeded.hybrid_ciphertext?.ml_kem_ciphertext).toEqual([2]);
    const ordinary = envelopeKeyRequestFromRow(row(10, {
      sealed_sender_envelope: { prekey_id: "", prekey_kind: "", hybrid_ciphertext: null, ratchet: { ...header, kind: "msg" } },
    }));
    expect(ordinary.hybrid_ciphertext).toBeNull();
    expect(ordinary.prekey_id).toBe("");
    expect(envelopeKeyRequestFromRow(row(11))).not.toHaveProperty("ratchet");
  });
});

describe("scheduling", () => {
  const base: HygieneReport = {
    skipped: null,
    forgottenDeletedKeys: 0,
    drain: null,
    drainedPrekeys: 0,
    purgedSignedPrekeys: 0,
    purgedOneTimePrekeys: 0,
    retainedSignedPrekeys: 0,
  };
  const drain = { complete: true, stoppedBecause: "done" as const, scanned: 0, derived: 0, alreadyRecorded: 0, unreadable: 0 };

  it("waits the full interval after a pass that finished", () => {
    expect(nextHygieneDelayMs({ ...base, skipped: "nothing_retired" })).toBe(HYGIENE_INTERVAL_MS);
    expect(nextHygieneDelayMs({ ...base, drain })).toBe(HYGIENE_INTERVAL_MS);
  });

  it("comes back soon after a pass that failed, ran out of budget, or had no ledger", () => {
    expect(nextHygieneDelayMs(null)).toBe(HYGIENE_RETRY_MS);
    expect(nextHygieneDelayMs({ ...base, skipped: "ledger_unavailable" })).toBe(HYGIENE_RETRY_MS);
    expect(nextHygieneDelayMs({ ...base, drain: { ...drain, complete: false, stoppedBecause: "budget" } })).toBe(HYGIENE_RETRY_MS);
  });

  it("chunks ids without losing or repeating any", () => {
    const ids = Array.from({ length: 45 }, (_unused, index) => `id-${index}`);
    const chunks = chunkIds(ids, 20);
    expect(chunks.map((chunk) => chunk.length)).toEqual([20, 20, 5]);
    expect(chunks.flat()).toEqual(ids);
    expect(chunkIds([], 20)).toEqual([]);
    // A nonsensical size must not loop forever.
    expect(chunkIds(["a", "b"], 0)).toEqual([["a"], ["b"]]);
  });
});
