import { describe, expect, it } from "vitest";
import {
  EnvelopeBodyCache,
  envelopeIndexEntry,
  planBodyFetch,
  type EnvelopeIndexEntry,
} from "@/lib/envelope-history";

const ME = "user-me";
const PEER = "user-peer";
const THIS_DEVICE = "device-here";
const OTHER_DEVICE = "device-elsewhere";
const LOCAL = { userId: ME, deviceId: THIS_DEVICE };

function entry(id: string, minute: number, recipientUser = ME, recipientDevice: string | null = THIS_DEVICE): EnvelopeIndexEntry {
  return {
    id,
    recipient_user_id: recipientUser,
    recipient_device_id: recipientDevice,
    created_at: `2026-10-13T08:${String(minute).padStart(2, "0")}:00+00:00`,
  };
}

describe("envelopeIndexEntry", () => {
  it("reads a listing row and keeps a missing device as null", () => {
    expect(envelopeIndexEntry({ id: 7, recipient_user_id: ME, recipient_device_id: null, created_at: "t" })).toEqual({
      id: "7",
      recipient_user_id: ME,
      recipient_device_id: null,
      created_at: "t",
    });
  });
});

describe("planBodyFetch", () => {
  it("asks for nothing when every listed row is already held", () => {
    const index = [entry("a", 1), entry("b", 2)];
    expect(planBodyFetch(index, () => true, LOCAL)).toEqual([]);
  });

  it("asks only for the rows that are not held", () => {
    const index = [entry("new", 3), entry("old-1", 2), entry("old-2", 1)];
    const held = new Set(["old-1", "old-2"]);
    expect(planBodyFetch(index, (id) => held.has(id), LOCAL)).toEqual([["new"]]);
  });

  it("fetches this device's copies first, then this account's, then everyone else's", () => {
    const index = [
      entry("peer-newest", 9, PEER, "device-peer"),
      entry("mine-elsewhere", 8, ME, OTHER_DEVICE),
      entry("mine-here-old", 1),
      entry("mine-here-new", 7),
    ];
    expect(planBodyFetch(index, () => false, LOCAL, 10)).toEqual([
      ["mine-here-new", "mine-here-old", "mine-elsewhere", "peer-newest"],
    ]);
  });

  it("orders newest first inside a tier and splits into chunks", () => {
    const index = [entry("m1", 1), entry("m3", 3), entry("m2", 2), entry("m5", 5), entry("m4", 4)];
    expect(planBodyFetch(index, () => false, LOCAL, 2)).toEqual([["m5", "m4"], ["m3", "m2"], ["m1"]]);
  });

  it("never puts another copy of a message ahead of this device's copy", () => {
    // Two copies of each message: one for this device, one for another device
    // of the same account. Every chunk boundary must leave this device's copy
    // on the earlier side.
    const index: EnvelopeIndexEntry[] = [];
    for (let minute = 1; minute <= 6; minute += 1) {
      index.push(entry(`here-${minute}`, minute));
      index.push(entry(`elsewhere-${minute}`, minute, ME, OTHER_DEVICE));
    }
    const order = planBodyFetch(index, () => false, LOCAL, 4).flat();
    for (let minute = 1; minute <= 6; minute += 1) {
      expect(order.indexOf(`here-${minute}`)).toBeLessThan(order.indexOf(`elsewhere-${minute}`));
    }
  });

  it("treats every own copy alike when this device has no id yet", () => {
    const index = [entry("a", 1, ME, OTHER_DEVICE), entry("b", 2), entry("c", 3, PEER, "device-peer")];
    expect(planBodyFetch(index, () => false, { userId: ME, deviceId: null }, 10)).toEqual([["b", "a", "c"]]);
  });

  it("does not loop forever on a nonsensical chunk size", () => {
    expect(planBodyFetch([entry("a", 1), entry("b", 2)], () => false, LOCAL, 0)).toEqual([["b"], ["a"]]);
  });
});

describe("EnvelopeBodyCache", () => {
  it("returns held rows in listing order", () => {
    const cache = new EnvelopeBodyCache<{ id: string }>();
    cache.bind("conv-1");
    cache.store("conv-1", [{ id: "a" }, { id: "b" }]);
    expect(cache.resolve("conv-1", [entry("b", 2), entry("a", 1)])).toEqual([{ id: "b" }, { id: "a" }]);
  });

  it("leaves out listed rows whose body has not arrived", () => {
    const cache = new EnvelopeBodyCache<{ id: string }>();
    cache.bind("conv-1");
    cache.store("conv-1", [{ id: "a" }]);
    expect(cache.resolve("conv-1", [entry("b", 2), entry("a", 1)])).toEqual([{ id: "a" }]);
  });

  it("forgets a row once the listing no longer contains it", () => {
    const cache = new EnvelopeBodyCache<{ id: string }>();
    cache.bind("conv-1");
    cache.store("conv-1", [{ id: "a" }, { id: "deleted" }]);
    cache.resolve("conv-1", [entry("a", 1)]);
    expect(cache.has("deleted")).toBe(false);
    expect(cache.has("a")).toBe(true);
  });

  it("drops everything when bound to another conversation", () => {
    const cache = new EnvelopeBodyCache<{ id: string }>();
    cache.bind("conv-1");
    cache.store("conv-1", [{ id: "a" }]);
    cache.bind("conv-2");
    expect(cache.has("a")).toBe(false);
    expect(cache.resolve("conv-1", [entry("a", 1)])).toEqual([]);
  });

  it("keeps its rows when bound to the same conversation again", () => {
    const cache = new EnvelopeBodyCache<{ id: string }>();
    cache.bind("conv-1");
    cache.store("conv-1", [{ id: "a" }]);
    cache.bind("conv-1");
    expect(cache.has("a")).toBe(true);
  });

  it("refuses a body fetched for a conversation that is no longer bound", () => {
    const cache = new EnvelopeBodyCache<{ id: string }>();
    cache.bind("conv-1");
    cache.bind("conv-2");
    cache.store("conv-1", [{ id: "late" }]);
    expect(cache.has("late")).toBe(false);
  });
});
