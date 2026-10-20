import { describe, expect, it } from "vitest";
import { admitGroupRing, makeGroupInvite, meshTargets, parseGroupInvite, type GroupInvite } from "./group-call";
import { PRIMARY_SLOT, createCallSignalHub, routeSignal } from "./call-signal-hub";
import type { CallSignalRow } from "./call-types";

const A = "00000000-0000-4000-8000-00000000000a";
const B = "00000000-0000-4000-8000-00000000000b";
const C = "00000000-0000-4000-8000-00000000000c";
const D = "00000000-0000-4000-8000-00000000000d";
const CONV = "c0000000-0000-4000-8000-000000000001";

const invite = (overrides: Partial<GroupInvite> = {}): GroupInvite => ({
  id: "10000000-0000-4000-8000-000000000001", conversationId: CONV, inviterUserId: A, members: [A, B, C], ...overrides,
});

function row(overrides: Partial<CallSignalRow>): CallSignalRow {
  return {
    id: "s", call_id: "call-1", conversation_id: CONV, from_user_id: A, from_device_id: "dev-a",
    to_user_id: B, to_device_id: "dev-b", signal_type: "ring", payload: {}, created_at: new Date().toISOString(),
    ...overrides,
  };
}

describe("group invites", () => {
  it("is three people, the inviter included", () => {
    expect(makeGroupInvite(CONV, A, [B, C]).members).toEqual([A, B, C]);
    expect(() => makeGroupInvite(CONV, A, [B])).toThrow(/three people/);
    expect(() => makeGroupInvite(CONV, A, [B, C, D])).toThrow(/at most 3/);
  });

  it("parses only well-formed invites", () => {
    expect(parseGroupInvite(invite())).toEqual(invite());
    expect(parseGroupInvite({ ...invite(), members: [A, B, C, D] })).toBeNull();
    expect(parseGroupInvite({ ...invite(), members: [A, A, B] })).toBeNull();
    expect(parseGroupInvite({ ...invite(), inviterUserId: D })).toBeNull();
    expect(parseGroupInvite({ ...invite(), id: "not-a-uuid" })).toBeNull();
    expect(parseGroupInvite("nope")).toBeNull();
  });
});

describe("admitGroupRing", () => {
  const base = { invite: invite(), fromUserId: A, conversationId: CONV, myUserId: B, current: null, oneToOneBusy: false };

  it("opens a fresh invite that names me, from one of its members", () => {
    expect(admitGroupRing(base)).toBe(true);
  });

  it("NEG refuses strangers, invites without me, other conversations and busy devices", () => {
    expect(admitGroupRing({ ...base, fromUserId: D })).toBe(false);
    expect(admitGroupRing({ ...base, myUserId: D })).toBe(false);
    expect(admitGroupRing({ ...base, conversationId: "c0000000-0000-4000-8000-000000000002" })).toBe(false);
    expect(admitGroupRing({ ...base, oneToOneBusy: true })).toBe(false);
  });

  it("admits a later link only for the same call, never one that adds people", () => {
    expect(admitGroupRing({ ...base, fromUserId: C, current: invite() })).toBe(true);
    expect(admitGroupRing({ ...base, current: invite({ id: "10000000-0000-4000-8000-000000000002" }) })).toBe(false);
    expect(admitGroupRing({ ...base, fromUserId: C, invite: invite({ members: [A, C, D], inviterUserId: C }), myUserId: A, current: invite() })).toBe(false);
  });
});

describe("meshTargets", () => {
  it("links every pair exactly once", () => {
    const group = invite();
    // A (inviter) rang B and C. B rings C (C sorts after B); C rings nobody.
    expect(meshTargets(group, B, [A])).toEqual([C]);
    expect(meshTargets(group, C, [A])).toEqual([]);
    expect(meshTargets(group, B, [A, C])).toEqual([]);
  });
});

describe("signal routing", () => {
  it("sends one-to-one signals to the primary engine, unchanged", () => {
    expect(routeSignal(row({}), new Map(), () => "group-1")).toBe(PRIMARY_SLOT);
  });

  it("routes a group ring to the slot the coordinator picks, then by call id", () => {
    const routes = new Map<string, string>();
    expect(routeSignal(row({ payload: { group: invite() } }), routes, () => "group-1")).toBe("group-1");
    // Later signals of that call carry no invite but still reach the same engine.
    expect(routeSignal(row({ signal_type: "ice", payload: { candidate: {} } }), routes, () => "group-2")).toBe("group-1");
  });

  it("refuses a group ring nobody may take", () => {
    expect(routeSignal(row({ payload: { group: invite() } }), new Map(), () => null)).toBeNull();
  });

  it("shares one subscription and answers refused rings", () => {
    let deliver: ((row: CallSignalRow) => void) | null = null;
    let subscriptions = 0;
    let closed = 0;
    const refused: string[] = [];
    const hub = createCallSignalHub({
      userId: A, deviceId: "dev-a",
      chooseSlot: () => null,
      onRefused: (signal) => refused.push(signal.call_id),
      subscribe: (opts) => {
        subscriptions += 1;
        deliver = opts.onSignal;
        return { boost: () => undefined, refresh: () => undefined, close: () => { closed += 1; } };
      },
    });
    const primary: string[] = [];
    const slot: string[] = [];
    const first = hub.attach(PRIMARY_SLOT, (signal) => primary.push(signal.call_id));
    const second = hub.attach("group-1", (signal) => slot.push(signal.call_id));
    hub.claim("outgoing-link", "group-1");
    deliver!(row({ call_id: "one-to-one" }));
    deliver!(row({ call_id: "outgoing-link", signal_type: "answer" }));
    deliver!(row({ call_id: "unwanted", payload: { group: invite() } }));
    expect({ subscriptions, primary, slot, refused }).toEqual({ subscriptions: 1, primary: ["one-to-one"], slot: ["outgoing-link"], refused: ["unwanted"] });
    first.close();
    expect(closed).toBe(0);
    second.close();
    expect(closed).toBe(1);
  });
});
