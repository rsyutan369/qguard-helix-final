import { describe, expect, test } from "vitest";
import {
  DEFAULT_NOTIFICATION_SETTINGS,
  describeMute,
  effectiveChatAlerts,
  isMuted,
  MUTE_FOREVER,
  muteUntil,
  preferenceFromRow,
  settingsFromRow,
  type ChatPreference,
} from "@/lib/chat-preferences";
import { formatContactCard, parseContactCard } from "@/lib/contact-card";
import { newMessagesSince } from "@/lib/use-message-alerts";

const NOW = Date.parse("2026-11-05T12:00:00Z");
const pref = (patch: Partial<ChatPreference>): ChatPreference => ({
  conversationId: "c1",
  peerUserId: "p1",
  mutedUntil: null,
  messageAlerts: null,
  messageSound: null,
  callRing: null,
  ...patch,
});

describe("mute", () => {
  test("a mute lasts until its time, then ends by itself", () => {
    const until = muteUntil(60 * 60_000, NOW);
    expect(until).toBe("2026-11-05T13:00:00.000Z");
    expect(isMuted(pref({ mutedUntil: until }), NOW)).toBe(true);
    expect(isMuted(pref({ mutedUntil: until }), NOW + 60 * 60_000 + 1)).toBe(false);
    expect(isMuted(pref({ mutedUntil: null }), NOW)).toBe(false);
    expect(isMuted(null, NOW)).toBe(false);
  });

  test("'until I turn it back on' never runs out and reads as just Muted", () => {
    expect(muteUntil(null, NOW)).toBe(MUTE_FOREVER);
    expect(isMuted(pref({ mutedUntil: MUTE_FOREVER }), NOW)).toBe(true);
    expect(describeMute(pref({ mutedUntil: MUTE_FOREVER }), NOW)).toBe("Muted");
    expect(describeMute(pref({ mutedUntil: muteUntil(60 * 60_000, NOW) }), NOW)).toMatch(/^Muted until /);
    expect(describeMute(pref({}), NOW)).toBeNull();
  });
});

describe("effective alerts", () => {
  test("a chat follows the app-wide settings unless it has its own", () => {
    expect(effectiveChatAlerts(DEFAULT_NOTIFICATION_SETTINGS, null, NOW)).toEqual({ muted: false, alert: true, sound: "chime", ring: true });
    expect(effectiveChatAlerts({ messageAlerts: true, messageSound: "pop", callRing: false }, pref({}), NOW)).toEqual({ muted: false, alert: true, sound: "pop", ring: false });
    expect(effectiveChatAlerts(DEFAULT_NOTIFICATION_SETTINGS, pref({ messageSound: "soft", callRing: false }), NOW)).toEqual({ muted: false, alert: true, sound: "soft", ring: false });
  });

  test("muting silences messages but not calls", () => {
    const muted = effectiveChatAlerts(DEFAULT_NOTIFICATION_SETTINGS, pref({ mutedUntil: MUTE_FOREVER }), NOW);
    expect(muted).toEqual({ muted: true, alert: false, sound: "none", ring: true });
  });

  test("alerts off means no sound either", () => {
    expect(effectiveChatAlerts(DEFAULT_NOTIFICATION_SETTINGS, pref({ messageAlerts: false }), NOW).sound).toBe("none");
    expect(effectiveChatAlerts({ ...DEFAULT_NOTIFICATION_SETTINGS, messageAlerts: false }, null, NOW)).toMatchObject({ alert: false, sound: "none" });
  });

  test("rows parse defensively", () => {
    expect(settingsFromRow(null)).toEqual(DEFAULT_NOTIFICATION_SETTINGS);
    expect(settingsFromRow({ message_alerts: false, message_sound: "bogus", call_ring: false })).toEqual({ messageAlerts: false, messageSound: "chime", callRing: false });
    expect(preferenceFromRow({ conversation_id: "c9", peer_user_id: null, muted_until: null, message_alerts: null, message_sound: "soft", call_ring: true })).toEqual({
      conversationId: "c9",
      peerUserId: null,
      mutedUntil: null,
      messageAlerts: null,
      messageSound: "soft",
      callRing: true,
    });
  });
});

describe("contact card", () => {
  const id = "2ef4dcc7-af45-4408-bbe9-1300289fdc6f";

  test("round-trips", () => {
    const text = formatContactCard({ userId: id.toUpperCase(), name: "Tesla Great", username: "@teslagreat101_92ab65" });
    expect(text).toBe(`Contact card · Tesla Great (@teslagreat101_92ab65)\nqguard-user:${id}`);
    expect(parseContactCard(text)).toEqual({ userId: id, name: "Tesla Great", username: "teslagreat101_92ab65" });
    expect(parseContactCard(formatContactCard({ userId: id, name: "Zach", username: null }))).toEqual({ userId: id, name: "Zach", username: null });
  });

  test("a name cannot break the card onto extra lines", () => {
    expect(formatContactCard({ userId: id, name: "Line\none", username: null })).toBe(`Contact card · Line one\nqguard-user:${id}`);
  });

  test("ordinary messages are not cards", () => {
    expect(parseContactCard(`my id is qguard-user:${id}`)).toBeNull();
    expect(parseContactCard(`Contact card · X\nqguard-user:not-a-uuid`)).toBeNull();
    expect(parseContactCard(`Contact card · X\nqguard-user:${id}\nand more text`)).toBeNull();
    expect(parseContactCard("")).toBeNull();
    expect(parseContactCard(null)).toBeNull();
  });
});

describe("new-message detection", () => {
  const row = (id: string, unread: number, extra: Partial<{ hidden_at: string | null; deleted_at: string | null }> = {}) => ({
    id,
    title: id,
    unread_count: unread,
    hidden_at: null,
    deleted_at: null,
    conversation_type: "direct",
    member_user_ids: ["me", `peer-${id}`],
    ...extra,
  });

  test("the first look only records counts", () => {
    expect(newMessagesSince(null, [row("a", 3)])).toEqual([]);
  });

  test("only conversations whose unread count went up", () => {
    const before = new Map([["a", 1], ["b", 2]]);
    expect(newMessagesSince(before, [row("a", 3), row("b", 2), row("c", 1)])).toEqual([
      { conversationId: "a", added: 2 },
      { conversationId: "c", added: 1 },
    ]);
  });

  test("hidden and deleted chats never alert", () => {
    const before = new Map([["h", 0], ["d", 0]]);
    expect(newMessagesSince(before, [row("h", 4, { hidden_at: "2026-11-01T00:00:00Z" }), row("d", 1, { deleted_at: "2026-11-01T00:00:00Z" })])).toEqual([]);
  });
});
