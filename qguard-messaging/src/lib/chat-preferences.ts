// Mute, and Notifications & Sounds, per chat and app-wide (migration 050).
//
// The rows live in Supabase so a choice made on one device applies on all of
// them; the provider (chat-preferences-context.tsx) applies a change in the UI
// before the server confirms it, and rolls it back if the server refuses.
//
// Nothing here touches message content: muting decides only whether this
// device plays a sound or shows an alert when a new encrypted message arrives.

import { supabase } from "@/lib/supabase";

export type MessageSound = "chime" | "pop" | "soft" | "none";

export const MESSAGE_SOUNDS: Array<{ id: MessageSound; label: string }> = [
  { id: "chime", label: "Chime" },
  { id: "pop", label: "Pop" },
  { id: "soft", label: "Soft" },
  { id: "none", label: "No sound" },
];

/** App-wide defaults (messaging_notification_settings). */
export interface NotificationSettings {
  messageAlerts: boolean;
  messageSound: MessageSound;
  callRing: boolean;
}

export const DEFAULT_NOTIFICATION_SETTINGS: NotificationSettings = {
  messageAlerts: true,
  messageSound: "chime",
  callRing: true,
};

/** One chat's row (messaging_chat_preferences). A null field means "use the app-wide default". */
export interface ChatPreference {
  conversationId: string;
  peerUserId: string | null;
  /** ISO time the mute ends, or null when not muted. */
  mutedUntil: string | null;
  messageAlerts: boolean | null;
  messageSound: MessageSound | null;
  callRing: boolean | null;
}

/** Stored for "until I turn it back on". */
export const MUTE_FOREVER = "9999-12-31T00:00:00.000Z";

export const MUTE_OPTIONS: Array<{ id: string; label: string; ms: number | null }> = [
  { id: "1h", label: "For 1 hour", ms: 60 * 60_000 },
  { id: "8h", label: "For 8 hours", ms: 8 * 60 * 60_000 },
  { id: "1w", label: "For 1 week", ms: 7 * 24 * 60 * 60_000 },
  { id: "always", label: "Until I turn it back on", ms: null },
];

export function muteUntil(optionMs: number | null, now: number): string {
  return optionMs === null ? MUTE_FOREVER : new Date(now + optionMs).toISOString();
}

export function isMuted(pref: Pick<ChatPreference, "mutedUntil"> | null | undefined, now: number): boolean {
  if (!pref?.mutedUntil) return false;
  const until = Date.parse(pref.mutedUntil);
  return Number.isFinite(until) && until > now;
}

/** "Muted until 5:30 PM", "Muted", "Muted until Nov 12" — or null when not muted. */
export function describeMute(pref: Pick<ChatPreference, "mutedUntil"> | null | undefined, now: number): string | null {
  if (!isMuted(pref, now)) return null;
  const until = Date.parse(pref!.mutedUntil!);
  if (until >= Date.parse(MUTE_FOREVER) - 24 * 60 * 60_000) return "Muted";
  const sameDay = new Date(until).toDateString() === new Date(now).toDateString();
  return `Muted until ${new Date(until).toLocaleString(undefined, sameDay ? { timeStyle: "short" } : { dateStyle: "medium", timeStyle: "short" })}`;
}

/** What this device actually does for a chat: its own choices over the app-wide ones. */
export interface EffectiveChatAlerts {
  muted: boolean;
  /** Show the "new message" alert. */
  alert: boolean;
  /** The sound to play, or "none". */
  sound: MessageSound;
  /** Ring for an incoming call from this chat's person. */
  ring: boolean;
}

export function effectiveChatAlerts(settings: NotificationSettings, pref: ChatPreference | null | undefined, now: number): EffectiveChatAlerts {
  const muted = isMuted(pref, now);
  const alert = pref?.messageAlerts ?? settings.messageAlerts;
  const sound = pref?.messageSound ?? settings.messageSound;
  return {
    muted,
    // Muting silences a chat's messages; it does not silence its calls (that is
    // the separate "Ring for calls" switch), as in WhatsApp and Messenger.
    alert: alert && !muted,
    sound: muted || !alert ? "none" : sound,
    ring: pref?.callRing ?? settings.callRing,
  };
}

// ---------------------------------------------------------------------------
// Rows <-> objects
// ---------------------------------------------------------------------------

const SOUNDS = new Set<MessageSound>(["chime", "pop", "soft", "none"]);
const asSound = (value: unknown): MessageSound | null => (typeof value === "string" && SOUNDS.has(value as MessageSound) ? (value as MessageSound) : null);
const asBool = (value: unknown): boolean | null => (typeof value === "boolean" ? value : null);

export function settingsFromRow(row: Record<string, unknown> | null | undefined): NotificationSettings {
  if (!row) return DEFAULT_NOTIFICATION_SETTINGS;
  return {
    messageAlerts: asBool(row.message_alerts) ?? DEFAULT_NOTIFICATION_SETTINGS.messageAlerts,
    messageSound: asSound(row.message_sound) ?? DEFAULT_NOTIFICATION_SETTINGS.messageSound,
    callRing: asBool(row.call_ring) ?? DEFAULT_NOTIFICATION_SETTINGS.callRing,
  };
}

export function preferenceFromRow(row: Record<string, unknown>): ChatPreference {
  return {
    conversationId: String(row.conversation_id),
    peerUserId: row.peer_user_id ? String(row.peer_user_id) : null,
    mutedUntil: row.muted_until ? String(row.muted_until) : null,
    messageAlerts: asBool(row.message_alerts),
    messageSound: asSound(row.message_sound),
    callRing: asBool(row.call_ring),
  };
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

export async function loadNotificationState(userId: string): Promise<{ settings: NotificationSettings; chats: ChatPreference[] }> {
  const [settings, chats] = await Promise.all([
    supabase.from("messaging_notification_settings").select("message_alerts,message_sound,call_ring").eq("user_id", userId).maybeSingle(),
    supabase.from("messaging_chat_preferences").select("conversation_id,peer_user_id,muted_until,message_alerts,message_sound,call_ring").eq("user_id", userId),
  ]);
  if (settings.error) throw settings.error;
  if (chats.error) throw chats.error;
  return {
    settings: settingsFromRow(settings.data as Record<string, unknown> | null),
    chats: ((chats.data ?? []) as Array<Record<string, unknown>>).map(preferenceFromRow),
  };
}

export async function saveNotificationSettings(userId: string, settings: NotificationSettings): Promise<void> {
  const { error } = await supabase.from("messaging_notification_settings").upsert(
    {
      user_id: userId,
      message_alerts: settings.messageAlerts,
      message_sound: settings.messageSound,
      call_ring: settings.callRing,
      updated_at: new Date().toISOString(),
    },
    { onConflict: "user_id" },
  );
  if (error) throw error;
}

export async function saveChatPreference(userId: string, pref: ChatPreference): Promise<void> {
  const { error } = await supabase.from("messaging_chat_preferences").upsert(
    {
      user_id: userId,
      conversation_id: pref.conversationId,
      peer_user_id: pref.peerUserId,
      muted_until: pref.mutedUntil,
      message_alerts: pref.messageAlerts,
      message_sound: pref.messageSound,
      call_ring: pref.callRing,
      updated_at: new Date().toISOString(),
    },
    { onConflict: "user_id,conversation_id" },
  );
  if (error) throw error;
}
