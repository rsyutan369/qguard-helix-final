import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { supabase } from "@/lib/supabase";
import {
  DEFAULT_NOTIFICATION_SETTINGS,
  effectiveChatAlerts,
  loadNotificationState,
  preferenceFromRow,
  saveChatPreference,
  saveNotificationSettings,
  settingsFromRow,
  type ChatPreference,
  type EffectiveChatAlerts,
  type NotificationSettings,
} from "@/lib/chat-preferences";

interface ChatPreferencesValue {
  /** False until the first load returned (or failed). */
  ready: boolean;
  settings: NotificationSettings;
  preferenceFor: (conversationId: string) => ChatPreference | null;
  effectiveFor: (conversationId: string) => EffectiveChatAlerts;
  /** Whether a call from this person should ring (per-chat switch, else app-wide). */
  ringFor: (peerUserId: string | null) => boolean;
  /** Applied in the UI at once; rolled back and rethrown if the server refuses. */
  updateSettings: (patch: Partial<NotificationSettings>) => Promise<void>;
  updateChat: (conversationId: string, peerUserId: string | null, patch: Partial<Omit<ChatPreference, "conversationId" | "peerUserId">>) => Promise<void>;
}

const ChatPreferencesContext = createContext<ChatPreferencesValue | null>(null);

const blankPreference = (conversationId: string, peerUserId: string | null): ChatPreference => ({
  conversationId,
  peerUserId,
  mutedUntil: null,
  messageAlerts: null,
  messageSound: null,
  callRing: null,
});

/**
 * One store of Mute / Notifications & Sounds for the signed-in user, shared by
 * Secure Chat, Settings, the new-message alerts and the incoming-call ring.
 * Live across devices: both tables are in the realtime publication (050).
 */
export function ChatPreferencesProvider({ userId, children }: { userId: string | null; children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [settings, setSettings] = useState<NotificationSettings>(DEFAULT_NOTIFICATION_SETTINGS);
  const [chats, setChats] = useState<Map<string, ChatPreference>>(new Map());
  // Re-render once a minute so a mute that runs out ends on screen too.
  const [tick, setTick] = useState(0);
  const settingsRef = useRef(settings);
  settingsRef.current = settings;
  const chatsRef = useRef(chats);
  chatsRef.current = chats;

  const reload = useCallback(async () => {
    if (!userId) return;
    try {
      const state = await loadNotificationState(userId);
      setSettings(state.settings);
      setChats(new Map(state.chats.map((pref) => [pref.conversationId, pref])));
    } catch {
      // Keep what is shown: defaults on a first failure, the last state after.
    } finally {
      setReady(true);
    }
  }, [userId]);

  useEffect(() => {
    setReady(false);
    setSettings(DEFAULT_NOTIFICATION_SETTINGS);
    setChats(new Map());
    void reload();
  }, [reload]);

  useEffect(() => {
    if (!userId) return undefined;
    const channel = supabase
      .channel(`chat-prefs-${userId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "messaging_notification_settings", filter: `user_id=eq.${userId}` }, (payload) => {
        setSettings(payload.eventType === "DELETE" ? DEFAULT_NOTIFICATION_SETTINGS : settingsFromRow(payload.new as Record<string, unknown>));
      })
      .on("postgres_changes", { event: "*", schema: "public", table: "messaging_chat_preferences", filter: `user_id=eq.${userId}` }, (payload) => {
        setChats((current) => {
          const next = new Map(current);
          if (payload.eventType === "DELETE") {
            const old = payload.old as Record<string, unknown>;
            if (old?.conversation_id) next.delete(String(old.conversation_id));
          } else {
            const pref = preferenceFromRow(payload.new as Record<string, unknown>);
            next.set(pref.conversationId, pref);
          }
          return next;
        });
      })
      .subscribe();
    const tick = window.setInterval(() => setTick((value) => value + 1), 60_000);
    const onWake = () => void reload();
    window.addEventListener("online", onWake);
    return () => {
      void supabase.removeChannel(channel);
      window.clearInterval(tick);
      window.removeEventListener("online", onWake);
    };
  }, [userId, reload]);

  const updateSettings = useCallback(
    async (patch: Partial<NotificationSettings>) => {
      if (!userId) return;
      const before = settingsRef.current;
      const next = { ...before, ...patch };
      setSettings(next);
      try {
        await saveNotificationSettings(userId, next);
      } catch (error) {
        setSettings(before);
        throw error;
      }
    },
    [userId],
  );

  const updateChat = useCallback<ChatPreferencesValue["updateChat"]>(
    async (conversationId, peerUserId, patch) => {
      if (!userId) return;
      const before = chatsRef.current.get(conversationId) ?? null;
      const next: ChatPreference = { ...(before ?? blankPreference(conversationId, peerUserId)), ...patch, peerUserId: peerUserId ?? before?.peerUserId ?? null };
      setChats((current) => new Map(current).set(conversationId, next));
      try {
        await saveChatPreference(userId, next);
      } catch (error) {
        setChats((current) => {
          const rolled = new Map(current);
          if (before) rolled.set(conversationId, before);
          else rolled.delete(conversationId);
          return rolled;
        });
        throw error;
      }
    },
    [userId],
  );

  const value = useMemo<ChatPreferencesValue>(() => {
    const now = Date.now();
    return {
      ready,
      settings,
      preferenceFor: (conversationId) => chats.get(conversationId) ?? null,
      effectiveFor: (conversationId) => effectiveChatAlerts(settings, chats.get(conversationId), now),
      ringFor: (peerUserId) => {
        if (!peerUserId) return settings.callRing;
        for (const pref of chats.values()) {
          if (pref.peerUserId === peerUserId && pref.callRing !== null) return pref.callRing;
        }
        return settings.callRing;
      },
      updateSettings,
      updateChat,
    };
    // `tick` changes once a minute so `now` (and with it a mute that ran out) is fresh.
  }, [ready, settings, chats, updateSettings, updateChat, tick]);

  return <ChatPreferencesContext.Provider value={value}>{children}</ChatPreferencesContext.Provider>;
}

/** The store; throws outside the provider so a missing wrapper is caught early. */
export function useChatPreferences(): ChatPreferencesValue {
  const value = useContext(ChatPreferencesContext);
  if (!value) throw new Error("useChatPreferences must be used inside ChatPreferencesProvider");
  return value;
}

/** The store, or null where it may legitimately be absent (tests, harnesses). */
export function useOptionalChatPreferences(): ChatPreferencesValue | null {
  return useContext(ChatPreferencesContext);
}
