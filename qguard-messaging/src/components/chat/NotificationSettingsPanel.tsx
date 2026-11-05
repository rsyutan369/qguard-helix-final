import { Bell, BellOff, Phone, Play, Volume2 } from "lucide-react";
import { useState } from "react";
import { useChatPreferences } from "@/lib/chat-preferences-context";
import { describeMute, isMuted, MESSAGE_SOUNDS, MUTE_OPTIONS, muteUntil, type MessageSound } from "@/lib/chat-preferences";
import { previewMessageSound } from "@/lib/message-sounds";

type Scope = { kind: "global" } | { kind: "chat"; conversationId: string; peerUserId: string | null; isDirect: boolean };

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (value: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={`relative h-6 w-11 shrink-0 rounded-full transition ${checked ? "bg-violet-600" : "bg-ink-200"}`}
    >
      <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-all ${checked ? "left-[22px]" : "left-0.5"}`} />
    </button>
  );
}

/**
 * Mute and Notifications & Sounds. `global` edits the app-wide defaults
 * (Settings); `chat` edits one conversation, where each switch can also follow
 * the app-wide default. Every change applies at once, on every device.
 */
export default function NotificationSettingsPanel({ scope, onError }: { scope: Scope; onError?: (text: string) => void }) {
  const prefs = useChatPreferences();
  const [error, setError] = useState<string | null>(null);
  const run = (work: Promise<void>) => {
    setError(null);
    work.catch((err: unknown) => {
      const text = err instanceof Error ? err.message : "The change could not be saved.";
      setError(text);
      onError?.(text);
    });
  };

  const settings = prefs.settings;
  const chat = scope.kind === "chat" ? prefs.preferenceFor(scope.conversationId) : null;
  const effective = scope.kind === "chat" ? prefs.effectiveFor(scope.conversationId) : null;
  const now = Date.now();
  const muted = scope.kind === "chat" && isMuted(chat, now);

  const setChat = (patch: Parameters<typeof prefs.updateChat>[2]) => {
    if (scope.kind !== "chat") return;
    run(prefs.updateChat(scope.conversationId, scope.peerUserId, patch));
  };

  const alertsOn = scope.kind === "chat" ? (chat?.messageAlerts ?? settings.messageAlerts) : settings.messageAlerts;
  const sound: MessageSound = scope.kind === "chat" ? (chat?.messageSound ?? settings.messageSound) : settings.messageSound;
  const ringOn = scope.kind === "chat" ? (chat?.callRing ?? settings.callRing) : settings.callRing;

  return (
    <div className="space-y-4">
      {scope.kind === "chat" && (
        <section>
          <div className="flex items-center gap-2 text-sm font-semibold text-ink-900">
            {muted ? <BellOff size={16} className="text-amber-600" /> : <Bell size={16} className="text-violet-600" />}
            Mute messages
          </div>
          <p className="mt-0.5 text-xs text-ink-500">
            {muted ? describeMute(chat, now) : "No sound or alert for new messages in this chat. Calls still ring unless you turn that off below."}
          </p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {MUTE_OPTIONS.map((option) => (
              <button
                key={option.id}
                type="button"
                onClick={() => setChat({ mutedUntil: muteUntil(option.ms, Date.now()) })}
                className="rounded-lg border border-line px-2.5 py-1.5 text-xs font-semibold text-ink-800 hover:bg-canvas"
              >
                {option.label}
              </button>
            ))}
            {muted && (
              <button type="button" onClick={() => setChat({ mutedUntil: null })} className="rounded-lg bg-violet-600 px-2.5 py-1.5 text-xs font-bold text-white">
                Unmute
              </button>
            )}
          </div>
        </section>
      )}

      <section className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-semibold text-ink-900">New message alerts</div>
          <p className="text-xs text-ink-500">
            {scope.kind === "global"
              ? "Show an alert inside the app when a message arrives in a chat you are not reading."
              : chat?.messageAlerts == null
                ? `Following your app setting (${settings.messageAlerts ? "on" : "off"}).`
                : "Set for this chat."}
          </p>
        </div>
        <Toggle
          label="New message alerts"
          checked={alertsOn}
          onChange={(value) => (scope.kind === "global" ? run(prefs.updateSettings({ messageAlerts: value })) : setChat({ messageAlerts: value }))}
        />
      </section>

      <section>
        <div className="flex items-center gap-2 text-sm font-semibold text-ink-900">
          <Volume2 size={16} className="text-violet-600" /> Message sound
        </div>
        <div className="mt-2 grid grid-cols-2 gap-1.5">
          {MESSAGE_SOUNDS.map((option) => (
            <div key={option.id} className={`flex items-center justify-between rounded-lg border px-2.5 py-1.5 ${sound === option.id ? "border-violet-300 bg-violet-50" : "border-line"}`}>
              <button
                type="button"
                onClick={() => (scope.kind === "global" ? run(prefs.updateSettings({ messageSound: option.id })) : setChat({ messageSound: option.id }))}
                className="min-w-0 flex-1 truncate text-left text-xs font-semibold text-ink-800"
                aria-pressed={sound === option.id}
              >
                {option.label}
              </button>
              {option.id !== "none" && (
                <button type="button" onClick={() => previewMessageSound(option.id)} className="shrink-0 text-ink-500 hover:text-violet-600" aria-label={`Play ${option.label}`} title="Play">
                  <Play size={13} />
                </button>
              )}
            </div>
          ))}
        </div>
        {scope.kind === "chat" && chat?.messageSound != null && (
          <button type="button" onClick={() => setChat({ messageSound: null })} className="mt-1.5 text-xs font-semibold text-violet-600 hover:underline">
            Use my app sound ({MESSAGE_SOUNDS.find((option) => option.id === settings.messageSound)?.label})
          </button>
        )}
      </section>

      {(scope.kind === "global" || scope.isDirect) && (
        <section className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-sm font-semibold text-ink-900">
              <Phone size={15} className="text-violet-600" /> Ring for calls
            </div>
            <p className="text-xs text-ink-500">
              {scope.kind === "global" ? "Play the ringtone for incoming calls. Calls still appear when it is off." : "Ring when this person calls you. The call still appears when it is off."}
            </p>
          </div>
          <Toggle
            label="Ring for calls"
            checked={ringOn}
            onChange={(value) => (scope.kind === "global" ? run(prefs.updateSettings({ callRing: value })) : setChat({ callRing: value }))}
          />
        </section>
      )}

      {effective && (
        <p className="rounded-lg bg-canvas p-2.5 text-xs text-ink-600">
          Right now this chat {effective.alert ? "shows alerts" : "shows no alerts"} and {effective.sound === "none" ? "plays no sound" : `plays “${MESSAGE_SOUNDS.find((option) => option.id === effective.sound)?.label}”`} for new messages
          {scope.kind === "chat" && scope.isDirect ? `; calls ${effective.ring ? "ring" : "arrive silently"}` : ""}. Applies on all your devices.
        </p>
      )}
      <p className="text-[11px] text-ink-400">Alerts and sounds play while QGuard Messaging is open. Alerts never show message text.</p>
      {error && <p className="text-sm text-rose-600">{error}</p>}
    </div>
  );
}
