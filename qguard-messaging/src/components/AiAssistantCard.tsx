import { useEffect, useState } from "react";
import { AlertTriangle, KeyRound, Loader2, Sparkles } from "lucide-react";
import {
  ASSISTANT_PROVIDERS,
  cleanModel,
  loadAssistantSettings,
  saveAssistantSettings,
  type AssistantProvider,
  type AssistantSettings,
} from "@/lib/ai-assistant";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

interface KeyStatus {
  provider: AssistantProvider;
  configured: boolean;
  hint: string | null;
}

type Note = { tone: "ok" | "error"; text: string } | null;

/**
 * Settings → AI assistant (roadmap Phase 8; owner decision 2026-10-20: cloud
 * models with the user's own key — Anthropic Claude first, then OpenAI). Off
 * by default. The key is stored encrypted by the core and shown only by its
 * last four characters.
 */
export function AiAssistantCard() {
  const [settings, setSettings] = useState<AssistantSettings>(loadAssistantSettings);
  const [keys, setKeys] = useState<KeyStatus[]>([]);
  const [keyInput, setKeyInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<Note>(null);
  const desktopOrPhone = isTauriRuntime();
  const provider = ASSISTANT_PROVIDERS.find((item) => item.id === settings.provider) ?? ASSISTANT_PROVIDERS[0];
  const keyStatus = keys.find((item) => item.provider === settings.provider) ?? null;

  useEffect(() => {
    if (!desktopOrPhone) return;
    void safeInvoke<KeyStatus[]>("assistant_key_status").then(setKeys).catch(() => setKeys([]));
  }, [desktopOrPhone]);

  const update = (next: AssistantSettings) => {
    setSettings(next);
    saveAssistantSettings(next);
  };

  const saveKey = async () => {
    setBusy(true);
    setNote(null);
    try {
      const status = await safeInvoke<KeyStatus>("assistant_key_set", { provider: settings.provider, key: keyInput });
      setKeys((current) => [...current.filter((item) => item.provider !== status.provider), status]);
      setKeyInput("");
      setNote({ tone: "ok", text: `${provider.label} key saved on this device (encrypted).` });
    } catch (error) {
      setNote({ tone: "error", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusy(false);
    }
  };

  const clearKey = async () => {
    setBusy(true);
    setNote(null);
    try {
      const status = await safeInvoke<KeyStatus>("assistant_key_clear", { provider: settings.provider });
      setKeys((current) => [...current.filter((item) => item.provider !== status.provider), status]);
      setNote({ tone: "ok", text: `${provider.label} key removed from this device.` });
    } catch (error) {
      setNote({ tone: "error", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="shell-card p-5">
      <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><Sparkles size={18} /> AI assistant</div>
      <div className="mt-3 space-y-4 text-sm text-ink-600">
        <div className="flex gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs leading-relaxed text-amber-900">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <span>
            The assistant uses a cloud model. When you press <em>Catch me up</em>, <em>Suggest replies</em> or <em>Translate</em>, the
            messages it reads are sent from this device to {provider.label} ({provider.host}) and are <strong>no longer end-to-end
            encrypted</strong> once they arrive there; the provider&apos;s own terms apply. Disappearing and one-time messages are never
            sent, and it only ever runs when you ask, in conversations you have allowed.
          </span>
        </div>

        {!desktopOrPhone && <p className="text-xs">The assistant is available in the desktop and Android apps.</p>}

        <label className="flex items-center gap-2 font-semibold text-ink-900">
          <input
            type="checkbox"
            checked={settings.enabled}
            disabled={!desktopOrPhone}
            onChange={(event) => update({ ...settings, enabled: event.target.checked })}
          />
          Use the AI assistant on this device
        </label>

        {settings.enabled && (
          <div className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="text-xs font-semibold text-ink-700">
                Provider
                <select
                  value={settings.provider}
                  onChange={(event) => update({ ...settings, provider: event.target.value === "openai" ? "openai" : "anthropic" })}
                  className="mt-1 w-full rounded-md border border-line bg-canvas px-2 py-1.5 text-sm"
                >
                  {ASSISTANT_PROVIDERS.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
                </select>
              </label>
              <label className="text-xs font-semibold text-ink-700">
                Model id
                <input
                  value={settings.models[settings.provider]}
                  placeholder={provider.defaultModel || "as published by the provider"}
                  onChange={(event) => update({ ...settings, models: { ...settings.models, [settings.provider]: cleanModel(event.target.value) } })}
                  className="mt-1 w-full rounded-md border border-line bg-canvas px-2 py-1.5 font-mono text-sm"
                />
              </label>
            </div>
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold text-ink-700"><KeyRound size={14} /> Your {provider.label} API key</div>
              <p className="mt-0.5 text-xs">
                {keyStatus?.configured ? `Saved on this device, ending in …${keyStatus.hint}.` : "No key saved. Usage is billed to your provider account."}
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                <input
                  type="password"
                  autoComplete="off"
                  value={keyInput}
                  onChange={(event) => setKeyInput(event.target.value)}
                  placeholder={keyStatus?.configured ? "Paste a new key to replace it" : "Paste your API key"}
                  aria-label={`${provider.label} API key`}
                  className="min-w-0 flex-1 rounded-md border border-line bg-canvas px-2 py-1.5 font-mono text-sm"
                />
                <button
                  type="button"
                  disabled={busy || keyInput.trim().length === 0}
                  onClick={() => void saveKey()}
                  className="flex items-center gap-1.5 rounded-md bg-violet-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-violet-700 disabled:opacity-60"
                >
                  {busy && <Loader2 size={12} className="animate-spin" />} Save key
                </button>
                {keyStatus?.configured && (
                  <button type="button" disabled={busy} onClick={() => void clearKey()} className="rounded-md border border-line bg-white px-3 py-1.5 text-xs font-bold text-rose-700 hover:bg-rose-50 disabled:opacity-60">
                    Remove key
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
        {note && (
          <div className={`rounded-md border p-2 text-xs font-semibold ${note.tone === "ok" ? "border-emerald-100 bg-emerald-50 text-emerald-700" : "border-rose-100 bg-rose-50 text-rose-700"}`}>
            {note.text}
          </div>
        )}
      </div>
    </section>
  );
}
