import { useState } from "react";
import { Languages, ListChecks, Loader2, MessageSquareReply, Sparkles, X } from "lucide-react";
import {
  ASSISTANT_PROVIDERS,
  assistantOutput,
  rememberAssistantOutput,
  runAssistant,
  selectAssistantInput,
  setConversationConsent,
  type AssistantCandidateMessage,
  type AssistantSettings,
  type AssistantTask,
} from "@/lib/ai-assistant";

/** The user's language by name ("Português"), for prompts and labels. */
function userLanguage(): string {
  try {
    const code = navigator.language || "en";
    return new Intl.DisplayNames([code], { type: "language" }).of(code) ?? "English";
  } catch {
    return "English";
  }
}

/**
 * The in-chat assistant (roadmap Phase 8). Runs only on a button press, only in
 * a conversation the user has allowed, over the messages
 * `selectAssistantInput` lets through. Output is display-only: a suggested
 * reply goes into the composer for the user to edit and send.
 */
export function AssistantPanel({ conversationId, settings, allowed, messages, onAllowed, onUseReply, onClose }: {
  conversationId: string;
  settings: AssistantSettings;
  allowed: boolean;
  messages: AssistantCandidateMessage[];
  onAllowed: () => void;
  onUseReply: (text: string) => void;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState<AssistantTask | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [, setVersion] = useState(0);
  const provider = ASSISTANT_PROVIDERS.find((item) => item.id === settings.provider) ?? ASSISTANT_PROVIDERS[0];
  const output = assistantOutput(conversationId);
  const readable = selectAssistantInput(messages);
  const language = userLanguage();

  const run = async (task: AssistantTask) => {
    setBusy(task);
    setError(null);
    try {
      const result = await runAssistant({ settings, task, messages: readable, language });
      rememberAssistantOutput(conversationId, result, settings.provider);
      setVersion((version) => version + 1);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(null);
    }
  };

  const taskButton = (task: AssistantTask, label: string, Icon: typeof Sparkles) => (
    <button
      type="button"
      disabled={busy !== null || readable.length === 0}
      onClick={() => void run(task)}
      className="flex items-center gap-1.5 rounded-md border border-line bg-white px-2.5 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas disabled:opacity-60"
    >
      {busy === task ? <Loader2 size={13} className="animate-spin" /> : <Icon size={13} />} {label}
    </button>
  );

  return (
    <div className="rounded-lg border border-fuchsia-200 bg-white p-4 text-sm text-ink-700 shadow-tight">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 font-bold text-ink-950"><Sparkles size={16} className="text-fuchsia-600" /> Assistant · {provider.label}</div>
        <button type="button" onClick={onClose} className="icon-button shrink-0" title="Close"><X size={14} /></button>
      </div>

      {!allowed ? (
        <div className="mt-3 space-y-2 text-xs leading-relaxed">
          <p>
            Allow the assistant in this conversation? When you ask it something, up to the last {readable.length} readable messages
            here are sent to {provider.label} ({provider.host}) and leave end-to-end encryption. The other people in this
            conversation are not told.
          </p>
          <button
            type="button"
            onClick={() => { setConversationConsent(conversationId); onAllowed(); }}
            className="rounded-md bg-fuchsia-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-fuchsia-700"
          >
            Allow in this conversation
          </button>
        </div>
      ) : (
        <>
          <p className="mt-1 text-[11px] text-ink-500">
            {readable.length} message{readable.length === 1 ? "" : "s"} it may read (disappearing and one-time messages never are).
            <button
              type="button"
              onClick={() => { setConversationConsent(conversationId, false); onAllowed(); }}
              className="ml-2 font-semibold text-ink-600 underline"
            >
              Stop allowing
            </button>
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {taskButton("summary", "Catch me up", ListChecks)}
            {taskButton("replies", "Suggest replies", MessageSquareReply)}
            {taskButton("translate", `Translate to ${language}`, Languages)}
          </div>
        </>
      )}

      {error && <div className="mt-3 rounded-md border border-rose-100 bg-rose-50 p-2 text-xs font-semibold text-rose-700">{error}</div>}

      {allowed && output && (
        <div className="mt-3 rounded-md border border-fuchsia-100 bg-fuchsia-50/50 p-3">
          <div className="mb-2 text-[11px] font-semibold text-fuchsia-800">
            AI-generated by {ASSISTANT_PROVIDERS.find((item) => item.id === output.provider)?.label ?? output.provider} — may be wrong. Kept
            on this device only until the app locks.
          </div>
          {output.task === "summary" && <div className="whitespace-pre-wrap text-sm text-ink-900">{output.text}</div>}
          {output.task === "replies" && (
            output.suggestions.length === 0 ? <p className="text-xs">No suggestions.</p> : (
              <div className="flex flex-wrap gap-2">
                {output.suggestions.map((suggestion) => (
                  <button
                    key={suggestion}
                    type="button"
                    onClick={() => onUseReply(suggestion)}
                    title="Put this in the message box to edit and send yourself"
                    className="rounded-full border border-fuchsia-200 bg-white px-3 py-1 text-left text-xs font-semibold text-ink-800 hover:bg-fuchsia-50"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            )
          )}
          {output.task === "translate" && (
            <ul className="space-y-1.5 text-sm text-ink-900">
              {output.translations.map((item, index) => (
                <li key={`${index}:${item.from}`}><span className="font-semibold">{item.from}:</span> {item.text}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
