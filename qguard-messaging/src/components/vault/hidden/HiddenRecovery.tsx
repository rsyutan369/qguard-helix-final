import { AlertTriangle, ArrowLeft, CheckCircle2, KeyRound, Loader2, ShieldCheck } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { PatternCapture } from "@/components/vault/PatternCapture";
import { VaultModal } from "@/components/vault/VaultModal";
import { ask as askDialog } from "@/lib/tauri-dialog";
import { fillWords, hiddenVault, PHRASE_WORDS, pickCheckPositions, splitPhrase, type HiddenSummary } from "@/lib/vault-hidden";
import { describeStoreError, formatBytes } from "@/lib/vault-store";

// Hidden vault recovery phrases (src-tauri/src/vault/hidden.rs, crypto/mnemonic.rs):
// 12 BIP-39 words that open one hidden vault when its pattern is forgotten.
// The core makes the words, shows them once and keeps only a key derived from
// them; checking a typed phrase and replacing the pattern happen in the core.

type Notice = { tone: "success" | "error" | "info"; text: string };

const emptyWords = () => Array.from({ length: PHRASE_WORDS }, () => "");

/** Twelve numbered word boxes; pasting a whole phrase into any box fills the rest. */
function PhraseInput({ words, onChange, disabled }: { words: string[]; onChange: (words: string[]) => void; disabled?: boolean }) {
  const boxes = useRef<(HTMLInputElement | null)[]>([]);
  // Several words typed or pasted into one box: fill the boxes after it and
  // move to the last one filled.
  const put = (position: number, text: string) => {
    onChange(fillWords(words, position, text));
    const spread = splitPhrase(text).length;
    if (spread > 1) {
      const target = Math.min(position + spread - 1, PHRASE_WORDS - 1);
      window.requestAnimationFrame(() => boxes.current[target]?.focus());
    }
  };
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3" role="group" aria-label="Recovery phrase">
      {words.map((word, position) => (
        <label key={position} className="flex min-w-0 items-center gap-1.5 rounded-lg border border-line bg-canvas px-2 py-1.5 focus-within:border-violet-300">
          <span className="w-5 shrink-0 text-right font-mono text-[11px] text-ink-500">{position + 1}</span>
          <input
            ref={(element) => {
              boxes.current[position] = element;
            }}
            value={word}
            disabled={disabled}
            onChange={(event) => put(position, event.currentTarget.value)}
            onPaste={(event) => {
              const text = event.clipboardData.getData("text");
              if (/\s/.test(text.trim())) {
                event.preventDefault();
                put(position, text);
              }
            }}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
            aria-label={`Word ${position + 1}`}
            className="min-w-0 flex-1 bg-transparent font-mono text-sm text-ink-950 outline-none"
          />
        </label>
      ))}
    </div>
  );
}

function ErrorLine({ text }: { text: string | null }) {
  if (!text) return null;
  return (
    <div className="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-semibold text-rose-600" role="alert">
      {text}
    </div>
  );
}

/**
 * Recover a hidden vault whose pattern is forgotten: type its 12 words, then
 * draw a new pattern. The vault opens (the Quantum Vault locks). Offered on
 * the vault lock screen to everyone, like the pattern pad, and inside the
 * Quantum Vault — neither says whether any hidden vault exists.
 */
export function RecoverHiddenVault({ onRecovered, onBack }: { onRecovered: () => void; onBack?: () => void }) {
  const [words, setWords] = useState<string[]>(emptyWords);
  const [found, setFound] = useState<HiddenSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const complete = words.every((word) => word.length > 0);
  const phrase = words.join(" ");

  const check = async () => {
    setBusy(true);
    setError(null);
    try {
      setFound(await hiddenVault.checkRecovery(phrase));
    } catch (err) {
      setError(describeStoreError(err));
    } finally {
      setBusy(false);
    }
  };

  if (found) {
    return (
      <div className="space-y-3">
        <div className="flex items-start gap-2 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs font-semibold text-emerald-800" role="status">
          <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
          <span>
            Phrase accepted — it opens a hidden vault with {found.files} file{found.files === 1 ? "" : "s"} ({formatBytes(found.bytes)}).
            Draw a new pattern for it twice. The old pattern stops working; your 12 words keep working.
          </span>
        </div>
        <PatternCapture
          mode="set"
          submitLabel="Re-sealing the hidden vault under the new pattern…"
          onSubmit={async (pattern) => {
            await hiddenVault.recover(phrase, pattern);
            setWords(emptyWords());
            onRecovered();
          }}
        />
        <p className="text-[11px] text-ink-500">
          Use a pattern different from your Quantum Vault's and from any other hidden vault's. Each try counts toward the pattern attempt limit.
        </p>
        <button type="button" onClick={() => setFound(null)} className="flex items-center gap-1 text-xs font-bold text-ink-500 hover:text-ink-700">
          <ArrowLeft size={13} /> Use different words
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-ink-600">
        Enter the 12 words you wrote down when you set up the hidden vault's recovery phrase, in order. You can paste them all into the
        first box. They only work on this device, where the hidden vault's files are.
      </p>
      <PhraseInput words={words} onChange={setWords} disabled={busy} />
      <ErrorLine text={error} />
      <button
        type="button"
        disabled={busy || !complete}
        onClick={() => void check()}
        className="flex w-full items-center justify-center gap-2 rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-bold text-white hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {busy ? <Loader2 className="animate-spin" size={16} /> : <KeyRound size={16} />} Check phrase
      </button>
      {onBack && (
        <button type="button" onClick={onBack} className="flex items-center gap-1 text-xs font-bold text-ink-500 hover:text-ink-700">
          <ArrowLeft size={13} /> Back
        </button>
      )}
    </div>
  );
}

/** Show a new phrase once, then have the owner type three of its words back. */
function NewPhraseFlow({ onClose, onCreated, onNotice }: { onClose: () => void; onCreated: (summary: HiddenSummary) => void; onNotice: (notice: Notice) => void }) {
  const [step, setStep] = useState<"intro" | "words" | "confirm">("intro");
  const [words, setWords] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const positions = useMemo(() => pickCheckPositions(), [words]);
  const [answers, setAnswers] = useState<Record<number, string>>({});
  const confirmed = words !== null && positions.every((p) => (answers[p] ?? "").trim().toLowerCase() === words[p]);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const setup = await hiddenVault.setUpRecovery();
      setWords(setup.words);
      setAnswers({});
      onCreated(setup.summary);
      setStep("words");
    } catch (err) {
      setError(describeStoreError(err));
    } finally {
      setBusy(false);
    }
  };

  const close = () => {
    if (words && step !== "intro" && !confirmed) {
      onNotice({ tone: "info", text: "The recovery phrase is set up, but you did not confirm you wrote it down. If you did not, create a new one." });
    }
    setWords(null);
    onClose();
  };

  return (
    <VaultModal title="Hidden vault recovery phrase" onClose={close}>
      {step === "intro" && (
        <div className="space-y-3 text-sm text-ink-700">
          <p>
            You will see 12 words. If you ever forget this vault's pattern, those words open it again on this device, and you choose a new
            pattern.
          </p>
          <ul className="space-y-1.5 text-[11px] text-ink-600">
            <li className="flex items-start gap-1.5">
              <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={12} />
              <span>
                <strong>Anyone who has the words can open this vault</strong> on this device without the pattern. Write them on paper and
                keep it apart from the device. No screenshots, photos, cloud notes or messages.
              </span>
            </li>
            <li className="flex items-start gap-1.5">
              <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={12} />
              <span>A written-down phrase is itself a sign that a hidden vault exists. Keep it somewhere it will not be found.</span>
            </li>
            <li className="flex items-start gap-1.5">
              <ShieldCheck className="mt-0.5 shrink-0 text-emerald-600" size={12} />
              <span>
                The app shows the words once and does not keep them. QGuard cannot show them again or recover them for you. A new phrase
                replaces any earlier one, which stops working.
              </span>
            </li>
          </ul>
          <ErrorLine text={error} />
          <button
            type="button"
            disabled={busy}
            onClick={() => void create()}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-bold text-white hover:opacity-90 disabled:opacity-50"
          >
            {busy ? <Loader2 className="animate-spin" size={16} /> : <KeyRound size={16} />} Show my 12 words
          </button>
        </div>
      )}

      {step === "words" && words && (
        <div className="space-y-3">
          <p className="text-xs text-ink-600">Write these words down, in order. They will not be shown again.</p>
          <ol className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {words.map((word, position) => (
              <li key={position} className="flex min-w-0 items-center gap-1.5 rounded-lg border border-line bg-canvas px-2 py-1.5">
                <span className="w-5 shrink-0 text-right font-mono text-[11px] text-ink-500">{position + 1}</span>
                <span className="truncate font-mono text-sm font-semibold text-ink-950 select-none">{word}</span>
              </li>
            ))}
          </ol>
          <button type="button" onClick={() => setStep("confirm")} className="w-full rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-bold text-white hover:opacity-90">
            I wrote them down
          </button>
        </div>
      )}

      {step === "confirm" && words && (
        <div className="space-y-3">
          <p className="text-xs text-ink-600">To check, type these words from your copy.</p>
          {positions.map((position) => (
            <label key={position} className="flex items-center gap-2 rounded-lg border border-line bg-canvas px-3 py-2 focus-within:border-violet-300">
              <span className="w-14 shrink-0 text-xs font-bold text-ink-700">Word {position + 1}</span>
              <input
                value={answers[position] ?? ""}
                onChange={(event) => {
                  const value = event.currentTarget.value;
                  setAnswers((current) => ({ ...current, [position]: value }));
                }}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
                className="min-w-0 flex-1 bg-transparent font-mono text-sm text-ink-950 outline-none"
              />
            </label>
          ))}
          <div className="flex gap-2">
            <button type="button" onClick={() => setStep("words")} className="rounded-lg border border-line px-4 py-2.5 text-sm font-semibold text-ink-700 hover:bg-canvas">
              Show words again
            </button>
            <button
              type="button"
              disabled={!confirmed}
              onClick={() => {
                onNotice({ tone: "success", text: "Recovery phrase set up. Keep your copy safe and away from this device." });
                setWords(null);
                onClose();
              }}
              className="flex-1 rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-bold text-white hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Done
            </button>
          </div>
        </div>
      )}
    </VaultModal>
  );
}

/** Inside an open hidden vault: whether it has a recovery phrase, and managing it. */
export function RecoveryPhraseCard({
  summary,
  busy,
  onChanged,
  onNotice,
}: {
  summary: HiddenSummary | null;
  busy: boolean;
  onChanged: (summary: HiddenSummary) => void;
  onNotice: (notice: Notice) => void;
}) {
  const [showing, setShowing] = useState(false);
  const [removing, setRemoving] = useState(false);
  const on = Boolean(summary?.recoveryPhrase);

  const start = async () => {
    if (on) {
      const confirmed = await askDialog("Create a new recovery phrase?\n\nThe 12 words you wrote down before stop working as soon as the new ones are made.", {
        title: "New recovery phrase",
        okLabel: "Continue",
        cancelLabel: "Cancel",
      }).catch(() => false);
      if (!confirmed) return;
    }
    setShowing(true);
  };

  const remove = async () => {
    const confirmed = await askDialog(
      "Remove this vault's recovery phrase?\n\nYour 12 words stop working at once. From then on only the pattern opens this vault — forget it and the files are gone.",
      { title: "Remove recovery phrase", okLabel: "Remove", cancelLabel: "Cancel" },
    ).catch(() => false);
    if (!confirmed) return;
    setRemoving(true);
    try {
      onChanged(await hiddenVault.removeRecovery());
      onNotice({ tone: "success", text: "Recovery phrase removed. Only this vault's pattern opens it now." });
    } catch (error) {
      onNotice({ tone: "error", text: describeStoreError(error) });
    } finally {
      setRemoving(false);
    }
  };

  return (
    <section className="min-w-0 rounded-xl border border-line bg-white p-4">
      <h2 className="flex items-center gap-2 text-sm font-bold text-ink-950">
        <KeyRound className={on ? "shrink-0 text-emerald-600" : "shrink-0 text-amber-500"} size={16} /> Recovery phrase
      </h2>
      <p className="mt-2 text-sm text-ink-700">
        {summary === null
          ? "Checking…"
          : on
            ? "Set up — if you forget this vault's pattern, your 12 words open it again on this device and you choose a new pattern."
            : "Not set up. If you forget this vault's pattern, its files cannot be opened by anyone. A 12-word phrase gives you a way back."}
      </p>
      <p className="mt-2 text-[11px] text-ink-500">
        Recover from the vault lock screen (Forgot …? → hidden vault recovery phrase) or from Security &amp; Backup in your Quantum Vault.
        The words are 128 random bits in the standard BIP-39 word list; the app keeps only a key derived from them, sealed inside this
        vault's encrypted index.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy || removing || summary === null}
          onClick={() => void start()}
          className={`rounded-lg px-3 py-1.5 text-xs font-bold disabled:opacity-50 ${on ? "border border-line text-ink-800 hover:bg-canvas" : "bg-violet-600 text-white hover:opacity-90"}`}
        >
          {on ? "Create a new phrase" : "Set up recovery phrase"}
        </button>
        {on && (
          <button
            type="button"
            disabled={busy || removing}
            onClick={() => void remove()}
            className="flex items-center gap-2 rounded-lg border border-line px-3 py-1.5 text-xs font-bold text-ink-800 hover:bg-canvas disabled:opacity-50"
          >
            {removing && <Loader2 className="animate-spin" size={13} />} Remove phrase
          </button>
        )}
      </div>
      {showing && <NewPhraseFlow onClose={() => setShowing(false)} onCreated={onChanged} onNotice={onNotice} />}
    </section>
  );
}
