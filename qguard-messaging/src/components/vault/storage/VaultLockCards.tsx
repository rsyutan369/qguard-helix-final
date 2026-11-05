import { AlertTriangle, EyeOff, Grid3x3, KeyRound, Loader2, ShieldCheck, Trash2 } from "lucide-react";
import { useState } from "react";
import { PatternCapture } from "@/components/vault/PatternCapture";
import { VaultModal as Modal } from "@/components/vault/VaultModal";
import { RecoverHiddenVault } from "@/components/vault/hidden/HiddenRecovery";
import { ask as askDialog } from "@/lib/tauri-dialog";
import type { ScopeStatus } from "@/lib/use-workspace-lock";
import { hiddenVault } from "@/lib/vault-hidden";

// Security & Backup cards for how the vault unlocks: a drawn pattern, and
// hidden vaults (src-tauri/src/vault/hidden.rs). Nothing here lists, counts or
// hints at existing hidden vaults — the app does not know them until their
// pattern is drawn.

export interface VaultLockControls {
  status: ScopeStatus | null;
  setPattern: (pattern: string) => Promise<unknown>;
  removePattern: () => Promise<unknown>;
  /** A hidden vault was created and opened; the Quantum Vault is now locked. */
  onHiddenOpened: () => void;
}

function describe(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (error && typeof error === "object" && "message" in error) return String((error as { message: unknown }).message);
  return "Something went wrong.";
}

export function PatternUnlockCard({ controls, onNotice }: { controls: VaultLockControls; onNotice: (tone: "success" | "error" | "info", text: string) => void }) {
  const [setting, setSetting] = useState(false);
  const [removing, setRemoving] = useState(false);
  const status = controls.status;
  const on = Boolean(status?.hasPattern);
  const otherMethod = Boolean(status?.hasPassword || status?.hasPin);

  const remove = async () => {
    const confirmed = await askDialog("Turn off unlocking with a pattern?\n\nYour password or PIN keeps working.", {
      title: "Turn off pattern unlock",
      okLabel: "Turn off",
      cancelLabel: "Cancel",
    }).catch(() => false);
    if (!confirmed) return;
    setRemoving(true);
    try {
      await controls.removePattern();
      onNotice("success", "Pattern unlock is off.");
    } catch (error) {
      onNotice("error", describe(error));
    } finally {
      setRemoving(false);
    }
  };

  return (
    <section className="min-w-0 rounded-xl border border-line bg-white p-4">
      <h3 className="flex items-center gap-2 text-sm font-bold text-ink-950">
        <Grid3x3 className="text-cyan-600" size={16} /> Unlock with a pattern
      </h3>
      <p className="mt-2 flex items-center gap-2 text-sm text-ink-800">
        {on ? <ShieldCheck className="shrink-0 text-emerald-600" size={15} /> : <EyeOff className="shrink-0 text-ink-400" size={15} />}
        {on ? "On — draw your pattern on the vault lock screen." : "Off — the vault opens with your password or PIN."}
      </p>
      <p className="mt-2 text-[11px] text-ink-500">
        Connect at least 6 dots on a 4 × 4 grid. Like your PIN, the pattern is stretched with Argon2id (64 MiB) and unwraps your
        Vault Master Key with AES-256-GCM; nothing about it is stored except that sealed copy. 5 wrong attempts pause unlocking
        for 30 seconds, 10 for 5 minutes, and 20 lock the vault until you sign in again.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" onClick={() => setSetting(true)} className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:opacity-90">
          {on ? "Change pattern" : "Set up a pattern"}
        </button>
        {on && otherMethod && (
          <button type="button" disabled={removing} onClick={() => void remove()} className="rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-800 hover:bg-canvas disabled:opacity-50">
            {removing ? "Turning off…" : "Turn off"}
          </button>
        )}
      </div>
      {setting && (
        <Modal title={on ? "Change your vault pattern" : "Set up a vault pattern"} onClose={() => setSetting(false)}>
          <PatternCapture
            mode="set"
            submitLabel="Sealing your vault key under the pattern…"
            onSubmit={async (pattern) => {
              await controls.setPattern(pattern);
              setSetting(false);
              onNotice("success", "Pattern unlock is on. Draw it on the vault lock screen next time.");
            }}
          />
          <p className="mt-3 text-[11px] text-ink-500">
            Use a pattern different from any hidden vault's. A short or common shape is easy to watch or guess — 8 or more dots is
            stronger.
          </p>
        </Modal>
      )}
    </section>
  );
}

export function HiddenVaultCard({ controls, onNotice }: { controls: VaultLockControls; onNotice: (tone: "success" | "error" | "info", text: string) => void }) {
  const [creating, setCreating] = useState(false);
  const [understood, setUnderstood] = useState(false);
  const [erasing, setErasing] = useState(false);
  const [opening, setOpening] = useState(false);
  const [recovering, setRecovering] = useState(false);

  const eraseAll = async () => {
    const confirmed = await askDialog(
      "Erase every hidden vault on this device?\n\nAll their files are destroyed and cannot be recovered by anyone. Your Quantum Vault is not touched.",
      { title: "Erase hidden vaults", okLabel: "Erase all", cancelLabel: "Cancel" },
    ).catch(() => false);
    if (!confirmed) return;
    setErasing(true);
    try {
      await hiddenVault.eraseAll();
      onNotice("success", "Every hidden vault on this device was erased.");
    } catch (error) {
      onNotice("error", describe(error));
    } finally {
      setErasing(false);
    }
  };

  return (
    <section className="min-w-0 rounded-xl border border-line bg-white p-4">
      <h3 className="flex items-center gap-2 text-sm font-bold text-ink-950">
        <EyeOff className="text-violet-600" size={16} /> Hidden vaults
      </h3>
      <p className="mt-2 text-sm text-ink-700">
        A hidden vault is a separate vault that opens only when you draw its own pattern on the vault lock screen. The app never
        lists hidden vaults or shows that one exists, and on this device's storage its files look like the random files every
        account keeps.
      </p>
      <ul className="mt-3 space-y-1.5 text-[11px] text-ink-600">
        <li className="flex items-start gap-1.5">
          <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={12} />
          <span>
            <strong>Recovery is up to you.</strong> Inside a hidden vault, set up its 12-word recovery phrase: if you forget the pattern,
            the words open it again on this device. Without the pattern or the phrase its files are gone — no cloud copy, and QGuard
            cannot open them either.
          </span>
        </li>
        <li className="flex items-start gap-1.5">
          <ShieldCheck className="mt-0.5 shrink-0 text-emerald-600" size={12} />
          <span>
            Every file is AES-256-GCM encrypted under its own key, kept only in the hidden vault's encrypted index. The vault key comes
            from your pattern (Argon2id) and this device's secure key store, so a copy of the disk alone cannot even be used to try
            patterns.
          </span>
        </li>
        <li className="flex items-start gap-1.5">
          <ShieldCheck className="mt-0.5 shrink-0 text-emerald-600" size={12} />
          <span>Deleting a file removes its key first, then overwrites the encrypted copy.</span>
        </li>
        <li className="flex items-start gap-1.5">
          <ShieldCheck className="mt-0.5 shrink-0 text-emerald-600" size={12} />
          <span>
            <strong>Decoys and duress erase.</strong> Under pressure, draw a decoy — a hidden vault holding harmless files — instead of
            the real one. Inside a hidden vault you can arm <em>duress erase</em>: drawing that vault's pattern on the lock screen then
            also destroys every other hidden vault, silently. To look after an armed decoy, open it here instead.
          </span>
        </li>
        <li className="flex items-start gap-1.5">
          <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={12} />
          <span>
            Limits: someone examining the device can see how much space the vault folder uses and, with forensic tools, when files in it
            were written or deleted. A short or common pattern can be guessed by someone who also extracts this device's keys — use 8 or
            more dots.
          </span>
        </li>
      </ul>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" onClick={() => { setUnderstood(false); setCreating(true); }} className="rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white hover:opacity-90">
          Create a hidden vault
        </button>
        <button type="button" onClick={() => setOpening(true)} className="flex items-center gap-2 rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-800 hover:bg-canvas">
          <Grid3x3 className="text-violet-600" size={14} /> Open a hidden vault here
        </button>
        <button type="button" onClick={() => setRecovering(true)} className="flex items-center gap-2 rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-800 hover:bg-canvas">
          <KeyRound className="text-violet-600" size={14} /> Forgot a pattern? Use a recovery phrase
        </button>
        <button type="button" disabled={erasing} onClick={() => void eraseAll()} className="flex items-center gap-2 rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-800 hover:bg-canvas disabled:opacity-50">
          {erasing ? <Loader2 className="animate-spin" size={14} /> : <Trash2 className="text-rose-500" size={14} />} Erase all hidden vaults
        </button>
      </div>
      {creating && (
        <Modal title="Create a hidden vault" onClose={() => setCreating(false)}>
          {!understood ? (
            <div className="space-y-3 text-sm text-ink-700">
              <p>
                You will draw a new pattern twice. When it is set, the hidden vault opens straight away and your Quantum Vault locks.
                Next time, open it by drawing this pattern on the vault lock screen (choose <em>Pattern</em> there).
              </p>
              <p className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs font-semibold text-amber-800">
                Remember the pattern. Once the vault is open, set up its 12-word recovery phrase (Recovery phrase card) — without it, a
                forgotten pattern cannot be recovered.
              </p>
              <button type="button" onClick={() => setUnderstood(true)} className="w-full rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-bold text-white hover:opacity-90">
                I understand — draw the pattern
              </button>
            </div>
          ) : (
            <PatternCapture
              mode="set"
              submitLabel="Creating the hidden vault…"
              onSubmit={async (pattern) => {
                await hiddenVault.create(pattern);
                setCreating(false);
                controls.onHiddenOpened();
              }}
            />
          )}
        </Modal>
      )}
      {opening && (
        <Modal title="Open a hidden vault" onClose={() => setOpening(false)}>
          <p className="mb-3 text-xs text-ink-600">
            Draw the hidden vault's pattern. Opened from here, a vault armed for duress erase does <strong>not</strong> fire, so you can
            add files to a decoy safely. Your Quantum Vault locks while it is open. Each try counts toward the pattern attempt limit.
          </p>
          <PatternCapture
            mode="unlock"
            submitLabel="Opening…"
            onSubmit={async (pattern) => {
              await hiddenVault.open(pattern);
              setOpening(false);
              controls.onHiddenOpened();
            }}
          />
        </Modal>
      )}
      {recovering && (
        <Modal title="Recover a hidden vault" onClose={() => setRecovering(false)}>
          <RecoverHiddenVault
            onRecovered={() => {
              setRecovering(false);
              controls.onHiddenOpened();
            }}
          />
        </Modal>
      )}
    </section>
  );
}
