import { useEffect, useState } from "react";
import { EyeOff, Fingerprint, ShieldAlert, Trash2 } from "lucide-react";
import { supabase } from "@/lib/supabase";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";
import type { BiometricStatus, useAppLock } from "@/lib/use-app-lock";

interface RecentsMasking {
  supported: boolean;
  enabled: boolean;
  method: string;
}

type Note = { tone: "ok" | "error"; text: string } | null;

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Settings → Device privacy (roadmap Phase 4): hide the app in Recent apps
 * (Android), biometric unlock and a duress PIN for the app PIN (Android), and
 * the panic wipe (every platform). Every state shown is what the core
 * reported, never the last button pressed.
 */
export function DevicePrivacyCard({ userId, appLock }: { userId: string; appLock?: ReturnType<typeof useAppLock> }) {
  const [masking, setMasking] = useState<RecentsMasking | null>(null);
  const [biometric, setBiometric] = useState<BiometricStatus | null>(null);
  const [duressPin, setDuressPin] = useState("");
  const [duressConfirm, setDuressConfirm] = useState("");
  const [showDuress, setShowDuress] = useState(false);
  const [wipeOpen, setWipeOpen] = useState(false);
  const [wipeConfirm, setWipeConfirm] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<Note>(null);
  const pinConfigured = Boolean(appLock?.status?.configured);
  // A duress PIN is typed on the PIN keypad; a pattern lock has no keypad, and
  // the core never checks a duress PIN against a drawn pattern.
  const patternLock = appLock?.status?.method === "pattern";

  useEffect(() => {
    if (!isTauriRuntime()) return;
    void safeInvoke<RecentsMasking>("privacy_recents_masking_status").then(setMasking).catch(() => setMasking(null));
  }, []);
  useEffect(() => {
    if (!appLock || !pinConfigured) return;
    void appLock.biometricStatus().then(setBiometric).catch(() => setBiometric(null));
  }, [appLock, pinConfigured]);

  if (!isTauriRuntime()) return null;

  const run = async (key: string, action: () => Promise<void>) => {
    setBusy(key);
    setNote(null);
    try {
      await action();
    } catch (error) {
      setNote({ tone: "error", text: errorText(error) });
    } finally {
      setBusy(null);
    }
  };

  const toggleMasking = () => run("masking", async () => {
    setMasking(await safeInvoke<RecentsMasking>("privacy_set_recents_masking", { enabled: !masking?.enabled }));
  });

  const toggleBiometric = () => run("biometric", async () => {
    if (!appLock) return;
    const next = biometric?.enabled ? await appLock.disableBiometric() : await appLock.enableBiometric();
    setBiometric(next);
    setNote({ tone: "ok", text: next.enabled ? "Biometric unlock is on. Your PIN still works, and is needed after a restart of the device's biometrics." : "Biometric unlock is off." });
  });

  const saveDuress = () => run("duress", async () => {
    if (!appLock) return;
    if (!/^\d{6}$/.test(duressPin)) throw new Error("The duress PIN must be 6 digits.");
    if (duressPin !== duressConfirm) throw new Error("The two duress PINs do not match.");
    await appLock.setDuressPin(duressPin);
    setDuressPin("");
    setDuressConfirm("");
    setShowDuress(false);
    setNote({ tone: "ok", text: "Duress PIN saved. Entering it at the lock screen erases this device's keys and shows the sign-in screen, as if the session had expired." });
  });

  const clearDuress = () => run("duress", async () => {
    await appLock?.clearDuressPin();
    setNote({ tone: "ok", text: "Duress PIN removed." });
  });

  const panicWipe = () => run("wipe", async () => {
    // Best effort, and quick: tell the relay this device is gone so nothing
    // more is sealed to it. The wipe does not wait on the network.
    const bundle = await safeInvoke<{ device_id?: string } | null>("keys_upload_identity_bundle", { userId }, null).catch(() => null);
    if (bundle?.device_id) {
      // The same server-side revocation the Device Trust Center uses.
      await Promise.race([
        supabase.rpc("revoke_messaging_device", { p_device_id: bundle.device_id }),
        new Promise((resolve) => window.setTimeout(resolve, 3000)),
      ]).catch(() => undefined);
    }
    await safeInvoke("privacy_panic_wipe", { confirmation: wipeConfirm });
    await supabase.auth.signOut({ scope: "local" }).catch(() => undefined);
    window.location.reload();
  });

  return (
    <section className="shell-card p-5">
      <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><ShieldAlert size={18} /> Device privacy</div>
      <div className="mt-3 space-y-4 text-sm text-ink-600">
        {masking?.supported && (
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 font-semibold text-ink-900"><EyeOff size={15} /> Hide in Recent apps</div>
              <p className="mt-0.5 text-xs">
                Shows a blank card instead of your chats in the app switcher. Screenshots keep working.
              </p>
            </div>
            <button
              type="button"
              disabled={busy !== null}
              onClick={() => void toggleMasking()}
              className="rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas disabled:opacity-60"
            >
              {masking.enabled ? "On — turn off" : "Off — turn on"}
            </button>
          </div>
        )}

        {pinConfigured && biometric && biometric.availability !== "unsupported" && (
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 font-semibold text-ink-900"><Fingerprint size={15} /> Unlock with fingerprint or face</div>
              <p className="mt-0.5 text-xs">
                {biometric.availability === "available"
                  ? "Uses this device's strong biometric. Adding a new fingerprint or face turns it off until you set it up again."
                  : biometric.availability === "none_enrolled"
                    ? "Set up a fingerprint or face in Android settings first."
                    : "This device has no strong biometric sensor available."}
              </p>
            </div>
            <button
              type="button"
              disabled={busy !== null || (!biometric.enabled && biometric.availability !== "available")}
              onClick={() => void toggleBiometric()}
              className="rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas disabled:opacity-60"
            >
              {biometric.enabled ? "On — turn off" : "Turn on"}
            </button>
          </div>
        )}

        {pinConfigured && appLock?.status && !appLock.status.locked && (
          <div>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="font-semibold text-ink-900">Duress PIN</div>
                {patternLock ? (
                  <p className="mt-0.5 text-xs">
                    Not available while this device unlocks with a pattern: a duress PIN is typed on the PIN keypad, and
                    the pattern screen has none.{" "}
                    {appLock.status.duressConfigured
                      ? "Your saved duress PIN does nothing right now. It works again if you switch back to a PIN in Application PIN above, or you can remove it."
                      : "Switch to a 6-digit PIN in Application PIN above to use one."}
                  </p>
                ) : (
                  <p className="mt-0.5 text-xs">
                    A second PIN for when you are forced to unlock. Entered at the lock screen, it erases this device&apos;s
                    keys and shows the sign-in screen, as if the session had expired. Messages already on the relay stay
                    unreadable without your other devices or recovery kit.
                  </p>
                )}
              </div>
              <div className="flex gap-2">
                {!patternLock && (
                  <button
                    type="button"
                    disabled={busy !== null}
                    onClick={() => setShowDuress((open) => !open)}
                    className="rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas disabled:opacity-60"
                  >
                    {appLock.status.duressConfigured ? "Change" : "Set up"}
                  </button>
                )}
                {appLock.status.duressConfigured && (
                  <button
                    type="button"
                    disabled={busy !== null}
                    onClick={() => void clearDuress()}
                    className="rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas disabled:opacity-60"
                  >
                    Remove
                  </button>
                )}
              </div>
            </div>
            {showDuress && !patternLock && (
              <div className="mt-2 flex flex-wrap gap-2">
                <input value={duressPin} onChange={(e) => setDuressPin(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" type="password" placeholder="6-digit duress PIN" aria-label="Duress PIN" className="w-40 rounded-lg border border-line bg-canvas px-3 py-1.5 text-sm" />
                <input value={duressConfirm} onChange={(e) => setDuressConfirm(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" type="password" placeholder="Repeat it" aria-label="Repeat the duress PIN" className="w-40 rounded-lg border border-line bg-canvas px-3 py-1.5 text-sm" />
                <button type="button" disabled={busy !== null} onClick={() => void saveDuress()} className="rounded-lg bg-ink-950 px-3 py-1.5 text-xs font-bold text-white disabled:opacity-60">Save</button>
              </div>
            )}
          </div>
        )}

        <div className="rounded-lg border border-rose-200 bg-rose-50/60 p-3">
          <div className="flex items-center gap-2 font-semibold text-rose-800"><Trash2 size={15} /> Erase this device</div>
          <p className="mt-0.5 text-xs text-rose-800">
            Destroys this device&apos;s keys for your account — messages, the Quantum Vault key, secure sessions, and
            the app PIN — and signs you out. It cannot be undone. Your other devices and your recovery kit are not
            affected; vault files stay encrypted and open only with your recovery kit.
          </p>
          {!wipeOpen ? (
            <button type="button" onClick={() => setWipeOpen(true)} className="mt-2 rounded-lg border border-rose-300 bg-white px-3 py-1.5 text-xs font-bold text-rose-700 hover:bg-rose-50">
              Erase this device…
            </button>
          ) : (
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <input value={wipeConfirm} onChange={(e) => setWipeConfirm(e.target.value)} placeholder="Type ERASE" aria-label="Type ERASE to confirm" className="w-36 rounded-lg border border-rose-300 bg-white px-3 py-1.5 text-sm" />
              <button
                type="button"
                disabled={busy !== null || wipeConfirm.trim() !== "ERASE"}
                onClick={() => void panicWipe()}
                className="rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-rose-700 disabled:opacity-50"
              >
                {busy === "wipe" ? "Erasing…" : "Erase now"}
              </button>
              <button type="button" onClick={() => { setWipeOpen(false); setWipeConfirm(""); }} className="text-xs font-bold text-ink-600">Cancel</button>
            </div>
          )}
        </div>

        {note && (
          <div className={`rounded-md border p-2 text-xs font-semibold ${note.tone === "ok" ? "border-emerald-100 bg-emerald-50 text-emerald-700" : "border-rose-100 bg-rose-50 text-rose-700"}`}>
            {note.text}
          </div>
        )}
      </div>
    </section>
  );
}
