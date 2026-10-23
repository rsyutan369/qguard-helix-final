import { useCallback, useEffect, useRef, useState } from "react";
import { CheckCircle2, Loader2, RefreshCcw, ShieldAlert, Smartphone } from "lucide-react";
import { QrCode } from "@/components/auth/QrCode";
import {
  buildLinkPayload,
  claimLink,
  describeClaimFailure,
  describeLinkError,
  generateBindingSecret,
  platformLabel,
  rememberLinkCompletion,
  startLink,
  thisDevicePlatform,
  type LinkCredential,
} from "@/lib/device-link";

/** Fresh codes are issued automatically this many times before asking for a tap. */
const AUTO_REFRESHES = 4;

type Phase =
  | { kind: "opening" }
  | { kind: "showing"; payload: string; code: string; expiresAt: number }
  | { kind: "approved" }
  | { kind: "stopped"; message: string; tone: "info" | "error" };

interface LinkThisDevicePanelProps {
  onCredential: (credential: LinkCredential) => Promise<boolean>;
  onCancel: () => void;
}

/**
 * The signed-out side of "Link a device": show a QR code for a signed-in phone
 * or desktop to scan, wait for its approval, then sign in with the one-time
 * credential the service issues to this device alone.
 */
export function LinkThisDevicePanel({ onCredential, onCancel }: LinkThisDevicePanelProps) {
  const [phase, setPhase] = useState<Phase>({ kind: "opening" });
  const [now, setNow] = useState(() => Date.now());
  const refreshesRef = useRef(0);
  const generationRef = useRef(0);
  const credentialRef = useRef(onCredential);
  credentialRef.current = onCredential;
  const platform = thisDevicePlatform();

  const open = useCallback(async () => {
    const generation = ++generationRef.current;
    setPhase({ kind: "opening" });
    let link;
    try {
      link = await startLink(platformLabel(platform), platform);
    } catch (error) {
      if (generation === generationRef.current) setPhase({ kind: "stopped", message: describeLinkError(error), tone: "error" });
      return;
    }
    if (generation !== generationRef.current) return;
    const bindingSecret = generateBindingSecret();
    setPhase({ kind: "showing", payload: buildLinkPayload(link.code, bindingSecret), code: link.code, expiresAt: Date.parse(link.expiresAt) });

    // Poll until approved, refused or expired. Each generation stops itself
    // once a newer one (refresh, cancel, unmount) has started.
    const poll = async () => {
      if (generation !== generationRef.current) return;
      try {
        const result = await claimLink(link.linkId, link.claimSecret);
        if (generation !== generationRef.current) return;
        switch (result.status) {
          case "pending":
            break;
          case "approved":
            generationRef.current += 1;
            setPhase({ kind: "approved" });
            rememberLinkCompletion({ linkId: link.linkId, claimSecret: link.claimSecret, bindingSecret });
            if (!(await credentialRef.current(result.credential))) {
              // Either MFA is now showing (the panel unmounts) or redemption failed (error shown).
              setPhase({ kind: "stopped", message: "Show a new QR code to try again.", tone: "info" });
            }
            return;
          case "expired":
            if (refreshesRef.current < AUTO_REFRESHES) {
              refreshesRef.current += 1;
              void open();
            } else {
              setPhase({ kind: "stopped", message: "The QR code expired. Show a new one when your other device is ready.", tone: "info" });
            }
            return;
          case "rejected":
            setPhase({ kind: "stopped", message: "The request was declined on your other device.", tone: "error" });
            return;
          case "failed":
            setPhase({ kind: "stopped", message: describeClaimFailure(result.reason), tone: "error" });
            return;
          default:
            setPhase({ kind: "stopped", message: "This QR code was already used. Show a new one.", tone: "info" });
            return;
        }
      } catch {
        // A dropped poll is retried; a real outage shows as an expired code.
      }
      setTimeout(() => void poll(), link.pollIntervalMs);
    };
    setTimeout(() => void poll(), link.pollIntervalMs);
  }, [platform]);

  useEffect(() => {
    void open();
    return () => {
      generationRef.current += 1;
    };
  }, [open]);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const secondsLeft = phase.kind === "showing" ? Math.max(0, Math.ceil((phase.expiresAt - now) / 1000)) : 0;

  return (
    <div className="mt-6">
      <div className="flex flex-col items-center">
        <div className="relative grid h-[248px] w-[248px] place-items-center rounded-2xl border border-white/10 bg-white/[0.04] p-2">
          {phase.kind === "showing" && <QrCode value={phase.payload} label="QR code to link this device" />}
          {phase.kind === "opening" && <Loader2 size={28} className="animate-spin text-violet-300" aria-label="Preparing QR code" />}
          {phase.kind === "approved" && (
            <div className="flex flex-col items-center gap-2 text-center text-emerald-200">
              <CheckCircle2 size={34} />
              <span className="text-[13px] font-semibold">Approved — signing in…</span>
            </div>
          )}
          {phase.kind === "stopped" && (
            <div className="flex flex-col items-center gap-3 px-4 text-center">
              <ShieldAlert size={28} className={phase.tone === "error" ? "text-rose-300" : "text-violet-300"} />
              <span className={`text-[13px] font-semibold ${phase.tone === "error" ? "text-rose-200" : "text-white/70"}`}>{phase.message}</span>
            </div>
          )}
        </div>

        {phase.kind === "showing" && (
          <div className="mt-3 text-center">
            <div className="font-mono text-[15px] font-semibold tracking-[0.18em] text-white/85" aria-label="Link code">{phase.code}</div>
            <div className="mt-1 text-[12px] text-white/45" aria-live="polite">
              {secondsLeft > 0 ? `Refreshes in ${secondsLeft}s` : "Refreshing…"}
            </div>
          </div>
        )}

        {phase.kind === "stopped" && (
          <button
            type="button"
            onClick={() => {
              refreshesRef.current = 0;
              void open();
            }}
            className="mt-4 flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.06] px-4 py-2.5 text-[13px] font-semibold text-white transition hover:bg-white/[0.1]"
          >
            <RefreshCcw size={14} /> Show a new QR code
          </button>
        )}
      </div>

      <ol className="mt-6 grid gap-2.5 text-[13px] leading-5 text-white/65">
        <li className="flex gap-2.5"><span className="font-bold text-violet-300">1.</span><span>Open QGuard Helix on a phone or computer where you're already signed in.</span></li>
        <li className="flex gap-2.5"><span className="font-bold text-violet-300">2.</span><span>Go to <span className="font-semibold text-white/85">Devices → Link a device</span>.</span></li>
        <li className="flex gap-2.5"><span className="font-bold text-violet-300">3.</span><span>Scan this code (or type the code under it) and approve.</span></li>
      </ol>

      <div className="mt-5 flex items-start gap-2.5 rounded-xl border border-amber-300/20 bg-amber-400/[0.07] p-3 text-[12px] leading-5 text-amber-100/85">
        <Smartphone size={15} className="mt-0.5 shrink-0" />
        <span>This device gets its own session and its own encryption keys. Your messages stay end-to-end encrypted; nothing is copied from the other device.</span>
      </div>

      <button
        type="button"
        onClick={() => {
          generationRef.current += 1;
          onCancel();
        }}
        className="mt-5 w-full text-[13px] font-semibold text-white/50 transition hover:text-white/80"
      >
        Back to sign in
      </button>
    </div>
  );
}
