import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, Camera, CheckCircle2, Keyboard, Laptop, Loader2, MonitorSmartphone, ShieldCheck, Smartphone, X } from "lucide-react";
import { supabase } from "@/lib/supabase";
import { useQrScanner } from "@/lib/qr-scanner";
import {
  approveLink,
  describeLinkError,
  inspectLink,
  linkStatus,
  parseLinkPayload,
  platformLabel,
  rejectLink,
  type LinkInspection,
  type ParsedLinkPayload,
} from "@/lib/device-link";
import { trustLinkedDevice } from "@/lib/device-link-trust";

/** How long to wait for the new device to sign in (it may be answering an MFA prompt). */
const COMPLETION_TIMEOUT_MS = 4 * 60_000;
const STATUS_POLL_MS = 2000;

type Step =
  | { kind: "scan" }
  | { kind: "checking" }
  | { kind: "confirm"; parsed: ParsedLinkPayload; request: LinkInspection }
  | { kind: "approving" }
  | { kind: "waiting"; parsed: ParsedLinkPayload; linkId: string; label: string }
  | { kind: "done"; title: string; detail: string; tone: "success" | "warning" }
  | { kind: "error"; message: string };

interface LinkDeviceDialogProps {
  open: boolean;
  userId: string;
  approverDeviceId: string | null;
  onClose: () => void;
  onLinked?: () => void;
}

function PlatformIcon({ platform }: { platform: string }) {
  if (platform === "android" || platform === "ios") return <Smartphone size={22} />;
  if (platform === "web") return <MonitorSmartphone size={22} />;
  return <Laptop size={22} />;
}

async function currentAccessToken(): Promise<string> {
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  if (!token) throw new Error("Your session has expired. Sign in again to link a device.");
  return token;
}

/**
 * The signed-in side of "Link a device": scan the QR code a new device shows,
 * confirm it is the user's own, approve — then trust it once it proves it is
 * the device that was scanned.
 */
export function LinkDeviceDialog({ open, userId, approverDeviceId, onClose, onLinked }: LinkDeviceDialogProps) {
  const [step, setStep] = useState<Step>({ kind: "scan" });
  const [manual, setManual] = useState(false);
  const [typedCode, setTypedCode] = useState("");
  const aliveRef = useRef(true);
  const linkedRef = useRef(onLinked);
  linkedRef.current = onLinked;

  useEffect(() => {
    aliveRef.current = true;
    if (open) {
      setStep({ kind: "scan" });
      setManual(false);
      setTypedCode("");
    }
    return () => {
      aliveRef.current = false;
    };
  }, [open]);

  const examine = useCallback(async (raw: string) => {
    const parsed = parseLinkPayload(raw);
    if (!parsed) {
      setStep({ kind: "error", message: "That isn't a QGuard Helix link code. Scan the QR code shown on the new device's sign-in screen." });
      return;
    }
    setStep({ kind: "checking" });
    try {
      const request = await inspectLink(parsed.code, await currentAccessToken());
      if (aliveRef.current) setStep({ kind: "confirm", parsed, request });
    } catch (error) {
      if (aliveRef.current) setStep({ kind: "error", message: describeLinkError(error) });
    }
  }, []);

  const scanning = open && step.kind === "scan" && !manual;
  const scanner = useQrScanner(scanning, (value) => void examine(value));

  async function approve(parsed: ParsedLinkPayload, request: LinkInspection) {
    setStep({ kind: "approving" });
    try {
      const approved = await approveLink(parsed.code, approverDeviceId, await currentAccessToken());
      if (aliveRef.current) setStep({ kind: "waiting", parsed, linkId: approved.linkId, label: request.label });
    } catch (error) {
      if (aliveRef.current) setStep({ kind: "error", message: describeLinkError(error) });
    }
  }

  async function decline(parsed: ParsedLinkPayload) {
    try {
      await rejectLink(parsed.code, await currentAccessToken());
    } catch {
      // Declining is best effort: an ignored code expires within two minutes anyway.
    }
    if (aliveRef.current) setStep({ kind: "done", title: "Request declined", detail: "The other device was told no. If you didn't start this, someone may have tried to trick you into scanning their code — your account is unchanged.", tone: "warning" });
  }

  // Follow the approved link until the new device has signed in and proved itself.
  useEffect(() => {
    if (step.kind !== "waiting") return undefined;
    let cancelled = false;
    const startedAt = Date.now();
    const { parsed, linkId, label } = step;

    const tick = async () => {
      if (cancelled) return;
      try {
        const status = await linkStatus(linkId, await currentAccessToken());
        if (cancelled) return;
        if (status.status === "failed") {
          setStep({ kind: "error", message: "The new device couldn't finish signing in. Ask it to show a new QR code and try again." });
          return;
        }
        if (status.linkedDeviceId) {
          if (!parsed.bindingSecret) {
            setStep({ kind: "done", title: `${label} is signed in`, detail: "Because the code was typed rather than scanned, approve the new device in the Device Trust Center to start syncing messages to it.", tone: "warning" });
            linkedRef.current?.();
            return;
          }
          const outcome = await trustLinkedDevice({
            client: supabase,
            userId,
            linkId,
            bindingSecret: parsed.bindingSecret,
            linkedDeviceId: status.linkedDeviceId,
            linkProof: status.linkProof,
            approverDeviceId,
          });
          if (cancelled) return;
          setStep(outcome.trusted
            ? { kind: "done", title: `${outcome.label} is linked`, detail: "It's signed in, verified as the device you scanned, and trusted on this device. New messages will reach it end-to-end encrypted.", tone: "success" }
            : { kind: "done", title: `${label} is signed in`, detail: outcome.reason, tone: "warning" });
          linkedRef.current?.();
          return;
        }
      } catch {
        // Transient: keep following until the timeout.
      }
      if (Date.now() - startedAt > COMPLETION_TIMEOUT_MS) {
        setStep({ kind: "done", title: "Approved", detail: "The new device hasn't finished signing in yet. Once it does, it will appear in your device list for review.", tone: "warning" });
        return;
      }
      setTimeout(() => void tick(), STATUS_POLL_MS);
    };
    void tick();
    return () => {
      cancelled = true;
    };
  }, [approverDeviceId, step, userId]);

  if (!open) return null;

  const close = () => {
    if (step.kind === "confirm") void decline(step.parsed);
    onClose();
  };

  return createPortal(
    <div
      className="tour-fade fixed inset-0 z-[80] flex items-end justify-center bg-slate-900/55 p-0 backdrop-blur-sm sm:items-center sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="link-device-title"
    >
      <div className="tour-card mobile-safe-bottom flex max-h-[100dvh] w-full flex-col overflow-hidden rounded-t-2xl border border-line bg-white shadow-soft sm:max-h-[calc(100vh-2rem)] sm:w-[min(92vw,440px)] sm:rounded-2xl">
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <div className="flex items-center gap-2.5">
            <span className="grid h-9 w-9 place-items-center rounded-xl bg-violet-50 text-violet-600"><MonitorSmartphone size={18} /></span>
            <div>
              <h2 id="link-device-title" className="text-sm font-bold text-ink-950">Link a device</h2>
              <p className="text-xs text-ink-500">Sign in a phone or computer with a QR code</p>
            </div>
          </div>
          <button type="button" aria-label="Close" onClick={close} className="icon-button"><X size={16} /></button>
        </div>

        <div className="overflow-y-auto p-5">
          {step.kind === "scan" && (
            <>
              {!manual ? (
                <div className="relative mx-auto aspect-square w-full max-w-[320px] overflow-hidden rounded-2xl bg-ink-950">
                  <video ref={scanner.videoRef} className="h-full w-full object-cover" muted playsInline />
                  <div className="pointer-events-none absolute inset-[14%] rounded-2xl border-2 border-white/80 shadow-[0_0_0_9999px_rgba(0,0,0,0.35)]" aria-hidden />
                  {scanner.starting && (
                    <div className="absolute inset-0 grid place-items-center text-white/80"><Loader2 className="animate-spin" size={26} /></div>
                  )}
                  {scanner.error && (
                    <div className="absolute inset-0 grid place-items-center bg-ink-950/90 p-5 text-center text-xs font-semibold leading-5 text-white/85">{scanner.error}</div>
                  )}
                </div>
              ) : (
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    void examine(typedCode);
                  }}
                >
                  <label className="block text-xs font-bold text-ink-700" htmlFor="link-code">Code shown under the QR</label>
                  <input
                    id="link-code"
                    value={typedCode}
                    onChange={(event) => setTypedCode(event.target.value.toUpperCase().slice(0, 16))}
                    placeholder="XXXX-XXXX-XXXX"
                    autoComplete="off"
                    autoCapitalize="characters"
                    spellCheck={false}
                    className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-3 text-center font-mono text-lg tracking-[0.2em] outline-none focus:border-cyan-300"
                  />
                  <button type="submit" disabled={typedCode.replace(/[^0-9A-Z]/gi, "").length < 12} className="mt-3 w-full rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-violet-700 disabled:opacity-50">
                    Continue
                  </button>
                </form>
              )}
              <p className="mt-4 text-center text-xs leading-5 text-ink-500">
                On the new device, choose <span className="font-semibold text-ink-700">Link with QR code</span> on the sign-in screen, then point this camera at it.
              </p>
              <button
                type="button"
                onClick={() => setManual((value) => !value)}
                className="mx-auto mt-3 flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-xs font-bold text-ink-700 hover:bg-canvas"
              >
                {manual ? <><Camera size={14} /> Scan with camera</> : <><Keyboard size={14} /> Type the code instead</>}
              </button>
            </>
          )}

          {(step.kind === "checking" || step.kind === "approving") && (
            <div className="flex flex-col items-center gap-3 py-10 text-sm font-semibold text-ink-600">
              <Loader2 className="animate-spin text-violet-600" size={26} />
              {step.kind === "checking" ? "Checking the request…" : "Approving…"}
            </div>
          )}

          {step.kind === "confirm" && (
            <div>
              <div className="flex items-center gap-3 rounded-xl border border-line bg-canvas p-4">
                <span className="grid h-11 w-11 place-items-center rounded-xl bg-white text-violet-600 shadow-sm"><PlatformIcon platform={step.request.platform} /></span>
                <div className="min-w-0">
                  <div className="truncate text-sm font-bold text-ink-950">{step.request.label}</div>
                  <div className="text-xs text-ink-500">{platformLabel(step.request.platform)}</div>
                </div>
              </div>
              <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
                <dt className="text-ink-500">Requested</dt>
                <dd className="text-right font-semibold text-ink-800">{new Date(step.request.createdAt).toLocaleTimeString()}</dd>
                <dt className="text-ink-500">From network</dt>
                <dd className="text-right font-mono font-semibold text-ink-800">{step.request.ip ?? "Unknown"}</dd>
                <dt className="text-ink-500">Identity binding</dt>
                <dd className={`text-right font-semibold ${step.parsed.bindingSecret ? "text-emerald-600" : "text-amber-600"}`}>
                  {step.parsed.bindingSecret ? "Scanned — will be verified" : "Typed — manual review"}
                </dd>
              </dl>
              <div className="mt-4 flex gap-2.5 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs leading-5 text-amber-800">
                <AlertTriangle size={16} className="mt-0.5 shrink-0" />
                <span>
                  Only approve if <strong>you</strong> are signing in on this device right now. Never scan a code someone sent you or showed you — approving gives that device full access to your account.
                </span>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-2.5">
                <button type="button" onClick={() => void decline(step.parsed)} className="rounded-lg border border-line px-4 py-2.5 text-sm font-bold text-ink-700 hover:bg-canvas">
                  Not me
                </button>
                <button type="button" onClick={() => void approve(step.parsed, step.request)} className="rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-violet-700">
                  Link device
                </button>
              </div>
            </div>
          )}

          {step.kind === "waiting" && (
            <div className="flex flex-col items-center gap-3 py-8 text-center">
              <Loader2 className="animate-spin text-violet-600" size={26} />
              <div className="text-sm font-bold text-ink-900">Waiting for {step.label} to sign in…</div>
              <p className="max-w-[300px] text-xs leading-5 text-ink-500">
                If your account uses an authenticator app, enter its code on the new device. Keep this window open so the device can be verified and trusted.
              </p>
            </div>
          )}

          {step.kind === "done" && (
            <div className="flex flex-col items-center gap-3 py-6 text-center">
              {step.tone === "success" ? <CheckCircle2 className="text-emerald-500" size={34} /> : <ShieldCheck className="text-amber-500" size={34} />}
              <div className="text-sm font-bold text-ink-950">{step.title}</div>
              <p className="max-w-[320px] text-xs leading-5 text-ink-500">{step.detail}</p>
              <button type="button" onClick={onClose} className="mt-2 rounded-lg bg-violet-600 px-5 py-2.5 text-sm font-bold text-white hover:bg-violet-700">Done</button>
            </div>
          )}

          {step.kind === "error" && (
            <div className="flex flex-col items-center gap-3 py-6 text-center">
              <AlertTriangle className="text-rose-500" size={30} />
              <p className="max-w-[320px] text-sm font-semibold leading-6 text-ink-800">{step.message}</p>
              <button type="button" onClick={() => setStep({ kind: "scan" })} className="mt-1 rounded-lg border border-line px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas">Try again</button>
            </div>
          )}
        </div>
      </div>
    </div>,
    document.body,
  );
}
