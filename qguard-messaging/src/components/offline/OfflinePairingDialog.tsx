import { useId, useLayoutEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { Fingerprint, Laptop, LoaderCircle, Monitor, MonitorSmartphone, ShieldCheck, Smartphone, Terminal } from "lucide-react";
import type { OfflinePairing, OfflinePairingDecision } from "@/lib/offline";
import "./offline-pairing-dialog.css";

interface OfflinePairingDialogProps {
  pairing: OfflinePairing | null;
  busy?: boolean;
  error?: string | null;
  onDecide: (id: string, decision: OfflinePairingDecision) => void;
  onDismiss: (id: string) => void;
  onRetry?: (pairing: OfflinePairing) => void;
  /** `intent` is set for XFER: send files now, or wait for the other device's files. */
  onOpen: (mode: "mesh" | "xfer", fingerprint: string, intent?: "send" | "receive") => void;
}

const platformDetails = {
  android: { name: "Android", icon: Smartphone },
  windows: { name: "Windows", icon: Monitor },
  macos: { name: "macOS", icon: Laptop },
  linux: { name: "Linux", icon: Terminal },
  ios: { name: "iOS", icon: Smartphone },
};

export function offlinePairingPlatform(platform: string | null | undefined) {
  const key = platform?.toLowerCase() ?? "";
  return Object.hasOwn(platformDetails, key)
    ? platformDetails[key as keyof typeof platformDetails]
    : { name: "Platform unknown", icon: MonitorSmartphone };
}

const stageContent = {
  requesting: {
    title: "Connecting to device",
    detail: "Opening an encrypted connection over your local network or Bluetooth. Over Bluetooth this can take a few seconds. Keep both devices close and Qguard open on both.",
  },
  awaitingApproval: {
    title: "Connection request sent",
    detail: "Waiting for approval on the other device.",
  },
  verifying: {
    title: "Verify you’re connecting to the right device",
    detail: "Check the verification code displayed on both devices. Confirm only if the codes match and you recognize the other device.",
  },
  awaitingConfirmation: {
    title: "Waiting for mutual confirmation",
    detail: "You confirmed the code. Ask the other user to compare and confirm it on their device.",
  },
  establishing: {
    title: "Establishing a secure session",
    detail: "Finishing mutual identity verification and saving your trusted device.",
  },
  trusted: {
    title: "Device successfully trusted",
    detail: "Both devices confirmed the verification code. You can now use the available offline features with this device.",
  },
  rejected: {
    title: "Connection declined",
    detail: "This pairing request was declined. You can start a new request when both users are ready.",
  },
  cancelled: {
    title: "Pairing cancelled",
    detail: "The pairing session ended before completion.",
  },
  failed: {
    title: "Pairing couldn’t finish",
    detail: "Keep both devices nearby, check that local discovery is running, then try again.",
  },
  expired: {
    title: "Pairing request expired",
    detail: "Start a new request and complete the approval and verification on both devices.",
  },
} satisfies Record<OfflinePairing["status"], { title: string; detail: string }>;

export function OfflinePairingDialog({ pairing, ...props }: OfflinePairingDialogProps) {
  return pairing ? createPortal(<PairingSessionDialog key={pairing.id} pairing={pairing} {...props} />, document.body) : null;
}

function PairingSessionDialog({ pairing, busy, error, onDecide, onDismiss, onRetry, onOpen }: OfflinePairingDialogProps & { pairing: OfflinePairing }) {
  const modal = useRef<HTMLDialogElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const titleId = useId();
  const detailId = useId();
  const { id, status, direction, peer, label, platform, requested, code } = pairing;
  const incoming = direction === "incoming" && status === "awaitingApproval";
  const trusted = status === "trusted";
  const ended = status === "rejected" || status === "cancelled" || status === "failed" || status === "expired";
  const waiting = status === "requesting" || (status === "awaitingApproval" && !incoming) || status === "awaitingConfirmation" || status === "establishing";
  const showCode = Boolean(code) && (status === "verifying" || status === "awaitingConfirmation");
  // Trust covers exactly what both users approved, not everything the device supports.
  const canMessage = requested.includes("mesh");
  const canTransfer = requested.includes("xfer");
  const displayedCapabilities = requested;
  const verificationStep = status === "verifying" || status === "awaitingConfirmation" || status === "establishing";
  const activeStep = trusted ? 2 : verificationStep ? 1 : 0;
  const PlatformIcon = offlinePairingPlatform(platform).icon;
  const content = incoming
    ? { title: "New device connection request", detail: "A nearby Qguard Messaging device wants to connect with you. Allow the request to compare a verification code on both devices." }
    : stageContent[status];

  useLayoutEffect(() => {
    const dialog = modal.current;
    const previous = document.activeElement;
    dialog?.showModal();
    return () => {
      dialog?.close();
      if (previous instanceof HTMLElement && previous.isConnected && document.activeElement === document.body) {
        previous.focus({ preventScroll: true });
      }
    };
  }, []);

  useLayoutEffect(() => {
    heading.current?.focus();
  }, [status]);

  function cancel() {
    if (busy) return;
    if (trusted || ended) onDismiss(id);
    else onDecide(id, incoming ? "reject" : "cancel");
  }

  return (
    <dialog
      ref={modal}
      className="offline-pairing-dialog"
      aria-labelledby={titleId}
      aria-describedby={detailId}
      onCancel={(event) => {
        event.preventDefault();
        cancel();
      }}
    >
      <div className="offline-pairing-content">
        <header className="offline-pairing-heading">
          <span className="offline-pairing-emblem" data-success={trusted} aria-hidden="true">
            {trusted ? <ShieldCheck size={24} /> : waiting ? <LoaderCircle size={24} className="offline-pairing-spinner" /> : <Fingerprint size={24} />}
          </span>
          <div>
            <p className="offline-pairing-eyebrow">OFFGRID · Device pairing</p>
            <h2 id={titleId} ref={heading} tabIndex={-1}>{content.title}</h2>
          </div>
        </header>
        {!ended && <ol className="offline-pairing-stages" aria-label="Pairing progress">
          {["Request", "Verify", "Trusted"].map((step, index) => (
            <li key={step} aria-current={activeStep === index ? "step" : undefined} data-complete={activeStep > index}>
              <span aria-hidden="true">{index + 1}</span> {step}
            </li>
          ))}
        </ol>}
        <p id={detailId} className="offline-pairing-description" aria-live="polite">{content.detail}</p>
        <section className="offline-pairing-peer" aria-label="Device details">
          <div className="offline-pairing-peer-heading">
            <span className="offline-pairing-platform" aria-hidden="true"><PlatformIcon size={22} /></span>
            <div>
              <p className="offline-pairing-peer-name">{label || "Nearby Qguard device"}</p>
              <p>{offlinePairingPlatform(platform).name}</p>
            </div>
          </div>
          <dl className="offline-pairing-metadata">
            <div>
              <dt>{trusted ? "Approved capabilities" : "Connection type"}</dt>
              <dd>{displayedCapabilities.map((mode) => mode === "mesh" ? "Mesh messaging" : "XFER file transfer").join(" and ") || "Pending negotiation"}</dd>
            </div>
            <div>
              <dt>Identity fingerprint</dt>
              <dd><code>{peer}</code></dd>
            </div>
          </dl>
        </section>
        {showCode && <div className="offline-pairing-code">
          <span>Verification code</span>
          <code aria-hidden="true">{code}</code>
          <span className="sr-only">{code?.replaceAll("-", " ").split("").join(" ")}</span>
        </div>}
        {status === "failed" && pairing.error && <p role="status" className="offline-pairing-error">{pairing.error}</p>}
        {error && <p role="alert" className="offline-pairing-error">{error}</p>}
        <div className="offline-pairing-actions" aria-busy={busy || undefined}>
          {incoming ? <>
            <button type="button" disabled={busy} onClick={() => onDecide(id, "reject")}>Do not allow</button>
            <button type="button" disabled={busy} data-primary onClick={() => onDecide(id, "allow")}>Allow connection</button>
          </> : status === "verifying" ? <>
            <button type="button" disabled={busy} onClick={() => onDecide(id, "cancel")}>They don’t match</button>
            <button type="button" disabled={busy || !showCode} data-primary onClick={() => onDecide(id, "confirm")}>They match · Trust device</button>
          </> : trusted ? <>
            <button type="button" disabled={busy} onClick={() => onDismiss(id)}>Done</button>
            {canMessage && <button type="button" disabled={busy} data-primary={!canTransfer || undefined} onClick={() => onOpen("mesh", peer)}>Start messaging</button>}
            {/* The device that approved the request usually receives: it waits
                on a dedicated screen instead of returning to the radar. */}
            {canTransfer && direction === "incoming" && <button type="button" disabled={busy} data-primary onClick={() => onOpen("xfer", peer, "receive")}>Wait for files</button>}
            {canTransfer && <button type="button" disabled={busy} data-primary={direction !== "incoming" || undefined} onClick={() => onOpen("xfer", peer, "send")}>Send files</button>}
            {canTransfer && direction !== "incoming" && <button type="button" disabled={busy} onClick={() => onOpen("xfer", peer, "receive")}>Wait for files</button>}
          </> : ended ? <>
            <button type="button" disabled={busy} onClick={() => onDismiss(id)}>Close</button>
            {onRetry && direction === "outgoing" && <button type="button" disabled={busy} data-primary onClick={() => onRetry(pairing)}>Try again</button>}
          </> : <button type="button" disabled={busy} onClick={cancel}>Cancel pairing</button>}
        </div>
      </div>
    </dialog>
  );
}
