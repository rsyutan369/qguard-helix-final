import { useCallback, useEffect, useState } from "react";
import { BadgeCheck, Loader2, ShieldQuestion, X } from "lucide-react";
import { formatVerifiedDate } from "@/lib/call-security";
import { peerIdentityOfDevice, type CallCandidateDevice } from "@/lib/call-targets";
import {
  clearContactVerification,
  createPairingOffer,
  describePairing,
  fetchContactVerification,
  markContactVerified,
  type ContactVerificationStatus,
  type PairingOffer,
} from "@/lib/contact-verification";

export interface VerifiableDevice extends CallCandidateDevice {
  label: string;
}

/**
 * "Verify contact" (roadmap Phase 3): compare each of the contact's devices'
 * safety number out of band and record the match on THIS device. The number
 * shown is computed by the core from the two devices' keys, and the core
 * re-derives it when the user confirms, so a stale screen verifies nothing.
 *
 * Verifying also starts the call pairing: this device seals its half to the
 * verified device, which `onPairingOffer` delivers as a control message.
 */
export function ContactVerificationPanel({ devices, peerName, onPairingOffer, onClose }: {
  devices: VerifiableDevice[];
  peerName: string;
  onPairingOffer: (deviceId: string, offer: PairingOffer) => Promise<void>;
  onClose: () => void;
}) {
  const name = peerName.trim() || "this contact";
  const [statuses, setStatuses] = useState<Record<string, ContactVerificationStatus | { error: string }>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  const load = useCallback(() => {
    for (const device of devices) {
      const peer = peerIdentityOfDevice(device);
      if (!peer) {
        setStatuses((current) => ({ ...current, [device.device_id]: { error: "This device has not published verifiable keys." } }));
        continue;
      }
      fetchContactVerification(peer)
        .then((status) => setStatuses((current) => ({ ...current, [device.device_id]: status })))
        .catch((error) => setStatuses((current) => ({ ...current, [device.device_id]: { error: error instanceof Error ? error.message : String(error) } })));
    }
  }, [devices]);
  useEffect(() => { load(); }, [load]);

  const verify = async (device: VerifiableDevice, status: ContactVerificationStatus) => {
    const peer = peerIdentityOfDevice(device);
    if (!peer) return;
    setBusy(device.device_id);
    setNote(null);
    try {
      const next = await markContactVerified(peer, status.safetyNumber, "safety_number");
      setStatuses((current) => ({ ...current, [device.device_id]: next }));
      // Our half of the call pairing, sealed to the device just verified.
      const offer = await createPairingOffer(peer);
      await onPairingOffer(device.device_id, offer);
      setStatuses((current) => ({ ...current, [device.device_id]: { ...next, pairing: next.pairing === "none" ? "waiting_for_them" : next.pairing } }));
      load();
      setNote({ tone: "ok", text: `${device.label} is verified on this device.` });
    } catch (error) {
      setNote({ tone: "error", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusy(null);
    }
  };

  const unverify = async (device: VerifiableDevice) => {
    const peer = peerIdentityOfDevice(device);
    if (!peer) return;
    setBusy(device.device_id);
    setNote(null);
    try {
      const next = await clearContactVerification(peer);
      setStatuses((current) => ({ ...current, [device.device_id]: next }));
    } catch (error) {
      setNote({ tone: "error", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="rounded-lg border border-cyan-200 bg-white p-4 text-sm text-ink-700 shadow-tight">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="flex items-center gap-2 font-bold text-ink-950"><BadgeCheck size={16} className="text-cyan-600" /> Verify {name}</div>
          <p className="mt-1 text-xs leading-relaxed text-ink-600">
            Compare the number below with {name} — in person, or over a channel you already trust (not a call you can&apos;t
            verify). If it matches theirs exactly, mark it verified. This records that you checked <em>this device&apos;s keys</em>;
            it does not vouch for whoever is holding it. Verified contacts can prove it&apos;s them on a call with a four-word phrase.
          </p>
        </div>
        <button type="button" onClick={onClose} className="icon-button shrink-0" title="Close"><X size={14} /></button>
      </div>
      {devices.length === 0 && (
        <p className="mt-3 text-xs text-ink-500">{name} has no device this app can send to yet.</p>
      )}
      <div className="mt-3 space-y-3">
        {devices.map((device) => {
          const status = statuses[device.device_id];
          return (
            <div key={device.device_id} className="rounded-md border border-line bg-canvas p-3">
              <div className="font-semibold text-ink-950">{device.label}</div>
              {!status ? (
                <div className="mt-2 flex items-center gap-2 text-xs text-ink-500"><Loader2 size={12} className="animate-spin" /> Computing safety number…</div>
              ) : "error" in status ? (
                <div className="mt-2 text-xs font-semibold text-rose-700">{status.error}</div>
              ) : (
                <>
                  <div className="mt-2 font-mono text-sm font-bold tracking-[0.12em] text-ink-950">{status.safetyNumber}</div>
                  {status.standing !== "pinned" ? (
                    <div className="mt-2 text-xs font-semibold text-amber-700">
                      {status.standing === "key_changed"
                        ? "This device is presenting different keys than the ones recorded for it, so it cannot be verified."
                        : "Approve this device first (above); only a device recorded here can be verified."}
                    </div>
                  ) : status.verifiedAt !== null ? (
                    <>
                      <div className="mt-2 flex items-center gap-1.5 text-xs font-semibold text-emerald-700">
                        <BadgeCheck size={13} /> Verified on {formatVerifiedDate(status.verifiedAt)}
                      </div>
                      <div className="mt-1 text-xs text-ink-600">{describePairing(status.pairing, name)}</div>
                      <button
                        type="button"
                        disabled={busy !== null}
                        onClick={() => void unverify(device)}
                        className="mt-2 rounded-md border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-700 hover:bg-white/70 disabled:opacity-60"
                      >
                        Remove verification
                      </button>
                    </>
                  ) : (
                    <>
                      <div className="mt-2 flex items-center gap-1.5 text-xs text-ink-600">
                        <ShieldQuestion size={13} /> Not verified. {status.pairing === "needs_your_verification" ? describePairing(status.pairing, name) : ""}
                      </div>
                      <button
                        type="button"
                        disabled={busy !== null}
                        onClick={() => void verify(device, status)}
                        className="mt-2 rounded-md bg-cyan-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-cyan-700 disabled:opacity-60"
                      >
                        {busy === device.device_id ? "Saving…" : `It matches ${name}'s number — mark verified`}
                      </button>
                    </>
                  )}
                </>
              )}
            </div>
          );
        })}
      </div>
      {note && (
        <div className={`mt-3 rounded-md border p-2 text-xs font-semibold ${note.tone === "ok" ? "border-emerald-100 bg-emerald-50 text-emerald-700" : "border-rose-100 bg-rose-50 text-rose-700"}`}>
          {note.text}
        </div>
      )}
    </div>
  );
}
