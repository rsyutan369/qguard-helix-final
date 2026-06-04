import { Copy, Loader2, QrCode, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { safeInvoke } from "@/lib/tauri";
import type { TrustedDevice } from "@/lib/types";

interface SafetyNumberResult {
  display?: string;
  safety_number?: string;
  qr_payload: string;
  verified?: boolean;
}

interface SecurityVerificationPageProps {
  devices: TrustedDevice[];
}

export default function SecurityVerificationPage({ devices }: SecurityVerificationPageProps) {
  const [selectedDeviceId, setSelectedDeviceId] = useState(devices[0]?.device_id ?? "");
  const [verification, setVerification] = useState<SafetyNumberResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"verify" | "copy" | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const selectedDevice = devices.find((device) => device.device_id === selectedDeviceId) ?? devices[0] ?? null;

  useEffect(() => {
    setSelectedDeviceId((current) => {
      if (devices.some((device) => device.device_id === current)) return current;
      return devices[0]?.device_id ?? "";
    });
    if (devices.length === 0) setVerification(null);
  }, [devices]);

  async function verify(device: TrustedDevice | null = selectedDevice) {
    if (!device) return;
    setError(null);
    setStatus(null);
    setBusy("verify");
    try {
      const result = await safeInvoke<SafetyNumberResult>("security_verify_fingerprint", {
        remoteFingerprint: device.fingerprint,
      });
      setVerification(result);
      setStatus("Safety number generated from live device fingerprint");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  async function copyPayload() {
    if (!verification) return;
    setBusy("copy");
    try {
      await navigator.clipboard.writeText(`${verification.display ?? verification.safety_number}\n${verification.qr_payload}`);
      setStatus("Verification payload copied");
    } catch (error) {
      setError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid grid-cols-[1fr_360px] gap-4">
      <section className="shell-card p-5">
        <div className="flex items-center gap-3">
          <ShieldCheck className="text-emerald-600" size={26} />
          <div>
            <h2 className="text-sm font-bold text-ink-950">Safety Number</h2>
            <div className="text-sm text-ink-600">Compare the generated value with a trusted device before approving key changes.</div>
          </div>
        </div>

        <label className="mt-5 block text-xs font-bold uppercase tracking-wide text-ink-400" htmlFor="device-fingerprint">
          Device fingerprint
        </label>
        <select
          id="device-fingerprint"
          value={selectedDevice?.device_id ?? ""}
          onChange={(event) => {
            setSelectedDeviceId(event.target.value);
            setVerification(null);
          }}
          className="mt-2 w-full rounded-lg border border-line bg-white px-3 py-2 text-sm text-ink-950 outline-none focus:border-violet-300"
        >
          {devices.length === 0 && <option value="">No devices available</option>}
          {devices.map((device) => (
            <option key={device.device_id} value={device.device_id}>{device.label}</option>
          ))}
        </select>

        <div className="mt-5 rounded-lg border border-line bg-canvas p-5 font-mono text-xl font-bold leading-relaxed text-ink-950">
          {verification ? verification.display ?? verification.safety_number : "Generate a safety number from a trusted device fingerprint."}
        </div>
        {selectedDevice && (
          <div className="mt-3 truncate font-mono text-xs text-ink-400">{selectedDevice.fingerprint}</div>
        )}
        {error && <div className="mt-3 text-sm font-semibold text-rose-500">{error}</div>}
        {status && <div className="mt-3 text-sm font-semibold text-emerald-600">{status}</div>}

        <div className="mt-4 flex gap-2">
          <button disabled={!selectedDevice || Boolean(busy)} onClick={() => verify()} className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-50">
            {busy === "verify" ? <Loader2 className="animate-spin" size={16} /> : <ShieldCheck size={16} />}
            {busy === "verify" ? "Verifying" : "Verify"}
          </button>
          <button disabled={!verification || Boolean(busy)} onClick={copyPayload} className="flex items-center gap-2 rounded-lg border border-line px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
            {busy === "copy" ? <Loader2 className="animate-spin" size={16} /> : <Copy size={16} />}
            {busy === "copy" ? "Copying" : "Copy"}
          </button>
        </div>
      </section>

      <section className="shell-card p-5">
        <QrCode className="text-violet-600" size={30} />
        <h2 className="mt-3 text-sm font-bold text-ink-950">QR Verification Payload</h2>
        <div className="mt-4 min-h-72 rounded-lg border border-line bg-white p-4 shadow-tight">
          {verification ? (
            <div className="break-all font-mono text-xs leading-relaxed text-ink-700">{verification.qr_payload}</div>
          ) : (
            <div className="flex h-60 items-center justify-center text-center text-sm text-ink-600">
              Select a trusted device and generate a signed verification payload.
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
