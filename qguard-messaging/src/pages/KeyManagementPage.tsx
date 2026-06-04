import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  KeyRound,
  Loader2,
  RefreshCcw,
  ShieldCheck,
  UnlockKeyhole,
  UploadCloud,
} from "lucide-react";
import { useMemo, useState } from "react";
import { bytesToBytea } from "@/lib/encoding";
import { supabase } from "@/lib/supabase";
import { safeInvoke } from "@/lib/tauri";
import type { KeyInventory, SecurityEvent, TrustedDevice } from "@/lib/types";

interface KeyManagementPageProps {
  devices: TrustedDevice[];
  keyInventory: KeyInventory;
  securityEvents: SecurityEvent[];
  onRefresh: () => void | Promise<void>;
}

interface PublicIdentityBundle {
  user_id: string;
  device_id: string;
  device_label: string;
  identity_id: string;
  x25519_identity_public: number[];
  mlkem_identity_public: number[];
  ed25519_identity_public: number[];
  mldsa_identity_public: number[];
  signature: Record<string, unknown>;
  fingerprint: string;
  suite: Record<string, unknown>;
}

interface PublicSignedPrekey {
  prekey_id: string;
  device_id: string;
  x25519_public: number[];
  mlkem_public: number[];
  signature: Record<string, unknown>;
  fingerprint: string;
  created_at: string;
  expires_at: string;
}

type KeyAction = "publish" | "unlock" | "rotate" | "refresh";
type OperationStatus = "running" | "success" | "error";

interface KeyOperationLog {
  id: string;
  stage: string;
  detail: string;
  status: OperationStatus;
}

const REQUEST_TIMEOUT_MS = 45_000;

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "Key management action failed.";
}

function deviceTime(device: TrustedDevice): number {
  const parsed = new Date(device.last_seen_at).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

async function withTimeout<T>(
  task: PromiseLike<T>,
  label: string,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<T> {
  let timeoutId: number | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timeoutId = window.setTimeout(() => {
      reject(new Error(`${label} timed out. The operation was stopped so the app can stay responsive.`));
    }, timeoutMs);
  });

  try {
    return await Promise.race([Promise.resolve(task), timeout]);
  } finally {
    if (timeoutId !== undefined) window.clearTimeout(timeoutId);
  }
}

export default function KeyManagementPage({ devices, keyInventory, securityEvents, onRefresh }: KeyManagementPageProps) {
  const [unlockStatus, setUnlockStatus] = useState("Private keys remain device-bound");
  const [busy, setBusy] = useState<KeyAction | null>(null);
  const [actionStatus, setActionStatus] = useState<string | null>(null);
  const [operationLogs, setOperationLogs] = useState<KeyOperationLog[]>([]);

  const latestThisDevice = useMemo(() => {
    return devices
      .filter((device) => device.trust_state === "ThisDevice")
      .sort((a, b) => deviceTime(b) - deviceTime(a))[0] ?? null;
  }, [devices]);
  const currentUserId = latestThisDevice?.user_id ?? devices[0]?.user_id ?? null;
  const ownDevices = useMemo(() => {
    const scopedDevices = currentUserId ? devices.filter((device) => device.user_id === currentUserId) : devices;
    return [...scopedDevices].sort((a, b) => deviceTime(b) - deviceTime(a));
  }, [currentUserId, devices]);
  const displayDevices = ownDevices.slice(0, 8);
  const hiddenDeviceCount = Math.max(0, ownDevices.length - displayDevices.length);
  const duplicateCurrentDeviceCount = ownDevices.filter((device) => device.trust_state === "ThisDevice").length;
  const nextRotation = keyInventory.next_signed_prekey_expiry
    ? new Date(keyInventory.next_signed_prekey_expiry).toLocaleString()
    : "No active signed prekey";
  const latestKeyEvent = securityEvents.find((event) => event.event_type.includes("key") || event.event_type.includes("prekey"));
  const latestLogStatus = operationLogs[0]?.status ?? "success";

  function pushLog(stage: string, detail: string, status: OperationStatus = "running") {
    setOperationLogs((current) => [
      {
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        stage,
        detail,
        status,
      },
      ...current,
    ].slice(0, 12));
  }

  async function runKeyAction(action: KeyAction, label: string, callback: () => Promise<string>) {
    if (busy) return;
    setBusy(action);
    setActionStatus(null);
    pushLog(label, "Started", "running");
    try {
      const message = await callback();
      setActionStatus(message);
      pushLog(label, message, "success");
    } catch (error) {
      const message = describeError(error);
      setActionStatus(message);
      pushLog(label, message, "error");
    } finally {
      setBusy(null);
    }
  }

  async function publishBundleToRelay(bundle: PublicIdentityBundle) {
    if (!bundle.user_id || !bundle.device_id || !bundle.identity_id) {
      throw new Error("Desktop key service returned an incomplete identity bundle.");
    }

    pushLog("Identity validation", `Validated local public bundle ${bundle.fingerprint.slice(0, 20)}`, "running");
    const deviceResult = await withTimeout(supabase.rpc("register_messaging_device", {
      p_device_id: bundle.device_id,
      p_device_label: bundle.device_label,
      p_identity_id: bundle.identity_id,
      p_x25519_identity_public: bytesToBytea(bundle.x25519_identity_public),
      p_mlkem_identity_public: bytesToBytea(bundle.mlkem_identity_public),
      p_ed25519_identity_public: bytesToBytea(bundle.ed25519_identity_public),
      p_mldsa_identity_public: bytesToBytea(bundle.mldsa_identity_public),
      p_identity_signature: bundle.signature,
      p_fingerprint: bundle.fingerprint,
      p_suite: bundle.suite,
    }), "Publish public identity bundle", 20_000);
    if (deviceResult.error) throw deviceResult.error;

    const normalizeResult = await withTimeout(
      supabase
        .from("messaging_devices")
        .update({ trust_state: "trusted", last_seen_at: new Date().toISOString() })
        .eq("user_id", bundle.user_id)
        .neq("id", bundle.device_id)
        .eq("trust_state", "this_device"),
      "Normalize current-device markers",
      15_000,
    );
    if (normalizeResult.error) throw normalizeResult.error;
    pushLog("Device registry", "Current device marker synchronized", "success");
  }

  async function prepareRegisteredDevice(): Promise<PublicIdentityBundle> {
    pushLog("Secure storage", "Loading device-bound public identity from OS keychain", "running");
    const bundle = await withTimeout(
      safeInvoke<PublicIdentityBundle>("keys_upload_identity_bundle"),
      "Load device identity",
      20_000,
    );
    await publishBundleToRelay(bundle);
    return bundle;
  }

  function publishPublicBundle() {
    void runKeyAction("publish", "Publish public bundle", async () => {
      const bundle = await prepareRegisteredDevice();
      pushLog("Inventory refresh", "Refreshing key inventory", "running");
      await Promise.resolve(onRefresh());
      return `Public identity bundle published for ${bundle.fingerprint.slice(0, 24)}`;
    });
  }

  function unlockPrivateKey() {
    void runKeyAction("unlock", "Unlock private key", async () => {
      const status = await withTimeout(
        safeInvoke<{ storage: string; fingerprint: string; private_key_exported: boolean }>("keys_unlock_private_key"),
        "Unlock private key",
        20_000,
      );
      if (status.private_key_exported) {
        throw new Error("Unlock blocked because private key export was attempted.");
      }
      const detail = `Unlocked via ${status.storage} - ${status.fingerprint}`;
      setUnlockStatus(detail);
      return "Private key unlocked locally; no private key bytes exported.";
    });
  }

  function rotateAndPublishPrekey() {
    void runKeyAction("rotate", "Rotate signed prekey", async () => {
      const bundle = await prepareRegisteredDevice();
      pushLog("Key generation", "Generating ML-KEM-768 + X25519 signed prekey locally", "running");
      const prekey = await withTimeout(
        safeInvoke<PublicSignedPrekey>("keys_rotate_prekeys"),
        "Rotate signed prekey",
        REQUEST_TIMEOUT_MS,
      );

      const deactivateResult = await withTimeout(
        supabase
          .from("messaging_signed_prekeys")
          .update({ is_active: false })
          .eq("user_id", bundle.user_id)
          .eq("device_id", prekey.device_id)
          .eq("is_active", true)
          .neq("id", prekey.prekey_id),
        "Deactivate previous signed prekeys",
        20_000,
      );
      if (deactivateResult.error) throw deactivateResult.error;

      pushLog("Relay publish", "Publishing active signed prekey", "running");
      const publishResult = await withTimeout(
        supabase.from("messaging_signed_prekeys").upsert({
          id: prekey.prekey_id,
          user_id: bundle.user_id,
          device_id: prekey.device_id,
          x25519_public: bytesToBytea(prekey.x25519_public),
          mlkem_public: bytesToBytea(prekey.mlkem_public),
          signature: prekey.signature,
          fingerprint: prekey.fingerprint,
          is_active: true,
          expires_at: prekey.expires_at,
          created_at: prekey.created_at,
        }, { onConflict: "id" }),
        "Publish signed prekey",
        20_000,
      );
      if (publishResult.error) throw publishResult.error;

      pushLog("Inventory refresh", "Refreshing key inventory", "running");
      await Promise.resolve(onRefresh());
      return `Signed prekey rotated and published: ${prekey.fingerprint.slice(0, 24)}`;
    });
  }

  function refreshInventory() {
    void runKeyAction("refresh", "Refresh key inventory", async () => {
      await withTimeout(Promise.resolve(onRefresh()), "Refresh key inventory", 20_000);
      return "Key inventory refreshed from live backend state.";
    });
  }

  return (
    <div className="grid gap-4">
      <div className="grid gap-4 lg:grid-cols-3">
        <section className="shell-card p-4">
          <KeyRound className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Hybrid Identity</div>
          <div className="mt-1 text-sm text-ink-600">{keyInventory.identity_device_count} device identities registered</div>
        </section>
        <section className="shell-card p-4">
          <RefreshCcw className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Prekey Rotation</div>
          <div className="mt-1 text-sm text-ink-600">Next signed prekey expiry: {nextRotation}</div>
        </section>
        <section className="shell-card p-4">
          <ShieldCheck className="text-violet-600" size={24} />
          <div className="mt-3 text-sm font-bold text-ink-950">Verification Policy</div>
          <div className="mt-1 text-sm text-ink-600">{keyInventory.rotation_events} key lifecycle events recorded</div>
        </section>
      </div>

      <section className="shell-card overflow-hidden" aria-busy={Boolean(busy)}>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line p-4">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Device Key Material</h2>
            <div className="mt-1 flex flex-wrap gap-2 text-xs">
              <span className="status-pill bg-emerald-50 text-emerald-600">
                <CheckCircle2 size={13} />
                Client-side keys
              </span>
              <span className="status-pill bg-violet-50 text-violet-600">
                <Clock3 size={13} />
                {busy ? "Operation running" : "Ready"}
              </span>
              {duplicateCurrentDeviceCount > 1 && (
                <span className="status-pill bg-amber-50 text-amber-700">
                  <AlertTriangle size={13} />
                  {duplicateCurrentDeviceCount} current markers
                </span>
              )}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={refreshInventory} disabled={Boolean(busy)} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-semibold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
              {busy === "refresh" ? <Loader2 className="animate-spin" size={16} /> : <RefreshCcw size={16} />}
              {busy === "refresh" ? "Refreshing" : "Refresh"}
            </button>
            <button onClick={publishPublicBundle} disabled={Boolean(busy)} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-semibold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
              {busy === "publish" ? <Loader2 className="animate-spin" size={16} /> : <UploadCloud size={16} />}
              {busy === "publish" ? "Publishing" : "Publish Public Bundle"}
            </button>
            <button onClick={unlockPrivateKey} disabled={Boolean(busy)} className="flex items-center gap-2 rounded-lg border border-cyan-200 px-3 py-2 text-sm font-semibold text-cyan-700 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60">
              {busy === "unlock" ? <Loader2 className="animate-spin" size={16} /> : <UnlockKeyhole size={16} />}
              {busy === "unlock" ? "Unlocking" : "Unlock Private Key"}
            </button>
            <button onClick={rotateAndPublishPrekey} disabled={Boolean(busy)} className="flex items-center gap-2 rounded-lg bg-violet-600 px-3 py-2 text-sm font-semibold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-50">
              {busy === "rotate" ? <Loader2 className="animate-spin" size={16} /> : <RefreshCcw size={16} />}
              {busy === "rotate" ? "Rotating" : "Rotate Prekeys"}
            </button>
          </div>
        </div>
        {actionStatus && (
          <div className={`border-b border-line px-4 py-2 text-xs font-semibold ${latestLogStatus === "error" ? "bg-rose-50 text-rose-600" : "bg-cyan-50 text-cyan-700"}`}>
            {actionStatus}
          </div>
        )}

        <div className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line bg-canvas px-4 py-3 text-xs font-bold uppercase tracking-wide text-ink-400">
          <span>Object</span>
          <span>Source</span>
          <span>Status</span>
          <span>Detail</span>
        </div>

        {ownDevices.length === 0 && (
          <div className="p-6 text-sm text-ink-600">No key bundles are registered for this user.</div>
        )}

        {displayDevices.map((device) => (
          <div key={device.device_id} className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line px-4 py-3 text-sm">
            <span className="font-semibold text-ink-950">Hybrid Identity</span>
            <span className="truncate font-mono text-xs text-violet-600">{device.fingerprint}</span>
            <span className={device.trust_state === "Revoked" ? "text-rose-500" : "text-emerald-600"}>{device.trust_state}</span>
            <span className="text-ink-600">{device.pqc_status}</span>
          </div>
        ))}

        {hiddenDeviceCount > 0 && (
          <div className="border-b border-line bg-amber-50/70 px-4 py-3 text-xs font-semibold text-amber-700">
            {hiddenDeviceCount} older registered identity {hiddenDeviceCount === 1 ? "row is" : "rows are"} hidden from this panel.
          </div>
        )}

        <div className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line px-4 py-3 text-sm">
          <span className="font-semibold text-ink-950">Private Decryption Key</span>
          <span className="truncate font-mono text-xs text-violet-600">OS keychain / secure storage</span>
          <span className="text-emerald-600">local only</span>
          <span className="truncate text-ink-600">{unlockStatus}</span>
        </div>

        <div className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line px-4 py-3 text-sm">
          <span className="font-semibold text-ink-950">Signed Prekeys</span>
          <span className="font-mono text-xs text-violet-600">messaging_signed_prekeys</span>
          <span className="text-emerald-600">{keyInventory.active_signed_prekeys} active</span>
          <span className="text-ink-600">{nextRotation}</span>
        </div>

        <div className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line px-4 py-3 text-sm">
          <span className="font-semibold text-ink-950">One-Time Prekeys</span>
          <span className="font-mono text-xs text-violet-600">messaging_one_time_prekeys</span>
          <span className="text-emerald-600">{keyInventory.available_one_time_prekeys} available</span>
          <span className="text-ink-600">Consumed prekeys are excluded by the user-scoped query</span>
        </div>

        <div className="grid grid-cols-[180px_1fr_160px_1fr] border-b border-line px-4 py-3 text-sm">
          <span className="font-semibold text-ink-950">Latest Key Event</span>
          <span className="font-mono text-xs text-violet-600">{latestKeyEvent?.event_hash ?? "No event hash"}</span>
          <span className={latestKeyEvent?.severity === "critical" ? "text-rose-500" : "text-emerald-600"}>
            {latestKeyEvent?.severity ?? "none"}
          </span>
          <span className="text-ink-600">{latestKeyEvent?.event_type ?? "No key rotation event has been recorded"}</span>
        </div>

        <div className="bg-ink-950 px-4 py-3 font-mono text-xs text-emerald-200">
          {operationLogs.length === 0 ? (
            <div className="text-emerald-200/70">qguard:key-management idle</div>
          ) : (
            [...operationLogs].reverse().map((entry) => (
              <div key={entry.id} className={entry.status === "error" ? "text-rose-300" : entry.status === "success" ? "text-cyan-200" : "text-emerald-200"}>
                [{entry.status}] {entry.stage}: {entry.detail}
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
