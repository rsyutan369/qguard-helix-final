import {
  AlertTriangle,
  BadgeCheck,
  Camera,
  CheckCircle2,
  Cpu,
  Download,
  KeyRound,
  LockKeyhole,
  Mail,
  Moon,
  QrCode,
  RefreshCcw,
  ShieldCheck,
  Smartphone,
  Sun,
  UserRound,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { accountAuditIdentifier, accountIdentifierLabel, displayableEmail, isPhoneAccount, sendAccountProofCode, verifyAccountProof } from "@/lib/account-identity";
import { useAuth } from "@/lib/auth-context";
import { invalidateAvatar } from "@/lib/avatars";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import type { QGuardLiveEvent, QGuardLiveStatus } from "@/lib/live-sse";
import { guardNativeFileInput } from "@/lib/native-dialog-guard";
import { describeSavedFile, saveFileToDevice } from "@/lib/save-file";
import { DevicePrivacyCard } from "@/components/DevicePrivacyCard";
import { RecoveryCenterCard } from "@/components/RecoveryCenterCard";
import { AiAssistantCard } from "@/components/AiAssistantCard";
import { OfflineDeliveryCard } from "@/components/OfflineDeliveryCard";
import { syncCurrentMessagingDevice } from "@/lib/messaging-bootstrap";
import { fetchRatchetStatus, resetRatchetSession, setRatchetEnabled, type RatchetStatus } from "@/lib/ratchet-status";
import { createEphemeralSupabaseClient, supabase } from "@/lib/supabase";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";
import { listTrustedDevices, revokeTrustedDevice, type TrustedDeviceRow } from "@/lib/trusted-devices";
import type { Profile, SecurityEvent, TelemetryEvent } from "@/lib/types";
import { useAppLock } from "@/lib/use-app-lock";
import type { ThemeMode } from "@/lib/use-theme";
import { INACTIVITY_OPTIONS, type WorkspaceStatus } from "@/lib/use-workspace-lock";
import { sha3_256Hex } from "@/lib/sha3";
import { hashRecoveryCode, recoveryHashScheme } from "@/lib/recovery-code-hash";

interface GpuSafeModeStatus {
  active: boolean;
  appliedThisSession: boolean;
  enabledAt: string | null;
  reason: string | null;
}

/**
 * Shows whether video calls run with the normal GPU-composited UI or in the
 * self-healing "GPU safe mode" (full software rendering) that engages after an
 * unexpected shutdown during a call, and lets the user return to hardware
 * rendering once their graphics driver is fixed. Hidden outside the desktop app.
 */
function CallDeviceProtectionCard() {
  const [gpuStatus, setGpuStatus] = useState<GpuSafeModeStatus | null>(null);
  const [restartNeeded, setRestartNeeded] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void safeInvoke<GpuSafeModeStatus | null>("call_gpu_safe_mode_status", undefined, null)
      .then(setGpuStatus)
      .catch(() => setGpuStatus(null));
  }, []);

  if (!gpuStatus) return null;

  const exitSafeMode = async () => {
    setBusy(true);
    try {
      const next = await safeInvoke<GpuSafeModeStatus | null>("call_gpu_safe_mode_clear", undefined, null);
      if (next) setGpuStatus(next);
      setRestartNeeded(true);
    } finally {
      setBusy(false);
    }
  };

  const enabledAt = gpuStatus.enabledAt ? new Date(gpuStatus.enabledAt).toLocaleString() : null;

  return (
    <section className="shell-card p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><Cpu size={18} /> Call Device Protection</div>
        <span className={`status-pill ${gpuStatus.active ? "bg-amber-50 text-amber-700" : "bg-emerald-50 text-emerald-600"}`}>
          <ShieldCheck size={12} /> {gpuStatus.active ? "GPU safe mode" : "Protected"}
        </span>
      </div>
      <p className="mt-1 text-sm text-ink-600">
        Video calls always run on crash-proof software codecs, so a faulty graphics driver can never freeze this device.
        If the app ever shuts down unexpectedly during a call, the next launch also draws the whole interface in software
        (GPU safe mode) as an extra safeguard.
      </p>
      {gpuStatus.active && (
        <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800">
          <div className="font-semibold">GPU safe mode is on{enabledAt ? ` (since ${enabledAt})` : ""}.</div>
          <p className="mt-1 text-[13px]">
            {gpuStatus.reason ?? "The app shut down unexpectedly during a call."} Update your graphics driver
            (Intel, NVIDIA, or AMD — via Windows Update or the manufacturer's tool) before returning to hardware rendering.
          </p>
          <button
            type="button"
            disabled={busy}
            onClick={() => void exitSafeMode()}
            className="mt-3 rounded-lg border border-amber-300 bg-white px-4 py-2 text-sm font-bold text-amber-800 hover:bg-amber-100 disabled:opacity-60"
          >
            I've updated my driver — return to hardware rendering
          </button>
        </div>
      )}
      {restartNeeded && (
        <div className="mt-3 rounded-lg border border-emerald-100 bg-emerald-50 p-3 text-sm font-semibold text-emerald-700">
          Done — hardware rendering returns the next time you open QGuard Messaging.
        </div>
      )}
    </section>
  );
}

/**
 * Settings → Advanced: the post-quantum session ratchet (roadmap Phase 2).
 *
 * Off by default while it is unaudited. Turning it on makes this device
 * advertise the capability (its published suite is re-registered right away)
 * and start a session with each contact device that advertises it too. The
 * state shown is what the core reports, never the switch position alone.
 */
function SessionRatchetCard({ userId }: { userId: string | null }) {
  const [status, setStatus] = useState<RatchetStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  useEffect(() => {
    if (!userId || !isTauriRuntime()) return;
    void fetchRatchetStatus(userId, []).then(setStatus).catch(() => setStatus(null));
  }, [userId]);

  if (!userId || !status) return null;
  const forced = status.env_override !== null;

  const toggle = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const next = await setRatchetEnabled(userId, !status.enabled);
      setStatus(next);
      // Peers learn the capability from the published suite.
      await syncCurrentMessagingDevice(supabase, userId);
      setMessage({
        tone: "ok",
        text: next.enabled
          ? "On. Contacts whose app supports it will use a per-message ratchet with this device from their next message."
          : "Off. New messages are one-shot sealed again; existing sessions are kept only to read what was already sent.",
      });
    } catch (error) {
      setMessage({ tone: "error", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusy(false);
    }
  };

  const resetAll = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const forgotten = await resetRatchetSession(userId, null);
      setMessage({ tone: "ok", text: forgotten ? "All secure sessions reset. The next message to each device starts a new one." : "There were no secure sessions to reset." });
    } catch (error) {
      setMessage({ tone: "error", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="shell-card p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><KeyRound size={18} /> Per-message ratchet (advanced)</div>
        <span className={`status-pill ${status.enabled ? "bg-emerald-50 text-emerald-600" : "bg-slate-100 text-ink-600"}`}>
          {status.enabled ? "On" : "Off"}{forced ? " · set by QGUARD_RATCHET" : ""}
        </span>
      </div>
      <p className="mt-1 text-sm text-ink-600">
        Gives every message its own key, deleted once used, and heals a stolen device key on the next reply — with a fresh
        ML-KEM-1024 exchange at least every 50 messages or 24 hours. Without it, each message is still sealed with
        X25519 + ML-KEM-1024, and forward secrecy follows the daily prekey rotation.
      </p>
      <p className="mt-2 text-[13px] text-amber-700">
        Not yet independently reviewed. It only takes effect with contacts whose app has it on too; everyone else keeps
        receiving one-shot sealed messages.
      </p>
      {!status.available && (
        <p className="mt-2 text-[13px] text-amber-700">This device&apos;s secure sessions could not be opened right now; messages go out one-shot sealed until they can.</p>
      )}
      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy || forced}
          onClick={() => void toggle()}
          className="rounded-lg border border-line bg-white px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas disabled:opacity-60"
        >
          {status.enabled ? "Turn off" : "Turn on"}
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => void resetAll()}
          className="rounded-lg border border-line bg-white px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas disabled:opacity-60"
        >
          Reset all secure sessions
        </button>
      </div>
      {message && (
        <div className={`mt-3 rounded-lg border p-3 text-sm font-semibold ${message.tone === "ok" ? "border-emerald-100 bg-emerald-50 text-emerald-700" : "border-red-100 bg-red-50 text-red-700"}`}>
          {message.text}
        </div>
      )}
    </section>
  );
}

interface SettingsPageProps {
  theme: ThemeMode;
  profile: Profile | null;
  telemetry: TelemetryEvent[];
  securityEvents: SecurityEvent[];
  liveEvents: QGuardLiveEvent[];
  liveStatus: QGuardLiveStatus;
  onToggleTheme: () => void;
  onRefresh: () => void | Promise<void>;
  inactivityMinutes: number;
  onSetInactivityMinutes: (minutes: number) => void;
  workspaceStatus: WorkspaceStatus | null;
  onLockWorkspaces: () => void | Promise<void>;
  // Android app-entry PIN (Task 6/8/9). Optional because desktop builds never
  // mount the Android app-lock gate, and the paywall-mode SettingsPage render
  // site in App.tsx has no `verifyAccountPassword` in scope.
  appLock?: ReturnType<typeof useAppLock>;
  verifyAccountPassword?: (password: string) => Promise<void>;
}

interface MfaEnrollment {
  factorId: string;
  qrCode: string;
  secret: string;
}

interface AuditRow {
  id: string;
  event_type: string;
  severity: "info" | "warning" | "critical";
  created_at: string;
}

type TelemetryStatus = "started" | "progress" | "verified" | "failed" | "complete";

const avatarTypes = new Set(["image/png", "image/jpeg", "image/webp"]);
const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function passwordScore(password: string) {
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(password)).length;
  const lengthScore = password.length >= 20 ? 3 : password.length >= 16 ? 2 : password.length >= 12 ? 1 : 0;
  const unique = new Set(password).size;
  const variety = classes + (unique >= 10 ? 1 : 0);
  const penalties = /(password|qguard|admin|letmein|1234|abcd)/i.test(password) || /(.)\1{2,}/.test(password) ? 1 : 0;
  const score = Math.max(0, Math.min(5, lengthScore + variety - penalties));
  const entropy = Math.round(Math.log2(Math.max(1, Math.pow(Math.max(unique, 2), password.length))));
  return { score, entropy, label: ["Very weak", "Weak", "Fair", "Strong", "Very strong", "Enterprise"][score] };
}

function randomCodeSegment(length: number) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((byte) => recoveryAlphabet[byte % recoveryAlphabet.length]).join("");
}

function newRecoveryCode() {
  return `${randomCodeSegment(4)}-${randomCodeSegment(4)}-${randomCodeSegment(4)}`;
}

function randomHex(bytes: number) {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}


function qrCodeSrc(value: string) {
  if (value.startsWith("data:")) return value;
  return `data:image/svg+xml;utf-8,${encodeURIComponent(value)}`;
}

async function resizeAvatar(file: File): Promise<Blob> {
  const imageUrl = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.decoding = "async";
    image.src = imageUrl;
    await image.decode();
    const size = Math.min(image.width, image.height);
    const canvas = document.createElement("canvas");
    canvas.width = 512;
    canvas.height = 512;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Avatar renderer is unavailable.");
    context.drawImage(image, (image.width - size) / 2, (image.height - size) / 2, size, size, 0, 0, 512, 512);
    return await new Promise<Blob>((resolve, reject) => {
      canvas.toBlob((blob) => blob ? resolve(blob) : reject(new Error("Avatar image could not be processed.")), "image/webp", 0.9);
    });
  } finally {
    URL.revokeObjectURL(imageUrl);
  }
}

/** "Current password" for email accounts; an SMS code (with a send button) for mobile-number accounts. */
function ProofInput({ phone, value, onChange, sentTo, onSend }: {
  phone: boolean;
  value: string;
  onChange: (value: string) => void;
  sentTo: string | null;
  onSend?: () => Promise<void>;
}) {
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  if (!phone) {
    return (
      <label className="text-sm font-semibold text-ink-700">
        Current password
        <input type="password" value={value} onChange={(event) => onChange(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" autoComplete="current-password" />
      </label>
    );
  }
  return (
    <div className="text-sm font-semibold text-ink-700">
      <label htmlFor="settings-sms-proof">SMS code</label>
      <div className="mt-2 flex gap-2">
        <input
          id="settings-sms-proof"
          value={value}
          onChange={(event) => onChange(event.target.value.replace(/\D/g, "").slice(0, 6))}
          inputMode="numeric"
          autoComplete="one-time-code"
          className="min-w-0 flex-1 rounded-lg border border-line bg-canvas px-3 py-2 text-center font-mono tracking-[0.25em] outline-none focus:border-cyan-300"
        />
        <button
          type="button"
          disabled={sending || !onSend}
          onClick={async () => {
            if (!onSend) return;
            setSending(true);
            setSendError(null);
            try {
              await onSend();
            } catch (error) {
              setSendError(error instanceof Error ? error.message : String(error));
            } finally {
              setSending(false);
            }
          }}
          className="shrink-0 rounded-lg border border-line px-3 py-2 text-xs font-bold text-ink-700 hover:bg-canvas disabled:opacity-50"
        >
          {sending ? "Sending…" : sentTo ? "Resend" : "Text me"}
        </button>
      </div>
      {sendError
        ? <div className="mt-1 text-[11px] text-rose-600">{sendError}</div>
        : sentTo && <div className="mt-1 text-[11px] text-emerald-600">Sent to {sentTo}</div>}
    </div>
  );
}

export default function SettingsPage({ theme, profile, telemetry, securityEvents, liveEvents, liveStatus, onToggleTheme, onRefresh, inactivityMinutes, onSetInactivityMinutes, workspaceStatus, onLockWorkspaces, appLock, verifyAccountPassword }: SettingsPageProps) {
  const auth = useAuth();
  const user = auth.user;
  const [displayName, setDisplayName] = useState(profile?.name ?? "");
  const [username, setUsername] = useState(profile?.username ?? "");
  // Prefer the authoritative auth session email (auth.users) over the denormalized
  // profiles.email mirror, so a completed email change is reflected immediately.
  const [email, setEmail] = useState(displayableEmail(user?.email) ?? displayableEmail(profile?.email) ?? "");
  const phoneAccount = isPhoneAccount(user);
  const [proofSentTo, setProofSentTo] = useState<string | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordNonce, setPasswordNonce] = useState("");
  const [stepUpCode, setStepUpCode] = useState("");
  const [avatarUrl, setAvatarUrl] = useState<string | null>(null);
  const avatarObjectUrlRef = useRef<string | null>(null);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [mfaFactorId, setMfaFactorId] = useState<string | null>(null);
  const [mfaEnrollment, setMfaEnrollment] = useState<MfaEnrollment | null>(null);
  const [mfaSetupCode, setMfaSetupCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [recoveryCount, setRecoveryCount] = useState(0);
  const [recoveryCheck, setRecoveryCheck] = useState("");
  const [auditRows, setAuditRows] = useState<AuditRow[]>([]);
  const [status, setStatus] = useState("Profile controls ready");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const strength = useMemo(() => passwordScore(newPassword), [newPassword]);
  const accountPosture = mfaEnabled ? "AAL2 Protected" : "AAL1 Session";
  const recoveryPosture = recoveryCount > 0 ? `${recoveryCount} active` : "No active codes";

  const setAvatarPreviewUrl = useCallback((nextUrl: string | null) => {
    if (avatarObjectUrlRef.current) {
      URL.revokeObjectURL(avatarObjectUrlRef.current);
      avatarObjectUrlRef.current = null;
    }
    avatarObjectUrlRef.current = nextUrl?.startsWith("blob:") ? nextUrl : null;
    setAvatarUrl(nextUrl);
  }, []);

  useEffect(() => {
    return () => {
      if (avatarObjectUrlRef.current) URL.revokeObjectURL(avatarObjectUrlRef.current);
    };
  }, []);

  const loadAvatarPreview = useCallback(async (path: string) => {
    const { data, error: downloadError } = await supabase.storage.from("profile-avatars").download(path);
    if (downloadError || !data) {
      setAvatarPreviewUrl(null);
      return;
    }
    setAvatarPreviewUrl(URL.createObjectURL(data));
  }, [setAvatarPreviewUrl]);

  const loadSecurityState = useCallback(async () => {
    if (!user) return;
    if (profile?.avatar_storage_path) {
      await loadAvatarPreview(profile.avatar_storage_path);
    } else {
      setAvatarPreviewUrl(null);
    }

    const [{ data: factors }, { count }, { data: audit }] = await Promise.all([
      supabase.auth.mfa.listFactors().catch(() => ({ data: null })),
      supabase.from("qguard_mfa_recovery_codes").select("id", { count: "exact", head: true }).eq("user_id", user.id).is("used_at", null),
      supabase.from("qguard_profile_audit_events").select("id,event_type,severity,created_at").eq("user_id", user.id).order("created_at", { ascending: false }).limit(8),
    ]);
    const verified = factors?.totp?.[0] ?? null;
    setMfaEnabled(Boolean(verified));
    setMfaFactorId(verified?.id ?? null);
    setRecoveryCount(count ?? 0);
    setAuditRows((audit ?? []) as AuditRow[]);
  }, [loadAvatarPreview, profile?.avatar_storage_path, setAvatarPreviewUrl, user]);

  useEffect(() => {
    setDisplayName(profile?.name ?? "");
    setUsername(profile?.username ?? "");
    setEmail(displayableEmail(user?.email) ?? displayableEmail(profile?.email) ?? "");
  }, [profile, user?.email]);

  useEffect(() => {
    loadSecurityState();
  }, [loadSecurityState]);

  useEffect(() => {
    if (!user) return undefined;
    const channel = supabase
      .channel(`qguard-profile-settings-${user.id}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "qguard_profile_audit_events", filter: `user_id=eq.${user.id}` }, loadSecurityState)
      .on("postgres_changes", { event: "*", schema: "public", table: "profiles", filter: `id=eq.${user.id}` }, () => {
        loadSecurityState();
        onRefresh();
      })
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [loadSecurityState, onRefresh, user]);

  async function recordSettingsTelemetry(stage: string, detail: string, progress: number, statusValue: TelemetryStatus) {
    if (!user) return;
    await recordCryptoTelemetry({
      userId: user.id,
      scope: "verification",
      stage,
      detail,
      progress,
      status: statusValue,
      metadata: {
        module: "settings",
        live_state: liveStatus.state,
        aal: mfaEnabled ? "aal2" : "aal1",
      },
    });
  }

  async function runAction(name: string, action: () => Promise<void>) {
    setBusy(name);
    setError(null);
    try {
      await recordSettingsTelemetry(`settings_${name}_started`, "Settings action started", 10, "started");
      await action();
      await Promise.resolve(onRefresh());
      await loadSecurityState();
      await recordSettingsTelemetry(`settings_${name}_complete`, "Settings action completed", 100, "complete");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      await recordSettingsTelemetry(`settings_${name}_failed`, message, 100, "failed");
    } finally {
      setBusy(null);
    }
  }

  async function audit(eventType: string, severity: "info" | "warning" | "critical" = "info", metadata: Record<string, string | number | boolean | null> = {}) {
    if (!user) return;
    try {
      await supabase.rpc("log_qguard_profile_security_event", {
        p_event_type: eventType,
        p_severity: severity,
        p_metadata: metadata,
        p_email_hash: sha3_256Hex(accountAuditIdentifier(user) || email.trim().toLowerCase()),
        p_user_id: user.id,
      });
    } catch {
      // Profile audit failures are intentionally non-blocking.
    }
  }

  async function enforceRateLimit(action: string, limit = 5) {
    const { data, error: limitError } = await supabase.rpc("check_qguard_profile_rate_limit", {
      p_action: action,
      p_email_hash: sha3_256Hex(accountAuditIdentifier(user) || email.trim().toLowerCase()),
      p_limit: limit,
      p_window_seconds: 300,
    });
    if (limitError) return;
    if (!data) throw new Error("This action is temporarily rate limited.");
  }

  async function validateCurrentPassword() {
    // Mobile-number accounts have no password: the "current password" field
    // carries a fresh SMS code instead (see ProofInput).
    if (user && phoneAccount) {
      if (!currentPassword) throw new Error("Text yourself a code and enter it to confirm this change.");
      await verifyAccountProof(user, currentPassword);
      return;
    }
    if (!user?.email) throw new Error("A verified email session is required.");
    if (!currentPassword) throw new Error("Current password is required.");
    const client = createEphemeralSupabaseClient();
    const { error: signInError } = await client.auth.signInWithPassword({ email: user.email, password: currentPassword });
    await client.auth.signOut({ scope: "local" }).catch(() => undefined);
    if (signInError) throw new Error("Current password could not be validated.");
  }

  async function confirmMfaCode() {
    if (!mfaFactorId) return;
    if (!stepUpCode.trim()) throw new Error("Authenticator confirmation is required.");
    const { error: verifyError } = await supabase.auth.mfa.challengeAndVerify({
      factorId: mfaFactorId,
      code: stepUpCode.trim(),
    });
    if (verifyError) throw verifyError;
  }

  async function confirmSensitive(action: string) {
    await enforceRateLimit(action);
    await validateCurrentPassword();
    await confirmMfaCode();
  }

  async function updateProfile(event: FormEvent) {
    event.preventDefault();
    if (!user) return;
    await runAction("profile", async () => {
      const cleanUsername = username.trim().toLowerCase();
      if (cleanUsername && !/^[a-z0-9_]{3,24}$/.test(cleanUsername)) {
        throw new Error("Username must be 3-24 lowercase letters, numbers, or underscores.");
      }
      await enforceRateLimit("profile_update", 10);
      const { error: profileError } = await supabase.from("profiles").update({
        name: displayName.trim() || null,
        username: cleanUsername || null,
        profile_updated_at: new Date().toISOString(),
      }).eq("id", user.id);
      if (profileError) throw profileError;
      const { error: authError } = await supabase.auth.updateUser({ data: { full_name: displayName.trim(), username: cleanUsername } });
      if (authError) throw authError;
      await audit("profile_updated", "info", { username_changed: cleanUsername !== profile?.username });
      setStatus("Profile updated");
      onRefresh();
    });
  }

  async function updateEmail(event: FormEvent) {
    event.preventDefault();
    if (!user) return;
    await runAction("email", async () => {
      const target = newEmail.trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target)) throw new Error("Enter a valid email address.");
      await confirmSensitive("email_change");
      const { error: updateError } = await supabase.auth.updateUser({ email: target }, { emailRedirectTo: window.location.origin });
      if (updateError) throw updateError;
      await audit("email_change_requested", "warning", { target_email_hash: sha3_256Hex(target) });
      setStepUpCode("");
      setCurrentPassword("");
      setNewEmail("");
      setStatus("Email verification sent");
    });
  }

  async function updatePassword(event: FormEvent) {
    event.preventDefault();
    await runAction("password", async () => {
      if (newPassword !== confirmPassword) throw new Error("New passwords do not match.");
      if (strength.score < 4 || newPassword.length < 12) throw new Error("Choose a stronger password.");
      await confirmSensitive("password_change");
      const { error: updateError } = await supabase.auth.updateUser({
        password: newPassword,
        ...(passwordNonce.trim() ? { nonce: passwordNonce.trim() } : {}),
      });
      if (updateError) {
        if (/reauth|nonce/i.test(updateError.message)) {
          await supabase.auth.reauthenticate();
          throw new Error("Check your email for the password-change code, then enter it in the nonce field.");
        }
        throw updateError;
      }
      await audit("password_changed", "critical");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setPasswordNonce("");
      setStepUpCode("");
      setStatus("Password updated");
    });
  }

  async function uploadAvatar(file: File) {
    if (!user) return;
    await runAction("avatar", async () => {
      if (!avatarTypes.has(file.type)) throw new Error("Avatar must be PNG, JPG, or WebP.");
      if (file.size > 3 * 1024 * 1024) throw new Error("Avatar must be 3 MB or smaller.");
      await enforceRateLimit("avatar_update", 10);
      const blob = await resizeAvatar(file);
      const path = `${user.id}/avatar.webp`;
      const { error: uploadError } = await supabase.storage.from("profile-avatars").upload(path, blob, {
        contentType: "image/webp",
        upsert: true,
      });
      if (uploadError) throw uploadError;
      const { error: profileError } = await supabase.from("profiles").update({
        avatar_storage_path: path,
        avatar_updated_at: new Date().toISOString(),
        profile_updated_at: new Date().toISOString(),
      }).eq("id", user.id);
      if (profileError) throw profileError;
      const { data: avatarBlob, error: downloadError } = await supabase.storage.from("profile-avatars").download(path);
      setAvatarPreviewUrl(URL.createObjectURL(downloadError || !avatarBlob ? blob : avatarBlob));
      invalidateAvatar(user.id);
      await audit("avatar_updated");
      setStatus("Avatar updated");
      onRefresh();
    });
  }

  async function startMfaEnrollment() {
    await runAction("mfa-enroll", async () => {
      await enforceRateLimit("mfa_enroll");
      // Clear any stale UNVERIFIED TOTP factor from an abandoned enrollment.
      // Otherwise re-enrolling fails with "a factor with this friendly name
      // already exists", locking the user out of enabling MFA again.
      try {
        const { data: existing } = await supabase.auth.mfa.listFactors();
        const stale = (existing?.all ?? []).filter(
          (factor) => factor.factor_type === "totp" && factor.status !== "verified",
        );
        for (const factor of stale) {
          await supabase.auth.mfa.unenroll({ factorId: factor.id }).catch(() => undefined);
        }
      } catch {
        // Best-effort cleanup; never block a fresh enrollment.
      }
      const { data, error: enrollError } = await supabase.auth.mfa.enroll({
        factorType: "totp",
        friendlyName: "QGuard Authenticator",
        issuer: "QGuard",
      });
      if (enrollError) throw enrollError;
      setMfaEnrollment({ factorId: data.id, qrCode: data.totp.qr_code, secret: data.totp.secret });
      await audit("mfa_enrollment_started", "warning");
      setStatus("Scan MFA QR code");
    });
  }

  async function storeRecoveryCodes(codes: string[]) {
    if (!user) return;
    await supabase.from("qguard_mfa_recovery_codes").delete().eq("user_id", user.id).is("used_at", null);
    // SHA3-256 once the server can check it (migration 037), SHA-256 until then.
    const scheme = await recoveryHashScheme(supabase);
    const rows = await Promise.all(codes.map(async (code) => {
      const salt = randomHex(16);
      return {
        user_id: user.id,
        salt,
        code_hash: await hashRecoveryCode(salt, code, scheme),
      };
    }));
    const { error: insertError } = await supabase.from("qguard_mfa_recovery_codes").insert(rows);
    if (insertError) throw insertError;
  }

  async function verifyMfaEnrollment() {
    if (!mfaEnrollment) return;
    await runAction("mfa-verify", async () => {
      const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({ factorId: mfaEnrollment.factorId });
      if (challengeError) throw challengeError;
      const { error: verifyError } = await supabase.auth.mfa.verify({
        factorId: mfaEnrollment.factorId,
        challengeId: challenge.id,
        code: mfaSetupCode.trim(),
      });
      if (verifyError) throw verifyError;
      const codes = Array.from({ length: 10 }, newRecoveryCode);
      await storeRecoveryCodes(codes);
      setRecoveryCodes(codes);
      setMfaEnrollment(null);
      setMfaSetupCode("");
      await audit("mfa_enabled", "critical", { recovery_codes_issued: codes.length });
      setStatus("MFA enabled");
      await loadSecurityState();
    });
  }

  async function disableMfa() {
    await runAction("mfa-disable", async () => {
      if (!mfaFactorId) return;
      await confirmSensitive("mfa_disable");
      const { error: unenrollError } = await supabase.auth.mfa.unenroll({ factorId: mfaFactorId });
      if (unenrollError) throw unenrollError;
      if (user) await supabase.from("qguard_mfa_recovery_codes").delete().eq("user_id", user.id);
      await audit("mfa_disabled", "critical");
      setStepUpCode("");
      setCurrentPassword("");
      setStatus("MFA disabled");
      await loadSecurityState();
    });
  }

  async function regenerateRecoveryCodes() {
    await runAction("recovery", async () => {
      await confirmSensitive("mfa_recovery_regenerate");
      const codes = Array.from({ length: 10 }, newRecoveryCode);
      await storeRecoveryCodes(codes);
      setRecoveryCodes(codes);
      await audit("mfa_recovery_codes_regenerated", "warning", { recovery_codes_issued: codes.length });
      setStatus("Recovery codes regenerated");
      await loadSecurityState();
    });
  }

  async function consumeRecoveryCode() {
    await runAction("recovery-check", async () => {
      const { data, error: consumeError } = await supabase.rpc("consume_qguard_mfa_recovery_code", { p_code: recoveryCheck });
      if (consumeError) throw consumeError;
      if (!data) throw new Error("Recovery code was not accepted.");
      setRecoveryCheck("");
      setStatus("Recovery code consumed");
      await loadSecurityState();
    });
  }

  async function downloadRecoveryCodes() {
    if (recoveryCodes.length === 0) return;
    const blob = new Blob([`QGuard recovery codes\n\n${recoveryCodes.join("\n")}\n`], { type: "text/plain" });
    try {
      // Audited only once the file really exists: on Android the old anchor
      // click wrote nothing while this line still recorded a download.
      const saved = await saveFileToDevice("qguard-recovery-codes.txt", blob);
      setError(null);
      setStatus(describeSavedFile(saved));
      void audit("mfa_recovery_codes_downloaded", "warning", { recovery_codes_exported: recoveryCodes.length });
      void recordSettingsTelemetry("settings_recovery_codes_downloaded", "Recovery codes downloaded locally", 100, "complete");
    } catch (err) {
      setError(`Recovery codes were not saved: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  function toggleThemeWithAudit() {
    const nextTheme = theme === "dark" ? "light" : "dark";
    void runAction("theme", async () => {
      onToggleTheme();
      await audit("theme_changed", "info", { theme: nextTheme });
      setStatus(`Theme set to ${nextTheme}`);
    });
  }

  return (
    <div className="grid max-w-7xl gap-4">
      <section className="profile-hero overflow-hidden border border-white/50 bg-white/75 p-5 shadow-tight backdrop-blur-xl">
        <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[280px_1fr_300px]">
          <div className="flex items-center gap-4">
            <label className="avatar-vortex group relative flex h-28 w-28 shrink-0 cursor-pointer items-center justify-center rounded-full">
              {avatarUrl ? (
                <img
                  src={avatarUrl}
                  alt="Profile avatar"
                  className="relative z-10 h-24 w-24 rounded-full object-cover"
                  onError={() => setAvatarPreviewUrl(null)}
                />
              ) : (
                <div className="relative z-10 flex h-24 w-24 items-center justify-center rounded-full bg-ink-950 text-2xl font-bold text-white">
                  {(displayName || email || "QG").slice(0, 2).toUpperCase()}
                </div>
              )}
              <span className="absolute bottom-2 right-1 z-20 flex h-8 w-8 items-center justify-center rounded-full bg-cyan-500 text-white shadow-tight">
                <Camera size={15} />
              </span>
              <input
                type="file"
                accept="image/png,image/jpeg,image/webp"
                className="hidden"
                onClick={() => guardNativeFileInput()}
                onChange={(event) => {
                  const file = event.currentTarget.files?.[0];
                  if (file) uploadAvatar(file);
                }}
              />
            </label>
            <div className="min-w-0">
              <div className="truncate text-lg font-bold text-ink-950">{displayName || "QGuard User"}</div>
              <div className="mt-1 truncate text-sm text-ink-600">{phoneAccount ? accountIdentifierLabel(user) : email}</div>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center gap-2 rounded-full border border-emerald-100 bg-emerald-50 px-3 py-1 text-xs font-bold text-emerald-600">
                  <ShieldCheck size={14} />
                  {accountPosture}
                </span>
                {/* Subscription is tied to the QGuard ACCOUNT (profiles.tier),
                    so the same plan applies on Desktop, Android, and any
                    future device — purchased once, unlocked everywhere. */}
                {profile?.tier && (
                  <span
                    className="inline-flex items-center gap-2 rounded-full border border-violet-100 bg-violet-50 px-3 py-1 text-xs font-bold uppercase text-violet-700"
                    title="Your subscription is account-based and applies on every device you sign in on."
                  >
                    {profile.tier} plan · all devices
                  </span>
                )}
              </div>
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-lg border border-white/60 bg-white/70 p-4">
              <div className="text-xs font-bold uppercase text-ink-400">Authenticator</div>
              <div className="mt-2 text-xl font-bold text-ink-950">{mfaEnabled ? "Enabled" : "Not enabled"}</div>
            </div>
            <div className="rounded-lg border border-white/60 bg-white/70 p-4">
              <div className="text-xs font-bold uppercase text-ink-400">Recovery Codes</div>
              <div className="mt-2 text-xl font-bold text-ink-950">{recoveryCount}</div>
            </div>
            <div className="rounded-lg border border-white/60 bg-white/70 p-4">
              <div className="text-xs font-bold uppercase text-ink-400">Session</div>
              <div className="mt-2 text-xl font-bold text-ink-950">{auth.session ? "Active" : "Locked"}</div>
            </div>
          </div>
          <div className="rounded-lg border border-line bg-white/70 p-4">
            <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
              {theme === "dark" ? <Moon size={17} /> : <Sun size={17} />}
              Theme
            </div>
            <div className="mt-3 text-sm text-ink-600">{theme}</div>
            <button onClick={toggleThemeWithAudit} disabled={Boolean(busy)} className="mt-4 rounded-lg bg-ink-950 px-4 py-2 text-sm font-bold text-white disabled:opacity-50">
              {busy === "theme" ? "Saving Theme" : "Toggle Theme"}
            </button>
          </div>
        </div>
      </section>

      {(error || status) && (
        <div className={`rounded-lg border p-3 text-sm font-semibold ${error ? "border-rose-100 bg-rose-50 text-rose-600" : "border-emerald-100 bg-emerald-50 text-emerald-600"}`}>
          {error ?? status}
        </div>
      )}

      <section className="shell-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><LockKeyhole size={18} /> Workspace Lock</div>
          <span className="status-pill bg-emerald-50 text-emerald-600"><ShieldCheck size={12} /> Zero-Trust</span>
        </div>
        <p className="mt-1 text-sm text-ink-600">
          Secure Chat and Quantum Vault each require their own password or PIN, separate from your account login. They lock automatically when the app is minimized, hidden, or idle.
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {(["chat", "vault"] as const).map((scope) => {
            const scopeStatus = workspaceStatus?.[scope];
            const label = scope === "chat" ? "Secure Chat" : "Quantum Vault";
            return (
              <div key={scope} className="rounded-lg border border-line bg-white p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm font-bold text-ink-950">{label}</div>
                  <span className={`status-pill ${!scopeStatus?.configured ? "bg-amber-50 text-amber-700" : scopeStatus.unlocked ? "bg-emerald-50 text-emerald-600" : "bg-ink-50 text-ink-600"}`}>
                    {!scopeStatus?.configured ? "Not set up" : scopeStatus.unlocked ? "Unlocked" : "Locked"}
                  </span>
                </div>
                <div className="mt-1 text-[11px] text-ink-500">
                  {scopeStatus?.configured
                    ? `Protected by ${[scopeStatus.hasPassword ? "password" : null, scopeStatus.hasPin ? "PIN" : null].filter(Boolean).join(" + ")}`
                    : `Open ${label} to set up a password or PIN.`}
                </div>
              </div>
            );
          })}
        </div>
        <div className="mt-4 flex flex-wrap items-end justify-between gap-3">
          <label className="text-sm font-semibold text-ink-700">
            Inactivity auto-lock
            <select
              value={inactivityMinutes}
              onChange={(event) => onSetInactivityMinutes(Number(event.currentTarget.value))}
              className="mt-1 block w-56 rounded-lg border border-line bg-canvas px-3 py-2 text-sm outline-none focus:border-cyan-300"
            >
              {INACTIVITY_OPTIONS.map((minutes) => (
                <option key={minutes} value={minutes}>
                  {minutes === 0 ? "Never (not recommended)" : `${minutes} minutes`}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={() => void onLockWorkspaces()}
            className="flex items-center gap-2 rounded-lg border border-line bg-white px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas"
          >
            <LockKeyhole size={16} /> Lock now
          </button>
        </div>
      </section>

      {appLock?.enabled && user?.id && (
        <ApplicationPinSection appLock={appLock} verifyAccountPassword={verifyAccountPassword} userId={user.id} />
      )}

      <CallDeviceProtectionCard />

      <SessionRatchetCard userId={user?.id ?? null} />

      {user?.id && <DevicePrivacyCard userId={user.id} appLock={appLock} />}

      {user?.id && <RecoveryCenterCard userId={user.id} />}
      {user?.id && <AiAssistantCard />}
      {user?.id && <OfflineDeliveryCard />}

      <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[1fr_420px]">
        <section className="grid gap-4">
          <form onSubmit={updateProfile} className="shell-card p-5">
            <div className="mb-4 flex items-center gap-2 text-sm font-bold text-ink-950"><UserRound size={18} /> Account Information</div>
            <div className="grid gap-4 md:grid-cols-2">
              <label className="text-sm font-semibold text-ink-700">
                Display name
                <input value={displayName} onChange={(event) => setDisplayName(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" />
              </label>
              <label className="text-sm font-semibold text-ink-700">
                Username
                <input value={username} onChange={(event) => setUsername(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" />
              </label>
            </div>
            <button disabled={busy === "profile"} className="mt-5 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-700 disabled:opacity-50">
              Save Profile
            </button>
          </form>

          <form onSubmit={updateEmail} className="shell-card p-5">
            <div className="mb-4 flex items-center gap-2 text-sm font-bold text-ink-950"><Mail size={18} /> {phoneAccount && !email ? "Add an Email Address" : "Email Address"}</div>
            {phoneAccount && !email && (
              <p className="-mt-2 mb-4 text-xs leading-5 text-ink-500">Optional. You keep signing in with your mobile number; an email adds a way to receive account notices.</p>
            )}
            <div className="grid gap-4 md:grid-cols-3">
              <label className="text-sm font-semibold text-ink-700">
                New email
                <input type="email" value={newEmail} onChange={(event) => setNewEmail(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" />
              </label>
              <ProofInput phone={phoneAccount} value={currentPassword} onChange={setCurrentPassword} sentTo={proofSentTo} onSend={user ? async () => setProofSentTo(await sendAccountProofCode(user)) : undefined} />
              <label className="text-sm font-semibold text-ink-700">
                MFA code
                <input value={stepUpCode} onChange={(event) => setStepUpCode(event.target.value.replace(/\D/g, "").slice(0, 6))} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" inputMode="numeric" />
              </label>
            </div>
            <button disabled={busy === "email"} className="mt-5 rounded-lg bg-ink-950 px-4 py-2 text-sm font-bold text-white disabled:opacity-50">
              Send Verification
            </button>
          </form>

          {phoneAccount ? (
            <section className="shell-card p-5">
              <div className="mb-3 flex items-center gap-2 text-sm font-bold text-ink-950"><Smartphone size={18} /> Sign-in Method</div>
              <p className="text-sm text-ink-700">
                You sign in with <span className="font-semibold">{accountIdentifierLabel(user)}</span> and a one-time SMS code. This account has no password to steal or reuse.
              </p>
              <p className="mt-2 text-xs leading-5 text-ink-500">
                For a second factor — so a SIM swap alone can never open your account — turn on authenticator MFA. New devices can also be linked by QR code from Devices → Link a device.
              </p>
            </section>
          ) : (
          <form onSubmit={updatePassword} className="shell-card p-5">
            <div className="mb-4 flex items-center gap-2 text-sm font-bold text-ink-950"><LockKeyhole size={18} /> Credential Management</div>
            <div className="grid gap-4 md:grid-cols-2">
              <ProofInput phone={phoneAccount} value={currentPassword} onChange={setCurrentPassword} sentTo={proofSentTo} onSend={user ? async () => setProofSentTo(await sendAccountProofCode(user)) : undefined} />
              <label className="text-sm font-semibold text-ink-700">
                Email nonce
                <input value={passwordNonce} onChange={(event) => setPasswordNonce(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" />
              </label>
              <label className="text-sm font-semibold text-ink-700">
                New password
                <input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" autoComplete="new-password" />
              </label>
              <label className="text-sm font-semibold text-ink-700">
                Confirm password
                <input type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" autoComplete="new-password" />
              </label>
            </div>
            <div className="mt-4 h-2 overflow-hidden rounded-full bg-canvas">
              <div className="h-full bg-cyan-500 transition-all" style={{ width: `${(strength.score / 5) * 100}%` }} />
            </div>
            <div className="mt-2 text-xs font-semibold text-ink-600">{strength.label} - {strength.entropy} bits estimated entropy</div>
            <button disabled={busy === "password"} className="mt-5 rounded-lg bg-rose-600 px-4 py-2 text-sm font-bold text-white hover:bg-rose-700 disabled:opacity-50">
              Update Password
            </button>
          </form>
          )}
        </section>

        <aside className="grid gap-4 content-start">
          <section className="shell-card p-5">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><KeyRound size={18} /> Multi-Factor Authentication</div>
              <span className={`status-pill ${mfaEnabled ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-600"}`}>
                {mfaEnabled ? <BadgeCheck size={14} /> : <AlertTriangle size={14} />}
                {mfaEnabled ? "Enabled" : "Off"}
              </span>
            </div>

            {!mfaEnabled && !mfaEnrollment && (
              <button onClick={startMfaEnrollment} className="mt-5 flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-700">
                <QrCode size={16} />
                Enable TOTP
              </button>
            )}

            {mfaEnrollment && (
              <div className="mt-5 grid gap-4">
                <img src={qrCodeSrc(mfaEnrollment.qrCode)} alt="TOTP QR code" className="mx-auto h-48 w-48 rounded-lg border border-line bg-white p-2" />
                <div className="rounded-lg border border-line bg-canvas p-3 font-mono text-xs text-ink-700">{mfaEnrollment.secret}</div>
                <label className="text-sm font-semibold text-ink-700">
                  Verification code
                  <input value={mfaSetupCode} onChange={(event) => setMfaSetupCode(event.target.value.replace(/\D/g, "").slice(0, 6))} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 text-center font-mono text-lg tracking-[0.3em] outline-none focus:border-cyan-300" inputMode="numeric" />
                </label>
                <button onClick={verifyMfaEnrollment} className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-bold text-white hover:bg-emerald-700">
                  Verify MFA
                </button>
              </div>
            )}

            {mfaEnabled && (
              <div className="mt-5 grid gap-3">
                <ProofInput phone={phoneAccount} value={currentPassword} onChange={setCurrentPassword} sentTo={proofSentTo} onSend={user ? async () => setProofSentTo(await sendAccountProofCode(user)) : undefined} />
                <label className="text-sm font-semibold text-ink-700">
                  MFA code
                  <input value={stepUpCode} onChange={(event) => setStepUpCode(event.target.value.replace(/\D/g, "").slice(0, 6))} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" inputMode="numeric" />
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button onClick={regenerateRecoveryCodes} className="rounded-lg border border-line px-3 py-2 text-sm font-bold text-ink-700 hover:bg-canvas">
                    Rotate Codes
                  </button>
                  <button onClick={disableMfa} className="rounded-lg bg-rose-600 px-3 py-2 text-sm font-bold text-white hover:bg-rose-700">
                    Disable MFA
                  </button>
                </div>
              </div>
            )}
          </section>

          <section className="shell-card p-5">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><Download size={18} /> Recovery Codes</div>
              <span className="status-pill bg-cyan-50 text-cyan-700">{recoveryCount} active</span>
            </div>
            {recoveryCodes.length > 0 && (
              <div className="mt-4 grid gap-2">
                {recoveryCodes.map((code) => <div key={code} className="rounded-lg bg-canvas px-3 py-2 font-mono text-sm text-ink-700">{code}</div>)}
                <button onClick={() => void downloadRecoveryCodes()} className="rounded-lg bg-ink-950 px-4 py-2 text-sm font-bold text-white">
                  Download Codes
                </button>
              </div>
            )}
            <div className="mt-4 flex gap-2">
              <input value={recoveryCheck} onChange={(event) => setRecoveryCheck(event.target.value.toUpperCase())} className="min-w-0 flex-1 rounded-lg border border-line bg-canvas px-3 py-2 text-sm outline-none focus:border-cyan-300" />
              <button onClick={consumeRecoveryCode} className="icon-button" title="Verify recovery code"><CheckCircle2 size={16} /></button>
            </div>
          </section>

          <section className="shell-card p-5">
            <div className="mb-4 flex items-center gap-2 text-sm font-bold text-ink-950"><RefreshCcw size={18} /> Security Audit</div>
            <div className="grid gap-2">
              {auditRows.length === 0 && <div className="text-sm text-ink-600">No profile security events yet.</div>}
              {auditRows.map((row) => (
                <div key={row.id} className="flex items-center justify-between gap-3 border-b border-line py-2 last:border-0">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold text-ink-950">{row.event_type}</div>
                    <div className="text-xs text-ink-400">{new Date(row.created_at).toLocaleString()}</div>
                  </div>
                  <span className={`status-pill ${row.severity === "critical" ? "bg-rose-50 text-rose-600" : row.severity === "warning" ? "bg-amber-50 text-amber-600" : "bg-emerald-50 text-emerald-600"}`}>
                    {row.severity}
                  </span>
                </div>
              ))}
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}

/**
 * Android-only "Application PIN" security section: change/switch the app-entry
 * PIN, remove it (falling back to account password on next launch), tune the
 * auto-lock timeout, and manage/revoke the trusted-device registry (migration
 * 031). Every control is an inline, styled form -- no window.prompt/alert,
 * since native browser dialogs render unreliably inside the Android WebView.
 * `verifyAccountPassword` is optional (the paywall-mode SettingsPage render
 * site in App.tsx has none in scope), so the Remove PIN control simply hides
 * when it's absent rather than allowing an unverified removal.
 */
function ApplicationPinSection({
  appLock,
  verifyAccountPassword,
  userId,
}: {
  appLock: ReturnType<typeof useAppLock>;
  verifyAccountPassword?: (password: string) => Promise<void>;
  userId: string;
}) {
  const [devices, setDevices] = useState<TrustedDeviceRow[]>([]);
  const [devicesBusy, setDevicesBusy] = useState(false);

  const [showChangeForm, setShowChangeForm] = useState(false);
  const [oldPin, setOldPin] = useState("");
  const [newPin, setNewPin] = useState("");
  // Preselect the currently configured digit count (a 4-digit user sees
  // "4-digit" preselected instead of always defaulting to 6).
  const [newDigits, setNewDigits] = useState<4 | 6>(appLock.status?.digits === 4 ? 4 : 6);
  const [changeBusy, setChangeBusy] = useState(false);
  const [changeMsg, setChangeMsg] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  const [showRemoveForm, setShowRemoveForm] = useState(false);
  const [removePassword, setRemovePassword] = useState("");
  const [removeBusy, setRemoveBusy] = useState(false);
  const [removeMsg, setRemoveMsg] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [devicesMsg, setDevicesMsg] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  const refreshDevices = useCallback(async () => {
    setDevices(await listTrustedDevices(supabase, userId));
  }, [userId]);

  useEffect(() => {
    void refreshDevices();
    // Re-pull whenever this device's own last-login timestamp advances (e.g.
    // after an unlock upserts it), so a freshly-registered device shows up
    // without requiring a manual refresh.
  }, [refreshDevices, appLock.status?.device?.lastLoginAt]);

  if (!appLock.enabled) return null;
  const status = appLock.status;

  if (appLock.loading || !status) {
    return (
      <section className="shell-card p-5">
        <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><LockKeyhole size={18} /> Application PIN</div>
        <p className="mt-2 text-xs text-ink-500">Checking device lock status…</p>
      </section>
    );
  }

  const submitChangePin = async (event: FormEvent) => {
    event.preventDefault();
    if (oldPin.length === 0 || newPin.length !== newDigits) return;
    setChangeBusy(true);
    setChangeMsg(null);
    try {
      await appLock.changePin(oldPin, newPin, newDigits);
      setChangeMsg({ tone: "ok", text: "PIN updated." });
      setOldPin("");
      setNewPin("");
      setShowChangeForm(false);
    } catch (err) {
      setChangeMsg({ tone: "error", text: err instanceof Error ? err.message : "Could not change PIN." });
    } finally {
      setChangeBusy(false);
    }
  };

  const submitRemovePin = async (event: FormEvent) => {
    event.preventDefault();
    if (!verifyAccountPassword || removePassword.length === 0) return;
    setRemoveBusy(true);
    setRemoveMsg(null);
    try {
      await verifyAccountPassword(removePassword);
      await appLock.remove();
      setRemoveMsg({ tone: "ok", text: "App PIN removed. You'll sign in with your password next launch." });
      setRemovePassword("");
      setShowRemoveForm(false);
    } catch (err) {
      setRemoveMsg({ tone: "error", text: err instanceof Error ? err.message : "Could not remove PIN." });
    } finally {
      setRemoveBusy(false);
    }
  };

  const revoke = async (deviceId: string) => {
    setDevicesBusy(true);
    setDevicesMsg(null);
    try {
      await revokeTrustedDevice(supabase, userId, deviceId);
      await refreshDevices();
    } catch (err) {
      setDevicesMsg({ tone: "error", text: err instanceof Error ? err.message : "Could not revoke device." });
    } finally {
      setDevicesBusy(false);
    }
  };

  return (
    <section className="shell-card p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><LockKeyhole size={18} /> Application PIN</div>
        <span className={`status-pill ${status.configured ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-700"}`}>
          {status.configured ? <ShieldCheck size={12} /> : <AlertTriangle size={12} />}
          {status.configured ? `${status.digits}-digit PIN active` : "Not configured"}
        </span>
      </div>
      <p className="mt-1 text-sm text-ink-600">
        Banking-grade unlock for QGuard Messaging on this device, separate from your account password.
      </p>

      {!status.configured && (
        <p className="mt-3 text-xs text-ink-500">No app PIN is configured on this device yet.</p>
      )}

      {status.configured && (
        <>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                setShowChangeForm((v) => !v);
                setShowRemoveForm(false);
                setChangeMsg(null);
              }}
              className="rounded-lg border border-line bg-white px-3 py-2 text-xs font-bold text-ink-700 hover:bg-canvas"
            >
              {showChangeForm ? "Cancel" : "Change / switch 4↔6 digits"}
            </button>
            {verifyAccountPassword && (
              <button
                type="button"
                onClick={() => {
                  setShowRemoveForm((v) => !v);
                  setShowChangeForm(false);
                  setRemoveMsg(null);
                }}
                className="rounded-lg border border-rose-200 bg-white px-3 py-2 text-xs font-bold text-rose-600 hover:bg-rose-50"
              >
                {showRemoveForm ? "Cancel" : "Remove PIN"}
              </button>
            )}
          </div>

          {showChangeForm && (
            <form onSubmit={submitChangePin} className="mt-4 grid gap-3 rounded-lg border border-line bg-canvas p-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="text-xs font-semibold text-ink-700">
                  Current PIN
                  <input
                    type="password"
                    inputMode="numeric"
                    autoComplete="off"
                    maxLength={12}
                    value={oldPin}
                    onChange={(event) => setOldPin(event.target.value.replace(/\D/g, "").slice(0, 12))}
                    className="mt-1.5 w-full rounded-lg border border-line bg-white px-3 py-2 text-sm outline-none focus:border-cyan-300"
                  />
                </label>
                <label className="text-xs font-semibold text-ink-700">
                  New {newDigits}-digit PIN
                  <input
                    type="password"
                    inputMode="numeric"
                    autoComplete="off"
                    maxLength={newDigits}
                    value={newPin}
                    onChange={(event) => setNewPin(event.target.value.replace(/\D/g, "").slice(0, newDigits))}
                    className="mt-1.5 w-full rounded-lg border border-line bg-white px-3 py-2 text-sm outline-none focus:border-cyan-300"
                  />
                </label>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-ink-700">New PIN length</span>
                <div className="grid grid-cols-2 gap-1 rounded-lg border border-line bg-white p-1" role="radiogroup" aria-label="New PIN length">
                  {([4, 6] as const).map((digitCount) => (
                    <button
                      key={digitCount}
                      type="button"
                      role="radio"
                      aria-checked={newDigits === digitCount}
                      onClick={() => { setNewDigits(digitCount); setNewPin(""); }}
                      className={`rounded-md px-3 py-1 text-xs font-bold transition ${newDigits === digitCount ? "bg-cyan-600 text-white" : "text-ink-600 hover:bg-canvas"}`}
                    >
                      {digitCount}-digit
                    </button>
                  ))}
                </div>
              </div>
              {changeMsg && (
                <p className={`text-xs font-semibold ${changeMsg.tone === "ok" ? "text-emerald-600" : "text-rose-600"}`}>{changeMsg.text}</p>
              )}
              <button
                type="submit"
                disabled={changeBusy || oldPin.length === 0 || newPin.length !== newDigits}
                className="rounded-lg bg-cyan-600 px-4 py-2 text-xs font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {changeBusy ? "Updating…" : "Update PIN"}
              </button>
            </form>
          )}

          {showRemoveForm && verifyAccountPassword && (
            <form onSubmit={submitRemovePin} className="mt-4 grid gap-3 rounded-lg border border-rose-200 bg-rose-50 p-4">
              <p className="text-xs font-semibold text-rose-700">
                Removing the app PIN means you'll sign in with your account password every time you open QGuard Messaging on this device.
              </p>
              <label className="text-xs font-semibold text-rose-700">
                Confirm your account password
                <input
                  type="password"
                  autoComplete="current-password"
                  value={removePassword}
                  onChange={(event) => setRemovePassword(event.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-rose-200 bg-white px-3 py-2 text-sm outline-none focus:border-rose-300"
                />
              </label>
              {removeMsg && (
                <p className={`text-xs font-semibold ${removeMsg.tone === "ok" ? "text-emerald-600" : "text-rose-600"}`}>{removeMsg.text}</p>
              )}
              <button
                type="submit"
                disabled={removeBusy || removePassword.length === 0}
                className="rounded-lg bg-rose-600 px-4 py-2 text-xs font-bold text-white hover:bg-rose-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {removeBusy ? "Removing…" : "Remove PIN"}
              </button>
            </form>
          )}

          <div className="mt-5">
            <label className="text-xs font-semibold text-ink-700">
              Auto-lock after
              <select
                value={status.inactivityMinutes}
                onChange={(event) => void appLock.setInactivity(Number(event.currentTarget.value))}
                className="ml-2 rounded-lg border border-line bg-white px-2 py-1 text-xs outline-none focus:border-cyan-300"
              >
                {[1, 5, 10, 15, 30, 60].map((minutes) => (
                  <option key={minutes} value={minutes}>{minutes} minute{minutes > 1 ? "s" : ""}</option>
                ))}
              </select>
            </label>
          </div>

          <div className="mt-5">
            <h4 className="flex items-center gap-2 text-xs font-bold text-ink-950"><Smartphone size={14} /> Trusted devices</h4>
            {devicesMsg && (
              <p className={`mt-1 text-[11px] font-semibold ${devicesMsg.tone === "ok" ? "text-emerald-600" : "text-rose-600"}`}>{devicesMsg.text}</p>
            )}
            <ul className="mt-2 space-y-2">
              {devices.map((device) => (
                <li key={device.id} className="flex items-center justify-between gap-3 rounded-lg border border-line bg-white px-3 py-2">
                  <div className="min-w-0">
                    <div className="truncate text-xs font-semibold text-ink-950">
                      {device.device_name ?? "Device"}{" "}
                      {device.revoked_at && <span className="text-rose-500">(revoked)</span>}
                    </div>
                    <div className="truncate text-[11px] text-ink-500">
                      {[device.platform, device.app_version ? `v${device.app_version}` : null].filter(Boolean).join(" · ")}
                      {device.last_login_at ? ` · last login ${new Date(device.last_login_at).toLocaleString()}` : ""}
                    </div>
                  </div>
                  {!device.revoked_at && (
                    <button
                      type="button"
                      disabled={devicesBusy}
                      onClick={() => void revoke(device.device_id)}
                      className="shrink-0 text-[11px] font-bold text-rose-600 hover:underline disabled:opacity-50"
                    >
                      Revoke
                    </button>
                  )}
                </li>
              ))}
              {devices.length === 0 && <li className="text-[11px] text-ink-500">No devices registered yet.</li>}
            </ul>
          </div>
        </>
      )}
    </section>
  );
}
