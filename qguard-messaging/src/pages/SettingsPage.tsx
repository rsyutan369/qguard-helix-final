import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  Camera,
  CheckCircle2,
  Database,
  Download,
  KeyRound,
  Loader2,
  LockKeyhole,
  Mail,
  Moon,
  QrCode,
  Radio,
  RefreshCcw,
  ShieldCheck,
  Sun,
  UserRound,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import type { QGuardLiveEvent, QGuardLiveStatus } from "@/lib/live-sse";
import { guardNativeFileInput } from "@/lib/native-dialog-guard";
import { createEphemeralSupabaseClient, supabase } from "@/lib/supabase";
import type { Profile, SecurityEvent, TelemetryEvent } from "@/lib/types";
import type { ThemeMode } from "@/lib/use-theme";
import { INACTIVITY_OPTIONS, type WorkspaceStatus } from "@/lib/use-workspace-lock";

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

const settingsLiveTables = new Set([
  "profiles",
  "qguard_profile_audit_events",
  "messaging_crypto_telemetry",
  "messaging_security_events",
]);

const settingsTerms = /settings|profile|avatar|theme|email|password|mfa|totp|recovery|session|login|auth/i;

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

async function sha256Hex(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function normalizedRecoveryCode(code: string) {
  return code.trim().replace(/-/g, "").toUpperCase();
}

function sortTime(value: string | null | undefined): number {
  const parsed = new Date(value ?? "").getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function latestIso(values: Array<string | null | undefined>): string | null {
  const latest = values.map(sortTime).filter(Boolean).sort((a, b) => b - a)[0];
  return latest ? new Date(latest).toISOString() : null;
}

function relativeTime(value: string | null | undefined): string {
  if (!value) return "No events yet";
  const time = sortTime(value);
  if (!time) return "Unknown";
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 10) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function cleanLabel(value: string): string {
  return value.replace(/_/g, " ");
}

function liveTone(state: QGuardLiveStatus["state"]): string {
  if (state === "live") return "bg-emerald-50 text-emerald-600";
  if (state === "connecting") return "bg-amber-50 text-amber-600";
  if (state === "fallback") return "bg-cyan-50 text-cyan-700";
  return "bg-rose-50 text-rose-600";
}

function statusTone(value: string): string {
  if (/critical|failed|error|blocked|locked/i.test(value)) return "text-rose-500";
  if (/warning|fallback|connecting|pending|off|not enabled|aal1|review/i.test(value)) return "text-amber-600";
  return "text-emerald-600";
}

function isSettingsTelemetry(event: TelemetryEvent): boolean {
  return settingsTerms.test(`${event.stage} ${event.detail}`);
}

function isSettingsSecurityEvent(event: SecurityEvent): boolean {
  return settingsTerms.test(event.event_type);
}

function isSettingsLiveEvent(event: QGuardLiveEvent): boolean {
  if (!settingsLiveTables.has(event.table)) return false;
  if (event.table === "messaging_crypto_telemetry" || event.table === "messaging_security_events") {
    return settingsTerms.test(event.detail);
  }
  return true;
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

export default function SettingsPage({ theme, profile, telemetry, securityEvents, liveEvents, liveStatus, onToggleTheme, onRefresh, inactivityMinutes, onSetInactivityMinutes, workspaceStatus, onLockWorkspaces }: SettingsPageProps) {
  const auth = useAuth();
  const user = auth.user;
  const [displayName, setDisplayName] = useState(profile?.name ?? "");
  const [username, setUsername] = useState(profile?.username ?? "");
  // Prefer the authoritative auth session email (auth.users) over the denormalized
  // profiles.email mirror, so a completed email change is reflected immediately.
  const [email, setEmail] = useState(user?.email ?? profile?.email ?? "");
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
  const settingsTelemetry = useMemo(() => telemetry.filter(isSettingsTelemetry).slice(0, 5), [telemetry]);
  const settingsSecurityEvents = useMemo(() => securityEvents.filter(isSettingsSecurityEvent).slice(0, 5), [securityEvents]);
  const settingsLiveEvents = useMemo(() => liveEvents.filter(isSettingsLiveEvent).slice(0, 5), [liveEvents]);
  const latestSettingsAt = latestIso([
    liveStatus.lastEventAt,
    settingsTelemetry[0]?.created_at,
    settingsSecurityEvents[0]?.created_at,
    auditRows[0]?.created_at,
    profile?.avatar_updated_at,
  ]);
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
    setEmail(user?.email ?? profile?.email ?? "");
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
        p_email_hash: await sha256Hex((user.email ?? email).trim().toLowerCase()),
        p_user_id: user.id,
      });
    } catch {
      // Profile audit failures are intentionally non-blocking.
    }
  }

  async function enforceRateLimit(action: string, limit = 5) {
    const { data, error: limitError } = await supabase.rpc("check_qguard_profile_rate_limit", {
      p_action: action,
      p_email_hash: await sha256Hex((user?.email ?? email).trim().toLowerCase()),
      p_limit: limit,
      p_window_seconds: 300,
    });
    if (limitError) return;
    if (!data) throw new Error("This action is temporarily rate limited.");
  }

  async function validateCurrentPassword() {
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
      await audit("email_change_requested", "warning", { target_email_hash: await sha256Hex(target) });
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
    const rows = await Promise.all(codes.map(async (code) => {
      const salt = randomHex(16);
      return {
        user_id: user.id,
        salt,
        code_hash: await sha256Hex(salt + normalizedRecoveryCode(code)),
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

  function downloadRecoveryCodes() {
    if (recoveryCodes.length === 0) return;
    const blob = new Blob([`QGuard recovery codes\n\n${recoveryCodes.join("\n")}\n`], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "qguard-recovery-codes.txt";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    void audit("mfa_recovery_codes_downloaded", "warning", { recovery_codes_exported: recoveryCodes.length });
    void recordSettingsTelemetry("settings_recovery_codes_downloaded", "Recovery codes downloaded locally", 100, "complete");
  }

  function toggleThemeWithAudit() {
    const nextTheme = theme === "dark" ? "light" : "dark";
    void runAction("theme", async () => {
      onToggleTheme();
      await audit("theme_changed", "info", { theme: nextTheme });
      setStatus(`Theme set to ${nextTheme}`);
    });
  }

  function refreshSettingsState() {
    void runAction("refresh", async () => {
      await loadSecurityState();
      setStatus("Settings state refreshed from live backend data");
    });
  }

  return (
    <div className="grid max-w-7xl gap-4">
      <section className="profile-hero overflow-hidden border border-white/50 bg-white/75 p-5 shadow-tight backdrop-blur-xl">
        <div className="grid gap-5 lg:grid-cols-[280px_1fr_300px]">
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
              <div className="mt-1 truncate text-sm text-ink-600">{email}</div>
              <div className="mt-3 inline-flex items-center gap-2 rounded-full border border-emerald-100 bg-emerald-50 px-3 py-1 text-xs font-bold text-emerald-600">
                <ShieldCheck size={14} />
                {accountPosture}
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

      <section className="shell-card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-ink-950">Realtime Settings Telemetry</h2>
            <div className="mt-1 text-xs text-ink-600">Profile and credential state refreshed {relativeTime(latestSettingsAt)}</div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className={`status-pill ${liveTone(liveStatus.state)}`}>
              <Radio size={13} />
              {liveStatus.state}
            </span>
            <button onClick={refreshSettingsState} disabled={Boolean(busy)} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-xs font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50">
              {busy === "refresh" ? <Loader2 className="animate-spin" size={14} /> : <RefreshCcw size={14} />}
              Refresh
            </button>
          </div>
        </div>

        <div className="mt-4 grid gap-4 border-y border-line py-3 md:grid-cols-4">
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Live Detail</div>
            <div className="mt-1 truncate text-sm font-semibold text-ink-950">{liveStatus.detail}</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Last Event</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{relativeTime(liveStatus.lastEventAt)}</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Profile Audit</div>
            <div className="mt-1 text-sm font-semibold text-ink-950">{auditRows.length} recent rows</div>
          </div>
          <div>
            <div className="text-[11px] font-bold uppercase text-ink-400">Account Posture</div>
            <div className={`mt-1 text-sm font-semibold ${statusTone(accountPosture)}`}>{accountPosture}</div>
          </div>
        </div>

        <div className="mt-4 grid gap-6 xl:grid-cols-3">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <Database size={14} />
              Backend Events
            </div>
            {settingsLiveEvents.length === 0 && <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">Live stream connected. No settings backend changes received yet.</div>}
            <div className="space-y-2">
              {settingsLiveEvents.map((event) => (
                <div key={event.id} className="flex items-center gap-3 border-t border-line pt-2 first:border-t-0 first:pt-0">
                  <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-ink-950">{event.detail}</div>
                    <div className="text-[11px] text-ink-400">{event.table} - {event.event.toLowerCase()} - {relativeTime(event.at)}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <Activity size={14} />
              Settings Telemetry
            </div>
            {settingsTelemetry.length === 0 && <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">No settings telemetry yet.</div>}
            <div className="space-y-2">
              {settingsTelemetry.map((event) => (
                <div key={event.id} className="flex items-center gap-3 border-t border-line pt-2 first:border-t-0 first:pt-0">
                  <span className={`status-pill shrink-0 ${event.progress >= 100 ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-600"}`}>{Math.max(0, Math.min(100, Math.round(event.progress)))}%</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-ink-950">{cleanLabel(event.stage)}</div>
                    <div className="truncate text-[11px] text-ink-500">{event.detail}</div>
                  </div>
                  <div className="shrink-0 text-[11px] text-ink-400">{relativeTime(event.created_at)}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase text-ink-400">
              <ShieldCheck size={14} />
              Security Signals
            </div>
            {settingsSecurityEvents.length === 0 && auditRows.length === 0 && <div className="rounded-lg border border-line bg-canvas p-3 text-xs text-ink-600">No settings security events yet.</div>}
            <div className="space-y-2">
              {[
                ...auditRows.map((row) => ({ id: `profile-${row.id}`, label: row.event_type, severity: row.severity, created_at: row.created_at })),
                ...settingsSecurityEvents.map((event) => ({ id: `security-${event.id}`, label: event.event_type, severity: event.severity, created_at: event.created_at })),
              ].sort((a, b) => sortTime(b.created_at) - sortTime(a.created_at)).slice(0, 5).map((event) => (
                <div key={event.id} className="flex items-center gap-3 border-t border-line pt-2 first:border-t-0 first:pt-0">
                  <span className={`status-pill shrink-0 ${event.severity === "critical" ? "bg-rose-50 text-rose-600" : event.severity === "warning" ? "bg-amber-50 text-amber-700" : "bg-emerald-50 text-emerald-600"}`}>{event.severity}</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-ink-950">{cleanLabel(event.label)}</div>
                    <div className="text-[11px] text-ink-400">{relativeTime(event.created_at)}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

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

      <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
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
            <div className="mb-4 flex items-center gap-2 text-sm font-bold text-ink-950"><Mail size={18} /> Email Address</div>
            <div className="grid gap-4 md:grid-cols-3">
              <label className="text-sm font-semibold text-ink-700">
                New email
                <input type="email" value={newEmail} onChange={(event) => setNewEmail(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" />
              </label>
              <label className="text-sm font-semibold text-ink-700">
                Current password
                <input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" autoComplete="current-password" />
              </label>
              <label className="text-sm font-semibold text-ink-700">
                MFA code
                <input value={stepUpCode} onChange={(event) => setStepUpCode(event.target.value.replace(/\D/g, "").slice(0, 6))} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" inputMode="numeric" />
              </label>
            </div>
            <button disabled={busy === "email"} className="mt-5 rounded-lg bg-ink-950 px-4 py-2 text-sm font-bold text-white disabled:opacity-50">
              Send Verification
            </button>
          </form>

          <form onSubmit={updatePassword} className="shell-card p-5">
            <div className="mb-4 flex items-center gap-2 text-sm font-bold text-ink-950"><LockKeyhole size={18} /> Credential Management</div>
            <div className="grid gap-4 md:grid-cols-2">
              <label className="text-sm font-semibold text-ink-700">
                Current password
                <input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" autoComplete="current-password" />
              </label>
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
                <label className="text-sm font-semibold text-ink-700">
                  Current password
                  <input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-cyan-300" />
                </label>
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
                <button onClick={downloadRecoveryCodes} className="rounded-lg bg-ink-950 px-4 py-2 text-sm font-bold text-white">
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
