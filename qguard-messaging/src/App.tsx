import { lazy, Suspense, useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";
import OnboardingTour from "@/components/onboarding/OnboardingTour";
import MobileShell from "@/components/mobile/MobileShell";
import MobileOnboarding, { isMobileOnboardingPending } from "@/components/mobile/MobileOnboarding";
import { CallProvider } from "@/components/call/CallProvider";
import { PaywallGate } from "@/components/PaywallGate";
import { UpdateBanner } from "@/components/UpdateBanner";
import { WorkspaceLockGate } from "@/components/workspace/WorkspaceLockGate";
import { AppLockScreen } from "@/components/applock/AppLockScreen";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AuthProvider, useAuth } from "@/lib/auth-context";
import { useSubscription } from "@/lib/use-subscription";
import { useIsMobile } from "@/lib/use-mobile";
import { useAppLock } from "@/lib/use-app-lock";
import { upsertTrustedDevice, isDeviceRevoked } from "@/lib/trusted-devices";
import { buildChecklist, buildTourSteps, useOnboarding } from "@/lib/onboarding";
import { useDashboardData } from "@/lib/use-dashboard-data";
import { useWorkspaceLock, type UnlockMethod, type WorkspaceScope } from "@/lib/use-workspace-lock";
import { createEphemeralSupabaseClient, supabase } from "@/lib/supabase";
import { isAndroidRuntime, safeInvoke } from "@/lib/tauri";
import { useTheme } from "@/lib/use-theme";
import LoginPage from "@/pages/LoginPage";
import type { Page } from "@/lib/types";

// Importer thunks are reused for both lazy() and idle-time prefetch (so the
// first switch to a module is instant). Prefetch only downloads/parses chunks;
// protected modules still don't *mount* until unlocked.
const pageImporters = {
  audit: () => import("@/pages/AuditLogsPage"),
  dashboard: () => import("@/pages/DashboardPage"),
  devices: () => import("@/pages/DeviceTrustCenterPage"),
  keys: () => import("@/pages/KeyManagementPage"),
  quantum: () => import("@/pages/QuantumSecurityDashboardPage"),
  vault: () => import("@/pages/QuantumVaultPage"),
  verification: () => import("@/pages/SecurityVerificationPage"),
  chat: () => import("@/pages/SecureChatPage"),
  subscription: () => import("@/pages/SubscriptionPage"),
  settings: () => import("@/pages/SettingsPage"),
};

const AuditLogsPage = lazy(pageImporters.audit);
const DashboardPage = lazy(pageImporters.dashboard);
const DeviceTrustCenterPage = lazy(pageImporters.devices);
const KeyManagementPage = lazy(pageImporters.keys);
const QuantumSecurityDashboardPage = lazy(pageImporters.quantum);
const QuantumVaultPage = lazy(pageImporters.vault);
const SecurityVerificationPage = lazy(pageImporters.verification);
const SecureChatPage = lazy(pageImporters.chat);
const SubscriptionPage = lazy(pageImporters.subscription);
const SettingsPage = lazy(pageImporters.settings);

const titles: Record<Page, [string, string]> = {
  dashboard: ["Dashboard", "Overview of secure communication and quantum security status."],
  chat: ["Secure Chat", "Hybrid encrypted messaging, voice notes, and file references."],
  vault: ["Quantum Vault", "Local-first encrypted files with signed metadata and hybrid grants."],
  keys: ["Key Management", "Identity keys, signed prekeys, one-time prekeys, and rotations."],
  devices: ["Device Trust Center", "QR approval, revocation, and trust posture per device."],
  verification: ["Security Verification", "Safety numbers, fingerprints, and QR verification."],
  audit: ["Message Audit Logs", "Tamper-evident local events and security export."],
  quantum: ["Quantum Security", "PQC status, HNDL protection, and key rotation history."],
  admin: ["Admin Security Console", "Organization member and device security posture."],
  subscription: ["Subscription", "Your plan, billing history, and activation across all your devices."],
  settings: ["Settings", "Security modes, alerts, retention, and advanced options."],
};

function ModuleFallback() {
  return (
    <div className="grid gap-4">
      <div className="grid grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((item) => <div key={item} className="h-36 animate-pulse rounded-lg border border-line bg-white" />)}
      </div>
      <div className="h-96 animate-pulse rounded-lg border border-line bg-white" />
    </div>
  );
}

function ProtectedMessagingApp() {
  const auth = useAuth();
  // Android app-entry PIN gate (banking-grade). appLock.status is null until
  // the first `applock_status` round-trip resolves; `android` is stable per
  // runtime so every desktop build takes none of the gate branches below.
  const android = isAndroidRuntime();
  const appLock = useAppLock(auth.user?.id ?? null);
  const [forcePasswordLogin, setForcePasswordLogin] = useState(false);
  const appVersion = (window as unknown as { __APP_VERSION__?: string }).__APP_VERSION__ ?? "0.0.0";
  const isMobile = useIsMobile();
  const [showMobileOnboarding, setShowMobileOnboarding] = useState(isMobileOnboardingPending);
  const { theme, toggleTheme } = useTheme();
  const { data, loading, error, refresh, liveEvents, liveStatus } = useDashboardData(auth.user, auth.session);
  const [page, setPage] = useState<Page>("dashboard");
  const lockState = useWorkspaceLock(auth.user?.id ?? null);
  // Account-based paywall: billing_subscriptions (realtime) decides whether the
  // premium app shell mounts at all. Purchases on ANY platform unlock here live.
  const subscriptionState = useSubscription(auth.user?.id ?? null);
  const [vaultRecoveryEnabled, setVaultRecoveryEnabled] = useState(false);
  const navigate = useCallback((next: Page) => setPage(next), []);
  // Total unread encrypted messages across visible conversations, surfaced as
  // notification bubbles on the sidebar chat entry and the top-bar bell.
  const unreadMessages = useMemo(
    () => data.conversations
      .filter((conversation) => !conversation.hidden_at && !conversation.deleted_at)
      .reduce((sum, conversation) => sum + conversation.unread_count, 0),
    [data.conversations],
  );

  // The Subscription page is a client-side module every account has (it must
  // stay reachable to manage/cancel/restore) — appended to the DB-driven list.
  const navModules = useMemo(() => {
    if (data.modules.length === 0) return data.modules;
    return [
      ...data.modules,
      { module_id: "subscription" as Page, label: "Subscription", icon: "subscription", route: "subscription" as Page, enabled: true, sort_order: 98 },
    ];
  }, [data.modules]);

  useEffect(() => {
    if (navModules.length === 0) return;
    if (!navModules.some((module) => module.route === page)) {
      setPage(navModules[0].route);
    }
  }, [navModules, page]);

  // Idle-time prefetch of route chunks so the first switch to each module is
  // instant. Only downloads/parses chunks — protected modules still don't mount
  // until unlocked.
  useEffect(() => {
    const win = window as Window & {
      requestIdleCallback?: (cb: () => void) => number;
      cancelIdleCallback?: (handle: number) => void;
    };
    const schedule = win.requestIdleCallback ?? ((cb: () => void) => window.setTimeout(cb, 200));
    const handle = schedule(() => {
      Object.values(pageImporters).forEach((load) => {
        void load();
      });
    });
    return () => {
      (win.cancelIdleCallback ?? window.clearTimeout)(handle as number);
    };
  }, []);

  // Whether vault recovery is configured (for the lock-gate telemetry chip).
  useEffect(() => {
    if (page !== "vault") return;
    let active = true;
    void safeInvoke<{ enabled: boolean }>("vault_recovery_status", undefined, { enabled: false }).then((statusValue) => {
      if (active) setVaultRecoveryEnabled(Boolean(statusValue.enabled));
    });
    return () => {
      active = false;
    };
  }, [page, lockState.status?.vault.unlocked]);

  const tourSteps = useMemo(() => buildTourSteps(data.modules), [data.modules]);
  const tourChecklist = useMemo(
    () => (auth.user ? buildChecklist(data, auth.user.id) : []),
    [data, auth.user],
  );
  const onboardingReady = Boolean(auth.user && auth.session) && !loading && !error && data.modules.length > 0;
  const onboarding = useOnboarding(auth.user?.id ?? null, tourSteps.length, onboardingReady);

  if (auth.loading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-canvas">
        <div className="h-24 w-80 animate-pulse rounded-lg border border-line bg-white" />
      </div>
    );
  }

  // ---- Android app-entry PIN gate (banking-grade) ----
  if (android && !appLock.loading && appLock.status?.configured && appLock.status.locked && !forcePasswordLogin) {
    // No live session yet (cold launch) -> unlocking restores it; else the app
    // is merely re-locked (background/inactivity) and unlock just clears the flag.
    const restoreFromUnlock = async (pin: string) => {
      const result = await appLock.unlock(pin);
      // 5th wrong attempt wiped the store -> fall back to full auth.
      if (result.status.requiresFullAuth || !result.session) {
        setForcePasswordLogin(true);
        await appLock.refresh();
        return;
      }
      if (!auth.user || !auth.session) {
        const { error } = await supabase.auth.setSession({
          access_token: result.session.accessToken,
          refresh_token: result.session.refreshToken,
        });
        if (error) {
          // Refresh token expired -> fall back to full auth, keep existing PIN.
          setForcePasswordLogin(true);
          throw new Error("Your session expired. Please sign in with your password.");
        }
      }
      // Check remote revocation (Settings -> Security -> Revoke) even on cold
      // launch, when the just-restored session hasn't yet propagated back into
      // `auth.user` (the setSession above updates auth state asynchronously via
      // onAuthStateChange) -- gate on the decrypted appLock device instead of
      // `auth.user` so a stolen-then-revoked device is blocked immediately
      // rather than only on its *next* unlock.
      if (appLock.status?.device) {
        const revoked = await isDeviceRevoked(supabase, result.session.userId, appLock.status.device.deviceId).catch(() => false);
        if (revoked) {
          // Revoked/stolen device: destroy the local session + stored PIN so this
          // device must pass full email/password (+ MFA) again, not a PIN reset.
          // scope:"local" clears only THIS device (never signs the user out elsewhere).
          await supabase.auth.signOut({ scope: "local" }).catch(() => undefined);
          await safeInvoke("applock_wipe", { userId: result.session.userId }, null);
          await appLock.refresh();
          setForcePasswordLogin(true);
          throw new Error("This device was signed out remotely. Please sign in again.");
        }
        await upsertTrustedDevice(supabase, result.session.userId, appLock.status.device).catch(() => undefined);
      }
    };
    return (
      <AppLockScreen
        mode="unlock"
        email={auth.user?.email ?? null}
        digits={appLock.status.digits}
        attemptsRemaining={appLock.status.attemptsRemaining}
        lockoutUntil={appLock.status.lockoutUntil}
        onSubmit={async (pin) => {
          await restoreFromUnlock(pin);
        }}
        onUsePassword={() => setForcePasswordLogin(true)}
      />
    );
  }

  if (!auth.user || !auth.session) {
    // First launch on a phone: branded splash + quantum-security tour before login.
    if (isMobile && showMobileOnboarding) {
      return <MobileOnboarding onDone={() => setShowMobileOnboarding(false)} />;
    }
    return (
      <LoginPage
        loading={auth.loading}
        error={auth.error}
        notice={auth.notice}
        pendingMfa={auth.pendingMfa}
        onSignIn={auth.signIn}
        onVerifyMfa={auth.verifyMfaSignIn}
        onCancelMfa={auth.cancelMfaSignIn}
        onSignUp={auth.signUp}
        onResendVerification={auth.resendVerification}
        onResetPassword={auth.resetPassword}
        onClearError={auth.clearError}
      />
    );
  }

  // First login on Android with no PIN yet -> force PIN creation before the app.
  if (android && !appLock.loading && auth.user && auth.session && !appLock.status?.configured) {
    const stored = auth.currentStoredSession();
    return (
      <AppLockScreen
        mode="setup"
        email={auth.user.email ?? null}
        onSubmit={async (pin, digits) => {
          if (!stored) throw new Error("No active session to secure.");
          const status = await appLock.setup(digits, pin, stored, "Android Device", appVersion);
          if (status.device && auth.user) {
            await upsertTrustedDevice(supabase, auth.user.id, status.device).catch(() => undefined);
          }
          setForcePasswordLogin(false);
        }}
      />
    );
  }

  // Forced-password re-login (5 wrong PIN attempts, or user chose "use
  // password") re-authenticated the account -> re-confirm the existing PIN so
  // it can re-wrap the freshly restored session, instead of silently trusting
  // a stale local PIN against a session it never wrapped.
  if (android && forcePasswordLogin && auth.user && auth.session && appLock.status?.configured) {
    const stored = auth.currentStoredSession();
    return (
      <AppLockScreen
        mode="setup"
        email={auth.user.email ?? null}
        digits={appLock.status.digits}
        onSubmit={async (pin, digits) => {
          if (!stored) throw new Error("No active session to secure.");
          await appLock.reset(digits, pin, stored, appLock.status?.device?.deviceName ?? "Android Device", appVersion);
          setForcePasswordLogin(false);
        }}
      />
    );
  }

  // ---- Subscription paywall (Qguard_Wiki/Android_Paywall_Guidelines) ----
  // Neutral splash while the entitlement check runs, so the app never flashes
  // unlocked-then-locked (or vice versa) at startup.
  if (subscriptionState.loading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-canvas">
        <div className="h-24 w-80 animate-pulse rounded-lg border border-line bg-white" />
      </div>
    );
  }
  // Without an access-granting subscription the premium shell NEVER mounts —
  // only Subscription (pricing/purchase/restore) and Settings stay reachable.
  // The database enforces the same rule independently (migration 030), and the
  // realtime billing stream swaps this gate out the moment a verified payment
  // (PayPal or Google Play, on any device) activates the account.
  if (!subscriptionState.access) {
    return (
      <PaywallGate
        expired={Boolean(subscriptionState.subscription)}
        onSignOut={auth.signOut}
        subscriptionPage={
          <Suspense fallback={<ModuleFallback />}>
            <SubscriptionPage
              userId={auth.user.id}
              email={auth.user.email ?? null}
              accessToken={auth.session.access_token ?? null}
              state={subscriptionState}
              mode="paywall"
            />
          </Suspense>
        }
        settingsPage={
          <Suspense fallback={<ModuleFallback />}>
            <SettingsPage theme={theme} onToggleTheme={toggleTheme} profile={data.profile} telemetry={data.telemetry} securityEvents={data.securityEvents} liveEvents={liveEvents} liveStatus={liveStatus} onRefresh={refresh} inactivityMinutes={lockState.inactivityMinutes} onSetInactivityMinutes={lockState.setInactivityMinutes} workspaceStatus={lockState.status} onLockWorkspaces={lockState.lockAll} appLock={appLock} />
          </Suspense>
        }
      />
    );
  }

  const [title, subtitle] = titles[page];

  let content;
  if (loading) {
    content = (
      <div className="grid gap-4">
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((item) => <div key={item} className="h-36 animate-pulse rounded-lg border border-line bg-white" />)}
        </div>
        <div className="h-96 animate-pulse rounded-lg border border-line bg-white" />
      </div>
    );
  } else if (error) {
    content = (
      <div className="shell-card border-rose-100 bg-rose-50 p-6">
        <div className="text-sm font-bold text-rose-600">Could not open workspace</div>
        <div className="mt-2 text-sm text-rose-600">{error}</div>
        <button onClick={refresh} className="mt-4 rounded-lg bg-rose-500 px-4 py-2 text-sm font-bold text-white">
          Retry
        </button>
      </div>
    );
  } else {
    // Zero-Trust Workspace Lock: Secure Chat and Quantum Vault require their own
    // password/PIN before the module mounts. While locked, render the gate; the
    // heavy page component only mounts once the scope is unlocked.
    // Verify the account password WITHOUT touching the live session (ephemeral
    // client, persistSession: false) — the identity proof that gates a lossless
    // chat reset and the destructive "start fresh" vault reset.
    const verifyAccountPassword = async (password: string): Promise<void> => {
      const email = auth.user?.email;
      if (!email) throw new Error("No account email is on file for this session.");
      const ephemeral = createEphemeralSupabaseClient();
      const { error: authError } = await ephemeral.auth.signInWithPassword({ email, password });
      await ephemeral.auth.signOut().catch(() => undefined);
      if (authError) throw new Error("That account password is incorrect.");
    };

    const renderProtected = (scope: WorkspaceScope, pageElement: ReactNode): ReactNode => {
      const scopeStatus = lockState.status?.[scope];
      if (!scopeStatus) return <ModuleFallback />;
      if (!scopeStatus.unlocked) {
        return (
          <WorkspaceLockGate
            scope={scope}
            status={scopeStatus}
            recoveryEnabled={scope === "vault" ? vaultRecoveryEnabled : undefined}
            inactivityMinutes={lockState.inactivityMinutes}
            onUnlock={(method, secret) => lockState.unlock(scope, method, secret)}
            onSetup={(method, secret) => lockState.setup(scope, method, secret)}
            onCancel={() => setPage("dashboard")}
            onRecoverChat={
              scope === "chat"
                ? async (accountPassword: string) => {
                    await verifyAccountPassword(accountPassword);
                    await lockState.resetChatLock();
                  }
                : undefined
            }
            onRecoverVaultWithKey={
              scope === "vault"
                ? (recoveryKey: string, method: UnlockMethod, secret: string) =>
                    lockState.resetVault({ recoveryKey, method, secret })
                : undefined
            }
            onRecoverVaultWithAccount={
              scope === "vault"
                ? async (accountPassword: string, method: UnlockMethod, secret: string) => {
                    await verifyAccountPassword(accountPassword);
                    await lockState.resetVault({ method, secret });
                  }
                : undefined
            }
          />
        );
      }
      return pageElement;
    };

    switch (page) {
      case "dashboard":
        content = <DashboardPage data={data} liveEvents={liveEvents} liveStatus={liveStatus} onNavigate={(next) => navigate(next as Page)} />;
        break;
      case "chat":
        content = renderProtected(
          "chat",
          <SecureChatPage userId={auth.user.id} conversations={data.conversations} devices={data.devices} contacts={data.contacts} onSent={refresh} />,
        );
        break;
      case "vault":
        content = renderProtected("vault", <QuantumVaultPage userId={auth.user.id} telemetry={data.telemetry} />);
        break;
      case "keys":
        content = <KeyManagementPage userId={auth.user.id} devices={data.devices} keyInventory={data.keyInventory} telemetry={data.telemetry} securityEvents={data.securityEvents} liveEvents={liveEvents} liveStatus={liveStatus} onRefresh={refresh} />;
        break;
      case "devices":
        content = <DeviceTrustCenterPage userId={auth.user.id} devices={data.devices} telemetry={data.telemetry} securityEvents={data.securityEvents} onRefresh={refresh} />;
        break;
      case "verification":
        content = <SecurityVerificationPage userId={auth.user.id} devices={data.devices} telemetry={data.telemetry} securityEvents={data.securityEvents} liveEvents={liveEvents} liveStatus={liveStatus} onRefresh={refresh} />;
        break;
      case "audit":
        content = <AuditLogsPage userId={auth.user.id} events={data.telemetry} securityEvents={data.securityEvents} liveEvents={liveEvents} liveStatus={liveStatus} onRefresh={refresh} />;
        break;
      case "quantum":
        content = <QuantumSecurityDashboardPage userId={auth.user.id} data={data} liveEvents={liveEvents} liveStatus={liveStatus} onRefresh={refresh} />;
        break;
      case "subscription":
        content = <SubscriptionPage userId={auth.user.id} email={auth.user.email ?? null} accessToken={auth.session.access_token ?? null} state={subscriptionState} mode="manage" />;
        break;
      case "settings":
        content = <SettingsPage theme={theme} onToggleTheme={toggleTheme} profile={data.profile} telemetry={data.telemetry} securityEvents={data.securityEvents} liveEvents={liveEvents} liveStatus={liveStatus} onRefresh={refresh} inactivityMinutes={lockState.inactivityMinutes} onSetInactivityMinutes={lockState.setInactivityMinutes} workspaceStatus={lockState.status} onLockWorkspaces={lockState.lockAll} appLock={appLock} verifyAccountPassword={verifyAccountPassword} />;
        break;
      default:
        content = <DashboardPage data={data} liveEvents={liveEvents} liveStatus={liveStatus} onNavigate={(next) => navigate(next as Page)} />;
        break;
    }
  }

  const moduleContent = (
    <ErrorBoundary resetKey={page}>
      <Suspense fallback={<ModuleFallback />}>{content}</Suspense>
    </ErrorBoundary>
  );

  // Phone layout (Android build + narrow windows): compact header, floating
  // bottom navigation, and a module sheet replace the sidebar/top-bar chrome.
  if (isMobile) {
    return (
      <CallProvider userId={auth.user.id}>
        <UpdateBanner />
        <MobileShell
          activePage={page}
          title={title}
          modules={navModules}
          unreadMessages={unreadMessages}
          liveStatus={liveStatus}
          theme={theme}
          onToggleTheme={toggleTheme}
          onNavigate={navigate}
          onSignOut={auth.signOut}
        >
          {moduleContent}
        </MobileShell>
      </CallProvider>
    );
  }

  return (
    // CallProvider sits ABOVE the router and the workspace lock: incoming
    // quantum-encrypted calls ring on every page (dashboard, settings, locked
    // chat...), not just while Secure Chat happens to be mounted.
    <CallProvider userId={auth.user.id}>
      <UpdateBanner />
      <div className="flex h-screen w-screen overflow-hidden bg-canvas">
        <Sidebar activePage={page} modules={navModules} snapshot={data.snapshot} unreadMessages={unreadMessages} onNavigate={navigate} />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar
            title={title}
            subtitle={subtitle}
            user={auth.user}
            theme={theme}
            activePage={page}
            liveStatus={liveStatus}
            lastLiveEvent={liveEvents[0] ?? null}
            unreadMessages={unreadMessages}
            onOpenChat={() => navigate("chat")}
            onToggleTheme={toggleTheme}
            onSignOut={auth.signOut}
            onStartTour={onboarding.replay}
          />
          <main className="min-h-0 flex-1 overflow-y-auto p-5">
            {moduleContent}
          </main>
        </div>
        <OnboardingTour
          controller={onboarding}
          steps={tourSteps}
          checklist={tourChecklist}
          userName={String(auth.user.user_metadata?.full_name ?? auth.user.email ?? "")}
          onNavigate={navigate}
        />
      </div>
    </CallProvider>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ProtectedMessagingApp />
    </AuthProvider>
  );
}
