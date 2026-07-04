import { lazy, Suspense, useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";
import OnboardingTour from "@/components/onboarding/OnboardingTour";
import { CallProvider } from "@/components/call/CallProvider";
import { UpdateBanner } from "@/components/UpdateBanner";
import { WorkspaceLockGate } from "@/components/workspace/WorkspaceLockGate";
import { AuthProvider, useAuth } from "@/lib/auth-context";
import { buildChecklist, buildTourSteps, useOnboarding } from "@/lib/onboarding";
import { useDashboardData } from "@/lib/use-dashboard-data";
import { useWorkspaceLock, type WorkspaceScope } from "@/lib/use-workspace-lock";
import { safeInvoke } from "@/lib/tauri";
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
  const { theme, toggleTheme } = useTheme();
  const { data, loading, error, refresh, liveEvents, liveStatus } = useDashboardData(auth.user, auth.session);
  const [page, setPage] = useState<Page>("dashboard");
  const lockState = useWorkspaceLock(auth.user?.id ?? null);
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

  useEffect(() => {
    if (data.modules.length === 0) return;
    if (!data.modules.some((module) => module.route === page)) {
      setPage(data.modules[0].route);
    }
  }, [data.modules, page]);

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

  if (!auth.user || !auth.session) {
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
        onClearError={auth.clearError}
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
      case "settings":
        content = <SettingsPage theme={theme} onToggleTheme={toggleTheme} profile={data.profile} telemetry={data.telemetry} securityEvents={data.securityEvents} liveEvents={liveEvents} liveStatus={liveStatus} onRefresh={refresh} inactivityMinutes={lockState.inactivityMinutes} onSetInactivityMinutes={lockState.setInactivityMinutes} workspaceStatus={lockState.status} onLockWorkspaces={lockState.lockAll} />;
        break;
      default:
        content = <DashboardPage data={data} liveEvents={liveEvents} liveStatus={liveStatus} onNavigate={(next) => navigate(next as Page)} />;
        break;
    }
  }

  return (
    // CallProvider sits ABOVE the router and the workspace lock: incoming
    // quantum-encrypted calls ring on every page (dashboard, settings, locked
    // chat...), not just while Secure Chat happens to be mounted.
    <CallProvider userId={auth.user.id}>
      <UpdateBanner />
      <div className="flex h-screen w-screen overflow-hidden bg-canvas">
        <Sidebar activePage={page} modules={data.modules} snapshot={data.snapshot} unreadMessages={unreadMessages} onNavigate={navigate} />
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
            <Suspense fallback={<ModuleFallback />}>{content}</Suspense>
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
