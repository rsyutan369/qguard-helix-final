import { useEffect, useState } from "react";
import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";
import { AuthProvider, useAuth } from "@/lib/auth-context";
import { useDashboardData } from "@/lib/use-dashboard-data";
import { useTheme } from "@/lib/use-theme";
import AuditLogsPage from "@/pages/AuditLogsPage";
import DashboardPage from "@/pages/DashboardPage";
import DeviceTrustCenterPage from "@/pages/DeviceTrustCenterPage";
import KeyManagementPage from "@/pages/KeyManagementPage";
import LoginPage from "@/pages/LoginPage";
import QuantumSecurityDashboardPage from "@/pages/QuantumSecurityDashboardPage";
import QuantumVaultPage from "@/pages/QuantumVaultPage";
import SecurityVerificationPage from "@/pages/SecurityVerificationPage";
import SecureChatPage from "@/pages/SecureChatPage";
import SettingsPage from "@/pages/SettingsPage";
import type { Page } from "@/lib/types";

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

function ProtectedMessagingApp() {
  const auth = useAuth();
  const { theme, toggleTheme } = useTheme();
  const { data, loading, error, refresh, liveEvents, liveStatus } = useDashboardData(auth.user, auth.session);
  const [page, setPage] = useState<Page>("dashboard");

  useEffect(() => {
    if (data.modules.length === 0) return;
    if (!data.modules.some((module) => module.route === page)) {
      setPage(data.modules[0].route);
    }
  }, [data.modules, page]);

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
    switch (page) {
      case "dashboard":
        content = <DashboardPage data={data} onNavigate={(next) => setPage(next as Page)} />;
        break;
      case "chat":
        content = <SecureChatPage userId={auth.user.id} conversations={data.conversations} devices={data.devices} contacts={data.contacts} onSent={refresh} />;
        break;
      case "vault":
        content = <QuantumVaultPage userId={auth.user.id} files={data.vaultFiles} telemetry={data.telemetry} onUploaded={refresh} />;
        break;
      case "keys":
        content = <KeyManagementPage devices={data.devices} keyInventory={data.keyInventory} securityEvents={data.securityEvents} onRefresh={refresh} />;
        break;
      case "devices":
        content = <DeviceTrustCenterPage userId={auth.user.id} devices={data.devices} telemetry={data.telemetry} securityEvents={data.securityEvents} onRefresh={refresh} />;
        break;
      case "verification":
        content = <SecurityVerificationPage devices={data.devices} />;
        break;
      case "audit":
        content = <AuditLogsPage events={data.telemetry} securityEvents={data.securityEvents} liveEvents={liveEvents} />;
        break;
      case "quantum":
        content = <QuantumSecurityDashboardPage report={data.report} hardening={data.hardening} />;
        break;
      case "settings":
        content = <SettingsPage theme={theme} onToggleTheme={toggleTheme} profile={data.profile} onRefresh={refresh} />;
        break;
      default:
        content = <DashboardPage data={data} onNavigate={(next) => setPage(next as Page)} />;
        break;
    }
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-canvas">
      <Sidebar activePage={page} modules={data.modules} snapshot={data.snapshot} onNavigate={setPage} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          title={title}
          subtitle={subtitle}
          user={auth.user}
          theme={theme}
          liveStatus={liveStatus}
          lastLiveEvent={liveEvents[0] ?? null}
          onToggleTheme={toggleTheme}
          onSignOut={auth.signOut}
        />
        <main className="min-h-0 flex-1 overflow-y-auto p-5">{content}</main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ProtectedMessagingApp />
    </AuthProvider>
  );
}
