import { lazy, Suspense, useCallback, useEffect, useMemo, useState, type ComponentProps, type ReactNode } from "react";
import { ArrowLeftRight, CircleCheck, FileDown, X } from "lucide-react";
import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";
import OnboardingTour from "@/components/onboarding/OnboardingTour";
import MobileShell from "@/components/mobile/MobileShell";
import MobileOnboarding, { isMobileOnboardingPending } from "@/components/mobile/MobileOnboarding";
import { CallProvider } from "@/components/call/CallProvider";
import { PaywallGate } from "@/components/PaywallGate";
import { UpdateBanner } from "@/components/UpdateBanner";
import { RelayHealthBanner } from "@/components/RelayHealthBanner";
import { OutboxCourier } from "@/components/OutboxCourier";
import { ConnectivityIndicator } from "@/components/ConnectivityIndicator";
import { OfflinePairingHost } from "@/components/offline/OfflinePairingHost";
import { DeviceKeyRecoveryScreen } from "@/components/auth/DeviceKeyRecoveryScreen";
import { WorkspaceLockGate } from "@/components/workspace/WorkspaceLockGate";
import { AppLockScreen } from "@/components/applock/AppLockScreen";
import SecuritySetupPage from "@/components/applock/SecuritySetupPage";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AuthProvider, isTransientAuthError, useAuth } from "@/lib/auth-context";
import { useSubscription } from "@/lib/use-subscription";
import { hasMessagingAccess, OFFLINE_GRACE_MS, type MessagingSubscription } from "@/lib/subscription";
import { OfflineModeShell, OfflineNoticeStack, isOfflineRoute, type OfflineRoute } from "@/components/offline/OfflineModeShell";
import { useIsMobile } from "@/lib/use-mobile";
import { useAppLock, type AppLockUnlockResult } from "@/lib/use-app-lock";
import { settlePinRestore, type PinRestorePhase } from "@/lib/pin-restore";
import { upsertTrustedDevice, isDeviceRevoked } from "@/lib/trusted-devices";
import { buildChecklist, buildTourSteps, useOnboarding } from "@/lib/onboarding";
import { useDashboardData } from "@/lib/use-dashboard-data";
import { useWorkspaceLock, type UnlockMethod, type WorkspaceScope } from "@/lib/use-workspace-lock";
import { supabase } from "@/lib/supabase";
import { accountIdentifierLabel, accountProofKind, sendAccountProofCode, verifyAccountProof } from "@/lib/account-identity";
import { finishPendingLinkCompletion, hasPendingLinkCompletion } from "@/lib/device-link";
import { ensureMessagingWorkspace, syncCurrentMessagingDevice } from "@/lib/messaging-bootstrap";
import { isAndroidRuntime, isTauriRuntime, safeInvoke } from "@/lib/tauri";
import { APP_VERSION } from "@/lib/app-update";
import { useTheme } from "@/lib/use-theme";
import { useAvatarUrl } from "@/lib/avatars";
import { useOfflineAvatarSync } from "@/lib/offline-avatars";
import type { OfflineMode } from "@/lib/offline";
import { useOfflineTransferMonitor, type TransferNotice } from "@/lib/use-offline-transfer-monitor";
import { useOfflineMeshMonitor } from "@/lib/use-offline-mesh-monitor";
import type { MeshNotice as MeshNoticeData } from "@/lib/offline";
import { MeshNotice } from "@/components/offline/MeshNotice";
import LoginPage from "@/pages/LoginPage";
import type { MessagingModule, Page } from "@/lib/types";
import type { CallMedia } from "@/lib/call-types";
import { useMissedCallCount } from "@/lib/use-missed-calls";
import { useIncomingShares } from "@/lib/use-incoming-shares";
import { requestVaultSection } from "@/lib/vault-nav";
import NotificationStack from "@/components/NotificationStack";
import { ChatPreferencesProvider } from "@/lib/chat-preferences-context";
import { requestOpenConversation } from "@/lib/chat-focus";
import type { RelayAvailability } from "@/lib/relay-health";

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
  // Prefetched for every account like the rest, so loading it says nothing.
  hidden: () => import("@/components/vault/hidden/HiddenVaultPage"),
  verification: () => import("@/pages/SecurityVerificationPage"),
  chat: () => import("@/pages/SecureChatPage"),
  calls: () => import("@/pages/CallsPage"),
  offline: () => import("@/pages/OfflinePage"),
  subscription: () => import("@/pages/SubscriptionPage"),
  settings: () => import("@/pages/SettingsPage"),
};

const AuditLogsPage = lazy(pageImporters.audit);
const DashboardPage = lazy(pageImporters.dashboard);
const DeviceTrustCenterPage = lazy(pageImporters.devices);
const KeyManagementPage = lazy(pageImporters.keys);
const QuantumSecurityDashboardPage = lazy(pageImporters.quantum);
const QuantumVaultPage = lazy(pageImporters.vault);
const HiddenVaultPage = lazy(pageImporters.hidden);
const SecurityVerificationPage = lazy(pageImporters.verification);
const SecureChatPage = lazy(pageImporters.chat);
const CallsPage = lazy(pageImporters.calls);
const OfflinePage = lazy(pageImporters.offline);
const SubscriptionPage = lazy(pageImporters.subscription);
const SettingsPage = lazy(pageImporters.settings);

const titles: Record<Page, [string, string]> = {
  dashboard: ["Dashboard", "Overview of secure communication and quantum security status."],
  chat: ["Secure Chat", "Hybrid encrypted messaging, voice notes, and file references."],
  calls: ["Calls", "Quantum-encrypted voice and video calls, with recent and missed calls."],
  vault: ["Quantum Vault", "Local-first encrypted files with signed metadata and hybrid grants."],
  mesh: ["Qguard Mesh", "Private messages between trusted devices on your local network."],
  xfer: ["Qguard XFER", "Send and receive verified files over a local connection."],
  "transfer-history": ["Transfer History", "Review completed transfers and recover interrupted ones."],
  "offline-settings": ["Offline Settings", "Manage local discovery and verify nearby devices."],
  keys: ["Key Management", "Identity keys, signed prekeys, one-time prekeys, and rotations."],
  devices: ["Device Trust Center", "QR approval, revocation, and trust posture per device."],
  verification: ["Security Verification", "Safety numbers, fingerprints, and QR verification."],
  audit: ["Message Audit Logs", "Tamper-evident local events and security export."],
  quantum: ["Quantum Security", "PQC status, HNDL protection, and key rotation history."],
  admin: ["Admin Security Console", "Organization member and device security posture."],
  subscription: ["Subscription", "Your plan, billing history, and activation across all your devices."],
  settings: ["Settings", "Security modes, alerts, retention, and advanced options."],
};

const offlineModules: MessagingModule[] = (["mesh", "xfer", "transfer-history", "offline-settings"] as const)
  .map((route, index) => ({ module_id: route, route, label: titles[route][0], icon: route, enabled: true, sort_order: 90 + index }));

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

function XferNotice({ notice, more, onOpen, onDismiss }: {
  notice: TransferNotice;
  more: number;
  onOpen: () => void;
  onDismiss: () => void;
}) {
  const verified = notice.status === "verified";
  const offer = notice.status === "awaitingConsent";
  const Icon = verified ? CircleCheck : offer ? FileDown : ArrowLeftRight;
  const title = verified ? "File transfer verified" : offer ? "Incoming XFER offer" : "XFER in progress";
  const detail = verified
    ? notice.direction === "incoming" ? "Qguard verified the received files." : "The receiving device confirmed file integrity."
    : offer ? "Review the offer before accepting any files." : "Follow verified progress on the transfer dashboard.";
  const action = verified ? "View receipt" : offer ? "Review offer" : "View progress";
  return (
    <div className="shell-card p-3 shadow-soft">
      <div className="flex items-start gap-3">
        <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl text-white ${verified ? "bg-emerald-700" : "bg-violet-700"}`}>
          <Icon size={19} aria-hidden />
        </span>
        <div className="min-w-0 flex-1" role="status">
          <p className="text-sm font-bold text-ink-950">{title}</p>
          <p className="mt-1 text-xs text-ink-600">{detail}</p>
          {more > 0 && <p className="mt-1 text-xs text-ink-600">{more} more XFER {more === 1 ? "update" : "updates"}</p>}
        </div>
        <button type="button" onClick={onDismiss} aria-label="Dismiss XFER notice"
          className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl text-ink-600 hover:bg-canvas focus-visible:outline focus-visible:outline-2 focus-visible:outline-violet-500">
          <X size={17} aria-hidden />
        </button>
      </div>
      <div className="mt-2 flex justify-end">
        <button type="button" onClick={onOpen} className="min-h-11 rounded-xl bg-violet-700 px-4 text-xs font-bold text-white hover:bg-violet-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-violet-500">{action}</button>
      </div>
    </div>
  );
}


function AccountXferPage({ avatarUserId, localIdentity, ...props }: ComponentProps<typeof OfflinePage> & {
  avatarUserId: string | null;
}) {
  const avatarUrl = useAvatarUrl(avatarUserId);
  return <OfflinePage {...props} localIdentity={{ ...localIdentity, avatarUrl }} />;
}

function ProtectedMessagingApp() {
  const auth = useAuth();
  const accountId = auth.user?.id;
  // Offline mode (no internet): only Mesh, XFER and local records run. Every
  // online service keeps its own user gate, so it stays idle until online.
  const offline = auth.offline;
  const onlineUser = offline ? null : auth.user;
  const onlineUserId = onlineUser?.id ?? null;
  const [relayObservation, setRelayObservation] = useState<{ accountId: string; value: RelayAvailability } | null>(null);
  const [outboxObservation, setOutboxObservation] = useState<{ accountId: string; count: number } | null>(null);
  const relay = relayObservation?.accountId === accountId ? relayObservation?.value ?? "unknown" : "unknown";
  const outboxCount = outboxObservation?.accountId === accountId ? outboxObservation?.count ?? 0 : 0;
  const onRelayAvailability = useCallback((value: RelayAvailability) => {
    if (accountId) setRelayObservation((previous) => previous?.accountId === accountId && previous.value === value ? previous : { accountId, value });
  }, [accountId]);
  const onQueueCount = useCallback((count: number) => {
    if (accountId) setOutboxObservation((previous) => previous?.accountId === accountId && previous.count === count ? previous : { accountId, count });
  }, [accountId]);
  const accessToken = auth.session?.access_token;
  // Android app-entry PIN gate (banking-grade). appLock.status is null until
  // the first `applock_status` round-trip resolves; `android` is stable per
  // runtime so every desktop build takes none of the gate branches below.
  const android = isAndroidRuntime();
  const appLock = useAppLock(auth.user?.id ?? null);
  const [forcePasswordLogin, setForcePasswordLogin] = useState(false);
  // The Security Setup page stays up until its last step (biometric) is done,
  // even though the lock is already configured once the PIN/pattern is saved.
  const [securitySetupActive, setSecuritySetupActive] = useState(false);
  // Keeps the PIN gate up through a cold-launch session restore (see pin-restore.ts).
  const [pinRestore, setPinRestore] = useState<PinRestorePhase>("idle");
  // The build-time constant (vite define), not a window global: the window
  // lookup always missed, so every Android device was registered as "0.0.0".
  const appVersion = APP_VERSION;
  const isMobile = useIsMobile();
  const [showMobileOnboarding, setShowMobileOnboarding] = useState(isMobileOnboardingPending);
  const { theme, toggleTheme } = useTheme();
  const { data, loading, error, refresh, liveEvents, liveStatus } = useDashboardData(onlineUser, auth.session);
  const [page, setPage] = useState<Page>("dashboard");
  const [pairedTarget, setPairedTarget] = useState<{ accountId: string; mode: OfflineMode; peer: string; intent?: "send" | "receive" } | null>(null);
  const [transferTarget, setTransferTarget] = useState<{ accountId: string; id: string; returnPage?: Page } | null>(null);
  const [focusedTransfer, setFocusedTransfer] = useState<{ accountId: string; id: string } | null>(null);
  // A Mesh message a notice asked to open, or a sender to reply to.
  const [meshTarget, setMeshTarget] = useState<{ accountId: string; id: string; sender: string; reply: boolean } | null>(null);
  useEffect(() => {
    setTransferTarget((current) => current?.accountId === accountId ? current : null);
    setFocusedTransfer((current) => current?.accountId === accountId ? current : null);
  }, [accountId]);
  const lockState = useWorkspaceLock(onlineUserId);
  // Account-based paywall: billing_subscriptions (realtime) decides whether the
  // premium app shell mounts at all. Purchases on ANY platform unlock here live.
  const subscriptionState = useSubscription(onlineUserId);
  // Offline, the verdict comes from the subscription row this device last saw
  // online (kept sealed with the offline enrollment). UI gate only, as online.
  const offlineSubscription = useMemo(() => {
    const row = offline?.entitlement;
    return row && row.user_id === offline.userId ? row as unknown as MessagingSubscription : null;
  }, [offline]);
  const offlineEntitled = offline !== null && hasMessagingAccess(offlineSubscription, Date.now(), OFFLINE_GRACE_MS);
  // Online: verify the account for offline use, then keep the plan verdict so
  // Mesh and XFER open after a restart without internet.
  const onlineSubscription = !onlineUserId || subscriptionState.loading || subscriptionState.error
    ? undefined : subscriptionState.subscription;
  useEffect(() => {
    if (!onlineUserId || !accessToken || auth.loading || relay !== "available" || !isTauriRuntime()) return undefined;
    let cancelled = false;
    void (async () => {
      try {
        await safeInvoke("offline_verify_principal");
      } catch {
        return;
      }
      if (cancelled || onlineSubscription === undefined) return;
      await safeInvoke("offline_store_entitlement", { expectedAccount: onlineUserId, subscription: onlineSubscription })
        .catch(() => undefined);
    })();
    return () => {
      cancelled = true;
    };
  }, [onlineUserId, accessToken, auth.loading, relay, onlineSubscription]);
  const [vaultRecoveryEnabled, setVaultRecoveryEnabled] = useState(false);
  // Secure Chat opens on its Contacts tab only when the dashboard's Contacts
  // card asked for it; any other way in starts on the chat list.
  const [chatOpensContacts, setChatOpensContacts] = useState(false);
  // A chat (and optionally a call) the Calls page asked Secure Chat to open.
  const [chatIntent, setChatIntent] = useState<{ key: string; peerUserId: string; media: CallMedia | null } | null>(null);
  const navigate = useCallback((next: Page) => {
    setChatOpensContacts(false);
    setChatIntent(null);
    setPairedTarget(null);
    setTransferTarget(null);
    setFocusedTransfer(null);
    setMeshTarget(null);
    setPage(next);
  }, []);
  const currentTransferTarget = transferTarget?.accountId === accountId ? transferTarget : null;
  const focusedTransferId = page === "xfer" && focusedTransfer?.accountId === accountId ? focusedTransfer?.id ?? null : null;
  const openTransfer = useCallback((id: string) => {
    if (!accountId || (page === "xfer" && focusedTransferId === id)) return;
    if (page !== "xfer") navigate("xfer");
    setTransferTarget({ accountId, id, returnPage: page === "xfer" ? currentTransferTarget?.returnPage : page });
    setFocusedTransfer({ accountId, id });
  }, [accountId, currentTransferTarget?.returnPage, focusedTransferId, navigate, page]);
  const closeTransfer = useCallback(() => {
    if (currentTransferTarget?.returnPage) {
      navigate(currentTransferTarget.returnPage);
    } else {
      setTransferTarget(null);
      setFocusedTransfer(null);
    }
  }, [currentTransferTarget?.returnPage, navigate]);
  const onTransferFocus = useCallback((id: string | null) => {
    if (!accountId || page !== "xfer") return;
    setFocusedTransfer((current) => !id ? null
      : current?.accountId === accountId && current.id === id ? current : { accountId, id });
  }, [accountId, page]);
  const xferEntitled = offline
    ? offlineEntitled
    : !subscriptionState.loading && subscriptionState.access && subscriptionState.subscription?.user_id === accountId;
  const nativeXferEnabled = Boolean(isTauriRuntime() && accountId && (accessToken || offline) && !auth.loading
    && xferEntitled
    && (!android || (!appLock.loading && appLock.status?.configured && !appLock.status.locked
      && !appLock.status.requiresFullAuth && pinRestore === "idle" && !forcePasswordLogin && !securitySetupActive)));
  const transfers = useOfflineTransferMonitor({
    accountId,
    enabled: nativeXferEnabled,
    focusedId: focusedTransferId,
    onOpen: openTransfer,
  });
  const ownProfile = data.profile?.id === accountId ? data.profile : null;
  // The native core shares this name with a device only after both users
  // confirm a pairing code. It is a label, never an identifier.
  const offlineOwnerName = ownProfile?.name?.trim() || ownProfile?.username?.trim() || null;
  useEffect(() => {
    if (!nativeXferEnabled || !accountId || !offlineOwnerName) return;
    // The native side accepts the name only after the offline account check,
    // which runs in parallel. Retry for a bounded time until it is accepted.
    let cancelled = false;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const sync = async () => {
      try {
        await safeInvoke("offline_set_owner_name", { displayName: offlineOwnerName, expectedAccount: accountId });
      } catch {
        attempts += 1;
        if (!cancelled && attempts < 24) timer = setTimeout(() => void sync(), 5_000);
      }
    };
    void sync();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [accountId, nativeXferEnabled, offlineOwnerName]);
  // The picture trusted devices see in Mesh and XFER: a thumbnail of the
  // signed-in profile picture, exchanged on the authenticated channel.
  // Unknown (offline, or the profile still loading) leaves the stored one.
  const ownAvatarPath = !offline ? ownProfile?.avatar_storage_path : undefined;
  const ownAvatarUrl = useAvatarUrl(ownAvatarPath ? accountId : null);
  useOfflineAvatarSync({
    accountId,
    enabled: nativeXferEnabled && !offline,
    avatarUrl: !ownProfile || offline ? undefined : ownAvatarPath ? ownAvatarUrl ?? undefined : null,
  });
  const openPairedPeer = useCallback((mode: OfflineMode, peer: string, intent?: "send" | "receive") => {
    if (!accountId) return;
    navigate(mode);
    setPairedTarget({ accountId, mode, peer, intent });
  }, [accountId, navigate]);
  const meshMonitor = useOfflineMeshMonitor({ accountId, enabled: nativeXferEnabled });
  const markMeshRead = meshMonitor.markRead;
  // Offline mode has no relay: start automatic local discovery (when the user
  // turned it on), as the connectivity indicator does when the relay drops.
  useEffect(() => {
    if (!offline || !nativeXferEnabled || !accountId) return;
    void safeInvoke("offline_relay_state", { unavailable: true, expectedAccount: accountId }).catch(() => undefined);
  }, [accountId, nativeXferEnabled, offline]);
  const openMeshMessage = useCallback((notice: MeshNoticeData, reply: boolean) => {
    if (!accountId) return;
    void markMeshRead([notice]);
    navigate("mesh");
    setMeshTarget({ accountId, id: notice.id, sender: notice.sender, reply });
  }, [accountId, markMeshRead, navigate]);
  // Ordinary dashboard links (Recent chats, My devices…). "contacts" is a tab
  // of Secure Chat rather than a page of its own.
  const navigateFromDashboard = useCallback(
    (next: string) => {
      if (next === "contacts") {
        navigate("chat");
        setChatOpensContacts(true);
      } else {
        navigate(next as Page);
      }
    },
    [navigate],
  );
  // The dashboard's Secure Chat / Calls / Quantum Vault / Contacts cards ALWAYS
  // ask for the PIN, password or pattern: the area is locked first, so its lock
  // gate shows even if it was unlocked a moment ago. Calls and Contacts sit
  // behind the Secure Chat lock (who you talk to is conversation metadata).
  const openProtectedArea = useCallback(
    (area: "chat" | "calls" | "vault" | "contacts") => {
      void (async () => {
        await lockState.lock(area === "vault" ? "vault" : "chat").catch(() => undefined);
        navigateFromDashboard(area);
      })();
    },
    // `lock` is stable (useCallback with no dependencies).
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [navigateFromDashboard, lockState.lock],
  );
  const missedCalls = useMissedCallCount();
  // Files other people shared with this account, waiting for Accept / Decline:
  // the app-wide notice and the Quantum Vault badges (live via realtime).
  const incomingShares = useIncomingShares(onlineUserId);
  const sharedFilesWaiting = incomingShares.pending.length;
  // "View" opens Quantum Vault on Shared → Shared with me (behind the vault lock).
  const openSharedFiles = useCallback(() => {
    requestVaultSection("shared");
    navigate("vault");
  }, [navigate]);
  // A new-message alert's "Open": Secure Chat opens that conversation (behind its lock).
  const openConversationFromAlert = useCallback((conversationId: string) => {
    requestOpenConversation(conversationId);
    navigate("chat");
  }, [navigate]);
  // Total unread encrypted messages across visible conversations, surfaced as
  // notification bubbles on the sidebar chat entry and the top-bar bell.
  const unreadMessages = useMemo(
    () => data.conversations
      .filter((conversation) => !conversation.hidden_at && !conversation.deleted_at)
      .reduce((sum, conversation) => sum + conversation.unread_count, 0),
    [data.conversations],
  );

  // A device that signed in from a QR link reports back once its identity keys
  // are registered, so the approving device can verify the binding proof and
  // trust it. No-op on every other sign-in.
  const userForLink = auth.user;
  const tokenForLink = auth.session?.access_token ?? null;
  useEffect(() => {
    if (!userForLink || !tokenForLink || !hasPendingLinkCompletion()) return;
    void finishPendingLinkCompletion(userForLink.id, tokenForLink, async () => {
      await ensureMessagingWorkspace(supabase, userForLink);
      return syncCurrentMessagingDevice(supabase, userForLink.id);
    });
  }, [tokenForLink, userForLink]);

  // The Subscription page is a client-side module every account has (it must
  // stay reachable to manage/cancel/restore) — appended to the DB-driven list.
  const navModules = useMemo(() => {
    const localModules = isTauriRuntime()
      ? offlineModules.filter((module) => !data.modules.some((existing) => existing.route === module.route))
      : [];
    if (data.modules.length === 0) return localModules;
    return [
      // Calls sits right after Secure Chat, behind the same lock.
      ...data.modules.flatMap((module) => (module.route === "chat"
        ? [module, { module_id: "calls" as Page, label: "Calls", icon: "calls", route: "calls" as Page, enabled: true, sort_order: module.sort_order }]
        : [module])),
      ...localModules,
      { module_id: "subscription" as Page, label: "Subscription", icon: "subscription", route: "subscription" as Page, enabled: true, sort_order: 98 },
    ];
  }, [data.modules]);

  useEffect(() => {
    if (data.modules.length === 0) return;
    if (!navModules.some((module) => module.route === page)) {
      setPage(navModules[0].route);
    }
  }, [data.modules.length, navModules, page]);

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

  useEffect(() => {
    setPinRestore((phase) =>
      settlePinRestore(phase, { signedIn: Boolean(auth.user && (auth.session || auth.offline)), loading: auth.loading }),
    );
  }, [pinRestore, auth.user, auth.session, auth.offline, auth.loading]);

  // Offline mode opens on Mesh and keeps to the offline workspaces.
  useEffect(() => {
    if (offline && !isOfflineRoute(page)) navigate("mesh");
  }, [navigate, offline, page]);

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

  // Mesh, XFER, Transfer History and Offline Settings: the same encrypted local
  // workspace online and offline (no server is involved in either case).
  const renderOfflineWorkspace = (user: NonNullable<typeof auth.user>, route: OfflineRoute): ReactNode => {
    const mesh = route === "mesh" && meshTarget?.accountId === user.id ? meshTarget : null;
    // Reply opens the composer for the sender; Open shows the message itself.
    const paired = !mesh?.reply && pairedTarget?.accountId === user.id && pairedTarget.mode === route ? pairedTarget : null;
    const initialPeer = mesh?.reply ? mesh.sender : paired?.peer;
    // XFER: a receiver opens a "waiting for files" screen, not the composer.
    const initialIntent = route === "xfer" ? paired?.intent : undefined;
    const initialMessage = mesh && !mesh.reply ? { id: mesh.id, sender: mesh.sender } : undefined;
    const initialTransferId = route === "xfer" ? currentTransferTarget?.id : undefined;
    const accountName = user.user_metadata?.full_name;
    const localIdentity = route === "xfer" ? {
      displayName: ownProfile?.name?.trim() || ownProfile?.username?.trim() || (typeof accountName === "string" ? accountName.trim() : null),
      deviceName: android ? appLock.status?.device?.deviceName : null,
    } : undefined;
    const key = `${user.id}:${route}:${initialTransferId ?? initialMessage?.id ?? initialPeer ?? ""}:${initialIntent ?? ""}`;
    const common = { page: route, accountId: user.id, onNavigate: navigate, relay, initialPeer,
      vaultUnlocked: !offline && lockState.status?.vault.unlocked === true };
    const meshProps = { initialMessage, onMeshRead: markMeshRead };
    return route === "xfer"
      ? <AccountXferPage key={key} {...common} initialTransferId={initialTransferId} initialIntent={initialIntent} localIdentity={localIdentity}
          avatarUserId={!offline && nativeXferEnabled && ownProfile?.avatar_storage_path ? user.id : null}
          onTransferFocus={onTransferFocus} onCloseTransfer={initialTransferId ? closeTransfer : undefined} />
      : <OfflinePage key={key} {...common} {...meshProps} />;
  };
  const renderPairingHost = (userId: string): ReactNode =>
    isTauriRuntime() && <OfflinePairingHost key={userId} accountId={userId} onOpen={openPairedPeer} />;
  const renderOfflineNotices = (): ReactNode => {
    const [nextTransferNotice] = transfers.notices;
    const xferNotice = nextTransferNotice && (
      <XferNotice key={`${nextTransferNotice.id}:${nextTransferNotice.status}`} notice={nextTransferNotice} more={transfers.notices.length - 1}
        onOpen={() => transfers.open(nextTransferNotice)} onDismiss={() => transfers.dismiss(nextTransferNotice)} />
    );
    const [nextMeshNotice] = meshMonitor.notices;
    const meshNotice = nextMeshNotice && (
      <MeshNotice key={`mesh:${nextMeshNotice.sender}:${nextMeshNotice.id}`} notice={nextMeshNotice} more={meshMonitor.notices.length - 1}
        onOpen={() => openMeshMessage(nextMeshNotice, false)} onReply={() => openMeshMessage(nextMeshNotice, true)}
        onDismiss={() => void markMeshRead([nextMeshNotice])} />
    );
    return meshNotice || xferNotice ? <>{meshNotice}{xferNotice}</> : null;
  };

  // ---- The call engine mounts ABOVE every gate below ----
  //
  // `CallProvider` used to sit inside the returned app shell, BELOW the Android
  // PIN gate. `use-app-lock` locks the app the moment `visibilitystate` goes
  // hidden, so backgrounding the phone or letting the screen blank returned the
  // `AppLockScreen` early -- which unmounted the provider and with it the
  // `messaging_call_signals` subscription. An incoming call then had nowhere to
  // land: the phone stayed silent, the caller gave up, and the ring surfaced
  // only once the user unlocked, i.e. after the call was already dead.
  //
  // Everything gated (PIN screen, login, onboarding, workspace lock, router)
  // now renders INSIDE the provider, so one engine instance survives every
  // transition -- a call in progress is no longer torn down by a lock, and a
  // ring reaches a locked-but-running app. Call media renders above the lock;
  // message history stays behind it.
  const renderShell = (): ReactNode => {
    // During a PIN session restore the (busy) PIN gate below stays on screen
    // instead of swapping to this splash mid-unlock.
    if (auth.loading && pinRestore === "idle") {
      return (
        <div className="flex h-screen w-screen items-center justify-center bg-canvas">
          <div className="h-24 w-80 animate-pulse rounded-lg border border-line bg-white" />
        </div>
      );
    }

    // On Android, wait for the app-lock status to load before deciding what to
    // render, so a cold launch never briefly flashes the email/password login
    // before the PIN gate appears. (The PIN gate below restores the session.)
    if (android && appLock.loading) {
      return (
        <div className="flex h-screen w-screen items-center justify-center bg-canvas">
          <div className="h-24 w-80 animate-pulse rounded-lg border border-line bg-white" />
        </div>
      );
    }

    // ---- Android app-entry PIN gate (banking-grade) ----
    // Stays up through a cold-launch session restore (pinRestore) so the
    // LoginPage never flashes between "PIN accepted" and "auth.user ready".
    if (
      android &&
      !appLock.loading &&
      appLock.status?.configured &&
      (appLock.status.locked || pinRestore !== "idle") &&
      !forcePasswordLogin
    ) {
      // No live session yet (cold launch) -> unlocking restores it; else the app
      // is merely re-locked (background/inactivity) and unlock just clears the flag.
      const restoreFromUnlock = async (unlockWith: () => Promise<AppLockUnlockResult>) => {
        const coldLaunch = !auth.user || !auth.session;
        if (coldLaunch) setPinRestore("restoring");
        try {
          const restored = await unlockAndRestore(unlockWith, coldLaunch);
          setPinRestore(coldLaunch && restored ? "applied" : "idle");
        } catch (error) {
          setPinRestore("idle");
          throw error;
        }
      };
      // Resolves true once the session is live, false when full auth is required.
      const unlockAndRestore = async (unlockWith: () => Promise<AppLockUnlockResult>, coldLaunch: boolean): Promise<boolean> => {
        const result = await unlockWith();
        // The store was wiped (5th wrong attempt, or the duress PIN) -> fall
        // back to full auth, looking exactly like an expired session: the
        // WebView's own copy of the session goes too.
        if (result.status.requiresFullAuth || !result.session) {
          await supabase.auth.signOut({ scope: "local" }).catch(() => undefined);
          setForcePasswordLogin(true);
          await appLock.refresh();
          return false;
        }
        if (coldLaunch) {
          const { error } = await supabase.auth.setSession({
            access_token: result.session.accessToken,
            refresh_token: result.session.refreshToken,
          });
          if (error && isTransientAuthError(error)) {
            // No internet: the unlock still proves the account on this device,
            // so Mesh and XFER open offline. The session returns online by
            // itself once the network is back.
            try {
              await auth.resumeOfflineAfterUnlock(result.session);
              return true;
            } catch (offlineError) {
              // Keep the PIN, pattern and stored session: lock again so the
              // user can retry once the connection is back.
              await appLock.lock().catch(() => undefined);
              const reason = offlineError instanceof Error ? offlineError.message : String(offlineError);
              throw new Error(`No internet connection. ${reason}`);
            }
          }
          if (error) {
            // Refresh token expired -> fall back to full auth, keep existing PIN.
            setForcePasswordLogin(true);
            throw new Error("Your session expired. Please sign in again.");
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
        return true;
      };
      return (
        <AppLockScreen
          mode="unlock"
          email={accountIdentifierLabel(auth.user) || null}
          digits={appLock.status.digits}
          method={appLock.status.method}
          attemptsRemaining={appLock.status.attemptsRemaining}
          lockoutUntil={appLock.status.lockoutUntil}
          busy={pinRestore !== "idle"}
          busyLabel="Unlocking your secure session…"
          onSubmit={async (pin) => {
            await restoreFromUnlock(() => appLock.unlock(pin));
          }}
          onBiometric={appLock.status.biometricEnabled ? async () => {
            await restoreFromUnlock(() => appLock.unlockWithBiometric());
          } : undefined}
          onUsePassword={() => setForcePasswordLogin(true)}
        />
      );
    }

    if (auth.deviceKeyRecovery) {
      return <DeviceKeyRecoveryScreen recovery={auth.deviceKeyRecovery} onRetry={auth.retryDeviceKeys}
        onReset={auth.resetDeviceKeys} onSignOut={auth.cancelDeviceKeyRecovery} />;
    }

    // ---- Offline mode: signed in on this device without internet ----
    // Only the local, end-to-end encrypted workspaces run; online services
    // (Secure Chat, Calls, Quantum Vault, billing) stay idle until online.
    if (offline && auth.user) {
      const route = isOfflineRoute(page) ? page : "mesh";
      return (
        <OfflineModeShell
          session={offline}
          android={android}
          entitled={offlineEntitled}
          page={route}
          title={titles[route][0]}
          theme={theme}
          onToggleTheme={toggleTheme}
          onNavigate={navigate}
          onReconnect={auth.reconnectOnline}
          onSignInOnline={auth.exitOffline}
          onSignOut={auth.signOut}
          overlays={<>
            {offlineEntitled && renderPairingHost(auth.user.id)}
            {offlineEntitled && <OfflineNoticeStack>{renderOfflineNotices()}</OfflineNoticeStack>}
          </>}
        >
          <ErrorBoundary resetKey={route}>
            <Suspense fallback={<ModuleFallback />}>{offlineEntitled && renderOfflineWorkspace(auth.user, route)}</Suspense>
          </ErrorBoundary>
        </OfflineModeShell>
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
          pendingPhone={auth.pendingPhone}
          onSignIn={auth.signIn}
          onVerifyMfa={auth.verifyMfaSignIn}
          onCancelMfa={auth.cancelMfaSignIn}
          onSignUp={auth.signUp}
          onRequestPhoneCode={auth.requestPhoneCode}
          onVerifyPhoneCode={auth.verifyPhoneCode}
          onCancelPhone={auth.cancelPhoneSignIn}
          onLinkCredential={auth.signInWithLinkCredential}
          onResendVerification={auth.resendVerification}
          onResetPassword={auth.resetPassword}
          onClearError={auth.clearError}
        />
      );
    }

    // Security Setup (new installation, new device, or after signing in again
    // with the password): choose a PIN or a drawn pattern, plus fingerprint /
    // face as extra ways in, before the app opens. After a password re-login
    // (5 wrong attempts, or "use password") the lock is set again so it wraps
    // the freshly restored session instead of trusting a stale one.
    if (
      android && !appLock.loading && auth.user && auth.session
      && (!appLock.status?.configured || securitySetupActive || (forcePasswordLogin && appLock.status?.configured))
    ) {
      const stored = auth.currentStoredSession();
      const rebinding = Boolean(appLock.status?.configured) && forcePasswordLogin;
      return (
        <SecuritySetupPage
          email={accountIdentifierLabel(auth.user) || null}
          reconfirm={rebinding}
          onStart={() => setSecuritySetupActive(true)}
          onSetup={async (method, secret) => {
            if (!stored) throw new Error("No active session to secure.");
            const digits = method === "pin" ? 6 : 0;
            const deviceName = appLock.status?.device?.deviceName ?? "Android Device";
            const status = rebinding
              ? await appLock.reset(digits, secret, stored, deviceName, appVersion, method)
              : await appLock.setup(digits, secret, stored, deviceName, appVersion, method);
            if (status.device && auth.user) {
              await upsertTrustedDevice(supabase, auth.user.id, status.device).catch(() => undefined);
            }
          }}
          biometricStatus={appLock.biometricStatus}
          onEnableBiometric={appLock.enableBiometric}
          onDone={() => {
            setSecuritySetupActive(false);
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
    const localVault = page === "vault" && isTauriRuntime()
      && navModules.some((module) => module.route === "vault" && module.enabled);

    let content;
    if (isOfflineRoute(page)) {
      content = renderOfflineWorkspace(auth.user, page);
    } else if (loading && !localVault) {
      content = (
        <div className="grid gap-4">
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((item) => <div key={item} className="h-36 animate-pulse rounded-lg border border-line bg-white" />)}
          </div>
          <div className="h-96 animate-pulse rounded-lg border border-line bg-white" />
        </div>
      );
    } else if (error && !localVault) {
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
      // Prove account ownership WITHOUT touching the live session — the proof
      // that gates a lossless chat reset and the destructive "start fresh" vault
      // reset. Email accounts type their password; mobile-number accounts (no
      // password) type a fresh SMS code. See lib/account-identity.ts.
      const verifyAccountPassword = async (secret: string): Promise<void> => {
        if (!auth.user) throw new Error("Your session has ended. Sign in again.");
        await verifyAccountProof(auth.user, secret);
      };
      const accountProof = auth.user && accountProofKind(auth.user) === "sms"
        ? { kind: "sms" as const, sendCode: () => sendAccountProofCode(auth.user!) }
        : { kind: "password" as const };

      const renderProtected = (scope: WorkspaceScope, pageElement: ReactNode): ReactNode => {
        const scopeStatus = lockState.status?.[scope];
        if (!scopeStatus && lockState.loadError) {
          return (
            <div className="shell-card border-rose-100 bg-rose-50 p-6">
              <div className="text-sm font-bold text-rose-600">Could not read the {titles[scope][0]} lock</div>
              <div className="mt-2 text-sm text-rose-600">{lockState.loadError}</div>
              <button onClick={() => void lockState.refresh()} className="mt-4 rounded-lg bg-rose-500 px-4 py-2 text-sm font-bold text-white">
                Retry
              </button>
            </div>
          );
        }
        if (!scopeStatus) return <ModuleFallback />;
        if (!scopeStatus.unlocked) {
          return (
            <WorkspaceLockGate
              scope={scope}
              status={scopeStatus}
              recoveryEnabled={scope === "vault" ? vaultRecoveryEnabled : undefined}
              inactivityMinutes={lockState.inactivityMinutes}
              accountProof={accountProof}
              onUnlock={(method, secret) => lockState.unlock(scope, method, secret)}
              onSetup={(method, secret) => lockState.setup(scope, method, secret)}
              onPatternUnlock={scope === "vault" ? (pattern) => lockState.patternUnlock(pattern) : undefined}
              onHiddenRecovered={scope === "vault" ? () => void lockState.hiddenOpened() : undefined}
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
          content = <DashboardPage data={data} liveEvents={liveEvents} liveStatus={liveStatus} onNavigate={navigateFromDashboard} onOpenArea={openProtectedArea} missedCalls={missedCalls} sharedFilesWaiting={sharedFilesWaiting} />;
          break;
        case "chat":
          content = renderProtected(
            "chat",
            <SecureChatPage userId={auth.user.id} conversations={data.conversations} devices={data.devices} contacts={data.contacts} onSent={refresh} openContacts={chatOpensContacts} callIntent={chatIntent} onOpenCalls={() => navigate("calls")} missedCalls={missedCalls} />,
          );
          break;
        case "calls":
          // Behind the Secure Chat lock: the core also refuses to list calls while it is closed.
          content = renderProtected(
            "chat",
            <CallsPage
              conversations={data.conversations}
              contacts={data.contacts}
              onCall={(peerUserId, media) => {
                navigate("chat");
                setChatIntent({ key: crypto.randomUUID(), peerUserId, media });
              }}
              onMessage={(peerUserId) => {
                navigate("chat");
                setChatIntent({ key: crypto.randomUUID(), peerUserId, media: null });
              }}
            />,
          );
          break;
        case "vault":
          // A hidden vault opened by its pattern takes the place of the vault
          // (which stays locked); locking it returns to the lock screen.
          content = lockState.hiddenOpen ? (
            <HiddenVaultPage onLock={() => void lockState.lockHidden()} />
          ) : (
            renderProtected(
              "vault",
              <QuantumVaultPage
                userId={auth.user.id}
                telemetry={data.telemetry}
                sharedFilesWaiting={sharedFilesWaiting}
                onOpenTransfers={isTauriRuntime() ? () => navigate("xfer") : undefined}
                vaultLock={{
                  status: lockState.status?.vault ?? null,
                  setPattern: (pattern: string) => lockState.setup("vault", "pattern", pattern),
                  removePattern: () => lockState.removeCredential("vault", "pattern"),
                  onHiddenOpened: () => void lockState.hiddenOpened(),
                }}
              />,
            )
          );
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
          content = <AuditLogsPage userId={auth.user.id} devices={data.devices} events={data.telemetry} securityEvents={data.securityEvents} liveEvents={liveEvents} liveStatus={liveStatus} onRefresh={refresh} />;
          break;
        case "quantum":
          content = <QuantumSecurityDashboardPage userId={auth.user.id} data={data} liveEvents={liveEvents} liveStatus={liveStatus} onRefresh={refresh} />;
          break;
        case "subscription":
          content = <SubscriptionPage userId={auth.user.id} email={auth.user.email ?? null} accessToken={auth.session.access_token ?? null} state={subscriptionState} mode="manage" />;
          break;
        case "settings":
          content = <SettingsPage theme={theme} onToggleTheme={toggleTheme} profile={data.profile} telemetry={data.telemetry} securityEvents={data.securityEvents} liveEvents={liveEvents} liveStatus={liveStatus} onRefresh={refresh} inactivityMinutes={lockState.inactivityMinutes} onSetInactivityMinutes={lockState.setInactivityMinutes} workspaceStatus={lockState.status} onLockWorkspaces={lockState.lockAll} appLock={appLock} verifyAccountPassword={verifyAccountPassword}
            onOpenOfflineDevices={isTauriRuntime() ? () => navigate("offline-settings") : undefined} />;
          break;
        default:
          content = <DashboardPage data={data} liveEvents={liveEvents} liveStatus={liveStatus} onNavigate={navigateFromDashboard} onOpenArea={openProtectedArea} missedCalls={missedCalls} sharedFilesWaiting={sharedFilesWaiting} />;
          break;
      }
    }

    const moduleContent = (
      <ErrorBoundary resetKey={page}>
        <Suspense fallback={<ModuleFallback />}>{content}</Suspense>
      </ErrorBoundary>
    );
    const connectivity = <ConnectivityIndicator key={auth.user.id} accountId={auth.user.id} relay={relay} outboxCount={outboxCount} vaultUnlocked={isTauriRuntime() && lockState.status?.vault.unlocked === true} showAlways={page === "settings" || page === "offline-settings"} />;
    // The relay notice sits in the page flow under the header on every screen,
    // so it cannot cover buttons or the bottom navigation. It stays mounted:
    // its probe also drives automatic offline delivery.
    const relayBanner = <RelayHealthBanner key={`relay:${auth.user.id}`} onAvailability={onRelayAvailability} />;
    const pairingHost = renderPairingHost(auth.user.id);
    // Offline notices share the app's notification stack on every screen.
    const transferNotice = renderOfflineNotices();

    // Phone layout (Android build + narrow windows): compact header, floating
    // bottom navigation, and a module sheet replace the sidebar/top-bar chrome.
    if (isMobile) {
      return (
        <>
          <UpdateBanner />
          <OutboxCourier key={`outbox:${auth.user.id}`} onQueueCount={onQueueCount} />
          {pairingHost}
          <NotificationStack
            userId={auth.user.id}
            conversations={data.conversations}
            chatUnlocked={lockState.status ? !lockState.status.chat.configured || lockState.status.chat.unlocked : false}
            showShares={page !== "vault"}
            showMessages
            pendingShares={incomingShares.pending}
            transferNotice={transferNotice}
            onRespondShare={incomingShares.respond}
            onViewShares={openSharedFiles}
            onOpenConversation={(alert) => openConversationFromAlert(alert.conversationId)}
          />
          <MobileShell
            activePage={page}
            title={title}
            modules={navModules}
            unreadMessages={unreadMessages}
            sharedFilesWaiting={sharedFilesWaiting}
            liveStatus={liveStatus}
            theme={theme}
            onToggleTheme={toggleTheme}
            onNavigate={navigate}
            onSignOut={auth.signOut}
            // Mesh and XFER open straight onto the discovery radar, which
            // reports its own local status, without the relay/vault chip row.
            connectivity={<>{relayBanner}{page === "mesh" || page === "xfer" ? null : connectivity}</>}
          >
            {moduleContent}
          </MobileShell>
        </>
      );
    }

    return (
      // The call engine is mounted by the caller of renderShell(), above every
      // gate -- incoming quantum-encrypted calls ring on every page (dashboard,
      // settings, locked chat, PIN screen), not only while Secure Chat is open.
      <>
        <UpdateBanner />
        <OutboxCourier key={`outbox:${auth.user.id}`} onQueueCount={onQueueCount} />
        {pairingHost}
        <NotificationStack
          userId={auth.user.id}
          conversations={data.conversations}
          chatUnlocked={lockState.status ? !lockState.status.chat.configured || lockState.status.chat.unlocked : false}
          showShares={page !== "vault"}
          showMessages
          pendingShares={incomingShares.pending}
          transferNotice={transferNotice}
          onRespondShare={incomingShares.respond}
          onViewShares={openSharedFiles}
          onOpenConversation={(alert) => openConversationFromAlert(alert.conversationId)}
        />
        <div className="flex h-screen w-screen overflow-hidden bg-canvas">
          <Sidebar activePage={page} modules={navModules} snapshot={data.snapshot} unreadMessages={unreadMessages} missedCalls={missedCalls} sharedFilesWaiting={sharedFilesWaiting} onNavigate={navigate} />
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
            {relayBanner}
            {page === "mesh" || page === "xfer" ? null : connectivity}
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
      </>
    );
  };

  return (
    // Mute / Notifications & Sounds are read by Secure Chat, Settings, the
    // message alerts and the incoming-call ring (inside CallProvider).
    <ChatPreferencesProvider userId={onlineUserId}>
      <CallProvider userId={onlineUserId ?? ""}>
        {renderShell()}
      </CallProvider>
    </ChatPreferencesProvider>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ProtectedMessagingApp />
    </AuthProvider>
  );
}
