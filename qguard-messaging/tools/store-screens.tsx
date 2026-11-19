// Local Vite-only harness for Google Play store screenshots. Not imported by
// the app and not part of dist. It renders the real app components over a
// clearly fictional demo account (names, files and messages below are sample
// content). Network access is blocked by the page CSP; native commands are
// answered by the small router below instead of the Rust core.
import { useState } from "react";
import { createRoot } from "react-dom/client";
import "../src/styles/globals.css";
import "../src/styles/mobile.css";
import "../src/styles/android-modernist.css";
import "../src/styles/android-modernist-pages.css";
import "../src/styles/android-premium.css";
import "../src/components/offline/offline-guided-flow.css";
import "../src/components/offline/offline-dashboard.css";
import { ShieldCheck, Lock, Paperclip, SendHorizontal, Phone, Video } from "lucide-react";
import { AuthProvider } from "../src/lib/auth-context";
import { CallProvider } from "../src/components/call/CallProvider";
import { useDashboardData } from "../src/lib/use-dashboard-data";
import { useTheme } from "../src/lib/use-theme";
import MobileShell from "../src/components/mobile/MobileShell";
import MobileDashboard from "../src/components/mobile/MobileDashboard";
import MobileOnboarding from "../src/components/mobile/MobileOnboarding";
import SecureChatPage from "../src/pages/SecureChatPage";
import QuantumVaultPage from "../src/pages/QuantumVaultPage";
import QuantumSecurityDashboardPage from "../src/pages/QuantumSecurityDashboardPage";
import SettingsPage from "../src/pages/SettingsPage";
import CallsPage from "../src/pages/CallsPage";
import HiddenVaultPage from "../src/components/vault/hidden/HiddenVaultPage";
import { WorkspaceLockGate } from "../src/components/workspace/WorkspaceLockGate";
import { MobileThreadHeader } from "../src/components/chat/MobileChat";
import { PqStatusBadge } from "../src/components/PqStatusBadge";
import { UserAvatar } from "../src/components/UserAvatar";
import { RadarConsole } from "../src/components/offline/OfflineDashboard";
import { MeshConversation } from "../src/components/offline/MeshConversation";
import { XferTransferDashboard } from "../src/components/offline/XferTransferDashboard";
import { InCallOverlay } from "../src/components/call/InCallOverlay";
import { INITIAL_CALL_STATE } from "../src/lib/call-state";
import type { DashboardData, MessagingModule, Page, TrustedDevice, ConversationSummary, ContactSummary } from "../src/lib/types";
import type { OfflineStatus, OfflineTransfer, MeshMessage, OfflinePeer } from "../src/lib/offline";
import type { StoreEntry, StoreStatus } from "../src/lib/vault-store";

const params = new URLSearchParams(location.search);
const screen = params.get("screen") || "dashboard";
document.documentElement.setAttribute("data-qg-skin", "modernist");
const noop = () => undefined;
const now = Date.now();
const iso = (msAgo: number) => new Date(now - msAgo).toISOString();
const MIN = 60_000, HOUR = 60 * MIN, DAY = 24 * HOUR;
const bytes = (n: number, seed = 7) => Array.from({ length: n }, (_, i) => (i * 31 + seed) % 256);

// ---------- Demo account (fictional) ----------
const ME = "11111111-1111-4111-8111-111111111111";
const people = [
  { id: "22222222-2222-4222-8222-222222222222", name: "Maya Chen", user: "maya" },
  { id: "33333333-3333-4333-8333-333333333333", name: "Daniel Okafor", user: "daniel" },
  { id: "44444444-4444-4444-8444-444444444444", name: "Field Team Alpha", user: "" },
  { id: "55555555-5555-4555-8555-555555555555", name: "Sofia Martins", user: "sofia" },
  { id: "66666666-6666-4666-8666-666666666666", name: "Arjun Patel", user: "arjun" },
  { id: "77777777-7777-4777-8777-777777777777", name: "Legal & Compliance", user: "" },
];
const previews = ["Contract draft is in the vault 🔐", "Call me when you land", "Rally point moved to the north gate", "Photos from the weekend 📷", "Keys rotated, all green ✅", "Board pack v3 shared"];
const conversations: ConversationSummary[] = people.map((p, i) => ({
  id: `c0000000-0000-4000-8000-00000000000${i}`, conversation_type: p.user ? "direct" : "group", title: p.name,
  last_activity: previews[i], unread_count: [2, 0, 5, 0, 0, 1][i], updated_at: iso([4 * MIN, 38 * MIN, 2 * HOUR, 5 * HOUR, DAY, 2 * DAY][i]),
  member_user_ids: p.user ? [ME, p.id] : [ME, people[0].id, people[1].id], archived_at: null, hidden_at: null, deleted_at: null,
}));
const contacts: ContactSummary[] = people.filter((p) => p.user).map((p, i) => ({
  id: `k${i}`, contact_user_id: p.id, alias: null, display_name: p.name, username: p.user, trust_state: "added", created_at: iso(30 * DAY), updated_at: iso(DAY),
}));
const sig = { ed25519: bytes(64, 1), ml_dsa_65: bytes(64, 2) };
const device = (id: string, label: string, state: TrustedDevice["trust_state"], seen: number): TrustedDevice => ({
  device_id: id, user_id: ME, label, fingerprint: "9f".repeat(16), trust_state: state, pqc_status: "ML-KEM-1024 + X25519",
  suite: {}, last_seen_at: iso(seen), created_at: iso(40 * DAY), revoked_at: null, approved_by_device_id: null,
  x25519_identity_public: bytes(32), mlkem_identity_public: bytes(32), ed25519_identity_public: bytes(32), mldsa_identity_public: bytes(32),
  identity_signature: sig,
  signed_prekey: { prekey_id: `pk-${id}`, x25519_public: bytes(32), mlkem_public: bytes(32), signature: sig, fingerprint: "ab".repeat(16) },
});
const devices = [device("d1", "Pixel 9 Pro", "ThisDevice", 0), device("d2", "Work laptop", "Trusted", 20 * MIN), device("d3", "Galaxy Tab S9", "Trusted", 3 * HOUR)];
const hardeningIds: Array<[string, string]> = [
  ["anti_debugger_protection", "Anti-debugger protection"], ["anti_tampering_detection", "Anti-tampering detection"],
  ["runtime_integrity_hash_checks", "Runtime integrity hash checks"], ["secure_memory_zeroize", "Secure memory zeroize"],
  ["symmetric_crypto_self_test", "Symmetric crypto self-test"], ["tls_transport_policy", "TLS transport policy"],
  ["tamper_evident_audit_chain", "Tamper-evident audit chain"], ["post_quantum_protection", "Post-quantum protection"], ["rate_limiting", "Rate limiting"],
];

function demoData(base: DashboardData): DashboardData {
  return {
    ...base,
    profile: { id: ME, email: "alex@example.com", name: "Alex Rivera", username: "alex", avatar_storage_path: null, avatar_updated_at: null, tier: "pro", q_score: 100, vault_storage_used: 0, max_vault_storage: 0 },
    devices, contacts, conversations,
    keyInventory: { identity_device_count: 3, active_signed_prekeys: 3, available_one_time_prekeys: 96, next_signed_prekey_expiry: iso(-20 * HOUR), rotation_events: 42, algorithms: ["ML-KEM-1024", "X25519", "ML-DSA-65", "ML-DSA-87", "Ed25519", "AES-256-GCM", "SHA3-256"] },
    hardening: { ...base.hardening, checks: hardeningIds.map(([id, label]) => ({ id, label, status: "active", active: true, detail: "Active" })) },
    snapshot: { ...base.snapshot, e2ee_status: "Active", pqc_status: "Hybrid ML-KEM-1024 + X25519", active_sessions: 6, device_count: 3, quantum_safe_score: 100, hndl_status: "Protected" },
    report: { ...base.report, hybrid_session_status: "Active", pqc_algorithm: "ML-KEM-1024 + ML-DSA-65", forward_secrecy: "Prekey rotating daily", forward_secrecy_healthy: true, hndl_protection: "Protected", quantum_safe_score: 100, key_rotation_history: [], warnings: [] },
  };
}

// ---------- Quantum Vault storage (fictional files) ----------
const entry = (id: string, name: string, kind: "file" | "folder", parentId: string | null, size: number, category: StoreEntry["category"], ct: string, ago: number, fav = false): StoreEntry => ({
  id, kind, name, parentId, createdAt: iso(ago), updatedAt: iso(ago), trashedAt: null, favorite: fav, sizeBytes: size, storedBytes: Math.round(size * 1.002),
  contentType: ct, category, typeCheck: kind === "file" ? "match" : "", plaintextSha3: "5e".repeat(32), containerVersion: 3, pinBound: true, totalChunks: Math.max(1, Math.ceil(size / 4_194_304)),
  recoveryProtected: true, integrity: kind === "file" ? "verified" : "", lastVerifiedAt: iso(ago / 2), hasThumbnail: false,
});
const MB = 1024 * 1024;
const vaultEntries: StoreEntry[] = [
  entry("f1", "Passports & IDs", "folder", null, 0, "", "", 9 * DAY),
  entry("f2", "Family photos", "folder", null, 0, "", "", 6 * DAY),
  entry("f3", "Contracts", "folder", null, 0, "", "", 3 * DAY),
  entry("e1", "Passport scan.pdf", "file", "f1", 2.4 * MB, "document", "application/pdf", 9 * DAY, true),
  entry("e2", "Driving licence.jpg", "file", "f1", 1.1 * MB, "image", "image/jpeg", 9 * DAY),
  entry("e3", "Beach day.jpg", "file", "f2", 4.8 * MB, "image", "image/jpeg", 6 * DAY),
  entry("e4", "Birthday clip.mp4", "file", "f2", 86 * MB, "video", "video/mp4", 5 * DAY),
  entry("e5", "NDA — signed.pdf", "file", "f3", 0.6 * MB, "document", "application/pdf", 3 * DAY),
  entry("e6", "Tax return 2025.pdf", "file", null, 1.8 * MB, "document", "application/pdf", 2 * DAY, true),
  entry("e7", "Wallet seed backup.txt", "file", null, 0.002 * MB, "document", "text/plain", 4 * HOUR, true),
  entry("e8", "Voice memo.m4a", "file", null, 3.2 * MB, "audio", "audio/mp4", 6 * HOUR),
  entry("e9", "Project archive.zip", "file", null, 48 * MB, "archive", "application/zip", 26 * HOUR),
];
const files = vaultEntries.filter((e) => e.kind === "file");
const sum = (cat: string) => ({ files: files.filter((f) => f.category === cat).length, bytes: files.filter((f) => f.category === cat).reduce((a, f) => a + f.sizeBytes, 0) });
const storeStatus: StoreStatus = {
  state: "ready", storageLocation: "App private storage", vaultId: "vault-demo", files: files.length, folders: 3, trashed: 0, favorites: 3,
  plaintextBytes: files.reduce((a, f) => a + f.sizeBytes, 0), storedBytes: files.reduce((a, f) => a + f.storedBytes, 0),
  categories: { image: sum("image"), video: sum("video"), audio: sum("audio"), document: sum("document"), archive: sum("archive"), other: sum("other") },
  verified: files.length, unverified: 0, failed: 0, missing: 0, typeMismatches: 0, legacyContainers: 0, recoveryProtected: files.length, orphanedObjects: 0, recoveryIndex: true,
  lastImportAt: iso(4 * HOUR), lastFullVerifyAt: iso(HOUR),
  recentActivity: [
    { id: "a1", at: iso(4 * HOUR), action: "import", entryId: "e7", name: "Wallet seed backup.txt", detail: "Encrypted with AES-256-GCM", outcome: "success" },
    { id: "a2", at: iso(HOUR), action: "verify_all", entryId: null, name: "All files", detail: "9 of 9 verified", outcome: "success" },
    { id: "a3", at: iso(26 * HOUR), action: "import", entryId: "e9", name: "Project archive.zip", detail: "Encrypted with AES-256-GCM", outcome: "success" },
  ],
  limits: { maxPreviewBytes: 50 * MB, maxImportBytes: 4096 * MB, maxThumbnailBytes: MB },
};
const hiddenEntries: StoreEntry[] = [
  entry("h0", "Private keys", "folder", null, 0, "", "", 12 * DAY),
  entry("h1", "Journal 2026.pdf", "file", null, 3.1 * MB, "document", "application/pdf", 2 * DAY, true),
  entry("h2", "Recovery codes.txt", "file", null, 0.004 * MB, "document", "text/plain", 5 * DAY),
  entry("h3", "Medical records.pdf", "file", null, 5.6 * MB, "document", "application/pdf", 8 * DAY),
  entry("h4", "Evidence photo.jpg", "file", null, 3.9 * MB, "image", "image/jpeg", 11 * DAY),
];
const hiddenSummary = { files: 4, folders: 1, bytes: hiddenEntries.reduce((a, e) => a + e.sizeBytes, 0), createdAt: iso(14 * DAY), duressErase: true, recoveryPhrase: true };

// Native command router (stands in for the Rust core in this harness only).
const routes: Record<string, unknown> = {
  vault_store_status: storeStatus, vault_store_list: vaultEntries, vault_store_activity: storeStatus.recentActivity,
  vault_hidden_status: { open: true, summary: hiddenSummary }, vault_hidden_list: hiddenEntries,
};
const unknownCommands = new Set<string>();
(window as unknown as Record<string, unknown>).__qgUnknown = unknownCommands;
if (params.get("native") !== "0") {
  (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {
    transformCallback: () => Math.floor(Math.random() * 1e9),
    unregisterCallback: noop,
    convertFileSrc: (p: string) => p,
    invoke: async (cmd: string) => {
      if (cmd in routes) return structuredClone(routes[cmd]);
      unknownCommands.add(cmd);
      throw new Error(`preview: ${cmd} unavailable`);
    },
  };
}

// ---------- Offline (Mesh / XFER) fixtures ----------
const nowS = Math.floor(now / 1000);
const LOCAL = "a1".repeat(32);
const meshPeers: OfflinePeer[] = [
  { fingerprint: "b2".repeat(32), label: "Pixel 8", owner: "Maya Chen", address: null, lastSeen: nowS, authenticatedAt: nowS, trusted: true, discovery: ["ble"], platform: "android", pairedAt: nowS - 9 * 86400, capabilities: ["mesh", "xfer"], rssi: -52, connected: true,
    link: { state: "connected", transport: "bluetooth", since: nowS - 420, session: "4f0a9c2e71d3b8a6", rttMs: 84, attempts: 0 } },
  { fingerprint: "c3".repeat(32), label: "Galaxy S24", owner: "Daniel Okafor", address: null, lastSeen: nowS - 4, authenticatedAt: nowS - 60, trusted: true, discovery: ["ble", "lan"], platform: "android", pairedAt: nowS - 20 * 86400, capabilities: ["mesh", "xfer"], rssi: -67 },
  { fingerprint: "d4".repeat(32), label: "ThinkPad X1", owner: "Sofia Martins", address: "192.168.43.18", lastSeen: nowS - 2, authenticatedAt: nowS - 30, trusted: true, discovery: ["lan"], platform: "windows", pairedAt: nowS - 4 * 86400, capabilities: ["xfer"] },
];
const offlineStatus: OfflineStatus = {
  running: true, lanDiscoveryRunning: true, autoStart: true, fingerprint: LOCAL, port: 41000, peers: meshPeers, networkError: null, platform: "android", localOwner: "Alex Rivera",
  smartConnect: { bluetoothAvailable: true, bluetoothPermissionGranted: true, bluetoothRunning: true, bluetoothScanning: true, bluetoothAdvertising: true, bluetoothError: null, hotspotAvailable: true, hotspotActive: false },
  background: true, relay: true, relayCarrying: 2,
};
const meshTexts = ["Signal is down across the valley. Mesh only from here.", "Copy. Rally point moved to the north gate.", "On my way, ETA five minutes.", "Bring the field kit — two people need first aid.", "Got it 👍 heading over now"];
const meshMessages: MeshMessage[] = meshTexts.map((body, index) => {
  const outgoing = index % 2 === 1;
  const peer = meshPeers[0].fingerprint;
  return { id: `m${index}`, direction: outgoing ? "outgoing" : "incoming", sender: outgoing ? LOCAL : peer, recipients: outgoing ? [peer] : [LOCAL], body, group: null,
    emergency: index === 3, createdAt: nowS - 600 + index * 70, receivedAt: outgoing ? null : nowS - 590 + index * 70, expiresAt: nowS + 3600,
    status: "delivered", deliveredTo: outgoing ? [peer] : [LOCAL], readAt: nowS } as MeshMessage;
});
const suite = { mode: "Hybrid", keyEstablishment: "ML-KEM-768 + X25519", signatures: "ML-DSA-65 + Ed25519", encryption: "AES-256-GCM", integrity: "SHA3-256" };
const xferTransfer: OfflineTransfer = {
  id: "00000000-0000-4000-8000-00000000f1f0", direction: "outgoing", sender: LOCAL, recipient: meshPeers[2].fingerprint,
  files: [
    { name: "Site survey/drone-footage.mp4", size: 412 * MB, verifiedBytes: 412 * MB, digest: "4f".repeat(32) },
    { name: "Site survey/site-plan.pdf", size: 38 * MB, verifiedBytes: 21 * MB, digest: "9c".repeat(32) },
    { name: "Site survey/photos.zip", size: 96 * MB, verifiedBytes: 0, digest: "7d".repeat(32) },
  ],
  folderName: "Site survey", status: "active", currentFile: 1, verifiedBytes: 433 * MB, totalBytes: 546 * MB,
  createdAt: nowS - 40, expiresAt: nowS + 3600, localCopyRetained: false,
  bytesPerSecond: 11.4 * MB, averageBytesPerSecond: 10.8 * MB, elapsedMs: 40_000, error: null,
  sessionId: "7F3A91D4C2B011EE", security: { phase: "secureTransfer", ...suite },
  throughput: [8.2, 9.6, 10.4, 11.1, 10.7, 11.9, 12.2, 10.9, 11.6, 11.4].map((v, i, a) => ({ atMs: now - (a.length - i) * 1000, bytesPerSecond: v * MB })),
} as OfflineTransfer;

// ---------- Secure chat thread (sample content, rendered with the app's bubble styles) ----------
const thread = [
  { mine: false, text: "Hey! Did the signed NDA come through?", t: 18 },
  { mine: true, text: "Yes — it's in my Quantum Vault. Sharing it with you now.", t: 16 },
  { mine: true, file: { name: "NDA — signed.pdf", size: "614 KB" }, t: 15 },
  { mine: false, text: "Got it, opened fine. Love that it's sealed end to end 🔐", t: 12 },
  { mine: true, text: "ML-KEM + X25519 on every message, built to resist future quantum attacks.", t: 9 },
  { mine: false, text: "Perfect. Quick call at 3?", t: 4 },
];
function ChatThreadDemo() {
  const peer = people[0];
  return (
    <section className="-mx-3.5 -my-3 flex min-h-0 flex-col overflow-hidden" style={{ height: "var(--qg-thread-h, calc(100dvh - 184px))" }}>
      <MobileThreadHeader
        onBack={noop}
        avatar={<UserAvatar userId={peer.id} name={peer.name} size={38} />}
        title={peer.name}
        badge={<PqStatusBadge status={{ level: "protected-pinned", label: "Quantum-safe", headline: "Hybrid ML-KEM-1024 + X25519, sender keys verified.", lines: [] }} />}
        call={<div className="flex"><span className="flex h-11 w-10 items-center justify-center text-ink-700"><Phone size={19} /></span><span className="flex h-11 w-10 items-center justify-center text-ink-700"><Video size={20} /></span></div>}
        onOptions={noop}
      />
      <div className="flex min-h-0 flex-1 flex-col justify-end gap-3 overflow-hidden px-3.5 py-3">
        <div className="mx-auto flex w-fit items-center gap-1.5 rounded-full border border-line bg-white px-3 py-1 text-[11px] font-semibold text-ink-500"><Lock size={11} /> Messages are end-to-end encrypted with post-quantum keys</div>
        {thread.map((m, i) => (
          <div key={i} className={`flex items-start gap-2 ${m.mine ? "justify-end" : "justify-start"}`}>
            {!m.mine && <UserAvatar userId={peer.id} name={peer.name} size={32} className="mt-1 shadow-tight" />}
            <div className={`group relative max-w-[74%] ${m.mine ? "order-1" : ""}`}>
              <div className={`rounded-2xl px-4 py-3 shadow-tight ${m.mine ? "rounded-br-md bg-violet-600 text-white" : "rounded-bl-md border border-line bg-white text-ink-900"}`}>
                {m.file ? (
                  <div className={`flex items-center gap-3 rounded-lg border px-3 py-3 ${m.mine ? "border-white/20 bg-white/10" : "border-line bg-canvas"}`}>
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-white/15"><Paperclip size={16} /></div>
                    <div className="min-w-0"><div className="truncate text-sm font-bold">{m.file.name}</div><div className="mt-0.5 text-[11px] text-violet-100">{m.file.size} · Encrypted attachment</div></div>
                  </div>
                ) : <div className="whitespace-pre-wrap break-words text-sm leading-6">{m.text}</div>}
                <div className={`mt-2 flex flex-wrap items-center gap-2 text-[11px] ${m.mine ? "text-violet-100" : "text-ink-400"}`}>
                  <span>{new Date(now - m.t * MIN).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span><span>Verified</span><span>Replay-safe</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      <div className="flex items-center gap-2 border-t border-line px-3 py-2.5">
        <span className="flex h-10 w-10 items-center justify-center text-ink-500"><Paperclip size={19} /></span>
        <div className="flex h-11 flex-1 items-center rounded-full border border-line bg-white px-4 text-sm text-ink-400">Encrypted message</div>
        <span className="flex h-11 w-11 items-center justify-center rounded-full bg-violet-600 text-white"><SendHorizontal size={18} /></span>
      </div>
    </section>
  );
}

const modules: MessagingModule[] = [["dashboard", "Home"], ["chat", "Chats"], ["vault", "Vault"], ["quantum", "Security"], ["settings", "Settings"], ["calls", "Calls"], ["keys", "Keys"], ["devices", "Devices"], ["verification", "Verification"], ["audit", "Audit"]]
  .map(([route, label], i) => ({ module_id: route as Page, route: route as Page, icon: route, label, enabled: true, sort_order: i }));
const unavailable = async () => { throw new Error("Store preview: account operations are unavailable."); };

function Preview() {
  const { data: empty, liveStatus: baseLive } = useDashboardData(null, null);
  const liveStatus = { ...baseLive, state: "live" } as typeof baseLive;
  const data = demoData(empty);
  const { theme, toggleTheme } = useTheme();
  const [page, setPage] = useState(screen);
  if (page === "onboarding") return <MobileOnboarding onDone={noop} />;
  if (page === "call") return <InCallOverlay
    state={{ ...INITIAL_CALL_STATE, phase: "connected", callId: "demo-call", role: "caller", conversationId: conversations[0].id, media: "voice",
      peerUserId: people[0].id, peerDeviceId: "d-maya", safetyNumber: "4821 0937 5560 1274 8833", forwardSecret: true, peerVerified: true,
      peerVerifiedAt: Math.floor((now - 9 * DAY) / 1000), peerPaired: true }}
    localStream={null} remoteStream={null} micEnabled cameraEnabled={false} peerName={people[0].name} peerUserId={people[0].id}
    quality="auto" onSetQuality={noop} onHangup={noop} onToggleMic={noop} onToggleCamera={noop} />;
  let content;
  let active: Page = page as Page;
  let title = modules.find((m) => m.route === page)?.label || "Qguard";
  switch (page) {
    case "chats": active = "chat"; title = "Chats"; content = <SecureChatPage userId={ME} conversations={conversations} devices={devices} contacts={contacts} onSent={noop} />; break;
    case "thread": active = "chat"; title = "Secure Chat"; content = <ChatThreadDemo />; break;
    case "vault": content = <QuantumVaultPage userId={ME} telemetry={[]} />; title = "Quantum Vault"; break;
    case "vault-lock": active = "vault"; title = "Quantum Vault";
      content = <WorkspaceLockGate scope="vault" status={{ configured: true, hasPassword: true, hasPin: true, hasPattern: true, unlocked: false, failedAttempts: 0, lockoutUntil: null, lockdown: false }} recoveryEnabled inactivityMinutes={5} onUnlock={unavailable} onSetup={unavailable} onPatternUnlock={unavailable} onCancel={noop} />; break;
    case "hidden": active = "vault"; title = "Hidden Vault"; content = <HiddenVaultPage onLock={noop} />; break;
    case "quantum": content = <QuantumSecurityDashboardPage userId={ME} data={data} liveEvents={[]} liveStatus={liveStatus} onRefresh={noop} />; title = "Security"; break;
    case "settings": content = <SettingsPage theme={theme} profile={data.profile} telemetry={[]} securityEvents={[]} liveEvents={[]} liveStatus={liveStatus} onToggleTheme={toggleTheme} onRefresh={noop} inactivityMinutes={5} onSetInactivityMinutes={noop} workspaceStatus={null} onLockWorkspaces={noop} />; break;
    case "calls": content = <CallsPage conversations={conversations} contacts={contacts} onCall={noop} onMessage={noop} />; break;
    case "mesh": case "xfer": active = page as Page; title = page === "mesh" ? "Qguard Mesh" : "Qguard XFER";
      content = <div className="offline-guided-flow" data-screen="discovery"><RadarConsole mode={page} status={offlineStatus} selected={page === "xfer" ? [meshPeers[2].fingerprint] : []} busy={false} onSelect={noop} onToggleDiscovery={noop} onOpenSettings={noop} onOpenDevices={noop} activeTransfers={page === "xfer" ? 1 : 0} /></div>; break;
    case "mesh-chat": active = "mesh" as Page; title = "Qguard Mesh";
      content = <div className="offline-dashboard"><MeshConversation peerId={meshPeers[0].fingerprint} peer={meshPeers[0]} messages={meshMessages} running onBack={noop} onOpenMessage={noop} onGroupMessage={noop} /></div>; break;
    case "xfer-transfer": active = "xfer" as Page; title = "Qguard XFER";
      content = <XferTransferDashboard transfer={xferTransfer} status={offlineStatus} localIdentity={{ displayName: "Alex Rivera", deviceName: "Pixel 9 Pro" }} onBack={noop} onDone={noop}
        actions={<div style={{ display: "flex", gap: 8 }}><button type="button" className="qg-btn">Pause</button><button type="button" className="qg-btn">Stop</button></div>} />; break;
    default: active = "dashboard"; title = "Home"; content = <MobileDashboard data={data} liveStatus={liveStatus} onNavigate={setPage} />;
  }
  return <MobileShell activePage={active} title={title} modules={modules} unreadMessages={8} liveStatus={liveStatus} theme={theme} onToggleTheme={toggleTheme} onNavigate={setPage} onSignOut={noop}>{content}</MobileShell>;
}

createRoot(document.getElementById("root")!).render(<AuthProvider><CallProvider userId=""><Preview /></CallProvider></AuthProvider>);
void ShieldCheck;
