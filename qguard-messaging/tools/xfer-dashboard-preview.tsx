// Local Vite-only layout harness for the XFER transfer dashboard. It is not
// imported by the app and is not part of dist. Every value below is an
// explicit layout fixture that exercises one dashboard state; none of it is
// operational data, and the production dashboard reads only native records.
import { createRoot } from "react-dom/client";
import "../src/styles/globals.css";
import { XferTransferDashboard } from "../src/components/offline/XferTransferDashboard";
import OfflinePage from "../src/pages/OfflinePage";
import { OfflineAccountContext } from "../src/lib/offline-avatars";
import type { OfflineStatus, OfflineTransfer } from "../src/lib/offline";

const params = new URLSearchParams(location.search);
const view = params.get("state") ?? "active";
document.documentElement.classList.toggle("theme-dark", params.get("theme") === "dark");
document.documentElement.classList.toggle("theme-light", params.get("theme") !== "dark");

const now = Date.now();
const local = "a".repeat(64);
const peer = "b".repeat(64);
const status: OfflineStatus = {
  running: true, lanDiscoveryRunning: true, autoStart: false, fingerprint: local, port: 41000,
  platform: "android", networkError: null, localOwner: "Layout fixture sender",
  peers: [{
    fingerprint: peer, label: "Fixture workstation", owner: "Layout fixture receiver", address: null, trusted: true,
    platform: "windows", pairedAt: now / 1_000 - 600, capabilities: ["mesh", "xfer"], lastSeen: now / 1_000,
    authenticatedAt: now / 1_000, discovery: ["lan"],
    // Fixture: a live LAN channel and a synced picture (?pictures).
    link: { state: "connected", transport: "lan", since: now / 1_000 - 120, session: "7f3a91d4c2b011ee", rttMs: 9, attempts: 0 },
    avatar: params.has("pictures") ? "b".repeat(64) : null,
    // ?link=<state>: a Wi-Fi link fixture (joinPrompt, manual, connected, failed, starting).
    wifiLink: params.get("link") ? {
      state: params.get("link") as never, role: params.get("link") === "starting" ? "host" : "join", automaticJoin: params.get("link") !== "manual",
      ...(params.get("link") === "manual" ? { network: "AndroidShare_4821", passphrase: "fixture-pass-8812" } : {}),
      ...(params.get("link") === "failed" ? { error: "Android could not start a temporary hotspot." } : {}),
    } : null,
  }],
  localAvatar: params.has("pictures") ? "a".repeat(64) : null,
};
// Layout-fixture pictures (plain gradients): the real ones are JPEG
// thumbnails the native core returns as data URLs.
const fixturePicture = (from: string, to: string) => "data:image/svg+xml;base64," + btoa(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${from}"/><stop offset="1" stop-color="${to}"/></linearGradient></defs><rect width="96" height="96" fill="url(#g)"/><circle cx="48" cy="38" r="17" fill="#fff" opacity=".85"/><rect x="20" y="62" width="56" height="34" rx="17" fill="#fff" opacity=".85"/></svg>`);
const suite = { mode: "Hybrid", keyEstablishment: "ML-KEM-768 + X25519", signatures: "ML-DSA-65 + Ed25519", encryption: "AES-256-GCM", integrity: "SHA3-256" };
const samples = (rates: number[], step = 1_000) => rates.map((bytesPerSecond, index) => ({ atMs: now - (rates.length - index) * step, bytesPerSecond }));
const base: OfflineTransfer = {
  id: "00000000-0000-4000-8000-00000000f1f0", direction: "outgoing", sender: local, recipient: peer,
  files: [
    { name: "Fixture folder/layout-a.jpg", size: 24 * 1024 * 1024, verifiedBytes: 24 * 1024 * 1024, digest: "4f".repeat(32) },
    { name: "Fixture folder/layout-b.pdf", size: 12 * 1024 * 1024, verifiedBytes: 900 * 1024, digest: "9c".repeat(32) },
  ],
  folderName: "Fixture folder", status: "active", currentFile: 1, verifiedBytes: 25 * 1024 * 1024, totalBytes: 36 * 1024 * 1024,
  createdAt: now / 1_000 - 20, expiresAt: now / 1_000 + 3_600, localCopyRetained: false,
  bytesPerSecond: 2.6 * 1024 * 1024, averageBytesPerSecond: 2.1 * 1024 * 1024, elapsedMs: 12_000, error: null,
  sessionId: "7F3A91D4C2B011EE", security: { phase: "secureTransfer", ...suite },
  throughput: samples([1.2, 1.9, 2.4, 2.2, 2.8, 2.5, 1.1, 2.7, 3.0, 2.6].map((value) => value * 1024 * 1024)),
};
const fixtures: Record<string, OfflineTransfer> = {
  active: base,
  stalled: {
    ...base, bytesPerSecond: 0,
    throughput: [
      ...samples([1.8, 2.4, 2.1].map((value) => value * 1024 * 1024), 1_000).map((sample) => ({ ...sample, atMs: sample.atMs - 30_000 })),
      ...samples([2.2, 2.6, 0, 0, 0].map((value) => value * 1024 * 1024)),
    ],
  },
  verified: {
    ...base, status: "verified", verifiedBytes: base.totalBytes, verifiedFiles: 2, completedAtMs: now, elapsedMs: 15_000,
    files: base.files.map((file) => ({ ...file, verifiedBytes: file.size, verified: true })),
    security: { phase: "verified", ...suite },
  },
  failed: {
    ...base, status: "failed", errorKind: "integrity", bytesPerSecond: null,
    error: "File integrity verification failed. Start a new transfer from the original files.",
    security: { phase: "error", ...suite },
  },
};

// ?state=waiting renders the real XFER page on the receiver's "waiting for
// files" screen, against a stubbed native core that reports no transfers.
(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {
  transformCallback: () => 0,
  invoke: async (command: string, args?: { peer?: string }) => command === "offline_dashboard_snapshot" ? { status, messages: null, transfers: [] }
    : command === "offline_avatar" && params.has("pictures")
      ? args?.peer ? { digest: "b".repeat(64), dataUrl: fixturePicture("#0f766e", "#1d4ed8") } : { digest: "a".repeat(64), dataUrl: fixturePicture("#7c3aed", "#db2777") }
      : null,
};

function Harness() {
  if (view === "waiting" || view === "radar") return <main style={{ padding: 16, maxWidth: 1100, margin: "0 auto" }}>
    <OfflinePage page="xfer" accountId="layout-fixture" vaultUnlocked={false} onNavigate={() => undefined}
      initialPeer={view === "waiting" ? peer : undefined} initialIntent={view === "waiting" ? "receive" : undefined} />
  </main>;
  const transfer = fixtures[view] ?? base;
  const nextAction = transfer.status === "verified" ? { kind: params.get("next") === "receive" ? "receive" as const : "send" as const, onSelect: () => undefined } : undefined;
  return <main style={{ padding: 16, maxWidth: 1100, margin: "0 auto", background: "var(--app-canvas, transparent)" }}>
    <p style={{ fontSize: 12, marginBottom: 8, opacity: .7 }}>Layout harness · fixture state “{view}” · not operational data</p>
    <XferTransferDashboard transfer={transfer} status={status} localIdentity={{ displayName: "Layout fixture sender", deviceName: "Fixture tablet" }}
      onBack={() => undefined} onDone={() => undefined} nextAction={nextAction}
      actions={transfer.status === "failed" ? <button type="button">Send again</button> : transfer.status === "active" ? <div><button type="button">Pause</button><button type="button">Stop</button><button type="button">Cancel</button></div> : undefined} />
  </main>;
}

createRoot(document.getElementById("root")!).render(<OfflineAccountContext.Provider value="layout-fixture"><Harness /></OfflineAccountContext.Provider>);
