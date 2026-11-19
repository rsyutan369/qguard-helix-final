// Local Vite-only layout harness for the Mesh conversation. Not imported by
// the app and not part of dist. Explicit layout fixtures replace the core.
import { createRoot } from "react-dom/client";
import "../src/styles/globals.css";
import "../src/components/offline/offline-dashboard.css";
// The Android skin moves the navigation rail into the page flow on phones;
// load it so ?android exercises the real layout rules.
import "../src/styles/mobile.css";
import "../src/styles/android-modernist.css";
import "../src/styles/android-premium.css";
import { MeshConversation } from "../src/components/offline/MeshConversation";
import type { MeshMessage, OfflinePeer } from "../src/lib/offline";

const params = new URLSearchParams(location.search);
document.documentElement.classList.toggle("theme-dark", params.get("theme") === "dark");
if (params.has("android")) document.documentElement.setAttribute("data-qg-skin", "modernist");

const ME = "aa".repeat(32);
const PEER = "bb".repeat(32);
const now = Math.floor(Date.now() / 1000);
const peer: OfflinePeer = {
  fingerprint: PEER, label: "Pixel 8", owner: "teslagreat101", address: null, lastSeen: now, authenticatedAt: now,
  trusted: true, discovery: ["ble"], platform: "android",
  link: params.has("down") ? { state: "reconnecting", transport: null, since: null, session: null, rttMs: null, attempts: 1 }
    : { state: "connected", transport: "bluetooth", since: now - 300, session: "4f0a9c2e71d3b8a6", rttMs: 84, attempts: 0 },
};
const texts = ["Are you at the north gate?", "Yes, by the blue door.", "On my way, five minutes.", "Bring the field kit please", "Got it 👍"];
const messages: MeshMessage[] = texts.map((body, index) => {
  const outgoing = index % 2 === 0;
  return {
    id: `m${index}`, direction: outgoing ? "outgoing" : "incoming", sender: outgoing ? ME : PEER, recipients: outgoing ? [PEER] : [ME],
    body, group: null, emergency: index === 3, createdAt: now - 600 + index * 60, receivedAt: outgoing ? null : now - 590 + index * 60,
    expiresAt: now + 3600, status: outgoing && index === 4 ? "pending" : "delivered", deliveredTo: outgoing && index !== 4 ? [PEER] : [ME], readAt: now,
  };
});
(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = { transformCallback: () => 0, invoke: async () => null };

const conversation = <MeshConversation peerId={PEER} peer={peer} messages={messages} running onBack={() => undefined}
  onOpenMessage={() => undefined} onGroupMessage={() => undefined} />;

// ?shell reproduces the phone layout the conversation actually sits in: a
// header and offline banner above a padded scroll area, a network notice
// above the thread, and the floating navigation bar over the bottom padding.
createRoot(document.getElementById("root")!).render(params.has("shell")
  ? <div className="mobile-shell qg-stage relative flex h-[100dvh] w-screen flex-col overflow-hidden bg-canvas">
    <header className="shrink-0 border-b border-line bg-white px-4 py-4 text-base font-bold text-ink-950">Qguard Mesh · layout fixture</header>
    <div className="shrink-0 border-b border-line bg-amber-50 px-4 py-3 text-xs text-ink-800">You're offline. Online messages will send and arrive after this device reconnects to the relay.</div>
    <main className="qg-scroll min-h-0 flex-1 overflow-x-hidden overflow-y-auto overscroll-contain p-3.5 pb-28">
      <div className="offline-dashboard mx-auto max-w-7xl min-w-0 space-y-4 pb-3">
        <div role="alert" className="shell-card p-4 text-sm text-ink-800">LAN broadcast unavailable: Network is unreachable (layout fixture)</div>
        {conversation}
      </div>
    </main>
    <nav className="mobile-safe-bottom pointer-events-none fixed inset-x-0 bottom-0 z-30 flex justify-center px-4 pb-3">
      <div className="qg-nav pointer-events-auto" data-qg-bottom-bar>
        {["Home", "Chats", "Vault", "Security", "Settings"].map((label) => <span key={label} className="qg-nav-item"><span>{label}</span></span>)}
      </div>
    </nav>
  </div>
  : <div className="min-h-screen bg-canvas p-3 sm:p-6">
    <div className="offline-dashboard mx-auto max-w-3xl">{conversation}</div>
  </div>,
);
