// Local Vite-only layout harness for Offline Settings (background Mesh and
// relay toggles, offline sign-in panel). Not imported by the app and not part
// of dist. The native bridge is replaced by explicit layout fixtures.
import { createRoot } from "react-dom/client";
import "../src/styles/globals.css";

const params = new URLSearchParams(location.search);
document.documentElement.classList.toggle("theme-dark", params.get("theme") === "dark");
const android = params.has("android");
if (android) document.documentElement.setAttribute("data-qg-skin", "modernist");

const status = {
  running: true, lanDiscoveryRunning: true, autoStart: true, fingerprint: "ab".repeat(32), port: 41000, peers: [],
  networkError: null, platform: android ? "android" : "windows", localOwner: "Layout Fixture",
  offlineAccess: { enrolled: true, offlineUntil: Date.UTC(2026, 11, 9) / 1000, passwordSignIn: !android },
  background: params.has("background"), relay: !params.has("norelay"), relayCarrying: 3,
};
(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {
  transformCallback: () => 0,
  invoke: async (command: string) => {
    if (command === "offline_dashboard_snapshot") return { status, messages: null, transfers: null };
    if (command === "plugin:event|listen") return 0;
    return null;
  },
};

void import("../src/pages/OfflinePage").then(({ default: OfflinePage }) => {
  createRoot(document.getElementById("root")!).render(
    <div className="min-h-screen bg-canvas p-4">
      <OfflinePage page="offline-settings" accountId="fixture" vaultUnlocked={false} onNavigate={() => undefined} relay="unknown" />
    </div>,
  );
});
