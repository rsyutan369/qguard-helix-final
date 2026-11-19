// Local Vite-only layout harness for the relay status strip. Not imported by
// the app and not part of dist. The relay probe is forced to fail and the
// browser is reported offline, so the strip renders its "You're offline" state
// above a page whose last control sits at the very bottom of the screen.
import { createRoot } from "react-dom/client";
import "../src/styles/globals.css";

const params = new URLSearchParams(location.search);
document.documentElement.classList.toggle("theme-dark", params.get("theme") === "dark");
if (params.has("android")) document.documentElement.setAttribute("data-qg-skin", "modernist");

Object.defineProperty(navigator, "onLine", { configurable: true, get: () => false });
window.fetch = () => Promise.reject(new TypeError("layout fixture: network unavailable"));

void import("../src/components/RelayHealthBanner").then(({ RelayHealthBanner }) => {
  createRoot(document.getElementById("root")!).render(
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-canvas">
      <header data-fixture="header" className="shrink-0 border-b border-line bg-white/75 px-4 py-3 text-sm font-bold text-ink-950">Qguard Mesh</header>
      <RelayHealthBanner />
      <main className="flex min-h-0 flex-1 flex-col overflow-y-auto p-4">
        <p className="text-sm text-ink-700">Connect to device</p>
        <div className="flex-1" />
        <button data-fixture="primary" type="button" className="w-full rounded-lg bg-violet-600 px-4 py-3 text-sm font-bold text-white">Connect Device</button>
      </main>
      <nav data-fixture="nav" className="shrink-0 border-t border-line bg-white/75 px-4 py-3 text-center text-xs text-ink-700">Home · Chats · Vault · Security · Settings</nav>
    </div>,
  );
});
