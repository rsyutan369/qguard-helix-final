// Local Vite-only layout harness for the offline-mode shell (signed in without
// internet). Not imported by the app and not part of dist. The account, date
// and workspace text are explicit layout fixtures; the buttons do nothing.
import { createRoot } from "react-dom/client";
import "../src/styles/globals.css";
import { OfflineModeShell } from "../src/components/offline/OfflineModeShell";

const params = new URLSearchParams(location.search);
const dark = params.get("theme") === "dark";
document.documentElement.classList.toggle("theme-dark", dark);
const android = params.has("android");
if (android) document.documentElement.setAttribute("data-qg-skin", "modernist");

createRoot(document.getElementById("root")!).render(<OfflineModeShell
  session={{ userId: "fixture", email: "layout-fixture@example.test", offlineUntil: Date.UTC(2026, 11, 9) / 1000, entitlement: null }}
  android={android}
  entitled={!params.has("unpaid")}
  page="mesh"
  title="Qguard Mesh"
  theme={dark ? "dark" : "light"}
  onToggleTheme={() => undefined}
  onNavigate={() => undefined}
  onReconnect={async () => false}
  onSignInOnline={async () => undefined}
  onSignOut={async () => undefined}
>
  <div className="shell-card p-6 text-sm text-ink-700">Layout fixture: the Mesh discovery radar renders here.</div>
</OfflineModeShell>);
