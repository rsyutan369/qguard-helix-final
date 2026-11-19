// Local Vite-only layout harness for the sign-in device key recovery screen.
// Not imported by the app and not part of dist. The account and detail text
// are explicit layout fixtures; the buttons do nothing here.
import { createRoot } from "react-dom/client";
import "../src/styles/globals.css";
import { DeviceKeyRecoveryScreen } from "../src/components/auth/DeviceKeyRecoveryScreen";

const params = new URLSearchParams(location.search);
document.documentElement.classList.toggle("theme-dark", params.get("theme") === "dark");
const error = params.get("error") ? "This device's keys still could not be opened." : null;

createRoot(document.getElementById("root")!).render(<DeviceKeyRecoveryScreen
  recovery={{ account: "layout-fixture@example.test", detail: "DEVICE_KEYS_UNREADABLE: layout fixture detail", error, busy: false }}
  onRetry={async () => false} onReset={async () => false} onSignOut={async () => undefined} />);
