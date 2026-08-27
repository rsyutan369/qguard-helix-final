import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { applyAndroidSkin } from "./lib/android-skin";
import "./styles/globals.css";
// Mobile design system (Cold Fusion). Loaded after globals.css so the mobile
// token layer wins over the desktop base for the phone/Android surfaces.
import "./styles/mobile.css";
// Modernist skin (Android build only). Both sheets are scoped to
// html[data-qg-skin="modernist"], so they are inert until applyAndroidSkin()
// sets that attribute -- which it only does on the Android runtime.
import "./styles/android-modernist.css";
import "./styles/android-modernist-pages.css";

// Applied BEFORE the first render so a cold launch paints Modernist straight
// away instead of flashing the Cold Fusion palette for a frame.
applyAndroidSkin();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
