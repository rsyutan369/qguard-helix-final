import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles/globals.css";
// Mobile design system (Cold Fusion). Loaded after globals.css so the mobile
// token layer wins over the desktop base for the phone/Android surfaces.
import "./styles/mobile.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

