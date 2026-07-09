/// <reference types="vite/client" />

// Build-time application version, injected by Vite `define` from
// src-tauri/tauri.conf.json (see vite.config.ts → readAppVersion).
declare const __APP_VERSION__: string;
