// Captures Play Store screenshots from tools/store-screens.html with headless
// Chrome over CDP (no Playwright needed), then composes framed 1080x1920
// store images from tools/store-frame.html.
//   node tools/store-screens-capture.mjs [raw|frame|all] [dark|light]
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const mode = process.argv[2] || "all";
const theme = process.argv[3] === "light" ? "light" : "dark";
const suffix = theme === "light" ? "-light" : "";
const base = (process.env.QGUARD_PREVIEW_URL || "http://localhost:5174").replace(/\/$/, "");
const out = path.resolve("artifacts/play-store");
const rawDir = path.join(out, `raw${suffix}`);
const finalDir = path.join(out, `phone${suffix}`);
await fs.mkdir(rawDir, { recursive: true });
await fs.mkdir(finalDir, { recursive: true });
const chrome = process.env.CHROME || "C:/Program Files/Google/Chrome/Application/chrome.exe";
const port = 9400 + Math.floor(Math.random() * 400);
const profile = await fs.mkdtemp(path.join(os.tmpdir(), "qg-store-"));
const proc = spawn(chrome, ["--headless=new", `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, "--hide-scrollbars", "--force-color-profile=srgb", "--no-first-run", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let target;
for (let i = 0; i < 50 && !target; i++) {
  try { target = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((t) => t.type === "page"); } catch { await sleep(200); }
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let id = 0; const pending = new Map(); const errors = [];
ws.addEventListener("message", (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) { const p = pending.get(msg.id); pending.delete(msg.id); msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result); }
  if (msg.method === "Runtime.exceptionThrown") errors.push(msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text);
});
const send = (method, params = {}) => new Promise((resolve, reject) => { const n = ++id; pending.set(n, { resolve, reject }); ws.send(JSON.stringify({ id: n, method, params })); });
await send("Page.enable"); await send("Runtime.enable");
const evaluate = async (expression) => (await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })).result.value;
const goto = async (url) => { await send("Page.navigate", { url }); for (let i = 0; i < 100; i++) { await sleep(150); if (await evaluate("document.readyState") === "complete") return; } };
const shot = async (file) => { const { data } = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false }); await fs.writeFile(file, Buffer.from(data, "base64")); };

const SCREENS = [
  ["01-onboarding-splash", "onboarding", 2600],
  ["02-onboarding-private", "onboarding", 5200],
  ["03-dashboard", "dashboard", 3500],
  ["04-chats", "chats", 3000],
  ["05-secure-chat", "thread", 2500],
  ["06-quantum-vault", "vault", 4500],
  ["07-vault-lock-pattern", "vault-lock", 2500],
  ["08-hidden-vault", "hidden", 3500],
  ["09-mesh-radar", "mesh", 3500],
  ["10-mesh-chat", "mesh-chat", 2500],
  ["11-xfer-transfer", "xfer-transfer", 3000],
  ["12-calls", "calls", 3000],
  ["13-settings", "settings", 3000],
  ["14-call", "call", 2500],
];

if (mode === "raw" || mode === "all") {
  await send("Emulation.setDeviceMetricsOverride", { width: 393, height: 852, deviceScaleFactor: 3, mobile: true });
  await send("Emulation.setUserAgentOverride", { userAgent: "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36" });
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
  await goto(`${base}/tools/store-screens.html?screen=dashboard`);
  await evaluate(`localStorage.setItem('qguard-messaging-theme','${theme}'); localStorage.removeItem('qguard_mobile_onboarding_done'); true`);
  for (const [name, screen, wait] of SCREENS) {
    await goto(`${base}/tools/store-screens.html?screen=${screen}`);
    await evaluate("document.fonts.ready.then(()=>true)");
    await sleep(wait);
    await shot(path.join(rawDir, `${name}.png`));
    const unknown = await evaluate("[...(window.__qgUnknown||[])].join(',')");
    console.log(`raw ${name}${unknown ? `  (native calls without a fixture: ${unknown})` : ""}`);
  }
}

// Captions: headline + one supporting line per store image.
const FRAMES = [
  ["02-onboarding-private", "Talk. Share.\nStay private.", "End-to-end encrypted messaging, calls and storage in one app."],
  ["03-dashboard", "Quantum-safe,\nat a glance", "See every cryptographic layer protecting your account, live."],
  ["05-secure-chat", "Messages no one\nelse can read", "Hybrid ML-KEM + X25519 encryption on every message and file."],
  ["06-quantum-vault", "Your private\nQuantum Vault", "Photos, videos and documents encrypted with AES-256-GCM on your device."],
  ["08-hidden-vault", "A vault nobody\nknows exists", "Hidden vaults open only with their own secret pattern."],
  ["07-vault-lock-pattern", "Locked by PIN,\npassword or pattern", "Every protected area asks again. Auto-lock when you step away."],
  ["09-mesh-radar", "No signal?\nStill connected.", "Qguard Mesh finds trusted devices nearby over Bluetooth and Wi-Fi."],
  ["10-mesh-chat", "Off-grid\nencrypted chat", "Message trusted devices with no internet, sealed end to end."],
  ["11-xfer-transfer", "Send big files\nfast and offline", "Qguard XFER moves folders device-to-device, verified file by file."],
  ["04-chats", "All your chats,\nsealed", "One-to-one and group conversations, encrypted on every device."],
];

// Light set: the same story, with the cryptography each screen really uses.
// Every chip below was checked against the code on 2026-11-12:
//   chat     src-tauri/src/pq_ratchet.rs, crypto/hybrid_kex.rs, message_crypto.rs
//   calls    src-tauri/src/commands/calls.rs, src/lib/call-frame-crypto.ts
//   vault    src-tauri/src/vault_stream.rs, crypto/passcode.rs
//   hidden   src-tauri/src/vault/hidden.rs
//   mesh     src-tauri/src/offline/session.rs, offline/relay.rs
//   xfer     src-tauri/src/offline/session.rs, offline/transfer.rs
// Do not add a chip here without finding it in the code first.
const CHAT = ["ML-KEM-1024 + X25519", "ML-DSA-65 + Ed25519", "AES-256-GCM", "Post-quantum ratchet"];
const OFFLINE = ["ML-KEM-768 + X25519", "ML-DSA-65 + Ed25519", "AES-256-GCM"];
const SUMMARY = [
  ["Secure Chat", ["ML-KEM-1024 + X25519", "ML-DSA-65 + Ed25519", "AES-256-GCM", "HMAC-SHA3-256 ratchet"]],
  ["Voice & video calls", ["ML-KEM-1024 + X25519", "ML-DSA-65 + Ed25519", "AES-256-GCM per frame", "HKDF-SHA3-256"]],
  ["Quantum Vault", ["AES-256-GCM", "Argon2id unlock", "ML-DSA-87 signed", "ML-KEM-1024 sharing", "SHA3-256"]],
  ["Hidden Vault", ["AES-256-GCM", "Argon2id 64 MiB", "Android Keystore", "12-word recovery"]],
  ["Qguard Mesh", [...OFFLINE, "Sealed multi-hop"]],
  ["Qguard XFER", [...OFFLINE, "SHA3-256 per file"]],
];
const FRAMES_LIGHT = [
  ["02-onboarding-private", "Talk. Share.\nStay private.", "Post-quantum encryption on every message, call and file.", ["ML-KEM", "ML-DSA", "AES-256-GCM", "Argon2id"]],
  ["SUMMARY", "Quantum encryption,\neverywhere", "What protects each part of Qguard, taken from the app's code."],
  ["05-secure-chat", "Messages no one\nelse can read", "New keys for every message, with a fresh ML-KEM exchange every 50.", CHAT],
  ["14-call", "Quantum-encrypted\nvoice & video calls", "A new key for every call. Compare safety numbers to verify.", ["ML-KEM-1024 + X25519", "ML-DSA-65 + Ed25519", "AES-256-GCM per frame"]],
  ["06-quantum-vault", "Your private\nQuantum Vault", "Files sealed in 1 MiB chunks; only your PIN or password unlocks them.", ["AES-256-GCM", "Argon2id", "ML-DSA-87 signed", "ML-KEM-1024 sharing"]],
  ["08-hidden-vault", "A vault nobody\nknows exists", "No names, no headers: just encrypted noise until you draw its pattern.", ["AES-256-GCM", "Argon2id 64 MiB", "Android Keystore", "12-word recovery"]],
  ["10-mesh-chat", "Off-grid\nencrypted chat", "No internet needed. Sealed end to end, even across relays.", OFFLINE],
  ["11-xfer-transfer", "Send big files\nfast and offline", "Device to device, every file verified on arrival.", [...OFFLINE, "SHA3-256 per file"]],
  ["03-dashboard", "Quantum-safe,\nat a glance", "Every layer measured live on your own devices.", ["ML-KEM-1024", "ML-DSA-65", "AES-256-GCM"]],
  ["07-vault-lock-pattern", "Locked by PIN,\npassword or pattern", "Every unlock is stretched with Argon2id, so guessing stays slow.", ["Argon2id", "HKDF-SHA3-256", "Auto-lock"]],
  ["09-mesh-radar", "No signal?\nStill connected.", "Trusted devices nearby over Bluetooth and Wi-Fi.", OFFLINE],
];
if (mode === "frame" || mode === "all") {
  await send("Emulation.setDeviceMetricsOverride", { width: 1080, height: 1920, deviceScaleFactor: 1, mobile: false });
  const frameUrl = `${base}/tools/store-frame.html`;
  const rawUrl = (name) => `${base}/artifacts/play-store/raw${suffix}/${name}.png`;
  let n = 0;
  // Warm-up: the first file:// render in a fresh headless profile can paint the image black.
  await goto(`${frameUrl}?${new URLSearchParams({ img: rawUrl(FRAMES[0][0]), title: "x", sub: "x" })}`);
  await sleep(1500);
  await fs.rm(finalDir, { recursive: true, force: true }); await fs.mkdir(finalDir, { recursive: true });
  for (const [raw, title, sub, chips] of theme === "light" ? FRAMES_LIGHT : FRAMES) {
    n++;
    const q = raw === "SUMMARY"
      ? new URLSearchParams({ summary: JSON.stringify(SUMMARY), title, sub, theme, foot: "ML-KEM: NIST FIPS 203 · ML-DSA: NIST FIPS 204 · each paired with a classical algorithm (X25519, Ed25519), so both would have to be broken." })
      : new URLSearchParams({ img: rawUrl(raw), title, sub, i: String(n), theme, ...(chips ? { chips: chips.join("|") } : {}) });
    await goto(`${frameUrl}?${q}`);
    for (let t = 0; t < 40; t++) {
      if (await evaluate("document.fonts.status==='loaded' && [...document.images].every(i=>i.complete && i.naturalWidth>0)")) break;
      await sleep(150);
    }
    await sleep(900);
    if (process.env.DEBUG_FRAMES) console.log(await evaluate("JSON.stringify([...document.images].map(i=>[i.naturalWidth,i.complete,i.currentSrc.slice(-30)]))"));
    const file = `${String(n).padStart(2, "0")}-${raw === "SUMMARY" ? "encryption-overview" : raw.replace(/^\d+-/, "")}.png`;
    await shot(path.join(finalDir, file));
    console.log(`frame ${file}`);
  }
  // Feature graphic 1024x500.
  await send("Emulation.setDeviceMetricsOverride", { width: 1024, height: 500, deviceScaleFactor: 1, mobile: false });
  const fq = new URLSearchParams({ feature: "1", theme, a: rawUrl("03-dashboard"), b: rawUrl("05-secure-chat"), c: rawUrl("09-mesh-radar") });
  await goto(`${frameUrl}?${fq}`);
  await evaluate("Promise.all([document.fonts.ready, ...[...document.images].map(i=>i.decode().catch(()=>0))]).then(()=>true)");
  await sleep(400);
  await shot(path.join(out, `feature-graphic-1024x500${suffix}.png`));
  console.log("feature graphic");
}
if (errors.length) console.log("page errors:", [...new Set(errors)].slice(0, 8));
ws.close(); proc.kill();
await sleep(500);
await fs.rm(profile, { recursive: true, force: true }).catch(() => undefined);
