// Probe every post-login native command in sequence via CDP. AppState is
// already authenticated (auth_sync_session was called for this user id).
import WebSocket from "ws";
import http from "node:http";

const port = process.argv[2] || "9222";
const uid = process.argv[3] || "00000000-0000-4000-8000-0000000000aa";

function getJSON(path) {
  return new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path }, (res) => {
      let b = ""; res.on("data", (c) => (b += c)); res.on("end", () => { try { resolve(JSON.parse(b)); } catch (e) { reject(e); } });
    }).on("error", reject);
  });
}

const cmds = [
  ["workspace_status", {}],
  ["security_hardening_status", {}],
  ["keys_upload_identity_bundle", { userId: uid }],
  ["keys_upload_signed_prekey", { userId: uid }],
  ["keys_upload_one_time_prekeys", { userId: uid }],
  ["keys_replenish_one_time_prekeys", { userId: uid, needed: 8 }],
  ["vault_recovery_status", {}],
];

const expr = `(async () => {
  const invoke = window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke;
  if (!invoke) return 'NO_TAURI';
  const cmds = ${JSON.stringify(cmds)};
  const out = [];
  for (const [name, args] of cmds) {
    const t0 = performance.now();
    try {
      const r = await invoke(name, args);
      out.push(name + ' -> OK (' + Math.round(performance.now()-t0) + 'ms) ' + JSON.stringify(r).slice(0,80));
    } catch (e) {
      out.push(name + ' -> ERR (' + Math.round(performance.now()-t0) + 'ms) ' + (e && e.message ? e.message : String(e)));
    }
  }
  return out.join('\\n');
})()`;

(async () => {
  const targets = await getJSON("/json");
  const page = targets.find((t) => t.type === "page" && t.webSocketDebuggerUrl) || targets[0];
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0;
  const send = (method, params) => new Promise((resolve) => {
    const mid = ++id;
    const onMsg = (data) => { const m = JSON.parse(data); if (m.id === mid) { ws.off("message", onMsg); resolve(m); } };
    ws.on("message", onMsg); ws.send(JSON.stringify({ id: mid, method, params }));
  });
  ws.on("close", () => console.log("WS_CLOSED (process may have crashed)"));
  await new Promise((r) => ws.on("open", r));
  await send("Runtime.enable", {});
  const res = await Promise.race([
    send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true, timeout: 90000 }),
    new Promise((r) => setTimeout(() => r({ timeout: true }), 95000)),
  ]);
  if (res.timeout) console.log("TIMEOUT/NO-RESPONSE (likely native crash mid-probe)");
  else if (res.result && res.result.result) console.log(res.result.result.value);
  else console.log(JSON.stringify(res.error || res));
  ws.close(); process.exit(0);
})().catch((e) => { console.log("SCRIPT_ERROR", e.message); process.exit(1); });
