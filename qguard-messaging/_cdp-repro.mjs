// Reproduce the post-login native path (auth_sync_session -> ensure_identity ->
// PQC keygen) WITHOUT real Supabase credentials, by invoking the Tauri command
// directly from the WebView via CDP with a structurally-valid but unsigned JWT.
// validate_token_claims() only base64-decodes the payload and checks sub/exp;
// it does NOT verify the signature, so a crafted token reaches the keygen.
//
// Usage: node cdp-repro.mjs <cdpPort> [userId]
import WebSocket from "ws";
import http from "node:http";

const port = process.argv[2] || "9222";
const userId = process.argv[3] || "00000000-0000-4000-8000-0000000000aa";

function getJSON(path) {
  return new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
      });
    }).on("error", reject);
  });
}

const expr = `(async () => {
  const uid = ${JSON.stringify(userId)};
  const b64 = (o) => btoa(JSON.stringify(o)).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
  const now = Math.floor(Date.now()/1000);
  const exp = now + 3600;
  const jwt = b64({alg:'HS256',typ:'JWT'}) + '.' + b64({sub:uid, exp}) + '.' + 'sig';
  const invoke = (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke);
  if (!invoke) return 'NO_TAURI_INTERNALS';
  try {
    const r = await invoke('auth_sync_session', {
      userId: uid, email: 'qa@qguard.local', tier: 'user',
      accessToken: jwt, expiresAt: exp, freshLogin: true,
    });
    return 'OK: ' + JSON.stringify(r).slice(0, 200);
  } catch (e) {
    return 'ERR: ' + (e && e.message ? e.message : String(e));
  }
})()`;

(async () => {
  const targets = await getJSON("/json");
  const page = targets.find((t) => t.type === "page" && t.webSocketDebuggerUrl) || targets[0];
  if (!page || !page.webSocketDebuggerUrl) {
    console.log("NO_PAGE_TARGET", JSON.stringify(targets).slice(0, 400));
    process.exit(2);
  }
  console.log("Target:", page.url);
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0;
  const send = (method, params) =>
    new Promise((resolve) => {
      const mid = ++id;
      const onMsg = (data) => {
        const msg = JSON.parse(data);
        if (msg.id === mid) { ws.off("message", onMsg); resolve(msg); }
      };
      ws.on("message", onMsg);
      ws.send(JSON.stringify({ id: mid, method, params }));
    });

  ws.on("close", () => console.log("WS_CLOSED (process may have crashed)"));
  ws.on("error", (e) => console.log("WS_ERROR", e.message));

  await new Promise((r) => ws.on("open", r));
  await send("Runtime.enable", {});
  console.log("Invoking auth_sync_session (keygen) ...");
  const started = Date.now();
  const res = await Promise.race([
    send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true, timeout: 60000 }),
    new Promise((r) => setTimeout(() => r({ timeout: true }), 65000)),
  ]);
  const ms = Date.now() - started;
  if (res.timeout) console.log(`RESULT after ${ms}ms: TIMEOUT/NO-RESPONSE (likely native crash)`);
  else console.log(`RESULT after ${ms}ms:`, JSON.stringify(res.result || res.error));
  ws.close();
  process.exit(0);
})().catch((e) => { console.log("SCRIPT_ERROR", e.message); process.exit(1); });
