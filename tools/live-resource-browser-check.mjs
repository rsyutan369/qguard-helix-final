// Runs the real React hook with offline auth and transport inputs in Chrome.
import { execFile } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { build } from 'esbuild';

const authStub = `
  import { useSyncExternalStore } from 'react';
  const listeners = new Set();
  let auth;
  export function signIn(id) {
    const user = { id };
    auth = { user, session: { user, access_token: id } };
    for (const listener of listeners) listener();
  }
  export function useAuth() {
    return useSyncExternalStore((listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    }, () => auth);
  }
`;

const entry = String.raw`
  import React from 'react';
  import { createRoot } from 'react-dom/client';
  import { useLiveResource } from './src/hooks/use-live-resource.ts';
  import { signIn } from '@/contexts/auth-context';

  const watermark = '2026-11-16T00:00:00.000Z';
  const snapshots = new Map();
  const requests = new Map();
  let oldRequest;
  let resource;
  let expire;
  const setTimer = window.setTimeout.bind(window);
  window.setTimeout = (fn, delay, ...args) => {
    if (delay === 65000) expire = () => fn(...args);
    return setTimer(fn, delay, ...args);
  };
  const assert = (condition, what) => { if (!condition) throw new Error(what); };
  const wait = async (condition, what) => {
    for (let index = 0; index < 120; index += 1) {
      if (condition()) return;
      await new Promise((resolve) => setTimer(resolve, 5));
    }
    throw new Error(what);
  };
  const json = (owner) => Response.json({data: {owner, generatedAt: watermark}});
  const send = (id, type, data) => snapshots.get(id).enqueue(new TextEncoder().encode(
    type === 'heartbeat' ? [': heartbeat', '', ''].join(String.fromCharCode(10)) :
      ['event: ' + type, 'data: ' + JSON.stringify(data), '', ''].join(String.fromCharCode(10)),
  ));
  window.fetch = async (url, options) => {
    const id = options.headers.Authorization.split(' ')[1];
    if (!String(url).includes('/stream')) {
      if (id === 'A') return new Promise((resolve) => { oldRequest = { resolve, signal: options.signal }; });
      return json(id);
    }
    requests.set(id, (requests.get(id) ?? 0) + 1);
    if (id === 'C') return new Response('<html>Sign in</html>', { headers: { 'Content-Type': 'text/html' } });
    const stream = new ReadableStream({ start(controller) {
      snapshots.set(id, controller);
      options.signal.addEventListener('abort', () => controller.error(options.signal.reason), { once: true });
    } });
    return new Response(stream, { headers: { 'Content-Type': 'text/event-stream' } });
  };
  function Harness() {
    resource = useLiveResource({ url: '/audit', streamUrl: '/audit/stream', event: 'model', empty: null, channelPrefix: 'audit' });
    return null;
  }

  async function verify() {
    signIn('A');
    createRoot(document.querySelector('#root')).render(<Harness />);
    await wait(() => snapshots.has('A'), 'account A did not connect');
    assert(!resource.sseConnected, 'headers marked the stream Live before the first model');
    send('A', 'model', {owner: 'A', generatedAt: watermark, fingerprint: 'a'});
    await wait(() => resource.data?.owner === 'A' && resource.sseConnected, 'account A did not render');
    void resource.refresh({ force: true });
    await wait(() => oldRequest, 'account A request did not start');
    signIn('B');
    await wait(() => snapshots.has('B'), 'account B did not connect');
    assert(resource.data === null && oldRequest.signal.aborted, 'account B retained account A data or request');
    send('B', 'model', {owner: 'B', generatedAt: watermark, fingerprint: 'b'});
    await wait(() => resource.data?.owner === 'B' && resource.sseConnected, 'account B did not render');
    oldRequest.resolve(json('A'));
    await new Promise((resolve) => setTimer(resolve, 15));
    assert(resource.data.owner === 'B', 'delayed account A data replaced account B data');
    const previousReceipt = resource.lastReceivedAt;
    send('B', 'model-unchanged', {fingerprint: 'b', checkedAt: watermark});
    await wait(() => resource.lastReceivedAt !== previousReceipt, 'unchanged frame was not processed');
    assert(resource.lastVerifiedAt === watermark, 'cached watermark was replaced with receipt time');
    send('B', 'model-error', {message: 'Unavailable'});
    await wait(() => resource.transport === 'polling' && !resource.sseConnected, 'error frame did not degrade the stream');
    resource.reconnect();
    await wait(() => requests.get('B') >= 2, 'Reconnect did not restart the stream');
    send('B', 'model', {owner: 'B', generatedAt: watermark, fingerprint: 'b'});
    await wait(() => resource.sseConnected, 'stream did not recover');
    send('B', 'heartbeat');
    expire();
    await wait(() => resource.transport === 'polling' && !resource.sseConnected, 'heartbeat kept a stalled stream Live');
    signIn('C');
    await wait(() => resource.transport === 'polling' && resource.data?.owner === 'C', 'non-SSE HTML did not fall back to REST');
    assert(!resource.sseConnected, 'non-SSE HTML connected the stream');
  }
  verify().then(() => { document.body.textContent = 'PASS live-resource browser check'; }, (error) => {
    document.body.textContent = 'FAIL ' + error.message;
  });
`;

const bundle = await build({
  stdin: { contents: entry, loader: 'tsx', resolveDir: process.cwd() },
  bundle: true,
  write: false,
  define: { 'process.env.NODE_ENV': '"production"' },
  plugins: [{
    name: 'offline-dashboard-edges',
    setup(builder) {
      builder.onResolve({ filter: /^@\/(contexts\/auth-context|lib\/supabase)$/ }, (args) => ({ path: args.path, namespace: 'offline' }));
      builder.onLoad({ filter: /.*/, namespace: 'offline' }, (args) => ({
        contents: args.path.endsWith('auth-context') ? authStub : 'export const supabase = {};',
        resolveDir: process.cwd(),
      }));
    },
  }],
});

const temp = mkdtempSync(join(tmpdir(), 'qguard-live-browser-'));
const profile = join(temp, 'profile');
mkdirSync(profile);
const html = join(temp, 'check.html');
writeFileSync(html, `<!doctype html><meta charset="utf-8"><body><div id="root"></div><script>${bundle.outputFiles[0].text.replaceAll('</script', '<\\/script')}</script></body>`);
const chrome = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const { stdout } = await promisify(execFile)(chrome, [
  '--headless', '--disable-gpu', '--no-first-run', '--disable-background-networking', '--disable-extensions',
  '--dump-dom', '--virtual-time-budget=6000', `--user-data-dir=${profile}`, pathToFileURL(html).href,
], { timeout: 30_000, windowsHide: true });
const outcome = /<body>(PASS live-resource browser check|FAIL [^<]*)<\/body>/.exec(stdout)?.[1];
console.log(outcome ?? 'No browser assertion result received');
process.exitCode = outcome?.startsWith('PASS') ? 0 : 1;
