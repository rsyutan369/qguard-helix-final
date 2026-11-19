/**
 * Real Time Scanning — interaction stability probe (real mouse, realistic window).
 *
 *   npx tsx tools/live-scan-ui-probe.ts <outDir> [origin] [email]
 *
 * Starts a live scan through the API, opens the page in headless Chrome at a
 * normal 1440×900 window, and while the scan streams:
 *  • samples every 250 ms: viewport transform, live nodes in the DOM, nodes
 *    actually on screen inside the canvas, canvas rect, scroll offsets of every
 *    scrolled ancestor;
 *  • hovers cards and CLICKS a card with real CDP mouse input;
 *  • after completion, presses "Fit to screen" and the full-screen toggle.
 * Reports jitter (viewport/scroll changes per second without user input),
 * blank frames (nodes exist, none on screen), NaN viewports and errors, and
 * writes screenshots. Deletes the scan history it created.
 */
import 'dotenv/config'
import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createClient } from '@supabase/supabase-js'

const OUT = process.argv[2] || '.'
const BASE = process.argv[3] || 'http://localhost:3000'
const EMAIL = process.argv[4] || 'zachmatthew369@gmail.com'
const TARGETS = (process.env.TARGETS || 'sha256.badssl.com,ecc256.badssl.com,rsa2048.badssl.com').split(',')
const CHROME = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
const SUPA = process.env.VITE_SUPABASE_URL!
const PORT = 9400 + Math.floor(Math.random() * 300)
const W = 1440
const H = 900
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

class Cdp {
  private id = 0
  private pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>()
  private listeners: Array<(method: string, params: any) => void> = []
  constructor(private ws: WebSocket) {
    ws.addEventListener('message', (event) => {
      const msg = JSON.parse(String(event.data))
      if (msg.id && this.pending.has(msg.id)) {
        const p = this.pending.get(msg.id)!
        this.pending.delete(msg.id)
        if (msg.error) p.reject(new Error(msg.error.message))
        else p.resolve(msg.result)
      } else if (msg.method) for (const l of this.listeners) l(msg.method, msg.params)
    })
  }
  send(method: string, params: Record<string, unknown> = {}): Promise<any> {
    const id = ++this.id
    return new Promise((resolve, reject) => { this.pending.set(id, { resolve, reject }); this.ws.send(JSON.stringify({ id, method, params })) })
  }
  on(listener: (method: string, params: any) => void) { this.listeners.push(listener) }
}

const SAMPLE = `(() => {
  const wrap = document.querySelector('.rt-canvas-wrap')
  if (!wrap) return null
  const w = wrap.getBoundingClientRect()
  const live = [...document.querySelectorAll('.react-flow__node-live')]
  const onScreen = live.filter((n) => { const r = n.getBoundingClientRect(); return r.width > 0 && r.right > Math.max(0, w.left) && r.left < Math.min(innerWidth, w.right) && r.bottom > Math.max(0, w.top) && r.top < Math.min(innerHeight, w.bottom) && getComputedStyle(n).visibility !== 'hidden' }).length
  const t = document.querySelector('.react-flow__viewport')?.style.transform || ''
  const scrolls = []
  for (let el = wrap.parentElement; el; el = el.parentElement) if (el.scrollTop || el.scrollLeft) scrolls.push(Math.round(el.scrollTop) + ':' + Math.round(el.scrollLeft))
  const stat = (name) => [...document.querySelectorAll('.rt-stat')].map((s) => s.innerText.split('\\n')).find((p) => p[0] === name)?.[1]
  return { t, live: live.length, onScreen, wrap: [Math.round(w.x), Math.round(w.y), Math.round(w.width), Math.round(w.height)], scroll: scrolls.join('|') + '|win:' + Math.round(scrollY), status: stat('STATUS') || null, drawer: Boolean(document.querySelector('.rt-drawer')), fs: Boolean(document.fullscreenElement) || Boolean(document.querySelector('.rt-canvas-stage.is-fullscreen')) }
})()`

async function main() {
  mkdirSync(OUT, { recursive: true })
  const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email: EMAIL })
  if (error) throw error
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: otp } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  const session = otp.session!
  const storageKey = `sb-${new URL(SUPA).hostname.split('.')[0]}-auth-token`
  const api = (path: string, init?: RequestInit) => fetch(`${BASE}/api/v1/scanner/live${path}`, { ...init, headers: { Authorization: `Bearer ${session.access_token}`, 'Content-Type': 'application/json' } })

  const started = await (await api('/runs', { method: 'POST', body: JSON.stringify({ name: 'UI stability probe', targets: TARGETS, authorized: true, concurrency: 2, targetTimeoutSec: 25 }) })).json()
  const runId = started.run?.id
  if (!runId) throw new Error(`scan did not start: ${JSON.stringify(started)}`)
  console.log(`run ${runId}`)

  const profile = mkdtempSync(join(tmpdir(), 'qg-probe-'))
  const chrome = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, '--no-first-run', '--disable-gpu', `--window-size=${W},${H}`, 'about:blank'], { stdio: 'ignore' })
  const samples: Array<{ at: number; s: any; input: string | null }> = []
  const errors: string[] = []
  try {
    let target: any = null
    for (let i = 0; i < 40 && !target; i++) { await sleep(250); try { target = ((await (await fetch(`http://127.0.0.1:${PORT}/json`)).json()) as any[]).find((t) => t.type === 'page') } catch { /* starting */ } }
    const ws = new WebSocket(target.webSocketDebuggerUrl)
    await new Promise<void>((resolve) => ws.addEventListener('open', () => resolve()))
    const cdp = new Cdp(ws)
    cdp.on((method, params) => {
      if (method === 'Runtime.exceptionThrown') errors.push(`exception: ${String(params.exceptionDetails?.exception?.description || params.exceptionDetails?.text).slice(0, 300)}`)
      if (method === 'Runtime.consoleAPICalled' && (params.type === 'error' || params.type === 'warning')) {
        const text = (params.args || []).map((a: any) => a.value ?? a.description ?? '').join(' ').slice(0, 300)
        if (!/fonts\.g|favicon|Download the React DevTools/i.test(text)) errors.push(`${params.type}: ${text}`)
      }
    })
    await cdp.send('Runtime.enable'); await cdp.send('Page.enable')
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false })
    await cdp.send('Page.navigate', { url: `${BASE}/robots.txt` }); await sleep(1200)
    await cdp.send('Runtime.evaluate', { expression: `localStorage.setItem(${JSON.stringify(storageKey)}, ${JSON.stringify(JSON.stringify(session))})` })
    await cdp.send('Page.navigate', { url: `${BASE}/dashboard/scanner/real-time?run=${runId}` })

    const evaluate = async (expression: string) => (await cdp.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })).result?.value
    const shot = async (name: string) => { const r = await cdp.send('Page.captureScreenshot', { format: 'png' }); writeFileSync(join(OUT, `${name}.png`), Buffer.from(r.data, 'base64')) }
    const mouse = async (type: string, x: number, y: number, extra: Record<string, unknown> = {}) => cdp.send('Input.dispatchMouseEvent', { type, x, y, button: 'none', ...extra })
    const click = async (x: number, y: number) => {
      await mouse('mouseMoved', x, y)
      await mouse('mousePressed', x, y, { button: 'left', clickCount: 1 })
      await mouse('mouseReleased', x, y, { button: 'left', clickCount: 1 })
    }
    const nodeCenter = async (kind: string | null) => evaluate(`(() => {
      const wrap = document.querySelector('.rt-canvas-wrap')?.getBoundingClientRect(); if (!wrap) return null
      const nodes = [...document.querySelectorAll('.react-flow__node-live')].filter((n) => ${kind ? `n.querySelector('.rt-node-kind')?.textContent === ${JSON.stringify(kind)}` : 'true'})
      for (const n of nodes) { const r = n.getBoundingClientRect(); const x = r.x + r.width / 2, y = r.y + r.height / 2
        if (r.width > 20 && x > wrap.left + 10 && x < wrap.right - 10 && y > wrap.top + 10 && y < wrap.bottom - 10 && y > 0 && y < innerHeight) return [Math.round(x), Math.round(y)] }
      return null })()`)

    const t0 = Date.now()
    let input: string | null = null
    let clicked = false
    let hoverDone = 0
    // Scroll the canvas into view like a user would.
    for (let i = 0; i < 30; i++) { await sleep(500); if (await evaluate(`Boolean(document.querySelector('.rt-canvas-wrap'))`)) break }
    await evaluate(`document.querySelector('.rt-canvas-stage').scrollIntoView({ block: 'center', behavior: 'instant' })`)
    await sleep(500)
    await shot('01-start')
    let completeAt = 0
    for (let i = 0; i < 1200; i++) {
      const s = await evaluate(SAMPLE)
      samples.push({ at: Date.now() - t0, s, input })
      input = null
      const elapsed = Date.now() - t0
      if (s && s.live > 8 && hoverDone < 6 && elapsed > 8000 + hoverDone * 2500) {
        const c = await nodeCenter(null)
        if (c) { await mouse('mouseMoved', c[0], c[1]); input = `hover ${c}`; hoverDone++ }
      }
      if (s && s.live > 15 && !clicked && elapsed > 22000) {
        const c = (await nodeCenter('Certificate')) || (await nodeCenter('Asset'))
        if (c) { await click(c[0], c[1]); input = `click ${c}`; clicked = true; await sleep(150); await shot('02-after-click') }
      }
      if (clicked && s?.drawer && elapsed > 30000 && !samples.some((x) => x.input === 'close-drawer')) {
        await cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 })
        await evaluate(`document.querySelector('button[aria-label="Close details"]')?.click()`)
        input = 'close-drawer'
      }
      if (s && /Completed|Failed|Cancelled/.test(s.status || '') && !completeAt) completeAt = Date.now()
      if (completeAt && Date.now() - completeAt > 5000) break
      await sleep(250)
    }
    await shot('03-complete')
    // Fit after the user has moved the view.
    const centre = await evaluate(`(() => { const r = document.querySelector('.rt-canvas-wrap').getBoundingClientRect(); return [Math.round(r.x + r.width / 2), Math.round(r.y + r.height / 2)] })()`)
    for (let i = 0; i < 6; i++) await cdp.send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: centre[0], y: centre[1], deltaX: 0, deltaY: -240 })
    await sleep(600)
    samples.push({ at: Date.now() - t0, s: await evaluate(SAMPLE), input: 'wheel-zoom-in' })
    const fitBtn = await evaluate(`(() => { const b = [...document.querySelectorAll('.rt-stage-toolbar button')].find((button) => button.textContent.trim() === 'Fit to screen'); if (!b) return null; const r = b.getBoundingClientRect(); return [Math.round(r.x + r.width / 2), Math.round(r.y + r.height / 2)] })()`)
    if (fitBtn) { await click(fitBtn[0], fitBtn[1]); await sleep(900) }
    samples.push({ at: Date.now() - t0, s: await evaluate(SAMPLE), input: 'fit' })
    await shot('04-after-fit')
    const fsBtn = await evaluate(`(() => { const b = document.querySelector('.rt-fullscreen-button'); if (!b) return null; const r = b.getBoundingClientRect(); return [Math.round(r.x + r.width / 2), Math.round(r.y + r.height / 2)] })()`)
    if (fsBtn) {
      await click(fsBtn[0], fsBtn[1]); await sleep(1200)
      samples.push({ at: Date.now() - t0, s: await evaluate(SAMPLE), input: 'fullscreen-on' })
      await shot('05-fullscreen')
      await cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 })
      await sleep(900)
      samples.push({ at: Date.now() - t0, s: await evaluate(SAMPLE), input: 'fullscreen-escape' })
    }
  } finally {
    chrome.kill()
    try { await api(`/runs/${runId}`).then(async (r) => { const b = await r.json(); if (b.run?.sessionId) await fetch(`${BASE}/api/v1/scanner/history/${b.run.sessionId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${session.access_token}` } }) }) } catch { /* best effort */ }
  }

  // ---- analysis ----
  writeFileSync(join(OUT, 'samples.json'), JSON.stringify(samples, null, 1))
  const valid = samples.filter((x) => x.s)
  const nan = valid.filter((x) => /NaN|Infinity/.test(x.s.t))
  const blank = valid.filter((x) => x.s.live > 0 && x.s.onScreen === 0 && !/translate\(0px, 0px\) scale\(1\)/.test(x.s.t))
  let viewportChanges = 0, scrollChanges = 0, wrapChanges = 0
  const changeTimes: number[] = []
  for (let i = 1; i < valid.length; i++) {
    const a = valid[i - 1].s, b = valid[i].s
    const userInput = valid[i].input || valid[i - 1].input
    if (a.t !== b.t && !userInput) { viewportChanges++; changeTimes.push(valid[i].at) }
    if (a.scroll !== b.scroll) scrollChanges++
    if (a.wrap.join() !== b.wrap.join()) wrapChanges++
  }
  const span = (valid[valid.length - 1]?.at - valid[0]?.at) / 1000 || 1
  const zooms = valid.map((x) => Number(/scale\(([\d.]+)\)/.exec(x.s.t)?.[1])).filter(Number.isFinite)
  console.log(`samples=${valid.length} over ${span.toFixed(0)}s`)
  console.log(`viewport changes without input: ${viewportChanges} (${(viewportChanges / span).toFixed(2)}/s)  zoom range ${Math.min(...zooms).toFixed(3)}–${Math.max(...zooms).toFixed(3)}`)
  console.log(`scroll changes: ${scrollChanges}   canvas rect changes: ${wrapChanges}`)
  console.log(`blank frames (nodes exist, none on screen): ${blank.length}   NaN viewports: ${nan.length}`)
  for (const x of valid.filter((v) => v.input)) console.log(`  ${String(x.at).padStart(6)}ms ${x.input} → live=${x.s.live} onScreen=${x.s.onScreen} t=${x.s.t} wrap=${x.s.wrap} drawer=${x.s.drawer} fs=${x.s.fs}`)
  for (const b of blank.slice(0, 5)) console.log(`  BLANK @${b.at}ms live=${b.s.live} t=${b.s.t} wrap=${b.s.wrap} scroll=${b.s.scroll}`)
  for (const e of [...new Set(errors)].slice(0, 10)) console.log(`  ${e}`)
}

main().catch((error) => { console.error(error); process.exit(1) })
