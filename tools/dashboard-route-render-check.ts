/**
 * Signed-in render check for dashboard routes, in headless system Chrome.
 *
 *   npx tsx tools/dashboard-route-render-check.ts <outDir> [email] [origin] [route …]
 *   (env: THEME=light|dark forces a theme, SETTLE_MS overrides the 14 s wait,
 *    ACTION_JS runs an async expression after settle — e.g. click a node — before capture)
 *
 * For each route it signs a throwaway magic-link session into localStorage,
 * loads the page, waits for it to settle, and records: uncaught exceptions,
 * console errors, failed /api/ requests, whether an error boundary rendered,
 * any access token that leaked into a request URL, the visible text, and a
 * screenshot. Exit code 1 if any route has an exception, an error boundary, a
 * failed API request or a token in a URL.
 *
 * Drives Chrome over CDP with Node's built-in WebSocket — Playwright is not
 * installed here. The session is signed out locally at the end.
 */
import 'dotenv/config'
import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createClient } from '@supabase/supabase-js'

const DEFAULT_ROUTES = [
  '/dashboard/assets',
  '/dashboard/cbom',
  '/dashboard/migration-intelligence',
  '/dashboard/migration-planner',
  '/dashboard/migration-sandbox',
]
const OUT = process.argv[2] || '.'
const EMAIL = process.argv[3] || 'zachmatthew369@gmail.com'
const BASE = process.argv[4] || 'http://localhost:3000'
const ROUTES = process.argv.slice(5).length ? process.argv.slice(5) : DEFAULT_ROUTES
const CHROME = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
const PORT = 9400 + Math.floor(Math.random() * 400)
const SUPA = process.env.VITE_SUPABASE_URL!
const SETTLE_MS = Number(process.env.SETTLE_MS || 14_000)
const THEME = process.env.THEME

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
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.ws.send(JSON.stringify({ id, method, params }))
    })
  }
  on(listener: (method: string, params: any) => void) { this.listeners.push(listener) }
}

async function main() {
  mkdirSync(OUT, { recursive: true })
  const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email: EMAIL })
  if (error) throw error
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: otp, error: otpError } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpError) throw otpError
  const session = otp.session!
  const storageKey = `sb-${new URL(SUPA).hostname.split('.')[0]}-auth-token`

  const profile = mkdtempSync(join(tmpdir(), 'qg-render-'))
  const chrome = spawn(CHROME, [
    '--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check', '--disable-gpu', '--hide-scrollbars',
    '--window-size=1600,2600', 'about:blank',
  ], { stdio: 'ignore' })

  let failedRoutes = 0
  try {
    let target: any = null
    for (let i = 0; i < 40 && !target; i += 1) {
      await sleep(250)
      try {
        const list = (await (await fetch(`http://127.0.0.1:${PORT}/json`)).json()) as any[]
        target = list.find((t) => t.type === 'page')
      } catch { /* not up yet */ }
    }
    if (!target) throw new Error('Chrome did not expose a debuggable page')
    const ws = new WebSocket(target.webSocketDebuggerUrl)
    await new Promise<void>((resolve, reject) => { ws.addEventListener('open', () => resolve()); ws.addEventListener('error', () => reject(new Error('CDP socket failed'))) })
    const cdp = new Cdp(ws)

    let exceptions: string[] = []
    let consoleErrors: string[] = []
    let failedApi: string[] = []
    let tokenUrls: string[] = []
    const requestUrl = new Map<string, string>()
    cdp.on((method, params) => {
      if (method === 'Runtime.exceptionThrown') {
        exceptions.push(String(params.exceptionDetails?.exception?.description || params.exceptionDetails?.text || 'exception').slice(0, 400))
      } else if (method === 'Runtime.consoleAPICalled' && params.type === 'error') {
        consoleErrors.push((params.args || []).map((a: any) => a.value ?? a.description ?? '').join(' ').slice(0, 300))
      } else if (method === 'Network.requestWillBeSent') {
        const url = String(params.request?.url || '')
        requestUrl.set(params.requestId, url)
        if (url.startsWith(BASE) && (url.includes(session.access_token) || /[?&](token|access_token)=/.test(url))) tokenUrls.push(url.split('?')[0])
      } else if (method === 'Network.responseReceived') {
        const url = String(params.response?.url || '')
        if (url.includes('/api/') && params.response.status >= 400) failedApi.push(`${params.response.status} ${url.replace(BASE, '')}`)
      }
    })
    await cdp.send('Runtime.enable')
    await cdp.send('Network.enable')
    await cdp.send('Page.enable')
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1600, height: 2600, deviceScaleFactor: 1, mobile: false })

    // Seed the session on the app's origin before any dashboard route loads.
    await cdp.send('Page.navigate', { url: `${BASE}/robots.txt` })
    await sleep(1500)
    await cdp.send('Runtime.evaluate', { expression: `localStorage.setItem(${JSON.stringify(storageKey)}, ${JSON.stringify(JSON.stringify(session))})` })
    // THEME=light|dark renders the routes in that theme (same key the theme context reads).
    if (THEME) await cdp.send('Runtime.evaluate', { expression: `localStorage.setItem('qguard-theme-mode-v1', ${JSON.stringify(THEME)})` })

    for (const route of ROUTES) {
      exceptions = []; consoleErrors = []; failedApi = []; tokenUrls = []
      await cdp.send('Page.navigate', { url: BASE + route })
      await sleep(SETTLE_MS)
      const evaluate = async (expression: string) => (await cdp.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })).result?.value
      await evaluate('new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))')
      // ACTION_JS: optional async expression run after settle (clicks, keyboard), its result logged.
      if (process.env.ACTION_JS) {
        const outcome = await evaluate(process.env.ACTION_JS)
        console.log(`  action → ${JSON.stringify(outcome)}`)
        await sleep(Number(process.env.ACTION_SETTLE_MS || 1500))
      }
      const text = String(await evaluate('document.body.innerText') || '')
      const path = String(await evaluate('location.pathname') || '')
      // A query string is not part of location.pathname — compare paths only.
      const routePath = route.split('?')[0]
      const boundary = /something went wrong|unexpected application error|error boundary/i.test(text)
      const stillLoading = /^\s*(loading|classifying)[^\n]*…?\s*$/im.test(text.slice(0, 400)) && text.length < 600
      const name = route.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '')
      const shot = await cdp.send('Page.captureScreenshot', { format: 'png' })
      writeFileSync(join(OUT, `${name}.png`), Buffer.from(shot.data, 'base64'))
      writeFileSync(join(OUT, `${name}.txt`), text)
      const realConsole = consoleErrors.filter((e) => !/fonts\.g(oogleapis|static)|favicon|ResizeObserver loop/i.test(e))
      const bad = exceptions.length > 0 || boundary || failedApi.length > 0 || tokenUrls.length > 0 || path !== routePath || stillLoading
      if (bad) failedRoutes += 1
      console.log(`${bad ? 'FAIL' : 'PASS'}  ${route}  text=${text.length}ch  exceptions=${exceptions.length}  consoleErrors=${realConsole.length}  failedApi=${failedApi.length}  tokenInUrl=${tokenUrls.length}${path !== routePath ? `  redirected→${path}` : ''}${boundary ? '  ERROR-BOUNDARY' : ''}${stillLoading ? '  STILL-LOADING' : ''}`)
      for (const e of [...new Set(exceptions)].slice(0, 5)) console.log(`      exception: ${e}`)
      for (const e of [...new Set(realConsole)].slice(0, 5)) console.log(`      console:   ${e}`)
      for (const e of [...new Set(failedApi)].slice(0, 8)) console.log(`      api:       ${e}`)
      for (const e of [...new Set(tokenUrls)].slice(0, 5)) console.log(`      token url: ${e}`)
    }
    ws.close()
  } finally {
    chrome.kill()
    await anon.auth.signOut({ scope: 'local' }).catch(() => undefined)
  }
  process.exit(failedRoutes ? 1 : 0)
}

main().catch((err) => { console.error(err); process.exit(1) })
