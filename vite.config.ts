import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import {createHash} from 'node:crypto';
import {mkdirSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {tsImport} from 'tsx/esm/api';
import {defineConfig, loadEnv, type Plugin} from 'vite';

/**
 * Resolve the connect-src allow-list from the configured Supabase project(s) so
 * the production CSP can be tight: only 'self' + the real Supabase HTTPS/WSS
 * origins. A compromised dependency therefore cannot exfiltrate to an arbitrary
 * host. Falls back to the *.supabase.co wildcard when no env is present at build.
 */
function resolveConnectSrc(env: Record<string, string>): string[] {
  const tokens = new Set<string>(["'self'", 'https://*.supabase.co', 'wss://*.supabase.co']);
  // VITE_API_ORIGIN: split-origin API (src/lib/api-origin.ts). VITE_BILLING_API_ORIGIN:
  // optional non-Supabase billing host (src/lib/billing/billing-api.ts). Both are
  // skipped when unset, so the policy is byte-identical to before in that case.
  for (const key of ['VITE_SUPABASE_URL', 'VITE_SUPABASE_FALLBACK_URL', 'VITE_API_ORIGIN', 'VITE_BILLING_API_ORIGIN']) {
    const value = env[key];
    if (!value) continue;
    try {
      const origin = new URL(value).origin;
      tokens.add(origin);
      tokens.add(origin.replace(/^http/, 'ws')); // https→wss, http→ws (realtime)
    } catch {
      /* ignore malformed URL */
    }
  }
  return [...tokens];
}

function buildContentSecurityPolicy(scriptSrc: string, connectSrc: string[]): string {
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' blob: data:",
    "media-src 'self' blob: data:",
    `connect-src ${connectSrc.join(' ')}`,
    "worker-src 'self' blob:",
    "frame-src 'self' blob:",
    "manifest-src 'self'",
    'upgrade-insecure-requests',
  ].join('; ');
}

/**
 * Build-time plugin: inject a strict CSP <meta> into the built index.html. The
 * inline bootstrap script(s) are allow-listed by SHA-256 hash rather than
 * 'unsafe-inline', so injected/reflected scripts cannot execute. Host-agnostic:
 * the policy travels with the HTML regardless of where the static build is served.
 */
function cspMetaPlugin(connectSrc: string[]): Plugin {
  return {
    name: 'qguard-csp-meta',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler(html: string) {
        const hashes: string[] = [];
        const inlineScript = /<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/gi;
        let match: RegExpExecArray | null;
        while ((match = inlineScript.exec(html)) !== null) {
          const code = match[1];
          if (!code) continue;
          hashes.push(`'sha256-${createHash('sha256').update(code, 'utf8').digest('base64')}'`);
        }
        const scriptSrc = `script-src 'self'${hashes.length ? ' ' + hashes.join(' ') : ''}`;
        const csp = buildContentSecurityPolicy(scriptSrc, connectSrc);
        const meta = `<meta http-equiv="Content-Security-Policy" content="${csp}">`;
        return html.replace(/<head>/i, `<head>\n    ${meta}`);
      },
    },
  };
}

/**
 * Website edition (`vite build --mode public`, i.e. `npm run build:public`).
 *
 * The public site is published to static hosting (Cloudflare) and must carry
 * the marketing pages and the free Web assessment only. This plugin swaps the
 * entry to src/main-public.tsx (src/PublicApp.tsx routes), and records every
 * module the bundler actually included in .public-site/modules.json, OUTSIDE
 * the published folder, so tools/deploy/public-site-check.ts can prove that no
 * platform module or engine reached the bundle.
 */
function websiteEditionPlugin(): Plugin {
  return {
    name: 'qguard-website-edition',
    apply: 'build',
    transformIndexHtml: {
      order: 'pre',
      handler(html: string) {
        if (!html.includes('/src/main.tsx')) throw new Error('index.html no longer loads /src/main.tsx; update websiteEditionPlugin');
        return html.replace('/src/main.tsx', '/src/main-public.tsx');
      },
    },
    generateBundle(_options, bundle) {
      const modules = new Set<string>();
      for (const output of Object.values(bundle)) {
        if (output.type !== 'chunk') continue;
        const ids = (output as {moduleIds?: string[]}).moduleIds ?? Object.keys(output.modules ?? {});
        for (const id of ids) {
          const clean = id.replace(/\?.*$/, '').replace(/\\/g, '/');
          const root = rootDir.replace(/\\/g, '/');
          if (clean.startsWith(`${root}/`)) modules.add(clean.slice(root.length + 1));
        }
      }
      const reportDir = path.join(rootDir, '.public-site');
      mkdirSync(reportDir, {recursive: true});
      writeFileSync(path.join(reportDir, 'modules.json'), JSON.stringify([...modules].sort(), null, 2));
    },
  };
}

const rootDir = path.dirname(fileURLToPath(import.meta.url));
const apiServerEntry = path.join(rootDir, 'src/api-server/index.ts');
const viteConfigUrl = pathToFileURL(path.join(rootDir, 'vite.config.ts')).href;
const tsconfigPath = path.join(rootDir, 'tsconfig.json');

export default defineConfig(({mode}) => {
  const env = loadEnv(mode, rootDir, '');
  for (const key of [
    'VITE_SUPABASE_URL',
    'VITE_SUPABASE_ANON_KEY',
    'SUPABASE_SERVICE_ROLE_KEY',
    'VITE_SUPABASE_FALLBACK_URL',
    'VITE_SUPABASE_FALLBACK_ANON_KEY',
    'SUPABASE_FALLBACK_SERVICE_ROLE_KEY',
    'VITE_SUPABASE_USE_FALLBACK',
    'SUPABASE_USE_FALLBACK',
  ]) {
    if (env[key] && !process.env[key]) {
      process.env[key] = env[key];
    }
  }

  // Server-side payment config (PayPal secret, plan ids, webhook id) must reach
  // process.env for the Vite-mounted API in dev. These are NOT VITE_-prefixed,
  // so they are never exposed to the browser bundle. .env is authoritative in
  // dev, so ALWAYS override (no `!process.env[key]` guard) — otherwise a
  // changed credential/plan id stays pinned to the first value the server saw
  // and edits appear to "not take" until a full restart. COPILOT_BYOK_SECRET
  // seals tenants' own model API keys (Sophia BYOK) — server-side only.
  for (const key of Object.keys(env)) {
    if (key.startsWith('PAYPAL_') || key === 'APP_ORIGIN' || key === 'PUBLIC_APP_ORIGIN' || key === 'COPILOT_BYOK_SECRET') {
      if (env[key]) process.env[key] = env[key];
    }
  }

  const connectSrc = resolveConnectSrc(env);
  const websiteEdition = mode === 'public';

  return {
    plugins: [
      react(),
      tailwindcss(),
      cspMetaPlugin(connectSrc),
      ...(websiteEdition ? [websiteEditionPlugin()] : []),
      {
        name: 'api-server',
        configureServer(server) {
          let apiApp: any = null
          let apiAppPromise: Promise<any> | null = null

          /**
           * Which edits must drop the cached API app.
           *
           * `src/api-server/` alone was NOT enough, and the gap was expensive: the
           * routers are thin wrappers over the engines in `src/lib/` (the whole
           * public-scan scanner, the web-scanner, the migration and reporting
           * engines), and those are loaded once through `tsImport` and then held
           * on `apiApp`. Editing an engine therefore changed nothing at runtime —
           * the page reloaded, the frontend hot-updated, and the API kept
           * answering from the module tree it had imported at boot. The symptom
           * is indistinguishable from "my fix doesn't work", which is the worst
           * possible failure mode for a dev loop.
           *
           * `src/lib` and `src/services` are included because the API server
           * imports them; `src/app` and `src/components` are not, because those
           * are client-only and would drop the app on every UI keystroke. The
           * reset is lazy (the next request re-imports), so a false positive here
           * costs one cold import, while a false negative costs a debugging
           * session.
           */
          const API_SOURCE_PREFIXES = ['src/api-server/', 'src/lib/', 'src/services/']

          const isApiSourceFile = (file: string) => {
            const normalizedFile = file.replace(/\\/g, '/')
            const normalizedRoot = rootDir.replace(/\\/g, '/')
            if (!normalizedFile.startsWith(`${normalizedRoot}/`)) return false
            const relative = normalizedFile.slice(normalizedRoot.length + 1)
            return API_SOURCE_PREFIXES.some((prefix) => relative.startsWith(prefix))
          }

          const resetApiServer = () => {
            apiApp = null
            apiAppPromise = null
          }

          const resetSsrLoader = () => {
            const viteServer = server as any
            viteServer._ssrCompatModuleRunner?.close?.()
            viteServer._ssrCompatModuleRunner = undefined
            viteServer.environments?.ssr?.moduleGraph?.invalidateAll?.()
            server.moduleGraph.invalidateAll()
          }

          const isViteTransportTimeout = (err: unknown) => {
            const message = err instanceof Error ? err.message : String(err || '')
            return message.includes('transport invoke timed out') || message.includes('fetchModule')
          }

          const invalidateApiServer = (file: string) => {
            resetApiServer()
            resetSsrLoader()
            const normalizedFile = file.replace(/\\/g, '/')
            void server.moduleGraph.getModuleByUrl(normalizedFile).then((moduleNode) => {
              if (moduleNode) server.moduleGraph.invalidateModule(moduleNode)
            })
            void server.moduleGraph.getModuleByUrl('/src/api-server/index.ts').then((moduleNode) => {
              if (moduleNode) server.moduleGraph.invalidateModule(moduleNode)
            })
          }

          const loadApiServerOnce = () => {
            const entryUrl = `${pathToFileURL(apiServerEntry).href}?t=${Date.now()}`
            return tsImport(entryUrl, { parentURL: viteConfigUrl, tsconfig: tsconfigPath })
              .then((mod) => {
                apiApp = mod.createApiServer()
                return apiApp
              })
          }

          const loadApiServer = () => {
            if (apiApp) return Promise.resolve(apiApp)
            if (!apiAppPromise) {
              apiAppPromise = loadApiServerOnce()
                .catch((err) => {
                  if (!isViteTransportTimeout(err)) throw err

                  console.warn('Vite API loader timed out; resetting SSR module cache and retrying once.')
                  resetApiServer()
                  resetSsrLoader()
                  return loadApiServerOnce()
                })
                .catch((err) => {
                  apiAppPromise = null
                  console.error('Failed to load API server:', err)
                  throw err
                })
            }
            return apiAppPromise
          }

          for (const eventName of ['add', 'change', 'unlink'] as const) {
            server.watcher.on(eventName, (file) => {
              if (isApiSourceFile(file)) {
                invalidateApiServer(file)
              }
            })
          }

          server.httpServer?.once('listening', () => {
            setTimeout(() => {
              void loadApiServer().catch(() => {
                // The request path reports the concrete API load error if prewarm fails.
              })
            }, 1000)
          })

          const sharePageCsp = [
            "default-src 'self'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "object-src 'none'",
            mode === 'production' ? "script-src 'self' 'unsafe-inline'" : "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com data:",
            "img-src 'self' blob: data:",
            "media-src 'self' blob:",
            "connect-src 'self' https://*.supabase.co wss://*.supabase.co ws: wss:",
            "worker-src 'self' blob:",
            mode === 'production' ? 'upgrade-insecure-requests' : '',
          ].filter(Boolean).join('; ')

          server.middlewares.use((req: any, res: any, next: any) => {
            const pathname = (req.url || '').split('?')[0]
            if (pathname.startsWith('/vault/shared')) {
              res.setHeader('Content-Security-Policy', sharePageCsp)
              res.setHeader('Referrer-Policy', 'no-referrer')
              res.setHeader('X-Frame-Options', 'DENY')
              res.setHeader('X-Content-Type-Options', 'nosniff')
              res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()')
              res.setHeader('Cache-Control', 'no-store, max-age=0')
              const forwardedProto = Array.isArray(req.headers['x-forwarded-proto'])
                ? req.headers['x-forwarded-proto'][0]
                : req.headers['x-forwarded-proto']
              if (mode === 'production' || forwardedProto === 'https') {
                res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')
              }
            }
            next()
          })

          /* The dev server serves `public/` directly, so Vite — not the API app —
             would answer /downloads/QGuard-Messaging-Setup.exe. Registering the
             refusal here keeps `npm run dev` honest about the entitlement gate;
             production gets the same block from blockPublicInstallerPath, which
             the API app mounts ahead of express.static. Only the installer is
             blocked: the images and latest.json in that folder stay public. */
          server.middlewares.use((req: any, res: any, next: any) => {
            const pathname = (req.url || '').split('?')[0]
            if (pathname === '/downloads/QGuard-Messaging-Setup.exe') {
              res.statusCode = 403
              res.setHeader('Content-Type', 'application/json')
              res.end(JSON.stringify({
                error: {
                  code: 'SUBSCRIPTION_REQUIRED',
                  message: 'The QGuard Messaging installer is available to signed-in subscribers. Download it from /qguard-messaging.',
                  detail: {downloadEndpoint: '/api/v1/downloads/messaging/windows'},
                },
              }))
              return
            }
            next()
          })

          server.middlewares.use((req: any, res: any, next: any) => {
            if (req.url?.startsWith('/api/')) {
              loadApiServer()
                .then((app) => {
                  // Express 4 compatible: wrap in Promise to catch async errors
                  Promise.resolve(app(req, res, next)).catch((err) => {
                    console.error('API server error:', err)
                    if (!res.headersSent) {
                      res.statusCode = 500
                      res.setHeader('Content-Type', 'application/json')
                      res.end(JSON.stringify({ error: { code: 'INTERNAL_ERROR', message: 'API request failed' } }))
                    }
                  })
                })
                .catch((err) => {
                  if (!res.headersSent) {
                    res.statusCode = 503
                    res.setHeader('Content-Type', 'application/json')
                    res.end(JSON.stringify({
                      error: {
                        code: 'API_LOAD_ERROR',
                        message: err instanceof Error ? err.message : 'API server failed to start',
                      },
                    }))
                  }
                })
            } else {
              next()
            }
          })
        },
      },
    ],
    define: {
      'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY),
      // 'public' compiles platform-only code paths out (src/app/public-scan/page.tsx).
      'import.meta.env.VITE_SITE_EDITION': JSON.stringify(websiteEdition ? 'public' : 'platform'),
    },
    ...(websiteEdition ? {build: {outDir: 'dist-public', emptyOutDir: true}} : {}),
    resolve: {
      alias: {
        '@': path.resolve(rootDir, 'src'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: {
        // The Tauri/Android build trees are GENERATED output, not source, and
        // together hold ~29k files (target/ alone is ~26k). Chokidar was walking
        // and watching every one of them, which burned CPU in the dev server and
        // — because they are inside the Vite root — made every incremental cargo
        // or gradle build trigger a full browser page reload, e.g.
        //   [vite] (client) page reload
        //     qguard-messaging/src-tauri/gen/android/build/reports/problems/problems-report.html
        // Nothing here is ever imported by the web app, so ignoring it costs no
        // reactivity. Keep this list to generated artefacts only.
        ignored: [
          '**/qguard-messaging/src-tauri/target/**',
          '**/qguard-messaging/src-tauri/gen/**',
          '**/dist/**',
          '**/.next/**',
        ],
      },
    },
    preview: {
      // The full CSP travels in the built index.html as a <meta> (script hashes
      // included). Here we add only the header-only protections that a <meta>
      // cannot express — clickjacking (X-Frame-Options), MIME sniffing, referrer,
      // and feature policy. These are also the headers the production host should
      // replicate. Setting a second CSP header here would intersect with the meta
      // and break the hash-allow-listed inline bootstrap, so it is intentionally omitted.
      headers: {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()',
      },
    },
  };
});
