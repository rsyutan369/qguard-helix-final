import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import {createHash} from 'node:crypto';
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
  for (const key of ['VITE_SUPABASE_URL', 'VITE_SUPABASE_FALLBACK_URL']) {
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

  const connectSrc = resolveConnectSrc(env);

  return {
    plugins: [
      react(),
      tailwindcss(),
      cspMetaPlugin(connectSrc),
      {
        name: 'api-server',
        configureServer(server) {
          let apiApp: any = null
          let apiAppPromise: Promise<any> | null = null

          const isApiSourceFile = (file: string) => {
            const normalizedFile = file.replace(/\\/g, '/')
            const normalizedRoot = rootDir.replace(/\\/g, '/')
            return normalizedFile.startsWith(`${normalizedRoot}/src/api-server/`)
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
    },
    resolve: {
      alias: {
        '@': path.resolve(rootDir, 'src'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
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
