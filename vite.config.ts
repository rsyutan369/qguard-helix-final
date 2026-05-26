import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {tsImport} from 'tsx/esm/api';
import {defineConfig, loadEnv} from 'vite';

const rootDir = path.dirname(fileURLToPath(import.meta.url));
const apiServerEntry = path.join(rootDir, 'src/api-server/index.ts');
const viteConfigUrl = pathToFileURL(path.join(rootDir, 'vite.config.ts')).href;
const tsconfigPath = path.join(rootDir, 'tsconfig.json');

export default defineConfig(({mode}) => {
  const env = loadEnv(mode, rootDir, '');
  for (const key of ['VITE_SUPABASE_URL', 'VITE_SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY']) {
    if (env[key] && !process.env[key]) {
      process.env[key] = env[key];
    }
  }

  return {
    plugins: [
      react(),
      tailwindcss(),
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
  };
});
