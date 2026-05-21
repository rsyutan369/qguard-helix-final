import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {defineConfig, loadEnv} from 'vite';

const rootDir = path.dirname(fileURLToPath(import.meta.url));

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

          const invalidateApiServer = (file: string) => {
            resetApiServer()
            const normalizedFile = file.replace(/\\/g, '/')
            void server.moduleGraph.getModuleByUrl(normalizedFile).then((moduleNode) => {
              if (moduleNode) server.moduleGraph.invalidateModule(moduleNode)
            })
            void server.moduleGraph.getModuleByUrl('/src/api-server/index.ts').then((moduleNode) => {
              if (moduleNode) server.moduleGraph.invalidateModule(moduleNode)
            })
          }

          const loadApiServer = () => {
            if (apiApp) return Promise.resolve(apiApp)
            if (!apiAppPromise) {
              apiAppPromise = server.ssrLoadModule('/src/api-server/index.ts')
                .then((mod) => {
                  apiApp = mod.createApiServer()
                  return apiApp
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
