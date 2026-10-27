import 'dotenv/config'
import { createPublicApiServer } from './public-api'
import { logEvent } from './runtime/observability'
import { jsonErrorHandler, listenWithGracefulDrain } from './runtime/serve'

/**
 * Public API entry (`npm run start:public-api`, the `public-api` image target).
 *
 * Serves the website's two backend features — the free Web assessment and the
 * Request Demo email — and nothing else (src/api-server/public-api.ts). Needs
 * no Supabase or payment credentials. What it does need is checked here and
 * reported at startup; none of it stops the process, because the scanner
 * works without email and the demo form says so when SMTP is missing.
 */

const port = Number(process.env.PORT || process.env.API_PORT || 8080)
const isProduction = process.env.NODE_ENV === 'production'

if (isProduction) {
  const allowList = [process.env.APP_ORIGIN, process.env.PUBLIC_APP_ORIGIN, process.env.ALLOWED_ORIGINS].filter(Boolean)
  if (!allowList.length) {
    logEvent('warn', 'config_warning', {
      message: 'ALLOWED_ORIGINS is not set: browsers on the website (e.g. https://qguardhelix.com) will be refused by CORS.',
    })
  }
  if (!process.env.TRUSTED_CLIENT_IP_HEADER) {
    logEvent('warn', 'config_warning', {
      message: 'TRUSTED_CLIENT_IP_HEADER is not set: behind a proxy every visitor shares one rate limit, and X-Forwarded-For can be spoofed. Use cf-connecting-ip behind Cloudflare.',
    })
  }
  if (!process.env.SMTP_HOST) {
    logEvent('warn', 'config_warning', {
      message: 'SMTP_HOST is not set: Request Demo answers 503 and tells visitors to email the inbox directly.',
    })
  }
}

const app = createPublicApiServer()
app.use(jsonErrorHandler)

listenWithGracefulDrain(app, { port, listening: { role: 'public' } })
