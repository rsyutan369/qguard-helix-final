# 02 — Environment strategy and variable inventory

## Environments

| | Development | Staging | Production |
|---|---|---|---|
| Frontend | `npm run dev` (Vite, port 3000) | Vercel **Preview** / custom environment `staging` → `staging.qguardhelix.com` | Vercel **Production** → `qguardhelix.com` |
| API | Mounted inside Vite (same origin) | DOKS ns `qguard-staging` → `api-staging.qguardhelix.com` | DOKS ns `qguard-production` → `api.qguardhelix.com` |
| Supabase | Should point at **staging** (today: the production project) | Separate `qguard-helix-staging` project | `xsbdlahuecadzfajlvis` (existing; keep: installed messaging clients bake its URL) |
| Config source | `.env` (gitignored) | Vercel env (Preview) + k8s ConfigMap/Secret | Vercel env (Production) + k8s ConfigMap/Secret |
| Deploys | — | Automatic on merge to `main` | Manual promotion of the staging-tested SHA, with approval |

`NODE_ENV=production` is what switches the API to its production posture:
registration auto-confirm off, HTTPS enforcement and HSTS on, and the startup
preflight on. The Dockerfile and the ConfigMap both set it, so it cannot be
forgotten.

## Classification legend

- **Public:** safe in the browser bundle. Every `VITE_*` value is inlined at build time.
- **Server:** API runtime only, not secret.
- **Secret:** API runtime only; lives in the k8s Secret or Supabase function secrets, never in git or ConfigMaps.
- **Build:** read at build time. **Runtime:** read by the running process.

## Frontend (Vercel project environment variables — build-time, all PUBLIC)

| Variable | Required | Notes |
|---|---|---|
| `VITE_SUPABASE_URL` | **Yes** | Also added to the CSP `connect-src`. Without it the client targets `https://example.invalid` |
| `VITE_SUPABASE_ANON_KEY` | **Yes** | The anon/publishable key; only anon JWTs are in the bundle (verified) |
| `VITE_API_ORIGIN` | Recommended | `https://api.qguardhelix.com` (Production) / `https://api-staging.qguardhelix.com` (Preview). Routes `/api` calls directly to the API and adds it to the CSP. Unset means calls go through the `/api/*` rewrite |
| `VITE_REPORT_VERIFICATION_ORIGIN` | Recommended | `https://qguardhelix.com`, so report QR codes never embed a preview URL |
| `VITE_BILLING_API_ORIGIN` | No | Leave unset (defaults to the Supabase `billing` Edge Function) |
| `VITE_SUPABASE_FALLBACK_*`, `VITE_SUPABASE_USE_FALLBACK` | **Never in production** | Would pin visitors to a second database |
| `GEMINI_API_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `PAYPAL_*` | **Never on Vercel** | The frontend build needs none of them. `GEMINI_API_KEY` feeds a Vite `define`, so it could leak if a client module ever referenced it |

## API (Kubernetes) — ConfigMap `qguard-api-config` (Server, Runtime)

| Variable | Value (production) | Purpose |
|---|---|---|
| `NODE_ENV` | `production` | Production posture + preflight |
| `QGUARD_ENVIRONMENT` | `production` | Strict agent control-plane validation |
| `PORT` | `8080` | Container port |
| `SERVE_STATIC` | `false` | API-only container (the SPA is on Vercel) |
| `APP_ORIGIN`, `PUBLIC_APP_ORIGIN` | `https://qguardhelix.com` | CORS allow-list and PayPal return URLs (**required**) |
| `PUBLIC_APP_URL` | `https://qguardhelix.com` | Admin password-recovery links |
| `ALLOWED_ORIGINS` | `https://qguardhelix.com,https://www.qguardhelix.com` | Extra CORS origins; supports single-label `*` (staging previews) |
| `QGUARD_CONTROL_PLANE_URL` | `https://api.qguardhelix.com` | Baked into every agent installer (**required**; changing it strands installed agents) |
| `CERT_VERIFICATION_ORIGIN` | `https://qguardhelix.com` | Certificate verification links |
| `REGISTRATION_AUTO_CONFIRM` | `false` | Real email confirmation through Supabase custom SMTP |
| `SUBSCRIPTION_ENFORCEMENT` | `enforce` | Server-side plan gating |
| `TOKEN_REVOCATION_REFRESH_MS` | `30000` | Re-read admin revocations (multi-pod safety) |
| `TRUSTED_CLIENT_IP_HEADER` | `cf-connecting-ip` | **Only via the `cloudflare-origin-lock` component**, once the LB accepts Cloudflare IPs only |
| `ACCESS_LOG` | `true` | JSON access log; credential query params redacted |
| `HTTP_KEEP_ALIVE_TIMEOUT_MS` | `65000` | Longer than upstream idle timeouts (avoids 502s) |
| `SHUTDOWN_DELAY_MS` / `SHUTDOWN_DRAIN_MS` | `5000` / `240000` | Graceful drain (scan budget is 240 s) |
| `READINESS_REQUIRE_SUPABASE` | `false` | A Supabase blip reports `degraded` instead of pulling the pod |
| `NODE_OPTIONS` | `--max-old-space-size=1024` | Heap below the 1536 Mi limit |
| `SUPABASE_MAX_SOCKETS` | `16` | Per-pod PostgREST concurrency gate |
| `API_JSON_LIMIT` / `API_PUBLIC_JSON_LIMIT` | unset (`80mb` / `256kb`) | Body limits; the public endpoints use the small one |
| `APP_VERSION`, `GIT_SHA` | baked into the image by CI | Reported in `/readyz` and every log line |

## API (Kubernetes) — Secret `qguard-api-secrets` (Secret, Runtime)

Template: `deploy/k8s/secrets.example.env` (names only).

| Variable | Required | Notes |
|---|---|---|
| `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY` | **Yes** | The server uses the same names as the client |
| `SUPABASE_SERVICE_ROLE_KEY` | **Yes** | Without it every server write silently runs as anon; the preflight refuses to start |
| `PAYPAL_CLIENT_ID`, `PAYPAL_SECRET_KEY`, `PAYPAL_ENV`, `PAYPAL_PLAN_*` (8) | For billing actions | Subscription revise/cancel from Settings |
| `PAYPAL_RECONCILE_SECRET` | Optional | Enables `POST /api/v1/paypal/reconcile` (and the CronJob component) |
| `PAYPAL_WEBHOOK_ID` | **Leave unset** | The live webhook is registered to the Edge Function; register exactly one receiver |
| `GOOGLE_PLAY_*`, `PLAY_RTDN_TOKEN` | Only for Android billing | RTDN URL: `https://api.qguardhelix.com/api/v1/play-billing/rtdn` |
| `STRIPE_*` | No | Dormant code path |

**Refused by the production preflight** (the pod exits with code 78 unless
`QGUARD_ALLOW_UNSAFE_CONFIG=true`, which never waives required variables):

- Any `*FALLBACK*` Supabase variable, or `SUPABASE_USE_FALLBACK=true`.
- `REGISTRATION_AUTO_CONFIRM=true`.
- `SUBSCRIPTION_ENFORCEMENT` set to anything other than `enforce`.
- Platform repository tokens (`GITHUB_TOKEN`, `GH_TOKEN`, `GITLAB_TOKEN`,
  `BITBUCKET_*`, `AZURE_DEVOPS_*`, `GITEA_TOKEN`, …). Production also ignores
  them in code unless `ALLOW_PLATFORM_REPO_TOKEN=true`.

## Supabase Edge Function `billing` (Secret, Runtime — `supabase secrets set`)

`PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET` (or `PAYPAL_SECRET_KEY`),
`PAYPAL_ENV`, `PAYPAL_WEBHOOK_ID`, `PAYPAL_PLAN_*` (8), `APP_ORIGIN`.

`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are injected by the platform.

## GitHub (CI/CD)

| Where | Name | Purpose |
|---|---|---|
| Repository variables | `DOCR_REGISTRY`, `DOKS_CLUSTER`, `API_HOST_STAGING`, `API_HOST_PRODUCTION` | Deploy targets |
| Environment secrets (`staging`, `production`) | `DIGITALOCEAN_ACCESS_TOKEN` | Scoped DO token (registry + Kubernetes) |
| Environment secrets (`staging`, `production`) | `SUPABASE_ACCESS_TOKEN`, `SUPABASE_PROJECT_REF` | Edge Function deploys |
| Environment `production` | Required reviewers | Manual approval gate |

## Customer agent (baked into generated installers)

`QGUARD_API_URL` (from the server's `QGUARD_CONTROL_PLANE_URL`), `QGUARD_AGENT_ID`,
`QGUARD_AGENT_TOKEN` (secret, per agent), `QGUARD_ENVIRONMENT`. A generated
installer refuses a plaintext or private control plane in production.
