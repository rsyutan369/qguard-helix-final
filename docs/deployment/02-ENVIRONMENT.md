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
| `PUBLIC_SCAN_MAX_CONCURRENT` | `24` (code default `6`) | Public scans running at once in this pod. See *Public scanner capacity* below |
| `PUBLIC_SCAN_MAX_QUEUE` | `500` | Visitors allowed to wait for a slot; each is told their place and an estimated wait |
| `PUBLIC_SCAN_MAX_ACTIVE_PER_CLIENT` | `3` | Coordinator fairness setting. The database allows only one outstanding Public Scan per account across all replicas |
| `PUBLIC_SCAN_RATE_LIMIT_PER_MINUTE` | `5` | Valid-target scan requests per account per minute. This throttle is separate from the daily allowance |
| `APP_VERSION`, `GIT_SHA` | baked into the image by CI | Reported in `/readyz` and every log line |

## Public scanner capacity

The landing page is public. `GET /api/v1/public-scan/usage`, `POST /api/v1/public-scan`,
and `POST /api/v1/public-scan/stream` require an Authorization Bearer token from
the same Supabase project used by the website. The API uses the project URL and
anon key to verify users, and its server-only service role to manage usage.

1. Authentication and request limits run before scanner admission. The API accepts
   a JSON object with one target, capped at 1 KiB, and checks the destination.
2. The quota RPC reserves one scan per account across API replicas. A newly
   completed reachable assessment uses one credit. Cached results, rejected
   requests, failures, and cancelled work leave the daily balance intact.
3. The allowance is three per day, resets at midnight UTC, and counts successful
   assessments against the day their reservation began.
4. Equivalent targets share in-flight work per process. The scan stream reports queue
   position and progress. A tab close releases its reservation. A running probe
   without subscribers stops after its grace period. Timeout and crash recovery
   expire unclaimed reservations.
5. The streaming route returns pre-admission refusals as JSON with their HTTP
   status. The browser reads SSE with bearer-authenticated fetch.

**Measured basis** (2026-10-14, real scans of 24 large public sites, one Node
process, a residential connection):

| Concurrent scans | Scan time p50 / max | CPU per scan | Process CPU | Peak RSS | Degraded reports |
|---|---|---|---|---|---|
| 6 | 19.9 s / 31.9 s | 250 ms | 5 % of a core | 103 MB | 0 |
| 12 | 22.7 s / 29.2 s | 245 ms | 10 % | 123 MB | 0 |
| 24 | 28.3 s / 35.9 s | 245 ms | 16 % | 138 MB | 0 |
| 48 | 39.1 s / 42.1 s | 204 ms | 23 % | 165 MB | 0 |

A scan is network-bound: CPU and memory stay small, and every site received
the same grade at 6, 12 and 24. At 48 a scan nears the engines' 45 s budget,
after which results degrade to inconclusive, so **24 is the production
setting** and 48 is the measured ceiling (`checkProductionConfig` warns above
it). Re-measure on the target node before going higher:
`npx tsx tools/public-scan-load-check.ts` (queue and fairness, offline) and a
concurrency run like the table above.

**What that means for visitors, one pod at 24** (throughput ≈ 24 scans per
~30 s ≈ 45 new sites a minute):

| Visitors arriving together | Distinct sites | Outcome |
|---|---|---|
| 10 | 10 | All start at once |
| 100 | 100 | 24 start at once; the rest wait in line, the last about 2 min |
| 1,000 | 20 popular sites | 20 scans; everyone else joins one of them or reads its cached result |
| 1,000 | 1,000 | 24 run, 500 wait (the last about 11 min), the rest are told the line is full and when to retry |

Measured against the dev server at the old fixed limit of 6 with no line:
10 visitors → 4 refused; 100 → 88 refused; 1,000 → 987 refused. With the
line, at the same limit of 6: 10 → all 10 completed; 100 over 20 sites → all
100 completed from 16 real scans; 1,000 over 20 sites → all 1,000 completed
from 20 real scans, the server answering every probe within 302 ms.

**Limits that still apply:**

- **Per pod.** The line, the shared jobs, the cache and the rate limit live in
  process memory (see `01-ARCHITECTURE.md` §5). Production runs one replica,
  so they are global today. With more replicas, each pod has its own line and
  limits multiply. That stays correct for a visitor (their stream stays on one
  pod) but is not a global queue. A shared store (Phase 2, Redis) would make it
  one.
- **Client identity.** Until `TRUSTED_CLIENT_IP_HEADER=cf-connecting-ip` is set
  (the `cloudflare-origin-lock` component), the per-client limits key on a
  client-supplied `X-Forwarded-For`, so one caller rotating that header could
  fill the line. Visitors behind one office NAT share one address: 5 new scans
  a minute between them, and 3 places while others are waiting.
- **Cloudflare rate-limit rule** on `/api/v1/public-scan*` (runbook §5) must be
  looser than these limits. Each visitor opens one stream per scan and the page
  reads `/capabilities`. Allow at least 20 requests a minute per IP, or the
  edge refuses what the app would have queued.

## API (Kubernetes) — Secret `qguard-api-secrets` (Secret, Runtime)

Template: `deploy/k8s/secrets.example.env` (names only).

| Variable | Required | Notes |
|---|---|---|
| `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY` | **Yes** | The server uses the same names as the client |
| `SUPABASE_SERVICE_ROLE_KEY` | **Yes** | Without it every server write silently runs as anon; the preflight refuses to start |
| `PAYPAL_CLIENT_ID`, `PAYPAL_SECRET_KEY`, `PAYPAL_ENV`, `PAYPAL_PLAN_*` (8) | For billing actions | Subscription revise/cancel from Settings |
| `PAYPAL_RECONCILE_SECRET` | Optional | Enables `POST /api/v1/paypal/reconcile` (and the CronJob component) |
| `PAYPAL_WEBHOOK_ID` | **Leave unset** | The live webhook is registered to the Edge Function; register exactly one receiver |
| `SMTP_HOST`, `SMTP_PORT` (465), `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` (defaults to `SMTP_USER`) | For the Request Demo form | `POST /api/v1/demo-request` emails each request to `DEMO_REQUEST_TO` (default `info@qguardhelix.com`) with the visitor as Reply-To. Unset: the form returns 503 and tells visitors to email the inbox. Port 587 must offer STARTTLS. Limits: `DEMO_REQUEST_MAX_PER_CLIENT` (3 per 10 min), `DEMO_REQUEST_MAX_PER_HOUR` (60). Verify with `npm run check:demo-request` |
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
