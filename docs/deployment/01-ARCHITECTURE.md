# 01 — Architecture: current state, MVP target, boundaries

## 1. Current-state architecture (as audited)

| Area | Reality in the code |
|---|---|
| **A. Frontend** | Vite 8 + React 19 SPA (`src/main.tsx`, `src/App.tsx`: `BrowserRouter`, ~156 routes). Tailwind 4, Framer Motion. Calls the API with **relative** `/api/v1/...` URLs from ~160 `fetch` sites and ~35 `EventSource` streams, with no shared API client. The build injects a hash-pinned CSP `<meta>` (`vite.config.ts`). |
| **B. API** | One Express 4 app, `createApiServer()` in `src/api-server/index.ts`. It has ~60 routers under `/api/v1` and imports engines from `src/lib` and `src/services`. Dev: mounted into Vite (`vite.config.ts` `configureServer`). Prod: `src/api-server/standalone.ts` run by `tsx`. The Next-style `src/app/api/**/route.ts` files are **dead code** (never served, excluded from `tsc`). |
| **C. Database** | Supabase Postgres 17, project `xsbdlahuecadzfajlvis` (ap-southeast-1). 152 public tables, all with RLS enabled; 224 policies; 56 SECURITY DEFINER functions. Accessed only through supabase-js (PostgREST over HTTPS), with no direct `pg` connections. |
| **D. Auth** | Supabase Auth (ES256 JWTs). The API verifies tokens **locally** against the JWKS, with a 60 s cache and an in-memory admin revocation list (`src/lib/supabase-server.ts`). Bearer header, or `?token=` on SSE streams. No cookies. Owner = hardcoded email (SQL `qguard_is_owner()` and `src/lib/admin-access.ts`). |
| **E. Storage** | Supabase Storage: 5 buckets (`avatars`, `profile-banners` public; `profile-avatars`, `messaging-files`, `vault-encrypted` private) with 16 `storage.objects` policies. The API itself writes **nothing** to disk. |
| **F. Realtime** | Browser `postgres_changes` subscriptions, plus ~38 API SSE routes with 10–30 s heartbeats. The API never uses Supabase Realtime. |
| **G. External services** | PayPal (subscriptions; live webhook → Supabase Edge Function `billing`), Google Play billing (RTDN → Express), Gemini (define only, unused by client code), cloud SDKs (AWS/Azure/GCP, lazily loaded, Dev scans), customer targets (scanners). |
| **H. Infrastructure** | Before this work: none in the repo (no Dockerfile, no manifests); `vercel.json` held headers only. |
| **I. CI/CD** | Before this work: none (`.github/` absent). |
| **J. Environment** | Local `.env`. `.env.example` contained a **real `service_role` key** (fixed; see 04). |
| **K. Security boundaries** | Browser (anon key only), then API (service role, tenant checks, subscription gateway), then Postgres RLS. The service key is confined to server modules (verified: no client import; the built bundle holds only the anon JWT). |
| **L. Data flows** | Dashboards: browser → API → Supabase (the user's JWT client under RLS, plus the service client for cross-table models) → SSE snapshots. Scans: browser → API (in-process scanner engines → external targets) → Supabase. Agents: customer host → API (agent token) → Supabase. Billing: browser → Edge Function → PayPal; PayPal webhook → Edge Function → Supabase. |
| **M. Critical dependencies** | Supabase (hard), PayPal (billing only), Node 24 / OpenSSL 3.5 (hybrid ML-KEM TLS probing), the `tools/qguard-agent/dist` build artefact (agent installer), `public/downloads/QGuard-Messaging-Setup.exe` (gated download). |

## 2. MVP target architecture

```
DISCOVER/ASSESS/PLAN/... UI                         Customer hosts
        │ HTTPS                                            │ agent token
        ▼                                                  ▼
 ┌─────────────┐   /api/* rewrite (fallback)   ┌──────────────────────────────┐
 │   Vercel    │ ─────────────────────────────►│ Cloudflare (api.qguardhelix  │
 │ static SPA  │                               │ .com, proxied, WAF, Full     │
 └─────────────┘                               │ strict TLS)                  │
        │  VITE_API_ORIGIN (primary, direct)    └──────────────┬───────────────┘
        └──────────────────────────────────────────────────────┤
                                                               ▼
                                            DigitalOcean HTTP LB (REGIONAL, 600 s idle)
                                                               ▼
                                   DOKS  ns qguard-production: Deployment qguard-api (1 pod)
                                     Express API + scanners · /api/v1/healthz · /api/v1/readyz
                                     NetworkPolicy: public egress only (no metadata/VPC)
                                                               ▼
                               Supabase Pro: Postgres/RLS · Auth · Storage · Realtime · Edge fn
```

**Primary browser-to-API path: direct** (`VITE_API_ORIGIN=https://api.qguardhelix.com`).
With it, `CF-Connecting-IP` identifies the real visitor, so per-client rate limits
work. SSE never passes through Vercel's proxy, which cuts a stream after 120 s
without data. Tokens in stream URLs stay out of Vercel's request logs. The
`/api/*` rewrite in `vercel.json` stays as a safety net for plain navigations
(e.g. `<a href="/api/...">`) and for deployments without the variable.

## 3. Production boundaries — what each service owns

| Service | Purpose / why required | Data it handles | Exposure & auth | Failure behaviour | Scaling | Backup / recovery | Cost | Phase |
|---|---|---|---|---|---|---|---|---|
| **Vercel Pro** | Build + CDN for the static SPA; preview deployments | Public JS/CSS/media only; `VITE_*` public values | Public; previews behind Vercel Authentication | SPA unavailable; API, agents and webhooks keep working | Automatic (CDN) | Immutable deployments; instant rollback in the dashboard | $20/mo (+usage over the $20 credit) | MVP |
| **Cloudflare Free** | DNS, TLS edge, WAF/rate-limit rule, DDoS shield for `api.` | Proxies API traffic (TLS terminated at the edge, re-encrypted to the origin) | Proxied only for `api.`; app hostname DNS-only | If down: API unreachable (DNS/proxy); can fail over to DNS-only | N/A | DNS zone export | $0 | MVP |
| **Supabase Pro** | System of record: Postgres + RLS, Auth, Storage, Realtime, Edge Function `billing` | All tenant data, identities, subscriptions, encrypted vault/chat files | Public HTTPS APIs guarded by RLS + JWT; service key server-only | API `/readyz` reports `degraded`; dashboards fail closed (no fabricated data) | Compute add-ons (Micro → Small …) | Daily backups (7 days on Pro); PITR add-on; Storage objects need separate backup | $25/mo (+$15 for Small compute if chosen) | MVP |
| **DOKS (2 nodes)** | Long-running API with 38 SSE routes, in-process scanners (raw TLS/TCP), agent control plane | Transient: requests, scan state, credentials in memory only | Only through the LB; pods non-root, read-only FS, no SA token, egress policy | Pod crash: restart (≈10–60 s). Node loss: reschedule to the second node | 1 replica now; HPA after Phase 2 | Stateless: redeploy the image; manifests in git | 2 × $24 (s-2vcpu-4gb) recommended; 2 × $12 is dev-grade | MVP |
| **DO Load Balancer (HTTP)** | TLS termination with the Cloudflare Origin cert, HTTP→HTTPS, health checks, 600 s idle for SSE | Pass-through | Public :80/:443; optional Cloudflare-only allow-list | LB outage = API outage | size-unit 1 (10k rps) | Recreated from the Service manifest | $12/mo | MVP |
| **DO Container Registry** | Stores the API image (tag = git SHA) | Image layers | Private; pull secret `docr-pull` | Deploys fail, running pods unaffected | — | Rebuild from git | $5/mo (Basic) — **missing from the original plan** | MVP |
| **GitHub + Actions** | Source, PR checks, image build, deploys, secret scanning | Source code, CI secrets (environment-scoped) | Private repo; production environment needs approval | Deploys pause; production unaffected | — | Git history | $0 (free minutes) | MVP |
| **Managed Redis/Valkey** | **Not used by the code today** (`bullmq`/`ioredis` are unused dependencies) | — | — | — | — | — | $0 now; $15 single node / $60 HA later | **Phase 2** |
| **DO Block Storage** | **Not needed**: the API is stateless and writes nothing to disk | — | — | — | — | — | $0 now | Phase 2 (only for self-hosted observability) |

### Corrected monthly budget

| Line | Original plan | Corrected MVP | Why |
|---|---|---|---|
| Vercel Pro | $20 | $20 | — |
| Supabase Pro | $25 | $25 | Consider +$15 Small compute (also needed for PITR) |
| Cloudflare Free | $0 | $0 | — |
| DOKS nodes | 2 × $12 = $24 | **2 × $24 = $48** | $12 nodes leave ≈1 GiB for pods; DO rates them development-only. The API requests 512 Mi and is limited to 1.5 Gi |
| DO Load Balancer | $12 | $12 | Only with `do-loadbalancer-type: REGIONAL` (set in `service.yaml`); otherwise a $15 network LB |
| Block Storage 100 GB | $10 | **$0** | Nothing uses a volume |
| Managed Redis | ~$15 | **$0** | Nothing uses Redis yet; see §6 |
| Container Registry | — | **$5** | Missing from the plan; Starter (500 MiB) is too small for this image |
| GitHub / Actions | $0 | $0 | — |
| **Total** | **≈ $106** | **≈ $110** | Lean variant on 2 × $12 nodes: ≈ $86 |

## 4. Request flows

- **Dashboard load:** Browser → `https://api.qguardhelix.com/api/v1/...` (Bearer) → Cloudflare → LB → pod → Supabase (user JWT client under RLS) → JSON.
- **Live telemetry:** `EventSource(https://api…/stream?token=…)` → Cloudflare (100 s idle limit; heartbeats keep it open) → LB (600 s idle) → pod → periodic Supabase snapshots.
- **Scan:** Browser → API `/api/v1/scanner/stream` → in-process engines → **outbound** TLS/TCP to customer targets (egress policy blocks private ranges) → results persisted to Supabase.
- **Agent:** Customer host → `https://api.qguardhelix.com` (`QGUARD_CONTROL_PLANE_URL`, baked into every installer) → agent routes → Supabase.
- **Billing:** Browser → Supabase Edge Function `billing` → PayPal. PayPal webhook → Edge Function (`verify_jwt=false`). In-app plan changes → API → PayPal.

## 5. Scaling limits and why `replicas: 1`

The audit found per-process state that breaks, or weakens security, when requests for the same flow land on different pods:

| State (file) | What breaks with 2+ pods | Sticky sessions help? |
|---|---|---|
| Dev exposure jobs + connection credentials (`run-dev-scan.ts`, `exposure.ts`) | Scan/stream/cancel 404 on the other pod | Yes |
| Scanner cancel handles (`scanner.ts activeJobs`) | Cancel returns 404 | Yes |
| Agent live-event bus (`agent-event-bus.ts`) | Agent progress never reaches a browser on another pod | **No** (agents send no cookie) |
| Vault share alerts (`lib/vault/share-events.ts`) | Owner misses failed-attempt alerts | **No** |
| Admin token revocation (`supabase-server.ts`) | Revoked token still works on other pods | **Mitigated:** `TOKEN_REVOCATION_REFRESH_MS=30000` re-reads revocations every 30 s |
| In-memory rate limiters (auth, public-scan, exposure, share) | Limits multiply by the replica count | No |
| Schedulers in `createApiServer()` (agent offline sweep, sandbox tick) | Run N times, with occasional duplicate alerts | No |

**Phase 1 decision:** one API pod. The `RollingUpdate` (`maxSurge: 1`,
`maxUnavailable: 0`) starts the new pod before the old one drains, and the
second node gives failover through rescheduling. **Phase 2** moves the event
bus, share alerts, rate limits and cache invalidation behind optional
`REDIS_URL` adapters, keeping the in-memory default for dev. Then replicas
and the HPA can be raised.

## 6. Redis / Valkey strategy

- **MVP: not provisioned.** No code path uses it, so paying for it adds
  operational surface and no function.
- **When it earns its cost (Phase 2):**

  | Use | Replaces | TTL / invalidation |
  |---|---|---|
  | Pub/sub fan-out | Agent event bus, share alerts, cache invalidation | None; ephemeral |
  | Shared rate limiting | In-memory limiters | `INCR` + `PEXPIRE` equal to the window |
  | BullMQ queue | In-process Dev scans | Jobs kept 1 h |
  | Short-lived SSE stream tickets | `?token=` JWT in stream URLs | 60 s, single use |

- **Rules:** never the source of truth (Supabase is); never plaintext
  credentials; TLS (`rediss://`, port 25061) over the VPC only, with the exact
  private IP allowed in the NetworkPolicy; `maxmemory-policy noeviction` for
  BullMQ. If Redis is down, fall back to per-pod behaviour (limits per pod,
  events delayed to the next poll). Never fail closed on reads.

## 7. Kubernetes strategy

| Workload | Kind | Why in Kubernetes | Replicas | Probes | Resources |
|---|---|---|---|---|---|
| `qguard-api` (API + scanners) | Deployment | Long-lived SSE, raw TCP/TLS scanners, agent control plane, 240 s scans (exceeds serverless limits) | 1 | startup/liveness `/api/v1/healthz`, readiness `/api/v1/readyz` | req 250m / 512Mi, limit 1536Mi |
| `qguard-paypal-reconcile` (optional component) | CronJob | Scheduled, secret-guarded reconciliation | — | — | curl only |

- **Not in Kubernetes:** the SPA (Vercel), the database, auth and storage
  (Supabase), and the PayPal webhook (Supabase Edge Function).
- **Report generation runs in the browser**, not on the server: the exporters
  live under `src/services/reporting`.

Manifests: `deploy/k8s/base` plus `overlays/{staging,production}` and
`components/{cloudflare-origin-lock,paypal-reconcile}`. They set:

- **Security context:** non-root, `readOnlyRootFilesystem`, all capabilities
  dropped, `seccomp: RuntimeDefault`, and no service-account token.
- **Network:** Pod Security `restricted` on the namespaces, and a NetworkPolicy
  that blocks metadata/VPC egress.
- **Behaviour:** `ndots: 2` for scanner DNS, and a PDB that never blocks node
  drains.

**No ingress controller.** `ingress-nginx` was retired (archived March 2026).
A single HTTP LB Service suffices. If routing grows, use DOKS's managed Cilium
Gateway API.

## 8. Repository structure

**Deliberately unchanged:** `src/` layout, routes, imports. Moving hundreds of
files would risk every flow for no deployment benefit. The deployment layer
was added beside the existing modules:

```
.github/
  workflows/ci.yml                 PR/main gates: tsc, boundary, deploy checks, domain suites, build, secrets, image smoke, manifests
  workflows/deploy-api.yml         build once (SHA) → staging → approved promotion to production
  workflows/supabase-functions.yml billing Edge Function deploy (--no-verify-jwt)
  actions/deploy-api/              shared rollout + smoke test + automatic rollback
deploy/k8s/                        kustomize base / overlays / optional components, secrets.example.env
docs/deployment/                   this documentation
src/api-server/runtime/            NEW infrastructure layer (no business logic):
  config.ts        production preflight (fail-safe config validation)
  health.ts        /api/v1/healthz, /api/v1/readyz
  lifecycle.ts     drain state + build identity
  observability.ts request ids, JSON access log with credential redaction
  client-ip.ts     trusted client-IP resolution (opt-in)
src/lib/api-origin(.ts|-core.ts)   optional split-origin API routing for the SPA
tools/deploy/                      prune-static-output.mjs (Vercel), deploy-readiness-check.ts (CI)
Dockerfile, .dockerignore, .vercelignore, .nvmrc
```

**Target modular-monolith boundaries** (evolve toward these incrementally; no big-bang move):

| Layer | Today | Direction |
|---|---|---|
| HTTP (routers) | `src/api-server/*.ts` | Keep; routers stay thin |
| Domain engines | `src/lib/**`, `src/services/**` (already isomorphic/pure in many modules) | Keep; extraction units for future services |
| Infrastructure | `src/api-server/runtime/*` (new), `src/lib/supabase-*.ts` | Grow here: Redis adapters, queue client, metrics |
| Config | `runtime/config.ts` (production preflight) | Move remaining ad-hoc `process.env` reads behind typed accessors over time |
| Dead code | `src/app/api/**` (Next-style, never served) | Remove in a dedicated PR after proving no import references |

## 9. Future enterprise evolution

1. **Phase 2 (shared state):**
   - `REDIS_URL` adapters for the event bus, share alerts, rate limits and cache invalidation.
   - Raise replicas to 2+ and add an HPA on CPU (install metrics-server first).
   - HA control plane (+$40).
2. **Phase 3 (service extraction):**
   - Run the same image with a role flag (`QGUARD_API_ROLE=api|scanner|worker`).
   - Dev and authorized scans move to BullMQ workers.
   - Separate scanner Deployment with its own egress (VPC NAT Gateway, $40, for a stable, publishable scanner IP).
3. **Enterprise:**
   - SSO/SAML/SCIM via Supabase Auth enterprise features.
   - Organisation-level tenancy (today tenancy is per `user_id`).
   - Audit trail export to a SIEM (the JSON access log is already log-shipper friendly).
   - Multi-region by region-scoped DOKS clusters and Supabase read replicas.
   - Supabase PITR and custom domain.
