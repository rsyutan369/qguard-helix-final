# 04 — Security, observability, backup and disaster recovery

## 1. Security findings from the production audit

| # | Finding | Severity | Status |
|---|---|---|---|
| S1 | A `service_role` key for the fallback Supabase project was committed in `.env.example` and pushed to GitHub. The API also accepts fallback-project tokens, and owner rights are granted by email | **Blocker** | **Partly fixed:** `.env.example` is names-only, the production preflight refuses any `*FALLBACK*` variable, and CI runs gitleaks. **You must rotate the key** (runbook §0) |
| S2 | Production posture depended on `NODE_ENV`, which `npm start` never sets. Without it registration auto-confirms, and there is no HTTPS redirect, no HSTS, and stack traces leak | **Blocker** | **Fixed:** the image and ConfigMap set `NODE_ENV=production`, the preflight refuses dev-only toggles, and a JSON error handler returns no stack traces |
| S3 | The paywalled Messaging installer would be served publicly by Vercel's CDN; the only block was Express middleware | High | **Fixed:** removed from the Vercel output (`tools/deploy/prune-static-output.mjs`), a redirect covers the path, and CI asserts it is absent |
| S4 | Kubelet and LB health probes got a 308 to `https://<podIP>`, so pods would never become Ready | **Blocker** | **Fixed:** `/api/v1/healthz` and `/api/v1/readyz` are mounted ahead of HTTPS enforcement |
| S5 | Behind a proxy, the registration limiter had one bucket for all users (8 sign-ups / 15 min platform-wide), and other limiters trusted a spoofable leftmost `X-Forwarded-For` | High | **Fixed (opt-in):** `TRUSTED_CLIENT_IP_HEADER`, enabled together with the Cloudflare-only LB allow-list (`cloudflare-origin-lock`) |
| S6 | Cross-tenant token reuse: Azure, GCP and registry token caches were keyed by non-secret identifiers | High | **Fixed:** cache keys include a SHA-256 of the secret material |
| S7 | Any tenant could cancel another tenant's authorized scan by job id | Medium | **Fixed:** cancel checks ownership, and a foreign id returns 404 |
| S8 | Platform repo tokens (`GITHUB_TOKEN` …) would be inherited by every tenant's Dev scan | High | **Fixed:** ignored in production unless `ALLOW_PLATFORM_REPO_TOKEN=true`; the preflight refuses them |
| S9 | Anonymous endpoints accepted 80 MB JSON bodies, and every body was copied twice | Medium | **Fixed:** a 256 KB limit on auth, public-scan and webhooks; the raw body is no longer copied |
| S10 | Admin audit rows stored full URLs including `?token=<JWT>` | Medium | **Fixed:** path only; the access log redacts credential parameters |
| S11 | SSRF: several fetch-based scanner probes follow redirects without re-validating the address. Inside a cluster that reaches 169.254.169.254, cluster services and the VPC | High | **Contained:** the NetworkPolicy blocks private, link-local, CGNAT and loopback egress. **Phase 2:** code-level `safeFetch` in those probes |
| S12 | The public scan resolves cluster-internal names (e.g. `kubernetes.default`), revealing ClusterIPs in DNS evidence | Medium | **Contained** (the egress policy blocks connections). **Phase 2:** call the existing `verifyPublicHost` before scanning |
| S13 | The share-password attempt counter is not atomic (read-then-write) | Medium | **Phase 2:** atomic RPC (`UPDATE … SET attempts = attempts + 1 RETURNING`) |
| S14 | JWT in the SSE query string (`?token=`) | Medium | **Mitigated:** redacted from logs, and direct-to-API routing keeps it out of Vercel logs. **Phase 2:** short-lived stream tickets |
| S15 | Browser profiles (Cookies / Login Data files), crash dumps and logs tracked in git (`.codex-tmp/`) | Medium | `.gitignore` updated; **run `git rm -r --cached .codex-tmp .codex-logs .playwright-cli`** (runbook §0) |
| S16 | Permissions-Policy `microphone=()` silently disabled Sophia voice input in production only | Low | **Fixed:** `microphone=(self)`; still fully denied on `/vault/shared` |

What was verified as already sound:

- **RLS:** enabled on all 152 tables.
- **Service key:** server-only; the built bundle holds only the anon JWT.
- **PayPal webhooks:** signature-verified and idempotent.
- **SECURITY DEFINER helpers:** guarded inside, with no mutable `search_path`.
- **Public scanner:** DNS-pinned SSRF guard.

## 2. CI/CD security gates (`.github/workflows/ci.yml`)

| Gate | Blocking |
|---|---|
| TypeScript (`npm run lint`) | Yes |
| Client/server bundle boundary (`npm run check:boundary`) | Yes |
| Deployment-readiness suite (`npm run check:deploy`, 50 checks) | Yes |
| Domain regression suites (scanner accuracy 143, agent access 110, crypto classification/detection, hero grading) | Yes |
| Production build + gated-artefact pruning + "no server secret in bundle" grep | Yes |
| gitleaks secret scan (full history) | Yes. Note: the committed fallback key in history will flag until history is rewritten or the finding is allow-listed **after rotation** |
| Container: build, ML-KEM capability, boot/probe/drain, unsafe-config refusal | Yes |
| Kubernetes manifests: kustomize + kubeconform (strict) | Yes |
| `npm audit --omit=dev --audit-level=high` | Reported (make blocking after triage) |
| Trivy image scan (CRITICAL/HIGH, fixed only) | Reported (make blocking after triage) |
| Production deploy | GitHub Environment approval; immutable SHA promotion; automatic rollback |

Also enforced in the image:

- The runtime image runs as uid 1000 with a read-only root filesystem, all
  capabilities dropped and seccomp `RuntimeDefault`.
- The npm used in the image blocks unapproved install scripts; none of the
  blocked scripts is needed at runtime.

## 3. Observability

Built in:

- **Structured logs:** every API request logs one JSON line (`ACCESS_LOG=true`)
  with `requestId`, method, redacted path, status, duration, `version` and
  `commit`.
- **Lifecycle events:** `server_listening` (with Node/OpenSSL versions),
  `config_warning`/`config_error`, `shutdown_*` and `unhandled_error`.
- **Correlation:** `X-Request-Id` on every response. An inbound id is reused
  only if it is a safe token.
- **Health:**
  - `/api/v1/healthz` is liveness only.
  - `/api/v1/readyz` reports drain state, config, a measured Supabase probe
    (reachability/latency, cached 15 s, never blocks more than 1.5 s) and the
    PostgREST gate saturation.
  - `/api/v1/health` is kept unchanged for the docs page.
- **Deployment identity:** the image carries `APP_VERSION`/`GIT_SHA`. `/readyz`
  and the deploy smoke test confirm the running version.

Recommended MVP stack (no in-cluster storage needed):

| Signal | Tool | Cost |
|---|---|---|
| Container logs | DOKS → DigitalOcean *Monitoring/Log forwarding*, or ship the JSON lines to Better Stack / Grafana Cloud free tier | $0–$ |
| Node/pod metrics | DOKS built-in Insights (CPU, memory, restarts) plus DO Monitoring alerts | $0 |
| Uptime | External check on `https://api.qguardhelix.com/api/v1/readyz` and `https://qguardhelix.com` every 1 min | $0 |
| Frontend | Vercel Observability (and External Origins if the `/api` rewrite is used) | incl. |
| Database | Supabase reports, advisors, query performance; alert on CPU, connections and disk | incl. |
| Errors | Optional Sentry (frontend and API); not added to avoid a new dependency without a DSN | — |

Minimum alerts:

- `readyz` non-200 for more than 2 min.
- Pod restarts above 3 per 10 min.
- Node memory above 85%.
- Supabase CPU above 80% or disk above 80%.
- Any `config_error` or `shutdown_forced` log line.
- A spike in the 5xx rate in the access log.

Never logged:

- Passwords, tokens and keys: query credentials are redacted, and the preflight
  names variables, never values.
- Request bodies, scan payloads and vault data.

## 4. Backup and disaster recovery

| Asset | Backup | RPO | RTO |
|---|---|---|---|
| Postgres (all tenant data) | Supabase Pro daily backups (7 days). **Recommended:** PITR add-on (needs Small compute), plus a weekly off-site `supabase db dump` to encrypted object storage | 24 h daily; ≈2 min with PITR | 1–4 h (restore into a new project, verify, switch) |
| Supabase Storage (vault/chat encrypted files, avatars) | **Not covered by DB backups.** Scheduled rclone copy through the S3-compatible endpoint to DO Spaces (Phase 2 CronJob) | 24 h (once scheduled) | hours |
| Auth users | Included in the database backups | as DB | as DB |
| API | Stateless. The image is in DOCR (by SHA) and the manifests are in git | 0 | minutes (redeploy) |
| Frontend | Immutable Vercel deployments | 0 | seconds (promote previous) |
| Secrets | K8s Secrets + Supabase function secrets. Keep an encrypted offline copy (password manager / sealed file) | — | minutes |
| DNS / Cloudflare | Export the zone file after every change | — | minutes |

**Recovery drill (quarterly):** restore the latest backup into a scratch
project, point a staging API at it, and run the smoke test.

## 5. Failure behaviour

| Failure | What users see | Automatic handling | Operator action |
|---|---|---|---|
| Vercel down | Site does not load | — | Wait, or temporarily serve `dist/` from the API image (`SERVE_STATIC=true` build) |
| Cloudflare down | API unreachable; site loads | — | Switch `api` to DNS-only (and remove the `cloudflare-origin-lock` component) |
| Supabase down | Auth and data fail. Dashboards show empty/unknown states, never fabricated values | `readyz` → `degraded` (pods stay in service); Supabase fetch retries | Watch status.supabase.com |
| Redis down | N/A (not used in MVP) | — | — |
| API pod crash | Brief 502s; SSE clients reconnect | Liveness restart; the new pod is ready in about 5–30 s | Check logs by `requestId` |
| Node failure | 30–90 s interruption | Pod rescheduled to the second node | Replace the node (DOKS auto-repair) |
| Bad deploy | Nothing (never becomes Ready), or a failed smoke test | Rollout stalls or the smoke test fails, then automatic `rollout undo` | Fix forward |
| Failed DB migration | — | — | Migrations are expand/contract, so the old code keeps working. Restore from PITR only for data corruption |
| Payment provider down | Checkout/billing errors | Webhook idempotency; reconciliation job (optional component) | Re-run reconciliation |
| External scan target slow | Scan stream shows per-target timeouts | Per-target budgets (8–45 s); LB idle 600 s | — |
