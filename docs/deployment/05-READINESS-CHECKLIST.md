# 05 — Production readiness checklist

Legend:

- ✅ Done and verified in this change.
- 🟡 In the codebase, but it needs a platform step from `03-RUNBOOK.md`.
- ⬜ Not done: an owner action, or deferred to a later phase.

| Area | Status | Evidence / next step |
|---|---|---|
| Code structure | ✅ | Deployment layer added (`src/api-server/runtime/`, `deploy/`, `.github/`); `src/` layout, routes and APIs unchanged |
| Build | ✅ | `npm run build` passes (35 s); Vercel build command prunes gated artefacts |
| TypeScript | ✅ | `tsc --noEmit` exit 0 |
| Tests | ✅ | Deploy readiness 50/50, scanner accuracy 143/143, agent access 110/110, crypto classification + detection, hero grading, billing edge 12/12, bundle boundary PASS |
| Authentication | ✅ | Unchanged (Bearer / `?token=` streams, local ES256 verification); revocations refresh every 30 s in production |
| Authorization | ✅ | Subscription gateway unchanged; scan-cancel ownership fixed; owner-by-email unchanged |
| Database | 🟡 | Upgrade the org to Pro; adopt the CLI migration baseline; create a staging project |
| RLS | ✅ | 152/152 tables RLS-enabled (live audit); no policy changes made |
| Storage | 🟡 | Buckets unchanged; scheduled Storage backup (Phase 2) |
| API security | ✅ | Probes before HTTPS enforcement, JSON errors without stacks, body limits, CORS for split origin, token-free audit paths |
| Environment variables | ✅ | `02-ENVIRONMENT.md`; production preflight fails fast (exit 78) |
| Secrets | 🟡 | `.env.example` names-only; gitleaks in CI; **rotate the fallback `service_role` key**; untrack `.codex-tmp` |
| Docker | ✅ | Multi-stage, non-root, tini, read-only-FS compatible. Built and verified locally: boot 3 s, 306 MiB RSS, ML-KEM groups available, SIGTERM drain exits 0 |
| Kubernetes | ✅ | kustomize base, overlays and components render; probes, resources, PDB, NetworkPolicy, Pod Security `restricted` |
| Cloudflare | 🟡 | DNS/proxy/TLS settings in the runbook §5; enable `cloudflare-origin-lock` after proxying |
| Vercel | 🟡 | `vercel.json` (SPA fallback, `/api` rewrite, installer redirect, caching headers); set env vars and domains |
| Supabase | 🟡 | Auth URLs, custom SMTP, leaked-password protection, Edge Function deploy with `--no-verify-jwt` |
| Redis | ✅ (not needed) | Deliberately not provisioned for MVP; Phase 2 adapters |
| GitHub Actions | 🟡 | Workflows committed; create environments, variables and secrets |
| Monitoring | 🟡 | JSON logs, request ids, `/readyz`; wire uptime checks and alerts |
| Logging | ✅ | Structured access log with credential redaction |
| Backups | ⬜ | Requires Supabase Pro (+ PITR recommended) and a Storage backup job |
| Disaster recovery | 🟡 | Procedures documented (04 §4–5); schedule the first restore drill |
| Rollback | ✅ | Automatic `rollout undo` on a failed rollout or smoke test; Vercel instant rollback |
| Performance | 🟡 | 1 replica, 512Mi–1.5Gi; 8.8 MB main JS chunk (code-splitting is Phase 2); move 60 MB of videos to a CDN |
| Security scanning | ✅ | gitleaks (blocking), Trivy + npm audit (reporting) |
| Dependency scanning | ✅ | npm audit in CI (reporting) |
| Production smoke tests | ✅ | Automated in the deploy action; manual list in runbook §7 |
| Documentation | ✅ | `docs/deployment/*` |

## Phase 2+ roadmap (deferred on purpose — not needed to launch)

1. **Horizontal scaling:**
   - Optional `REDIS_URL` adapters for the agent event bus, share alerts,
     rate limits and cache invalidation.
   - Schedulers behind a flag, or run by a single worker.
   - Then replicas ≥ 2, metrics-server and an HPA.
2. **Scanner SSRF (code level):** a shared `safeFetch` (DNS-pinned,
   `redirect: 'manual'` with a re-check at each hop) in the OCSP, web-crypto,
   api-security, k8s, registry and repo probes. Call `verifyPublicHost` in
   the public scan.
3. **Atomic share-attempt counter** (Supabase RPC) and unique indexes for the
   scheduler check-then-insert paths.
4. **Stream tickets** replacing `?token=` JWTs on SSE.
5. **Supabase CLI migrations** as the only schema path. Advisor gate in CI.
   Realtime publication sync (38 tables the dashboards subscribe to are not
   in `supabase_realtime`).
6. **Performance:**
   - Route-level code splitting (the main chunk is 8.8 MB).
   - Serve large media from Vercel Blob or a video CDN.
   - Precompile the API with esbuild (smaller image, faster start).
7. **Remove dead code** `src/app/api/**` after proving it has no references.
8. **Enterprise:**
   - HA control plane.
   - VPC NAT gateway (stable scanner egress IP).
   - Organisation-level tenancy, SSO/SAML/SCIM, SIEM export, multi-region.
