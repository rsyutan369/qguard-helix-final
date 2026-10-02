# QGuard Helix — Phase 1 MVP Production Deployment

This folder is the source of truth for deploying QGuard Helix to production.
It was produced from a full audit of the repository (September 2026) and
describes what is **implemented in the codebase**, what must be **configured on
each platform**, and what is **deliberately deferred**.

| Document | What it answers |
|---|---|
| [01-ARCHITECTURE.md](01-ARCHITECTURE.md) | How the system works today, target MVP architecture, service boundaries, scaling limits, Redis/Kubernetes strategy, repository structure, future evolution |
| [02-ENVIRONMENT.md](02-ENVIRONMENT.md) | Every environment variable, classified (public / server / secret, build / runtime, required / optional), per environment |
| [03-RUNBOOK.md](03-RUNBOOK.md) | Exact first-time setup and deployment steps (Supabase, DigitalOcean, Cloudflare, Vercel, GitHub), smoke tests, rollback |
| [04-SECURITY-AND-OPERATIONS.md](04-SECURITY-AND-OPERATIONS.md) | Security findings and fixes, CI security gates, observability, backups, disaster recovery, failure behaviour |
| [05-READINESS-CHECKLIST.md](05-READINESS-CHECKLIST.md) | Production readiness checklist with current status, and the Phase 2+ roadmap |

## Verdict

**The codebase is deployable to the Vercel + Supabase + DigitalOcean Kubernetes
topology once the platform steps in the runbook are done.** Before this work it
was not. There was no container image, no Kubernetes manifests, no CI/CD, no SPA
routing for Vercel, and several defects that only appear behind a load balancer.
Examples: probes redirected to HTTPS, the registration rate limit collapsing into
one bucket for every user, and the paywalled installer being publicly
downloadable from a CDN.

Four items **must be handled by you before go-live**. Code cannot fix them:

1. **Rotate the leaked Supabase key.** A `service_role` key for the *fallback*
   Supabase project (ref `hies…`) was committed in `.env.example` and has been
   on GitHub since June 2026. The file is now names-only, but rotation is the
   real fix: rotate that project's JWT secret / API keys, or delete the project.
2. **Upgrade the Supabase organisation to Pro.** It is on the Free plan today,
   which has no platform backups and can be paused. The project ref and URL are
   unchanged, so this is non-breaking.
3. **Configure custom SMTP in Supabase Auth.** Without it, confirmation and
   password-reset emails only reach project team members.
4. **Keep the API at 1 replica.** Scale out only after the Phase 2 shared-state
   work ([01-ARCHITECTURE.md § Scaling](01-ARCHITECTURE.md#5-scaling-limits-and-why-replicas-1)).

## At a glance

```
                    ┌──────────────────────────── Cloudflare (DNS, WAF, TLS) ─────────────────────────────┐
 Browser ──HTTPS──► │ qguardhelix.com  (DNS-only / grey)          api.qguardhelix.com  (proxied / orange) │
                    └──────────┬──────────────────────────────────────────────┬───────────────────────────┘
                               ▼                                              ▼
                    Vercel (static SPA, CDN)                DigitalOcean HTTP Load Balancer (TLS: Origin CA)
                    · dist/ + SPA fallback                                    ▼
                    · /api/* rewrite → api host (safety net)   DOKS: Deployment qguard-api (1 pod, 2 nodes)
                               │                               · Express API + scanner engines
                               │  VITE_API_ORIGIN (direct)     · probes /healthz /readyz · graceful drain
                               └──────────────────────────────►│
                                                               ▼
                                   Supabase Pro (Postgres + RLS, Auth, Storage, Realtime, Edge Function `billing`)
 Customer agents ──HTTPS──► api.qguardhelix.com        PayPal webhooks ──► Supabase Edge Function `billing`
```
