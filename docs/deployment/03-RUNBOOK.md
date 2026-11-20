# 03 — Deployment runbook

> Updated 2026-11-19: the obsolete DigitalOcean Kubernetes deployment workflow
> and shared deployment action have been removed at the owner's request.
> DOKS provisioning, automatic staging/promotion, and automatic rollback described
> below are historical reference; they are not active GitHub Actions automation.
> CI still builds and checks the API image.

Do the steps in order. Every step that is not automated by the pipelines is
marked **(manual)**. Region: keep everything in **Singapore (SGP1)**, next to the
Supabase project (ap-southeast-1). Each PostgREST round trip multiplies with a
dashboard's 12–54 queries.

---

## 0. Pre-flight (manual, once)

1. **Rotate the leaked fallback-project key.** In the Supabase dashboard of the
   fallback project (ref `hies…`, owned by a different account than
   `xsbdlahuecadzfajlvis`):
   - either roll the JWT secret / disable the legacy API keys,
   - or delete the project if it is no longer needed.

   Optionally purge the key from git history afterwards (`git filter-repo`).
   Rotation is what closes the exposure.
2. **Remove tracked browser profiles and logs from git.** The files stay on
   disk; `.gitignore` already covers them:
   ```bash
   git rm -r --cached .codex-tmp .codex-logs .playwright-cli
   git commit -m "Stop tracking local tool state"
   ```
3. **Upgrade the Supabase organisation to Pro.** Billing only; no URL or key
   change.
4. **Take an off-site logical backup** before any schema work:
   ```bash
   supabase db dump --db-url "$DB_URL" -f prod-schema.sql
   supabase db dump --db-url "$DB_URL" --data-only -f prod-data.sql
   ```

## 1. Supabase (manual)

**Production project `xsbdlahuecadzfajlvis`**:

- **Auth → URL Configuration**
  - Site URL: `https://qguardhelix.com`.
  - Redirect URLs: `https://qguardhelix.com/dashboard`,
    `https://qguardhelix.com/reset-password`, `https://qguardhelix.com/auth/confirm`,
    `https://qguardhelix.com/auth/callback`, `https://qguardhelix.com/auth/confirm/public-scan`,
    and the `www.` variants if served.
  - Keep existing entries used by the messaging app.
- **Google sign-in:** the web app uses PKCE and returns to `/auth/callback`
  on the origin where sign-in began. For local development, allow the exact
  callback on the port being used (for example,
  `http://localhost:3001/auth/callback`). Complete the login in the same
  browser tab so its session-stored verifier is available. Google Cloud's
  authorized redirect URI remains the Supabase project's
  `https://<project-ref>.supabase.co/auth/v1/callback`. Configure the public
  name, logo, homepage, privacy policy, and terms under Google Auth Platform
  Branding and submit brand verification as required. A Supabase custom auth
  domain requires its paid custom-domain add-on and a matching callback URI
  in Google Cloud before activation.
- **Auth → Email Templates → Confirm sign up:** deploy the full platform app
  with `/auth/confirm` first. Then paste
  [the signup template](../../supabase/templates/confirm-signup.html)
  into the Supabase project used by the web deployment. Compare that project's
  reference with the hostname in the deployed `VITE_SUPABASE_URL` before
  saving. The template selects the branded link for the exact web callback and
  uses the standard confirmation link for other clients. If a separate
  fallback Auth project issues web signup emails, configure it with the same
  allowlist and add `&amp;source=fallback` after the token in its branded link.
  Keep SMTP click tracking off for Auth mail. Test with a fresh signup after
  saving, since messages already sent still contain their original URL.
- **Auth → SMTP:** custom SMTP (Resend / Postmark / SES) with SPF, DKIM and
  DMARC records in Cloudflare DNS. Raise the email rate limit above the default.
- **Auth settings**
  - *Confirm email*: **ON**.
  - *Secure email change*: **ON**.
  - Enable **leaked-password protection** (a Pro feature).
- **Database**
  - SSL enforcement: ON.
  - Consider PITR, which needs Small compute (+$15/mo).
- **Edge Function `billing`**
  - Must stay `verify_jwt = false`. Always deploy it with the
    *Deploy Supabase Edge Function* workflow, which passes `--no-verify-jwt`,
    or run manually:
    ```bash
    supabase functions deploy billing --project-ref xsbdlahuecadzfajlvis --no-verify-jwt
    ```
  - Set its secrets:
    `supabase secrets set --project-ref … PAYPAL_CLIENT_ID=… PAYPAL_CLIENT_SECRET=… PAYPAL_ENV=live PAYPAL_WEBHOOK_ID=… APP_ORIGIN=https://qguardhelix.com PAYPAL_PLAN_…`
- **Owner account:** make sure the owner account already exists and is
  confirmed. Owner rights are granted by email.

**Staging project** (new, same Pro org):

- Create `qguard-helix-staging`.
- Give it the schema, then point Vercel Preview and the `qguard-staging`
  namespace at it. Two ways to create the schema, in order of preference:
  - **Preferred (repeatable):** adopt the Supabase CLI migration workflow.
    ```bash
    supabase init          # adds supabase/config.toml; the loose *.sql files are untouched
    supabase link --project-ref xsbdlahuecadzfajlvis
    supabase migration repair --status reverted 20260922031932 20260922053306 20260922053848 20260922055212 20260923060808
    supabase db pull       # baseline: supabase/migrations/<ts>_remote_schema.sql
    ```
    Then:
    - Hand-write `<ts>_platform_objects.sql` for what `db pull` omits: the
      2 `auth.users` triggers, storage buckets and their 16 policies, the
      `cron.schedule` job, `supabase_realtime` membership, and Data API grants.
    - Mark both as applied on production with
      `supabase migration repair --status applied <ts>`.
    - `supabase db push` them into staging.
    - Compare against production: table/policy/function counts and advisors.
    - Add `[functions.billing] verify_jwt = false` to `config.toml`.
  - **Interim:** restore `prod-schema.sql` (from step 0.4) into staging.

## 2. DigitalOcean (manual, once)

1. **Container Registry:** create it (Basic, $5), e.g. named `qguard`. Enable
   garbage collection.
2. **Kubernetes cluster** in SGP1:
   - 1 node pool, 2 × `s-2vcpu-4gb`, latest 1.33+ version, VPC-native.
   - Integrate the registry with the cluster (registry settings →
     *DigitalOcean Kubernetes integration*).
3. **Origin certificate:**
   - In Cloudflare → SSL/TLS → Origin Server, create a certificate for
     `api.qguardhelix.com` (and `api-staging.qguardhelix.com`).
   - In DO → Networking → Certificates → *Upload*, name them
     `qguard-api-origin-production` and `qguard-api-origin-staging`. These names
     match the Service annotations.
4. **Secrets**, from a file **outside** the repo, filled from
   `deploy/k8s/secrets.example.env`:
   ```bash
   doctl kubernetes cluster kubeconfig save <cluster>
   kubectl apply -f deploy/k8s/overlays/production/namespace.yaml
   kubectl -n qguard-production create secret generic qguard-api-secrets \
     --from-env-file=$HOME/qguard/api.production.env --dry-run=client -o yaml | kubectl apply -f -
   # repeat for qguard-staging with the STAGING Supabase project's values
   ```
5. **DO API token for CI:** create a scoped token with *registry* and
   *kubernetes* read/write access.

## 3. GitHub (manual, once)

- **Settings → Environments:**
  - Create `staging` and `production`.
  - Add required reviewers to `production`.
  - Add these environment secrets to both:
    - `DIGITALOCEAN_ACCESS_TOKEN`
    - `SUPABASE_ACCESS_TOKEN`
    - `SUPABASE_PROJECT_REF` (the matching project for each environment)
- **Settings → Variables:** `DOCR_REGISTRY=qguard`, `DOKS_CLUSTER=<name>`,
  `API_HOST_STAGING=api-staging.qguardhelix.com`,
  `API_HOST_PRODUCTION=api.qguardhelix.com`.
- **Branch protection on `main`:** require the **CI** workflow checks.

## 4. First API deployment

1. Merge to `main`. **CI** runs:
   - Typecheck, then the boundary, deploy and domain suites.
   - The build, with pruning of gated artefacts.
   - Secret scan, dependency audit, and container boot/probe/drain.
   - The unsafe-config refusal test, and manifest validation.
2. **Deploy API** then builds the image `registry.digitalocean.com/qguard/qguard-api:<sha>`
   and rolls it out to `qguard-staging`. The rollout waits for readiness,
   smoke-tests `https://api-staging…/api/v1/readyz` (including the version
   check), and **rolls back automatically** on failure.
3. Find the load balancer's IP:
   ```bash
   kubectl -n qguard-staging get svc qguard-api -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
   ```
4. Promote to production: *Actions → Deploy API → Run workflow* with
   `environment=production` and `image_tag=<full 40-char SHA>`. A reviewer
   approves, and the same image rolls out to `qguard-production`.

## 5. Cloudflare (manual)

| Record | Type | Target | Proxy |
|---|---|---|---|
| `api` | A | production LB IP | **Proxied (orange)** |
| `api-staging` | A | staging LB IP | Proxied |
| `@` (apex) | A | `76.76.21.21` (Vercel) | **DNS only (grey)** |
| `www` | CNAME | `cname.vercel-dns.com` | DNS only |
| `staging` | CNAME | `cname.vercel-dns.com` | DNS only |

Use the IP and CNAME values the Vercel dashboard shows for your project.

- **SSL/TLS:** mode **Full (strict)**.
- **Speed:** Rocket Loader, Email Obfuscation and Mirage all **OFF**. They
  rewrite HTML and break the hash-pinned CSP, which shows as a blank page.
- **Security:**
  - Bot Fight Mode **off** for `api.`: agents, PayPal and Google push are
    machines and would be challenged.
  - Add one rate-limiting rule on `api.qguardhelix.com/api/v1/public-scan*`,
    per IP and looser than the app's own limits (at least 20 requests a
    minute). The app already queues, shares and rate-limits public scans, and
    tells the visitor why. A tighter edge rule refuses visitors the app would
    have queued, and they see a bare error instead. See `02-ENVIRONMENT.md`,
    *Public scanner capacity*.
- **Caching:** add a *Cache Rule* "Bypass cache" for `api.qguardhelix.com/*`.
- **After the API answers through Cloudflare, lock the origin:**
  - Uncomment `../../components/cloudflare-origin-lock` in
    `deploy/k8s/overlays/production/kustomization.yaml` and deploy.
  - This restricts the LB to Cloudflare's IP ranges and sets
    `TRUSTED_CLIENT_IP_HEADER=cf-connecting-ip`, so rate limits become
    per-visitor.
  - Re-check <https://www.cloudflare.com/ips-v4/> first.

## 6. Vercel (manual, once)

1. Import the GitHub repo. Framework **Vite**; root = repo root.
   `vercel.json` already sets install/build/output. Node **24.x**
   (`engines` in `package.json` allows 22.12+).
2. **Environment variables:**

   | Name | Production | Preview |
   |---|---|---|
   | `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY` | prod project | staging project |
   | `VITE_API_ORIGIN` | `https://api.qguardhelix.com` | `https://api-staging.qguardhelix.com` |
   | `VITE_REPORT_VERIFICATION_ORIGIN` | `https://qguardhelix.com` | `https://staging.qguardhelix.com` |

   Set **no** server secrets on Vercel.
3. **Domains:**
   - Add `qguardhelix.com` and `www` (redirect one to the other) and
     `staging.qguardhelix.com` (assigned to the staging branch or custom
     environment).
   - The staging API's `ALLOWED_ORIGINS` already accepts
     `https://qguard-helix-*.vercel.app`. Adjust it to your project slug.
4. **Deployment Protection:** Standard Protection keeps previews private.

## 7. Production smoke test (after every production release)

```bash
curl -fsS https://api.qguardhelix.com/api/v1/healthz
curl -fsS https://api.qguardhelix.com/api/v1/readyz        # status "ready", build.version == released SHA
curl -sI  https://qguardhelix.com/dashboard | head -1       # 200 (SPA fallback)
curl -sI  https://qguardhelix.com/downloads/QGuard-Messaging-Setup.exe | head -3   # 307 → /qguard-messaging, never the binary
curl -sI  https://qguardhelix.com/assets/ | head -1         # not index.html
```

In a browser:

- Sign in and open `/dashboard`.
- Open the Scanner and run a scan on an authorised host. The progress stream
  must keep flowing past 2 minutes.
- Open Quantum Readiness; live updates should arrive.
- Download a report.
- Check that Settings → Billing loads the plan.
- DevTools should show no CSP violations. API calls should go to
  `api.qguardhelix.com`, and every response should carry an `X-Request-Id`
  header.

## 8. Rollback

| Layer | How | Time |
|---|---|---|
| **API** (automatic) | The deploy action runs `kubectl rollout undo` when the rollout or smoke test fails | ~1–5 min |
| **API** (manual) | `kubectl -n qguard-production rollout undo deployment/qguard-api` (or `--to-revision=N`; 5 revisions kept), or re-run *Deploy API* with the previous good SHA | ~1–5 min |
| **Frontend** | Vercel → Deployments → previous production deployment → *Promote to Production* (instant) | seconds |
| **Edge Function** | Re-run *Deploy Supabase Edge Function* from the previous commit | ~1 min |
| **Database** | Migrations must be **expand/contract**: add columns/tables in release N, switch code in N+1, drop in N+2. So a code rollback never needs a schema rollback. For data loss: PITR (if enabled) or daily backup restore **into a new project first**, then promote | minutes–hours |
| **Config** | ConfigMap/Secret changes are applied by the deploy; roll back by reverting the commit (ConfigMap) or re-applying the previous env file (Secret), then `kubectl rollout restart` | minutes |
