# 06 — Public website (website edition)

The public website is a separate build of the same codebase. It ships the
marketing pages, the legal documents, the resources and the **free Web
assessment only**. The website includes the shared account flows for Public Scan. Dashboard, checkout,
Agent Center, Local/Dev engines, and reporting exporters are platform features.

```
 Browser ──► qguardhelix.com          Cloudflare Pages (free): dist-public/  — static files only
        └──► <public API origin>      Node 24 host: src/api-server/public-standalone.ts
                                      · /api/v1/public-scan   (account-authenticated Web assessment, SSE)
                                      · /api/v1/demo-request  (record and optionally send an inbox notification)
                                      · /api/v1/checklist-request  (record a checklist form submission)
                                      · /api/v1/healthz, /api/v1/readyz
                                      · every other /api path → 404
```

## Why two pieces

- **Cloudflare Pages can host the website.** It is static files.
- **Cloudflare cannot run the scanner.** The assessment opens raw TLS
  connections and offers each key-exchange group separately, including the
  hybrid ML-KEM groups. That needs Node 24's `node:tls` with OpenSSL 3.5. Cloudflare
  Workers expose neither, and the free plan allows 10 ms of CPU per request.
  So the scanner runs on a small Node host as the **public API**. The scanner
  verifies Supabase sessions and requires the project’s server-only service role
  to enforce the daily allowance. The public API exposes no admin routes.

## What keeps the platform out of the website

| Layer | Mechanism | Verified by |
|---|---|---|
| Routes | `src/PublicApp.tsx` loads public pages and shared account flows; platform paths render `PlatformOnly` | `tools/deploy/public-site-check.ts` |
| Entry | `vite build --mode public` swaps `index.html` to `src/main-public.tsx` (`websiteEditionPlugin` in `vite.config.ts`) | the check requires `src/main-public.tsx` in the bundle |
| Scan page | `VITE_SITE_EDITION=public` compiles out the Local/Dev panels (lazy `import()` in a dead branch) | the bundler's own module list, `.public-site/modules.json` |
| Files | `tools/deploy/prune-public-site.mjs` keeps only `public/` files the bundle names; internal screenshots and installers are never published | the check refuses `To_Fix/`, `To_Audit/`, `.exe/.msi/.apk/.aab`, `.map`, `.env*` |
| Secrets | — | the check decodes every JWT in shipped files and fails on `role: service_role` |
| Limits | — | the check enforces Cloudflare Pages' 25 MiB per file and 20,000 files |

The full platform build (`npm run build`, `dist/`) is unchanged apart from the
Local/Dev panels now loading on demand.

## Build and publish the website

```bash
# 1. Build with the public API's HTTPS address baked in (CSP connect-src + fetch routing)
VITE_API_ORIGIN=https://<public-api-host> npm run build:public
#    → dist-public/, pruned and checked. A WARN means VITE_API_ORIGIN is missing or plain http.

# 2. Publish (Cloudflare account login once: npx wrangler login)
npx wrangler pages deploy dist-public --project-name <your-pages-project>
```

Pages serves `index.html` for every route because `dist-public/` has no root
`404.html` (the check enforces this). `_headers` from `public/` carries HSTS and
the frame and referrer policies. The CSP is in the page as a `<meta>`.

Without a public API the website still works, but the assessment shows
"Connection to the assessment service was lost". The Request Demo form offers
a pre-filled email to info@qguardhelix.com instead.

## Run the public API

```bash
npm run start:public-api                     # local, port 8080
docker build --target public-api -t qguard-public-api .
```

| Variable | Value | Why |
|---|---|---|
| `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` | Same project used by the website | Session validation and quota storage. The service-role key stays on the server. |
| `ALLOWED_ORIGINS` | `https://qguardhelix.com,https://www.qguardhelix.com` | CORS: without it the website's browsers are refused |
| `TRUSTED_CLIENT_IP_HEADER` | `cf-connecting-ip`, **only** when the host accepts traffic from Cloudflare alone | per-visitor rate limits; otherwise `X-Forwarded-For` is caller-controlled |
| `SMTP_*`, `DEMO_REQUEST_TO` | see [02-ENVIRONMENT.md](02-ENVIRONMENT.md) | Optional demo inbox notification. Requests are still saved when SMTP is unset. |
| `PORT` | host-provided | — |

Node 24 is required for the hybrid ML-KEM probes; the image pins it. The scan line, cache and short-window rate limits are per API process. The daily
allowance is shared through PostgreSQL. Smoke test:
`GET /api/v1/readyz` returns `{"status":"ready","role":"public"}`.

## Release authenticated Public Scan

1. Confirm the API and website point to the same existing Supabase Auth project. Apply [the quota migration](../../supabase/public-scan-quota.sql) there before switching Web traffic. Use the anon key for browser auth and keep the service role on the API host. Keep registration auto-confirm off in production and enable email confirmation, Supabase Auth rate limits, and production SMTP. Apply the signup template and exact OAuth and email redirect allowlist in [the runbook](03-RUNBOOK.md).
2. Build and deploy the same reviewed revision to the API host and website with the [Droplet and Cloudflare Pages procedure](07-CLOUDFLARE-DROPLET.md), or the website-edition commands above. Include the actual browser origin in the API CORS allowlist. Trust the proxy IP header only when direct access to the API origin is blocked. Deny outbound traffic to internal and metadata networks at the infrastructure boundary as well. Keep the scanner endpoints uncached and preserve streaming for POST requests.
3. Verify the API release SHA in `/api/v1/readyz`. Check that anonymous POST requests and usage reads return 401. With a verified test account, check that usage starts at 3, actual progress arrives and the next distinct successful scans reduce the allowance to 2, 1, then 0. Confirm a fourth request returns 429 with the midnight UTC reset. Recheck using a fresh browser session and confirm that a second test account has its own allowance. Confirm the anonymous landing page still renders and sign-in returns to Public Scan.
4. For rollback, retain authenticated enforcement on the API. If this is unavailable during recovery, disable scan execution at the edge until the protected API is restored. Leave successful usage records in Supabase.

## Website submission monitoring

Apply [the website submissions schema](../../supabase/website-submissions.sql) to the same Supabase project used by the full platform Admin Console. Route both form endpoints to the full API or configure the standalone public API with that project's server-only Supabase URL and service-role credentials. Keep these credentials on the API host. Cloudflare Pages serves the frontend and static PDF.

Open **Administration → Website submissions** in the full platform as the configured owner. New records appear newest first and the view refreshes every 30 seconds. Demo requests retain notification status so the team can follow up during an email outage. Checklist entries represent saved form submissions that trigger the PDF download. Direct visits to the PDF and the browser's save result are outside that measurement.

## Self-hosted on your own VM ($0) — Cloudflare Tunnel

A VM at home or anywhere else works, with no public IP, no router port
forwarding and no certificate to manage. `cloudflared` on the VM makes an
**outbound** connection to Cloudflare, and Cloudflare serves
`https://scan-api.qguardhelix.com` through it. The tunnel is free on the
Cloudflare Free plan.

```
 Browser ──HTTPS──► Cloudflare edge ──tunnel (outbound from the VM)──► cloudflared ──► 127.0.0.1:8080 (public API)
```

1. **VM:** any 64-bit Linux (Ubuntu 24.04 is simplest), 1 vCPU / 1 GB RAM is
   enough. Install Node 24 (`nvm install 24`, or NodeSource), then:
   ```bash
   git clone <repo> qguard && cd qguard && npm ci --omit=dev
   ```
2. **Run it as a service** — `/etc/systemd/system/qguard-public-api.service`:
   ```ini
   [Unit]
   Description=QGuard Helix public API
   After=network-online.target
   [Service]
   WorkingDirectory=/home/<user>/qguard
   ExecStart=/usr/bin/env node --import tsx src/api-server/public-standalone.ts
   Environment=NODE_ENV=production HOST=127.0.0.1 PORT=8080
   Environment=ALLOWED_ORIGINS=https://qguardhelix.com,https://www.qguardhelix.com
   Environment=TRUSTED_CLIENT_IP_HEADER=cf-connecting-ip
   EnvironmentFile=-/etc/qguard-public-api.env
   Restart=always
   User=<user>
   [Install]
   WantedBy=multi-user.target
   ```
   SMTP credentials go in `/etc/qguard-public-api.env` (`chmod 600`), not in
   the unit. Then `sudo systemctl enable --now qguard-public-api`.
3. **Tunnel:** `cloudflared tunnel login`, `cloudflared tunnel create qguard-scan`,
   `cloudflared tunnel route dns qguard-scan scan-api.qguardhelix.com`, and
   `~/.cloudflared/config.yml`:
   ```yaml
   tunnel: qguard-scan
   credentials-file: /home/<user>/.cloudflared/<tunnel-id>.json
   ingress:
     - hostname: scan-api.qguardhelix.com
       service: http://127.0.0.1:8080
     - service: http_status:404
   ```
   `sudo cloudflared service install` keeps it running across reboots.
4. **Website:** `VITE_API_ORIGIN=https://scan-api.qguardhelix.com npm run build:public`, then publish.

Why these settings are safe:

- **`HOST=127.0.0.1`**: the API listens only on the VM's loopback, so
  `cloudflared` is the one way in. That is also what makes
  `TRUSTED_CLIENT_IP_HEADER=cf-connecting-ip` trustworthy, since every request
  has passed through Cloudflare. Do not set that header with `HOST=0.0.0.0`.
- **The home network is protected.** The scanner refuses private, loopback,
  link-local and reserved targets at connect time (`safe-dns.ts`), so visitors
  cannot use it to reach other machines on the VM's network.
- **Outbound scans use the VM's internet address.** Signed-in users can run bounded TLS and HTTPS checks against a public host.
  The API applies per-account throttling and the database enforces the three-scan daily quota.

Limits: the scanner is down whenever the VM is (the site then shows
"Connection to the assessment service was lost"); a home connection's upload
speed bounds how many people can scan at once.
