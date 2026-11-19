# Full platform deployment on Cloudflare Pages and a DigitalOcean Droplet

Cloudflare Pages serves the full React app at `https://qguardhelix.com`. The browser sends API requests and SSE connections to `https://api.qguardhelix.com`. Cloudflare Tunnel routes that hostname to the Droplet's Docker API on loopback. The API image contains the scanner engines. Supabase remains the account, database, Realtime, and provider webhook backend.

Use the same reviewed Git revision for the Pages build, Docker image, and Supabase functions. Preview the release before moving the production domain. Keep the previous Pages deployment and API image tag available for rollback.

## 1. Run the API and scanners on the Droplet

Install current Docker Engine with Compose and install `cloudflared` as a host service. Clone the repository and check out the release revision. Create an API environment file readable only by the server operator, such as `/etc/qguard/api.env`. Fill the Supabase URL, public key, and service role key from the same production project. Include PayPal configuration for Express Billing Settings and the other server features you enable. Use `.env.example` for names and keep production secret values on the server.

Set `APP_ORIGIN` and `PUBLIC_APP_URL` to `https://qguardhelix.com`, `ALLOWED_ORIGINS` to the exact frontend origins you serve, and `QGUARD_CONTROL_PLANE_URL` to `https://api.qguardhelix.com`. Set `READINESS_REQUIRE_SUPABASE=true`. The Compose service enforces subscription checks and leaves registration auto-confirm off. Use no global repository token and no Supabase fallback project.

Run from the repository root on the Droplet:

```bash
export RELEASE_SHA="$(git rev-parse HEAD)"
export QGUARD_API_IMAGE="qguard-api:$RELEASE_SHA"
export QGUARD_API_ENV_FILE=/etc/qguard/api.env
docker build --target runtime --build-arg "GIT_SHA=$RELEASE_SHA" -t "$QGUARD_API_IMAGE" .
docker compose -f deploy/droplet/compose.yaml config --quiet
docker compose -f deploy/droplet/compose.yaml up -d --wait
curl --fail-with-body -sS http://127.0.0.1:8080/api/v1/readyz
```

In the Cloudflare Tunnel dashboard, publish `api.qguardhelix.com` to `http://127.0.0.1:8080`. Keep port 8080 off the public network. Once the API is reachable only through the tunnel externally, use `TRUSTED_CLIENT_IP_HEADER=cf-connecting-ip`. Keep the API hostname out of caching rules and verify that Cloudflare forwards streaming responses. Restrict Droplet SSH to the operator's network.

```bash
curl --fail-with-body -sS https://api.qguardhelix.com/api/v1/readyz
curl -i -X OPTIONS https://api.qguardhelix.com/api/v1/revenue/snapshot \
  -H 'Origin: https://qguardhelix.com' \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: authorization'
curl -i https://api.qguardhelix.com/api/v1/revenue/snapshot
```

Require a JSON ready response from the release commit, CORS for the intended frontend origin, and a JSON `401` on the unauthenticated revenue route. [Cloudflare Tunnel setup](https://developers.cloudflare.com/tunnel/get-started/).

## 2. Build the full frontend on Cloudflare Pages

| Pages setting | Value |
| --- | --- |
| Project root | Repository root |
| Node version | 24 |
| Build command | `npm run build:cloudflare` |
| Output directory | `dist` |
| `VITE_API_ORIGIN` | `https://api.qguardhelix.com` |
| `VITE_SUPABASE_URL` | Same production Supabase URL as the Droplet |
| `VITE_SUPABASE_ANON_KEY` | Public key for that project |

Add only public build variables to Pages. The full build publishes `dist/` and removes the entitlement-gated desktop installer. The separate `build:public` command publishes a marketing-only site. For a Pages preview that needs login, use an explicit preview origin in the API CORS allowlist and Supabase Auth redirect URLs. Add the final website domain and confirmation URLs to Supabase Auth. Verify direct navigation and reload at `/dashboard/settings`, `/checkout`, and `/subscription/thank-you`. [Cloudflare Pages limits](https://developers.cloudflare.com/pages/platform/limits/).

For a local Cloudflare build, add this public setting to the gitignored
`.env.production` file at the repository root:

```dotenv
VITE_API_ORIGIN=https://api.qguardhelix.com
```

Then run `npm run build:cloudflare`. Vite and the post-build check both load
`.env`, `.env.local`, `.env.production`, and `.env.production.local`, with
the same precedence. A value supplied by the shell or Cloudflare Pages takes
priority. Keep this variable unset for local development when the API runs
inside Vite.

## 3. Align payments before enabling live checkout

1. Confirm the production Supabase project in all three places: Pages build variables, Droplet server variables, and the `billing` Edge Function. Apply `supabase/subscription-catalog-monthly-pricing.sql` to the existing project and deploy the `billing` function from the release revision using the production Supabase workflow. The deployed catalog for both providers must show Starter **$1/$12**, Basic **$8/$60**, Pro **$30/$240**, and Elite **$199/$1,800** for monthly/yearly USD list prices.
2. In the intended live PayPal REST app, change the existing listener to `https://<project-ref>.supabase.co/functions/v1/billing/api/v1/paypal/webhook`. Verify that `PAYPAL_WEBHOOK_ID` on the Edge Function matches that listener and that the same app's credentials and eight plan IDs are used for checkout. Keep the nine subscribed lifecycle, sale, refund, and reversal events. Set `paypal_reconcile_url` and the matching reconcile secret in Supabase Vault, then apply `supabase/paypal-reconcile-schedule.sql`. Confirm the latest cron execution and Edge result. For a read-only registration check, set `SUPABASE_PROJECT_REF` to the verified project and run `npx tsx tools/paypal-webhook-setup.ts --dry-run`. [PayPal webhook setup](https://developer.paypal.com/api/rest/webhooks/rest/).
3. In Google Play Console, verify the active regional base plan prices for `com.qguard.messaging`. The Android checkout uses Play's regional price. The Supabase migration changes Qguard's USD list price only. Wire Google Play RTDN through authenticated Pub/Sub push using the procedure in `qguard-messaging/docs/PAYWALL.md`. Verify a license-tester purchase, restore, renewal and cancellation before accepting production Play purchases. [Play Console pricing rules](https://developer.android.com/google/play/billing/price-changes).

## 4. Production acceptance

On a controlled release, verify registration and sign-in, a normal customer session and an owner session, customer billing, a permitted scan and report, and the installer download behind its entitlement check. Reload deep links and verify authorization remains intact on reconnect. Confirm a non-owner cannot read Revenue Intelligence or Admin data. Observe live Customer Billing, Admin and Revenue Intelligence streams from the deployed frontend.

Exercise PayPal's signed sandbox events for activation, sale, renewal, cancellation, and refund against the same release configuration before running an approved production Starter purchase. Verify the actual merchant sale, one correctly priced invoice, paid access, and matching updates in the three billing views. Compare the sale, fee and settled proceeds in PayPal Business. Check an eligible bank transfer from PayPal Wallet against the bank receipt if withdrawal is part of acceptance. Review the outstanding billing integrity findings in the audit before signing off on payment handling at scale.

During rollback, restore the previous Pages deployment and point `QGUARD_API_IMAGE` to the previous tested image tag. Run Compose again and confirm readiness. Leave payment histories and provider event records intact.
