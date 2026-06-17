# Deployment Security Headers — QGuard Helix

Ready-to-use HTTP security-header configs for every common host. Pick the file
that matches your platform; they all apply the **same** header set.

## How this fits together

- The **full Content-Security-Policy** (script-src SHA-256 hash, your Supabase
  `connect-src`, `img-src`, etc.) is injected into `index.html` as a `<meta>` at
  **build time** by `vite.config.ts`. It is always correct for the exact build you
  ship and updates automatically — nothing to maintain.
- These **header configs** add what a `<meta>` tag cannot express:
  `Strict-Transport-Security` (HSTS), `frame-ancestors`/`X-Frame-Options`
  (clickjacking), `Referrer-Policy`, `Permissions-Policy`, and
  `Cross-Origin-Opener-Policy`. They are env-agnostic, so they never break when you
  point the app at a different Supabase project.

> Net effect: the build owns the resource policy; the host owns transport &
> framing protection. Defense in depth, with nothing to keep in sync.

The canonical header set (applied site-wide):

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=()` |
| `Cross-Origin-Opener-Policy` | `same-origin-allow-popups` |
| `Content-Security-Policy` | `frame-ancestors 'none'` |

Plus a tighter override on `/vault/shared/*` (protects the URL-fragment key):
`Referrer-Policy: no-referrer` and `Cache-Control: no-store`.

---

## Per-platform

### Vercel
`vercel.json` (repo root) — already included. Vercel applies it automatically on
deploy. No further action.

### Netlify
`public/_headers` ships to the publish dir (`dist/_headers`) and Netlify applies it
automatically. *Alternative* if you prefer TOML, add to `netlify.toml`:
```toml
[[headers]]
  for = "/*"
  [headers.values]
    Strict-Transport-Security = "max-age=63072000; includeSubDomains"
    X-Frame-Options = "DENY"
    X-Content-Type-Options = "nosniff"
    Referrer-Policy = "strict-origin-when-cross-origin"
    Permissions-Policy = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=()"
    Cross-Origin-Opener-Policy = "same-origin-allow-popups"
    Content-Security-Policy = "frame-ancestors 'none'"
[[headers]]
  for = "/vault/shared/*"
  [headers.values]
    Referrer-Policy = "no-referrer"
    Cache-Control = "no-store, max-age=0"
```

### Cloudflare Pages
`public/_headers` → `dist/_headers` is read automatically (same format as Netlify).
Nothing else to do.

### DigitalOcean
- **App Platform (static site):** add to your app spec (`.do/app.yaml`) under the
  static site component:
  ```yaml
  static_sites:
    - name: qguard
      # ...build config...
      catchall_document: index.html   # SPA fallback
      cors: {}
      headers:
        - path: /
          name: Strict-Transport-Security
          value: "max-age=63072000; includeSubDomains"
        - path: /
          name: X-Frame-Options
          value: "DENY"
        - path: /
          name: X-Content-Type-Options
          value: "nosniff"
        - path: /
          name: Referrer-Policy
          value: "strict-origin-when-cross-origin"
        - path: /
          name: Permissions-Policy
          value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=()"
        - path: /
          name: Cross-Origin-Opener-Policy
          value: "same-origin-allow-popups"
        - path: /
          name: Content-Security-Policy
          value: "frame-ancestors 'none'"
  ```
- **Droplet / VPS (nginx):** use `deploy/nginx-security-headers.conf`.

### Hostinger / cPanel / Apache
`public/.htaccess` → `dist/.htaccess` ships with the build. Upload the contents of
`dist/` to your web root. Requires Apache 2.4+ (`mod_headers`, `mod_rewrite`). If
your pipeline strips dotfiles, copy `.htaccess` into the web root manually.

### Generic nginx (any provider)
`deploy/nginx-security-headers.conf` — a complete `server` block. Set `root` to your
`dist/` and `include` it (or paste it). Note the documented `add_header`
inheritance quirk handled inside the `/vault/shared/` location.

---

## Optional: enforce the FULL CSP at the header level too

The `<meta>` already enforces the full resource policy. If you also want it as an
HTTP header (slightly earlier enforcement), copy the **exact** policy from your
built `dist/index.html` — it already contains the correct script hash and your
Supabase origins:

```bash
# Extract the live policy from the build:
grep -o 'content="[^"]*"' dist/index.html | head -1
```

Then set `Content-Security-Policy` to that value **plus** `; frame-ancestors 'none'`,
replacing the `frame-ancestors 'none'`-only value in your chosen config.

⚠️ Caveats if you go this route:
- The `script-src 'sha256-…'` hash must match the inline bootstrap in
  `index.html`. If you edit that script, re-copy the policy after rebuilding.
- The `connect-src` must list the Supabase project(s) the deployed build actually
  uses. The `<meta>` is generated from your build env, so it is always right —
  a hand-copied header can drift. This is why the default keeps the full CSP in
  the `<meta>` and only `frame-ancestors` in the header.

---

## Verify after deploy

```bash
curl -sI https://your-domain.example | grep -iE 'content-security|strict-transport|x-frame|referrer|permissions|opener|content-type-options'
```
Or scan at https://securityheaders.com and https://csp-evaluator.withgoogle.com.

## Notes
- **HSTS `preload`:** not enabled by default. Only add `; preload` (and submit to
  https://hstspreload.org) once every subdomain is HTTPS-only — it is hard to undo.
- **SPA fallback:** each config routes unknown paths to `index.html` so deep links
  like `/vault/shared/<id>` work on reload. Vercel/Netlify/Cloudflare/DO App
  Platform handle this via their static-site presets / `catchall_document`.
