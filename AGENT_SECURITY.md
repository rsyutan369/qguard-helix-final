# Agent Security — Environment Separation and Control-Plane Trust

Spec: `Qguard_Wiki/Agent_Installer_Refactor_Enhancements` §2, §3, §61, §62, §69.

---

## The defect this prevents

§2, quoted:

> The current configuration incorrectly identifies itself as
> `Environment: production` while communicating with `http://localhost:3000`.

That combination is not a misconfiguration a warning should tolerate. An agent
that believes it is in production while talking plaintext to a loopback address
will accept whatever answers on that port — and every security property
downstream (signed commands, tenant isolation, revocation) rests on the control
plane being the real one.

So the combination is now **representable and refused**, not merely discouraged.

---

## Environments

| Environment | Control plane | Plaintext allowed? |
|---|---|---|
| `development` | `http://localhost:3000` | Yes, **to a local address only** |
| `staging` | `https://api-staging.qguardhelix.com` | No |
| `production` | `https://api.qguardhelix.com` | No |

Configured through environment variables, never hard-coded (§2):

```bash
QGUARD_ENVIRONMENT=production
QGUARD_CONTROL_PLANE_URL=https://api.qguardhelix.com
```

`QGUARD_ENVIRONMENT` defaults to `development` when unset or unrecognised —
the safe-to-be-wrong value. Mislabelling production as development produces
loud validation noise and a refusal to enrol against a remote plaintext host;
the reverse silently blesses an insecure setup.

---

## What production refuses

`validateControlPlane()` in `src/lib/agent-installer/agent-environment.ts`:

- **Plaintext HTTP** — credentials, commands and telemetry would cross the
  network unprotected.
- **Loopback** — `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`.
- **Private ranges** — RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), link-local
  (`169.254/16`), IPv6 ULA (`fc00::/7`) and link-local (`fe80::/10`).
- **Internal suffixes** — `.local`, `.internal`, `.localhost`.
- **Non-HTTP schemes.**

Hostnames are matched **parsed, not by substring**. A substring check would
reject the legitimate production host `my-localhost-proxy.example.com` and —
far worse — accept `https://localhost.evil.example` as production because the
hostname merely *starts* with a permitted string.

---

## Three fail-closed enforcement points

1. **Installer generation** — `POST /api/v1/agent-installer/package` refuses with
   `CONTROL_PLANE_INSECURE` (500). This is the last point at which the platform
   controls what an agent will talk to; once a package is downloaded and run, a
   bad URL is on somebody's production host.

2. **Agent runtime boot** — `assertSecureControlPlane()` runs before enrolment
   and exits `78` (`EX_CONFIG`). No telemetry is sent and no host is read.

   ```
   $ QGUARD_ENVIRONMENT=production QGUARD_API_URL=http://localhost:3000 qguard-agent scan
   Insecure agent control-plane configuration for environment "production":
     • Production requires HTTPS. "http://localhost:3000" is plaintext, so agent
       credentials, commands and telemetry would cross the network unprotected.
     • Production cannot use the loopback or private address "localhost". An agent
       that believes it is in production must reach the real control plane, not
       whatever answers locally.

     Set QGUARD_CONTROL_PLANE_URL to the HTTPS production endpoint, or set
     QGUARD_ENVIRONMENT=development if this is a local instance.
   [qguard-agent] Refusing to start. No telemetry was sent and no host was read.
   ```

3. **Installer URL resolution** — explicit configuration wins over the
   request-derived fallback. Deriving a production endpoint from a `Host` header
   would let anyone who can reach the server choose where the agents they
   provision phone home.

---

## Dependency evidence honesty

Related, and worth recording because it was a real defect: the agent's package
classifier used to map dependency names to a specific algorithm **and key size**
— `openssl` → RSA-2048, `libsodium` → RSA-2048, `bcrypt` → SHA-256, `crypto-js`
→ AES-128.

Three were factually wrong (libsodium ships no RSA; bcrypt is Blowfish-derived,
not SHA-based) and all four invented a key size that appears in no manifest.
Those rows then flowed into the CBOM, the vulnerable-component count and the
migration plan as though something had been measured.

A dependency proves a **library is present**. That is availability, not usage:
OpenSSL provides dozens of algorithms and a project depending on it may use one
or none. The classifier now delegates to the knowledge base's library catalogue
(`providesAlgorithms` is documented as availability by design), reports at
**low** confidence, and names an algorithm only where the package name itself
states one — `ml-kem-768` does; `openssl` does not.

---

## Verification

```bash
npx tsx tools/agent-access-check.ts
```

Covers the exact §2 combination, every legitimate environment/URL pairing, the
substring-matching trap in both directions, the environment default, and
source-level assertions that all three enforcement points are still wired.

### §69 repository sweep

| Pattern | Production source |
|---|---|
| `TrustAllCertificates` | none |
| `DisableCertificateValidation` | none |
| `SkipCertificateCheck` | none |
| `node -e` | none |
| `$AgentToken =` | none |
| `http://localhost:3000` | `agent.ts` `DEFAULT_API_URL` (development default, gated by the validator above) and one `Host`-header fallback (explicit config wins). Everything else is dev/test tooling defaults. |
