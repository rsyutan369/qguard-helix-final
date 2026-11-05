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

## Transport hardening (agent v1.6.0)

Pointing an agent at the right HTTPS URL is not enough if the connection can be
weakened on the way. Each of these fails closed.

| Risk | Control | Where |
|---|---|---|
| A redirect replays the agent token (a custom header) to another host or to `http://` | The agent's control-plane client uses `redirect: 'error'`; installers use curl without `-L`, `-MaximumRedirection 0`, and Node `fetch` with `redirect: 'error'` in containers | `agent.ts` `requestJson`, `installer-templates.ts` |
| Certificate verification disabled process-wide | `NODE_TLS_REJECT_UNAUTHORIZED=0` → refuse to start (exit 78) | `assertTrustedTransport()` |
| TLS floor lowered (`--tls-min-v1.0`) | Refuse to start; installers pin TLS 1.2+ (`--proto =https --tlsv1.2`, PowerShell `SecurityProtocol`) | same |
| A TLS-inspection proxy | Allowed via `NODE_EXTRA_CA_CERTS` and logged; it can read telemetry but request signatures stop it altering or forging any | same |
| Hung control plane | 30 s request timeout (`QGUARD_REQUEST_TIMEOUT_MS`) | `requestJson` |
| Agent credentials sent over plaintext to a production server | `426 AGENT_HTTPS_REQUIRED`, never a redirect (the token already crossed in the clear, so a redirect would only invite a retry); the loopback exemption needs a loopback *peer*, not just a `Host: localhost` header | `http-baseline.ts` `enforceHttps` |
| BusyBox `wget` in containers (certificate checks not verifiable, follows redirects) | Replaced by a small Node fetch script written to a file (never an inline one-liner) | docker / kubernetes templates |
| Installed agents silently ran in `development` trust mode (installers wrote only the *asset* label `QGUARD_AGENT_ENVIRONMENT`) | Installers stamp `QGUARD_ENVIRONMENT`, the control-plane environment the URL was validated against when the package was generated, so boot and generation apply identical rules | package route + templates |

## Request signing — integrity and replay protection above TLS

TLS protects the hop it terminates on. Enterprise networks often terminate it
early, and anything that can read that plaintext can also read the bearer token.
So from v1.6.0 every agent request is also **signed with a key that never leaves
the host** (`src/lib/agent-installer/agent-request-signing.ts`, scheme `qgs1`):

```
QGUARD-AGENT-REQUEST-V1 \n METHOD \n /api/v1/…path?query \n agentId \n timestamp(ms) \n nonce \n SHA3-256(body)
```

- **Algorithms:** Ed25519 always, plus **ML-DSA-65 (FIPS 204)** wherever the runtime provides it (Node 24+), which makes the signature hybrid. Ed25519 is the floor: an ML-DSA-only signature is refused.
- **Binding:** the agent's first signed request pins its public keys (`scanner_agents.signing_public_keys`, compare-and-set on `signing_key_version`). After that, these are all refused: another key (`KEY_MISMATCH`), a missing bound algorithm (`MISSING_BOUND_ALGORITHM`, which blocks downgrade), and no signature at all (`UNSIGNED`).
  - An agent that gains ML-DSA, while still signing with its bound Ed25519 key, *extends* the binding.
  - A control plane that cannot verify an algorithm never binds it.
- **Freshness:** a ±5 min timestamp window plus a per-agent nonce store. Replays return `REPLAYED`. A forged request cannot burn a legitimate nonce, because the nonce is recorded only after the signature verifies.
- **Path:** the signed path is the part from `/api/v1/` onward, so a reverse-proxy mount prefix doesn't break verification.
- **Every refusal** is a `401 AGENT_SIGNATURE_*` with guidance, and an `agent.request_signature_refused` audit row (throttled per agent and failure kind). Bind, extend and reset are audited too.
- **Provenance at rest:** each `agent_heartbeats` row stores `telemetry.transportIntegrity`: signed, algorithms, key fingerprints, the SHA3-256 of the exact signed bytes, bound, HTTPS, and the verification time. The Agent Center shows the same facts under **Transport security**.

### Keys at rest on the host

Keys are generated by the agent on first start. They are written owner-only (`0600`, atomically), with the control plane holding only the public halves. The state directory must persist:

| Platform | Location | Protection |
|---|---|---|
| Linux (systemd, cloud-init) | `/var/lib/qguard-agent` | `0700 root`, systemd `StateDirectory` |
| Windows service (1.6.2+) | `%ProgramData%\QGuardHelix\Agents\<agent-id>\state` | ACL SYSTEM + Administrators, inheritance protected; one task/config per identity |
| PowerShell portable | `%LOCALAPPDATA%\QGuardHelix\Agent\state` | user profile (private by default) |
| Docker | named volume `qguard-agent-state` | do not `down -v` |
| Kubernetes | PVC `qguard-agent-state` | `fsGroupChangePolicy: OnRootMismatch`, so the kubelet never re-chmods the key |

On POSIX, in staging and production, the agent refuses to start when its config (which holds the token) or its key file is readable by other users or owned by someone else.

Windows upgrades preserve the identity's bound key from the legacy shared
`%ProgramData%\QGuardHelix\Agent\state` directory. A newly installed task selects
its exact configuration with `--config`; an unreadable explicitly selected file
fails closed instead of falling through to another agent's configuration.
Startup verification requires a signed heartbeat containing the current launch
ID, rather than trusting a task's Running state or an older heartbeat. Local
startup logs inherit the private installation-directory ACL, redact the token,
and retain at most two 2 MiB files.

### Shared-host coordination (1.6.3+)

Each identity has its own installation, signing state and command queue. Readers
may run concurrently. Writers acquire a host mutation mutex before claiming jobs
and a lock beside the canonical target file before patching, validation and
rollback. Another live owner is never evicted by a timeout. Stale automatic
rollback cannot overwrite a newer configuration. Duplicate processes using the
same identity/state are refused without publishing an error on the live agent.

Job claims and agent/asset metadata updates use tenant-scoped compare-and-set
conditions. Write jobs must match the executor's assigned asset as well as its
authorized path/target. Only Patcher receives remediation jobs; only Migration
Operator receives migration jobs. Older writers are withheld from dispatch until
upgraded. See [agent coexistence and recovery](docs/AGENT_COEXISTENCE.md).

**Lost key** (host rebuilt, volume deleted): **Agent Center → agent → Transport security → Reset signing key**. This is audited and compare-and-set. Until the agent's next signed request re-binds, anyone holding the token could bind first, so rotate the token too if it may have leaked.

### Rollout and known limits

- **Apply `supabase/agent-request-signing.sql` first.** Without those columns, signatures are still verified per request (tamper, replay and freshness), but no key can be pinned. That means a party holding the token could strip or re-sign requests. The SQL also adds a trigger, so a tenant browser session cannot rewrite a binding through the Data API.
- **Pre-1.6 agents keep working** unsigned until upgraded. Set `QGUARD_AGENT_REQUIRE_SIGNED_REQUESTS=true` on the API to refuse them once the fleet is upgraded. An agent that has bound a key is always held to it, whatever this flag says.
- **The nonce store is per API instance.** Behind several replicas, a captured request could be replayed to *another* replica within the 5-minute window. It cannot be altered, and its content was already accepted once.
- **Install-time scripts** (the runtime download, install-phase events) use TLS + token only. The runtime they fetch is pinned by its SHA-256.
- **Server → agent responses** (policy, commands, jobs) are protected by TLS alone. Signing them needs a platform signing key provisioned as a secret; that's the next step.
- **Server-side data at rest** relies on Supabase's encryption at rest, plus RLS tenant isolation. Agent tokens are stored as SHA-256 hashes only, and no agent private key ever reaches the platform.

```bash
npx tsx tools/agent-transport-security-check.ts   # signing, installers, plaintext gate, built agent
```

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
