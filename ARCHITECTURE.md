# QGuard Helix Architecture

QGuard Helix is a React + Vite frontend with an Express API backend.

## Runtime Boundaries

- `src/main.tsx`, `src/App.tsx`, and `src/app/**` contain the browser application.
- `src/api-server/**` contains the active backend API.
- Vite mounts the Express API during development through `vite.config.ts`.
- `src/api-server/standalone.ts` serves the built Vite app and Express API from one Node process for deliberate single-service deployments.
- `src/app/api/**/route.ts` files are legacy Next-style route files. They are not served by Vite and should not be used as the active backend path.

## Data And Security

- Supabase remains the auth, database, storage, and realtime layer.
- Browser code calls `/api/v1/**` for sensitive writes and server-owned operations.
- Express creates Supabase clients with the authenticated user's JWT so RLS still protects user-owned data.
- Supabase Realtime and Express SSE provide live telemetry.
- User-owned tables should keep RLS enabled with `auth.uid() = user_id` policies.

## Local Development

- `npm run dev` runs Vite on port `3000` and mounts Express under `/api/v1`.
- API health is available at `/api/v1/health`.
- Dashboard/profile/module endpoints are implemented in `src/api-server`.

## Production Options

- Static frontend plus separate Node API service: build the Vite app and deploy `src/api-server` as its own Node service/API gateway target.
- Single Node service: run `npm run build`, then `npm start` to serve both `dist/` and `/api/v1/**`.

## Agents, Collectors, Connectors, And Operator Patchers

The Scanner -> Agents module is an active crypto-agility and PQC remediation surface, not a local-only inventory tool.

QGuard Helix Control Plane:

- Owns tenant-scoped policy, RBAC, approval state, audit logs, telemetry, evidence, and remediation orchestration.
- Streams agent, connector, and operator state through SSE/WebSocket-compatible telemetry.
- Requires tenant administrator approval before any patch action can move from plan to execution.

Local Collectors:

- A Local Collector is a tenant-owned QGuard agent installed on an endpoint, server, VM, container, sidecar, or controlled jump host.
- It can monitor local operating system resources, files, packages, TLS/SSH state, runtime crypto events, certificates, and configuration paths only when those targets are explicitly allowlisted.
- It is not limited to local-only discovery. It can scan allowlisted network targets, public TLS endpoints, APIs, web apps, and provider/resource identifiers when the customer authorizes that scope.
- It can trigger and validate remediation workflows for cloud, web, SaaS, Kubernetes, and API assets, but remote mutation requires an authorized connector or operator patcher with least-privilege scopes.

Cloud Connectors and Remote Connectors:

- Connectors represent customer-authorized API access to AWS, Azure, GCP, Oracle Cloud, Alibaba Cloud, Kubernetes, CDN/edge providers, PKI systems, SaaS platforms, databases, and network devices.
- Connectors upload observed evidence and can execute approved remediation actions only within declared provider scopes and policy allowlists.
- Supported remote targets include resource IDs, ARNs, Kubernetes resources, SaaS app IDs, CDN zones, load balancer IDs, certificate IDs, KMS/HSM keys, database resources, public TLS endpoints, and API gateways.

Operator Patchers:

- Operator Patchers execute tenant-approved change actions across local, hybrid, cloud, Kubernetes, web, API, SaaS, PKI, database, HSM/KMS, and network-device environments.
- Supported actions include TLS upgrades, certificate replacement, weak cipher removal, legacy crypto replacement, ML-KEM deployment, ML-DSA deployment, SLH-DSA readiness, hybrid cryptography deployment, key rotation, configuration hardening, and compliance policy enforcement.
- Every action must record before state, snapshots, after state, verification, validation result, and audit metadata.
- Rollback is required for guarded local patches and must be represented for connector-backed changes through the owning provider's snapshot, backup, version, or restore mechanism.

Security Gates:

- RBAC validation.
- Tenant administrator approval.
- Change approval with approve, reject, or schedule decision state.
- Least-privilege connector scopes.
- Configuration snapshot, certificate backup, key backup metadata, and TLS policy snapshot where applicable.
- Post-remediation functional, TLS, certificate, dependency, rollback, and compliance validation.
- Continuous monitoring for runtime crypto intelligence, PQC adoption, certificate health, crypto agility, trust fabric drift, failed migrations, and unauthorized crypto changes.
