# QGuard Messaging

QGuard Messaging is a Tauri 2 desktop application for zero-knowledge secure messaging, vault file sharing, voice-note envelopes, device trust, and quantum security telemetry.

The app is Signal-inspired at the cryptographic architecture level, but it does not copy Signal branding, UI, trademarks, proprietary assets, or claim official compatibility.

## Stack

- Desktop: Tauri 2
- Frontend: React, TypeScript, Tailwind CSS
- Security core: Rust
- Relay: Supabase Auth, Database, Storage, and Realtime
- Default PQC backend: pure Rust `pqcrypto-*` crates
- Optional build feature: `oqs-backend` integration point for liboqs packaging

## Commands

```powershell
npm install
npm run tauri dev
cd src-tauri
cargo test
cargo clippy --all-targets --all-features
```

## Supabase Auth And Realtime

Create a local `.env.local` with either `NEXT_PUBLIC_` or `VITE_` Supabase auth variables:

```powershell
NEXT_PUBLIC_SUPABASE_URL=your-project-url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
```

Apply `supabase/migrations/001_secure_messaging.sql` to the same QGuard Supabase project that owns `public.profiles`. The migration enables RLS, creates user-scoped messaging modules/settings, seeds default dashboard navigation per profile, and adds messaging tables to the Supabase Realtime publication when available.

The dashboard does not render until Supabase Auth validates the user and the desktop Rust command layer accepts the unexpired session token. Dashboard modules, devices, conversations, vault files, audit events, and key inventory are loaded through RLS-scoped Supabase queries and refreshed via Realtime subscriptions.

## Documentation

- [Architecture](docs/architecture.md)
- [Cryptographic Design](docs/cryptographic-design.md)
- [Threat Model](docs/threat-model.md)
- [Key Lifecycle](docs/key-lifecycle.md)
- [Device Trust Model](docs/device-trust-model.md)
- [PQC Migration Model](docs/pqc-migration-model.md)
- [API Documentation](docs/api.md)
- [SDK Examples](docs/sdk-examples.md)
- [Security Limitations](docs/security-limitations.md)
- [Deployment Guide](docs/deployment.md)
- [Security Checklist](docs/security-checklist.md)
