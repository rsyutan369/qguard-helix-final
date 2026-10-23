# Mobile-number accounts and QR device linking

Two ways in, besides email + password:

1. **Mobile number.** Register and sign in with a phone number and a one-time
   SMS code. No password.
2. **Link with QR code.** On a new phone or computer, show a QR code and scan it
   from a device that is already signed in. The new device signs in on its own,
   with no password typed.

Both work the same on Windows desktop and Android: they live in the shared
React layer, and the Rust core needs no changes (it only stores the session it
is handed).

## 1. Mobile-number accounts

| | |
|---|---|
| Auth | Supabase Auth phone OTP (`signInWithOtp({ phone })` → `verifyOtp({ type: "sms" })`) |
| Password | None. The Signal/Telegram model: possession of the number is the first factor |
| Second factor | Authenticator MFA (TOTP), exactly as for email accounts. This is what stops a SIM swap alone from opening the account |
| Number format | Normalised to E.164 in `src/lib/phone-number.ts`. `0917 123 4567`, `+63 917 123 4567` and `0063 917 123 4567` are one account |
| Privacy | The number stays in `auth.users`. It is never copied into `profiles`, never searchable, and shown to its owner only masked (`+63 ••• ••• 4567`). Contacts find the account by username |
| Sign-in vs sign-up | *Sign in* never creates an account (`shouldCreateUser: false`), so a mistyped number cannot open a second, empty one. *Create account* may |
| Identity proof | Where an email account types its password before something sensitive (workspace-lock reset, email change, MFA changes), a phone account types a fresh SMS code (`src/lib/account-identity.ts`) |
| Profile | `profiles.email` is `NOT NULL`, so a phone account gets the placeholder `<uuid>@qguard.local` (migration 045). It is never delivered to and never displayed (`displayableEmail`) |

The sign-in screen reads `GET /auth/v1/settings` and offers mobile sign-up only
when the project has phone auth enabled. Until then the tab explains that it is
not switched on yet.

### Enabling SMS (Supabase dashboard → Authentication)

Phone auth needs an SMS provider. **The project currently reports
`"phone": false`**, so this step is required before anyone can use it.

Choose one:

- **A. Built-in provider (simplest).** *Sign In / Providers → Phone* → enable,
  pick Twilio / Twilio Verify / MessageBird / Vonage / Textlocal, and paste its
  credentials. Phone sign-in works. QR linking works for email accounts, but
  **not for phone-only accounts** (see below).
- **B. Send-SMS hook (recommended).** *Providers → Phone* → enable (the
  provider fields can stay empty), then *Hooks → Send SMS hook* → HTTPS →
  `https://<project>.supabase.co/functions/v1/device-link/sms-hook`, and
  generate the secret. Set the function secrets:

  ```
  supabase secrets set SEND_SMS_HOOK_SECRET='v1,whsec_…' \
    TWILIO_ACCOUNT_SID=AC… TWILIO_AUTH_TOKEN=… \
    TWILIO_MESSAGING_SERVICE_SID=MG…        # or TWILIO_FROM_NUMBER=+1…
  ```

  The function texts every code itself, and can therefore hand a code that a
  QR link asked for straight to the linking device instead of texting it. This
  is what makes QR linking work for phone-only accounts.

Recommended settings: SMS OTP length 6, expiry 300 s, and a per-hour SMS rate
limit sized to expected sign-ups (each code costs money and SMS pumping fraud
targets open sign-up forms). Turn on CAPTCHA if sign-ups are abused.

## 2. Link a device by QR code

```
 NEW DEVICE (signed out)              device-link Edge Function            SIGNED-IN DEVICE
 ──────────────────────               ─────────────────────────            ────────────────
 POST /start ───────────────────────► row: hash(code), hash(claimSecret)
 ◄─ linkId, code, claimSecret         expires in 120 s
 shows QR = code + bindingSecret                                          scans QR (or types code)
                                                                          POST /inspect (JWT) ─► label, platform, IP
                                                                          user confirms "Link device"
                                      status = approved, user_id  ◄────── POST /approve (JWT, aal2 if MFA)
 POST /claim (claimSecret) polling ─► mints a ONE-TIME credential
 ◄─ credential (never stored)         status = consumed
 verifyOtp(credential) → own session
 (TOTP prompt here if the account has MFA)
 registers its device keys
 POST /complete (JWT, claimSecret,
   deviceId, proof) ────────────────► stores device id + proof
                                                                          POST /status ─► deviceId, proof
                                                                          core computes fingerprint from keys,
                                                                          checks HMAC proof, then trusts + pins it
```

**Credentials.** The new device always gets its own session; sharing the
approver's refresh token would trip GoTrue's reuse detection and sign both
devices out.

- **Email accounts:** `auth.admin.generateLink({ type: "magiclink" })` returns a
  `hashed_token` and sends no email. The new device redeems it with
  `verifyOtp({ token_hash, type: "magiclink" })`.
- **Phone-only accounts:** the function requests an SMS code through GoTrue, and
  its own Send-SMS hook stores that code on the link row for the claim, instead
  of texting it. This needs option B above; with option A, approval is refused
  up front with a message telling the user to sign in with an SMS code.

Either way the session is `aal1`, so an account with MFA still answers its TOTP
challenge on the new device.

### Security properties

| Threat | Control |
|---|---|
| Someone photographs the QR | The code only lets a *signed-in* user approve it **into their own account**. Claiming needs the claim secret, which never leaves the new device |
| Guessing a code | 60 random bits, 120 s lifetime, single use |
| Flooding `/start` | 12 requests per IP per 10 min. Rows and the IPs they hold are purged an hour after expiry |
| Bulk minting from a stolen unlocked phone | 10 approvals per account per 10 min. If the account has MFA, approval needs an `aal2` session |
| Server or relay swaps in another device | The binding secret travels only in the QR. The approver checks `HMAC-SHA3-256(bindingSecret, link‖user‖device‖fingerprint)` against the fingerprint **its own core computes from the device keys**. A typed code has no binding secret, so the device signs in but is left for manual approval |
| Leaked database | Only SHA-256 hashes of codes and secrets. No credential is ever stored. A captured SMS code lives for the length of one request |
| Clients reading the table | RLS on, no policies, no grants to `anon` / `authenticated`. Only the function's service role can touch it |
| Display spoofing | Labels are stripped of control and bidi-override characters |

**Residual risk (same as WhatsApp and Signal): QR-jacking.** An attacker can
show a victim *their own* new-device QR and talk them into scanning it. The
confirmation screen shows the platform and the requesting network's IP, and
warns to approve only a device you are signing in on yourself. Declining tells
the other side no. Every link is written to the audit log (`device_linked`,
`login_device_linked`).

## Deployment checklist

1. Apply `supabase/migrations/045_phone_accounts_and_device_linking.sql` (SQL editor).
2. Deploy the function from the platform repo root:
   `npx supabase functions deploy device-link --project-ref xsbdlahuecadzfajlvis --no-verify-jwt`
   (`--no-verify-jwt`: `/start`, `/claim` and `/sms-hook` carry no user JWT; every user route verifies the token itself.)
3. Enable phone auth (option A or B above).
4. Probe: `npx tsx tools/device-link-edge-check.ts --live` (from the platform repo root).

## Verification

| Check | How |
|---|---|
| Function logic (codes, expiry, credential choice, webhook signature, SMS payload) | `npx tsx tools/device-link-edge-check.ts`: 13 offline checks |
| Function typing | `deno check supabase/functions/device-link/index.ts` |
| Migration on real Postgres (phone bootstrap, unique-email safety, constraints, no client access) | PGlite harness: 16 checks |
| E.164, masking, payload parsing, binding proof, completion handoff, account proof | `npx vitest run src/lib/phone-number.test.ts src/lib/device-link.test.ts src/lib/account-identity.test.ts`: 36 tests |
| Trust decision (proof against the core-computed fingerprint; refuses key_changed / invalid / swapped keys) | `src/lib/device-link-trust.test.ts`: 7 tests |
| Approver dialog flows (scan → confirm → approve → verify; typed code; "Not me"; foreign QR; expired) | `src/components/devices/LinkDeviceDialog.test.ts`: 5 tests |
| QR encode/decode | 200 random payloads round-trip through qrcode-generator → jsQR (QR version 5, 37 modules) |
| Live deployed function | `tools/device-link-edge-check.ts --live` |
| End to end (desktop ↔ Android) | Manual. Needs the function deployed, the migration applied, and SMS enabled for the phone path |
