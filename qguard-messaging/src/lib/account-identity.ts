/**
 * Who the signed-in account is, and how it proves it is still the owner.
 *
 * An account is created with EITHER an email + password OR a mobile number
 * (SMS one-time codes, no password — the Signal/Telegram model). Every place
 * that used to ask for "your account password" before something sensitive (a
 * workspace reset, an email change) asks this module instead: a password for
 * email accounts, a fresh SMS code for phone accounts.
 *
 * Phone accounts get a placeholder profile address `<uuid>@qguard.local`
 * (migration 045) so `profiles.email` is never empty. It is not an address: it
 * is never shown and never mailed.
 */
import type { User } from "@supabase/supabase-js";
import { maskPhone } from "@/lib/phone-number";
import { createEphemeralSupabaseClient, supabaseAnonKey, supabaseUrl } from "@/lib/supabase";

export const PLACEHOLDER_EMAIL_DOMAIN = "@qguard.local";

export function isPlaceholderEmail(email: string | null | undefined): boolean {
  return Boolean(email && email.trim().toLowerCase().endsWith(PLACEHOLDER_EMAIL_DOMAIN));
}

/** An address fit to show a person, or null. */
export function displayableEmail(email: string | null | undefined): string | null {
  const value = email?.trim();
  return value && !isPlaceholderEmail(value) ? value : null;
}

type IdentityUser = Pick<User, "email" | "phone" | "app_metadata">;

export type AccountProofKind = "password" | "sms";

/**
 * Phone-registered accounts have no password, even after they add an email,
 * so the registration provider decides — not which fields happen to be set.
 */
export function accountProofKind(user: IdentityUser | null | undefined): AccountProofKind {
  if (!user) return "password";
  const provider = String(user.app_metadata?.provider ?? "");
  if (provider === "phone") return "sms";
  if (!displayableEmail(user.email) && user.phone) return "sms";
  return "password";
}

export function isPhoneAccount(user: IdentityUser | null | undefined): boolean {
  return accountProofKind(user) === "sms";
}

function e164(phone: string): string {
  return `+${phone.replace(/\D/g, "")}`;
}

/** How the account is labelled to its owner: "name@example.com" or "+63 ••• ••• 4567". */
export function accountIdentifierLabel(user: IdentityUser | null | undefined): string {
  if (!user) return "";
  if (isPhoneAccount(user)) return user.phone ? maskPhone(e164(user.phone)) : "Mobile number";
  return displayableEmail(user.email) ?? (user.phone ? maskPhone(e164(user.phone)) : "");
}

/** The identifier rate limits and audit hashes are keyed on (never stored in clear). */
export function accountAuditIdentifier(user: IdentityUser | null | undefined): string {
  if (!user) return "";
  const email = displayableEmail(user.email);
  if (email && !isPhoneAccount(user)) return email.toLowerCase();
  return user.phone ? e164(user.phone) : (email ?? "").toLowerCase();
}

/** Phone accounts: text a fresh code to the account's own number. */
export async function sendAccountProofCode(user: IdentityUser): Promise<string> {
  if (!user.phone) throw new Error("This account has no mobile number on file.");
  const phone = e164(user.phone);
  const client = createEphemeralSupabaseClient();
  const { error } = await client.auth.signInWithOtp({ phone, options: { shouldCreateUser: false } });
  if (error) {
    if (/rate|seconds|too many/i.test(error.message)) throw new Error("A code was sent very recently. Wait a minute, then request another.");
    throw new Error("Couldn't send a verification code. Try again in a moment.");
  }
  return maskPhone(phone);
}

/**
 * Prove ownership WITHOUT touching the live session: an ephemeral client signs
 * in once, and that one extra session is revoked straight away. `scope: "local"`
 * matters — the default ("global") would sign the user out on every device.
 */
export async function verifyAccountProof(user: IdentityUser, secret: string): Promise<void> {
  const client = createEphemeralSupabaseClient();
  if (accountProofKind(user) === "sms") {
    if (!user.phone) throw new Error("This account has no mobile number on file.");
    const code = secret.replace(/\D/g, "");
    if (code.length < 6) throw new Error("Enter the 6-digit code we texted you.");
    const { error } = await client.auth.verifyOtp({ phone: e164(user.phone), token: code, type: "sms" });
    await client.auth.signOut({ scope: "local" }).catch(() => undefined);
    if (error) throw new Error("That code is incorrect or has expired.");
    return;
  }
  const email = displayableEmail(user.email);
  if (!email) throw new Error("No account email is on file for this session.");
  const { error } = await client.auth.signInWithPassword({ email, password: secret });
  await client.auth.signOut({ scope: "local" }).catch(() => undefined);
  if (error) throw new Error("That account password is incorrect.");
}

// ---- what the auth server offers ------------------------------------------

export interface AuthCapabilities {
  email: boolean;
  phone: boolean;
}

export function parseAuthSettings(value: unknown): AuthCapabilities {
  const external = (value as { external?: Record<string, unknown> } | null)?.external ?? {};
  return { email: external.email !== false, phone: external.phone === true };
}

let capabilitiesPromise: Promise<AuthCapabilities> | null = null;

/**
 * Whether this project has phone sign-in enabled (an SMS provider configured
 * in Supabase Auth). Read from GoTrue's public settings endpoint, so the login
 * screen offers mobile sign-up only when a code could actually be delivered.
 */
export function fetchAuthCapabilities(): Promise<AuthCapabilities> {
  if (!capabilitiesPromise) {
    capabilitiesPromise = (async () => {
      if (!supabaseUrl || !supabaseAnonKey) return { email: true, phone: false };
      try {
        const response = await fetch(`${supabaseUrl.replace(/\/+$/, "")}/auth/v1/settings`, { headers: { apikey: supabaseAnonKey } });
        if (!response.ok) throw new Error(String(response.status));
        return parseAuthSettings(await response.json());
      } catch {
        capabilitiesPromise = null; // retry on the next render rather than caching a network blip
        return { email: true, phone: false };
      }
    })();
  }
  return capabilitiesPromise;
}
