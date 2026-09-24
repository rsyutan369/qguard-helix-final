/**
 * Client for the QGuard billing service.
 *
 * The service is the `billing` Edge Function on the same Supabase project the
 * app already uses (supabase/functions/billing in the platform repo). It used to
 * be `https://api.qguard.dev` — a domain that never existed — so every upgrade
 * ended in the browser's bare "Failed to fetch". Two rules keep that from
 * recurring:
 *
 * 1. The default origin is DERIVED from the Supabase URL this build was made
 *    with, so it cannot point at a host the app does not otherwise talk to.
 *    `VITE_BILLING_API_ORIGIN` still overrides it for a self-hosted Express API
 *    (the paths are identical), which then also needs a CSP connect-src entry.
 * 2. A network failure is reported as one, naming the host that could not be
 *    reached, instead of the fetch API's generic TypeError text.
 */

type EnvLike = Partial<Record<string, string | undefined>>;

/**
 * Each variable is read individually on purpose: Vite replaces
 * `import.meta.env.X` with that one value, but an `import.meta.env` used as an
 * object is inlined WHOLE — every exposed variable copied into this chunk.
 */
function buildEnv(): EnvLike {
  return {
    VITE_BILLING_API_ORIGIN: import.meta.env.VITE_BILLING_API_ORIGIN as string | undefined,
    VITE_SUPABASE_URL: import.meta.env.VITE_SUPABASE_URL as string | undefined,
    NEXT_PUBLIC_SUPABASE_URL: import.meta.env.NEXT_PUBLIC_SUPABASE_URL as string | undefined,
  };
}

export function billingApiOrigin(env: EnvLike = buildEnv()): string {
  const configured = env.VITE_BILLING_API_ORIGIN?.trim();
  if (configured) return configured.replace(/\/+$/, "");
  const supabase = (env.VITE_SUPABASE_URL || env.NEXT_PUBLIC_SUPABASE_URL || "").trim().replace(/\/+$/, "");
  return supabase ? `${supabase}/functions/v1/billing` : "";
}

function hostOf(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

export class BillingRequestError extends Error {
  constructor(message: string, readonly status: number | null, readonly code: string | null) {
    super(message);
    this.name = "BillingRequestError";
  }
}

/**
 * Whether the billing service can verify Google Play purchases.
 *
 * Asked BEFORE launching a Play purchase: a Play charge the service cannot
 * verify is money taken with no plan granted (Google refunds unacknowledged
 * purchases after three days, but the buyer still paid and got nothing). The
 * service advertises the capability on its public health route; absent, false,
 * or unreachable all mean "use PayPal".
 */
export async function billingSupportsPlayVerification(
  options: { origin?: string; fetchImpl?: typeof fetch } = {},
): Promise<boolean> {
  const origin = options.origin ?? billingApiOrigin();
  if (!origin) return false;
  try {
    const response = await (options.fetchImpl ?? fetch)(`${origin}/health`, { method: "GET", cache: "no-store" });
    if (!response.ok) return false;
    const json = await response.json().catch(() => null) as { data?: { playVerification?: unknown } } | null;
    return json?.data?.playVerification === true;
  } catch {
    return false;
  }
}

/**
 * POST to the billing service and return its `data`. Throws a
 * BillingRequestError whose message is fit to show the user as-is.
 */
export async function postBilling<T = any>(
  path: string,
  accessToken: string,
  body: unknown,
  options: { origin?: string; fetchImpl?: typeof fetch } = {},
): Promise<T> {
  const origin = options.origin ?? billingApiOrigin();
  if (!origin) {
    throw new BillingRequestError("Billing is not configured in this build of QGuard Messaging.", null, "NOT_CONFIGURED");
  }
  const fetchImpl = options.fetchImpl ?? fetch;

  let response: Response;
  try {
    response = await fetchImpl(`${origin}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(body),
    });
  } catch {
    throw new BillingRequestError(
      `Can't reach the QGuard billing service (${hostOf(origin)}). Check your internet connection and try again.`,
      null,
      "NETWORK",
    );
  }

  const json = await response.json().catch(() => null) as { data?: T; error?: { code?: string; message?: string } } | null;
  if (!response.ok) {
    const message = json?.error?.message || `The billing service returned an error (HTTP ${response.status}).`;
    throw new BillingRequestError(message, response.status, json?.error?.code ?? null);
  }
  return (json?.data ?? null) as T;
}
