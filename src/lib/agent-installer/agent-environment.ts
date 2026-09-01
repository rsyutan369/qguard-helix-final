/**
 * Agent control-plane environment policy (Agent_Installer_Refactor §2, §3, §61, §62).
 *
 * The defect this module exists to prevent, quoted from §2:
 *
 *   "The current configuration incorrectly identifies itself as
 *    Environment: production while communicating with http://localhost:3000."
 *
 * That combination is not a misconfiguration a warning should tolerate. An
 * agent that believes it is in production while talking plaintext to a loopback
 * address will happily accept whatever answers on port 3000, and every security
 * property downstream — signed commands, tenant isolation, revocation — rests
 * on the control plane being the real one.
 *
 * So this module makes the combination REPRESENTABLE and then REFUSES it. The
 * validator is called from three places, and all three fail closed:
 *
 *   1. the API server at startup, so a misconfigured deployment never serves
 *   2. installer generation, so a bad URL is never baked into a package
 *   3. the agent runtime at boot, so an agent will not run against one
 *
 * Isomorphic and dependency-free: the same function runs in the api-server, in
 * the browser (to show the operator what will be baked in) and inside the
 * bundled agent runtime.
 */

export type AgentEnvironment = 'development' | 'staging' | 'production';

export const AGENT_ENVIRONMENTS: AgentEnvironment[] = ['development', 'staging', 'production'];

export function isAgentEnvironment(value: unknown): value is AgentEnvironment {
  return typeof value === 'string' && (AGENT_ENVIRONMENTS as string[]).includes(value);
}

/**
 * Hosts that may only ever be reached in development.
 *
 * Matched against the parsed hostname, not by substring: a substring test would
 * reject the legitimate production host `localhost.qguardhelix.com` and, worse,
 * would accept `https://localhost.evil.example` as production because the
 * hostname merely *starts* with a permitted string.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0', '[::1]', '[::]']);

/** RFC 1918 / link-local / unique-local ranges — private, never production. */
function isPrivateHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (LOOPBACK_HOSTS.has(host)) return true;
  if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.localhost')) return true;

  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  /* IPv6 unique-local (fc00::/7) and link-local (fe80::/10). */
  if (/^f[cd][0-9a-f]{2}:/.test(host)) return true;
  if (/^fe[89ab][0-9a-f]:/.test(host)) return true;
  return false;
}

export interface ControlPlaneValidation {
  ok: boolean;
  environment: AgentEnvironment;
  /** Normalised URL with any trailing slash removed. Empty when unparseable. */
  url: string;
  hostname: string;
  protocol: string;
  /** Blocking problems. Non-empty means the configuration must be refused. */
  errors: string[];
  /** Non-blocking observations worth surfacing to an operator. */
  warnings: string[];
}

/**
 * Validate a control-plane URL against an environment.
 *
 * §3: production requires HTTPS and rejects loopback, private addresses and any
 * plaintext endpoint. Development may use `http://localhost:3000` — that is the
 * whole point of having environments — but it must SAY it is development.
 */
export function validateControlPlane(
  rawUrl: string | null | undefined,
  environment: AgentEnvironment,
): ControlPlaneValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  const url = String(rawUrl ?? '').trim().replace(/\/+$/, '');

  if (!url) {
    return {
      ok: false,
      environment,
      url: '',
      hostname: '',
      protocol: '',
      errors: ['No control-plane URL is configured. Set QGUARD_CONTROL_PLANE_URL.'],
      warnings,
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return {
      ok: false,
      environment,
      url,
      hostname: '',
      protocol: '',
      errors: [`"${url}" is not a valid absolute URL. Include the scheme, e.g. https://api.qguardhelix.com.`],
      warnings,
    };
  }

  const protocol = parsed.protocol.replace(':', '');
  const hostname = parsed.hostname;
  const isSecure = protocol === 'https';
  const isPrivate = isPrivateHost(hostname);

  if (protocol !== 'http' && protocol !== 'https') {
    errors.push(`Unsupported scheme "${protocol}". The control plane must be reached over HTTPS.`);
  }

  if (environment === 'production') {
    /* The exact combination §2 names. Reported as one sentence rather than two
       findings, because the pair is the defect — either half alone is fine in
       its own environment. */
    if (!isSecure) {
      errors.push(
        `Production requires HTTPS. "${url}" is plaintext, so agent credentials, commands and telemetry would cross the network unprotected.`,
      );
    }
    if (isPrivate) {
      errors.push(
        `Production cannot use the loopback or private address "${hostname}". An agent that believes it is in production must reach the real control plane, not whatever answers locally.`,
      );
    }
    if (parsed.port && parsed.port !== '443') {
      warnings.push(`Production control plane uses non-standard port ${parsed.port}. Confirm this is intended.`);
    }
  }

  if (environment === 'staging' && !isSecure) {
    errors.push(`Staging requires HTTPS. "${url}" is plaintext.`);
  }

  if (environment === 'development' && !isPrivate && isSecure) {
    warnings.push(
      `Development is configured against the remote host "${hostname}". Agents enrolled here will report into that control plane.`,
    );
  }

  if (environment === 'development' && !isSecure && !isPrivate) {
    errors.push(
      `Development may use plaintext only against a local address. "${hostname}" is remote, so HTTPS is required.`,
    );
  }

  return { ok: errors.length === 0, environment, url, hostname, protocol, errors, warnings };
}

/**
 * Read the environment from configuration, defaulting to development.
 *
 * Defaults to the SAFE-TO-BE-WRONG value: mislabelling production as
 * development produces loud validation noise and a refusal to enrol against a
 * remote plaintext host, while the reverse silently blesses an insecure setup.
 */
export function readAgentEnvironment(value: string | null | undefined): AgentEnvironment {
  const normalised = String(value ?? '').trim().toLowerCase();
  return isAgentEnvironment(normalised) ? normalised : 'development';
}

/**
 * Startup assertion for the API server (§61).
 *
 * Returns the validation rather than throwing, so the caller decides whether to
 * exit or log — a hard exit is right for the agent runtime and for a production
 * API server, but a developer running `npm run dev` should get a readable
 * message, not a crash loop.
 */
export function describeControlPlaneFailure(validation: ControlPlaneValidation): string {
  const lines = [
    `Insecure agent control-plane configuration for environment "${validation.environment}":`,
    ...validation.errors.map((error) => `  • ${error}`),
  ];
  if (validation.environment === 'production') {
    lines.push('', '  Set QGUARD_CONTROL_PLANE_URL to the HTTPS production endpoint, or set');
    lines.push('  QGUARD_ENVIRONMENT=development if this is a local instance.');
  }
  return lines.join('\n');
}
