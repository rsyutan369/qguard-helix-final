/**
 * Dev exposure stream — authentication contract check.
 *
 * WHY THIS EXISTS
 * ---------------
 * `/api/v1/exposure/scans/:scanId/events` is consumed by the browser's
 * `EventSource`, which CANNOT set an `Authorization` header. When the route
 * authenticated from that header alone, every subscription arrived anonymous
 * and was refused with 401; `EventSource` treats a non-2xx as fatal (readyState
 * goes to CLOSED and it never retries), so the Dev panel reported
 * "The connection to the assessment stream was lost" on every GitHub scan while
 * the scan itself ran happily on the server.
 *
 * The rest of the platform already solved this: ~20 authenticated streams pass
 * the access token as `?token=`. These assertions pin that behaviour HERE, and
 * pin the boundary of it — the widening applies to the event stream only, never
 * to the mutating or data-returning routes beside it.
 *
 * Run against a live dev server:
 *   npx tsx tools/exposure-stream-auth-check.ts [baseUrl]
 */

const BASE = process.argv[2] ?? 'http://localhost:3000';
const GARBAGE = 'not.a.real.jwt';

interface Outcome {
  status: number;
  code: string | null;
  reason: string | null;
}

async function probe(path: string): Promise<Outcome> {
  /* `connection: close` keeps undici from pooling the socket. A pooled
     keep-alive socket holds the event loop open after the last assertion, and
     forcing the process down instead trips a libuv assertion on Windows. */
  const response = await fetch(`${BASE}${path}`, {
    headers: { accept: 'text/event-stream', connection: 'close' },
  });
  let body: { error?: { code?: string; detail?: { reason?: string } } } = {};
  try {
    body = (await response.json()) as typeof body;
  } catch {
    /* a 200 stream is not JSON — the status alone is the signal */
  }
  return {
    status: response.status,
    code: body.error?.code ?? null,
    reason: body.error?.detail?.reason ?? null,
  };
}

const results: Array<{ name: string; pass: boolean; detail: string }> = [];

function assert(name: string, pass: boolean, detail: string) {
  results.push({ name, pass, detail });
}

async function main() {
  /* 1. Anonymous is still refused. Dev mode is a paid tier and opening the
        stream must not become a way around that. */
  const anonymous = await probe('/api/v1/exposure/scans/probe-scan/events');
  assert(
    'stream refuses an anonymous subscriber',
    anonymous.status === 401 && anonymous.reason === 'unauthenticated',
    `status=${anonymous.status} code=${anonymous.code} reason=${anonymous.reason}`,
  );

  /* 2. THE REGRESSION. A query token must be READ and VERIFIED. A rejected
        token proves the route looked at it; a token that is never read is
        indistinguishable from no token at all, which is exactly the bug. */
  const queryToken = await probe(`/api/v1/exposure/scans/probe-scan/events?token=${GARBAGE}`);
  assert(
    'stream reads the query token (EventSource cannot send a header)',
    queryToken.status === 401 && queryToken.code === 'INVALID_TOKEN',
    `status=${queryToken.status} code=${queryToken.code} reason=${queryToken.reason} ` +
      '— expected INVALID_TOKEN; AUTHENTICATION_REQUIRED means the query token was ignored',
  );

  /* 3. The widening is scoped. Every other Dev route keeps header-only auth, so
        a token in a URL cannot start, cancel or read a scan. */
  const pollRoute = await probe(`/api/v1/exposure/scans/probe-scan?token=${GARBAGE}`);
  assert(
    'poll route still ignores a query token',
    pollRoute.status === 401 && pollRoute.reason === 'unauthenticated',
    `status=${pollRoute.status} code=${pollRoute.code} reason=${pollRoute.reason}`,
  );

  const findingsRoute = await probe(`/api/v1/exposure/scans/probe-scan/findings?token=${GARBAGE}`);
  assert(
    'findings route still ignores a query token',
    findingsRoute.status === 401 && findingsRoute.reason === 'unauthenticated',
    `status=${findingsRoute.status} code=${findingsRoute.code} reason=${findingsRoute.reason}`,
  );

  let failures = 0;
  for (const result of results) {
    if (!result.pass) failures += 1;
    console.log(`${result.pass ? 'PASS' : 'FAIL'}  ${result.name}\n      ${result.detail}`);
  }
  console.log(`\n${results.length - failures}/${results.length} checks passed.`);
  /* `exitCode`, not `process.exit()`: forcing exit while undici's keep-alive
     sockets are still closing trips a libuv assertion on Windows. */
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((error) => {
  console.error('probe failed to run:', (error as Error).message);
  console.error(`Is a dev server listening at ${BASE}?`);
  process.exitCode = 2;
});
