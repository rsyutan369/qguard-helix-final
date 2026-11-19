import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { runInNewContext } from 'node:vm';
import { build } from 'esbuild';

const require = createRequire(resolve('package.json'));
const requests = [];
let rejectVerification = false;
const user = { id: 'confirmation-test-user', aud: 'authenticated', role: 'authenticated', email: 'test@example.invalid' };
const session = { access_token: 'test-access-token', refresh_token: 'test-refresh-token', expires_in: 3600, token_type: 'bearer', user };

const bundle = await build({
  stdin: {
    contents: `
      export * from './src/lib/signup-confirmation';
      export { confirmSignupEmail, getSupabaseClient } from './src/lib/supabase';
    `,
    resolveDir: process.cwd(),
    loader: 'ts',
  },
  bundle: true,
  platform: 'node',
  format: 'cjs',
  write: false,
  define: {
    'import.meta.env.VITE_SUPABASE_URL': JSON.stringify('https://primary.example.invalid'),
    'import.meta.env.VITE_SUPABASE_ANON_KEY': JSON.stringify('public-test-key'),
    'import.meta.env.VITE_SUPABASE_FALLBACK_URL': JSON.stringify('https://fallback.example.invalid'),
    'import.meta.env.VITE_SUPABASE_FALLBACK_ANON_KEY': JSON.stringify('public-fallback-test-key'),
    'import.meta.env.VITE_SUPABASE_USE_FALLBACK': JSON.stringify('false'),
  },
});

const module = { exports: {} };
runInNewContext(bundle.outputFiles[0].text, {
  module,
  exports: module.exports,
  require,
  console,
  process,
  Buffer,
  URL,
  URLSearchParams,
  Headers,
  Request,
  Response,
  AbortController,
  AbortSignal,
  TextEncoder,
  TextDecoder,
  WebSocket,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  fetch: async (url, options) => {
    const request = { url: new URL(url), body: JSON.parse(options.body) };
    requests.push(request);
    assert.equal(request.url.pathname.startsWith('/auth/v1/'), true);
    if (request.url.pathname.endsWith('/verify') && rejectVerification) {
      return Response.json({ code: 'otp_expired', msg: 'Email link is invalid or has expired' }, { status: 403 });
    }
    return Response.json(session);
  },
});

const { SIGNUP_CONFIRMATION_URL, readSignupConfirmation, confirmSignupEmail, getSupabaseClient } = module.exports;
assert.equal(SIGNUP_CONFIRMATION_URL, 'https://qguardhelix.com/auth/confirm');
const token = 'a'.repeat(64);
assert.equal(readSignupConfirmation('#token_hash=' + token).source, 'primary');
assert.equal(readSignupConfirmation('#source=fallback&token_hash=' + token).source, 'fallback');
for (const hash of ['', '#token_hash=short', '#token_hash=' + token + '&source=https://evil.invalid']) {
  assert.equal(readSignupConfirmation(hash), null);
}

const main = getSupabaseClient();
await main.auth.signInWithPassword({ email: user.email, password: 'test-password' });
const originalSession = (await main.auth.getSession()).data.session;
assert.ok(originalSession);
assert.equal(await confirmSignupEmail(token, 'primary'), true);
assert.equal(requests.at(-1).url.hostname, 'primary.example.invalid');
assert.equal(requests.at(-1).url.pathname, '/auth/v1/verify');
assert.equal(requests.at(-1).body.type, 'signup');
assert.equal(requests.at(-1).body.token_hash, token);
assert.equal(requests.at(-1).url.search, '');
assert.equal(await confirmSignupEmail(token, 'fallback'), true);
assert.equal(requests.at(-1).url.hostname, 'fallback.example.invalid');
rejectVerification = true;
assert.equal(await confirmSignupEmail(token, 'primary'), false);
assert.equal((await main.auth.getSession()).data.session.access_token, originalSession.access_token);
assert.equal((await main.auth.getSession()).data.session.user.id, originalSession.user.id);
console.log('PASS signup confirmation destination, token validation, project routing, expired links, and existing-session preservation');
