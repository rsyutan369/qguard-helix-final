import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import { createRequire } from 'node:module'
import { resolve } from 'node:path'
import { runInNewContext } from 'node:vm'
import { build } from 'esbuild'

const require = createRequire(resolve('package.json'))
const requests = []
let rejectExchange = false
const user = { id: 'oauth-test-user', aud: 'authenticated', role: 'authenticated', email: 'test@example.invalid' }
const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url')
const accessToken = encode({ alg: 'HS256', typ: 'JWT' }) + '.' +
  encode({ sub: user.id, exp: Math.floor(Date.now() / 1000) + 3600 }) + '.' + Buffer.from('test-signature').toString('base64url')
const session = { access_token: accessToken, refresh_token: 'test-refresh-token', expires_in: 3600, token_type: 'bearer', user, provider_token: 'test-provider-token' }

const bundle = await build({
  stdin: {
    contents: `export * from './src/lib/supabase'; export * from './src/lib/oauth-callback';`,
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
})

function loadClient(storage) {
  const module = { exports: {} }
  runInNewContext(bundle.outputFiles[0].text, {
    module, exports: module.exports, require, console, process, Buffer,
    URL, URLSearchParams, Headers, Request, Response, AbortController, AbortSignal,
    TextEncoder, TextDecoder, WebSocket, btoa, atob, crypto: webcrypto,
    setTimeout, clearTimeout, setInterval, clearInterval,
    sessionStorage: {
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: (key) => storage.delete(key),
    },
    fetch: async (url, options) => {
      const request = { url: new URL(url), body: options.body ? JSON.parse(options.body) : null }
      requests.push(request)
      if (request.url.pathname.endsWith('/user')) return Response.json(user)
      if (rejectExchange) return Response.json({ code: 'bad_code_verifier', msg: 'Invalid code' }, { status: 400 })
      assert.equal(request.url.searchParams.get('grant_type'), 'pkce')
      return Response.json(session)
    },
  })
  return module.exports
}

const storage = new Map()
const initiating = loadClient(storage)
const redirectTo = 'https://qguardhelix.com/auth/callback'
const started = await initiating.beginGoogleOAuth(redirectTo)
assert.equal(started.error, null)
const authorizationUrl = new URL(started.data.url)
assert.equal(authorizationUrl.searchParams.get('provider'), 'google')
assert.equal(authorizationUrl.searchParams.get('redirect_to'), redirectTo)
assert.equal(authorizationUrl.searchParams.get('code_challenge_method'), 's256')
const verifierKey = 'qguard:google-oauth:primary-code-verifier'
const verifier = JSON.parse(storage.get(verifierKey))
assert.equal(authorizationUrl.searchParams.get('code_challenge'), createHash('sha256').update(verifier).digest('base64url'))
assert.equal(authorizationUrl.searchParams.has('access_token'), false)
assert.equal(requests.length, 0)

// A fresh module context represents the callback after a full-page navigation.
const returning = loadClient(storage)
const completed = await returning.finishGoogleOAuth('test-one-time-code')
assert.equal(completed.error, null)
const exchange = requests.find(request => request.url.searchParams.get('grant_type') === 'pkce')
assert.equal(exchange.body.auth_code, 'test-one-time-code')
assert.equal(exchange.body.code_verifier, verifier)
assert.equal(exchange.url.searchParams.has('code_verifier'), false)
assert.equal((await returning.getSupabaseClient().auth.getSession()).data.session.user.id, user.id)
assert.equal((await returning.getSupabaseClient().auth.getSession()).data.session.provider_token, undefined)
assert.equal(storage.has(verifierKey), false)
assert.equal(storage.has('qguard:google-oauth-source'), false)
assert.equal([...storage.values()].some(value => value.includes('test-refresh-token')), false)

assert.equal(returning.cleanAuthReturnUrl('https://qguardhelix.com/auth/callback?code=test&next=keep'), '/auth/callback?next=keep')
assert.equal(returning.cleanAuthReturnUrl('https://qguardhelix.com/#access_token=test&refresh_token=test&provider_token=test&expires_in=3600&token_type=bearer'), '/')
assert.equal(returning.cleanAuthReturnUrl('https://qguardhelix.com/reset-password#access_token=test&refresh_token=test&type=recovery'), '/reset-password')
assert.equal(returning.cleanAuthReturnUrl('https://qguardhelix.com/auth/confirm#token_hash=keep'), '/auth/confirm#token_hash=keep')
assert.equal(returning.cleanAuthReturnUrl('https://qguardhelix.com/docs?code=example#section'), '/docs?code=example#section')
await assert.rejects(() => returning.finishGoogleOAuth('test-stale-code'))

await returning.beginGoogleOAuth(redirectTo)
rejectExchange = true
await assert.rejects(() => returning.finishGoogleOAuth('test-rejected-code'))
assert.equal(storage.has(verifierKey), false)
assert.equal(storage.has('qguard:google-oauth-source'), false)
assert.equal((await returning.getSupabaseClient().auth.getSession()).data.session.user.id, user.id)

rejectExchange = false
await returning.beginGoogleOAuth(redirectTo)
storage.delete(verifierKey)
const callsBeforeMissingVerifier = requests.length
await assert.rejects(() => returning.finishGoogleOAuth('test-without-verifier'))
assert.equal(requests.length, callsBeforeMissingVerifier)

const fallbackStorage = new Map()
const fallbackStart = loadClient(fallbackStorage)
fallbackStart.switchToFallbackSupabase()
const fallbackAuthorization = await fallbackStart.beginGoogleOAuth(redirectTo)
assert.equal(new URL(fallbackAuthorization.data.url).hostname, 'fallback.example.invalid')
const fallbackReturn = loadClient(fallbackStorage)
const fallbackSession = await fallbackReturn.finishGoogleOAuth('test-fallback-code')
assert.equal(fallbackSession.error, null)
assert.equal(fallbackReturn.getActiveSupabaseSource(), 'fallback')
assert.equal(requests.at(-1).url.hostname, 'fallback.example.invalid')
assert.equal(fallbackStorage.size, 0)
console.log('PASS Google PKCE S256, verifier continuity across navigation, code exchange, URL cleanup, rejected callbacks, and session transfer')
