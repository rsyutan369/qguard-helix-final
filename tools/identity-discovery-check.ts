/**
 * Identity Discovery engine — offline invariant check.
 *
 * The assertions below encode the defects this capability exists to prevent.
 * Each is drawn from something the PQAuth audit found being published as fact.
 *
 *   1. NO VENDOR GUESSING. "Microsoft Entra ID" was reported for a tenant that
 *      has none, invented by finding the word "entra" in a crypto row. A vendor
 *      is named only when the ISSUER HOST is that vendor's documented domain.
 *   2. NO PROVIDER WITHOUT AN ISSUER. The issuer is the protocol's primary key;
 *      a document without one is not a provider, and a 404 page must never
 *      become an "identity provider".
 *   3. SIGNATURES MIGRATE TO ML-DSA, NEVER ML-KEM. RS256 is a JWS signature
 *      algorithm. RSA-OAEP is JWE key management. They share the field name
 *      `alg` and mean different things.
 *   4. HMAC IS NOT SHOR-VULNERABLE. HS256/384/512 are symmetric; listing them
 *      beside RSA as quantum-broken is wrong.
 *   5. ADVERTISED ≠ OBSERVED. A provider's posture comes from the keys actually
 *      in its JWKS where one was read; advertised support is only a fallback.
 *   6. KEYS ATTACH TO THEIR OWN PROVIDER. JWKS keys are bound to the provider
 *      whose `jwks_uri` they came from, never to whichever provider is first.
 *   7. UNSTATED IS NULL. A JWKS key with no `alg` reports `algorithm: null` and
 *      is classified from its key type — never given an invented `alg`.
 *
 * Run: npx tsx tools/identity-discovery-check.ts
 */

import {
  assembleIdentityDiscovery,
  classifyJoseAlgorithm,
  parseJwks,
  parseOidcDiscovery,
  parseSamlMetadata,
  vendorForIssuer,
  worstQuantumClass,
  type RawProbe,
} from '../src/lib/scanner/identity/identity-discovery'
import { isSafePublicJwksUrl } from '../src/lib/scanner/identity/identity-probe'

let failures = 0
function assert(condition: boolean, label: string, extra = '') {
  console.log(`  ${condition ? '✓' : '✗ FAIL'} ${label}${extra ? ` — ${extra}` : ''}`)
  if (!condition) failures += 1
}

const AT = '2026-08-13T12:00:00Z'
const ev = (url: string, method: string) => ({ sourceUrl: url, method, observedAt: AT, httpStatus: 200 })

/* ------------------------------------------------------------------ */
/* 1. Vendor identification                                            */
/* ------------------------------------------------------------------ */
console.log('\n1. A vendor is named only when the issuer host proves it')
{
  assert(vendorForIssuer('https://login.microsoftonline.com/tenant/v2.0') === 'Microsoft Entra ID', 'the real Entra host resolves to Entra')
  assert(vendorForIssuer('https://dev-123.okta.com') === 'Okta', 'okta.com resolves to Okta')
  assert(vendorForIssuer('https://example.auth0.com/') === 'Auth0', 'auth0.com resolves to Auth0')
  assert(vendorForIssuer('https://sso.acme.com/realms/prod') === 'Keycloak', 'a /realms/ path is Keycloak\'s own protocol contract')

  // The audit's actual defect, in one line.
  assert(vendorForIssuer('https://expired.badssl.com') === null, 'a TLS test domain resolves to NO vendor', String(vendorForIssuer('https://expired.badssl.com')))
  assert(vendorForIssuer('https://qguardhelix.com') === null, 'an ordinary web host resolves to NO vendor')
  assert(vendorForIssuer('https://entra-notes.example.com') === null, 'the WORD "entra" in a hostname is not Microsoft Entra ID')
  assert(vendorForIssuer('') === null, 'an empty issuer resolves to no vendor')
}

/* ------------------------------------------------------------------ */
/* 2. No provider without an issuer                                    */
/* ------------------------------------------------------------------ */
console.log('\n2. The issuer is the identity; without it there is no provider')
{
  assert(parseOidcDiscovery({}, ev('https://x/.well-known/openid-configuration', 'oidc-discovery')) === null, 'an empty document yields no provider')
  assert(parseOidcDiscovery({ error: 'not found' }, ev('https://x/404', 'oidc-discovery')) === null, 'a 404 body yields no provider')
  assert(parseOidcDiscovery(null, ev('https://x', 'oidc-discovery')) === null, 'a null body yields no provider')
  assert(parseSamlMetadata('<html>not saml</html>', ev('https://x/saml', 'saml-metadata')) === null, 'non-SAML XML yields no provider')
  assert(parseSamlMetadata('<md:EntityDescriptor></md:EntityDescriptor>', ev('https://x', 'saml-metadata')) === null, 'SAML metadata with no entityID yields no provider')
}

/* ------------------------------------------------------------------ */
/* 3. Signature vs key encapsulation                                   */
/* ------------------------------------------------------------------ */
console.log('\n3. JWT signatures migrate to ML-DSA; key establishment to ML-KEM')
{
  const rs256 = classifyJoseAlgorithm('RS256', 'signature')
  assert(rs256.purpose === 'signature', 'RS256 is a SIGNATURE algorithm', rs256.purpose)
  assert(rs256.quantumClass === 'vulnerable', 'and it is Shor-vulnerable', rs256.quantumClass)
  assert(/ML-DSA/.test(rs256.pqcTarget ?? ''), 'its target is ML-DSA', String(rs256.pqcTarget))
  assert(!/ML-KEM/.test(rs256.pqcTarget ?? ''), 'and NEVER ML-KEM', String(rs256.pqcTarget))
  assert(rs256.standard === 'FIPS 204', 'cited against the signature standard', String(rs256.standard))

  const es256 = classifyJoseAlgorithm('ES256', 'signature')
  assert(/ML-DSA/.test(es256.pqcTarget ?? '') && !/ML-KEM/.test(es256.pqcTarget ?? ''), 'ECDSA also targets ML-DSA only')
  const eddsa = classifyJoseAlgorithm('EdDSA', 'signature')
  assert(/ML-DSA/.test(eddsa.pqcTarget ?? ''), 'EdDSA targets ML-DSA')

  const oaep = classifyJoseAlgorithm('RSA-OAEP-256', 'key-encapsulation')
  assert(oaep.purpose === 'key-encapsulation', 'RSA-OAEP is KEY MANAGEMENT, not a signature', oaep.purpose)
  assert(/ML-KEM/.test(oaep.pqcTarget ?? ''), 'and it targets ML-KEM', String(oaep.pqcTarget))
  assert(oaep.standard === 'FIPS 203', 'cited against the KEM standard', String(oaep.standard))

  const ecdh = classifyJoseAlgorithm('ECDH-ES+A256KW', 'key-encapsulation')
  assert(/ML-KEM/.test(ecdh.pqcTarget ?? ''), 'ECDH-ES targets ML-KEM')

  const mldsa = classifyJoseAlgorithm('ML-DSA-65', 'signature')
  assert(mldsa.quantumClass === 'safe' && mldsa.pqcTarget === null, 'ML-DSA is already safe and needs no target')
  const hybridKem = classifyJoseAlgorithm('X25519MLKEM768', 'key-encapsulation')
  assert(hybridKem.quantumClass === 'hybrid', 'a hybrid group reads hybrid', hybridKem.quantumClass)
}

/* ------------------------------------------------------------------ */
/* 4. HMAC and the "none" algorithm                                    */
/* ------------------------------------------------------------------ */
console.log('\n4. Symmetric token signing is not Shor-vulnerable')
{
  const hs256 = classifyJoseAlgorithm('HS256', 'signature')
  assert(hs256.quantumClass !== 'vulnerable', 'HS256 is NOT classed with RSA as quantum-broken', hs256.quantumClass)
  assert(/symmetric/i.test(hs256.rationale), 'and the rationale says why', hs256.rationale.slice(0, 40))
  const hs512 = classifyJoseAlgorithm('HS512', 'signature')
  assert(hs512.quantumClass === 'safe', 'HS512 retains an adequate post-quantum margin', hs512.quantumClass)

  const none = classifyJoseAlgorithm('none', 'signature')
  assert(none.quantumClass === 'vulnerable', 'alg=none is reported as critical')
  assert(/unauthenticated|disables signature/i.test(none.rationale), 'and named as an authentication flaw, not a quantum one', none.rationale.slice(0, 46))

  assert(worstQuantumClass([]) === 'unknown', 'no evidence ⇒ unknown, never safe')
  assert(worstQuantumClass(['safe', 'unknown']) === 'unknown', 'unknown outranks safe')
  assert(worstQuantumClass(['safe', 'vulnerable', 'hybrid']) === 'vulnerable', 'vulnerable wins')
  assert(worstQuantumClass(['safe', 'hybrid']) === 'hybrid', 'hybrid outranks safe')
}

/* ------------------------------------------------------------------ */
/* 5-7. JWKS parsing, attribution, and observed-over-advertised        */
/* ------------------------------------------------------------------ */
console.log('\n5-7. Keys are parsed, attributed and preferred over advertisements')
{
  const jwks = {
    keys: [
      // 2048-bit RSA signing key with a stated alg.
      { kty: 'RSA', use: 'sig', kid: 'sig-1', alg: 'RS256', n: 'A'.repeat(342), e: 'AQAB' },
      // EC key with NO alg — must classify from key type, not invent one.
      { kty: 'EC', use: 'sig', kid: 'sig-2', crv: 'P-256', x: 'x', y: 'y' },
      // Encryption key — must not be counted as a signing primitive.
      { kty: 'RSA', use: 'enc', kid: 'enc-1', alg: 'RSA-OAEP-256', n: 'B'.repeat(342), e: 'AQAB' },
      // Post-quantum signing key.
      { kty: 'RSA', use: 'sig', kid: 'sig-3', alg: 'ML-DSA-65', n: 'C'.repeat(342), e: 'AQAB' },
    ],
  }
  const keys = parseJwks(jwks, ev('https://idp.acme.com/jwks', 'jwks'))
  assert(keys.length === 4, 'every JWK is parsed', String(keys.length))

  const sig2 = keys.find((k) => k.keyId === 'sig-2')!
  assert(sig2.algorithm === null, 'a key with no alg reports algorithm: null, not an invented one', String(sig2.algorithm))
  assert(sig2.classification.quantumClass === 'vulnerable', 'but is still classified vulnerable from its EC key type', sig2.classification.quantumClass)
  assert(sig2.curve === 'P-256' && sig2.keySize === 256, 'curve and size come from the document', `${sig2.curve}/${sig2.keySize}`)

  const sig1 = keys.find((k) => k.keyId === 'sig-1')!
  assert(sig1.keySize === 2048, 'RSA modulus size is derived from n', String(sig1.keySize))
  assert(sig1.use === 'signature', 'use=sig maps to signature', sig1.use)

  const enc1 = keys.find((k) => k.keyId === 'enc-1')!
  assert(enc1.use === 'encryption', 'use=enc maps to encryption', enc1.use)
  assert(enc1.classification.purpose === 'key-encapsulation', 'and is classified as key management')

  assert(parseJwks({ keys: [] }, ev('u', 'jwks')).length === 0, 'an empty JWKS yields no keys')
  assert(parseJwks(null, ev('u', 'jwks')).length === 0, 'a null JWKS yields no keys')

  /* ---- Observed beats advertised ---- */
  const advertisedOnly = parseOidcDiscovery(
    { issuer: 'https://idp.acme.com', jwks_uri: 'https://idp.acme.com/jwks', id_token_signing_alg_values_supported: ['ML-DSA-65'] },
    ev('https://idp.acme.com/.well-known/openid-configuration', 'oidc-discovery'),
  )!
  assert(advertisedOnly.quantumClass === 'safe', 'with no JWKS read, advertised support decides', advertisedOnly.quantumClass)

  const withJwks = parseOidcDiscovery(
    { issuer: 'https://idp.acme.com', jwks_uri: 'https://idp.acme.com/jwks', id_token_signing_alg_values_supported: ['ML-DSA-65'] },
    ev('https://idp.acme.com/.well-known/openid-configuration', 'oidc-discovery'),
    keys,
  )
  assert(
    withJwks!.quantumClass === 'vulnerable',
    'but a JWKS holding RSA/EC signing keys OVERRIDES a rosy advertisement',
    withJwks!.quantumClass,
  )
  assert(withJwks!.protocol === 'oidc', 'a document with id_token algs is OIDC', withJwks!.protocol)

  /* ---- Attribution across two providers on one host ---- */
  const probes: RawProbe[] = [
    {
      url: 'https://a.acme.com/.well-known/openid-configuration', method: 'oidc-discovery', httpStatus: 200, observedAt: AT,
      body: { issuer: 'https://a.acme.com', jwks_uri: 'https://a.acme.com/jwks', id_token_signing_alg_values_supported: ['RS256'], userinfo_endpoint: 'https://a.acme.com/ui' },
    },
    {
      url: 'https://a.acme.com/jwks', method: 'jwks', httpStatus: 200, observedAt: AT,
      body: { keys: [{ kty: 'RSA', use: 'sig', kid: 'A-KEY', alg: 'RS256', n: 'A'.repeat(342), e: 'AQAB' }] },
    },
    {
      url: 'https://b.acme.com/.well-known/openid-configuration', method: 'oidc-discovery', httpStatus: 200, observedAt: AT,
      body: { issuer: 'https://b.acme.com', jwks_uri: 'https://b.acme.com/jwks', id_token_signing_alg_values_supported: ['ML-DSA-65'], userinfo_endpoint: 'https://b.acme.com/ui' },
    },
    {
      url: 'https://b.acme.com/jwks', method: 'jwks', httpStatus: 200, observedAt: AT,
      body: { keys: [{ kty: 'RSA', use: 'sig', kid: 'B-KEY', alg: 'ML-DSA-65', n: 'B'.repeat(342), e: 'AQAB' }] },
    },
  ]
  const result = assembleIdentityDiscovery(probes)
  assert(result.providers.length === 2, 'two issuers ⇒ two providers', String(result.providers.length))

  const a = result.providers.find((p) => p.issuer === 'https://a.acme.com')!
  const b = result.providers.find((p) => p.issuer === 'https://b.acme.com')!
  assert(a.signingKeys.length === 1 && a.signingKeys[0].keyId === 'A-KEY', 'provider A holds ONLY its own key', a.signingKeys.map((k) => k.keyId).join(','))
  assert(b.signingKeys.length === 1 && b.signingKeys[0].keyId === 'B-KEY', 'provider B holds ONLY its own key', b.signingKeys.map((k) => k.keyId).join(','))
  assert(a.quantumClass === 'vulnerable', 'A is vulnerable (RSA signing key)', a.quantumClass)
  assert(b.quantumClass === 'safe', 'B is safe (ML-DSA signing key)', b.quantumClass)
  assert(a.vendor === null && b.vendor === null, 'neither gets an invented vendor')
}

/* ------------------------------------------------------------------ */
/* 8. Endpoints, protocol detection, and honest absence                */
/* ------------------------------------------------------------------ */
console.log('\n8. Endpoints, protocol and absence are reported faithfully')
{
  const record = parseOidcDiscovery(
    {
      issuer: 'https://sso.acme.com/realms/prod',
      authorization_endpoint: 'https://sso.acme.com/auth',
      token_endpoint: 'http://sso.acme.com/token',
      jwks_uri: 'https://sso.acme.com/jwks',
      grant_types_supported: ['authorization_code', 'refresh_token'],
      scopes_supported: ['openid', 'profile'],
      id_token_signing_alg_values_supported: ['RS256', 'ES256'],
      id_token_encryption_alg_values_supported: ['RSA-OAEP-256'],
      id_token_encryption_enc_values_supported: ['A256GCM'],
    },
    ev('https://sso.acme.com/.well-known/openid-configuration', 'oidc-discovery'),
  )!
  assert(record.vendor === 'Keycloak', 'the /realms/ contract identifies Keycloak', String(record.vendor))
  assert(record.endpoints.length === 3, 'every stated endpoint is captured', String(record.endpoints.length))
  const insecure = record.endpoints.find((e) => e.kind === 'token')!
  assert(insecure.insecureTransport, 'a plain-http token endpoint is flagged', insecure.url)
  assert(record.endpoints.find((e) => e.kind === 'authorization')!.insecureTransport === false, 'and an https endpoint is not')
  assert(record.grantTypesSupported.length === 2, 'grant types are captured')
  assert(record.signingAlgorithmsSupported.includes('RS256'), 'signing algorithms captured')
  assert(record.keyEncryptionAlgorithmsSupported.includes('RSA-OAEP-256'), 'key-management algorithms captured SEPARATELY from signing')
  assert(!record.signingAlgorithmsSupported.includes('RSA-OAEP-256'), 'and never mixed into the signing list')
  assert(record.contentEncryptionAlgorithmsSupported.includes('A256GCM'), 'content encryption captured separately again')

  const bare = parseOidcDiscovery(
    { issuer: 'https://as.acme.com', token_endpoint: 'https://as.acme.com/token', grant_types_supported: ['client_credentials'] },
    ev('https://as.acme.com/.well-known/oauth-authorization-server', 'oauth-as-metadata'),
  )!
  assert(bare.protocol === 'oauth2', 'a document with no OIDC fields is a bare OAuth 2.0 server', bare.protocol)

  const empty = assembleIdentityDiscovery([
    { url: 'https://nothing.example/.well-known/openid-configuration', method: 'oidc-discovery', httpStatus: 404, observedAt: AT, body: null },
  ])
  assert(empty.providers.length === 0, 'a 404 probe discovers no provider')
  assert(empty.probedWithoutResult.length === 1, 'but the probe is RECORDED as having run — proof of absence', String(empty.probedWithoutResult.length))

  const garbage = assembleIdentityDiscovery([
    { url: 'https://cdn.example/.well-known/openid-configuration', method: 'oidc-discovery', httpStatus: 200, observedAt: AT, body: { message: 'hello' } },
  ])
  assert(garbage.providers.length === 0, 'a 200 response that is not a discovery document yields no provider')
  assert(garbage.unparsed.length === 1 && /issuer/i.test(garbage.unparsed[0].reason), 'and the reason is recorded', garbage.unparsed[0]?.reason ?? '')
}

/* ------------------------------------------------------------------ */
/* 9. SAML                                                             */
/* ------------------------------------------------------------------ */
console.log('\n9. SAML metadata is read without executing untrusted XML')
{
  const xml = `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.acme.com/saml">
  <md:IDPSSODescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.acme.com/sso"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.acme.com/slo"/>
    <ds:SignatureMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`
  const saml = parseSamlMetadata(xml, ev('https://idp.acme.com/saml/metadata', 'saml-metadata'))!
  assert(Boolean(saml), 'valid SAML metadata parses')
  assert(saml.issuer === 'https://idp.acme.com/saml', 'entityID becomes the issuer', saml.issuer)
  assert(saml.protocol === 'saml2', 'protocol is saml2', saml.protocol)
  assert(saml.endpoints.length === 2, 'SSO and SLO endpoints captured', String(saml.endpoints.length))
  assert(saml.quantumClass === 'vulnerable', 'rsa-sha256 XML signing is Shor-vulnerable', saml.quantumClass)

  // An XXE payload must be inert: the reader is regex-based and never expands entities.
  const xxe = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<md:EntityDescriptor entityID="https://evil.example">&x;</md:EntityDescriptor>`
  const parsed = parseSamlMetadata(xxe, ev('u', 'saml-metadata'))
  assert(parsed !== null && parsed.issuer === 'https://evil.example', 'the entityID is still read')
  assert(!JSON.stringify(parsed).includes('root:'), 'and no external entity is ever expanded')
}

/* ------------------------------------------------------------------ */
/* 10. SSRF guard on the jwks_uri                                      */
/* ------------------------------------------------------------------ */
console.log('\n10. A document-supplied jwks_uri cannot steer the scanner')
{
  // A discovery document is attacker-controllable: whoever runs the probed host
  // chooses its jwks_uri. Cross-ORIGIN must be allowed (Google publishes its
  // JWKS on googleapis.com — an earlier same-host guard silently discarded the
  // very keys that decide the provider's posture), but internal destinations
  // must not be.
  const allow = [
    'https://www.googleapis.com/oauth2/v3/certs',
    'https://login.microsoftonline.com/common/discovery/v2.0/keys',
    'https://dev-123.okta.com/oauth2/v1/keys',
  ]
  const block = [
    'http://www.googleapis.com/certs',              // plaintext
    'https://169.254.169.254/latest/meta-data/',    // cloud metadata
    'https://127.0.0.1/jwks',                       // loopback
    'https://10.0.0.5/jwks',                        // private range
    'https://localhost/jwks',
    'https://vault.internal/jwks',
    'https://intranet-host/jwks',                   // single-label, resolves via search domain
    'https://[::1]/jwks',                           // IPv6 loopback
    'not-a-url',
  ]
  for (const url of allow) assert(isSafePublicJwksUrl(url), `allows a legitimate cross-origin JWKS: ${url.slice(8, 48)}`)
  for (const url of block) assert(!isSafePublicJwksUrl(url), `blocks ${url.slice(0, 44)}`)
}

console.log(`\n${failures === 0 ? '✓ All identity discovery invariants hold.' : `✗ ${failures} invariant(s) FAILED.`}`)
process.exit(failures === 0 ? 0 : 1)
