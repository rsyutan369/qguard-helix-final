/**
 * The agent test lab — real cryptographic material, built fresh per run.
 *
 * Shared by the offline collector check and the live four-role check so both
 * exercise the identical estate. OpenSSL-issued certificates (RSA, an ECDSA leaf
 * under an RSA-named CA, ML-DSA-65, a two-certificate bundle), private keys (one
 * encrypted), a JWKS, SAML IdP metadata, configuration files, a package manifest
 * and an SSH public key; plus live local TLS servers.
 */
import { execFileSync } from 'node:child_process'
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import tls from 'node:tls'

export function openssl(args: string[], cwd: string) {
  execFileSync('openssl', args, { cwd, stdio: 'pipe', env: { ...process.env, MSYS_NO_PATHCONV: '1' } })
}
export const sha256File = (file: string) => createHash('sha256').update(fs.readFileSync(file)).digest('hex')

/* ─────────────────────────────────────────────────────────────── lab ── */

export function buildLab(root: string) {
  for (const dir of ['pki', 'keys', 'identity', 'app', 'migrate', 'deps', 'ssh']) fs.mkdirSync(path.join(root, dir), { recursive: true })
  const pki = path.join(root, 'pki')

  // RSA-2048 self-signed certificate + key (the key doubles as a key-file sample).
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', '../keys/rsa2048.key', '-out', 'rsa2048.crt', '-days', '30', '-subj', '/CN=lab-rsa'], pki)
  // An RSA CA whose NAME contains "RSA", issuing an ECDSA P-256 leaf — the issuer-name trap.
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '30', '-subj', '/CN=Lab Global G2 TLS RSA SHA256 2026 CA1'], pki)
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', 'ecdsa-leaf.key'], pki)
  openssl(['req', '-new', '-key', 'ecdsa-leaf.key', '-out', 'ecdsa-leaf.csr', '-subj', '/CN=lab-ecdsa'], pki)
  openssl(['x509', '-req', '-in', 'ecdsa-leaf.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'ecdsa-leaf.crt', '-days', '30'], pki)
  // Post-quantum certificate.
  openssl(['req', '-x509', '-newkey', 'mldsa65', '-nodes', '-keyout', 'mldsa65.key', '-out', 'mldsa65.crt', '-days', '30', '-subj', '/CN=lab-mldsa'], pki)
  // A bundle holding two certificates.
  fs.writeFileSync(path.join(pki, 'chain.pem'), fs.readFileSync(path.join(pki, 'ecdsa-leaf.crt'), 'utf8') + fs.readFileSync(path.join(pki, 'ca.crt'), 'utf8'))
  // CA/CSR/serial helpers are not lab evidence.
  for (const f of ['ca.key', 'ecdsa-leaf.csr', 'ca.srl']) fs.rmSync(path.join(pki, f), { force: true })
  fs.renameSync(path.join(pki, 'ecdsa-leaf.key'), path.join(root, 'keys', 'ecdsa-leaf.key'))
  fs.renameSync(path.join(pki, 'mldsa65.key'), path.join(root, 'keys', 'mldsa65.key'))

  // Key files: P-384 and an encrypted PKCS#8 key.
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-384', '-out', 'ec384.key'], path.join(root, 'keys'))
  openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-aes256', '-pass', 'pass:lab-only', '-out', 'encrypted.key'], path.join(root, 'keys'))

  // Identity: a JWKS (RSA-2048 RS256 + P-384 ES384) and SAML IdP metadata.
  const rsaJwk = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' })
  const ecJwk = generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({ format: 'jwk' })
  fs.writeFileSync(path.join(root, 'identity', 'jwks.json'), JSON.stringify({ keys: [
    { ...rsaJwk, kid: 'lab-rs', use: 'sig', alg: 'RS256' },
    { ...ecJwk, kid: 'lab-es', use: 'sig', alg: 'ES384' },
  ] }, null, 2))
  const samlCertDer = new X509Certificate(fs.readFileSync(path.join(pki, 'rsa2048.crt'))).raw.toString('base64')
  fs.writeFileSync(path.join(root, 'identity', 'idp-metadata.xml'), `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.lab.qguard.test/saml">
  <ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo></ds:Signature>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${samlCertDer}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
`)

  // Configurations the Patcher and Operator will change.
  fs.writeFileSync(path.join(root, 'app', 'tls.conf'), 'TLS_GROUPS=X25519\nssl_protocols TLSv1.2;\n')
  fs.writeFileSync(path.join(root, 'migrate', 'gateway.conf'), 'TLS_GROUPS=X25519\nssl_protocols TLSv1.2;\n')
  fs.writeFileSync(path.join(root, 'migrate', 'edge.conf'), 'TLS_GROUPS=X25519\n')

  // Dependencies.
  fs.writeFileSync(path.join(root, 'deps', 'package.json'), JSON.stringify({ name: 'lab-app', dependencies: { 'node-forge': '1.3.1', jsonwebtoken: '9.0.2' } }, null, 2))

  // SSH public key.
  execFileSync('ssh-keygen', ['-t', 'ed25519', '-N', '', '-C', 'lab', '-f', path.join(root, 'ssh', 'id_ed25519'), '-q'], { stdio: 'pipe' })
  fs.rmSync(path.join(root, 'ssh', 'id_ed25519'), { force: true }) // keep only the public half
}

export function startTlsServer(root: string, group: string, certFile: string, keyFile: string): Promise<tls.Server> {
  return new Promise((resolve) => {
    const server = tls.createServer({
      key: fs.readFileSync(path.join(root, keyFile)),
      cert: fs.readFileSync(path.join(root, certFile)),
      ecdhCurve: group,
      minVersion: 'TLSv1.3',
    }, (socket) => socket.end())
    server.on('tlsClientError', () => { /* refused probes are expected */ })
    server.listen(0, '127.0.0.1', () => resolve(server))
  })
}

