// Fixed-input lab worker. No DB credentials, user code, filesystem writes, or network sockets.
import * as crypto from 'node:crypto'
import tls from 'node:tls'
import { Duplex } from 'node:stream'

const input = JSON.parse(process.argv[2] || '{}')
const provider = `Node ${process.version} / OpenSSL ${process.versions.openssl}`
const primitives = ['ML-KEM-768', 'ML-KEM-1024', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128f', 'AES-256-GCM', 'SHA3-256', 'HKDF-SHA3-256']
const groups = ['X25519MLKEM768', 'SecP384r1MLKEM1024']
const message = Buffer.from('Qguard Helix lab payload v1')
const equal = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b)
const record = (data) => process.stdout.write(JSON.stringify(data) + '\n')
const bytes = (name, value) => ({ name, value, unit: 'bytes' })
const ms = (name, value) => ({ name, value: Math.round(value * 1000) / 1000, unit: 'ms' })
const assert = (success, detail) => { if (!success) throw new Error(detail) }
function measure(metrics, name, run) {
  const start = performance.now()
  const result = run()
  metrics.push(ms(name, performance.now() - start))
  return result
}

function exercise(config) {
  const { algorithm, keySize } = config
  const metrics = []
  const type = algorithm.toLowerCase()
  if (type.startsWith('ml-kem-')) {
    const keys = measure(metrics, 'Key generation', () => crypto.generateKeyPairSync(type))
    const { sharedKey, ciphertext } = measure(metrics, 'Encapsulation', () => crypto.encapsulate(keys.publicKey))
    const recovered = measure(metrics, 'Decapsulation', () => crypto.decapsulate(keys.privateKey, ciphertext))
    assert(equal(recovered, sharedKey), 'The encapsulated and recovered secrets differ.')
    metrics.push(bytes('Encapsulation key (raw)', keys.publicKey.export({ format: 'raw-public' }).length), bytes('Ciphertext', ciphertext.length))
  } else if (/^(ml-dsa-|slh-dsa-)/.test(type) || ['rsa', 'ec', 'ed25519'].includes(type)) {
    const options = type === 'rsa' ? { modulusLength: keySize } : type === 'ec' ? { namedCurve: keySize === 384 ? 'secp384r1' : 'prime256v1' } : {}
    const keys = measure(metrics, 'Key generation', () => crypto.generateKeyPairSync(type, options))
    const digest = type === 'rsa' || type === 'ec' ? 'sha256' : null
    const sig = measure(metrics, 'Signing', () => crypto.sign(digest, message, keys.privateKey))
    assert(measure(metrics, 'Verification', () => crypto.verify(digest, message, keys.publicKey, sig)), 'The signature did not verify.')
    assert(!crypto.verify(digest, Buffer.from('Modified test payload'), keys.publicKey, sig), 'The verifier accepted a modified payload.')
    metrics.push(bytes('Signature', sig.length), bytes('Public key (SPKI DER)', keys.publicKey.export({ type: 'spki', format: 'der' }).length))
  } else if (type === 'x25519' || type === 'ecdh') {
    const generate = () => type === 'x25519' ? crypto.generateKeyPairSync(type) : crypto.generateKeyPairSync('ec', { namedCurve: keySize === 384 ? 'secp384r1' : 'prime256v1' })
    const a = measure(metrics, 'Key generation', generate)
    const b = generate()
    const shared = measure(metrics, 'Shared secret derivation', () => crypto.diffieHellman({ privateKey: a.privateKey, publicKey: b.publicKey }))
    assert(equal(shared, crypto.diffieHellman({ privateKey: b.privateKey, publicKey: a.publicKey })), 'The test peers derived different secrets.')
    metrics.push(bytes('Public key (SPKI DER)', a.publicKey.export({ type: 'spki', format: 'der' }).length))
  } else if (/^aes-(128|256)-gcm$/.test(type)) {
    const key = crypto.randomBytes(type === 'aes-256-gcm' ? 32 : 16)
    const nonce = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv(type, key, nonce)
    const encrypted = measure(metrics, 'Authenticated encryption', () => Buffer.concat([cipher.update(message), cipher.final()]))
    const tag = cipher.getAuthTag()
    const decrypt = (authTag) => {
      const decipher = crypto.createDecipheriv(type, key, nonce)
      decipher.setAuthTag(authTag)
      return Buffer.concat([decipher.update(encrypted), decipher.final()])
    }
    assert(equal(message, measure(metrics, 'Authenticated decryption', () => decrypt(tag))), 'The recovered plaintext differs.')
    const invalidTag = Buffer.from(tag)
    invalidTag[0] ^= 1
    let rejected = false
    try { decrypt(invalidTag) } catch { rejected = true }
    assert(rejected, 'The cipher accepted an invalid authentication tag.')
    metrics.push(bytes('Ciphertext and tag', encrypted.length + tag.length))
  } else if (type === 'sha3-256' || type === 'sha256') {
    const digest = measure(metrics, 'Digest', () => crypto.createHash(type).update('abc').digest())
    const expected = type === 'sha3-256' ? '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532' : 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    assert(digest.toString('hex') === expected, 'The fixed-input digest did not match the expected vector.')
    metrics.push(bytes('Digest', digest.length))
  } else if (type === 'hkdf-sha3-256') {
    const ikm = Buffer.alloc(32, 0x0b)
    const salt = Buffer.from('qguard-lab-salt')
    const info = Buffer.from('qguard-lab-info')
    const derived = measure(metrics, 'Derivation', () => Buffer.from(crypto.hkdfSync('sha3-256', ikm, salt, info, 32)))
    const prk = crypto.createHmac('sha3-256', salt).update(ikm).digest()
    const expected = crypto.createHmac('sha3-256', prk).update(info).update(Buffer.from([1])).digest()
    assert(equal(derived, expected), 'HKDF output differs from the independent extract/expand steps.')
    metrics.push(bytes('Derived key length', derived.length))
  } else {
    throw new Error('The algorithm has no lab adapter.')
  }
  return metrics
}

const der = (tag, ...fields) => {
  const value = Buffer.concat(fields)
  const length = value.length < 128 ? [value.length]
    : value.length <= 255 ? [0x81, value.length] : [0x82, value.length >>> 8, value.length & 255]
  return Buffer.concat([Buffer.from([tag, ...length]), value])
}
const seq = (...fields) => der(0x30, ...fields)
const hex = (input) => Buffer.from(input, 'hex')
function certificate(type = 'ec', size = 256) {
  const options = type === 'rsa' ? { modulusLength: size } : type === 'ec' ? { namedCurve: size === 384 ? 'secp384r1' : 'prime256v1' } : {}
  const { privateKey, publicKey } = crypto.generateKeyPairSync(type, options)
  const signatureId = {
    ec: '300a06082a8648ce3d040302',
    rsa: '300d06092a864886f70d01010b0500',
    'ed25519': '300506032b6570',
    'ml-dsa-65': '300b0609608648016503040312',
    'ml-dsa-87': '300b0609608648016503040313',
  }[type]
  const signature = hex(signatureId)
  const name = seq(der(0x31, seq(hex('0603550403'), der(0x0c, Buffer.from('sandbox.invalid')))))
  const date = (value) => der(0x18, Buffer.from(value.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z'))
  const validity = seq(date(new Date(Date.now() - 60_000)), date(new Date(Date.now() + 3_600_000)))
  const serial = crypto.randomBytes(12)
  serial[0] = 1
  const tbs = seq(hex('a003020102'), der(2, serial), signature, name, validity, name, publicKey.export({ type: 'spki', format: 'der' }))
  const signed = crypto.sign(type === 'rsa' || type === 'ec' ? 'sha256' : null, tbs, privateKey)
  const cert = seq(tbs, signature, der(3, Buffer.from([0]), signed))
  const pem = `-----BEGIN CERTIFICATE-----\n${cert.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`
  const key = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' }))
  return { key, cert: pem, size: cert.length }
}

// Fixed paired streams carry encrypted records only inside this subprocess.
// Both sides restrict the negotiated version and group to the profile requested.
async function handshake({ group, protocol, certificateType, certificateSize }) {
  const fixture = certificate(certificateType, certificateSize)
  let up = 0
  let down = 0
  let receivedBytes = 0
  let left, right
  const endpoint = (peer, count) => new Duplex({
    read() {},
    write(chunk, _encoding, callback) { count(chunk.length); peer().push(Buffer.from(chunk)); callback() },
  })
  left = endpoint(() => right, (size) => { up += size })
  right = endpoint(() => left, (size) => { down += size })
  const options = { minVersion: protocol, maxVersion: protocol, ecdhCurve: group }
  let server, client
  try {
    const context = tls.createSecureContext({ ...options, cert: fixture.cert, key: fixture.key })
    fixture.key.fill(0)
    server = new tls.TLSSocket(right, { isServer: true, secureContext: context })
    server.on('data', (data) => server.write(data))
    const start = performance.now()
    client = tls.connect({ ...options, socket: left, ca: fixture.cert, rejectUnauthorized: true, servername: 'sandbox.invalid' })
    const observed = await new Promise((resolve, reject) => {
      server.on('error', reject)
      client.on('error', reject)
      client.once('secureConnect', () => {
        try {
          const observedGroup = client.getEphemeralKeyInfo()?.name
          const normalized = (name) => name?.toLowerCase().replace('prime256v1', 'secp256r1')
          assert(client.authorized && client.getProtocol() === protocol, 'The negotiated protocol or certificate trust differed from the harness profile.')
          if (observedGroup) assert(normalized(observedGroup) === normalized(group), 'A different TLS group was negotiated.')
          const measurements = [ms('TLS handshake', performance.now() - start), bytes('Encrypted handshake traffic at client completion', up + down), bytes('Synthetic TLS certificate (DER)', fixture.size)]
          const detail = `${client.getProtocol()} · ${client.getCipher().standardName} · ${observedGroup || `only configured group: ${group}`} · trusted synthetic ${certificateType || 'ec'} certificate · encrypted application echo`
          client.on('data', (data) => {
            const expected = message.subarray(receivedBytes, receivedBytes + data.length)
            if (!equal(data, expected)) return reject(new Error('The authenticated TLS payload did not round-trip.'))
            receivedBytes += data.length
            if (receivedBytes === message.length) resolve({ measurements, detail })
          })
          client.write(message)
        } catch (error) { reject(error) }
      })
    })
    return observed
  } finally {
    fixture.key.fill(0)
    client?.destroy()
    server?.destroy()
    left.destroy()
    right.destroy()
  }
}

async function probe() {
  const availablePrimitives = {}
  const availableGroups = {}
  const availableCertificates = {}
  for (const algorithm of primitives) {
    try { exercise({ algorithm }); availablePrimitives[algorithm] = true } catch { availablePrimitives[algorithm] = false }
  }
  for (const group of groups) {
    availableCertificates[group] = {}
    for (const [label, certificateType] of [['ecdsa', 'ec'], ['ml-dsa-65', 'ml-dsa-65'], ['ml-dsa-87', 'ml-dsa-87']]) {
      try {
        await handshake({ group, protocol: 'TLSv1.3', certificateType })
        availableCertificates[group][label] = true
      } catch { availableCertificates[group][label] = false }
    }
    availableGroups[group] = Object.values(availableCertificates[group]).some(Boolean)
  }
  record({ type: 'capabilities', data: { provider, worker: true, primitives: availablePrimitives, tlsGroups: availableGroups, tlsCertificates: availableCertificates } })
}

async function run() {
  for (const task of input.tasks) {
    const { level, profile, operation } = task
    record({ type: 'operation', data: operation + ' · ' + profile })
    const cpu = process.cpuUsage()
    let result
    try {
      if (level === 'execution') {
        result = { status: 'passed', detail: 'Operation and result checks completed using generated test material.', measures: exercise(task) }
      } else {
        const check = await handshake(task)
        result = { status: 'passed', detail: check.detail, measures: check.measurements }
      }
      const usage = process.cpuUsage(cpu)
      result.measures.push(ms('Process CPU elapsed', (usage.user + usage.system) / 1000), bytes('Process resident memory at sample', process.memoryUsage.rss()))
    } catch (error) {
      const code = String(error.code || 'CHECK_FAILED').slice(0, 80)
      const reason = String(error.message || 'The check failed.').slice(0, 250)
      const unsupported = /INVALID_ARG_VALUE|NOT_SUPPORTED|UNSUPPORTED|ERR_CRYPTO_UNKNOWN|ERR_TLS_INVALID_PROTOCOL_VERSION|ERR_SSL_NO_SUITABLE_SIGNATURE_ALGORITHM/.test(code)
      result = {
        status: unsupported ? 'unsupported' : 'failed', detail: `${code} · ${reason}`,
        issues: [{
          severity: 'high', component: profile, explanation: reason, blocks: true,
          impact: 'This profile has no passing check on the lab runtime.',
          remediation: level === 'emulation' ? 'Use a compatible TLS version, groups and certificate profile. Re-run with the provider used by representative peers.' : 'Verify runtime algorithm support and configuration, then rerun the operation.',
        }],
      }
    }
    record({ type: 'result', data: { level, profile, operation, provider, observedAt: new Date().toISOString(), ...result } })
  }
}

await (input.probe ? probe() : run())
