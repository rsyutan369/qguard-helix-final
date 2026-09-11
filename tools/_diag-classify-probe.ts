import { analyzeCryptoObservation } from '../src/lib/crypto/suite-anatomy'
const names = [
  'sha256WithRSAEncryption','sha1WithRSAEncryption','sha384WithRSAEncryption','SHA256withRSA',
  'rsassa-pss','ecdsa-with-SHA384','SHA256withECDSA','sha1WithDSA','SHA-256','SHA-1','MD5',
  'RSA-2048','AES-128-GCM','AES-256-GCM','TLSv1.3','X25519','ML-KEM-768','X25519MLKEM768',
  'TLS_AES_128_GCM_SHA256','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256','TLS_RSA_WITH_AES_128_CBC_SHA',
  'ECDHE','Ed25519','universal','traversal',
]
for (const n of names) {
  const a = analyzeCryptoObservation({ algorithm: n })
  console.log(n.padEnd(38),'|',a.kind.padEnd(13),'|',a.quantumClass.padEnd(10),'| family='+String(a.family).padEnd(24),'| mac='+String(a.mac))
}
