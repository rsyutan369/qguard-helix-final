import { ISSUANCE_UNAVAILABLE } from '@/lib/crypto/issuance-evidence'

export function IssuanceApiDocs({ kind }: { kind: 'keys' | 'pki' }) {
  const keys = kind === 'keys'
  return (
    <div className="max-w-3xl space-y-5">
      <h1 className="text-2xl font-bold">{keys ? 'Encryption Key Records' : 'Digital Certificate Records'}</h1>
      <p>Use <code>GET /api/v1/{kind}</code> with a Bearer access token to list historical records for your account. The response includes pagination metadata; use <code>limit</code> and <code>offset</code>.</p>
      <p>These records preserve reported metadata. They are not proof of key generation, signed certificate issuance, an approved entropy source, or FIPS 140 module validation.</p>
      <h2 className="text-lg font-semibold">Issuance unavailable</h2>
      <p><code>POST /api/v1/{kind}</code> and the {keys ? 'key' : 'PKI'} action on the QRNG stream return HTTP 503 with <code>{ISSUANCE_UNAVAILABLE.code}</code>.</p>
      <p>{ISSUANCE_UNAVAILABLE.message}</p>
    </div>
  )
}
