import http, { type IncomingMessage } from 'node:http'
import https from 'node:https'
import { canFollowRedirect, safeLookup } from './safe-dns'

const MAX_REDIRECTS = 5
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

interface WebRequestOptions {
  method: 'GET' | 'HEAD'
  accept: string
  timeoutMs: number
  bodyLimit?: number
  requireHttps?: boolean
  userAgent?: string
}

interface WebResponse {
  status: number
  ok: boolean
  url: string
  headers: Headers
  body: string
}

async function readBody(response: IncomingMessage, limit: number): Promise<string> {
  const encoding = response.headers['content-encoding']?.toLowerCase()
  if ((encoding && encoding !== 'identity') || Number(response.headers['content-length']) > limit) {
    response.destroy()
    throw new Error('Web resource exceeds the scanner response budget')
  }

  const chunks: Buffer[] = []
  let bytes = 0
  for await (const chunk of response) {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    bytes += data.length
    if (bytes > limit) throw new Error('Web resource exceeds the scanner response budget')
    chunks.push(data)
  }
  return Buffer.concat(chunks, bytes).toString('utf8')
}

/** Read a public resource, validating every connection while preserving HTTP Host and TLS SNI. */
export async function requestPublicWebResource(rawUrl: string, options: WebRequestOptions): Promise<WebResponse> {
  const signal = AbortSignal.timeout(options.timeoutMs)
  let target = new URL(rawUrl)

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const verdict = canFollowRedirect(target.href)
    if (!verdict.ok || target.username || target.password || (options.requireHttps && target.protocol !== 'https:')) {
      throw new Error('Web resource destination is outside the public scanner policy')
    }

    const request = target.protocol === 'https:' ? https.request : http.request
    const response = await new Promise<IncomingMessage>((resolve, reject) => {
      const outgoing = request(target, {
        agent: false,
        lookup: safeLookup,
        signal,
        method: options.method,
        headers: {
          'User-Agent': options.userAgent ?? 'QGuard-Scanner/2.4',
          Accept: options.accept,
          'Accept-Encoding': 'identity',
        },
      }, resolve)
      outgoing.once('error', reject)
      outgoing.end()
    })

    const status = response.statusCode || 0
    const location = response.headers.location
    if (location && REDIRECT_STATUSES.has(status)) {
      response.destroy()
      target = new URL(location, target)
      continue
    }

    const headers = new Headers()
    for (const [name, value] of Object.entries(response.headers)) {
      if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(', ') : value)
    }
    const ok = status >= 200 && status < 300
    if (ok && options.method === 'GET' && options.bodyLimit !== undefined) {
      return { status, ok, url: target.href, headers, body: await readBody(response, options.bodyLimit) }
    }
    response.destroy()
    return { status, ok, url: target.href, headers, body: '' }
  }

  throw new Error('Web resource exceeded the redirect budget')
}
