/**
 * Request Demo delivery — verification harness.
 *
 *   npx tsx tools/demo-request-check.ts
 *
 * Offline: no mail server is contacted. Drives the real router over HTTP with
 * a recording sender, and renders the real message through nodemailer's
 * stream transport, asserting:
 *   • a valid request is delivered once, to the sales inbox, with Reply-To set
 *   • nothing a visitor types can add a mail header (CR/LF, address tricks)
 *   • invalid input, the honeypot, missing SMTP and a failed send are each
 *     answered honestly — never "sent" unless the sender accepted it
 *   • per-client and global limits hold, and a failed send is not charged
 */

import express from 'express'
import type { AddressInfo } from 'node:net'
import nodemailer from 'nodemailer'
import { DEMO_REQUEST_INBOX, validateDemoRequest } from '../src/lib/demo-request'
import { createChecklistRequestRouter } from '../src/api-server/checklist-request'
import type { WebsiteSubmission } from '../src/api-server/website-submissions'
import {
  composeDemoEmail,
  createDemoRequestRouter,
  type DemoEmail,
  type DemoRequestRouterConfig,
} from '../src/api-server/demo-request'

let passed = 0
let failed = 0

function check(name: string, condition: boolean, detail = ''): void {
  if (condition) {
    passed += 1
    console.log(`  PASS  ${name}${detail ? ` — ${detail}` : ''}`)
  } else {
    failed += 1
    console.error(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

const VALID = {
  name: 'Ada Lovelace',
  email: 'ada@example.com',
  organization: 'Analytical Engines Ltd',
  stage: 'piloting',
  whitepaper: true,
  message: 'We run 400 TLS endpoints.\nInterested in ML-KEM hybrid rollout.',
}

async function withServer(
  config: DemoRequestRouterConfig,
  run: (post: (body: unknown, ip?: string) => Promise<{ status: number; json: any; headers: Headers }>) => Promise<void>,
): Promise<void> {
  const app = express()
  app.set('trust proxy', true)
  app.use(express.json({ limit: '256kb' }))
  app.use('/api/v1/demo-request', createDemoRequestRouter(config))
  const server = app.listen(0)
  await new Promise<void>((resolve) => server.once('listening', () => resolve()))
  const { port } = server.address() as AddressInfo
  const post = async (body: unknown, ip = '203.0.113.10') => {
    const response = await fetch(`http://127.0.0.1:${port}/api/v1/demo-request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip },
      body: JSON.stringify(body),
    })
    return { status: response.status, json: await response.json().catch(() => null), headers: response.headers }
  }
  try {
    await run(post)
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
}

function recorder() {
  const sent: DemoEmail[] = []
  return { sent, sender: async (email: DemoEmail) => { sent.push(email) } }
}

async function main(): Promise<void> {
  console.log('\nValidator')
  check('valid request passes', validateDemoRequest(VALID).ok)
  const crlf = validateDemoRequest({ ...VALID, name: 'Eve\r\nBcc: victim@example.net', organization: 'X\nY' })
  check('CR/LF in single-line fields collapse to spaces',
    crlf.ok === true && crlf.value.name === 'Eve Bcc: victim@example.net' && crlf.value.organization === 'X Y')
  for (const email of ['"a b"@example.com', 'a@b.com, c@d.com', 'Eve <eve@x.com>', 'a@b.com;c@d.com', 'a(c)@b.com', 'a@b', 'a@b.com\r\nBcc: x@y.com']) {
    check(`email rejected: ${JSON.stringify(email)}`, validateDemoRequest({ ...VALID, email }).ok === false)
  }
  check('unknown stage rejected', validateDemoRequest({ ...VALID, stage: 'quantum' }).ok === false)
  check('overlong message rejected', validateDemoRequest({ ...VALID, message: 'x'.repeat(4001) }).ok === false)
  check('missing organization rejected', validateDemoRequest({ ...VALID, organization: '   ' }).ok === false)
  const lines = validateDemoRequest({ ...VALID, message: 'line one\r\nline two\u0007' })
  check('message keeps line breaks, drops other control characters',
    lines.ok === true && lines.value.message === 'line one\nline two')

  console.log('\nRendered message (nodemailer stream transport)')
  const parsed = validateDemoRequest({ ...VALID, name: 'Eve\r\nBcc: victim@example.net' })
  if (parsed.ok === false) throw new Error('fixture invalid')
  const email = composeDemoEmail(parsed.value, { to: DEMO_REQUEST_INBOX, from: 'noreply@qguardhelix.com' }, new Date('2026-10-27T00:00:00Z'))
  const transport = nodemailer.createTransport({ streamTransport: true, buffer: true, newline: 'unix' })
  const info = await transport.sendMail(email)
  const raw = (info.message as Buffer).toString('utf8')
  const headerBlock = raw.split('\n\n')[0]
  check('To is the sales inbox', /^To: info@qguardhelix\.com$/m.test(headerBlock), DEMO_REQUEST_INBOX)
  check('Reply-To is the visitor', /^Reply-To: .*<ada@example\.com>$/m.test(headerBlock))
  check('no injected Bcc header', !/^Bcc:/mi.test(headerBlock))
  check('envelope recipients are only the inbox',
    JSON.stringify(info.envelope.to) === JSON.stringify([DEMO_REQUEST_INBOX]), JSON.stringify(info.envelope.to))
  check('plain text only (no HTML part)', !/text\/html/i.test(raw))
  check('body carries the message and stage label',
    email.text.includes('Interested in ML-KEM hybrid rollout.') && email.text.includes('Piloting Post-Quantum Algorithms'))

  console.log('\nRouter')
  {
    const { sent, sender } = recorder()
    await withServer({ sender, from: 'noreply@qguardhelix.com' }, async (post) => {
      const ok = await post(VALID)
      check('valid request → 200 ok', ok.status === 200 && ok.json?.ok === true && ok.json?.inbox === DEMO_REQUEST_INBOX)
      check('delivered exactly once, to the inbox', sent.length === 1 && sent[0].to === DEMO_REQUEST_INBOX)
      check('Reply-To carries the visitor address', sent[0]?.replyTo.address === VALID.email)

      const bot = await post({ ...VALID, website: 'https://spam.example' }, '203.0.113.20')
      check('honeypot → 200 but nothing sent', bot.status === 200 && sent.length === 1)

      const bad = await post({ ...VALID, email: 'not-an-email' }, '203.0.113.30')
      check('invalid email → 400 with field', bad.status === 400 && bad.json?.error?.code === 'INVALID_DEMO_REQUEST' && bad.json?.error?.field === 'email')
      const notObject = await post(['x'], '203.0.113.31')
      check('non-object body → 400', notObject.status === 400)
    })
  }
  {
    await withServer({ sender: null }, async (post) => {
      const res = await post(VALID)
      check('no SMTP configured → 503 with the inbox to email',
        res.status === 503 && res.json?.error?.code === 'DEMO_EMAIL_NOT_CONFIGURED' && res.json?.error?.inbox === DEMO_REQUEST_INBOX)
    })
  }
  {
    const { sent, sender } = recorder()
    await withServer({ sender, from: 'noreply@qguardhelix.com', maxPerClient: 3, maxPerHour: 5 }, async (post) => {
      const statuses: number[] = []
      for (let i = 0; i < 4; i += 1) statuses.push((await post(VALID, '198.51.100.1')).status)
      check('per-client limit: 3 accepted, 4th refused', statuses.join(',') === '200,200,200,429', statuses.join(','))
      const limited = await post(VALID, '198.51.100.1')
      check('429 carries Retry-After', Number(limited.headers.get('retry-after')) > 0, limited.headers.get('retry-after') ?? 'missing')
      const other = await post(VALID, '198.51.100.2')
      check('another client is unaffected', other.status === 200)
      const third = await post(VALID, '198.51.100.3')
      const overGlobal = await post(VALID, '198.51.100.4')
      check('global hourly cap holds', third.status === 200 && overGlobal.status === 429 && sent.length === 5, `sent=${sent.length}`)
    })
  }
  {
    let attempts = 0
    const flaky = async () => {
      attempts += 1
      if (attempts <= 3) throw Object.assign(new Error('Connection refused'), { code: 'ECONNECTION' })
    }
    await withServer({ sender: flaky, from: 'noreply@qguardhelix.com', maxPerClient: 1 }, async (post) => {
      const failure = await post(VALID)
      check('failed send → 502, never reported as sent',
        failure.status === 502 && failure.json?.ok !== true && failure.json?.error?.code === 'DEMO_EMAIL_FAILED')
      await post(VALID)
      await post(VALID)
      const retry = await post(VALID)
      check('failed sends are not charged to the limit', retry.status === 200, `status=${retry.status}`)
    })
  }

  {
    const submissions: WebsiteSubmission[] = []
    const record = async (row: WebsiteSubmission) => { submissions.push(row); return 'fixture-id' }
    await withServer({ record }, async (post) => {
      const response = await post({ ...VALID, source: 'footer' })
      check('demo is recorded when email is unconfigured', response.status === 201 &&
        response.json?.emailAccepted === false && submissions[0]?.source === 'footer' && submissions[0]?.email_status === 'not_configured')
    })
    let status = ''
    await withServer({ record, from: 'noreply@qguardhelix.com',
      sender: async () => { throw new Error('Fixture SMTP outage') },
      updateEmailStatus: async (_id, result) => { status = result },
    }, async (post) => {
      const response = await post({ ...VALID, source: 'navigation' })
      check('notification failure preserves the demo record', response.status === 201 && response.json?.emailAccepted === false &&
        status === 'failed' && submissions[1]?.source === 'navigation')
    })
    await withServer({
      record: async () => { throw new Error('Fixture storage outage') },
      from: 'noreply@qguardhelix.com',
      sender: async () => { status = 'unexpected-send' },
    }, async (post) => {
      const response = await post(VALID)
      check('demo storage failure is explicit and SMTP is skipped', response.status === 503 && status === 'failed')
    })

    const app = express()
    app.use(express.json())
    app.use('/checklist', createChecklistRequestRouter(record))
    app.use('/offline', createChecklistRequestRouter(async () => { throw new Error('Fixture storage outage') }))
    const server = app.listen(0)
    await new Promise<void>((resolve) => server.once('listening', resolve))
    try {
      const port = (server.address() as AddressInfo).port
      const request = { firstName: 'Test', lastName: 'Visitor', workEmail: VALID.email, company: VALID.organization, title: 'Engineer', country: 'Philippines', consent: true }
      const post = (path: string, body: typeof request) => fetch(`http://127.0.0.1:${port}/${path}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      })
      const valid = await post('checklist', request)
      const invalid = await post('checklist', { ...request, consent: false })
      const offline = await post('offline', request)
      check('checklist saves contact details and consent', valid.status === 201 && submissions[2]?.kind === 'pqc-checklist' &&
        submissions[2]?.details.communicationsConsent === true)
      check('invalid checklist consent is rejected without a record', invalid.status === 400 && submissions.length === 3)
      check('checklist storage failure does not confirm a download', offline.status === 503)
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  }

  console.log(`\n${passed} passed, ${failed} failed`)
  if (failed > 0) process.exit(1)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
