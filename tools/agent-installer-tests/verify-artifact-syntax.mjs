/**
 * Syntax-validates every generated installer artifact.
 *
 * A script that embeds the right values but does not parse is still broken, so
 * this runs each artifact through its real parser: bash -n, the PowerShell
 * tokenizer, and a YAML load.
 */

import { createClient } from '@supabase/supabase-js'
import { execFile } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'

const run = promisify(execFile)
const BASE = 'http://localhost:3000'
const OWNER_EMAIL = 'zachmatthew369@gmail.com'

const env = Object.fromEntries(
  fs.readFileSync(new URL('../../.env', import.meta.url), 'utf8')
    .split(/\r?\n/)
    .filter((l) => l.includes('=') && !l.startsWith('#'))
    .map((l) => { const i = l.indexOf('='); return [l.slice(0, i).trim(), l.slice(i + 1).trim().replace(/^["']|["']$/g, '')] }),
)

const admin = createClient(env.VITE_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
const anon = createClient(env.VITE_SUPABASE_URL, env.VITE_SUPABASE_ANON_KEY, { auth: { persistSession: false } })

let pass = 0
let fail = 0
const check = (name, ok, detail = '') => {
  if (ok) { pass += 1; console.log(`  PASS  ${name}`) }
  else { fail += 1; console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`) }
}

const link = await admin.auth.admin.generateLink({ type: 'magiclink', email: OWNER_EMAIL })
const verified = await anon.auth.verifyOtp({ type: 'magiclink', token_hash: link.data.properties.hashed_token })
const token = verified.data.session.access_token

const enroll = await fetch(`${BASE}/api/v1/agent-scanner/agents/enroll`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'Syntax Fixture Agent',
    environment: 'lab',
    // Deliberately awkward scope: Windows backslashes and a UNC-style admin share,
    // which must survive sanitisation and still produce parseable artifacts.
    policy: {
      enabled: true,
      intervalSeconds: 45,
      allowedTargets: ['api.example.com:443', 'ssh://build.internal:22'],
      allowedPaths: ['C:\\ProgramData\\App\\conf', '/etc/nginx', '\\\\fileserver\\share'],
      scanTypes: ['tls', 'certificates', 'configs'],
      alertThreshold: 'moderate',
    },
    metadata: { role: 'collector', source: 'syntax-fixture' },
  }),
}).then((r) => r.json())

const agentId = enroll.data.enrollment.agentId
const agentToken = enroll.data.enrollment.agentToken
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qguard-syntax-'))

console.log('\n=== Installer artifact syntax validation ===\n')

for (const platform of ['linux', 'windows', 'docker', 'kubernetes', 'powershell', 'cloud-init']) {
  const result = await fetch(`${BASE}/api/v1/agent-installer/package`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId, platform, token: agentToken }),
  }).then((r) => r.json())

  const pkg = result?.data
  if (!pkg) { check(`${platform} generated`, false, JSON.stringify(result).slice(0, 140)); continue }

  const file = path.join(dir, pkg.filename)
  fs.writeFileSync(file, pkg.content, 'utf8')

  if (platform === 'linux') {
    try {
      await run('bash', ['-n', file])
      check('linux installer parses (bash -n)', true)
    } catch (error) {
      check('linux installer parses (bash -n)', false, String(error.stderr || error).slice(0, 300))
    }
  }

  if (platform === 'windows' || platform === 'powershell') {
    const script = `$errors = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('${file.replace(/\\/g, '\\\\')}', [ref]$null, [ref]$errors); if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Output $_.Message }; exit 1 } else { Write-Output 'OK' }`
    try {
      const { stdout } = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', script])
      check(`${platform} installer parses (PowerShell parser)`, stdout.includes('OK'), stdout.slice(0, 300))
    } catch (error) {
      check(`${platform} installer parses (PowerShell parser)`, false, String(error.stdout || error.stderr || error).slice(0, 400))
    }
  }

  if (platform === 'docker' || platform === 'kubernetes' || platform === 'cloud-init') {
    // Parse with the YAML implementation already vendored in this repo.
    try {
      const yaml = await import('js-yaml')
      const docs = yaml.loadAll(pkg.content).map((value) => ({ toJS: () => value, errors: [] }))
      const errors = docs.flatMap((doc) => doc.errors)
      check(`${platform} artifact parses (YAML)`, errors.length === 0, errors.map((e) => e.message).join('; ').slice(0, 300))

      if (platform === 'kubernetes') {
        const kinds = docs.map((doc) => doc.toJS()?.kind).filter(Boolean)
        check('k8s has Namespace/ServiceAccount/Secret/ConfigMap/Deployment',
          ['Namespace', 'ServiceAccount', 'Secret', 'ConfigMap', 'Deployment'].every((k) => kinds.includes(k)),
          kinds.join(','))
      }
      if (platform === 'docker') {
        const compose = docs[0].toJS()
        check('compose defines the qguard-agent service', Boolean(compose?.services?.['qguard-agent']))
        check('compose passes the runtime digest to the container',
          String(compose?.services?.['qguard-agent']?.environment?.QGUARD_RUNTIME_SHA256 || '').length === 64)
      }
      if (platform === 'cloud-init') {
        const config = docs[0].toJS()
        const embedded = config?.write_files?.[0]?.content || ''
        check('cloud-init embeds the bash installer', embedded.startsWith('#!/usr/bin/env bash'))
        // The embedded script must itself still parse once cloud-init writes it out.
        const embeddedFile = path.join(dir, 'cloud-init-embedded.sh')
        fs.writeFileSync(embeddedFile, embedded, 'utf8')
        try {
          await run('bash', ['-n', embeddedFile])
          check('cloud-init embedded script parses (bash -n)', true)
        } catch (error) {
          check('cloud-init embedded script parses (bash -n)', false, String(error.stderr || error).slice(0, 300))
        }
      }
    } catch (error) {
      check(`${platform} artifact parses (YAML)`, false, String(error).slice(0, 200))
    }
  }

  // Scope values with backslashes must survive into the artifact intact.
  if (platform === 'linux') {
    check('linux config keeps Windows-style path', pkg.content.includes('C:\\ProgramData\\App\\conf'))
  }
  if (platform === 'kubernetes') {
    const doc = (await import('js-yaml')).loadAll(pkg.content).find((d) => d?.kind === 'ConfigMap')
    check('k8s ConfigMap preserves backslash paths', String(doc?.data?.QGUARD_ALLOWED_PATHS || '').includes('C:\\ProgramData\\App\\conf'),
      String(doc?.data?.QGUARD_ALLOWED_PATHS))
  }
}

await fetch(`${BASE}/api/v1/agent-scanner/agents/${agentId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } })
fs.rmSync(dir, { recursive: true, force: true })

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail === 0 ? 0 : 1)
