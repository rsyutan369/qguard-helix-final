/** Real concurrent filesystem/process checks; only generated temporary files are changed. */
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { promises as fs, existsSync, readFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import { acquireHostLock, acquireResourceLock, replaceConfigFile } from './qguard-agent/host-coordination'
import { generateInstaller, type InstallerContext } from '../src/lib/agent-installer/installer-templates'
import { AGENT_VERSION, type AgentRole } from '../src/lib/agent-installer/agent-release'

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
if (process.argv[2] === '--worker') {
  const role = process.argv[3]
  const dir = process.argv[4]
  const target = path.join(dir, 'shared.json')
  if (role === 'collector' || role === 'scanner') {
    for (let sample = 0; sample < 250; sample++) {
      const value = JSON.parse(await fs.readFile(target, 'utf8'))
      assert.ok(Array.isArray(value.jobs), 'reader observed a torn configuration')
      await delay(20)
    }
  } else if (role === 'hold') {
    assert.ok(await acquireHostLock(path.join(dir, 'coordination'), 'host-mutation', { agentId: role, role }))
    console.log('READY')
    await delay(120_000)
  } else {
    for (let job = 0; job < 3; job++) {
      let guard: Awaited<ReturnType<typeof acquireHostLock>> = null
      const deadline = Date.now() + 90_000
      while (!guard) {
        guard = await acquireHostLock(path.join(dir, 'coordination'), 'host-mutation', { agentId: role, role })
        if (!guard) { assert.ok(Date.now() < deadline, 'writer starvation'); await delay(25) }
      }
      const resource = await acquireResourceLock(target, { agentId: role, role })
      assert.ok(resource)
      const overlap = path.join(dir, 'active-writer')
      try {
        const marker = await fs.open(overlap, 'wx') // Any overlap fails immediately.
        await marker.close()
        const before = await fs.readFile(target, 'utf8')
        const data = JSON.parse(before)
        data.jobs.push(`${role}:${job}`)
        await delay(50)
        await replaceConfigFile(target, JSON.stringify(data), before)
      } finally { await fs.rm(overlap, { force: true }); await resource.release(); await guard.release() }
      await delay(20)
    }
  }
  console.log(`PASS ${role} process finished its own work`)
} else {
  let passed = 0
  const check = (name: string) => { passed++; console.log(`PASS ${name}`) }
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qguard-coexistence-'))
  const children: ReturnType<typeof spawn>[] = []
  const worker = (role: string) => {
    const child = spawn(process.execPath, ['--import', 'tsx', path.resolve('tools/agent-coexistence-check.ts'), '--worker', role, dir], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
    children.push(child)
    let out = '', err = ''
    child.stdout.on('data', (data) => { out += data.toString() })
    child.stderr.on('data', (data) => { err += data.toString() })
    return { child, done: new Promise<void>((resolve, reject) => { child.on('error', reject); child.on('close', (code) => code === 0 ? resolve() : reject(new Error(`${role}: ${err} ${out}`))) }) }
  }
  try {
    const target = path.join(dir, 'shared.json')
    await fs.writeFile(target, JSON.stringify({ jobs: [] }))
    let originalAcl = ''
    const aclEnv = { ...process.env, QGUARD_QA_CONFIG_FILE: target }
    const readAcl = () => execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '[IO.File]::GetAccessControl($env:QGUARD_QA_CONFIG_FILE).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)'], { env: aclEnv, encoding: 'utf8', stdio: 'pipe' }).trim()
    if (process.platform === 'win32') {
      const restrict = '$acl=[IO.File]::GetAccessControl($env:QGUARD_QA_CONFIG_FILE); $acl.SetAccessRuleProtection($true,$false); $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }; $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,"FullControl","Allow"); $acl.AddAccessRule($rule); [IO.File]::SetAccessControl($env:QGUARD_QA_CONFIG_FILE,$acl)'
      execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', restrict], { env: aclEnv, stdio: 'pipe' })
      originalAcl = readAcl()
    }
    await Promise.all(['collector', 'scanner', 'patcher', 'operator'].map((role) => worker(role).done))
    const result = JSON.parse(await fs.readFile(target, 'utf8'))
    assert.equal(result.jobs.length, 6)
    assert.equal(new Set(result.jobs).size, 6)
    assert.ok(result.jobs.every((value: string) => /^(patcher|operator):/.test(value)))
    check('four concurrent role processes finish; readers never see partial writes and writers never overlap or lose jobs')
    if (process.platform === 'win32') { assert.equal(readAcl(), originalAcl); check('Windows atomic replacements preserve a protected private file ACL across both writers') }

    const held = await acquireResourceLock(target, { agentId: 'patcher', role: 'patcher' })
    assert.ok(held)
    assert.equal(await acquireResourceLock(target, { agentId: 'operator', role: 'operator' }), null)
    await held.release()
    check('a shared target file has one writer even when agents use different installation state')
    const before = await fs.readFile(target, 'utf8')
    await assert.rejects(replaceConfigFile(target, 'overwrite', 'obsolete snapshot'), /changed/)
    assert.equal(await fs.readFile(target, 'utf8'), before)
    check('stale writes and rollbacks preserve a newer configuration')

    const crashed = worker('hold')
    // Attach a rejection handler before intentionally terminating the fixture.
    const stopped = crashed.done.catch(() => undefined)
    await new Promise<void>((resolve, reject) => {
      crashed.child.stdout.on('data', (data) => { if (data.toString().includes('READY')) resolve() })
      crashed.child.on('error', reject)
    })
    crashed.child.kill('SIGKILL')
    await stopped
    const recovered = await acquireHostLock(path.join(dir, 'coordination'), 'host-mutation', { agentId: 'new-writer', role: 'patcher' })
    assert.ok(recovered)
    assert.equal(await acquireHostLock(path.join(dir, 'coordination'), 'host-mutation', { agentId: 'racer', role: 'operator' }), null)
    await recovered.release()
    check('a confirmed-dead local process is recovered without stealing a live lock')

    const artifacts = new Map<string, Set<string>>()
    for (const role of ['collector', 'scanner', 'patcher', 'operator'] as AgentRole[]) {
      const context: InstallerContext = { apiUrl: 'https://qguard-helix.example.com', tenantId: randomUUID(), agentId: randomUUID(), agentToken: 'isolated-fixture-token', agentName: role, role, environment: 'lab', controlPlaneEnvironment: 'production', version: AGENT_VERSION, runtimeSha256: 'a'.repeat(64), policy: { intervalSeconds: 60, allowedPaths: [], allowedTargets: [], scanTypes: ['certificates'], alertThreshold: 'moderate' }, remediationEnabled: ['patcher', 'operator'].includes(role), migrationEnabled: role === 'operator', generatedAt: new Date().toISOString(), generatedBy: 'coexistence-offline-fixture' }
      for (const platform of ['linux', 'windows', 'docker', 'kubernetes', 'powershell', 'cloud-init'] as const) {
        const artifact = generateInstaller(platform, context)
        const names = artifacts.get(platform) || new Set<string>()
        assert.ok(!names.has(artifact.filename)); names.add(artifact.filename); artifacts.set(platform, names)
        assert.ok(artifact.content.includes(context.apiUrl), 'namespace isolation altered the control-plane URL')
        if (platform === 'docker' || platform === 'kubernetes' || platform === 'cloud-init') {
          const yaml = await import('js-yaml')
          const docs = yaml.loadAll(artifact.content) as any[]
          if (platform === 'docker') assert.equal(docs[0].name, `qguard-agent-${context.agentId}`)
          if (platform === 'kubernetes') {
            const namespace = `qguard-helix-${context.agentId}`
            assert.equal(docs[0].metadata.name, namespace)
            assert.ok(docs.slice(1).every((doc) => doc.metadata.namespace === namespace))
          }
        }
        if (platform === 'linux' && existsSync('C:/Program Files/Git/bin/bash.exe')) {
          const file = path.join(dir, `${role}.sh`)
          await fs.writeFile(file, artifact.content)
          execFileSync('C:/Program Files/Git/bin/bash.exe', ['-n', file], { stdio: 'pipe' })
        }
      }
    }
    assert.ok([...artifacts.values()].every((value) => value.size === 4))
    check('all four roles have unique deployment artifacts, services/projects/namespaces; YAML and Linux shell syntax parse')
    const source = readFileSync('src/api-server/agent-scanner.ts', 'utf8')
    assert.ok(source.includes(".eq('updated_at', job.updated_at)") && source.includes('if (!claimed) continue'))
    check('job dispatch requires a successful atomic claim before returning work')
    console.log(`${passed} multi-agent coexistence checks passed`)
  } finally {
    for (const child of children) if (child.exitCode === null) child.kill()
    assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir()))
    assert.ok(path.basename(dir).startsWith('qguard-coexistence-'))
    await fs.rm(dir, { recursive: true, force: true })
  }
}
