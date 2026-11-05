import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createHash, randomUUID } from 'node:crypto'
import { spawn } from 'node:child_process'

export interface HostLock { release(): Promise<void> }
export async function acquireResourceLock(file: string, owner: { agentId: string; role: string }): Promise<HostLock | null> {
  const canonical = await fs.realpath(file)
  // Adjacent to the actual file, so containers or symlink aliases sharing that
  // file also share its lock, even when their installation directories differ.
  const name = createHash('sha256').update(path.basename(canonical)).digest('hex')
  return acquireHostLock(path.join(path.dirname(canonical), '.qguard-coordination'), name, owner)
}
export function coordinationDirectory(env: NodeJS.ProcessEnv = process.env): string {
  if (env.QGUARD_COORDINATION_DIR) return path.resolve(env.QGUARD_COORDINATION_DIR)
  return process.platform === 'win32'
    ? path.join(env.ProgramData || 'C:\\ProgramData', 'QGuardHelix', 'coordination')
    : path.join('/var/lib/qguard-agent', 'coordination')
}

/** Atomic host-wide mutex. Never evict a live owner because its work took too long. */
export async function acquireHostLock(directory: string, name: string, owner: { agentId: string; role: string }): Promise<HostLock | null> {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 })
  if ((await fs.lstat(directory)).isSymbolicLink()) throw new Error('Coordination directory must not be a symbolic link')
  const file = path.join(directory, `${name.replace(/[^A-Za-z0-9_-]/g, '_')}.lock`)
  const token = randomUUID()
  const value = JSON.stringify({ ...owner, token, pid: process.pid, hostname: os.hostname(), startedAt: new Date().toISOString() })
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const handle = await fs.open(file, 'wx', 0o600)
      try { await handle.writeFile(value) } finally { await handle.close() }
      return { release: async () => {
        try {
          const current = JSON.parse(await fs.readFile(file, 'utf8'))
          if (current.token === token) await fs.unlink(file)
        } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
      } }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      // A partially written lock or inaccessible owner is busy, never proof of
      // abandonment. Recover only a confirmed-dead process on this same host.
      const raw = await fs.readFile(file, 'utf8').catch(() => '')
      let held: { pid?: number; hostname?: string }
      try { held = JSON.parse(raw) } catch { return null }
      if (held.hostname !== os.hostname() || !Number.isInteger(held.pid) || Number(held.pid) <= 0) return null
      try { process.kill(held.pid!, 0); return null } catch (failure) {
        if ((failure as NodeJS.ErrnoException).code !== 'ESRCH') return null
      }
      // Serialize stale recovery and re-read UNDER that guard: two contenders
      // must not both unlink a dead owner's file after a new owner replaced it.
      let recovery
      try { recovery = await fs.open(`${file}.recover`, 'wx', 0o600) } catch (failure) {
        if ((failure as NodeJS.ErrnoException).code === 'EEXIST') return null
        throw failure
      }
      try {
        await recovery.writeFile(value)
        const latest = await fs.readFile(file, 'utf8').catch(() => '')
        if (latest !== raw) continue
        // The current file is still precisely the confirmed-dead owner.
        await fs.unlink(file)
      } finally {
        await recovery.close()
        await fs.unlink(`${file}.recover`)
      }
    }
  }
  return null
}

/** Readers see a complete old or new file; a stale rollback never overwrites newer work. */
export async function replaceConfigFile(file: string, content: string, expected: string | null): Promise<void> {
  const stat = await fs.lstat(file)
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Configuration replacement requires a regular file')
  const current = await fs.readFile(file, 'utf8')
  if (expected !== null && current !== expected) throw new Error('Configuration changed since it was inspected; replacement withheld')
  const temporary = path.join(path.dirname(file), `.${path.basename(file)}.qguard-${process.pid}-${randomUUID()}.tmp`)
  try {
    if (process.platform === 'win32') {
      // File.Replace preserves the target DACL. Protect the empty staging file
      // before writing any content, including configurations containing secrets.
      const script = `$ErrorActionPreference='Stop'; $temp=$env:QGUARD_REPLACE_TEMP; $target=$env:QGUARD_REPLACE_TARGET; $held=$false; $mutex=New-Object Threading.Mutex($false,'Global\\QGuardHelixConfigMutation'); try { try { $held=$mutex.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $held=$true }; if(-not $held){throw 'Another configuration write is active'}; $sha=[Security.Cryptography.SHA256]::Create(); $stream=[IO.File]::OpenRead($target); try { $hash=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLower() } finally { $stream.Dispose(); $sha.Dispose() }; if($hash -ne $env:QGUARD_REPLACE_EXPECTED){throw 'Configuration changed; replacement withheld'}; [IO.File]::Open($temp,[IO.FileMode]::CreateNew).Dispose(); [IO.File]::SetAccessControl($temp,[IO.File]::GetAccessControl($target)); [IO.File]::WriteAllText($temp,[Console]::In.ReadToEnd(),(New-Object Text.UTF8Encoding($false))); [IO.File]::Replace($temp,$target,[NullString]::Value,$false) } finally { if($held){$mutex.ReleaseMutex()}; $mutex.Dispose() }`
      await new Promise<void>((resolve, reject) => {
        const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
          windowsHide: true, timeout: 20_000, env: { ...process.env, QGUARD_REPLACE_TEMP: temporary, QGUARD_REPLACE_TARGET: file, QGUARD_REPLACE_EXPECTED: createHash('sha256').update(current).digest('hex') },
          stdio: ['pipe', 'ignore', 'pipe'],
        })
        let error = ''
        child.stderr.on('data', (chunk) => { error = (error + chunk.toString()).slice(-2000) })
        child.on('error', reject)
        child.on('close', (code) => code === 0 ? resolve() : reject(new Error(`Atomic configuration replacement failed: ${error}`)))
        child.stdin.on('error', () => undefined)
        child.stdin.end(content)
      })
      return
    }
    await fs.writeFile(temporary, content, { encoding: 'utf8', mode: stat.mode & 0o777, flag: 'wx' })
    await fs.chmod(temporary, stat.mode & 0o777)
    await fs.chown(temporary, stat.uid, stat.gid)
    // Same-directory rename is atomic. All agent writers hold the shared mutex.
    if (expected !== null && await fs.readFile(file, 'utf8') !== expected) throw new Error('Configuration changed during preparation; replacement withheld')
    await fs.rename(temporary, file)
  } finally { await fs.rm(temporary, { force: true }) }
}
