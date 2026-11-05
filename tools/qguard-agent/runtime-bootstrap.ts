import { appendFileSync, mkdirSync, readFileSync, renameSync, rmSync, statSync } from 'node:fs'
import path from 'node:path'
import { format } from 'node:util'

/** An explicitly selected configuration must never fall through to another agent. */
export function loadAgentConfig(
  argv = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env,
  platform = process.platform,
  cwd = process.cwd(),
): string | null {
  const flag = argv.indexOf('--config')
  const explicit = flag >= 0 ? argv[flag + 1] : env.QGUARD_CONFIG
  if (flag >= 0 && (!explicit || explicit.startsWith('--'))) throw new Error('--config requires an absolute configuration file path')
  if (explicit && !path.isAbsolute(explicit)) throw new Error('Agent configuration path must be absolute')
  const candidates = explicit ? [explicit] : platform === 'win32'
    ? [path.join(env.ProgramData || 'C:\\ProgramData', 'QGuardHelix', 'Agent', 'agent.env'), path.join(cwd, 'qguard-agent.env')]
    : ['/etc/qguard-agent/agent.env', '/opt/qguard-agent/agent.env', path.join(cwd, 'qguard-agent.env')]
  for (const candidate of candidates) {
    let contents: string
    try {
      contents = readFileSync(candidate, 'utf8')
    } catch (error) {
      if (explicit) throw new Error(`Cannot read selected agent configuration: ${candidate}`, { cause: error })
      continue
    }
    for (const raw of contents.split(/\r?\n/)) {
      const line = raw.trim()
      if (!line || line.startsWith('#')) continue
      const separator = line.indexOf('=')
      if (separator <= 0) continue
      const key = line.slice(0, separator).trim()
      const value = line.slice(separator + 1).trim().replace(/^["']|["']$/g, '')
      if (key.startsWith('QGUARD_') && !env[key]) env[key] = value
    }
    return candidate
  }
  return null
}

/** Scheduled tasks have no terminal. Keep bounded, token-redacted startup errors. */
export function configureAgentLog(env: NodeJS.ProcessEnv = process.env): void {
  const file = env.QGUARD_LOG_FILE
  if (!file) return
  if (!path.isAbsolute(file)) throw new Error('QGUARD_LOG_FILE must be an absolute path')
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
  const limit = 2 * 1024 * 1024
  const redact = (value: string) => env.QGUARD_AGENT_TOKEN ? value.split(env.QGUARD_AGENT_TOKEN).join('[REDACTED]') : value
  const append = (level: string, args: unknown[]) => {
    const line = `${new Date().toISOString()} ${level} ${redact(format(...args)).slice(0, 16_384)}\n`
    try {
      if (statSync(file).size + Buffer.byteLength(line) > limit) {
        rmSync(`${file}.1`, { force: true })
        renameSync(file, `${file}.1`)
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    }
    appendFileSync(file, line, { mode: 0o600 })
  }
  // Verify writability before the service enters its watch loop.
  append('INFO', [`Agent process ${process.pid} starting`])
  for (const level of ['log', 'info', 'warn', 'error'] as const) {
    const original = console[level].bind(console)
    console[level] = (...args: unknown[]) => {
      const safe = redact(format(...args))
      original(safe)
      try { append(level.toUpperCase(), [safe]) } catch { /* A later disk failure must not stop heartbeats. */ }
    }
  }
}
