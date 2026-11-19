import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { setTimeout as delay } from 'node:timers/promises'
import type { Request, Response } from 'express'
import { streamLiveSnapshot } from '../src/api-server/live-snapshot-stream'

async function main() {
  const request = Object.assign(new EventEmitter(), { headers: {} })
  const frames: Array<{ name: string; data: Record<string, unknown> }> = []
  const headers = new Map<string, string>()
  const response = {
    status(code: number) { assert.equal(code, 200); return this },
    setHeader(name: string, value: string) { headers.set(name, value) },
    write(frame: string) {
      const [event, data] = frame.split('\n')
      if (!event.startsWith('event: ')) return
      frames.push({ name: event.slice(7), data: JSON.parse(data.slice(6)) })
    },
  }
  let checks = 0
  let progress = 25
  let available = true
  const waitFor = async (name: string, predicate: (data: Record<string, unknown>) => boolean = () => true) => {
    for (let attempt = 0; attempt < 100; attempt++) {
      const match = frames.find((frame) => frame.name === name && predicate(frame.data))
      if (match) return match.data
      await delay(10)
    }
    assert.fail(`Timed out waiting for ${name}`)
  }

  streamLiveSnapshot(request as unknown as Request, response as unknown as Response, {
    event: 'migration-plan',
    intervalMs: 15,
    heartbeatMs: 35,
    build: async () => {
      if (!available) throw new Error('Evidence source temporarily unavailable')
      return { progress, generatedAt: String(++checks) }
    },
  })

  try {
    assert.equal(headers.get('Content-Type'), 'text/event-stream')
    const initial = await waitFor('migration-plan', (data) => data.progress === 25)
    const unchanged = await waitFor('migration-plan-unchanged')
    assert.equal(unchanged.fingerprint, initial.fingerprint)
    progress = 60
    const updated = await waitFor('migration-plan', (data) => data.progress === 60)
    assert.notEqual(updated.fingerprint, initial.fingerprint)
    available = false
    await waitFor('migration-plan-error')
    available = true
    await waitFor('migration-plan-unchanged', (data) => data.fingerprint === updated.fingerprint)
  } finally {
    request.emit('close')
  }
  const previousChecks = checks
  await delay(80)
  assert.equal(checks, previousChecks, 'closing the response stops snapshot work')
  console.log('Planner SSE contract passed: initial snapshot, unchanged check, updated evidence, error, recovery, and cleanup.')
}

void main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
