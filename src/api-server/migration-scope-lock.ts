import type { Request, Response } from 'express'

const writes = new Map<string, Promise<void>>()

/** Serialize queue, proposal and handoff writes for the signed-in workspace. */
export function serializeMigrationScope<T extends Request & { user?: { id: string } }>(handler: (req: T, res: Response) => Promise<unknown>) {
  return async (req: T, res: Response) => {
    const owner = req.user!.id
    const prior = writes.get(owner)
    let release!: () => void
    const next = new Promise<void>((resolve) => { release = resolve })
    writes.set(owner, next)
    try {
      await prior
      if (!res.destroyed) return await handler(req, res)
    } catch (error) {
      console.error('Migration scope write failed:', error)
      if (!res.headersSent) return res.status(503).json({ error: { message: 'The migration scope could not be verified. Refresh and retry.' } })
    } finally {
      release()
      if (writes.get(owner) === next) writes.delete(owner)
    }
  }
}
