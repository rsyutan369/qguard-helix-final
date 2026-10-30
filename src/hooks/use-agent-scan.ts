import { useCallback, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/contexts/auth-context'
import type { AgentCommand, ConnectionState } from '@/lib/agent-installer/agent-release'
import { scanWorkflowPath } from '@/lib/agent-installer/scan-tracking'

/** All agent scan entry points queue the same command and open its durable receipt. */
export function useAgentScan() {
  const { session } = useAuth()
  const token = session?.access_token
  const navigate = useNavigate()
  const pending = useRef(false)
  const [scanning, setScanning] = useState(false)
  const requestScan = useCallback(async (agentId: string) => {
    type Receipt = { command: AgentCommand; delivery: string; connectionState: ConnectionState }
    if (!token) return { ok: false, message: 'Sign in to request a scan.', data: undefined as Receipt | undefined }
    if (pending.current) return { ok: false, message: 'A scan request is already being submitted.', data: undefined as Receipt | undefined }
    pending.current = true
    setScanning(true)
    try {
      const response = await fetch(`/api/v1/agent-installer/agents/${encodeURIComponent(agentId)}/scan`, {
        method: 'POST', headers: { Authorization: `Bearer ${token}` },
      })
      const json = await response.json()
      if (!response.ok) throw new Error(json?.error?.message || 'Unable to queue the scan.')
      const data = json.data as Receipt
      if (!data?.command?.id) throw new Error('The server did not return a scan command receipt.')
      navigate(scanWorkflowPath(agentId, data.command.id))
      return { ok: true, data, message: data.delivery }
    } catch (error) {
      return { ok: false, message: error instanceof Error ? error.message : 'Unable to queue the scan.', data: undefined as Receipt | undefined }
    } finally {
      pending.current = false
      setScanning(false)
    }
  }, [navigate, token])
  return { requestScan, scanning }
}
