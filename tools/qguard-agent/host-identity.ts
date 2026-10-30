import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { promisify } from 'node:util'

const run = promisify(execFile)
let identity: Promise<Awaited<ReturnType<typeof collectIdentity>>> | null = null

export function classifyHostIdentity(manufacturer: string | null, model: string | null) {
  const value = `${manufacturer || ''} ${model || ''}`
  const detected = /vmware|virtualbox|virtual machine|qemu|\bkvm\b|xen|parallels|openstack|nutanix|amazon ec2|google compute/i.test(value)
  return { manufacturer, model, virtualization: { detected: detected ? true : null, basis: manufacturer || model ? 'Reported system manufacturer and model' : 'System identity unavailable' } }
}

async function collectIdentity() {
  let manufacturer: string | null = null
  let model: string | null = null
  try {
    if (process.platform === 'win32') {
      const result = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model | ConvertTo-Json -Compress'], { timeout: 4000, windowsHide: true, maxBuffer: 16_384 })
      const parsed = JSON.parse(result.stdout)
      manufacturer = typeof parsed.Manufacturer === 'string' ? parsed.Manufacturer.trim().slice(0, 200) : null
      model = typeof parsed.Model === 'string' ? parsed.Model.trim().slice(0, 200) : null
    } else if (process.platform === 'linux') {
      const rows = await Promise.allSettled([readFile('/sys/class/dmi/id/sys_vendor', 'utf8'), readFile('/sys/class/dmi/id/product_name', 'utf8')])
      manufacturer = rows[0].status === 'fulfilled' ? rows[0].value.trim().slice(0, 200) : null
      model = rows[1].status === 'fulfilled' ? rows[1].value.trim().slice(0, 200) : null
    }
  } catch { /* Hardware identity is optional. Failure never blocks a scan or invents a platform. */ }
  return { ...classifyHostIdentity(manufacturer, model), kubernetes: Boolean(process.env.KUBERNETES_SERVICE_HOST) }
}

/** Cached once per process; CIM is bounded and no instance-metadata endpoint is queried. */
export const collectHostIdentity = () => (identity ??= collectIdentity())
