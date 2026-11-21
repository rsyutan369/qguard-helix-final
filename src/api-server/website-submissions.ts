import { getServiceClient } from '@/lib/supabase-server'

export interface WebsiteSubmission {
  kind: 'demo' | 'pqc-checklist'
  source: 'navigation' | 'footer' | 'homepage' | 'checklist'
  name: string
  email: string
  organization: string
  details: Record<string, string | boolean>
  email_status: 'pending' | 'not_configured' | 'not_applicable'
}

export async function recordWebsiteSubmission(submission: WebsiteSubmission): Promise<string> {
  const client = getServiceClient()
  if (!client) throw new Error('Submission storage is unavailable')
  const { data, error } = await client.from('website_submissions').insert(submission).select('id').single()
  if (error || !data?.id) throw new Error('Submission could not be stored')
  return data.id
}

export async function updateDemoEmailStatus(id: string, status: 'accepted' | 'failed'): Promise<void> {
  const client = getServiceClient()
  if (!client) throw new Error('Submission storage is unavailable')
  const { error } = await client.from('website_submissions').update({ email_status: status }).eq('id', id).eq('kind', 'demo')
  if (error) throw new Error('Email status could not be stored')
}
