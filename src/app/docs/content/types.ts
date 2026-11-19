export type Category = 'start' | 'dashboard' | 'readiness' | 'inventory' | 'migration' | 'sandbox' | 'agility' | 'cryptography' | 'intelligence' | 'messaging' | 'administration' | 'developers' | 'support'

// "implemented" means checked against the source; it never implies a live test.
export type Implementation = 'implemented' | 'partial' | 'ui-only' | 'planned' | 'unavailable'

export type DocSection = {
  id: string
  title: string
  body?: string[]
  bullets?: string[]
  steps?: string[]
  note?: string
  warning?: string
  table?: { headers: string[]; rows: string[][] }
  flow?: string[]
  code?: { language: string; value: string }
  questions?: { question: string; answer: string }[]
}

export type DocArticle = {
  id: string
  category: Category
  title: string
  summary: string
  sections: DocSection[]
  keywords?: string[]
  routes?: string[]
  sources?: string[] // Repository paths for the coverage checker and maintainers. Never include credentials or private URLs.
  status?: Implementation
  product?: string
  updated?: string
  related?: string[]
  aliases?: string[]
  tutorial?: { time: string; permissions: string; prerequisites: string[]; steps: string[]; result: string; security: string; mistakes: string; troubleshoot: string }
}
