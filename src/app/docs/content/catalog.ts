import { Activity, BookOpen, Box, Braces, CircleHelp, Compass, Database, Fingerprint, LayoutDashboard, MessageSquare, Route, Settings2, Workflow } from 'lucide-react'
import { administrationArticles } from './administration'
import { discoveryArticles } from './discovery'
import { messagingArticles } from './messaging'
import { migrationArticles } from './migration'
import { securityArticles } from './security'
import { trustArticles } from './trust'
import type { Category, DocArticle, DocSection } from './types'
import { welcome } from './welcome'

export const categories = [
  { id: 'start', title: 'Getting started', icon: Compass },
  { id: 'dashboard', title: 'Platform dashboard', icon: LayoutDashboard },
  { id: 'readiness', title: 'Quantum readiness', icon: Activity },
  { id: 'inventory', title: 'Discovery & CBOM', icon: Database },
  { id: 'migration', title: 'Migration planner', icon: Route },
  { id: 'sandbox', title: 'Migration sandbox', icon: Box },
  { id: 'agility', title: 'Cryptographic agility', icon: Workflow },
  { id: 'cryptography', title: 'PQC & cryptographic tools', icon: Fingerprint },
  { id: 'intelligence', title: 'Security intelligence', icon: BookOpen },
  { id: 'messaging', title: 'QGuard Messaging', icon: MessageSquare },
  { id: 'administration', title: 'Administration & billing', icon: Settings2 },
  { id: 'developers', title: 'API & developer reference', icon: Braces },
  { id: 'support', title: 'Troubleshooting & FAQ', icon: CircleHelp },
] as const satisfies ReadonlyArray<{ id: Category; title: string; icon: typeof Compass }>

const content = [welcome, ...administrationArticles, ...discoveryArticles, ...migrationArticles, ...securityArticles, ...trustArticles, ...messagingArticles]

export const articles = categories.flatMap(({ id }) => content.filter(article => article.category === id))
export const articlesById = new Map(articles.map(article => [article.id, article]))
export const aliases = new Map(articles.flatMap(article => (article.aliases ?? []).map(alias => [alias, article.id] as const)))
export const tutorials = articles.filter(article => article.tutorial)

export const articleUrl = (id: string, section?: string) =>
  (id === 'welcome' ? '/docs' : '/docs/' + id) + (section ? '#' + section : '')

export const sectionsOf = (article: DocArticle): DocSection[] =>
  article.tutorial ? [{ id: 'walkthrough', title: 'Interactive walkthrough' }, ...article.sections] : article.sections

export function readingTime(article: DocArticle) {
  return Math.max(1, Math.ceil(readableText(article).trim().split(/\s+/).length / 210))
}

function sectionText(section: DocSection) {
  return [...(section.body ?? []), ...(section.bullets ?? []), ...(section.steps ?? []), section.note, section.warning,
    ...(section.flow ?? []), ...(section.table?.headers ?? []), ...(section.table?.rows.flat() ?? []), section.code?.value,
    ...(section.questions ?? []).flatMap(({ question, answer }) => [question, answer])].filter(Boolean).join(' ')
}

function walkthroughText(article: DocArticle) {
  const t = article.tutorial
  return t ? [t.time, t.permissions, ...t.prerequisites, ...t.steps, t.result, t.security, t.mistakes, t.troubleshoot].join(' ') : ''
}

function readableText(article: DocArticle) {
  return [article.title, article.summary, walkthroughText(article), ...article.sections.map(s => s.title + ' ' + sectionText(s))].join(' ')
}

const index = articles.flatMap(article => [
  { article, section: undefined as string | undefined, title: article.title, excerpt: article.summary, text: [
    article.summary, article.category, categories.find(c => c.id === article.category)?.title, article.product,
    ...(article.keywords ?? []), ...(article.routes ?? []),
  ].filter(Boolean).join(' ') },
  ...article.sections.map(s => ({ article, section: s.id, title: s.title, excerpt: s.body?.[0] ?? s.steps?.[0] ?? s.bullets?.[0] ?? s.note ?? s.questions?.[0]?.question ?? article.summary, text: sectionText(s) })),
  ...(article.tutorial ? [{ article, section: 'walkthrough', title: 'Interactive walkthrough', excerpt: article.tutorial.steps[0], text: walkthroughText(article) }] : []),
])

const normalize = (s: string) => s.toLocaleLowerCase('en').normalize('NFKD').replace(/[^a-z0-9]+/g, ' ').trim()
const searchIndex = index.map(row => ({ row, title: normalize(row.title), parent: normalize(row.article.title), text: normalize(row.text) }))

export function searchDocs(query: string) {
  const phrase = normalize(query)
  if (!phrase) return []
  const terms = [...new Set(phrase.split(' '))]
  return searchIndex.flatMap(({ row, title, parent, text }) => {
    if (!terms.every(term => title.includes(term) || parent.includes(term) || text.includes(term))) return []
    const score = terms.reduce((sum, term) => sum + (title.includes(term) ? 8 : parent.includes(term) ? 3 : 1), 0)
      + (title === phrase ? 28 : title.includes(phrase) ? 12 : 0) + (row.section ? 0 : 3)
    return [{ ...row, score }]
  }).sort((a, b) => b.score - a.score).slice(0, 18)
}

export function articleMarkdown(article: DocArticle) {
  const text = ['# ' + article.title, article.summary]
  const numbered = (items: string[]) => items.map((s, i) => (i + 1) + '. ' + s).join('\n')
  const bulletList = (items: string[]) => items.map(s => '- ' + s).join('\n')
  const t = article.tutorial
  if (t) text.push('## Walkthrough', 'Estimated time: ' + t.time, 'Permissions: ' + t.permissions, '### Prerequisites', bulletList(t.prerequisites), '### Steps', numbered(t.steps), 'Expected result: ' + t.result, 'Security: ' + t.security, 'Common mistakes: ' + t.mistakes, 'Troubleshooting: ' + t.troubleshoot)
  for (const s of article.sections) {
    text.push('## ' + s.title, ...(s.body ?? []))
    if (s.steps) text.push(numbered(s.steps))
    if (s.bullets) text.push(bulletList(s.bullets))
    if (s.flow) text.push(s.flow.join(' → '))
    if (s.table) {
      const row = (cells: string[]) => '| ' + cells.map(cell => cell.replaceAll('|', '\\|').replace(/\r?\n/g, ' ')).join(' | ') + ' |'
      text.push([row(s.table.headers), row(s.table.headers.map(() => '---')), ...s.table.rows.map(row)].join('\n'))
    }
    if (s.note) text.push('> Note: ' + s.note)
    if (s.warning) text.push('> Important: ' + s.warning)
    if (s.code) text.push(['```' + s.code.language, s.code.value, '```'].join('\n'))
    if (s.questions) text.push(...s.questions.flatMap(q => ['### ' + q.question, q.answer]))
  }
  if (article.routes?.length) text.push('## In the application', bulletList(article.routes))
  return text.join('\n\n') + '\n'
}
