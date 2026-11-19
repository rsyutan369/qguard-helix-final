/** Run with npx tsx tools/docs-content-check.ts from the repository root. */
import { readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { matchPath } from 'react-router-dom'
import ts from 'typescript'
import { aliases, articles, articlesById, articleUrl, sectionsOf } from '../src/app/docs/content/catalog'
import { visuals, type DocVisual } from '../src/app/docs/content/visuals'
import { walkthroughScreens } from '../src/app/docs/content/walkthrough-screens'
import type { DocArticle } from '../src/app/docs/content/types'

const root = path.resolve(import.meta.dirname, '..')
const readTsx = (file: string) => ts.createSourceFile(file, readFileSync(path.join(root, file), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)

type Opening = ts.JsxOpeningElement | ts.JsxSelfClosingElement

function attribute(node: Opening, key: string) {
  return node.attributes.properties.find((item): item is ts.JsxAttribute => ts.isJsxAttribute(item) && item.name.getText() === key)
}

function stringValue(node?: ts.Node): string | undefined {
  if (!node) return
  if (ts.isStringLiteralLike(node)) return node.text
  if (ts.isJsxExpression(node)) return stringValue(node.expression)
}

function jsxOpening(node: ts.Node) {
  if (ts.isJsxElement(node)) return node.openingElement
  if (ts.isJsxSelfClosingElement(node)) return node
}

function collectRoutes(file: string) {
  const routes = new Set<string>()
  const targets = new Map<string, string>()
  function visit(node: ts.Node, parent = '/') {
    const opening = jsxOpening(node)
    if (opening?.tagName.getText() === 'Route') {
      const route = stringValue(attribute(opening, 'path')?.initializer)
      const index = attribute(opening, 'index')
      const element = attribute(opening, 'element')?.initializer
      if (route || index) {
        if (route) parent = route.startsWith('/') ? route : `${parent.replace(/\/$/, '')}/${route}`
        routes.add(parent)
      }
      const redirect = element && ts.isJsxExpression(element) && element.expression ? jsxOpening(element.expression) : undefined
      if (redirect?.tagName.getText() === 'Navigate') {
        const target = stringValue(attribute(redirect, 'to')?.initializer)
        if (target?.startsWith('/dashboard/')) targets.set(parent, target)
      }
    }
    node.forEachChild(child => visit(child, parent))
  }
  visit(readTsx(file))
  return { routes, targets }
}

function isFile(source: string) {
  const target = path.resolve(root, source)
  const relative = path.relative(root, target)
  return relative && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative) && statSync(target, { throwIfNoEntry: false })?.isFile()
}

function headingIds(article: DocArticle) {
  return [
    ...sectionsOf(article).map(({ id }) => id),
    ...(article.id === 'welcome' ? ['learning-library'] : []),
    ...(visuals[article.id]?.length ? ['product-screens'] : []),
  ]
}

const errors: string[] = []
const site = collectRoutes('src/App.tsx')
const publicSite = collectRoutes('src/PublicApp.tsx')
const dashboardRoutes = [...site.routes].filter(route => route === '/dashboard' || route.startsWith('/dashboard/'))
const coveredDashboardRoutes = new Set<string>()
const slug = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
const declaredAliases = new Set<string>()
const isRoute = (routes: Set<string>, pathname: string) => [...routes].some(pattern => matchPath(pattern, pathname))
const siteOrigin = 'https://docs-check.invalid'

function checkLink(link: string, location: string) {
  if (!link.startsWith('/') || link.startsWith('//')) return
  const { pathname, hash } = new URL(link, siteOrigin)
  if (!isRoute(site.routes, pathname) || /(^|\/):[^/]+/.test(pathname)) {
    errors.push(`${location}: ${link} does not point to a concrete application route`)
    return
  }
  if (pathname === '/docs' || pathname.startsWith('/docs/')) {
    const id = pathname.slice('/docs'.length).replace(/^\/+|\/+$/g, '') || 'welcome'
    const article = articlesById.get(aliases.get(id) ?? id)
    if (!isRoute(publicSite.routes, pathname)) errors.push(`${location}: ${link} is unreachable in PublicApp`)
    if (!article) errors.push(`${location}: unknown documentation article ${id}`)
    else if (hash && !headingIds(article).includes(hash.slice(1))) errors.push(`${location}: ${link} points to a missing heading`)
  }
}

if (articles.length !== articlesById.size) errors.push('Duplicate article IDs')
for (const article of articles) {
  const id = article.id
  if (!slug.test(id)) errors.push(`Invalid article ID ${id}`)
  const headings = headingIds(article)
  if (new Set(headings).size !== headings.length) errors.push(`${id}: duplicate heading IDs`)
  for (const heading of headings) if (!slug.test(heading)) errors.push(`${id}: invalid heading ID ${heading}`)
  checkLink(articleUrl(id), id)
  for (const alias of article.aliases ?? []) {
    if (!alias.split('/').every(part => slug.test(part)) || declaredAliases.has(alias) || articlesById.has(alias)) {
      errors.push(`${id}: invalid or conflicting documentation alias ${alias}`)
    }
    declaredAliases.add(alias)
    checkLink(`/docs/${alias}`, id)
  }
  for (const related of article.related ?? []) {
    if (!articlesById.has(related) || id === related) errors.push(`${id}: invalid related article ${related}`)
  }
  for (const source of article.sources ?? []) {
    if (!isFile(source)) errors.push(`${id}: missing cited source ${source}`)
  }
  for (const link of article.routes ?? []) {
    checkLink(link, id)
    const pathname = new URL(link, siteOrigin).pathname.replace(/(.+)\/$/, '$1')
    if (pathname === '/dashboard' || pathname.startsWith('/dashboard/')) coveredDashboardRoutes.add(pathname)
  }
}

for (const route of dashboardRoutes) {
  if (!coveredDashboardRoutes.has(route)) errors.push(`Undocumented dashboard route ${route}`)
}
for (const [alias, target] of site.targets) {
  if (!site.routes.has(target)) errors.push(`Dashboard alias ${alias} redirects to unknown route ${target}`)
}

// Inspect real UI links and entry cards without maintaining a duplicate list of article IDs.
for (const file of ['src/app/docs/page.tsx', 'src/app/docs/ArticleParts.tsx']) {
  function visit(node: ts.Node) {
    const opening = jsxOpening(node)
    if (opening) {
      const tag = opening.tagName.getText()
      const link = tag === 'Link' || tag === 'Navigate' ? attribute(opening, 'to') : tag === 'a' ? attribute(opening, 'href') : undefined
      const target = stringValue(link?.initializer)
      if (target) checkLink(target, file)
    }
    if (ts.isCallExpression(node) && node.expression.getText() === 'articleUrl') {
      const id = stringValue(node.arguments[0])
      if (id) checkLink(articleUrl(id, stringValue(node.arguments[1])), file)
    }
    if (ts.isVariableDeclaration(node) && node.name.getText() === 'entryPoints' && node.initializer && ts.isArrayLiteralExpression(node.initializer)) {
      for (const entry of node.initializer.elements) {
        if (!ts.isObjectLiteralExpression(entry)) continue
        const property = entry.properties.find(item => ts.isPropertyAssignment(item) && item.name.getText() === 'id')
        const id = property && ts.isPropertyAssignment(property) ? stringValue(property.initializer) : undefined
        if (id) checkLink(articleUrl(id), file)
      }
    }
    node.forEachChild(visit)
  }
  visit(readTsx(file))
}

function checkImages(id: string, images: DocVisual[]) {
  for (const image of images) {
    if (!image.src.startsWith('/') || !isFile(`public${image.src}`)) errors.push(`${id}: missing gallery image ${image.src}`)
    if (!image.alt.trim() || !image.caption.trim() || image.width <= 0 || image.height <= 0) errors.push(`${id}: missing screenshot description or size metadata`)
  }
}
for (const [id, images] of Object.entries(visuals)) {
  if (!articlesById.has(id)) errors.push(`Product gallery references unknown article ${id}`)
  checkImages(id, images)
}

let illustratedSteps = 0
for (const [id, steps] of Object.entries(walkthroughScreens)) {
  const tutorial = articlesById.get(id)?.tutorial
  for (const [step, images] of Object.entries(steps)) {
    const number = Number(step)
    if (!tutorial || !Number.isInteger(number) || number < 1 || number > tutorial.steps.length || !images?.length) {
      errors.push(`${id}: invalid screenshot reference to step ${step}`)
      continue
    }
    checkImages(`${id}, step ${step}`, images)
    illustratedSteps++
  }
}

if (errors.length) {
  console.error(errors.join('\n'))
  process.exitCode = 1
} else {
  console.log(`Checked ${articles.length} articles, ${declaredAliases.size} documentation aliases, ${dashboardRoutes.length} dashboard routes, and ${illustratedSteps} illustrated tutorial steps.`)
}
