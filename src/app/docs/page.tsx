import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { ArrowDown, ArrowLeft, ArrowRight, ArrowUpRight, BookOpen, ChevronDown, ChevronRight, CircleHelp, Compass, Menu, Moon, PanelLeft, Play, Search, Shield, Sun, X } from 'lucide-react'
import { Link, Navigate, useLocation } from 'react-router-dom'
import { useReducedMotion } from 'motion/react'
import { useTheme } from '@/contexts/theme-context'
import { ButtonDot, Chars } from '@/pages/landing-chars'
import { useLandingMotion } from '@/pages/landing-motion'
import { DownloadGuide, Feedback, ProductGallery, Related, SectionContent, Walkthrough, describeStatus } from './ArticleParts'
import { aliases, articleUrl, articles, articlesById, categories, readingTime, searchDocs, sectionsOf, tutorials } from './content/catalog'
import type { DocArticle } from './content/types'
import { visuals } from './content/visuals'
import '@/pages/landing.css'
import './docs.css'

function Navigation({ articleId, close }: { articleId?: string; close?: () => void }) {
  const [overrides, setOverrides] = useState<Record<string, boolean>>({})
  const navId = useId()
  const activeCategory = articleId ? articlesById.get(articleId)?.category : undefined
  return <nav className="hc-nav" aria-label="Documentation">
    <p className="hc-kicker">Browse the knowledge center</p>
    {categories.map(({ id, title, icon: Icon }, index) => {
      const open = overrides[id] ?? (id === activeCategory || id === 'start')
      return <div className="hc-nav-group" key={id}>
        <button aria-expanded={open} aria-controls={navId + id} type="button" onClick={() => setOverrides(curr => ({ ...curr, [id]: !open }))}>
          <Icon size={17} aria-hidden="true"/><span>{title}</span><ChevronDown size={14} className={open ? 'hc-twist' : ''} aria-hidden="true" />
        </button>
        <ul hidden={!open} id={navId + id}>
          {articles.filter(a => a.category === id).map(a => <li key={a.id}><Link to={articleUrl(a.id)} onClick={close} aria-current={articleId === a.id ? 'page' : undefined}>{a.id === 'welcome' ? 'Overview' : a.title}</Link></li>)}
        </ul>
        {index === 8 && <hr />}
      </div>
    })}
  </nav>
}

function SearchDialog({ dialogRef }: { dialogRef: React.RefObject<HTMLDialogElement | null> }) {
  const [query, setQuery] = useState('')
  const hits = useMemo(() => searchDocs(query), [query])
  return <dialog className="hc-dialog hc-search-dialog" aria-labelledby="hc-search-title" ref={dialogRef}>
    <div className="hc-search-head">
      <Search size={20} aria-hidden="true" />
      <label className="hc-sr-only" id="hc-search-title" htmlFor="hc-search">Search the documentation</label>
      <input id="hc-search" type="search" autoFocus value={query} onChange={event => setQuery(event.target.value)} placeholder="Search guides, modules and terms…" />
      <form method="dialog"><button type="submit" aria-label="Close search"><X size={20}/></button></form>
    </div>
    {query.trim() ? <p role="status" className="hc-search-meta">{hits.length ? 'Showing ' + hits.length + ' result' + (hits.length === 1 ? '' : 's') : 'No results for “' + query + '”. Try a module name or a shorter term.'}</p>
      : <p className="hc-search-meta">Try “ML-KEM”, “migration sandbox”, “device trust” or “billing”.</p>}
    <ul className="hc-search-results">{hits.map(hit => <li key={hit.article.id + ':' + (hit.section ?? '')}>
      <Link to={articleUrl(hit.article.id, hit.section)} onClick={() => dialogRef.current?.close()}>
        <BookOpen size={17} aria-hidden="true" />
        <span><strong>{hit.title}</strong>{hit.section && <small>{hit.article.title}</small>}<span className="hc-excerpt">{hit.excerpt}</span></span><ArrowUpRight size={16} aria-hidden="true" />
      </Link>
    </li>)}</ul>
  </dialog>
}

const entryPoints = [
  { id: 'account-setup', icon: Compass, title: 'Set up your workspace', description: 'Create your account, sign in, and find your way around the platform.' },
  { id: 'migration-roadmap-tutorial', icon: Play, title: 'Plan a PQC migration', description: 'Turn discovery evidence into a migration roadmap you can review and test.' },
  { id: 'messaging', icon: Shield, title: 'Explore QGuard Messaging', description: 'Learn what’s supported for secure chat, vaults, and nearby connections.' },
]

function LandingContent() {
  return <>
    <div className="hc-entrypoints">
      {entryPoints.map(({ id, title, icon: Icon, description }) => <Link key={id} to={articleUrl(id)} className="hc-entry" data-lp-reveal>
        <div><Icon size={19} aria-hidden="true"/><ArrowUpRight size={16} aria-hidden="true" /></div><strong>{title}</strong><span>{description}</span>
      </Link>)}
    </div>
    <section className="hc-doc-section hc-library" aria-labelledby="learning-library" data-lp-glow-cover>
      <h2 id="learning-library" tabIndex={-1} data-lp-reveal>Learn by doing</h2>
      <p>Follow a workflow, check off each step, and learn how to verify the result in your environment.</p>
      <ul className="hc-tutorial-links">{tutorials.map(tutorial => <li key={tutorial.id}><Link to={articleUrl(tutorial.id)}>
        <Play size={15} aria-hidden="true"/><strong>{tutorial.title}</strong><span>{tutorial.tutorial?.time}</span><ArrowRight size={15} aria-hidden="true" />
      </Link></li>)}</ul>
    </section>
  </>
}

function Article({ article }: { article: DocArticle }) {
  const category = categories.find(c => c.id === article.category)!
  const landing = article.id === 'welcome'
  const index = articles.indexOf(article)
  const nearby = [{ label: 'Previous article', icon: ArrowLeft, article: articles[index - 1] }, { label: 'Next article', icon: ArrowRight, article: articles[index + 1] }]
  const headings = [
    ...(landing ? [{ id: 'learning-library', title: 'Learn by doing' }] : []),
    ...(visuals[article.id]?.length ? [{ id: 'product-screens', title: 'Product screens' }] : []),
    ...sectionsOf(article),
  ]
  const related = article.related ?? articles.filter(other => other.category === article.category && other !== article && other.id !== 'welcome').slice(0, 3).map(other => other.id)
  return <div className="hc-reading">
    <main className="hc-main" id="hc-main" tabIndex={-1}>
      <nav className="hc-breadcrumbs" aria-label="Breadcrumbs"><Link to="/docs">Documentation</Link><ChevronRight size={13} aria-hidden="true" /><span aria-current={landing ? 'page' : undefined}>{category.title}</span></nav>
      <header className={'hc-article-header' + (landing ? ' hc-welcome' : '')}>
        <div className="hc-eyebrow" data-lp-reveal>{landing ? 'Platform documentation' : category.title}</div>
        {landing ? <h1 data-letters="load" aria-label={article.title}><Chars text="QGuard Helix" /><br /><em><Chars text="Knowledge Center" /></em></h1> : <h1>{article.title}</h1>}
        <p>{article.summary}</p>
        {landing ? <div className="hc-hero-actions" data-lp-reveal>
          <Link className="lp-btn lp-btn--primary lp-btn--dot" to={articleUrl('account-setup')}>Get started <ButtonDot /></Link>
          <Link className="lp-btn lp-btn--secondary" to="/docs#learning-library">Browse tutorials <ArrowDown size={16} /></Link>
        </div> : <div className="hc-meta">
          <span>{article.product ?? (article.category === 'messaging' ? 'QGuard Messaging' : 'QGuard Helix')}</span>
          <span>{readingTime(article)} min read</span>
          {article.status && article.status !== 'implemented' && <span className="hc-status">{describeStatus[article.status]}</span>}
          <time dateTime={article.updated ?? '2026-11-16'}>Updated {new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeZone: 'UTC' }).format(new Date(article.updated ?? '2026-11-16'))}</time>
        </div>}
      </header>
      {landing && <LandingContent />}
      {article.routes?.length ? <nav className="hc-product-links" aria-label="Open in product">{article.routes.map((route, i) =>
        <Link key={route} to={route}>{article.routes!.length === 1 ? 'Open in product' : route.split('/').filter(Boolean).slice(-1)[0].replaceAll(/[-_]/g, ' ')} <ArrowUpRight size={15} aria-hidden="true" />{article.routes!.length > 1 && <span className="hc-sr-only"> ({route})</span>}</Link>)}</nav> : null}
      <details className="hc-mobile-toc"><summary>On this page</summary><Toc article={article} headings={headings} /></details>
      <ProductGallery articleId={article.id} />
      {article.tutorial && <Walkthrough article={article} />}
      {article.sections.map(section => <SectionContent key={section.id} section={section} />)}
      {related.length > 0 && <Related ids={related} />}
      <div className="hc-actions"><DownloadGuide article={article} /></div>
      <Feedback />
      <nav aria-label="Previous and next articles" className="hc-nearby">{nearby.map(({ label, icon: Icon, article: link }) =>
        link ? <Link key={label} to={articleUrl(link.id)}><span><Icon size={16} />{label}</span><strong>{link.title}</strong></Link> : <span key={label} />)}</nav>
    </main>
    <aside className="hc-toc-desktop" data-lenis-prevent>
      <p className="hc-kicker">On this page</p><Toc article={article} headings={headings} />
      <hr/><Link className="hc-help-link" to={articleUrl('faq')}><CircleHelp size={16} /> Frequently asked questions</Link>
    </aside>
  </div>
}

function Toc({ article, headings }: { article: DocArticle; headings: { id: string; title: string }[] }) {
  const { hash } = useLocation()
  return <nav className="hc-toc" aria-label="On this page"><ul>{headings.map(heading =>
    <li key={heading.id}><Link to={articleUrl(article.id, heading.id)} aria-current={hash === '#' + heading.id ? 'location' : undefined}>{heading.title}</Link></li>)}</ul></nav>
}

export default function DocsPage() {
  const { pathname, hash } = useLocation()
  const requested = pathname.replace(/^\/docs\/?|\/+$/g, '') || 'welcome'
  const article = articlesById.get(aliases.get(requested) ?? requested)
  const { isLight, toggleTheme } = useTheme()
  const [sidebar, setSidebar] = useState(true)
  const root = useRef<HTMLDivElement>(null)
  const glow = useRef<HTMLCanvasElement>(null)
  const search = useRef<HTMLDialogElement>(null)
  const mobile = useRef<HTMLDialogElement>(null)
  const reduceMotion = useReducedMotion()
  useLandingMotion(root, glow, false, {
    animate: !reduceMotion,
    allowNestedScroll: true,
    smoothAnchors: false,
    routeKey: pathname,
  })

  useEffect(() => {
    const open = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        if (!search.current?.open) search.current?.showModal()
      }
    }
    window.addEventListener('keydown', open)
    return () => window.removeEventListener('keydown', open)
  }, [])

  useEffect(() => {
    document.title = article?.id === 'welcome' ? article.title : article ? article.title + ' | QGuard Helix Docs' : 'Article not found | QGuard Helix Docs'
    const id = hash && hash.slice(1)
    const target = id ? document.getElementById(id) : null
    if (target) {
      target.scrollIntoView({ block: 'start' })
      target.focus({ preventScroll: true })
    } else {
      window.scrollTo({ top: 0, behavior: 'instant' })
    }
    return () => { document.title = 'QGuard Helix' }
  }, [article, hash, pathname])

  if (article && requested !== article.id) return <Navigate replace to={articleUrl(article.id) + hash} />

  return <div className={'lp hc-shell' + (isLight ? '' : ' lp-dark')} ref={root}>
    <div className="lp-atmo hc-atmo" aria-hidden="true"><canvas ref={glow} width={96} height={60} /></div>
    <a href="#hc-main" className="hc-skip">Skip to content</a>
    <header className="hc-top qh-nav__shell">
      <button type="button" className="hc-icon hc-mobile-menu" aria-label="Open documentation navigation" onClick={() => mobile.current?.showModal()}><Menu size={20}/></button>
      <button type="button" className="hc-icon hc-sidebar-toggle" aria-label={sidebar ? 'Collapse sidebar' : 'Expand sidebar'} aria-expanded={sidebar} onClick={() => setSidebar(!sidebar)}><PanelLeft size={19}/></button>
      <div className="hc-brand">
        <Link to="/" aria-label="QGuard Helix homepage"><img src="/NEW_LOGO.png" alt="" width={42} height={42} /><strong>QGuard Helix</strong></Link>
        <span className="hc-brand-rule" aria-hidden="true" />
        <Link className="hc-brand-docs" to="/docs">Docs</Link>
      </div>
      <button type="button" className="hc-search-open" onClick={() => search.current?.showModal()} aria-label="Search documentation"><Search size={17} aria-hidden="true" /><span>Search documentation</span><kbd>Ctrl K</kbd></button>
      <div className="hc-top-actions">
        <button type="button" className="hc-icon" onClick={toggleTheme} aria-label={isLight ? 'Switch to dark theme' : 'Switch to light theme'}>{isLight ? <Moon size={18}/> : <Sun size={18}/>}</button>
        <Link className="hc-button hc-platform-link" to="/dashboard">Open platform <ArrowUpRight aria-hidden="true" size={16}/></Link>
      </div>
    </header>
    <div className={'hc-layout' + (!sidebar ? ' hc-no-sidebar' : '')}>
      {sidebar && <aside className="hc-sidebar" data-lenis-prevent><Navigation key={article?.category} articleId={article?.id} /></aside>}
      {article ? <Article key={article.id} article={article} /> : <main className="hc-main hc-missing" id="hc-main" tabIndex={-1}><h1>Article not found</h1><p>Search for the module or return to the documentation overview.</p><Link className="hc-button hc-button-primary" to="/docs"><ArrowLeft size={16} /> Documentation overview</Link></main>}
    </div>
    <SearchDialog dialogRef={search} />
    <dialog className="hc-dialog hc-mobile-nav" ref={mobile} aria-label="Documentation navigation" data-lenis-prevent>
      <form method="dialog"><button type="submit" aria-label="Close documentation navigation"><X size={20} /></button></form>
      <Navigation key={article?.category} articleId={article?.id} close={() => mobile.current?.close()} />
    </dialog>
  </div>
}
