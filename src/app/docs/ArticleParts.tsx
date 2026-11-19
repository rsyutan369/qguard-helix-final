import { useEffect, useRef, useState } from 'react'
import { ArrowRight, Check, Clipboard, Download, Flag, Info } from 'lucide-react'
import { Link } from 'react-router-dom'
import { articleMarkdown, articleUrl, articlesById } from './content/catalog'
import type { DocArticle, DocSection } from './content/types'
import { visuals, type DocVisual } from './content/visuals'
import { walkthroughScreens } from './content/walkthrough-screens'

export const describeStatus = {
  implemented: 'Implemented',
  partial: 'Availability varies',
  'ui-only': 'Preview interface',
  planned: 'Under development',
  unavailable: 'Unavailable',
}

export function Callout({ title, text, warning = false }: { title: string; text: string; warning?: boolean }) {
  const Icon = warning ? Flag : Info
  return <aside className={'hc-callout' + (warning ? ' hc-caution' : '')}><Icon size={18} aria-hidden="true" /><div><strong>{title}</strong><p>{text}</p></div></aside>
}

function CodeBlock({ code }: { code: NonNullable<DocSection['code']> }) {
  const [status, setStatus] = useState('')
  async function copy() {
    try {
      await navigator.clipboard.writeText(code.value)
      setStatus('Copied')
    } catch {
      setStatus('Select and copy the text')
    }
  }
  return <div className="hc-code"><div><span>{code.language}</span><button type="button" onClick={copy}><Clipboard size={15} /> Copy code</button></div><pre tabIndex={0}><code>{code.value}</code></pre>{status && <p role="status">{status}</p>}</div>
}

export function SectionContent({ section }: { section: DocSection }) {
  return <section className="hc-doc-section" aria-labelledby={section.id}>
    <h2 id={section.id} tabIndex={-1}>{section.title}</h2>
    {section.body?.map((paragraph, i) => <p key={i}>{paragraph}</p>)}
    {section.bullets && <ul className="hc-bullets">{section.bullets.map((item, i) => <li key={i}>{item}</li>)}</ul>}
    {section.steps && <ol className="hc-numbered">{section.steps.map((item, i) => <li key={i}>{item}</li>)}</ol>}
    {section.flow && <ol className="hc-flow" aria-label="Workflow">{section.flow.map((item, i) => <li key={i}><span>{i + 1}</span><strong>{item}</strong></li>)}</ol>}
    {section.table && <div className="hc-table" role="region" aria-label={section.title + ' table'} tabIndex={0}><table><thead><tr>{section.table.headers.map((column, i) => <th scope="col" key={i}>{column}</th>)}</tr></thead><tbody>
      {section.table.rows.map((row, i) => <tr key={i}>{row.map((cell, j) => j === 0 ? <th scope="row" key={j}>{cell}</th> : <td key={j}>{cell}</td>)}</tr>)}
    </tbody></table></div>}
    {section.note && <Callout title="Good to know" text={section.note} />}
    {section.warning && <Callout title="Important" text={section.warning} warning />}
    {section.code && <CodeBlock code={section.code} />}
    {section.questions?.map(({ question, answer }, i) => <details className="hc-faq" key={i}><summary>{question}</summary><p>{answer}</p></details>)}
  </section>
}

function loadChecks(key: string, count: number): number[] {
  try {
    const value = JSON.parse(localStorage.getItem(key) ?? '[]') as unknown
    return Array.isArray(value) ? [...new Set(value.filter((i): i is number => typeof i === 'number' && Number.isInteger(i) && i >= 0 && i < count))] : []
  } catch { return [] }
}

export function Walkthrough({ article }: { article: DocArticle }) {
  const tutorial = article.tutorial!
  const key = 'qguard-docs-walkthrough-v1:' + article.id
  const [checked, setChecked] = useState(() => loadChecks(key, tutorial.steps.length))
  const toggle = (i: number) => {
    const next = checked.includes(i) ? checked.filter(n => n !== i) : [...checked, i]
    setChecked(next)
    try { localStorage.setItem(key, JSON.stringify(next)) } catch { /* The checklist still works for this visit. */ }
  }
  return <section className="hc-doc-section" aria-labelledby="walkthrough">
    <h2 id="walkthrough" tabIndex={-1}>Interactive walkthrough</h2>
    <dl className="hc-facts">
      <div><dt>Estimated time</dt><dd>{tutorial.time}</dd></div>
      <div><dt>Required access</dt><dd>{tutorial.permissions}</dd></div>
    </dl>
    <h3>Before you start</h3>
    <ul className="hc-bullets">{tutorial.prerequisites.map((s, i) => <li key={i}>{s}</li>)}</ul>
    <div className="hc-progress"><label htmlFor="hc-progress">Your progress</label><span>{checked.length} / {tutorial.steps.length} steps</span><progress id="hc-progress" value={checked.length} max={tutorial.steps.length} /></div>
    <ol className="hc-checklist">{tutorial.steps.map((step, i) => <li key={i}>
      <label><input type="checkbox" checked={checked.includes(i)} onChange={() => toggle(i)} /><span><strong>Step {i + 1}</strong>{step}</span></label>
      <ScreenGallery screens={walkthroughScreens[article.id]?.[i + 1]} label={`Step ${i + 1} screenshots`} inline />
    </li>)}</ol>
    <h3>Expected result</h3><p>{tutorial.result}</p>
    <Callout title="Security considerations" text={tutorial.security} warning />
    <details className="hc-faq"><summary>Common mistakes</summary><p>{tutorial.mistakes}</p></details>
    <details className="hc-faq"><summary>If you get stuck</summary><p>{tutorial.troubleshoot}</p></details>
  </section>
}

export function ProductGallery({ articleId }: { articleId: string }) {
  const gallery = visuals[articleId]
  if (!gallery?.length) return null
  return <section className="hc-doc-section" aria-labelledby="product-screens">
    <h2 id="product-screens" tabIndex={-1}>Product screens</h2>
    <ScreenGallery screens={gallery} label="Product screenshots" />
  </section>
}

function ScreenGallery({ screens, label, inline = false }: { screens?: DocVisual[]; label: string; inline?: boolean }) {
  const [active, setActive] = useState<number | null>(null)
  const dialog = useRef<HTMLDialogElement>(null)
  if (!screens?.length) return null
  const item = active === null ? undefined : screens[active]
  return <div className={inline ? 'hc-step-media' : undefined} role="group" aria-label={label}>
    <div className="hc-gallery">{screens.map((screen, i) => <figure key={screen.src}>
      <button type="button" onClick={() => { setActive(i); dialog.current?.showModal() }} aria-label={'Enlarge: ' + screen.alt}>
        <img src={screen.src} alt={screen.alt} width={screen.width} height={screen.height} loading="lazy" decoding="async" />
        <span className="hc-screen-zoom">Enlarge screenshot</span>
      </button>
      <figcaption>{screen.caption}</figcaption>
    </figure>)}</div>
    <dialog className="hc-dialog hc-image-dialog" ref={dialog} aria-label={label} onClose={() => setActive(null)} data-lenis-prevent>
      <form method="dialog"><button type="submit">Close</button></form>
      {item && <><img src={item.src} alt={item.alt} width={item.width} height={item.height} /><p aria-live="polite">{item.caption}</p><a className="hc-button hc-button-quiet" href={item.src} target="_blank" rel="noreferrer">Open full resolution (new tab)</a></>}
      {active !== null && screens.length > 1 && <div className="hc-gallery-controls"><button type="button" disabled={active === 0} onClick={() => setActive(active - 1)}>Previous screen</button><button type="button" disabled={active === screens.length - 1} onClick={() => setActive(active + 1)}>Next screen</button></div>}
    </dialog>
  </div>
}

export function Related({ ids }: { ids: string[] }) {
  const links = ids.flatMap(id => { const article = articlesById.get(id); return article ? [article] : [] })
  return links.length > 0 && <section className="hc-doc-section"><h2>Related reading</h2><ul className="hc-related">{links.map(article => <li key={article.id}><Link to={articleUrl(article.id)}>{article.title} <ArrowRight size={16} /></Link></li>)}</ul></section>
}

export function DownloadGuide({ article }: { article: DocArticle }) {
  const url = useRef('')
  useEffect(() => () => { if (url.current) URL.revokeObjectURL(url.current) }, [])
  const download = () => {
    if (url.current) URL.revokeObjectURL(url.current)
    url.current = URL.createObjectURL(new Blob([articleMarkdown(article)], { type: 'text/markdown;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url.current
    link.download = 'qguard-helix-' + article.id + '.md'
    link.click()
  }
  return <button type="button" className="hc-button hc-button-quiet" onClick={download}><Download size={16} /> Download guide</button>
}

export function Feedback() {
  const [choice, setChoice] = useState<'Yes' | 'No' | null>(null)
  return <div className="hc-feedback">
    <div><strong>Was this article helpful?</strong><p>Answers stay in this view.</p></div>
    <div className="hc-votes">{(['Yes', 'No'] as const).map(vote => <button aria-pressed={choice === vote} type="button" key={vote} onClick={() => setChoice(vote)}>{choice === vote && <Check size={14} />}{vote}</button>)}</div>
    {choice !== null && <p className="hc-feedback-note" role="status">Thanks for checking in. <Link to="/contact">Contact support</Link> to report a documentation issue.</p>}
  </div>
}
