/**
 * Migration Sandbox — enterprise report generation (client side).
 *
 * Builds a structured document model from the live sandbox snapshot for each
 * of the 9 report types, then renders PDF (pdf-lib) or Word (docx) via lazy
 * imports so neither library enters the main bundle. JSON/CSV exports come
 * from the server (/api/v1/sandbox/export) — this module covers the
 * presentation formats required for audits and change-management approvals.
 */
import type { SandboxSnapshot } from './_shared'

export type SandboxReportType = 'executive' | 'technical' | 'compliance' | 'migration' | 'performance' | 'rollback' | 'risk' | 'twin' | 'ai'

export const SANDBOX_REPORT_TYPES: Array<{ id: SandboxReportType; label: string; description: string }> = [
  { id: 'executive', label: 'Executive Report', description: 'Leadership verdict: confidence scores, approval gate, business impact, priority actions.' },
  { id: 'technical', label: 'Technical Report', description: 'Simulations, digital twin composition, dependency stats, and failure predictions.' },
  { id: 'compliance', label: 'Crypto Posture Report', description: 'Per-control-family cryptographic screening indicators, each with the measurement it was decided from.' },
  { id: 'migration', label: 'Migration Report', description: 'Workflow pipeline, simulation history, and the live migration timeline.' },
  { id: 'performance', label: 'Performance Report', description: 'Before/after benchmark projection across 13 metrics with methodology.' },
  { id: 'rollback', label: 'Rollback Report', description: 'RTO/RPO, rollback success probability, and restoration checklist coverage.' },
  { id: 'risk', label: 'Risk Assessment', description: 'Risk factors, failure predictions with probabilities, and detected blockers.' },
  { id: 'twin', label: 'Digital Twin Summary', description: 'Twin coverage/fidelity, isolation attestation, and component inventory.' },
  { id: 'ai', label: 'AI Recommendations', description: 'Sophia\'s migration sequence, root causes, and prioritized guidance.' },
]

export type ReportSection = {
  title: string
  paragraphs?: string[]
  table?: { headers: string[]; rows: string[][] }
}

export type SandboxReportDoc = {
  title: string
  subtitle: string
  generatedAt: string
  sections: ReportSection[]
}

const s = (v: unknown) => (v == null ? '--' : String(v))
const pctText = (v: unknown) => (v == null ? '--' : `${v}%`)

export function buildSandboxReportDoc(snapshot: SandboxSnapshot, type: SandboxReportType): SandboxReportDoc {
  const meta = SANDBOX_REPORT_TYPES.find((t) => t.id === type)!
  const doc: SandboxReportDoc = {
    title: `QGuard Helix — Migration Sandbox ${meta.label}`,
    subtitle: meta.description,
    generatedAt: snapshot.generatedAt,
    sections: [],
  }
  const push = (section: ReportSection) => doc.sections.push(section)
  const sophia = snapshot.sophia
  const gate = snapshot.approvalGate

  const summarySection = (): ReportSection => ({
    title: 'Snapshot Summary',
    table: {
      headers: ['Metric', 'Value'],
      rows: [
        ['Total assets', s(snapshot.summary.totalAssets)],
        ['Sandbox simulations', s(snapshot.summary.totalSimulations)],
        ['Completed / failed', `${snapshot.summary.completed} / ${snapshot.summary.failed}`],
        ['PQC readiness', pctText(snapshot.summary.pqcReadiness)],
        ['Quantum risk (0-100, lower is better)', snapshot.summary.quantumRiskScore === null ? 'Not assessed' : `${snapshot.summary.quantumRiskScore} (${snapshot.summary.quantumRiskLevel})`],
        ['Compliance score', pctText(snapshot.complianceScore)],
        ['Critical exposures', s(snapshot.summary.criticalExposures)],
      ],
    },
  })

  if (type === 'executive' || type === 'ai') {
    if (sophia) {
      push({ title: 'Executive Summary', paragraphs: [sophia.executiveSummary, ...(type === 'ai' ? sophia.narrative : [])] })
      push({
        title: 'Confidence Scores',
        table: {
          headers: ['Dimension', 'Score'],
          rows: [
            ['Migration confidence', pctText(sophia.migrationConfidencePct)],
            ['Compatibility score', pctText(sophia.compatibilityScorePct)],
            ['Rollback confidence', pctText(sophia.rollbackConfidencePct)],
            ['AI confidence (evidence depth)', pctText(sophia.aiConfidencePct)],
            ['Quantum risk (0-100, lower is better)', sophia.quantumRiskScore === null ? 'Not assessed' : s(sophia.quantumRiskScore)],
          ],
        },
      })
      if (sophia.recommendedSequence.length > 0) {
        push({
          title: 'Recommended Migration Sequence',
          table: { headers: ['#', 'Wave', 'Assets', 'Rationale'], rows: sophia.recommendedSequence.map((step) => [s(step.order), step.label, s(step.assets), step.rationale]) },
        })
      }
      if (sophia.detectedBlockers.length > 0) {
        push({
          title: 'Detected Blockers',
          table: { headers: ['Blocker', 'Probability', 'Severity', 'Recommendation'], rows: sophia.detectedBlockers.map((b) => [b.label, pctText(b.probabilityPct), b.severity, b.recommendation]) },
        })
      }
      if (sophia.priorityActions.length > 0) push({ title: 'Priority Actions', paragraphs: sophia.priorityActions.map((a, i) => `${i + 1}. ${a}`) })
      if (type === 'ai' && sophia.rootCauses.length > 0) push({ title: 'Root Cause Analysis', paragraphs: sophia.rootCauses })
    }
    if (gate) {
      push({
        title: 'Production Approval Gate',
        paragraphs: [`Simulation status: ${gate.simulationStatus}. ${gate.aiRecommendation}`, gate.guarantee],
        table: { headers: ['Gate', 'Value', 'Status'], rows: gate.gates.map((g) => [g.label, g.value, g.status.toUpperCase()]) },
      })
    }
    if (type === 'executive') push(summarySection())
    return doc
  }

  if (type === 'technical') {
    push(summarySection())
    if (snapshot.digitalTwin) {
      push({
        title: 'Digital Twin Composition',
        table: {
          headers: ['Component', 'Assets', 'Vulnerable', 'Critical'],
          rows: snapshot.digitalTwin.componentGroups.map((g) => [g.label, s(g.assets), s(g.vulnerable), s(g.critical)]),
        },
      })
    }
    if (snapshot.dependencyGraph) {
      const st = snapshot.dependencyGraph.stats
      push({
        title: 'Dependency Graph',
        table: { headers: ['Metric', 'Value'], rows: [['Nodes', s(st.totalNodes)], ['Observed edges', s(st.observedEdges)], ['Inferred edges', s(st.inferredEdges)], ['Max blast radius', s(st.maxBlastRadius)]] },
      })
    }
    if (snapshot.failurePrediction) {
      push({
        title: 'Failure Predictions',
        table: { headers: ['Prediction', 'Probability', 'Severity', 'Evidence'], rows: snapshot.failurePrediction.predictions.map((p) => [p.label, pctText(p.probabilityPct), p.severity, p.evidence]) },
      })
    }
    push({
      title: 'Simulations',
      table: { headers: ['Name', 'Status', 'Progress', 'Source → Target'], rows: snapshot.simulations.slice(0, 40).map((sim) => [sim.name, sim.status, pctText(sim.progress), `${sim.fromAlgo} → ${sim.toAlgo}`]) },
    })
    return doc
  }

  if (type === 'compliance') {
    push({ title: 'Compliance Posture', paragraphs: [`Overall compliance score: ${snapshot.complianceScore}%.`] })
    push({
      title: 'Framework Validation',
      table: { headers: ['Control family', 'Indicator', 'Status', 'Score', 'Basis'], rows: snapshot.complianceItems.map((c) => [c.framework, c.control, c.status, s(c.score), c.basis || '']) },
    })
    if (gate) push({ title: 'Approval Evidence', table: { headers: ['Simulation', 'Decision', 'Decided By', 'At'], rows: gate.decisions.map((d) => [d.jobName, d.decision, s(d.decidedBy), s(d.decidedAt)]) } })
    return doc
  }

  if (type === 'migration') {
    push(summarySection())
    push({
      title: 'Migration Workflows',
      table: { headers: ['Name', 'Mode', 'Status', 'Progress', 'Phase'], rows: snapshot.workflows.slice(0, 50).map((w) => [w.name, w.runModeLabel, w.status, pctText(w.progress), w.phase]) },
    })
    if (snapshot.timeline && snapshot.timeline.length > 0) {
      push({ title: 'Live Migration Timeline', table: { headers: ['Time', 'Event', 'Severity'], rows: snapshot.timeline.slice(0, 30).map((t) => [t.at, t.label, t.severity]) } })
    }
    return doc
  }

  if (type === 'performance') {
    const bench = snapshot.performanceBenchmark
    if (bench?.available) {
      push({ title: 'Methodology', paragraphs: [bench.methodology, `Sample: ${bench.sampleSize} crypto inventory records. Algorithm prevalence (overlapping shares of records, not a partition) — RSA ${bench.algorithmMix.rsaSharePct}%, ECC ${bench.algorithmMix.eccSharePct}%, PQC ${bench.algorithmMix.pqcSharePct}%, symmetric ${bench.algorithmMix.symmetricSharePct}%.`] })
      push({
        title: 'Before vs After Migration',
        table: { headers: ['Metric', 'Before', 'After', 'Δ %', 'Note'], rows: bench.metrics.map((m) => [`${m.label} (${m.unit})`, s(m.before), s(m.after), `${m.deltaPct > 0 ? '+' : ''}${m.deltaPct}%`, m.note]) },
      })
    } else {
      push({ title: 'Performance Benchmark', paragraphs: ['No crypto inventory discovered yet — run discovery scans to enable the benchmark projection.'] })
    }
    return doc
  }

  if (type === 'rollback') {
    const rb = snapshot.rollbackAnalysis
    if (rb) {
      push({
        title: 'Recovery Objectives',
        table: {
          headers: ['Metric', 'Value'],
          rows: [
            ['Rollback success probability', rb.successProbabilityPct === null ? 'Not assessed (no rehearsal)' : pctText(rb.successProbabilityPct)],
            ['Recovery Time Objective (RTO)', rb.rtoMinutes === null ? 'Not assessed' : `${rb.rtoMinutes} min`],
            ['Recovery Point Objective (RPO)', rb.rpoMinutes === null ? 'Not assessed' : `${rb.rpoMinutes} min`],
            ['Predicted downtime', rb.downtimePredictionMin === null ? 'Not assessed' : `${rb.downtimePredictionMin} min`],
            ['Snapshot coverage', rb.snapshotCoveragePct === null ? 'Not assessed' : pctText(rb.snapshotCoveragePct)],
            ['Automatic rollback ready', rb.automaticRollbackReady ? 'Yes' : 'No'],
          ],
        },
      })
      push({ title: 'Restoration Checklist', table: { headers: ['Item', 'Covered', 'Detail'], rows: rb.restorationChecklist.map((c) => [c.label, c.covered ? 'Yes' : 'No', c.detail]) } })
      push({ title: 'Notes', paragraphs: [rb.note] })
    }
    return doc
  }

  if (type === 'risk') {
    push(summarySection())
    if (snapshot.riskFactors.length > 0) {
      push({ title: 'Risk Factors', table: { headers: ['Factor', 'Count', 'Severity', 'Impact'], rows: snapshot.riskFactors.map((r) => [r.label, s(r.count), r.severity, r.impact]) } })
    }
    if (snapshot.failurePrediction) {
      push({ title: `Failure Predictions (overall ${snapshot.failurePrediction.overallFailureProbabilityPct}%)`, table: { headers: ['Prediction', 'Probability', 'Severity', 'Recommendation'], rows: snapshot.failurePrediction.predictions.map((p) => [p.label, pctText(p.probabilityPct), p.severity, p.recommendation]) } })
    }
    return doc
  }

  // twin
  const twin = snapshot.digitalTwin
  if (twin) {
    push({
      title: 'Twin Summary',
      table: {
        headers: ['Metric', 'Value'],
        rows: [
          ['Twin nodes', s(twin.summary.totalNodes)],
          ['Nodes with evidence', s(twin.summary.nodesWithEvidence)],
          ['Coverage', pctText(twin.summary.coveragePct)],
          ['Fidelity', pctText(twin.summary.fidelityPct)],
          ['Inventory records cloned', s(twin.summary.inventoryRecordsCloned)],
          ['Certificates cloned', s(twin.summary.certificatesCloned)],
          ['Trust relationships', s(twin.summary.trustRelationships)],
          ['Runtime signals sampled', s(twin.summary.runtimeSignalsSampled)],
        ],
      },
    })
    push({ title: 'Isolation Attestation', paragraphs: [`Scope: ${twin.isolation.scope}. Production writes: ${twin.isolation.productionWrites}.`, ...twin.isolation.guarantees] })
    push({ title: 'Component Groups', table: { headers: ['Component', 'Assets', 'Vulnerable', 'Critical'], rows: twin.componentGroups.map((g) => [g.label, s(g.assets), s(g.vulnerable), s(g.critical)]) } })
  } else {
    push({ title: 'Digital Twin', paragraphs: ['Twin not yet generated — refresh the sandbox snapshot.'] })
  }
  return doc
}

/* ═══════════════════════════════════════════════════════════════════════════
   PDF RENDERER (pdf-lib, lazy)
   ═══════════════════════════════════════════════════════════════════════════ */

export async function renderSandboxReportPdf(doc: SandboxReportDoc): Promise<Blob> {
  const { PDFDocument, StandardFonts, rgb } = await import('pdf-lib')
  const pdf = await PDFDocument.create()
  const font = await pdf.embedFont(StandardFonts.Helvetica)
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold)

  const PAGE_W = 595.28
  const PAGE_H = 841.89
  const MARGIN = 46
  const CONTENT_W = PAGE_W - MARGIN * 2
  let page = pdf.addPage([PAGE_W, PAGE_H])
  let y = PAGE_H - MARGIN

  const GOLD_C = rgb(0.85, 0.66, 0.13)
  const DARK = rgb(0.09, 0.11, 0.15)
  const MUTED = rgb(0.38, 0.42, 0.48)

  const sanitize = (text: string) => text.replace(/[→]/g, '->').replace(/[Δ]/g, 'Delta').replace(/[’‘]/g, "'").replace(/[“”]/g, '"').replace(/[—–]/g, '-').replace(/[≥]/g, '>=').replace(/[≤]/g, '<=').replace(/[^\x00-\xFF]/g, '')

  const ensure = (needed: number) => {
    if (y - needed < MARGIN) {
      page = pdf.addPage([PAGE_W, PAGE_H])
      y = PAGE_H - MARGIN
    }
  }

  const wrap = (text: string, size: number, useFont = font, maxWidth = CONTENT_W) => {
    const words = sanitize(text).split(/\s+/)
    const lines: string[] = []
    let line = ''
    for (const word of words) {
      const candidate = line ? `${line} ${word}` : word
      if (useFont.widthOfTextAtSize(candidate, size) > maxWidth && line) {
        lines.push(line)
        line = word
      } else {
        line = candidate
      }
    }
    if (line) lines.push(line)
    return lines
  }

  const drawLines = (text: string, size: number, useFont = font, color = DARK, maxWidth = CONTENT_W, x = MARGIN) => {
    for (const line of wrap(text, size, useFont, maxWidth)) {
      ensure(size + 5)
      page.drawText(line, { x, y: y - size, size, font: useFont, color })
      y -= size + 4
    }
  }

  // Header band
  page.drawRectangle({ x: 0, y: PAGE_H - 92, width: PAGE_W, height: 92, color: rgb(0.05, 0.08, 0.13) })
  page.drawText(sanitize('QGUARD HELIX — MIGRATION SANDBOX'), { x: MARGIN, y: PAGE_H - 38, size: 9, font: bold, color: GOLD_C })
  for (const [i, line] of wrap(doc.title.replace('QGuard Helix — Migration Sandbox ', ''), 20, bold, CONTENT_W).entries()) {
    page.drawText(line, { x: MARGIN, y: PAGE_H - 62 - i * 22, size: 20, font: bold, color: rgb(1, 1, 1) })
  }
  page.drawText(sanitize(`Generated ${doc.generatedAt} · Digital Twin simulation evidence · Production systems untouched`), { x: MARGIN, y: PAGE_H - 84, size: 8, font, color: rgb(0.7, 0.73, 0.78) })
  y = PAGE_H - 112
  drawLines(doc.subtitle, 10, font, MUTED)
  y -= 8

  for (const section of doc.sections) {
    ensure(40)
    y -= 8
    page.drawText(sanitize(section.title.toUpperCase()), { x: MARGIN, y: y - 11, size: 11, font: bold, color: GOLD_C })
    y -= 20
    page.drawLine({ start: { x: MARGIN, y }, end: { x: PAGE_W - MARGIN, y }, thickness: 0.75, color: GOLD_C })
    y -= 10

    for (const paragraph of section.paragraphs || []) {
      drawLines(paragraph, 9.5)
      y -= 4
    }

    if (section.table) {
      const cols = section.table.headers.length
      const colW = CONTENT_W / cols
      ensure(18)
      section.table.headers.forEach((header, i) => {
        page.drawText(sanitize(header).slice(0, 42), { x: MARGIN + i * colW, y: y - 9, size: 8.5, font: bold, color: DARK })
      })
      y -= 14
      page.drawLine({ start: { x: MARGIN, y }, end: { x: PAGE_W - MARGIN, y }, thickness: 0.5, color: MUTED })
      y -= 4
      for (const row of section.table.rows) {
        const cellLines = row.map((cell) => wrap(String(cell ?? '--'), 8, font, colW - 8))
        const rowHeight = Math.max(...cellLines.map((l) => l.length)) * 10 + 4
        ensure(rowHeight)
        cellLines.forEach((lines, i) => {
          lines.forEach((line, li) => {
            page.drawText(line, { x: MARGIN + i * colW, y: y - 8 - li * 10, size: 8, font, color: DARK })
          })
        })
        y -= rowHeight
      }
      y -= 4
    }
  }

  const pages = pdf.getPages()
  pages.forEach((p, i) => {
    p.drawText(sanitize(`QGuard Helix Migration Sandbox · Page ${i + 1} of ${pages.length}`), { x: MARGIN, y: 24, size: 7.5, font, color: MUTED })
  })

  const bytes = await pdf.save()
  return new Blob([bytes as unknown as BlobPart], { type: 'application/pdf' })
}

/* ═══════════════════════════════════════════════════════════════════════════
   WORD RENDERER (docx, lazy)
   ═══════════════════════════════════════════════════════════════════════════ */

export async function renderSandboxReportDocx(doc: SandboxReportDoc): Promise<Blob> {
  const { Document, HeadingLevel, Packer, Paragraph, Table, TableCell, TableRow, TextRun, WidthType } = await import('docx')

  const children: any[] = [
    new Paragraph({ heading: HeadingLevel.TITLE, children: [new TextRun({ text: doc.title, bold: true })] }),
    new Paragraph({ children: [new TextRun({ text: doc.subtitle, italics: true, color: '666666' })] }),
    new Paragraph({ children: [new TextRun({ text: `Generated ${doc.generatedAt} — Digital Twin simulation evidence. Production systems untouched.`, size: 18, color: '888888' })] }),
    new Paragraph({ text: '' }),
  ]

  for (const section of doc.sections) {
    children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: section.title, bold: true })] }))
    for (const paragraph of section.paragraphs || []) {
      children.push(new Paragraph({ children: [new TextRun({ text: paragraph })] }))
    }
    if (section.table) {
      children.push(new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          new TableRow({ children: section.table.headers.map((h) => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: h, bold: true })] })] })) }),
          ...section.table.rows.map((row) => new TableRow({ children: row.map((cell) => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: String(cell ?? '--') })] })] })) })),
        ],
      }))
    }
    children.push(new Paragraph({ text: '' }))
  }

  const wordDoc = new Document({ sections: [{ children }] })
  return Packer.toBlob(wordDoc)
}
