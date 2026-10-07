/**
 * Exposure report catalogue — the four templates and the three presented
 * depths, as plain data.
 *
 * It is a module of its own, with NO imports, because the scanner panels render
 * this catalogue on a card that is always mounted while the builder behind it
 * (`ExposureReport.ts`, and transitively zod, jose and @noble/hashes) must only
 * load when an operator opens the drawer. A single static import of the builder
 * from an always-mounted component would pull the whole report engine into the
 * main bundle and quietly undo the lazy split.
 *
 * `ExposureReport.ts` re-exports everything here, so a caller that already has
 * the builder loaded never needs to know this file exists.
 */

/* Type-only, so this module still has no runtime dependency at all: the History
   tab's provenance shape, mapped by `exposureRecordFromProvenance` below. */
import type { HistoryProvenance } from '@/lib/scanner/exposure/history'

export type ExposureReportTemplate = 'executive' | 'technical' | 'remediation' | 'compliance'

export interface ExposureReportTemplateSpec {
  key: ExposureReportTemplate
  name: string
  audience: string
  description: string
  /** Section titles in reading order, including the ones every template has. */
  sections: string[]
}

export const EXPOSURE_REPORT_TEMPLATES: ExposureReportTemplateSpec[] = [
  {
    key: 'executive',
    name: 'Executive Exposure Brief',
    audience: 'CISO · Board · Risk committee',
    description:
      'Board-ready posture of this assessment: where the quantum exposure sits, what drives the risk score, what to fix first and the decisions required.',
    sections: [
      'Executive Summary',
      'Executive Dashboard',
      'Risk Decomposition',
      'Quantum Exposure',
      'Priority Exposures',
      'Recommended Actions',
      'Assessment Coverage & Limits',
      'Decision Register',
      'Methodology & Definitions',
      'Validation & Integrity',
    ],
  },
  {
    key: 'technical',
    name: 'Technical Exposure & CBOM Register',
    audience: 'Security engineering · Architecture · Audit',
    description:
      'The complete record: engine ledger, cryptographic bill of materials, findings register, correlated exposures, scanned inventory and how each observation was made.',
    sections: [
      'Executive Summary',
      'Scope & Methodology',
      'Engine Execution Ledger',
      'Posture Analysis',
      'Cryptographic Bill of Materials',
      'Findings Register',
      'Correlated Exposures',
      'Scanned Inventory',
      'How This Was Detected',
      'Secret Material',
      'Dependency Surface',
      'Assessment Coverage & Limits',
      'Decision Register',
      'Methodology & Definitions',
      'Validation & Integrity',
    ],
  },
  {
    key: 'remediation',
    name: 'PQC Remediation Worklist',
    audience: 'Platform teams · Service owners',
    description:
      'Prioritised remediation per exposure: the evidence, the recommended action, the role-appropriate post-quantum target and the blast radius across layers.',
    sections: [
      'Executive Summary',
      'Remediation Priorities',
      'Exposure Worklists',
      'Engine Recommendations',
      'Classical Weaknesses',
      'Unclassified Cryptography',
      'Already Quantum-Safe',
      'Assessment Coverage & Limits',
      'Decision Register',
      'Methodology & Definitions',
      'Validation & Integrity',
    ],
  },
  {
    key: 'compliance',
    name: 'Standards & Evidence Dossier',
    audience: 'Compliance · Internal audit · Assurance',
    description:
      'Audit-facing evidence: which publications the findings cite and who they bind, the quality and provenance of each observation, and every gap in coverage stated as a gap.',
    sections: [
      'Executive Summary',
      'Scope & Methodology',
      'Cryptographic Posture',
      'Standards Cited',
      'Evidence Quality',
      'Control Observations',
      'Coverage Gaps',
      'Record Provenance',
      'Decision Register',
      'Methodology & Definitions',
      'Validation & Integrity',
    ],
  },
]

export type ExposureReportDepth = 'summary' | 'standard' | 'complete'

export interface ExposureReportDepthSpec {
  key: ExposureReportDepth
  label: string
  detail: string
  /** Rows of a register presented in the narrative formats. */
  rows: number
}

/**
 * How many rows of each register the NARRATIVE formats carry.
 *
 * The Excel, CSV and JSON exports are always complete — they read
 * `report.tables`, which the builder never truncates. A PDF, a Word file and
 * especially a deck are summary formats: 1,100 findings is a hundred slides, and
 * a reader handed that does not read it. So the presented depth is the
 * operator's choice, and every table that was limited says so on its own face
 * and names where the complete register is.
 */
export const EXPOSURE_REPORT_DEPTHS: ExposureReportDepthSpec[] = [
  { key: 'summary', label: 'Summary', detail: 'Top 25 rows per register — briefing-length PDF and deck', rows: 25 },
  { key: 'standard', label: 'Standard', detail: 'Up to 250 rows per register — the usual working document', rows: 250 },
  { key: 'complete', label: 'Complete', detail: 'Every row in every format — large PDFs and long decks', rows: Number.POSITIVE_INFINITY },
]

/* ================================================================== */
/* Record provenance                                                   */
/* ================================================================== */

/**
 * Provenance of a RECORDED assessment, when a report is built from the History
 * tab rather than from a live run.
 *
 * A record has edges — fields the platform recomputed, fields it never
 * retained, lists it capped. They are published in the document because a
 * reader cannot otherwise tell a field the scan found nothing in from a field
 * the record did not keep.
 */
export interface ExposureReportRecord {
  recordedAt: string
  recordVersion: number
  rehydrated: string[]
  recomputed: string[]
  notRetained: string[]
  truncated: string[]
}

/**
 * Map the History tab's provenance onto the report's record block.
 *
 * It lives beside the catalogue rather than in the builder so the History panel
 * — which is part of the main bundle — can call it without dragging the report
 * engine in, and so `tools/exposure-report-check.ts` exercises the SAME mapping
 * the UI uses. The whole point of the record block is that a field the record
 * did not keep prints as "not retained"; a mapping that silently dropped
 * `notRetained` would turn that promise into an empty section with nothing to
 * fail.
 */
export function exposureRecordFromProvenance(provenance: HistoryProvenance): ExposureReportRecord {
  return {
    recordedAt: provenance.recordedAt ?? '',
    recordVersion: provenance.recordVersion,
    rehydrated: provenance.rehydrated,
    recomputed: provenance.derived,
    notRetained: provenance.notRetained.map((entry) => `${entry.field} — ${entry.reason}`),
    truncated: provenance.truncated.map((entry) => `${entry.field} — kept ${entry.kept.toLocaleString('en-US')}: ${entry.note}`),
  }
}
