import {
  AlignmentType,
  Document,
  Footer,
  Header,
  HeadingLevel,
  ImageRun,
  Packer,
  PageNumber,
  Paragraph,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
  BorderStyle,
} from 'docx';
import type { EnterpriseAssessmentReport, ReportTable } from '../schemas/ReportSchema';

function dataUrlToBytes(dataUrl: string): Uint8Array {
  const base64 = dataUrl.split(',')[1] || '';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const INK = '0F172A';
const MUTED = '64748B';

function heading(text: string): Paragraph {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 120 }, children: [new TextRun({ text, color: INK, bold: true })] });
}

function para(text: string, color = '334155'): Paragraph {
  return new Paragraph({ spacing: { after: 120 }, children: [new TextRun({ text, color, size: 21 })] });
}

function docTable(table: ReportTable): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: {
      top: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' },
      bottom: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' },
      left: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' },
      right: { style: BorderStyle.SINGLE, size: 1, color: 'E2E8F0' },
      insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: 'EDF2F7' },
      insideVertical: { style: BorderStyle.SINGLE, size: 1, color: 'EDF2F7' },
    },
    rows: [
      new TableRow({
        tableHeader: true,
        children: table.columns.map((column) => new TableCell({ shading: { fill: '0F172A' }, children: [new Paragraph({ children: [new TextRun({ text: String(column), bold: true, color: 'FFFFFF', size: 18 })] })] })),
      }),
      ...table.rows.map((row) => new TableRow({ children: row.map((cell) => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: String(cell), size: 18, color: '334155' })] })] })) })),
    ],
  });
}

function chartParagraphs(report: EnterpriseAssessmentReport): Paragraph[] {
  const out: Paragraph[] = [];
  for (const chart of report.charts) {
    try {
      out.push(new Paragraph({ spacing: { before: 160, after: 40 }, children: [new ImageRun({ type: 'png', data: dataUrlToBytes(chart.dataUrl), transformation: { width: 460, height: 260 } })] }));
      out.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 }, children: [new TextRun({ text: chart.title, color: MUTED, size: 18, italics: true })] }));
    } catch {
      out.push(para(`${chart.title}: Evidence Not Available`, MUTED));
    }
  }
  return out;
}

/**
 * Programmatic DOCX export with branded cover, running header/footer + page
 * numbers, KPI/finding/compliance/roadmap tables and embedded chart images.
 */
export async function exportDocx(report: EnterpriseAssessmentReport): Promise<Blob> {
  const { branding, meta } = report;

  const coverChildren: Paragraph[] = [];
  if (branding.companyLogo) {
    try {
      coverChildren.push(new Paragraph({ spacing: { after: 240 }, children: [new ImageRun({ type: 'png', data: dataUrlToBytes(branding.companyLogo), transformation: { width: 160, height: 60 } })] }));
    } catch {
      /* logo not embeddable */
    }
  }
  coverChildren.push(
    new Paragraph({ spacing: { after: 80 }, children: [new TextRun({ text: branding.classification, bold: true, color: 'FFFFFF', size: 16, highlight: 'black' })] }),
    new Paragraph({ spacing: { before: 200, after: 60 }, children: [new TextRun({ text: meta.title, bold: true, size: 52, color: INK })] }),
    new Paragraph({ spacing: { after: 240 }, children: [new TextRun({ text: `${branding.companyName}${branding.businessUnit ? ` — ${branding.businessUnit}` : ''}`, size: 26, color: MUTED })] }),
    para(`Report ID: ${meta.id}`, MUTED),
    para(`Version: ${meta.version}  |  Generated: ${new Date(meta.generatedAt).toLocaleString()}  |  By: ${meta.generatedBy}`, MUTED),
    para(`Report Owner: ${branding.reportOwner || 'Evidence Not Available'}  |  Reviewer: ${branding.reviewer || 'Evidence Not Available'}`, MUTED),
  );

  const kpiTable: ReportTable = { title: 'KPIs', columns: ['KPI', 'Value', 'Level'], rows: report.kpis.map((kpi) => [kpi.label, `${kpi.value}${kpi.unit || ''}`, kpi.level || '—']) };
  const findingsTable: ReportTable = {
    title: 'Findings',
    columns: ['Severity', 'Title', 'Evidence', 'Recommendation'],
    rows: report.findings.length ? report.findings.map((f) => [f.severity.toUpperCase(), f.title, f.evidence, f.recommendation]) : [['—', 'Evidence Not Available', '—', '—']],
  };
  const complianceTable: ReportTable = { title: 'Compliance', columns: ['Framework', 'Control', 'Status', 'Detail'], rows: report.compliance.map((c) => [c.framework, c.control, c.status, c.detail]) };
  const roadmapTable: ReportTable = { title: 'Roadmap', columns: ['Phase', 'Description', 'Status', 'Effort (wks)'], rows: report.roadmap.map((p) => [p.phase, p.description, p.status, p.effortWeeks]) };

  const doc = new Document({
    creator: branding.companyName,
    title: meta.title,
    sections: [
      {
        properties: {},
        headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: `${branding.companyName} · ${branding.classification}`, color: MUTED, size: 16 })] })] }) },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [new TextRun({ text: `${meta.title} · v${meta.version} · Page `, color: MUTED, size: 16 }), new TextRun({ children: [PageNumber.CURRENT], color: MUTED, size: 16 }), new TextRun({ text: ' of ', color: MUTED, size: 16 }), new TextRun({ children: [PageNumber.TOTAL_PAGES], color: MUTED, size: 16 })],
              }),
            ],
          }),
        },
        children: [
          ...coverChildren,
          heading('Executive Summary'),
          para(report.executiveSummary),
          ...(branding.customNotes ? [para(`Notes: ${branding.customNotes}`, MUTED)] : []),
          heading('Key Performance Indicators'),
          docTable(kpiTable),
          heading('Visual Analysis'),
          ...chartParagraphs(report),
          heading('Findings'),
          docTable(findingsTable),
          heading('PQC Readiness'),
          para(report.pqcReadiness.summary),
          docTable(report.pqcReadiness.table),
          heading('HNDL Exposure'),
          para(report.hndl.summary),
          docTable(report.hndl.table),
          heading('Asset & CBOM Inventory'),
          docTable(report.assets),
          docTable(report.cbom),
          heading('Compliance'),
          docTable(complianceTable),
          heading('Remediation Plan'),
          docTable(report.remediation),
          heading('Migration Roadmap'),
          docTable(roadmapTable),
          heading('Evidence Sources'),
          para(report.evidence.sources.join(' · '), MUTED),
          para(report.evidence.notes, MUTED),
          ...(report.integrity ? [para(`Integrity (${report.integrity.algorithm}): ${report.integrity.hash}`, MUTED)] : []),
        ],
      },
    ],
  });

  return Packer.toBlob(doc);
}
