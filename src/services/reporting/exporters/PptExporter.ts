import pptxgen from 'pptxgenjs';
import type { EnterpriseAssessmentReport } from '../schemas/ReportSchema';

const INK = '0F172A';
const BRAND = '2478FF';
const MUTED = '64748B';
const SEV_COLOR: Record<string, string> = { critical: 'DC2626', high: 'EA580C', medium: 'D97706', low: '16A34A', info: '2563FF' };

/**
 * Board-ready PPTX deck: cover, KPI summary, visual analysis slides (one per
 * chart), top findings and migration roadmap. Built from the unified model.
 */
export async function exportPptx(report: EnterpriseAssessmentReport): Promise<Blob> {
  const pptx = new pptxgen();
  pptx.author = report.branding.companyName;
  pptx.company = report.branding.companyName;
  pptx.title = report.meta.title;
  pptx.layout = 'LAYOUT_WIDE';

  const footer = (slide: pptxgen.Slide) => {
    slide.addText(`${report.branding.companyName} · ${report.branding.classification} · v${report.meta.version}`, { x: 0.4, y: 7.0, w: 12.5, h: 0.3, fontSize: 9, color: MUTED, align: 'left' });
  };

  // Cover
  const cover = pptx.addSlide();
  cover.background = { color: 'F8FAFC' };
  if (report.branding.companyLogo) {
    try {
      cover.addImage({ data: report.branding.companyLogo, x: 0.6, y: 0.5, w: 2.2, h: 0.8 });
    } catch {
      /* logo not embeddable */
    }
  }
  cover.addText(report.branding.classification, { x: 0.6, y: 1.6, w: 3, h: 0.4, fontSize: 11, color: 'FFFFFF', fill: { color: INK }, align: 'center' });
  cover.addText(report.meta.title, { x: 0.6, y: 2.4, w: 12, h: 1.2, fontSize: 40, bold: true, color: INK });
  cover.addText(`${report.branding.companyName}${report.branding.businessUnit ? ` — ${report.branding.businessUnit}` : ''}`, { x: 0.6, y: 3.6, w: 12, h: 0.6, fontSize: 20, color: MUTED });
  cover.addText(`Version ${report.meta.version}  ·  Generated ${new Date(report.meta.generatedAt).toLocaleString()}  ·  ${report.meta.generatedBy}`, { x: 0.6, y: 4.4, w: 12, h: 0.4, fontSize: 12, color: MUTED });
  footer(cover);

  // KPI summary
  const kpiSlide = pptx.addSlide();
  kpiSlide.addText('Key Performance Indicators', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
  report.kpis.slice(0, 8).forEach((kpi, index) => {
    const col = index % 4;
    const row = Math.floor(index / 4);
    const x = 0.5 + col * 3.1;
    const y = 1.3 + row * 2.4;
    kpiSlide.addShape(pptx.ShapeType.roundRect, { x, y, w: 2.9, h: 2.1, fill: { color: 'FFFFFF' }, line: { color: 'E2E8F0', width: 1 }, rectRadius: 0.08 });
    kpiSlide.addText(`${kpi.value}${kpi.unit || ''}`, { x, y: y + 0.3, w: 2.9, h: 0.9, fontSize: 32, bold: true, color: INK, align: 'center' });
    kpiSlide.addText(kpi.label, { x, y: y + 1.2, w: 2.9, h: 0.5, fontSize: 11, color: MUTED, align: 'center' });
    if (kpi.level) kpiSlide.addText(kpi.level, { x, y: y + 1.6, w: 2.9, h: 0.4, fontSize: 11, color: BRAND, align: 'center' });
  });
  footer(kpiSlide);

  // Executive summary
  const summary = pptx.addSlide();
  summary.addText('Executive Summary', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
  summary.addText(report.executiveSummary, { x: 0.5, y: 1.1, w: 12.3, h: 5, fontSize: 15, color: '334155', align: 'left', valign: 'top' });
  footer(summary);

  // Visual analysis — one slide per chart
  for (const chart of report.charts) {
    const slide = pptx.addSlide();
    slide.addText(chart.title, { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 22, bold: true, color: INK });
    try {
      slide.addImage({ data: chart.dataUrl, x: 2.4, y: 1.1, w: 8.5, h: 5.2, sizing: { type: 'contain', w: 8.5, h: 5.2 } });
    } catch {
      slide.addText('Evidence Not Available', { x: 0.5, y: 3, w: 12, h: 1, fontSize: 18, color: MUTED, align: 'center' });
    }
    footer(slide);
  }

  // Top findings
  const findingsSlide = pptx.addSlide();
  findingsSlide.addText('Top Findings', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
  const rows: pptxgen.TableRow[] = [
    [
      { text: 'Severity', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Finding', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Recommendation', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
    ],
    ...(report.findings.length
      ? report.findings.slice(0, 8).map((finding) => [
          { text: finding.severity.toUpperCase(), options: { color: 'FFFFFF', fill: { color: SEV_COLOR[finding.severity] || MUTED }, bold: true } },
          { text: finding.title, options: { color: '334155' } },
          { text: finding.recommendation, options: { color: '334155' } },
        ])
      : [[{ text: 'Evidence Not Available', options: { colspan: 3, color: MUTED } }]]),
  ];
  findingsSlide.addTable(rows, { x: 0.5, y: 1.1, w: 12.3, colW: [1.6, 5, 5.7], fontSize: 11, border: { type: 'solid', color: 'E2E8F0', pt: 1 }, valign: 'middle' });
  footer(findingsSlide);

  // Roadmap
  const roadmapSlide = pptx.addSlide();
  roadmapSlide.addText('PQC Migration Roadmap', { x: 0.5, y: 0.3, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
  const roadmapRows: pptxgen.TableRow[] = [
    [
      { text: 'Phase', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Description', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Status', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
      { text: 'Weeks', options: { bold: true, color: 'FFFFFF', fill: { color: INK } } },
    ],
    ...report.roadmap.map((phase) => [
      { text: phase.phase, options: { bold: true, color: INK } },
      { text: phase.description, options: { color: '334155' } },
      { text: phase.status, options: { color: BRAND } },
      { text: String(phase.effortWeeks), options: { color: '334155', align: 'center' as const } },
    ]),
  ];
  roadmapSlide.addTable(roadmapRows, { x: 0.5, y: 1.1, w: 12.3, colW: [2, 7, 2, 1.3], fontSize: 11, border: { type: 'solid', color: 'E2E8F0', pt: 1 }, valign: 'middle' });
  footer(roadmapSlide);

  const blob = (await pptx.write({ outputType: 'blob' })) as Blob;
  return blob;
}
