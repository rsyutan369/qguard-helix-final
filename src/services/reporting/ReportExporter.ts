import { format as formatDate } from 'date-fns';
import type { EnterpriseAssessmentReport, ReportFormat } from './schemas/ReportSchema';

const MIME: Record<ReportFormat, string> = {
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  csv: 'text/csv',
  json: 'application/json',
  html: 'text/html',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

export interface ExportResult {
  blob: Blob;
  filename: string;
  mime: string;
  format: ReportFormat;
}

/**
 * Dispatch the unified report model to the requested export format. Each
 * exporter (and its heavy library) is lazy-loaded on demand so a single format
 * only pulls in what it needs and one library can never block the others.
 */
export async function exportReport(report: EnterpriseAssessmentReport, fmt: ReportFormat): Promise<ExportResult> {
  let blob: Blob;
  switch (fmt) {
    case 'pdf': blob = await (await import('./exporters/PdfExporter')).exportPdf(report); break;
    case 'docx': blob = await (await import('./exporters/DocxExporter')).exportDocx(report); break;
    case 'xlsx': blob = await (await import('./exporters/ExcelExporter')).exportExcel(report); break;
    case 'pptx': blob = await (await import('./exporters/PptExporter')).exportPptx(report); break;
    case 'csv': blob = (await import('./exporters/CsvExporter')).exportCsv(report); break;
    case 'html': blob = (await import('./exporters/HtmlExporter')).exportHtml(report); break;
    case 'json':
    default: blob = (await import('./exporters/JsonExporter')).exportJson(report); break;
  }
  const stamp = formatDate(new Date(), 'yyyy-MM-dd');
  const filename = `${report.meta.kind}-report-${stamp}-v${report.meta.version}.${fmt}`;
  return { blob, filename, mime: MIME[fmt], format: fmt };
}

/** Trigger a browser download for an export result. */
export function downloadResult(result: ExportResult): void {
  const url = URL.createObjectURL(result.blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = result.filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/** Open an HTML report blob in a new tab for preview. */
export async function previewHtml(report: EnterpriseAssessmentReport): Promise<void> {
  const { exportHtml } = await import('./exporters/HtmlExporter');
  const blob = exportHtml(report);
  const url = URL.createObjectURL(blob);
  window.open(url, '_blank');
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
