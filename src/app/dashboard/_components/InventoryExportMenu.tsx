/**
 * Inventory export menu — shared by the Assets register and the CBOM Explorer.
 *
 * One component so both pages offer the same formats, the same wording and the
 * same accuracy guarantee. The caller passes the rows it is CURRENTLY rendering
 * (post-filter, post-selection) plus the summary its KPI cards read, so the
 * exported document can never disagree with the screen it was launched from.
 */
import * as React from 'react';
import { Check, ChevronDown, FileCode2, FileDown, FileSpreadsheet, FileText, Loader2 } from 'lucide-react';
import {
  buildInventoryReport,
  type InventoryBuildInput,
  type InventoryReport,
} from '@/services/reporting/InventoryReport';
import {
  downloadInventory,
  exportInventory,
  type InventoryFormat,
} from '@/services/reporting/exporters/InventoryExporters';

type FormatSpec = {
  format: InventoryFormat;
  label: string;
  detail: string;
  icon: React.ComponentType<{ className?: string }>;
};

const FORMATS: FormatSpec[] = [
  { format: 'pdf', label: 'PDF', detail: 'Branded, print-ready register', icon: FileText },
  { format: 'xlsx', label: 'Excel', detail: 'Filterable workbook, one sheet per table', icon: FileSpreadsheet },
  { format: 'docx', label: 'Word', detail: 'Editable document for reports', icon: FileText },
  { format: 'html', label: 'HTML', detail: 'Self-contained, shareable page', icon: FileCode2 },
  { format: 'csv', label: 'CSV', detail: 'Raw rows for analysis', icon: FileSpreadsheet },
  { format: 'json', label: 'JSON', detail: 'Full model incl. reconciliation', icon: FileCode2 },
];

/**
 * Generic six-format export menu.
 *
 * Takes an already-built report document, so every surface — the Assets
 * register, the CBOM Explorer, Live Migration — offers the same formats,
 * wording and accuracy guarantee from one implementation.
 */
export function ReportExportMenu({
  buildReport,
  label,
  disabled,
  align = 'right',
  title = 'Export inventory',
  note = 'Built from the rows shown here. Every document carries a reconciliation table proving it matches this view.',
  className,
}: {
  /** Built lazily on click so a large data set is not serialised on every render. */
  buildReport: () => InventoryReport;
  label: string;
  disabled?: boolean;
  align?: 'left' | 'right';
  title?: string;
  note?: string;
  className?: string;
}) {
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState<InventoryFormat | null>(null);
  const [done, setDone] = React.useState<InventoryFormat | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const rootRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onPointer);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onPointer); document.removeEventListener('keydown', onKey); };
  }, [open]);

  const run = async (format: InventoryFormat) => {
    setBusy(format);
    setError(null);
    try {
      const result = await exportInventory(buildReport(), format);
      downloadInventory(result);
      setDone(format);
      window.setTimeout(() => setDone(null), 2200);
      setOpen(false);
    } catch (cause) {
      // A failed export must say so — a silent no-op reads as "nothing to export".
      setError(cause instanceof Error ? cause.message : 'Export failed');
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="relative" ref={rootRef}>
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((value) => !value)}
        aria-haspopup="menu"
        aria-expanded={open}
        className={className ?? "inline-flex items-center gap-1.5 rounded-md border border-cyan-400/30 bg-cyan-400/10 px-3 py-1.5 text-[11px] font-bold uppercase tracking-wide text-cyan-200 transition-colors hover:border-cyan-300/60 hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-40"}
      >
        {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileDown className="h-3.5 w-3.5" />}
        {label}
        <ChevronDown className={`h-3 w-3 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div
          role="menu"
          className={`absolute z-50 mt-1.5 w-72 overflow-hidden rounded-lg border border-white/10 bg-[#070c16] shadow-2xl ${align === 'right' ? 'right-0' : 'left-0'}`}
        >
          <div className="border-b border-white/8 px-3 py-2">
            <p className="text-[10px] font-black uppercase tracking-[0.14em] text-white/45">{title}</p>
            <p className="mt-0.5 text-[10px] leading-snug text-white/35">{note}</p>
          </div>
          {FORMATS.map((spec) => {
            const Icon = spec.icon;
            return (
              <button
                key={spec.format}
                type="button"
                role="menuitem"
                disabled={busy !== null}
                onClick={() => void run(spec.format)}
                className="flex w-full items-center gap-2.5 px-3 py-2 text-left transition-colors hover:bg-white/[0.05] disabled:opacity-50"
              >
                <Icon className="h-3.5 w-3.5 shrink-0 text-cyan-300/80" />
                <span className="min-w-0 flex-1">
                  <span className="block text-[11.5px] font-bold text-white/85">{spec.label}</span>
                  <span className="block truncate text-[9.5px] text-white/40">{spec.detail}</span>
                </span>
                {busy === spec.format && <Loader2 className="h-3 w-3 animate-spin text-cyan-300" />}
                {done === spec.format && <Check className="h-3 w-3 text-emerald-400" />}
              </button>
            );
          })}
          {error && (
            <p role="alert" className="border-t border-red-400/20 bg-red-500/10 px-3 py-2 text-[10px] text-red-300">
              {error}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Inventory flavour — unchanged API for the Assets register and CBOM Explorer.
 */
export function InventoryExportMenu({
  build,
  label,
  disabled,
  align = 'right',
}: {
  /** Built lazily on click so a large register is not serialised on every render. */
  build: () => InventoryBuildInput;
  label: string;
  disabled?: boolean;
  align?: 'left' | 'right';
}) {
  return (
    <ReportExportMenu
      buildReport={() => buildInventoryReport(build())}
      label={label}
      disabled={disabled}
      align={align}
    />
  );
}
