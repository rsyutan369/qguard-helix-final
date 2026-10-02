import { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Bell, AlertTriangle, AlertOctagon, CheckCircle, Info, 
  ExternalLink, FileSearch, ShieldAlert, History, ChevronLeft, ChevronRight
} from 'lucide-react';
import type { SecurityEvent } from '@/hooks/use-dashboard';

interface Props {
  events: SecurityEvent[];
  loading: boolean;
  /** True while a realtime channel is actually open. */
  live?: boolean;
}

const SEVERITY_COLORS: Record<SecurityEvent['severity'], string> = {
  critical: 'text-red-500 bg-red-500/10 border-red-500/20',
  high: 'text-orange-500 bg-orange-500/10 border-orange-500/20',
  warning: 'text-amber-400 bg-amber-400/10 border-amber-400/20',
  info: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
  success: 'text-green-500 bg-green-500/10 border-green-500/20',
};

const SEVERITY_ICONS: Record<SecurityEvent['severity'], typeof Info> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  warning: ShieldAlert,
  info: Info,
  success: CheckCircle,
};

const GLASS_PANEL_CLASSES = 'qg-executive-panel group relative overflow-hidden rounded-lg text-white';
const EVENTS_PER_PAGE = 5;

function eventHref(event: SecurityEvent) {
  const type = `${event.eventType || ''} ${event.resourceType || ''}`.toLowerCase();
  if (event.assetId) return `/dashboard/assets?asset=${encodeURIComponent(event.assetId)}`;
  if (type.includes('scan') || type.includes('scanner')) return '/dashboard/scanner';
  if (type.includes('runtime') || type.includes('crypto')) return '/dashboard/runtime-telemetry';
  if (type.includes('vulnerab') || type.includes('finding')) return '/dashboard/quantum-readiness/risk-analysis';
  if (type.includes('migration')) return '/dashboard/live-migration';
  if (type.includes('cert')) return '/dashboard/certificate-telemetry';
  if (type.includes('audit') || type.includes('auth') || type.includes('vault')) return '/dashboard/audit-vault';
  return '/dashboard/telemetry-correlation';
}

/** Date AND time — a bare time-of-day made a week-old event read as today's. */
function eventStamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function SecurityEventsPanel({ events, loading, live = false }: Props) {
  const [currentPage, setCurrentPage] = useState(1);
  const pageCount = Math.max(1, Math.ceil(events.length / EVENTS_PER_PAGE));

  useEffect(() => {
    setCurrentPage((page) => Math.min(page, pageCount));
  }, [pageCount]);

  useEffect(() => {
    setCurrentPage(1);
  }, [events.length]);

  const pageNumbers = useMemo(() => Array.from({ length: pageCount }, (_, index) => index + 1), [pageCount]);
  const safeCurrentPage = Math.min(currentPage, pageCount);
  const pageStart = (safeCurrentPage - 1) * EVENTS_PER_PAGE;
  const visibleEvents = events.slice(pageStart, pageStart + EVENTS_PER_PAGE);
  const eventRangeStart = events.length === 0 ? 0 : pageStart + 1;
  const eventRangeEnd = Math.min(pageStart + visibleEvents.length, events.length);

  if (loading && events.length === 0) {
    return (
      <div className={`h-full flex flex-col items-center justify-center ${GLASS_PANEL_CLASSES}`}>
        <div className="w-8 h-8 border-2 border-gold/30 border-t-gold rounded-full animate-spin mb-3" />
        <p className="text-[10px] text-gold/40 uppercase font-black tracking-widest">Awaiting Telemetry...</p>
      </div>
    );
  }

  return (
    <div className={`flex flex-col h-full overflow-hidden ${GLASS_PANEL_CLASSES}`}>
      <div className="flex justify-between items-center px-4 py-3.5 border-b border-white/5 bg-white/[0.01]">
        <h2 className="text-sm font-black uppercase tracking-[0.2em] text-white/80 flex items-center gap-2">
          <Bell className="h-4 w-4 text-gold" />
          Security Events
        </h2>
        <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full border ${live ? 'bg-gold/10 border-gold/20' : 'bg-white/5 border-white/10'}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${live ? 'bg-gold animate-pulse' : 'bg-white/30'}`} />
          <span className={`text-[9px] font-black uppercase tracking-widest ${live ? 'text-gold' : 'text-white/40'}`}>{live ? 'Real-time' : 'Polling'}</span>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
        <AnimatePresence initial={false} mode="popLayout">
          {events.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center opacity-30 py-12">
                <History className="w-10 h-10 mb-4 text-gold/50" />
                <p className="text-[10px] uppercase font-black tracking-widest">No security events recorded</p>
            </div>
          ) : (
            visibleEvents.map((event) => {
              const Icon = SEVERITY_ICONS[event.severity] || Info;
              const colorClass = SEVERITY_COLORS[event.severity];
              
              return (
                <motion.a
                  key={event.id}
                  href={eventHref(event)}
                  aria-label={`Open ${event.eventType.replace(/_/g, ' ')}`}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className={`p-3 rounded-lg border flex gap-3 relative group/event overflow-hidden no-underline outline-none focus-visible:ring-2 focus-visible:ring-gold/70 hover:border-gold/40 ${colorClass}`}
                >
                  <div className="absolute top-0 right-0 p-1 opacity-0 group-hover/event:opacity-100 transition-opacity">
                    <div className="p-1 rounded bg-white/5" title="View Details">
                        <ExternalLink className="w-3 h-3 text-white/40" />
                    </div>
                  </div>

                  <div className="mt-0.5 shrink-0">
                    <Icon className="w-4 h-4" />
                  </div>
                  
                  <div className="flex-1 space-y-1">
                    <div className="flex justify-between items-start gap-2">
                      <div className="text-[10px] font-black uppercase tracking-wider">{event.eventType.replace(/_/g, ' ')}</div>
                      <div className="text-[8px] font-mono opacity-50 whitespace-nowrap">
                        {eventStamp(event.timestamp)}
                      </div>
                    </div>
                    <p className="text-[11px] text-white/70 leading-relaxed font-medium [display:-webkit-box] [-webkit-line-clamp:2] [-webkit-box-orient:vertical] overflow-hidden">
                      {event.message}
                    </p>
                    {event.resourceName && (
                        <div className="flex items-center gap-1 text-[9px] font-bold text-white/30 uppercase tracking-tighter pt-1">
                            <FileSearch className="w-2.5 h-2.5" />
                            {event.resourceType}: <span className="text-white/50">{event.resourceName}</span>
                        </div>
                      )}
                  </div>
                </motion.a>
              );
            })
          )}
        </AnimatePresence>
      </div>

      <div className="flex flex-col gap-3 border-t border-gold/10 p-3 relative z-20">
        {events.length > EVENTS_PER_PAGE && (
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-[9px] font-mono uppercase tracking-widest text-white/30">
              Showing {eventRangeStart}-{eventRangeEnd} of {events.length}
            </div>
            <div className="flex flex-wrap items-center justify-center gap-1.5">
              <button
                type="button"
                onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
                disabled={safeCurrentPage === 1}
                className="inline-flex h-7 w-7 items-center justify-center rounded border border-white/10 bg-white/[0.03] text-white/45 transition-colors hover:border-gold/35 hover:text-gold disabled:cursor-not-allowed disabled:opacity-30"
                aria-label="Previous security events page"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </button>
              {pageNumbers.map((page) => (
                <button
                  key={page}
                  type="button"
                  onClick={() => setCurrentPage(page)}
                  aria-current={safeCurrentPage === page ? 'page' : undefined}
                  className={`h-7 min-w-7 rounded border px-2 text-[10px] font-black transition-colors ${
                    safeCurrentPage === page
                      ? 'border-gold/50 bg-gold/15 text-gold'
                      : 'border-white/10 bg-white/[0.03] text-white/40 hover:border-gold/35 hover:text-gold'
                  }`}
                >
                  {page}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setCurrentPage((page) => Math.min(pageCount, page + 1))}
                disabled={safeCurrentPage === pageCount}
                className="inline-flex h-7 w-7 items-center justify-center rounded border border-white/10 bg-white/[0.03] text-white/45 transition-colors hover:border-gold/35 hover:text-gold disabled:cursor-not-allowed disabled:opacity-30"
                aria-label="Next security events page"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}
        <div className="text-center">
        <a href="/dashboard/audit-vault" className="text-[9px] font-black uppercase tracking-[0.2em] text-white/40 hover:text-gold transition-colors no-underline">
            View All Audit Logs
        </a>
        </div>
      </div>
    </div>
  );
}
