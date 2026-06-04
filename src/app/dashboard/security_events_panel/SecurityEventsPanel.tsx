import { useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Bell, AlertTriangle, Shield, CheckCircle, Info, 
  ExternalLink, FileSearch, ShieldAlert, History
} from 'lucide-react';
import type { SecurityEvent } from '@/hooks/use-dashboard';

interface Props {
  events: SecurityEvent[];
  loading: boolean;
}

const SEVERITY_COLORS = {
  critical: 'text-red-500 bg-red-500/10 border-red-500/20',
  warning: 'text-orange-500 bg-orange-500/10 border-orange-500/20',
  info: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
  success: 'text-green-500 bg-green-500/10 border-green-500/20',
};

const SEVERITY_ICONS = {
  critical: AlertTriangle,
  warning: ShieldAlert,
  info: Info,
  success: CheckCircle,
};

const GLASS_PANEL_CLASSES = 'qg-executive-panel group relative overflow-hidden rounded-lg text-white';

function eventHref(event: SecurityEvent) {
  const type = `${event.eventType || ''} ${event.resourceType || ''}`.toLowerCase();
  if (event.assetId) return `/dashboard/assets?asset=${encodeURIComponent(event.assetId)}`;
  if (type.includes('scan') || type.includes('scanner')) return '/dashboard/scanner';
  if (type.includes('runtime') || type.includes('crypto')) return '/dashboard/runtime-telemetry';
  if (type.includes('vulnerab') || type.includes('finding')) return '/dashboard/vulnerabilities';
  if (type.includes('migration')) return '/dashboard/live-migration';
  if (type.includes('cert')) return '/dashboard/certificate-telemetry';
  if (type.includes('audit') || type.includes('auth') || type.includes('vault')) return '/dashboard/audit-vault';
  return '/dashboard/telemetry-correlation';
}

export default function SecurityEventsPanel({ events, loading }: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);

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
        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-gold/10 border border-gold/20">
          <span className="w-1.5 h-1.5 bg-gold rounded-full animate-pulse" />
          <span className="text-[9px] font-black text-gold uppercase tracking-widest">Real-time</span>
        </div>
      </div>
      <div 
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar"
      >
        <AnimatePresence initial={false}>
          {events.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center opacity-30 py-12">
                <History className="w-10 h-10 mb-4 text-gold/50" />
                <p className="text-[10px] uppercase font-black tracking-widest">No recent security events</p>
            </div>
          ) : (
            events.map((event) => {
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
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                    <p className="text-[11px] text-white/70 leading-relaxed font-medium">
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

      <div className="p-3 border-t border-gold/10 text-center relative z-20">
        <a href="/dashboard/audit-vault" className="text-[9px] font-black uppercase tracking-[0.2em] text-white/40 hover:text-gold transition-colors no-underline">
            View All Audit Logs
        </a>
      </div>
    </div>
  );
}
