import { PhoneIncoming, PhoneOff, Video } from "lucide-react";

export function IncomingCallModal({ callerName, onAccept, onReject }: { callerName: string; onAccept: () => void; onReject: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-xl border border-white/30 bg-white p-6 text-center shadow-soft">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-cyan-50 text-cyan-600"><Video size={28} /></div>
        <div className="mt-4 text-lg font-bold text-ink-950">{callerName}</div>
        <div className="text-sm text-ink-600">Incoming quantum-encrypted video call</div>
        <div className="mt-6 flex justify-center gap-4">
          <button type="button" onClick={onReject} className="flex h-12 w-12 items-center justify-center rounded-full bg-rose-500 text-white hover:bg-rose-600"><PhoneOff size={20} /></button>
          <button type="button" onClick={onAccept} className="flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500 text-white hover:bg-emerald-600"><PhoneIncoming size={20} /></button>
        </div>
      </div>
    </div>
  );
}