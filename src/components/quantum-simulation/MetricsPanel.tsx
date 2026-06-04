import { motion } from 'motion/react';
import { TargetType } from '../../types';
import { Scenario } from '../../data/scenario';
import { ShieldCheck, Flame, Network, Gauge } from 'lucide-react';

interface MetricsPanelProps {
  activeStep: number;
  activeScenario: Scenario;
  activeTarget: TargetType;
  packetsCaptured: number;
}

export default function MetricsPanel({ activeStep, activeScenario, activeTarget, packetsCaptured }: MetricsPanelProps) {
  // Compute simulated dynamic scores based on scenario parameters
  const baseRisk = (activeScenario.id.charCodeAt(0) % 12) + 8;
  const riskIndex = Math.min(99, activeStep * 14 + baseRisk);
  const readinessPercentage = Math.max(12, 100 - riskIndex);

  // Derive target cipher based on selected scenario
  const cryptoCipher = activeScenario.id === 'hndl' ? 'RSA-2048 / ECDSA-256' :
                       activeScenario.id === 'rsa-breaking' ? 'RSA-2048 / Diffie-Hellman' :
                       activeScenario.id === 'tls-compromise' ? 'ECDHE-RSA / TLS-1.2' :
                       activeScenario.id === 'vpn-compromise' ? 'IKEv2 / IPsec-RSA' :
                       activeScenario.id === 'symmetric-entropy' ? 'AES-GCM-256 / SHA-256' :
                       activeScenario.id === 'qkd-intercept' ? 'QKD / BB84 Protocol' :
                       'RSA-4096 / ECC-384';

  return (
    <div id="metrics-panel" className="bg-white/70 backdrop-blur-md rounded-2xl p-5 border border-slate-100 shadow-xs h-full font-sans flex flex-col justify-between">
      <div>
        <div className="flex justify-between items-center pb-3 border-b border-slate-100">
          <h3 className="text-xs font-bold tracking-wider text-slate-900 uppercase flex items-center gap-1.5">
            <Gauge className="w-4 h-4 text-indigo-500" />
            Vulnerability Metrics
          </h3>
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">Real-Time</span>
        </div>

        {/* Big visual score display */}
        <div className="grid grid-cols-2 gap-4 mt-4">
          
          {/* Card 1: Quantum Threat Index */}
          <div className="p-3.5 bg-rose-500/5 border border-rose-100 hover:bg-rose-500/10 rounded-xl transition-all duration-200">
            <div className="flex items-center gap-1 text-rose-600">
              <Flame className="w-3.5 h-3.5" />
              <span className="text-[9px] font-mono font-bold uppercase">Threat Index</span>
            </div>
            <p className="text-2xl font-extrabold text-rose-500 font-display mt-1 tracking-tight">
              {riskIndex}%
            </p>
            <p className="text-[9px] text-slate-400 mt-1 uppercase font-mono tracking-wider font-semibold">
              CRITICAL LEVEL
            </p>
          </div>

          {/* Card 2: Cryptographic Rigidity */}
          <div className="p-3.5 bg-emerald-500/5 border border-emerald-100 hover:bg-emerald-500/10 rounded-xl transition-all duration-200">
            <div className="flex items-center gap-1 text-emerald-600">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span className="text-[9px] font-mono font-bold uppercase">Hardening</span>
            </div>
            <p className="text-2xl font-extrabold text-emerald-600 font-display mt-1 tracking-tight">
              {readinessPercentage}%
            </p>
            <p className="text-[9px] text-slate-400 mt-1 uppercase font-mono tracking-wider font-semibold">
              QUANTUM SAFE
            </p>
          </div>

        </div>

        {/* Bottom matrix list */}
        <div className="mt-4.5 space-y-2 text-xs">
          <div className="flex justify-between items-center py-2 border-b border-slate-100">
            <span className="text-slate-500 font-medium">Core Target Cipher:</span>
            <span className="font-mono font-bold text-slate-700 bg-slate-100 px-2 py-0.5 rounded-sm">
              {cryptoCipher}
            </span>
          </div>
          <div className="flex justify-between items-center py-2 border-b border-slate-100">
            <span className="text-slate-500 font-medium">Exfiltration Channels:</span>
            <span className="font-mono text-indigo-600 font-bold">
              4.5 GHz Matrix Loop
            </span>
          </div>
          <div className="flex justify-between items-center py-2">
            <span className="text-slate-500 font-medium">Interception Efficiency:</span>
            <span className="font-mono text-emerald-600 font-bold text-right">
              {Math.min(99.8, (packetsCaptured * 0.005 + 88.5)).toFixed(2)}%
            </span>
          </div>
        </div>
      </div>

      <div className="mt-4 pt-3.5 border-t border-slate-100 text-[10px] text-slate-400 font-mono text-center">
        Telemetry bound client ID: pqc-sim-agent-v1
      </div>

    </div>
  );
}
