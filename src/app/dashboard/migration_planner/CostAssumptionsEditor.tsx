/**
 * Cost assumptions editor.
 *
 * Every currency figure the platform prints for a migration programme is a
 * planning estimate built on four assumptions and, optionally, the tenant's own
 * approved budget. Those assumptions used to be hardcoded and invisible, so a
 * customer whose real engineer rate is not $165/hr saw a forecast they could
 * neither correct nor audit. This is where they correct it.
 *
 * Leaving a field blank means "use the published default" — deliberately
 * distinct from entering 0, which is a real value a tenant may legitimately want
 * (e.g. valuing untagged assets at nothing).
 */
import * as React from 'react';
import { Loader2, RotateCcw, X } from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import {
  COST_ASSUMPTION_LIMITS,
  DEFAULT_COST_ASSUMPTIONS,
  type CostAssumptions,
} from '@/lib/migration/cost-model';

const CYAN = '#22d3ee';

type FieldKey = 'blendedRateUsd' | 'hoursPerWeek' | 'valuePerCriticalAssetUsd' | 'valuePerStandardAssetUsd' | 'budgetUsd';

const FIELDS: Array<{
  key: FieldKey;
  label: string;
  hint: string;
  prefix?: string;
  suffix?: string;
}> = [
  {
    key: 'blendedRateUsd',
    label: 'Blended engineer rate',
    hint: 'Fully-loaded cost of one engineer hour. Drives every cost line.',
    prefix: '$',
    suffix: '/hr',
  },
  {
    key: 'hoursPerWeek',
    label: 'Productive hours per week',
    hint: 'Hours per engineer actually available for migration work.',
    suffix: 'hrs',
  },
  {
    key: 'valuePerCriticalAssetUsd',
    label: 'Value per business-critical asset',
    hint: 'Loss exposure if a business-critical asset is compromised.',
    prefix: '$',
  },
  {
    key: 'valuePerStandardAssetUsd',
    label: 'Value per standard asset',
    hint: 'Loss exposure for an asset without a critical/high criticality tag.',
    prefix: '$',
  },
  {
    key: 'budgetUsd',
    label: 'Approved budget (optional)',
    hint: 'Your allocated programme budget. Leave blank if none — the platform will not invent one.',
    prefix: '$',
  },
];

export function CostAssumptionsEditor({
  open,
  onClose,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [values, setValues] = React.useState<Record<FieldKey, string>>({
    blendedRateUsd: '',
    hoursPerWeek: '',
    valuePerCriticalAssetUsd: '',
    valuePerStandardAssetUsd: '',
    budgetUsd: '',
  });
  const [loading, setLoading] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [source, setSource] = React.useState<'default' | 'tenant'>('default');

  React.useEffect(() => {
    if (!open || !token) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch('/api/v1/cost-assumptions', { headers: { Authorization: `Bearer ${token}` } })
      .then((response) => response.json())
      .then((payload) => {
        if (cancelled) return;
        const assumptions = payload?.data?.assumptions as CostAssumptions | undefined;
        if (!assumptions) return;
        setSource(assumptions.source);
        // Only pre-fill fields the tenant actually set; defaults stay as
        // placeholder text so "unset" and "set to the default value" stay
        // visually distinct.
        setValues({
          blendedRateUsd: assumptions.source === 'tenant' ? String(assumptions.blendedRateUsd) : '',
          hoursPerWeek: assumptions.source === 'tenant' ? String(assumptions.hoursPerWeek) : '',
          valuePerCriticalAssetUsd: assumptions.source === 'tenant' ? String(assumptions.valuePerCriticalAssetUsd) : '',
          valuePerStandardAssetUsd: assumptions.source === 'tenant' ? String(assumptions.valuePerStandardAssetUsd) : '',
          budgetUsd: assumptions.budgetUsd === null ? '' : String(assumptions.budgetUsd),
        });
      })
      .catch(() => {
        if (!cancelled) setError('Could not load current assumptions.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, token]);

  if (!open) return null;

  const submit = async (reset: boolean) => {
    if (!token) return;
    setSaving(true);
    setError(null);
    try {
      const body: Record<string, number | null> = {};
      if (!reset) {
        for (const field of FIELDS) {
          const raw = values[field.key].trim();
          // '' clears the override back to the published default.
          body[field.key] = raw === '' ? null : Number(raw);
        }
      }
      const response = await fetch('/api/v1/cost-assumptions', {
        method: reset ? 'DELETE' : 'PUT',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: reset ? undefined : JSON.stringify(body),
      });
      const payload = await response.json();
      if (!response.ok) {
        setError(payload?.error?.message || 'Could not save assumptions.');
        return;
      }
      onSaved();
      onClose();
    } catch {
      setError('Could not save assumptions.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="w-full max-w-lg overflow-hidden rounded-xl border border-white/10 bg-[#080d17] shadow-2xl">
        <div className="flex items-center justify-between border-b border-white/8 px-5 py-3.5">
          <div>
            <h2 className="text-sm font-bold text-white/90">Cost & Value Assumptions</h2>
            <p className="mt-0.5 text-[10.5px] text-white/45">
              {source === 'tenant' ? 'Using your organisation’s values' : 'Using platform defaults'} · blank = default
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded p-1 text-white/45 transition-colors hover:bg-white/5 hover:text-white/80">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-[60vh] space-y-3.5 overflow-y-auto px-5 py-4">
          {loading ? (
            <div className="flex items-center gap-2 py-6 text-xs text-white/50">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading assumptions…
            </div>
          ) : (
            FIELDS.map((field) => {
              const limits = COST_ASSUMPTION_LIMITS[field.key];
              const fallback = DEFAULT_COST_ASSUMPTIONS[field.key];
              return (
                <label key={field.key} className="block">
                  <span className="text-[11px] font-semibold text-white/75">{field.label}</span>
                  <div className="mt-1 flex items-center gap-1.5 rounded-md border border-white/10 bg-black/30 px-2.5 focus-within:border-cyan-400/50">
                    {field.prefix ? <span className="text-xs text-white/40">{field.prefix}</span> : null}
                    <input
                      type="number"
                      inputMode="decimal"
                      min={limits.min}
                      max={limits.max}
                      value={values[field.key]}
                      placeholder={fallback === null ? 'none' : String(fallback)}
                      onChange={(event) => setValues((previous) => ({ ...previous, [field.key]: event.target.value }))}
                      className="w-full bg-transparent py-2 font-mono text-sm text-white/90 outline-none placeholder:text-white/25"
                    />
                    {field.suffix ? <span className="text-xs text-white/40">{field.suffix}</span> : null}
                  </div>
                  <span className="mt-1 block text-[10px] leading-snug text-white/40">{field.hint}</span>
                </label>
              );
            })
          )}

          {error ? (
            <p role="alert" className="rounded-md border border-red-400/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-300">
              {error}
            </p>
          ) : null}

          <p className="rounded-md border border-white/8 bg-white/[0.02] px-3 py-2 text-[10px] leading-relaxed text-white/45">
            These are planning inputs, not measured spend. They change every cost and business-value figure on the
            Migration Planner, Quantum Readiness Executive, AI Migration Advisor and Executive Command Center — and the
            exported reports — so all surfaces stay in agreement.
          </p>
        </div>

        <div className="flex items-center justify-between gap-2 border-t border-white/8 px-5 py-3">
          <button
            type="button"
            onClick={() => submit(true)}
            disabled={saving}
            className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[11px] font-semibold text-white/50 transition-colors hover:bg-white/5 hover:text-white/80 disabled:opacity-50"
          >
            <RotateCcw className="h-3 w-3" /> Reset to defaults
          </button>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md px-3 py-1.5 text-[11px] font-semibold text-white/60 transition-colors hover:bg-white/5 hover:text-white/85"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => submit(false)}
              disabled={saving || loading}
              className="inline-flex items-center gap-1.5 rounded-md px-3.5 py-1.5 text-[11px] font-bold text-black transition-opacity disabled:opacity-50"
              style={{ backgroundColor: CYAN }}
            >
              {saving ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
              Save assumptions
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
