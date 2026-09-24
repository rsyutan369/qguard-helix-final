'use client'

import { useMemo, useRef, useState } from 'react'
import { analyzeFiles, decodeReport, type QShrinkAnalysis, type QShrinkReport } from '@/lib/vault/q-shrink'

/**
 * Q-Shrink Vault Engine™ — dashboard panel.
 *
 * Two real, non-fabricated views:
 *  1. Aggregate optimization posture, computed from the `envelope_meta.qshrink`
 *     summaries that real sealed files carry (no synthetic metrics; empty state
 *     with guidance when nothing has been optimized yet).
 *  2. An interactive analyzer that runs the real engine in-browser on
 *     user-selected files — no upload — and verifies byte-for-byte reversibility.
 */

interface QShrinkFileLike {
  original_size: number | null
  size: number
  is_locked: boolean
  /** Absent on rows that were never Q-Shrink processed. */
  envelope_meta?: Record<string, unknown> | null
}

interface QShrinkEnginePanelProps {
  files: QShrinkFileLike[]
}

const C = {
  cyan: 'var(--qg-cyan)',
  green: 'var(--qg-green, #10b981)',
  amber: 'var(--qg-amber, #f59e0b)',
  violet: 'var(--qg-violet)',
  red: 'var(--qg-red, #ef4444)',
  text: 'var(--qg-text-primary)',
  sub: 'var(--qg-text-secondary)',
  muted: 'var(--qg-text-muted)',
  border: 'var(--qg-border)',
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(2)} GB`
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value) return null
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : null
    } catch {
      return null
    }
  }
  return typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null
}

const PIPELINE_STAGES = [
  { icon: '🧩', label: 'Chunk', detail: 'Content-defined (FastCDC)' },
  { icon: '♻️', label: 'Dedup', detail: 'SHA3-256 content-addressed' },
  { icon: '🗜️', label: 'Compress', detail: 'Entropy-gated deflate' },
  { icon: '🌳', label: 'Manifest', detail: 'Merkle integrity' },
  { icon: '🔐', label: 'PQC Seal', detail: 'ML-KEM-1024 + AES-256-GCM' },
]

export default function QShrinkEnginePanel({ files }: QShrinkEnginePanelProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [analysis, setAnalysis] = useState<QShrinkAnalysis | null>(null)
  const [analyzedNames, setAnalyzedNames] = useState<string[]>([])
  const [analyzeError, setAnalyzeError] = useState<string | null>(null)
  const [elapsedMs, setElapsedMs] = useState<number | null>(null)

  // ── Aggregate posture from real sealed-file metadata ──────────────────────
  const stats = useMemo(() => {
    const reports: QShrinkReport[] = []
    for (const f of files) {
      const report = decodeReport(asRecord(f.envelope_meta)?.qshrink)
      if (report) reports.push(report)
    }
    const applied = reports.filter((r) => r.applied)
    const logicalAll = reports.reduce((s, r) => s + r.logicalSize, 0)
    const storedAll = reports.reduce((s, r) => s + r.optimizedSize, 0)
    const reclaimed = Math.max(0, logicalAll - storedAll)
    const dedupSaved = applied.reduce((s, r) => s + r.dedupSavedBytes, 0)
    const avgReduction = applied.length
      ? applied.reduce((s, r) => s + r.reductionPercent, 0) / applied.length
      : 0
    const bestReduction = applied.reduce((m, r) => Math.max(m, r.reductionPercent), 0)
    const overallReduction = logicalAll > 0 ? (1 - storedAll / logicalAll) * 100 : 0

    const codecCounts = new Map<string, number>()
    for (const r of applied) codecCounts.set(r.codec, (codecCounts.get(r.codec) ?? 0) + 1)

    return {
      total: reports.length,
      appliedCount: applied.length,
      optimalCount: reports.length - applied.length,
      logicalAll,
      storedAll,
      reclaimed,
      dedupSaved,
      avgReduction,
      bestReduction,
      overallReduction,
      codecCounts: Array.from(codecCounts.entries()).sort((a, b) => b[1] - a[1]),
      hasData: reports.length > 0,
    }
  }, [files])

  async function runAnalysis(selected: FileList | null): Promise<void> {
    if (!selected || selected.length === 0) return
    setAnalyzing(true)
    setAnalyzeError(null)
    setAnalysis(null)
    try {
      const inputs = await Promise.all(
        Array.from(selected).map(async (f) => ({
          path: f.webkitRelativePath || f.name,
          data: new Uint8Array(await f.arrayBuffer()),
          mime: f.type,
        })),
      )
      const start = performance.now()
      const result = await analyzeFiles(inputs)
      const ms = performance.now() - start
      setAnalysis(result)
      setElapsedMs(ms)
      setAnalyzedNames(inputs.map((i) => i.path))
    } catch (err) {
      setAnalyzeError(err instanceof Error ? err.message : 'Analysis failed')
    } finally {
      setAnalyzing(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  return (
    <div className="q-card animate-fade-in-up" style={{ marginBottom: 16, padding: '20px 22px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, marginBottom: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 20 }}>🪐</span>
            <h3 style={{ fontSize: 16, margin: 0, color: C.text }}>
              Q-Shrink Vault Engine
              <span style={{ fontSize: 11, color: C.amber, verticalAlign: 'super', marginLeft: 2 }}>™</span>
            </h3>
          </div>
          <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>
            Pre-encryption data reduction with exact post-decryption restoration · chunk → dedup → compress → seal
          </div>
        </div>
        <span style={{
          fontSize: 9, padding: '3px 8px', borderRadius: 6, flexShrink: 0,
          background: 'rgba(16,185,129,0.12)', color: C.green,
          fontFamily: 'var(--font-mono)', letterSpacing: '0.08em', textTransform: 'uppercase',
        }}>
          Reversible · Quantum-Safe
        </span>
      </div>

      {/* Pipeline strip */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap',
        padding: '12px 14px', borderRadius: 10, marginBottom: 16,
        background: 'rgba(212,175,55,0.04)', border: `1px solid ${C.border}`,
      }}>
        {PIPELINE_STAGES.map((stage, i) => (
          <div key={stage.label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ textAlign: 'center', minWidth: 78 }}>
              <div style={{ fontSize: 16 }}>{stage.icon}</div>
              <div style={{ fontSize: 11, fontWeight: 600, color: C.text }}>{stage.label}</div>
              <div style={{ fontSize: 9, color: C.muted, lineHeight: 1.2 }}>{stage.detail}</div>
            </div>
            {i < PIPELINE_STAGES.length - 1 && (
              <span style={{ color: C.amber, fontSize: 14, opacity: 0.6 }}>→</span>
            )}
          </div>
        ))}
      </div>

      {/* Aggregate KPIs (real data) */}
      {stats.hasData ? (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 10, marginBottom: 14 }}>
            <Kpi label="Overall Reduction" value={`${stats.overallReduction.toFixed(1)}%`} color={C.green}
              hint={`${stats.appliedCount} of ${stats.total} objects reduced`} />
            <Kpi label="Storage Reclaimed" value={formatBytes(stats.reclaimed)} color={C.cyan}
              hint="Before encryption" />
            <Kpi label="Logical → Stored" value={`${formatBytes(stats.logicalAll)} → ${formatBytes(stats.storedAll)}`} color={C.violet}
              hint="Plaintext footprint" small />
            <Kpi label="Dedup Reclaimed" value={formatBytes(stats.dedupSaved)} color={C.amber}
              hint="Duplicate blocks removed" />
            <Kpi label="Avg / Best Reduction" value={`${stats.avgReduction.toFixed(0)}% / ${stats.bestReduction.toFixed(0)}%`} color={C.green}
              hint="Across optimized files" />
            <Kpi label="Already Optimal" value={`${stats.optimalCount}`} color={C.muted}
              hint="Stored raw (high-entropy)" />
          </div>
          {stats.codecCounts.length > 0 && (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
              <span style={{ fontSize: 11, color: C.muted }}>Codecs in use:</span>
              {stats.codecCounts.map(([codec, count]) => (
                <span key={codec} style={{
                  fontSize: 10, padding: '2px 8px', borderRadius: 6,
                  background: 'rgba(34,211,238,0.1)', color: C.cyan, fontFamily: 'var(--font-mono)',
                }}>
                  {codec} × {count}
                </span>
              ))}
            </div>
          )}
        </>
      ) : (
        <div style={{
          padding: '20px', borderRadius: 10, marginBottom: 16, textAlign: 'center',
          background: 'rgba(212,175,55,0.04)', border: `1px dashed ${C.border}`,
        }}>
          <div style={{ fontSize: 28, marginBottom: 8 }}>📦</div>
          <div style={{ fontSize: 13, color: C.text, fontWeight: 600, marginBottom: 4 }}>
            No optimized objects yet
          </div>
          <div style={{ fontSize: 12, color: C.muted, maxWidth: 460, margin: '0 auto' }}>
            Q-Shrink runs automatically on every upload, shrinking the plaintext before the
            post-quantum envelope seals it. Text, logs, CSV/JSON, source code, database dumps,
            and backups benefit most. Try the analyzer below to preview the reduction on any file.
          </div>
        </div>
      )}

      {/* Interactive analyzer */}
      <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 10, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Optimization Analyzer</div>
            <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>
              Runs the real engine in your browser — no upload. Select multiple files to preview folder-level deduplication.
            </div>
          </div>
          <button
            type="button"
            className="q-btn q-btn-primary"
            style={{ padding: '8px 18px', fontSize: 12, flexShrink: 0 }}
            disabled={analyzing}
            onClick={() => fileInputRef.current?.click()}
          >
            {analyzing ? '⏳ Analyzing…' : '＋ Analyze file(s)'}
          </button>
          <input
            ref={fileInputRef}
            type="file"
            multiple
            style={{ display: 'none' }}
            onChange={(e) => runAnalysis(e.target.files)}
          />
        </div>

        {analyzeError && (
          <div style={{ fontSize: 12, color: C.red, padding: '8px 12px', borderRadius: 8, background: 'rgba(239,68,68,0.08)' }}>
            {analyzeError}
          </div>
        )}

        {analysis && (
          <div className="animate-fade-in-up" style={{
            padding: '14px 16px', borderRadius: 10,
            background: analysis.reversible ? 'rgba(16,185,129,0.05)' : 'rgba(239,68,68,0.06)',
            border: `1px solid ${analysis.reversible ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}`,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
              <span style={{
                fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 6,
                background: analysis.reversible ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
                color: analysis.reversible ? C.green : C.red,
              }}>
                {analysis.reversible ? '✓ Reversible — byte-for-byte verified' : '✗ Reversibility check failed'}
              </span>
              <span style={{ fontSize: 11, color: C.muted }}>
                {analysis.fileCount} file{analysis.fileCount === 1 ? '' : 's'}
                {elapsedMs != null && ` · ${elapsedMs.toFixed(0)} ms`}
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 10, marginBottom: 12 }}>
              <Metric label="Reduction" value={`${analysis.reductionPercent.toFixed(1)}%`} color={C.green} />
              <Metric label="Logical → Optimized" value={`${formatBytes(analysis.logicalSize)} → ${formatBytes(analysis.optimizedSize)}`} small />
              <Metric label="Dedup ratio" value={`${analysis.dedupRatio.toFixed(2)}×`} color={C.amber} />
              <Metric label="Compression" value={`${analysis.compressionRatio.toFixed(2)}×`} color={C.cyan} />
              <Metric label="Chunks (unique)" value={`${analysis.totalChunks} (${analysis.uniqueChunks})`} />
              <Metric label="Entropy" value={`${analysis.entropyBitsPerByte.toFixed(2)} b/B`} />
              <Metric label="Codec" value={analysis.codec} />
              <Metric label="Avg chunk" value={formatBytes(analysis.avgChunkSize)} />
            </div>

            {analysis.merkleRoot && (
              <div style={{ fontSize: 10, color: C.muted, fontFamily: 'var(--font-mono)', marginBottom: 10, wordBreak: 'break-all' }}>
                Chunk Merkle root (SHA3-256): {analysis.merkleRoot.slice(0, 32)}…
              </div>
            )}

            {analysis.files.length > 1 && (
              <div style={{ marginTop: 4 }}>
                <div style={{ fontSize: 11, color: C.sub, marginBottom: 6 }}>Per-file breakdown</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {analysis.files.map((f, i) => (
                    <div key={`${f.path}-${i}`} style={{
                      display: 'flex', justifyContent: 'space-between', gap: 12,
                      fontSize: 11, color: C.sub, padding: '4px 8px', borderRadius: 6,
                      background: 'rgba(255,255,255,0.02)',
                    }}>
                      <span style={{ fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {analyzedNames[i] || f.path}
                      </span>
                      <span style={{ flexShrink: 0, color: C.muted }}>{formatBytes(f.size)} · {f.chunks} chunks</span>
                    </div>
                  ))}
                </div>
                <div style={{ fontSize: 10, color: C.muted, marginTop: 6 }}>
                  Cross-file deduplication finds blocks shared between these files and stores each unique block once.
                </div>
              </div>
            )}
          </div>
        )}

        {!analysis && !analyzeError && (
          <div style={{ fontSize: 11, color: C.muted, lineHeight: 1.5 }}>
            Compression always happens <strong>before</strong> encryption — ciphertext is high-entropy and cannot be
            shrunk. Each file is optimized in isolation with its own key, so there is no shared-context compression
            side channel (CRIME/BREACH-class). Restoration is byte-exact, verified by a per-file SHA3-256 digest.
          </div>
        )}
      </div>
    </div>
  )
}

function Kpi({ label, value, color, hint, small }: { label: string; value: string; color: string; hint?: string; small?: boolean }) {
  return (
    <div style={{
      padding: '12px 14px', borderRadius: 10,
      background: 'rgba(255,255,255,0.02)', border: `1px solid ${C.border}`,
    }}>
      <div style={{ fontSize: 10, color: C.muted, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
        {label}
      </div>
      <div style={{ fontSize: small ? 13 : 18, fontWeight: 700, color }}>{value}</div>
      {hint && <div style={{ fontSize: 10, color: C.muted, marginTop: 3 }}>{hint}</div>}
    </div>
  )
}

function Metric({ label, value, color, small }: { label: string; value: string; color?: string; small?: boolean }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: C.muted, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>
        {label}
      </div>
      <div style={{ fontSize: small ? 11 : 14, fontWeight: 600, color: color ?? C.text }}>{value}</div>
    </div>
  )
}
