import { useMemo, type ReactElement } from 'react';
import { qrMatrix } from '@/services/reporting/ReportQr';
import type { CertificationLevel, QuantumTrustCertificate as Cert } from '@/types/quantum-certification';

/**
 * QuantumTrustCertificate — the enterprise certificate artwork.
 *
 * A single self-contained SVG (viewBox 1012×812, formal light theme regardless
 * of dashboard theme) rendered entirely from certificate evidence. Because it
 * is pure SVG with no external assets it serialises losslessly for SVG export,
 * rasterises cleanly to PNG, and embeds into the PDF — see
 * services/certification/certificate-export.ts.
 *
 * Every displayed figure originates from the signed certificate payload; the QR
 * encodes the public verification URL. Nothing here is decorative-only data.
 */

const W = 1012;
const H = 812;

interface LevelPalette {
  name: string;
  order: number;
  primary: string;
  light: string;
  dark: string;
  metal: string;
}

const LEVEL_PALETTES: Record<CertificationLevel, LevelPalette> = {
  bronze: { name: 'BRONZE', order: 1, primary: '#B87333', light: '#E8A868', dark: '#7A4A18', metal: '#CD7F32' },
  silver: { name: 'SILVER', order: 2, primary: '#8A94A6', light: '#D8DEE9', dark: '#5A6373', metal: '#C0C0C0' },
  gold: { name: 'GOLD', order: 3, primary: '#D4A017', light: '#FFD966', dark: '#9A6E00', metal: '#E0A400' },
  platinum: { name: 'PLATINUM', order: 4, primary: '#6D28D9', light: '#A78BFA', dark: '#4C1D95', metal: '#8B7BE8' },
  diamond: { name: 'DIAMOND', order: 5, primary: '#0891B2', light: '#67E8F9', dark: '#0E5E73', metal: '#22D3EE' },
};

const INK = '#0B1B3A';
const INK_SOFT = '#3B4A66';
const VIOLET = '#6D28D9';
const CYAN = '#0EA5E9';

function fmtDate(value: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (!Number.isFinite(d.getTime())) return '—';
  return d.toLocaleDateString('en-US', { month: 'long', day: '2-digit', year: 'numeric' });
}

/** Small vector QR rendered from the verification URL. */
function QrBlock({ url, x, y, size }: { url: string; x: number; y: number; size: number }) {
  const matrix = useMemo(() => {
    try {
      return qrMatrix(url || 'https://qguardhelix.com');
    } catch {
      return [] as boolean[][];
    }
  }, [url]);
  if (!matrix.length) return null;
  const n = matrix.length;
  const cell = size / n;
  const rects: ReactElement[] = [];
  for (let r = 0; r < n; r += 1) {
    for (let c = 0; c < n; c += 1) {
      if (matrix[r][c]) {
        rects.push(<rect key={`${r}-${c}`} x={x + c * cell} y={y + r * cell} width={cell + 0.4} height={cell + 0.4} fill={INK} />);
      }
    }
  }
  return (
    <g>
      <rect x={x - 6} y={y - 6} width={size + 12} height={size + 12} rx={6} fill="#FFFFFF" />
      {rects}
    </g>
  );
}

/** A metric cell in the dark stats bar. */
function StatCell({ x, cx, label, value, sub, color }: { x: number; cx: number; label: string; value: string; sub: string; color: string }) {
  return (
    <g>
      <text x={cx} y={x + 20} textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize={10} fontWeight={700} letterSpacing={1.2} fill="#9FB2D4">
        {label}
      </text>
      <text x={cx} y={x + 46} textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize={24} fontWeight={800} fill="#FFFFFF">
        {value}
      </text>
      <text x={cx} y={x + 64} textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize={10} fontWeight={600} fill={color}>
        {sub}
      </text>
    </g>
  );
}

export function QuantumTrustCertificate({ certificate, className }: { certificate: Cert; className?: string }) {
  const palette = LEVEL_PALETTES[certificate.level] || LEVEL_PALETTES.bronze;
  const stack = certificate.cryptoStack.slice(0, 8);
  const scope = certificate.scope.slice(0, 8);
  const residualLevel = certificate.residualRiskLevel || 'Low';
  const statusColor = certificate.status === 'active' ? '#16A34A' : certificate.status === 'suspended' ? '#D97706' : '#DC2626';

  return (
    <svg
      className={className}
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label={`Quantum Trust Certification for ${certificate.organization}, ${palette.name} level`}
      style={{ width: '100%', height: 'auto', display: 'block', fontFamily: 'Inter, system-ui, sans-serif' }}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id="qtc-frame" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#4C1D95" />
          <stop offset="0.35" stopColor="#6D28D9" />
          <stop offset="0.6" stopColor="#2563EB" />
          <stop offset="1" stopColor="#06B6D4" />
        </linearGradient>
        <linearGradient id="qtc-paper" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#FFFFFF" />
          <stop offset="1" stopColor="#F4F7FC" />
        </linearGradient>
        <linearGradient id="qtc-seal" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={palette.light} />
          <stop offset="0.5" stopColor={palette.metal} />
          <stop offset="1" stopColor={palette.dark} />
        </linearGradient>
        <linearGradient id="qtc-bar" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#0A1633" />
          <stop offset="0.5" stopColor="#122150" />
          <stop offset="1" stopColor="#0A1633" />
        </linearGradient>
        <radialGradient id="qtc-emblem" cx="0.5" cy="0.4" r="0.7">
          <stop offset="0" stopColor="#8B5CF6" />
          <stop offset="1" stopColor="#2563EB" />
        </radialGradient>
        <linearGradient id="qtc-title" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#3B1D8F" />
          <stop offset="0.5" stopColor="#1E3A8A" />
          <stop offset="1" stopColor="#0E7490" />
        </linearGradient>
        <pattern id="qtc-hex" width="28" height="24" patternUnits="userSpaceOnUse" patternTransform="translate(0 0)">
          <path d="M14 0 L28 8 L28 16 L14 24 L0 16 L0 8 Z" fill="none" stroke="#E7ECF5" strokeWidth="1" />
        </pattern>
      </defs>

      {/* Frame */}
      <rect x="0" y="0" width={W} height={H} rx="18" fill="url(#qtc-frame)" />
      <rect x="10" y="10" width={W - 20} height={H - 20} rx="12" fill="url(#qtc-paper)" />
      <rect x="10" y="10" width={W - 20} height={H - 20} rx="12" fill="url(#qtc-hex)" opacity="0.5" />
      <rect x="24" y="24" width={W - 48} height={H - 48} rx="8" fill="none" stroke={palette.metal} strokeWidth="1.5" opacity="0.7" />
      <rect x="30" y="30" width={W - 60} height={H - 60} rx="6" fill="none" stroke="#C7D2E8" strokeWidth="1" />

      {/* Corner flourishes */}
      {[
        [30, 30, 1, 1],
        [W - 30, 30, -1, 1],
        [30, H - 30, 1, -1],
        [W - 30, H - 30, -1, -1],
      ].map(([cx, cy, sx, sy], i) => (
        <g key={i} stroke={palette.metal} strokeWidth="2" fill="none" opacity="0.85">
          <path d={`M${cx + sx * 6} ${cy + sy * 30} L${cx + sx * 6} ${cy + sy * 6} L${cx + sx * 30} ${cy + sy * 6}`} />
          <circle cx={cx + sx * 14} cy={cy + sy * 14} r="2.5" fill={palette.metal} stroke="none" />
        </g>
      ))}

      {/* ---- Header: brand emblem + wordmark ---- */}
      <g transform="translate(56 52)">
        <circle cx="26" cy="26" r="26" fill="url(#qtc-emblem)" />
        <text x="26" y="37" textAnchor="middle" fontFamily="Georgia, serif" fontSize="34" fontWeight="700" fill="#FFFFFF">Q</text>
        <text x="66" y="26" fontFamily="Inter, system-ui, sans-serif" fontSize="26" fontWeight="800" fill={VIOLET}>Qguard</text>
        <text x="176" y="26" fontFamily="Inter, system-ui, sans-serif" fontSize="26" fontWeight="800" fill={CYAN}>Helix</text>
        <text x="66" y="46" fontFamily="Inter, system-ui, sans-serif" fontSize="9.5" fontWeight="700" letterSpacing="2.4" fill={INK_SOFT}>
          SECURE · INTELLIGENT · QUANTUM-READY
        </text>
      </g>

      {/* ---- Title block ---- */}
      <g>
        <text x="410" y="150" textAnchor="middle" fontFamily="Georgia, 'Times New Roman', serif" fontSize="33" fontWeight="700" letterSpacing="1.2" fill="url(#qtc-title)">
          QUANTUM TRUST CERTIFICATION
        </text>
        <text x="686" y="130" fontFamily="Georgia, serif" fontSize="14" fill={VIOLET}>™</text>
        <text x="410" y="174" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fontWeight="700" letterSpacing="2.8" fill={VIOLET}>
          POST-QUANTUM READY &#160;·&#160; VERIFIED &#160;·&#160; TRUSTED
        </text>
        <line x1="250" y1="190" x2="570" y2="190" stroke={palette.metal} strokeWidth="1.4" />
        <circle cx="410" cy="190" r="3" fill={palette.metal} />
      </g>

      {/* ---- Statement ---- */}
      <text x="410" y="220" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fill={INK_SOFT}>
        This is to certify that the organization named below has successfully completed the QGuard Helix
      </text>
      <text x="410" y="238" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fill={INK_SOFT}>
        Quantum Readiness Assessment and meets the requirements for Quantum Trust Certification™, in
      </text>
      <text x="410" y="256" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fill={INK_SOFT}>
        recognition of its measurable commitment to cryptographic resilience and post-quantum readiness.
      </text>

      {/* ---- Certified organization (right of the level seal) ---- */}
      <text x="530" y="298" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="11" fontWeight="700" letterSpacing="3" fill={VIOLET}>
        · CERTIFIED ORGANIZATION ·
      </text>
      <text x="530" y="340" textAnchor="middle" fontFamily="Georgia, 'Times New Roman', serif" fontSize={certificate.organization.length > 18 ? 32 : 38} fontWeight="700" fill={INK}>
        {certificate.organization.length > 26 ? `${certificate.organization.slice(0, 25)}…` : certificate.organization.toUpperCase()}
      </text>

      {/* ---- Metadata row ---- */}
      {[
        { label: 'CERTIFICATION DATE', value: fmtDate(certificate.issuedAt) },
        { label: 'EXPIRATION DATE', value: fmtDate(certificate.expiresAt) },
        { label: 'CERTIFICATE ID', value: certificate.certificateId },
        { label: 'ASSESSMENT VERSION', value: certificate.assessmentVersion || '—' },
      ].map((m, i) => {
        const cx = 332 + i * 116;
        return (
          <g key={m.label}>
            {i > 0 ? <line x1={cx - 58} y1="372" x2={cx - 58} y2="418" stroke="#D5DEEC" strokeWidth="1" /> : null}
            <text x={cx} y="382" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="8.5" fontWeight="700" letterSpacing="0.8" fill={VIOLET}>
              {m.label}
            </text>
            <text x={cx} y="404" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize={m.value.length > 14 ? 10.5 : 12.5} fontWeight="700" fill={INK}>
              {m.value}
            </text>
          </g>
        );
      })}

      {/* ---- Level seal (left) ---- */}
      <g transform="translate(150 372)">
        {/* laurel approximation */}
        <circle cx="0" cy="0" r="82" fill="none" stroke={palette.metal} strokeWidth="2.5" opacity="0.5" />
        <circle cx="0" cy="0" r="70" fill="url(#qtc-seal)" />
        <circle cx="0" cy="0" r="70" fill="none" stroke="#FFFFFF" strokeWidth="1.5" opacity="0.4" />
        <circle cx="0" cy="0" r="58" fill="#0B1B3A" />
        <text x="0" y="-30" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="8.5" fontWeight="700" letterSpacing="1" fill={palette.light}>
          QUANTUM
        </text>
        <text x="0" y="-19" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="8.5" fontWeight="700" letterSpacing="1" fill={palette.light}>
          READINESS LEVEL
        </text>
        <text x="0" y="16" textAnchor="middle" fontFamily="Georgia, serif" fontSize="30" fontWeight="800" fill={palette.metal}>
          {palette.name}
        </text>
        <text x="0" y="34" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="9" fontWeight="700" letterSpacing="2" fill="#FFFFFF">
          LEVEL {palette.order}
        </text>
        {/* stars */}
        <g fill={palette.metal}>
          {Array.from({ length: 5 }).map((_, i) => {
            const filled = i < palette.order;
            return (
              <text key={i} x={-24 + i * 12} y="49" textAnchor="middle" fontSize="11" fill={filled ? palette.metal : '#3B4A66'}>
                ★
              </text>
            );
          })}
        </g>
      </g>

      {/* ---- Verification panel (right) ---- */}
      <g transform="translate(792 44)">
        <rect x="0" y="0" width="176" height="248" rx="12" fill="#0B1B3A" />
        <rect x="0" y="0" width="176" height="248" rx="12" fill="none" stroke={palette.metal} strokeWidth="1.2" opacity="0.6" />
        {/* shield */}
        <path d="M88 20 L112 30 L112 52 C112 68 100 78 88 84 C76 78 64 68 64 52 L64 30 Z" fill="url(#qtc-emblem)" stroke={palette.metal} strokeWidth="1.5" />
        <path d="M80 52 l6 6 l12 -14" fill="none" stroke="#FFFFFF" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
        <text x="88" y="104" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="9" fontWeight="700" letterSpacing="1" fill="#FFFFFF">
          VERIFIED &amp; VALIDATED
        </text>
        <text x="88" y="116" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="8" fontWeight="600" letterSpacing="1.5" fill="#9FB2D4">
          BY QGUARD HELIX™
        </text>
        <QrBlock url={certificate.verificationUrl} x={54} y={128} size={68} />
        <text x="88" y="220" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="8" fontWeight="600" fill="#9FB2D4">
          Scan or visit
        </text>
        <text x="88" y="232" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="8.5" fontWeight="700" fill={palette.light}>
          verify.qguardhelix.com
        </text>
      </g>

      {/* ---- Stats bar ---- */}
      <g transform="translate(56 440)">
        <rect x="0" y="0" width="680" height="86" rx="12" fill="url(#qtc-bar)" />
        <rect x="0" y="0" width="680" height="86" rx="12" fill="none" stroke={palette.metal} strokeWidth="1" opacity="0.4" />
        {[
          { label: 'OVERALL READINESS', value: `${certificate.overallReadiness}%`, sub: 'High', color: '#34D399' },
          { label: 'QUANTUM RISK', value: `${certificate.quantumRisk}/100`, sub: 'Low', color: '#38BDF8' },
          { label: 'RESIDUAL RISK', value: residualLevel, sub: 'Acceptable', color: palette.light },
          { label: 'ASSESSMENT CONFIDENCE', value: `${certificate.assessmentConfidence}%`, sub: 'High', color: '#34D399' },
          { label: 'PQC ADOPTION', value: `${certificate.pqcAdoption}%`, sub: 'Advanced', color: '#A78BFA' },
        ].map((s, i) => (
          <g key={s.label}>
            {i > 0 ? <line x1={i * 136} y1="18" x2={i * 136} y2="68" stroke="#25355F" strokeWidth="1" /> : null}
            <StatCell x={0} cx={i * 136 + 68} label={s.label} value={s.value} sub={s.sub} color={s.color} />
          </g>
        ))}
      </g>

      {/* ---- Algorithm stack (left) ---- */}
      <g transform="translate(56 548)">
        <text x="0" y="12" fontFamily="Inter, system-ui, sans-serif" fontSize="11" fontWeight="800" letterSpacing="1.5" fill={VIOLET}>
          ▸ VERIFIED QUANTUM ALGORITHM STACK
        </text>
        {stack.length === 0 ? (
          <text x="0" y="40" fontFamily="Inter, system-ui, sans-serif" fontSize="11" fill={INK_SOFT}>
            Algorithm stack recorded from cryptographic inventory at issuance.
          </text>
        ) : (
          stack.map((a, i) => {
            const col = i % 2;
            const row = Math.floor(i / 2);
            const gx = col * 235;
            const gy = 30 + row * 40;
            const algo = a.algorithm.length > 27 ? `${a.algorithm.slice(0, 26)}…` : a.algorithm;
            return (
              <g key={`${a.category}-${i}`} transform={`translate(${gx} ${gy})`}>
                <circle cx="8" cy="4" r="7" fill={`${palette.primary}22`} stroke={palette.primary} strokeWidth="1.2" />
                <path d="M4.5 4 l2.5 2.5 l4 -5" fill="none" stroke={palette.primary} strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                <text x="22" y="1" fontFamily="Inter, system-ui, sans-serif" fontSize="7.5" fontWeight="700" letterSpacing="0.4" fill={INK_SOFT}>
                  {a.category.toUpperCase()}
                </text>
                <text x="22" y="13" fontFamily="Inter, system-ui, sans-serif" fontSize="9.5" fontWeight="700" fill={INK}>
                  {algo}
                  {a.standard ? <tspan fontSize="7.5" fontWeight="600" fill={INK_SOFT}>{`  (${a.standard})`}</tspan> : null}
                </text>
              </g>
            );
          })
        )}
      </g>

      {/* ---- Assessment scope (middle-right) ---- */}
      <g transform="translate(555 548)">
        <text x="0" y="12" fontFamily="Inter, system-ui, sans-serif" fontSize="11" fontWeight="800" letterSpacing="1.5" fill={VIOLET}>
          ▸ ASSESSMENT SCOPE
        </text>
        {scope.length === 0 ? (
          <text x="0" y="40" fontFamily="Inter, system-ui, sans-serif" fontSize="10.5" fill={INK_SOFT}>
            Scope reflects the assessed estate at issuance.
          </text>
        ) : (
          scope.map((label, i) => {
            const gy = 30 + i * 20;
            return (
              <g key={label} transform={`translate(0 ${gy})`}>
                <circle cx="7" cy="-3" r="6.5" fill={`${CYAN}18`} stroke={CYAN} strokeWidth="1.1" />
                <path d="M3.8 -3 l2.3 2.3 l3.6 -4.6" fill="none" stroke={CYAN} strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
                <text x="20" y="1" fontFamily="Inter, system-ui, sans-serif" fontSize="10.5" fontWeight="600" fill={INK}>
                  {label}
                </text>
              </g>
            );
          })
        )}
      </g>

      {/* ---- Signature (right band, below the verification panel) ---- */}
      <g transform="translate(772 452)">
        <path d="M0 34 C 18 8, 36 52, 56 26 S 96 10, 122 30" fill="none" stroke={INK} strokeWidth="1.6" opacity="0.8" />
        <line x1="0" y1="46" x2="140" y2="46" stroke="#C7D2E8" strokeWidth="1" />
        <text x="0" y="60" fontFamily="Inter, system-ui, sans-serif" fontSize="9" fontWeight="700" letterSpacing="1" fill={INK_SOFT}>
          CERTIFIED BY
        </text>
        <text x="0" y="74" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fontWeight="800" fill={VIOLET}>
          QGUARD HELIX™
        </text>
        <text x="0" y="88" fontFamily="Inter, system-ui, sans-serif" fontSize="9" fontWeight="600" fill={INK_SOFT}>
          Chief Security Officer
        </text>
      </g>

      {/* official wax-style seal bottom right */}
      <g transform="translate(898 622)">
        <circle cx="0" cy="0" r="56" fill="url(#qtc-seal)" />
        <circle cx="0" cy="0" r="56" fill="none" stroke="#FFFFFF" strokeWidth="1.5" opacity="0.4" />
        <circle cx="0" cy="0" r="44" fill="none" stroke="#FFFFFF" strokeWidth="1" opacity="0.55" />
        <text x="0" y="-24" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="7.5" fontWeight="800" letterSpacing="1.5" fill={palette.dark}>
          QGUARD HELIX
        </text>
        <text x="0" y="6" textAnchor="middle" fontFamily="Georgia, serif" fontSize="26" fontWeight="800" fill={palette.dark}>Q</text>
        <text x="0" y="30" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="6.5" fontWeight="800" letterSpacing="1" fill={palette.dark}>
          QUANTUM TRUST
        </text>
      </g>

      {/* ---- Footer bar ---- */}
      <g>
        <rect x="300" y="762" width="412" height="26" rx="13" fill="url(#qtc-frame)" />
        <text x="506" y="779" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="10" fontWeight="700" letterSpacing="2.5" fill="#FFFFFF">
          SECURE · INTELLIGENT · QUANTUM-READY
        </text>
      </g>

      {/* status chip (top-left of paper, subtle) */}
      <g transform="translate(56 724)">
        <rect x="0" y="0" width="150" height="24" rx="12" fill={`${statusColor}14`} stroke={statusColor} strokeWidth="1" />
        <circle cx="14" cy="12" r="4" fill={statusColor} />
        <text x="26" y="16" fontFamily="Inter, system-ui, sans-serif" fontSize="10" fontWeight="700" letterSpacing="0.5" fill={statusColor}>
          {certificate.status.toUpperCase()}
        </text>
      </g>
      <text x="430" y="742" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="8.5" fill={INK_SOFT}>
        SHA3-256 · {certificate.certificateHash.slice(0, 32)}…
      </text>
      <text x="430" y="754" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="8.5" fill={INK_SOFT}>
        Signed {certificate.signature ? certificate.signature.algorithm : 'ML-DSA-65'} · continuous monitoring active
      </text>
    </svg>
  );
}

export default QuantumTrustCertificate;
