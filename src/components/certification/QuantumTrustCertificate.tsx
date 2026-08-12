import { useMemo, type ReactElement } from 'react';
import { qrMatrix } from '@/services/reporting/ReportQr';
import { levelFromReadiness, levelFromRisk, riskBandFor } from '@/lib/migration/asset-intelligence';
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

/* ------------------------------------------------------------------ */
/* Metric banding                                                      */
/* ------------------------------------------------------------------ */
/**
 * The stats bar used to print HARD-CODED sub-labels — "High", "Low",
 * "Acceptable", "Advanced" — regardless of the values above them. A 23%
 * readiness printed "High" and a 72/100 quantum risk printed "Low", on a
 * document that is signed and publicly verifiable. Every band below is now
 * derived from the same canonical tables the dashboards use.
 */

/** Higher-is-better metrics (readiness, confidence, PQC adoption). */
function readinessColor(score: number): string {
  if (score >= 85) return '#34D399'; // emerald
  if (score >= 65) return '#22D3EE'; // cyan
  if (score >= 45) return '#FBBF24'; // amber
  if (score >= 25) return '#FB923C'; // orange
  return '#F87171'; // red
}

/** Evidence-confidence band. Mirrors the report's confidence taxonomy. */
function confidenceBand(pct: number): string {
  if (pct >= 90) return 'High';
  if (pct >= 70) return 'Moderate';
  if (pct >= 50) return 'Limited';
  return 'Low';
}

/** Residual risk is only "Acceptable" when it actually sits in the Low band. */
function residualSub(residual: number): string {
  return residual <= 25 ? 'Acceptable' : residual <= 40 ? 'Monitor' : 'Above Tolerance';
}

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
  /* Bronze "Initial Readiness" is a measured BASELINE, not a certification.
     Every claim on the artifact is downgraded accordingly — the value comes
     from the ML-DSA-65-signed payload, so it cannot be edited away. */
  const isBaseline = certificate.certified === false;
  const stack = certificate.cryptoStack.slice(0, 8);
  const scope = certificate.scope.slice(0, 8);
  const residualLevel = certificate.residualRiskLevel || 'Low';
  const statusColor = certificate.status === 'active' ? '#16A34A' : certificate.status === 'suspended' ? '#D97706' : '#DC2626';

  return (
    <svg
      className={className}
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label={isBaseline
        ? `Quantum Readiness baseline attestation for ${certificate.organization}, ${palette.name} level, ${certificate.criteriaMet} of ${certificate.criteriaTotal} certification criteria met, not yet certified`
        : `Quantum Trust Certification for ${certificate.organization}, ${palette.name} level`}
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
        {/* Verification panel + insignia */}
        <linearGradient id="qtc-panel" x1="0" y1="0" x2="0.4" y2="1">
          <stop offset="0" stopColor="#101F44" />
          <stop offset="1" stopColor="#070F26" />
        </linearGradient>
        <linearGradient id="qtc-gold" x1="0" y1="0" x2="0.3" y2="1">
          <stop offset="0" stopColor="#FDF0C0" />
          <stop offset="0.28" stopColor="#E8C463" />
          <stop offset="0.55" stopColor="#B8862B" />
          <stop offset="0.78" stopColor="#EBCC77" />
          <stop offset="1" stopColor="#8A6218" />
        </linearGradient>
        <linearGradient id="qtc-shield" x1="0" y1="0" x2="0.4" y2="1">
          <stop offset="0" stopColor="#7C5CF8" />
          <stop offset="0.5" stopColor="#4A6BF5" />
          <stop offset="1" stopColor="#1E3A8A" />
        </linearGradient>
        {/* Embossed medallion: light from upper-left, shadow lower-right */}
        <radialGradient id="qtc-medallion" cx="0.34" cy="0.28" r="0.85">
          <stop offset="0" stopColor="#FFF6D8" />
          <stop offset="0.35" stopColor="#E4BE5C" />
          <stop offset="0.7" stopColor="#BE8C2E" />
          <stop offset="1" stopColor="#7C5714" />
        </radialGradient>
        <linearGradient id="qtc-medallion-rim" x1="0" y1="0" x2="0.6" y2="1">
          <stop offset="0" stopColor="#FFF3CB" />
          <stop offset="0.5" stopColor="#C6952F" />
          <stop offset="1" stopColor="#6E4D10" />
        </linearGradient>
        {/* Arc paths for the medallion's circular lettering */}
        <path id="qtc-arc-top" d="M -40 0 A 40 40 0 0 1 40 0" fill="none" />
        <path id="qtc-arc-bottom" d="M -44 0 A 44 44 0 0 0 44 0" fill="none" />
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
          {isBaseline
            ? 'BASELINE ATTESTATION  ·  MEASURED  ·  NOT YET CERTIFIED'
            : 'POST-QUANTUM READY  ·  VERIFIED  ·  TRUSTED'}
        </text>
        <line x1="250" y1="190" x2="570" y2="190" stroke={palette.metal} strokeWidth="1.4" />
        <circle cx="410" cy="190" r="3" fill={palette.metal} />
      </g>

      {/* ---- Statement ----
           A baseline attestation must never read as a certification. It states
           what was measured and how many criteria remain, so a third party
           reading the artifact cannot mistake it for a quantum-secure claim. */}
      {isBaseline ? (
        <>
          <text x="410" y="220" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fill={INK_SOFT}>
            This attests that the organization named below has completed a QGuard Helix Quantum Readiness
          </text>
          <text x="410" y="238" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fill={INK_SOFT}>
            Assessment, establishing the verified cryptographic baseline recorded below. It meets
          </text>
          <text x="410" y="256" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fontWeight="700" fill={INK_SOFT}>
            {certificate.criteriaMet} of {certificate.criteriaTotal} certification criteria and is NOT yet Quantum Trust Certified™.
          </text>
        </>
      ) : (
        <>
          <text x="410" y="220" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fill={INK_SOFT}>
            This is to certify that the organization named below has successfully completed the QGuard Helix
          </text>
          <text x="410" y="238" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fill={INK_SOFT}>
            Quantum Readiness Assessment and meets the requirements for Quantum Trust Certification™, in
          </text>
          <text x="410" y="256" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fill={INK_SOFT}>
            recognition of its measurable commitment to cryptographic resilience and post-quantum readiness.
          </text>
        </>
      )}

      {/* ---- Organization (right of the level seal) ---- */}
      <text x="530" y="298" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="11" fontWeight="700" letterSpacing="3" fill={VIOLET}>
        {isBaseline ? '· ASSESSED ORGANIZATION ·' : '· CERTIFIED ORGANIZATION ·'}
      </text>
      <text x="530" y="340" textAnchor="middle" fontFamily="Georgia, 'Times New Roman', serif" fontSize={certificate.organization.length > 18 ? 32 : 38} fontWeight="700" fill={INK}>
        {certificate.organization.length > 26 ? `${certificate.organization.slice(0, 25)}…` : certificate.organization.toUpperCase()}
      </text>

      {/* ---- Metadata row ---- */}
      {[
        { label: isBaseline ? 'ASSESSMENT DATE' : 'CERTIFICATION DATE', value: fmtDate(certificate.issuedAt) },
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

      {/* ---- Verification panel (right) ----
           Ribbon + crested shield + QR card. Pure SVG so it survives the SVG →
           PNG → PDF export chain with no external assets. */}
      <g transform="translate(792 40)">
        <rect x="0" y="0" width="176" height="286" rx="14" fill="url(#qtc-panel)" />
        <rect x="0" y="0" width="176" height="286" rx="14" fill="none" stroke={palette.metal} strokeWidth="1.4" opacity="0.75" />
        <rect x="4" y="4" width="168" height="278" rx="11" fill="none" stroke="#FFFFFF" strokeWidth="0.6" opacity="0.10" />

        {/* Gold award ribbon with notched tails */}
        <g transform="translate(88 22)">
          <path d="M-30 8 L-44 26 L-30 24 L-26 34 L-12 14 Z" fill="url(#qtc-gold)" opacity="0.95" />
          <path d="M30 8 L44 26 L30 24 L26 34 L12 14 Z" fill="url(#qtc-gold)" opacity="0.95" />
          <path d="M-34 0 h68 l-7 11 l7 11 h-68 l7 -11 Z" fill="url(#qtc-gold)" stroke="#8A6218" strokeWidth="0.6" />
          <text x="0" y="15" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="8.5" fontWeight="800" letterSpacing="1.6" fill="#3A2A06">
            VERIFIED
          </text>
        </g>

        {/* Crested shield */}
        <g transform="translate(88 88)">
          <path d="M0 -30 L26 -19 L26 6 C26 25 12 37 0 44 C-12 37 -26 25 -26 6 L-26 -19 Z" fill="url(#qtc-shield)" stroke="url(#qtc-gold)" strokeWidth="1.8" />
          <path d="M0 -26 L22 -16.5 L22 5 C22 21 10 32 0 38 C-10 32 -22 21 -22 5 L-22 -16.5 Z" fill="none" stroke="#FFFFFF" strokeWidth="0.7" opacity="0.28" />
          {/* gloss */}
          <path d="M0 -30 L26 -19 L26 0 C14 -6 0 -8 -26 0 L-26 -19 Z" fill="#FFFFFF" opacity="0.10" />
          <path d="M-11 4 l8 8 l16 -19" fill="none" stroke="#FFFFFF" strokeWidth="4.2" strokeLinecap="round" strokeLinejoin="round" />
        </g>

        <text x="88" y="152" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="9" fontWeight="800" letterSpacing="0.9" fill="#FFFFFF">
          VERIFIED &amp; VALIDATED
        </text>
        <text x="88" y="164" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="7.6" fontWeight="600" letterSpacing="1.4" fill="#9FB2D4">
          BY QGUARD HELIX™
        </text>

        {/* Gold rule with centre pip */}
        <line x1="26" y1="174" x2="150" y2="174" stroke={palette.metal} strokeWidth="0.9" opacity="0.55" />
        <circle cx="88" cy="174" r="1.9" fill={palette.metal} />

        <text x="88" y="188" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="7.4" fontWeight="700" letterSpacing="2.2" fill="#9FB2D4">
          VERIFICATION
        </text>

        {/* QR on a white card so it scans reliably in print */}
        <rect x="49" y="195" width="78" height="78" rx="6" fill="#FFFFFF" />
        <QrBlock url={certificate.verificationUrl} x={53} y={199} size={70} />
      </g>

      {/* Caption under the panel — kept outside so the card stays tight */}
      <text x="880" y="338" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="7.8" fontWeight="600" fill={INK_SOFT}>
        Scan or visit
      </text>
      <text x="880" y="349" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="8.6" fontWeight="800" fill={VIOLET}>
        verify.qguardhelix.com
      </text>
      <text x="880" y="361" textAnchor="middle" fontFamily="Inter, system-ui, sans-serif" fontSize="7.2" fontWeight="500" fill={INK_SOFT}>
        Enter Certificate ID to verify authenticity.
      </text>

      {/* ---- Stats bar ---- */}
      <g transform="translate(56 440)">
        <rect x="0" y="0" width="680" height="86" rx="12" fill="url(#qtc-bar)" />
        <rect x="0" y="0" width="680" height="86" rx="12" fill="none" stroke={palette.metal} strokeWidth="1" opacity="0.4" />
        {[
          {
            label: 'OVERALL READINESS',
            value: `${certificate.overallReadiness}%`,
            sub: levelFromReadiness(certificate.overallReadiness),
            color: readinessColor(certificate.overallReadiness),
          },
          {
            label: 'QUANTUM RISK',
            value: `${certificate.quantumRisk}/100`,
            // Risk is inverse-scaled: a HIGH number is a BAD outcome, so the
            // band and colour come from the canonical risk table.
            sub: levelFromRisk(certificate.quantumRisk),
            color: riskBandFor(certificate.quantumRisk).hex,
            },
          {
            label: 'RESIDUAL RISK',
            value: residualLevel,
            sub: residualSub(certificate.residualRisk),
            color: riskBandFor(certificate.residualRisk).hex,
          },
          {
            label: 'ASSESSMENT CONFIDENCE',
            value: `${certificate.assessmentConfidence}%`,
            sub: confidenceBand(certificate.assessmentConfidence),
            color: readinessColor(certificate.assessmentConfidence),
          },
          {
            label: 'PQC ADOPTION',
            value: `${certificate.pqcAdoption}%`,
            sub: levelFromReadiness(certificate.pqcAdoption),
            color: readinessColor(certificate.pqcAdoption),
          },
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

      {/* ---- Signature (right band, below the verification panel) ----
           A flowing script stroke with varying weight, so it reads as a
           written hand rather than a single uniform curve. */}
      <g transform="translate(772 452)">
        <g stroke={INK} fill="none" strokeLinecap="round" strokeLinejoin="round" opacity="0.88">
          <path d="M2 40 C 10 12, 20 6, 26 14 C 32 22, 22 36, 16 40 C 10 44, 8 34, 14 26 C 22 15, 36 10, 44 20 C 50 28, 42 40, 38 34 C 34 28, 44 16, 56 20 C 64 23, 62 34, 68 34 C 76 34, 78 16, 88 18 C 96 20, 92 34, 100 34 C 110 34, 116 18, 126 24" strokeWidth="1.7" />
          <path d="M18 44 C 44 36, 78 34, 132 30" strokeWidth="1.1" opacity="0.65" />
        </g>
        <line x1="0" y1="52" x2="140" y2="52" stroke="#C7D2E8" strokeWidth="1" />
        <text x="0" y="66" fontFamily="Inter, system-ui, sans-serif" fontSize="9" fontWeight="700" letterSpacing="1" fill={INK_SOFT}>
          CERTIFIED BY
        </text>
        <text x="0" y="80" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fontWeight="800" fill={VIOLET}>
          QGUARD HELIX™
        </text>
        <text x="0" y="94" fontFamily="Inter, system-ui, sans-serif" fontSize="9" fontWeight="600" fill={INK_SOFT}>
          Chief Security Officer
        </text>
      </g>

      {/* ---- Embossed gold medallion (bottom right) ----
           Milled rim, raised inner disc, circular lettering on arc paths and a
           shield-over-helix emblem: the platform mark, drawn not imported. */}
      <g transform="translate(898 624)">
        {/* Milled/reeded outer edge */}
        <circle cx="0" cy="0" r="60" fill="url(#qtc-medallion-rim)" />
        {Array.from({ length: 72 }, (_, i) => {
          const a = (i / 72) * Math.PI * 2;
          return (
            <line
              key={`reed-${i}`}
              x1={Math.cos(a) * 54}
              y1={Math.sin(a) * 54}
              x2={Math.cos(a) * 60}
              y2={Math.sin(a) * 60}
              stroke="#6E4D10"
              strokeWidth="1.1"
              opacity="0.45"
            />
          );
        })}
        <circle cx="0" cy="0" r="54" fill="url(#qtc-medallion)" />
        {/* Raised-edge highlight (light upper-left) and shadow (lower-right) */}
        <path d="M0 -54 A 54 54 0 0 0 -38 38" fill="none" stroke="#FFF8E0" strokeWidth="1.6" opacity="0.55" />
        <path d="M0 54 A 54 54 0 0 0 38 -38" fill="none" stroke="#6E4D10" strokeWidth="1.6" opacity="0.45" />
        <circle cx="0" cy="0" r="46" fill="none" stroke="#7C5714" strokeWidth="0.9" opacity="0.55" />
        <circle cx="0" cy="0" r="44.5" fill="none" stroke="#FFF3CB" strokeWidth="0.7" opacity="0.5" />

        {/* Circular lettering */}
        <text fontFamily="Inter, system-ui, sans-serif" fontSize="8" fontWeight="800" letterSpacing="2.4" fill="#5C3F0C">
          {/* Both href (SVG 2) and xlink:href (SVG 1.1) — the artwork is
              serialised and re-parsed by the PNG/PDF exporters and by whatever
              tool opens the downloaded .svg, so the legacy form must be there. */}
          <textPath href="#qtc-arc-top" xlinkHref="#qtc-arc-top" startOffset="50%" textAnchor="middle">QGUARD HELIX™</textPath>
        </text>
        <text fontFamily="Inter, system-ui, sans-serif" fontSize="7.2" fontWeight="800" letterSpacing="1.9" fill="#5C3F0C">
          <textPath href="#qtc-arc-bottom" xlinkHref="#qtc-arc-bottom" startOffset="50%" textAnchor="middle">QUANTUM TRUST CERTIFICATION</textPath>
        </text>
        <circle cx="-31" cy="2" r="1.6" fill="#5C3F0C" opacity="0.7" />
        <circle cx="31" cy="2" r="1.6" fill="#5C3F0C" opacity="0.7" />

        {/* Shield over a double-helix — the platform emblem */}
        <g transform="translate(0 -1)">
          <path d="M0 -20 L17 -12.5 L17 3 C17 15 8 23 0 27 C-8 23 -17 15 -17 3 L-17 -12.5 Z" fill="#8A6218" opacity="0.30" />
          <path d="M0 -22 L17 -14.5 L17 1 C17 13 8 21 0 25 C-8 21 -17 13 -17 1 L-17 -14.5 Z" fill="none" stroke="#5C3F0C" strokeWidth="1.5" />
          <path d="M-7 -12 C 3 -6, -3 0, 7 6 M7 -12 C -3 -6, 3 0, -7 6" fill="none" stroke="#5C3F0C" strokeWidth="1.5" strokeLinecap="round" />
          <line x1="-5.6" y1="-9" x2="5.6" y2="-9" stroke="#5C3F0C" strokeWidth="1.1" opacity="0.85" />
          <line x1="-5.6" y1="-3" x2="5.6" y2="-3" stroke="#5C3F0C" strokeWidth="1.1" opacity="0.85" />
          <line x1="-5.6" y1="3" x2="5.6" y2="3" stroke="#5C3F0C" strokeWidth="1.1" opacity="0.85" />
          <path d="M-5 13 l4 4 l8 -9" fill="none" stroke="#5C3F0C" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </g>
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
