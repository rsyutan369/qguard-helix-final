'use client';

import { useObservedDetail } from '@/hooks/use-observed-paged-resource';
import { TelemetryAssetComparison } from '../_components/observability/TelemetryAssetComparison';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  Atom,
  Binary,
  Database,
  FileKey,
  Fingerprint,
  KeyRound,
  Lock,
  Package,
  ShieldAlert,
  Vault,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { useEncryptionMonitoring, useEncryptionTable, type AlgorithmDetail } from '@/hooks/use-encryption-monitoring';
import type { AlgorithmRow, EncryptionFinding, KeyRecord, ProtectionLayer } from '@/lib/encryption/types';
import { EncryptionPostureStrip } from '../_components/observability/EncryptionPostureStrip';
import {
  ConnectionLost,
  Drawer,
  ErrorState,
  EvidenceList,
  FilterSelect,
  FreshnessBar,
  Kpi,
  ModuleNav,
  NoDataState,
  PageHeader,
  Pager,
  Panel,
  PanelEmpty,
  Pill,
  ProvenanceFooter,
  SearchInput,
  SecurityBits,
  SectionLabel,
  SeverityBadge,
  SHELL_CLASS,
  SHELL_CSS,
  Skeleton,
  StackedTrend,
  StrengthBadge,
  TableShell,
  Td,
  Th,
  TONE,
  absoluteTime,
  fmtNumber,
  fmtPercent,
  relativeTime,
  type ProtectionStrengthKey,
} from '../_components/observability/primitives';

/**
 * Encryption Monitoring — the data-protection console.
 *
 * Deliberately NOT a second TLS page. The transport modules own protocol
 * versions, cipher-suite negotiation, key agreement and certificates; this page
 * owns what protects DATA: symmetric ciphers, hashes, MACs, KDFs, key material,
 * data-at-rest policy, vault protection and the crypto operations an agent
 * actually observed.
 *
 * The quantum model here is GROVER, not Shor, and the page says so out loud —
 * because the single most damaging error it could make is to render AES-256-GCM
 * as a critical quantum vulnerability, which this platform has done before.
 */

const PAGE_SIZE = 25;

const LAYER_LABEL: Record<ProtectionLayer, string> = {
  symmetric: 'Symmetric cipher',
  hash: 'Hash',
  mac: 'MAC',
  kdf: 'Key derivation',
  'key-material': 'Key material',
  'at-rest': 'Data at rest',
  vault: 'Vault',
  application: 'Application crypto',
};

export default function EncryptionMonitoring() {
  const { data, state, error, live, lastSyncedAt, refresh, reconnect } = useEncryptionMonitoring();

  const [search, setSearch] = useState('');
  const [strength, setStrength] = useState('all');
  const [layer, setLayer] = useState('all');
  const [offset, setOffset] = useState(0);
  const [detailId, setDetailId] = useState<string | null>(null);
  const { detail, detailError, detailLoading, retryDetail } = useObservedDetail<AlgorithmDetail>(
    '/api/v1/dashboard/encryption-monitoring/algorithms', detailId, data?.generatedAt,
  );

  const revision = useMemo(() => Date.parse(data?.generatedAt || '') || 0, [data?.generatedAt]);
  const query = useMemo(
    () => ({ search, strength, layer, limit: PAGE_SIZE, offset, sort: 'observations' }),
    [search, strength, layer, offset],
  );
  const { rows: algorithms, total: algorithmTotal, error: tableError, retry: retryTable, loading: tableLoading } = useEncryptionTable<AlgorithmRow>(
    '/algorithms',
    'algorithms',
    query,
    revision,
  );

  const openAlgorithm = setDetailId;

  const showSkeleton = state === 'loading' && !data;
  const showHardError = state === 'error' && !data;
  const connectionLost = Boolean(data && !live && state !== 'loading');

  if (showSkeleton) {
    return (
      <div className={SHELL_CLASS}>
        <style>{SHELL_CSS}</style>
        <Skeleton />
      </div>
    );
  }

  if (showHardError) {
    return (
      <div className={SHELL_CLASS}>
        <style>{SHELL_CSS}</style>
        <ErrorState message={error || 'The encryption monitoring service did not respond.'} onRetry={reconnect} />
      </div>
    );
  }

  return (
    <div className={SHELL_CLASS}>
      <style>{SHELL_CSS}</style>
      <WorkflowRail activeStage="monitoring" />

      <PageHeader
        icon={Lock}
        title="Encryption"
        accent="Monitoring"
        subtitle="What protects your data: symmetric ciphers, hashes, key derivation, key material, storage encryption and vault protection — measured and explained by cryptographic role and risk. CNSA 2.0 is a comparison for U.S. National Security Systems."
        right={
          <FreshnessBar
            live={live}
            state={state}
            generatedAt={data?.generatedAt ?? null}
            latestEvidenceAt={data?.latestEvidenceAt ?? null}
            telemetry={data?.telemetry ?? null}
            onRefresh={() => void refresh(true)}
            refreshing={state === 'loading'}
          />
        }
      />

      <ModuleNav />

      {connectionLost ? <ConnectionLost onReconnect={reconnect} lastSyncedAt={lastSyncedAt} /> : null}
      <TelemetryAssetComparison />
      {tableError ? <ErrorState message={tableError} onRetry={retryTable} /> : null}
      {error && data ? (
        <p className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-[11px] text-red-200/85">{error}</p>
      ) : null}

      {data && !data.hasData ? (
        <NoDataState
          title="No data-protection evidence yet"
          body="This console reports only measured primitives — nothing is inferred from an asset count or a policy default. Connect a source below and it fills in as observations arrive."
          telemetry={data.telemetry}
        />
      ) : null}

      {data ? (
        <>
          <EncryptionPostureStrip posture={data.posture} totals={data.totals} />

          {/* ---- Why this page grades differently ------------------- */}
          <GroverExplainer posture={data.posture} />

          {/* ---- Overview ------------------------------------------- */}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Kpi
              label="Symmetric · hash · MAC · KDF"
              value={fmtNumber(data.totals.algorithms)}
              detail={`${fmtNumber(data.totals.applicationAlgorithms)} more declared by application code · ${fmtNumber(data.totals.observations)} distinct measurement(s)`}
              tone="neutral"
              hint="Distinct symmetric ciphers, hashes, MACs and KDFs actually measured in your estate. Transport cipher suites are counted once, on Protocol Analytics — not here."
            />
            <Kpi
              label="Key material"
              value={fmtNumber(data.totals.keys)}
              detail={data.keys.measured ? `${fmtNumber(data.keys.rotationsObserved)} rotation(s) evidenced` : 'No key store connected'}
              tone={data.keys.measured ? (data.posture.keysAtRisk ? 'warning' : 'good') : 'neutral'}
              unmeasured={!data.keys.measured}
              hint="Keys the platform manages, with their entropy source, quality score and lifecycle. Rotations are counted only where a key records the key it replaced."
            />
            <Kpi
              label="Encryption at rest"
              value={data.atRest.measured ? fmtPercent(data.atRest.coveragePercent) : '—'}
              detail={
                data.atRest.measured
                  ? `${fmtNumber(data.atRest.encrypted)} encrypted · ${fmtNumber(data.atRest.unencrypted)} unencrypted · ${fmtNumber(data.atRest.undetermined)} undetermined`
                  : 'No storage or KMS policy evidence collected'
              }
              tone={data.atRest.unencrypted ? 'critical' : data.atRest.measured ? 'good' : 'neutral'}
              unmeasured={!data.atRest.measured}
              hint="Storage, database and KMS policy evidence from cloud connectors and agents. With no such source this reads 'Not measured' rather than 0% — an absent instrument is not an unencrypted estate."
            />
            <Kpi
              label="Crypto operations"
              value={fmtNumber(data.operations.total)}
              detail={data.operations.measured ? 'Encrypt / decrypt / sign / verify observed at runtime' : 'No runtime collector reports operations'}
              tone={data.operations.measured ? 'neutral' : 'neutral'}
              unmeasured={!data.operations.measured}
              hint="Counted only where a runtime agent recorded the operation. Scans record configuration, not activity."
            />
          </div>

          {/* ---- Timeline + operations ------------------------------ */}
          <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr]">
            <Panel>
              <SectionLabel icon={Activity} meta="Last 14 days" hint="Each bar counts evidence whose own timestamp falls in that day. Empty days mean no collection, not a quiet estate.">
                Data-protection evidence
              </SectionLabel>
              <StackedTrend
                points={data.timeline as unknown as Array<Record<string, string | number>>}
                series={[
                  { key: 'observations', label: 'Primitive observations', hex: TONE.neutral.hex },
                  { key: 'operations', label: 'Crypto operations', hex: TONE.info.hex },
                  { key: 'findings', label: 'Findings', hex: TONE.warning.hex },
                ]}
                emptyLabel="No dated data-protection evidence in the last 14 days"
              />
            </Panel>

            <Panel>
              <SectionLabel icon={Binary} hint="What the runtime collectors observed cryptography being used FOR.">
                Operations profile
              </SectionLabel>
              {!data.operations.measured ? (
                <PanelEmpty>
                  No runtime collector reports crypto operations. Deploy an agent to see what your applications actually encrypt, decrypt and sign.
                </PanelEmpty>
              ) : (
                <ul className="space-y-1.5">
                  {data.operations.byOperation.map((row) => (
                    <li key={row.operation} className="grid grid-cols-[minmax(0,1fr)_minmax(60px,1fr)_44px_40px] items-center gap-2">
                      <span className="truncate text-[11px] text-white/75">{row.operation}</span>
                      <span className="h-2 overflow-hidden rounded-full bg-white/10">
                        <span className="block h-full rounded-full" style={{ width: `${Math.max(2, row.percent)}%`, backgroundColor: TONE.info.hex }} />
                      </span>
                      <span className="text-right font-mono text-[11px] tabular-nums text-white/60">{fmtNumber(row.count)}</span>
                      <span className="text-right font-mono text-[11px] tabular-nums text-white/40">{fmtPercent(row.percent)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>

          {/* ---- Algorithm inventories ------------------------------ */}
          <div className="grid gap-3 xl:grid-cols-2">
            <AlgorithmPanel
              icon={Lock}
              title="Symmetric ciphers"
              hint="Bulk data encryption. Grover halves the key strength — AES-256 keeps ~128 bits and is CNSA 2.0 approved; AES-128 drops to ~64 bits and is weakened, not broken."
              rows={data.symmetric}
              onOpen={openAlgorithm}
              empty="No standalone symmetric cipher observed. Transport suites are inventoried on Protocol Analytics."
            />
            <AlgorithmPanel
              icon={Fingerprint}
              title="Hashes"
              hint="Integrity and digest functions. SHA-1 and MD5 are collision-broken classically; CNSA 2.0 specifies SHA-384 or SHA-512."
              rows={data.hashes}
              onOpen={openAlgorithm}
              empty="No hash function observed outside a transport suite."
            />
            <AlgorithmPanel
              icon={Binary}
              title="Message authentication"
              hint="HMAC, Poly1305, CMAC. HMAC-SHA-1 is notably NOT broken by the SHA-1 collision attacks — HMAC rests on pseudorandomness, not collision resistance."
              rows={data.macs}
              onOpen={openAlgorithm}
              empty="No MAC construction observed."
            />
            <AlgorithmPanel
              icon={KeyRound}
              title="Key derivation & password hashing"
              hint="PBKDF2, Argon2, scrypt, bcrypt, HKDF. Memory-hard functions resist GPU and quantum-assisted search far better than iteration-only designs."
              rows={data.kdfs}
              onOpen={openAlgorithm}
              empty="No key-derivation or password-hashing function observed."
            />
          </div>

          {/* ---- Application crypto --------------------------------- */}
          <Panel>
            <SectionLabel
              icon={Package}
              meta={`${fmtNumber(data.totals.applicationAlgorithms)} declared`}
              href="/dashboard/shadow-crypto"
              hint="Cryptography declared by application code — libraries, package manifests, JWT algorithms and configuration. This is where unmanaged crypto hides."
            >
              Application-declared cryptography
            </SectionLabel>
            {data.application.length === 0 ? (
              <PanelEmpty>No application-declared cryptography observed. Agent collectors report libraries, manifests and JWT algorithms.</PanelEmpty>
            ) : (
              <TableShell minWidth={760}>
                <thead>
                  <tr>
                    <Th>Algorithm</Th>
                    <Th>Where declared</Th>
                    <Th align="right">Occurrences</Th>
                    <Th>Strength</Th>
                    <Th>Security level</Th>
                  </tr>
                </thead>
                <tbody>
                  {data.application.slice(0, 12).map((row) => (
                    <tr key={row.label} className="transition hover:bg-white/[0.04]">
                      <Td>
                        <button type="button" onClick={() => void openAlgorithm(row.label)} className="font-mono text-[11px] text-white hover:text-cyan-300">
                          {row.label}
                        </button>
                      </Td>
                      <Td>
                        <span className="block max-w-[280px] truncate text-[10.5px] text-white/55" title={row.assetNames.join(', ')}>
                          {row.assetNames.slice(0, 3).join(', ') || 'Unassigned'}
                        </span>
                      </Td>
                      <Td align="right">{fmtNumber(row.observations)}</Td>
                      <Td>
                        <StrengthBadge strength={row.strength.strength as ProtectionStrengthKey} title={row.strength.rationale} />
                      </Td>
                      <Td>
                        <SecurityBits classical={row.strength.classicalBits} quantum={row.strength.quantumBits} />
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
            )}
          </Panel>

          {/* ---- Key material --------------------------------------- */}
          <KeyMaterialPanel keys={data.keys} />

          {/* ---- At rest + vault ------------------------------------ */}
          <div className="grid gap-3 xl:grid-cols-2">
            <Panel>
              <SectionLabel icon={Database} hint="Storage, database and KMS policy evidence. Each row is a measured surface, not a policy assumption.">
                Encryption at rest
              </SectionLabel>
              {!data.atRest.records.length ? (
                <PanelEmpty>
                  No storage or key-management policy evidence has been collected. Connect a cloud account or deploy an agent — until then this page
                  cannot state whether your data at rest is encrypted, and will not guess.
                </PanelEmpty>
              ) : (
                <TableShell minWidth={620}>
                  <thead>
                    <tr>
                      <Th>Surface</Th>
                      <Th>Asset</Th>
                      <Th>Algorithm</Th>
                      <Th>Key custody</Th>
                      <Th align="center">Encrypted</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.atRest.records.slice(0, 12).map((row) => (
                      <tr key={row.id}>
                        <Td>
                          <span className="block max-w-[170px] truncate text-white/80" title={row.detail}>
                            {row.surface}
                          </span>
                        </Td>
                        <Td>
                          <span className="block max-w-[140px] truncate text-[10.5px] text-white/60">{row.assetName}</span>
                        </Td>
                        <Td>
                          <span className="font-mono text-[10px] text-white/60">{row.algorithm || 'Not recorded'}</span>
                        </Td>
                        <Td>
                          <span className="text-[10.5px] text-white/55">{row.keyCustody}</span>
                        </Td>
                        <Td align="center">
                          {row.encrypted === true ? (
                            <Pill tone="good">Yes</Pill>
                          ) : row.encrypted === false ? (
                            <Pill tone="critical">No</Pill>
                          ) : (
                            <Pill tone="neutral">Undetermined</Pill>
                          )}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </TableShell>
              )}
            </Panel>

            <Panel>
              <SectionLabel icon={Vault} href="/dashboard/vault" hint="Quantum Vault protection: ML-KEM-1024 envelope encryption with AES-256-GCM content encryption and ML-DSA-65 signatures.">
                Vault protection
              </SectionLabel>
              {!data.vault.measured ? (
                <PanelEmpty>No vault files stored. The Quantum Vault protects files with ML-KEM-1024 + AES-256-GCM when you use it.</PanelEmpty>
              ) : (
                <>
                  <div className="grid grid-cols-3 gap-2">
                    <div className="rounded-lg border border-white/10 bg-black/25 p-3">
                      <div className="text-[9px] font-black uppercase tracking-wider text-white/40">Files</div>
                      <div className="mt-1 text-[20px] font-black text-cyan-300">{fmtNumber(data.vault.files)}</div>
                    </div>
                    <div className="rounded-lg border border-white/10 bg-black/25 p-3">
                      <div className="text-[9px] font-black uppercase tracking-wider text-white/40">Encrypted</div>
                      <div className="mt-1 text-[20px] font-black text-emerald-300">{fmtNumber(data.vault.encrypted)}</div>
                    </div>
                    <div className="rounded-lg border border-white/10 bg-black/25 p-3">
                      <div className="text-[9px] font-black uppercase tracking-wider text-white/40">Signature verified</div>
                      <div className={cn('mt-1 text-[20px] font-black', data.vault.signatureUnverified ? 'text-amber-300' : 'text-emerald-300')}>
                        {fmtNumber(data.vault.signatureVerified)}
                      </div>
                    </div>
                  </div>
                  <ul className="mt-3 space-y-1.5">
                    {data.vault.algorithms.map((row) => (
                      <li key={row.label} className="flex items-center justify-between gap-2 rounded-lg border border-white/10 bg-black/25 p-2.5">
                        <span className="min-w-0 truncate font-mono text-[10.5px] text-white/75">{row.label}</span>
                        <span className="flex items-center gap-2">
                          <span className="font-mono text-[10px] text-white/40">{fmtNumber(row.count)}</span>
                          <StrengthBadge strength={row.strength.strength as ProtectionStrengthKey} title={row.strength.rationale} />
                        </span>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </Panel>
          </div>

          {/* ---- Algorithm table ------------------------------------ */}
          <Panel>
            <SectionLabel icon={Atom} meta={`${fmtNumber(algorithmTotal)} primitive(s)`}>
              Primitive inventory
            </SectionLabel>

            <div className="mb-3 flex flex-wrap items-center gap-2">
              <SearchInput
                value={search}
                onChange={(value) => {
                  setSearch(value);
                  setOffset(0);
                }}
                placeholder="Search algorithm, asset or operation"
              />
              <FilterSelect
                label="Strength"
                value={strength}
                onChange={(value) => {
                  setStrength(value);
                  setOffset(0);
                }}
                options={[
                  { value: 'all', label: 'All' },
                  { value: 'quantum-safe', label: 'Quantum safe' },
                  { value: 'post-quantum', label: 'Post-quantum' },
                  { value: 'adequate', label: 'Adequate' },
                  { value: 'weakened', label: 'Weakened' },
                  { value: 'broken', label: 'Broken' },
                  { value: 'unknown', label: 'Unknown' },
                ]}
              />
              <FilterSelect
                label="Layer"
                value={layer}
                onChange={(value) => {
                  setLayer(value);
                  setOffset(0);
                }}
                options={[
                  { value: 'all', label: 'All' },
                  ...(Object.keys(LAYER_LABEL) as ProtectionLayer[]).map((key) => ({ value: key, label: LAYER_LABEL[key] })),
                ]}
              />
            </div>

            {algorithms.length === 0 ? (
              <PanelEmpty>{tableLoading ? 'Loading primitives…' : 'No primitive matches these filters.'}</PanelEmpty>
            ) : (
              <TableShell minWidth={980}>
                <thead>
                  <tr>
                    <Th>Algorithm</Th>
                    <Th>Layer</Th>
                    <Th align="right">Occurrences</Th>
                    <Th align="right">Assets</Th>
                    <Th>Strength</Th>
                    <Th>Security level</Th>
                    <Th>Target</Th>
                    <Th align="right">Last observed</Th>
                  </tr>
                </thead>
                <tbody>
                  {algorithms.map((row) => (
                    <tr key={`${row.layer}-${row.label}`} className="transition hover:bg-white/[0.04]">
                      <Td>
                        <button
                          type="button"
                          onClick={() => void openAlgorithm(row.label)}
                          className="font-mono text-[11px] font-semibold text-white hover:text-cyan-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
                        >
                          {row.label}
                        </button>
                      </Td>
                      <Td>
                        <span className="text-[10.5px] text-white/55">{LAYER_LABEL[row.layer]}</span>
                      </Td>
                      <Td align="right">{fmtNumber(row.observations)}</Td>
                      <Td align="right">{fmtNumber(row.assetIds.length || row.assetNames.length)}</Td>
                      <Td>
                        <StrengthBadge strength={row.strength.strength as ProtectionStrengthKey} title={row.strength.rationale} />
                      </Td>
                      <Td>
                        <SecurityBits classical={row.strength.classicalBits} quantum={row.strength.quantumBits} />
                      </Td>
                      <Td>
                        <span className="font-mono text-[10px] text-emerald-200/80">{row.strength.target || '—'}</span>
                      </Td>
                      <Td align="right">
                        <span className="font-mono text-[10px] text-white/40" title={absoluteTime(row.lastObservedAt)}>
                          {relativeTime(row.lastObservedAt)}
                        </span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
            )}
            <Pager offset={offset} limit={PAGE_SIZE} total={algorithmTotal} onChange={setOffset} />
          </Panel>

          {/* ---- Findings ------------------------------------------- */}
          <Panel>
            <SectionLabel icon={ShieldAlert} meta={`${fmtNumber(data.totals.findings)} open`} hint="Every finding states the threat that actually applies — classical break or Grover weakening — so remediation is not misprioritised.">
              Data-protection findings
            </SectionLabel>
            {data.findings.length === 0 ? (
              <PanelEmpty>
                No data-protection finding is open. That is only meaningful for what was actually measured — see the coverage figure above.
              </PanelEmpty>
            ) : (
              <ul className="space-y-2">
                {data.findings.slice(0, 12).map((finding) => (
                  <FindingRow key={finding.id} finding={finding} />
                ))}
              </ul>
            )}
          </Panel>

          <ProvenanceFooter telemetry={data.telemetry} reads={data.reads} />
        </>
      ) : null}

      <Drawer
        open={Boolean(detailId)}
        title={detail?.algorithm.label ?? 'Algorithm'}
        subtitle={detail ? LAYER_LABEL[detail.algorithm.layer] : undefined}
        onClose={() => setDetailId(null)}
      >
        {detailError ? <ErrorState message={detailError} onRetry={retryDetail} /> : null}
        {detailLoading && !detail ? <PanelEmpty>Loading evidence…</PanelEmpty> : null}
        {detail ? <AlgorithmInvestigation detail={detail} /> : null}
      </Drawer>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Grover explainer                                                    */
/* ------------------------------------------------------------------ */

/**
 * States the threat model in one panel.
 *
 * Without it, a reader arriving from TLS Telemetry — where RSA and ECDSA are
 * marked quantum-vulnerable — would reasonably expect AES-256 to be marked the
 * same way, and read its "Quantum Safe" badge as an inconsistency rather than
 * as the correct answer to a different question.
 */
function GroverExplainer({
  posture,
}: {
  posture: { weakenedAlgorithms: number; brokenAlgorithms: number; quantumSafeAlgorithms: number; quantumVulnerableAlgorithms: number };
}) {
  const [open, setOpen] = useState(false);
  return (
    <Panel>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-violet-400/30 bg-violet-500/10 text-violet-300">
            <Atom className="h-4.5 w-4.5" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <h2 className="text-[11px] font-black uppercase tracking-[0.14em] text-white">Why these grades differ from the TLS pages</h2>
            <p className="mt-1.5 max-w-4xl text-[11.5px] leading-relaxed text-white/60">
              Transport keys are broken by <strong className="text-white/85">Shor</strong>: a quantum computer recovers an RSA or ECC private key
              outright. Symmetric ciphers and hashes are only weakened by <strong className="text-white/85">Grover</strong>, which halves the
              effective security level. <strong className="text-emerald-300">AES-256 keeps ~128 bits and needs no migration.</strong> AES-128 drops
              to ~64 bits — weakened, not broken. 3DES, RC4, SHA-1 and MD5 are broken by classical cryptanalysis and should be fixed regardless of
              quantum timelines.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[9.5px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08]"
        >
          {open ? 'Hide the table' : 'Show the CNSA 2.0 table'}
        </button>
      </div>

      {open ? (
        <TableShell minWidth={720}>
          <thead>
            <tr>
              <Th>Primitive</Th>
              <Th>Classical</Th>
              <Th>Post-quantum (Grover/BHT)</Th>
              <Th>Verdict</Th>
            </tr>
          </thead>
          <tbody>
            {[
              ['AES-256', '256-bit', '~128-bit', 'quantum-safe', 'CNSA 2.0 cipher family; verify the mode and deployment'],
              ['ChaCha20-Poly1305', '256-bit', '~128-bit', 'quantum-safe', 'Outside the CNSA 2.0 suite'],
              ['AES-192', '192-bit', '~96-bit', 'adequate', 'Sound; CNSA 2.0 specifies AES-256'],
              ['AES-128', '128-bit', '~64-bit', 'weakened', 'Not broken — below the bar for long-lived data'],
              ['3DES · DES · RC4', 'already broken', '—', 'broken', 'Classical break; quantum is irrelevant'],
              ['SHA-384 · SHA-512', '—', 'adequate margin', 'quantum-safe', 'CNSA 2.0 hash families'],
              ['SHA-3', 'Varies by output', 'Varies by output', 'quantum-safe', 'NIST FIPS 202; outside the CNSA 2.0 suite'],
              ['SHA-256', '128-bit collision', '~85-bit', 'adequate', 'Sound; CNSA 2.0 specifies SHA-384 or SHA-512'],
              ['SHA-1 · MD5', 'collision-broken', '—', 'broken', 'Classical break; fix independently of PQC'],
              ['RSA · ECDSA · ECDH (wrapping data)', 'sound today', 'recovered by Shor', 'quantum-vulnerable', 'A break, not a halving — prioritise by data lifetime'],
            ].map(([primitive, classical, quantum, verdict, note]) => (
              <tr key={primitive}>
                <Td>
                  <span className="font-mono text-[10.5px] text-white/85">{primitive}</span>
                </Td>
                <Td>
                  <span className="font-mono text-[10.5px] text-white/55">{classical}</span>
                </Td>
                <Td>
                  <span className="font-mono text-[10.5px] text-white/55">{quantum}</span>
                </Td>
                <Td>
                  <div className="flex items-center gap-2">
                    <StrengthBadge strength={verdict as ProtectionStrengthKey} />
                    <span className="text-[10px] text-white/45">{note}</span>
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </TableShell>
      ) : null}

      <div className="mt-3 flex flex-wrap gap-1.5">
        <Pill tone="good">Quantum safe: {fmtNumber(posture.quantumSafeAlgorithms)}</Pill>
        <Pill tone="warning">Weakened by Grover: {fmtNumber(posture.weakenedAlgorithms)}</Pill>
        <Pill tone="critical">Quantum vulnerable (Shor): {fmtNumber(posture.quantumVulnerableAlgorithms)}</Pill>
        <Pill tone="critical">Broken classically: {fmtNumber(posture.brokenAlgorithms)}</Pill>
        <Link
          to="/dashboard/protocol-analytics"
          className="rounded-full border border-cyan-400/35 bg-cyan-500/10 px-2.5 py-0.5 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 no-underline hover:bg-cyan-500/20"
        >
          Transport ciphers →
        </Link>
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Algorithm panel                                                     */
/* ------------------------------------------------------------------ */

function AlgorithmPanel({
  icon,
  title,
  hint,
  rows,
  onOpen,
  empty,
}: {
  icon: typeof Lock;
  title: string;
  hint: string;
  rows: AlgorithmRow[];
  onOpen: (label: string) => void;
  empty: string;
}) {
  return (
    <Panel>
      <SectionLabel icon={icon} meta={rows.length ? `${fmtNumber(rows.length)} distinct` : undefined} hint={hint}>
        {title}
      </SectionLabel>
      {rows.length === 0 ? (
        <PanelEmpty>{empty}</PanelEmpty>
      ) : (
        <ul className="space-y-1.5">
          {rows.slice(0, 8).map((row) => (
            <li key={row.label} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <button
                  type="button"
                  onClick={() => onOpen(row.label)}
                  className="min-w-0 truncate font-mono text-[11px] font-semibold text-white hover:text-cyan-300"
                >
                  {row.label}
                </button>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] text-white/40">{fmtNumber(row.observations)}×</span>
                  <StrengthBadge strength={row.strength.strength as ProtectionStrengthKey} title={row.strength.rationale} />
                </div>
              </div>
              <div className="mt-1 flex flex-wrap items-center justify-between gap-2">
                <SecurityBits classical={row.strength.classicalBits} quantum={row.strength.quantumBits} />
                {row.strength.target ? (
                  <span className="font-mono text-[9.5px] text-emerald-200/70">→ {row.strength.target}</span>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Key material                                                        */
/* ------------------------------------------------------------------ */

function KeyMaterialPanel({ keys }: { keys: ReturnType<typeof useEncryptionMonitoring>['data'] extends null ? never : NonNullable<ReturnType<typeof useEncryptionMonitoring>['data']>['keys'] }) {
  return (
    <Panel>
      <SectionLabel
        icon={FileKey}
        href="/dashboard/qkms/inventory"
        meta={keys.measured ? `${fmtNumber(keys.total)} key(s)` : undefined}
        hint="Key material the platform manages, with the entropy source it was generated from and its lifecycle state. Rotation is counted only where a key records the key it replaced."
      >
        Key material
      </SectionLabel>

      {!keys.measured ? (
        <PanelEmpty>
          No key material is managed by this tenant. QKMS generates and tracks keys with QRNG entropy — until then, no key lifecycle, entropy quality
          or rotation figure can be stated for your estate.
        </PanelEmpty>
      ) : (
        <>
          <div className="grid gap-2 sm:grid-cols-3 xl:grid-cols-6">
            {(
              [
                ['Active', keys.lifecycle.active, 'good'],
                ['Expiring', keys.lifecycle.expiring, 'warning'],
                ['Expired', keys.lifecycle.expired, 'critical'],
                ['Revoked', keys.lifecycle.revoked, 'critical'],
                ['Rotations evidenced', keys.rotationsObserved, 'info'],
                ['No expiry set', keys.withoutExpiry, 'warning'],
              ] as const
            ).map(([label, value, tone]) => (
              <div key={label} className="rounded-lg border border-white/10 bg-black/25 p-3">
                <div className="text-[9px] font-black uppercase tracking-wider text-white/40">{label}</div>
                <div className={cn('mt-1 text-[20px] font-black', value ? TONE[tone].text : 'text-white/30')}>{fmtNumber(value)}</div>
              </div>
            ))}
          </div>

          {keys.entropySources.length ? (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {keys.entropySources.map((source) => (
                <Pill key={source.label} tone={/qrng|quantum/i.test(source.label) ? 'good' : 'neutral'}>
                  {source.label}: {fmtNumber(source.count)} ({fmtPercent(source.percent)})
                </Pill>
              ))}
              {keys.averageQuality !== null ? (
                <Pill tone={keys.averageQuality >= 0.9 ? 'good' : keys.averageQuality >= 0.8 ? 'warning' : 'critical'}>
                  Mean entropy quality {fmtPercent(keys.averageQuality * 100)}
                </Pill>
              ) : null}
            </div>
          ) : null}

          <div className="mt-3">
            <TableShell minWidth={820}>
              <thead>
                <tr>
                  <Th>Key</Th>
                  <Th>Algorithm</Th>
                  <Th>Entropy source</Th>
                  <Th align="right">Quality</Th>
                  <Th>Lifecycle</Th>
                  <Th>Strength</Th>
                  <Th align="right">Expires</Th>
                </tr>
              </thead>
              <tbody>
                {keys.keys.slice(0, 10).map((key: KeyRecord) => (
                  <tr key={key.id}>
                    <Td>
                      <span className="block max-w-[170px] truncate font-semibold text-white">{key.label}</span>
                      {key.rotatedFromId ? <span className="font-mono text-[9px] text-cyan-300">rotated</span> : null}
                    </Td>
                    <Td>
                      <span className="font-mono text-[10.5px]">
                        {key.algorithm}
                        {key.bitLength ? `-${key.bitLength}` : ''}
                      </span>
                    </Td>
                    <Td>
                      <span className="text-[10.5px] text-white/60">{key.entropySource}</span>
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[10.5px] text-white/60">
                        {key.qualityScore === null ? 'Not recorded' : fmtPercent(key.qualityScore * 100)}
                      </span>
                    </Td>
                    <Td>
                      <Pill
                        tone={
                          key.lifecycle === 'expired' || key.lifecycle === 'revoked'
                            ? 'critical'
                            : key.lifecycle === 'expiring'
                              ? 'warning'
                              : key.lifecycle === 'active'
                                ? 'good'
                                : 'neutral'
                        }
                      >
                        {key.lifecycle}
                      </Pill>
                    </Td>
                    <Td>
                      <StrengthBadge strength={key.strength.strength as ProtectionStrengthKey} title={key.strength.rationale} />
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[10px] text-white/50">
                        {key.daysToExpiry === null ? 'No expiry' : key.daysToExpiry < 0 ? `Expired ${Math.abs(key.daysToExpiry)}d ago` : `${key.daysToExpiry}d`}
                      </span>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
          </div>
        </>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Finding row                                                         */
/* ------------------------------------------------------------------ */

function FindingRow({ finding }: { finding: EncryptionFinding }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="rounded-lg border border-white/10 bg-black/25 p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="text-[12px] font-black text-white">{finding.title}</h3>
          <p className="mt-1 font-mono text-[10px] text-white/40">
            {finding.assetName} · {LAYER_LABEL[finding.layer]} · {finding.instances > 1 ? `${finding.instances} instances · ` : ''}
            {relativeTime(finding.lastObservedAt)}
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          <Pill tone="info">{finding.standard}</Pill>
          <button
            type="button"
            onClick={() => setOpen((value) => !value)}
            aria-expanded={open}
            className="rounded-md border border-white/12 bg-white/[0.04] px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08]"
          >
            {open ? 'Hide' : 'Detail'}
          </button>
        </div>
      </div>
      {open ? (
        <div className="mt-3 grid gap-3 lg:grid-cols-2">
          <div className="space-y-2">
            <div>
              <h4 className="text-[9px] font-black uppercase tracking-wider text-white/35">Impact</h4>
              <p className="mt-1 text-[11px] leading-relaxed text-white/65">{finding.impact}</p>
            </div>
            <div>
              <h4 className="text-[9px] font-black uppercase tracking-wider text-white/35">Remediation</h4>
              <p className="mt-1 text-[11px] leading-relaxed text-white/65">{finding.remediation}</p>
            </div>
            <div className="rounded-md border border-violet-500/25 bg-violet-500/5 p-2.5">
              <h4 className="text-[9px] font-black uppercase tracking-wider text-violet-300/70">Does quantum change this?</h4>
              <p className="mt-1 text-[11px] leading-relaxed text-violet-100/80">{finding.quantumRelevance}</p>
            </div>
          </div>
          <div>
            <h4 className="mb-1.5 text-[9px] font-black uppercase tracking-wider text-white/35">Evidence</h4>
            <EvidenceList evidence={finding.evidence} />
          </div>
        </div>
      ) : null}
    </li>
  );
}

/* ------------------------------------------------------------------ */
/* Algorithm investigation                                             */
/* ------------------------------------------------------------------ */

function AlgorithmInvestigation({ detail }: { detail: AlgorithmDetail }) {
  const { algorithm, observations, findings } = detail;
  return (
    <>
      <section className="rounded-lg border border-white/10 bg-black/25 p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <StrengthBadge strength={algorithm.strength.strength as ProtectionStrengthKey} />
          <Pill tone="neutral">{LAYER_LABEL[algorithm.layer]}</Pill>
          <Pill tone="info">{algorithm.strength.standard}</Pill>
        </div>
        <p className="mt-2.5 text-[12px] leading-relaxed text-white/70">{algorithm.strength.rationale}</p>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <div className="rounded-md border border-white/10 bg-black/25 p-2.5">
            <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Security level</div>
            <div className="mt-1">
              <SecurityBits classical={algorithm.strength.classicalBits} quantum={algorithm.strength.quantumBits} />
            </div>
          </div>
          <div className="rounded-md border border-emerald-500/25 bg-emerald-500/5 p-2.5">
            <div className="text-[9px] font-black uppercase tracking-wider text-emerald-300/70">Approved target</div>
            <div className="mt-1 font-mono text-[11px] text-emerald-100/90">{algorithm.strength.target || 'Already meets the bar'}</div>
          </div>
        </div>
        <dl className="mt-3 grid grid-cols-2 gap-2 text-[10.5px]">
          <div>
            <dt className="text-white/35">Observations</dt>
            <dd className="text-white/75">{fmtNumber(algorithm.observations)}</dd>
          </div>
          <div>
            <dt className="text-white/35">Assets</dt>
            <dd className="text-white/75">{fmtNumber(algorithm.assetIds.length || algorithm.assetNames.length)}</dd>
          </div>
          <div>
            <dt className="text-white/35">First observed</dt>
            <dd className="text-white/75">{absoluteTime(algorithm.firstObservedAt)}</dd>
          </div>
          <div>
            <dt className="text-white/35">Last observed</dt>
            <dd className="text-white/75">{absoluteTime(algorithm.lastObservedAt)}</dd>
          </div>
        </dl>
        {algorithm.operations.length ? (
          <div className="mt-3">
            <h4 className="text-[9px] font-black uppercase tracking-wider text-white/35">Observed performing</h4>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {algorithm.operations.map((operation) => (
                <Pill key={operation} tone="info">
                  {operation}
                </Pill>
              ))}
            </div>
          </div>
        ) : null}
      </section>

      <section>
        <h3 className="mb-2 text-[10px] font-black uppercase tracking-wider text-white/40">Where it was measured ({fmtNumber(observations.length)})</h3>
        {observations.length === 0 ? (
          <PanelEmpty>No individual observation retained for this primitive.</PanelEmpty>
        ) : (
          <ul className="space-y-1.5">
            {observations.slice(0, 25).map((observation) => (
              <li key={observation.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="min-w-0 truncate text-[11px] font-semibold text-white">{observation.assetName}</span>
                  <span className="font-mono text-[9.5px] text-white/35">{relativeTime(observation.observedAt)}</span>
                </div>
                <p className="mt-1 break-words font-mono text-[10px] text-white/50">{observation.location}</p>
                <p className="mt-1 font-mono text-[9px] text-white/30">
                  {observation.evidence.table} · {observation.evidence.recordId}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>

      {findings.length ? (
        <section>
          <h3 className="mb-2 text-[10px] font-black uppercase tracking-wider text-white/40">Findings</h3>
          <ul className="space-y-2">
            {findings.map((finding) => (
              <FindingRow key={finding.id} finding={finding} />
            ))}
          </ul>
        </section>
      ) : null}
    </>
  );
}
