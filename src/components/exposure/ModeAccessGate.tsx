'use client';

/**
 * Subscription gate for the Local and Dev assessment modes.
 *
 * The brief for this surface is unusual and worth stating: it must SELL the
 * mode, not hide it. A visitor who cannot run a Local assessment should still
 * leave knowing exactly what one does — which engines run, what they read, what
 * never leaves their device — because that is the argument for the plan. A gate
 * that renders "Upgrade required" over an empty panel makes the case for
 * nothing.
 *
 * So the gate is a full disclosure of the mode with the execution controls
 * removed, and one honest sentence about why. The three refusal reasons get
 * three different calls to action, because "sign in", "reactivate your
 * subscription" and "upgrade your plan" are three different problems and
 * sending a lapsed customer to the pricing page is a small insult.
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'motion/react';
import { ArrowRight, Check, Code2, Lock, MonitorSmartphone, ShieldCheck, Sparkles } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ACCENT, Panel, SectionLabel } from '@/components/quantum-scan/ui';
import { TIER_LABEL, type ExposureScanMode, type PlanTier } from '@/lib/subscription-access';
import type { UseExposureAccessResult } from '@/hooks/use-exposure-access';

/* ─────────────────────────────────────────────────────── mode copy ────────── */

interface ModeCopy {
  label: string;
  icon: typeof MonitorSmartphone;
  headline: string;
  summary: string;
  /** What the mode actually reads. Drawn from the engine registry's own words. */
  capabilities: string[];
  /** The one thing about this mode a buyer most needs to know. */
  assurance: { title: string; body: string };
}

const MODE_COPY: Record<Exclude<ExposureScanMode, 'web'>, ModeCopy> = {
  local: {
    label: 'Local',
    icon: MonitorSmartphone,
    headline: 'Local device, filesystem and codebase assessment',
    summary:
      'Point the scanner at a folder on your own machine and it reads the cryptography your code actually uses — the algorithms, the key sizes, the roles they are used in, and the dependencies that carry them.',
    capabilities: [
      'Cryptographic usage across 16 languages, proven from the call shape rather than the name',
      'Credential and key material, fingerprinted and never stored',
      'Dependency manifests across nine package ecosystems',
      'TLS, PKI, SSH and application configuration files',
      'X.509 certificates and OpenSSH keys, parsed and classified',
      'Dockerfiles, Compose, Kubernetes, Helm and Kustomize',
      'Terraform, CloudFormation, Bicep, ARM and Ansible',
      'CI/CD pipelines across eight platforms',
      'Repository references, remotes and loose Git objects',
    ],
    assurance: {
      title: 'Your source never leaves the device',
      body:
        'Files are read through the browser’s own picker after you authorise a folder, and analysed in a Web Worker in the same tab. No file content, secret value or Git object is uploaded. Only a sanitised assessment can be synchronised, and only when you explicitly choose to.',
    },
  },
  dev: {
    label: 'Dev',
    icon: Code2,
    headline: 'Repository, container, Kubernetes and cloud-native assessment',
    summary:
      'Connect a repository, a cluster, a registry or a cloud account and the platform assesses it server-side — then correlates what it finds across those layers into one supply-chain picture.',
    capabilities: [
      'GitHub, GitLab, Bitbucket, Azure DevOps and self-hosted Git',
      'Everything the Local engines read, run over the fetched repository',
      'Live Kubernetes clusters through a read-only ServiceAccount',
      'Container registries — OCI manifests and config blobs, read-only',
      'AWS, Azure and Google Cloud, read-only and metadata-first',
      'Cross-layer supply-chain correlation between code, image and cluster',
      'Private repositories through your own credential, never a platform token',
    ],
    assurance: {
      title: 'Read-only, and scoped to your tenant',
      body:
        'Every connector uses credentials that belong to you and are used read-only: no repository, cluster, registry or cloud account is ever modified, and no repository code is executed. Anything a credential cannot read is reported as Not Assessed rather than as a pass.',
    },
  },
};

/* ────────────────────────────────────────────────────── plan ribbon ───────── */

function PlanChips({ plans, className }: { plans: PlanTier[]; className?: string }) {
  if (plans.length === 0) return null;
  return (
    <div className={cn('flex flex-wrap items-center gap-1.5', className)}>
      {plans.map((plan) => (
        <span
          key={plan}
          className="inline-flex items-center gap-1 rounded-md border border-cyan-400/25 bg-cyan-400/[0.07] px-2 py-0.5 font-mono text-[9.5px] font-bold uppercase tracking-[0.14em] text-cyan-200"
        >
          <Check aria-hidden className="h-2.5 w-2.5" />
          {TIER_LABEL[plan]}
        </span>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------ skeleton ---- */

/**
 * Shown while the entitlement is still resolving.
 *
 * It exists for one reason: a Pro customer opening the Dev tab must never see
 * the upgrade wall flash before their plan resolves. Rendering a neutral shell
 * for a few hundred milliseconds is the difference between a product that knows
 * who you are and one that asks you to buy what you already own.
 */
export function ModeAccessSkeleton() {
  return (
    <div className="space-y-5" role="status" aria-busy="true" aria-label="Checking your plan">
      <Panel className="overflow-hidden">
        <div className="flex items-start gap-4 px-5 py-5 sm:px-6">
          <span className="h-11 w-11 shrink-0 animate-pulse rounded-2xl bg-white/[0.05]" />
          <div className="min-w-0 flex-1 space-y-2.5">
            <span className="block h-4 w-52 animate-pulse rounded bg-white/[0.06]" />
            <span className="block h-3 w-full max-w-2xl animate-pulse rounded bg-white/[0.04]" />
            <span className="block h-3 w-2/3 max-w-xl animate-pulse rounded bg-white/[0.04]" />
            <span className="mt-2 block h-9 w-40 animate-pulse rounded-lg bg-white/[0.05]" />
          </div>
        </div>
      </Panel>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        <Panel className="h-64 animate-pulse" />
        <Panel className="h-64 animate-pulse" />
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────────────── the gate ────────── */

export interface ModeAccessGateProps {
  mode: Exclude<ExposureScanMode, 'web'>;
  access: UseExposureAccessResult;
  /** Rendered under the CTA — the shared enterprise upsell block. */
  upsellSlot?: React.ReactNode;
}

export function ModeAccessGate({ mode, access, upsellSlot }: ModeAccessGateProps) {
  const copy = MODE_COPY[mode];
  const Icon = copy.icon;

  /* Three refusals, three next steps. */
  const cta = React.useMemo(() => {
    switch (access.reason) {
      case 'unauthenticated':
        return {
          primary: { label: 'Sign in', to: '/login' },
          secondary: { label: 'See plans', to: '/#pricing' },
          note: `${copy.label} assessment is included in the ${access.includedIn.map((plan) => TIER_LABEL[plan]).join(', ')} plans. Sign in to use it, or run the Web assessment now without an account.`,
        };
      case 'inactive-subscription':
        return {
          primary: { label: 'Manage subscription', to: '/dashboard/settings?tab=subscription' },
          secondary: null,
          note: 'Your plan includes this assessment, but the subscription is not currently active. Reactivating it restores access immediately.',
        };
      case 'tier-too-low':
      default:
        return {
          primary: { label: `Upgrade to ${TIER_LABEL[access.requiredTier as PlanTier]}`, to: '/#pricing' },
          secondary: { label: 'Compare plans', to: '/#pricing' },
          note: `${copy.label} assessment is included in the ${access.includedIn.map((plan) => TIER_LABEL[plan]).join(', ')} plans.`,
        };
    }
  }, [access.reason, access.requiredTier, access.includedIn, copy.label]);

  return (
    <div className="space-y-5">
      {/* ── the lock, stated once, at the top ─────────────────────────────── */}
      <Panel className="overflow-hidden border-cyan-400/20">
        <div className="relative">
          {/* A single soft wash so the gate reads as a premium surface rather
              than an error state. Pointer-events-none: it must never eat a click. */}
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 bg-[radial-gradient(120%_140%_at_10%_0%,rgba(34,211,238,0.10),transparent_60%),radial-gradient(90%_120%_at_100%_0%,rgba(139,92,246,0.10),transparent_55%)]"
          />

          <div className="relative flex flex-wrap items-start gap-4 px-5 py-5 sm:px-6">
            <span className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl border border-cyan-400/30 bg-cyan-400/[0.08] text-cyan-300">
              <Icon className="h-5 w-5" />
            </span>

            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-[16px] font-black tracking-tight text-white sm:text-[17px]">
                  {copy.label} Assessment
                </h2>
                <span className="inline-flex items-center gap-1 rounded-md border border-amber-400/30 bg-amber-400/[0.08] px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-amber-300">
                  <Lock aria-hidden className="h-2.5 w-2.5" />
                  {access.reason === 'unauthenticated' ? 'Sign in required' : 'Plan required'}
                </span>
              </div>

              <p className="mt-1.5 max-w-3xl text-[13px] leading-relaxed text-slate-300">{copy.summary}</p>

              <p className="mt-2.5 text-[12.5px] leading-relaxed text-cyan-100/85">{cta.note}</p>
              <PlanChips plans={access.includedIn} className="mt-2.5" />

              {access.degraded && (
                <p className="mt-3 rounded-lg border border-amber-400/25 bg-amber-400/[0.06] px-3 py-2 text-[11.5px] leading-relaxed text-amber-100/85">
                  Your subscription could not be verified just now, so this is showing the locked state. If you hold a
                  plan that includes {copy.label} assessment, reload in a moment — this is a temporary read failure, not
                  a change to your entitlement.
                </p>
              )}

              <div className="mt-4 flex flex-wrap items-center gap-2.5">
                <Link
                  to={cta.primary.to}
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-violet-500 to-cyan-400 px-5 py-2.5 text-[13px] font-black text-[#04060e] no-underline transition-opacity hover:opacity-90"
                >
                  {cta.primary.label}
                  <ArrowRight aria-hidden className="h-4 w-4" />
                </Link>
                {cta.secondary && (
                  <Link
                    to={cta.secondary.to}
                    className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/[0.10] px-4 py-2.5 text-[13px] font-semibold text-slate-300 no-underline transition-colors hover:border-cyan-400/30 hover:text-cyan-200"
                  >
                    {cta.secondary.label}
                  </Link>
                )}
                <Link
                  to="/public-scan"
                  className="inline-flex items-center gap-1.5 px-1 py-2.5 text-[12.5px] font-semibold text-slate-400 no-underline transition-colors hover:text-cyan-300"
                >
                  Run the free Web assessment instead
                  <ArrowRight aria-hidden className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>
          </div>
        </div>
      </Panel>

      {/* ── what it does, in full ─────────────────────────────────────────── */}
      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        <Panel className="overflow-hidden">
          <div className="border-b border-white/[0.06] px-5 py-3">
            <SectionLabel>What {copy.label} assessment reads</SectionLabel>
          </div>
          <p className="border-b border-white/[0.06] px-5 py-2.5 text-[12px] leading-relaxed text-slate-400">
            {copy.headline}.
          </p>
          <ul className="divide-y divide-white/[0.04]">
            {copy.capabilities.map((capability, index) => (
              <motion.li
                key={capability}
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.25, delay: Math.min(index * 0.03, 0.24) }}
                className="flex items-start gap-2.5 px-5 py-2.5"
              >
                <Check aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-400" />
                <span className="text-[12.5px] leading-relaxed text-slate-300">{capability}</span>
              </motion.li>
            ))}
          </ul>
        </Panel>

        <div className="space-y-5">
          <Panel className="overflow-hidden border-emerald-400/20">
            <div className="flex items-start gap-3 px-5 py-4">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-emerald-400/25 bg-emerald-400/[0.08] text-emerald-300">
                <ShieldCheck className="h-4.5 w-4.5" />
              </span>
              <div className="min-w-0">
                <h3 className="text-[13.5px] font-black text-white">{copy.assurance.title}</h3>
                <p className="mt-1 text-[12px] leading-relaxed text-slate-400">{copy.assurance.body}</p>
              </div>
            </div>
          </Panel>

          <Panel className="overflow-hidden">
            <div className="border-b border-white/[0.06] px-5 py-3">
              <SectionLabel accent={ACCENT.violet}>Included in</SectionLabel>
            </div>
            <ul className="divide-y divide-white/[0.04]">
              {access.includedIn.map((plan) => (
                <li key={plan} className="flex items-center justify-between gap-3 px-5 py-2.5">
                  <span className="text-[13px] font-bold text-white">{TIER_LABEL[plan]}</span>
                  <span className="inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-widest text-emerald-300">
                    <Check aria-hidden className="h-3 w-3" />
                    Included
                  </span>
                </li>
              ))}
            </ul>
            <p className="border-t border-white/[0.06] px-5 py-2.5 text-[11.5px] leading-relaxed text-slate-500">
              <Sparkles aria-hidden className="mr-1 inline h-3 w-3 -translate-y-px text-violet-300" />
              The Web assessment stays free and needs no account, on every plan and none.
            </p>
          </Panel>

          {upsellSlot}
        </div>
      </div>
    </div>
  );
}
