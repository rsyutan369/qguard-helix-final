/**
 * Remediation-playbook presentation model.
 *
 * Every playbook shares the same enterprise change-management controls
 * (pre-requisites, dependencies, validation, rollback, SLA impact). Printing
 * them inside all six playbooks repeated 50+ identical rows in a single report
 * and buried the handful of lines that actually differ per finding.
 *
 * `buildPlaybookStandardControls` hoists every row whose value is identical
 * across ALL playbooks into one "Standard Change Controls" block; `playbookRows`
 * then renders each playbook with only its finding-specific rows. Nothing is
 * dropped — the hoisted rows are stated once and explicitly scoped to every
 * playbook, so the document stays complete while reading as a premium runbook.
 *
 * Both helpers are pure and shared by all exporters, so the PDF, HTML, DOCX,
 * XLSX, CSV and PPTX renderings can never drift apart.
 */

import type { PlaybookDetail, PlaybookStandardControls } from './schemas/ReportSchema';

type RowDef = { key: string; label: string; value: (p: PlaybookDetail) => string };

/** Ordered render definition for a playbook — the single source both the
 *  hoisting pass and every exporter read. */
const ROW_DEFS: RowDef[] = [
  { key: 'currentState', label: 'Current State', value: (p) => p.currentState },
  { key: 'targetState', label: 'Target State', value: (p) => p.targetState },
  { key: 'prerequisites', label: 'Pre-Requisites', value: (p) => p.prerequisites.join('; ') },
  { key: 'dependencies', label: 'Dependencies', value: (p) => p.dependencies.join('; ') },
  { key: 'executionSteps', label: 'Execution Steps', value: (p) => p.executionSteps.map((s, i) => `${i + 1}. ${s}`).join('  ') },
  { key: 'validationSteps', label: 'Validation Steps', value: (p) => p.validationSteps.join('; ') },
  { key: 'rollbackSteps', label: 'Rollback Steps', value: (p) => p.rollbackSteps.join('; ') },
  { key: 'successCriteria', label: 'Success Criteria', value: (p) => p.successCriteria.join('; ') },
  { key: 'estimatedDowntime', label: 'Expected Downtime', value: (p) => p.estimatedDowntime },
  { key: 'maintenanceWindow', label: 'Maintenance Window', value: (p) => p.maintenanceWindow },
  { key: 'rollbackDuration', label: 'Rollback Duration', value: (p) => p.rollbackDuration },
  { key: 'validationOwner', label: 'Validation Owner', value: (p) => p.validationOwner },
  { key: 'successKpi', label: 'Success KPI', value: (p) => p.successKpi },
  { key: 'automationStatus', label: 'Automation Status', value: (p) => p.automationStatus },
  { key: 'slaImpact', label: 'SLA Impact', value: (p) => p.slaImpact },
];

/**
 * Rows that are byte-identical across every playbook, hoisted into a single
 * block. Requires at least two playbooks — hoisting a lone playbook's rows
 * would just move them without removing any repetition.
 */
export function buildPlaybookStandardControls(details: PlaybookDetail[]): PlaybookStandardControls {
  if (details.length < 2) return { applies: details.length, sharedKeys: [], rows: [], note: '' };

  const shared = ROW_DEFS.filter((def) => {
    const first = def.value(details[0]);
    return first.length > 0 && details.every((d) => def.value(d) === first);
  });
  if (!shared.length) return { applies: details.length, sharedKeys: [], rows: [], note: '' };

  return {
    applies: details.length,
    sharedKeys: shared.map((d) => d.key),
    rows: shared.map((d) => ({ step: d.label, detail: d.value(details[0]) })),
    note: `These controls are identical for all ${details.length} remediation playbook(s) below and are stated once here rather than repeated in each. Every playbook that follows is governed by them; the per-playbook tables list only what differs for that finding.`,
  };
}

/** Render rows for one playbook, minus anything hoisted into the shared block. */
export function playbookRows(detail: PlaybookDetail, sharedKeys: string[] = []): Array<[string, string]> {
  const skip = new Set(sharedKeys);
  return ROW_DEFS.filter((def) => !skip.has(def.key)).map((def) => [def.label, def.value(detail)] as [string, string]);
}
