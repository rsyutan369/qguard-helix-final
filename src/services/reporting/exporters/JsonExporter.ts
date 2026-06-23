import type { EnterpriseAssessmentReport } from '../schemas/ReportSchema';

/** Full machine-readable export of the unified report model. */
export function exportJson(report: EnterpriseAssessmentReport): Blob {
  return new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
}
