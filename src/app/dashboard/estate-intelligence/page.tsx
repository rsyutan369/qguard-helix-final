import { PageErrorBoundary } from '../_components/external-trust/_shared';
import EstateIntelligence from './EstateIntelligence';

export default function EstateIntelligencePage() {
  return (
    <PageErrorBoundary page="Estate Remediation Intelligence">
      <EstateIntelligence />
    </PageErrorBoundary>
  );
}
