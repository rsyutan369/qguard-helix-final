import { PageErrorBoundary } from '../_components/external-trust/_shared';
import VendorPqcReadiness from './VendorPqcReadiness';

export default function VendorPqcReadinessPage() {
  return (
    <PageErrorBoundary page="Vendor PQC Readiness">
      <VendorPqcReadiness />
    </PageErrorBoundary>
  );
}
