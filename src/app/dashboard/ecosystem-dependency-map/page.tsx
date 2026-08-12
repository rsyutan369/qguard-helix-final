import { PageErrorBoundary } from '../_components/external-trust/_shared';
import EcosystemDependencyMap from './EcosystemDependencyMap';

export default function EcosystemDependencyMapPage() {
  return (
    <PageErrorBoundary page="Ecosystem Dependency Map">
      <EcosystemDependencyMap />
    </PageErrorBoundary>
  );
}
