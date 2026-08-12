import { PageErrorBoundary } from '../_components/external-trust/_shared';
import HybridCryptoLab from './HybridCryptoLab';

export default function HybridCryptoCompatibilityLabPage() {
  return (
    <PageErrorBoundary page="Hybrid Crypto Lab">
      <HybridCryptoLab />
    </PageErrorBoundary>
  );
}
