import { PageErrorBoundary } from '../_components/external-trust/_shared';
import TrustChainAnalyzer from './TrustChainAnalyzer';

export default function TrustChainAnalyzerPage() {
  return (
    <PageErrorBoundary page="Trust Chain Analyzer">
      <TrustChainAnalyzer />
    </PageErrorBoundary>
  );
}
