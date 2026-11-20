import { useTelemetryAccount } from '@/hooks/use-observed-paged-resource';
import TlsOrchestrator from './TlsOrchestrator';

export default function TlsOrchestratorPage() {
  const { accountId } = useTelemetryAccount();
  return <TlsOrchestrator key={accountId} />;
}
