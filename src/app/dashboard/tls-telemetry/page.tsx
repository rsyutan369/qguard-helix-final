import { useTelemetryAccount } from '@/hooks/use-observed-paged-resource';
import TlsTelemetry from './TlsTelemetry';

export default function TlsTelemetryPage() {
  const { accountId } = useTelemetryAccount();
  return <TlsTelemetry key={accountId} />;
}
