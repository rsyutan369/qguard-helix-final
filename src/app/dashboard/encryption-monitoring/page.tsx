import { useTelemetryAccount } from '@/hooks/use-observed-paged-resource';
import EncryptionMonitoring from './EncryptionMonitoring';

export default function EncryptionMonitoringPage() {
  const { accountId } = useTelemetryAccount();
  return <EncryptionMonitoring key={accountId} />;
}
