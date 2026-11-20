import { useTelemetryAccount } from '@/hooks/use-observed-paged-resource';
import ProtocolAnalytics from './ProtocolAnalytics';

export default function ProtocolAnalyticsPage() {
  const { accountId } = useTelemetryAccount();
  return <ProtocolAnalytics key={accountId} />;
}
