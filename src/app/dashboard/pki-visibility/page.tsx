import { useTelemetryAccount } from '@/hooks/use-observed-paged-resource';
import PkiVisibility from './PkiVisibility';

export default function PkiVisibilityPage() {
  const { accountId } = useTelemetryAccount();
  return <PkiVisibility key={accountId} />;
}
