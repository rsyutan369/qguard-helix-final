import MigrationSandbox from './MigrationSandbox';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '@/contexts/auth-context';
import { SandboxLab } from './SandboxLab';

export default function MigrationSandboxPage() {
  const [params] = useSearchParams();
  const { user } = useAuth();
  const analysis = params.get('view') === 'analysis' || (params.has('planId') && !params.has('asset'));
  return analysis ? <MigrationSandbox key={user?.id} /> : <SandboxLab key={user?.id} />;
}
