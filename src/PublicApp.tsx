/**
 * Website edition — the public site published to static hosting
 * (`npm run build:public` → dist-public/, entry src/main-public.tsx).
 *
 * Marketing pages, resources, the Web assessment, and its shared account
 * flows are routed here. Dashboard, checkout and Agent Center destinations
 * resolve to PlatformOnly.
 * tools/deploy/public-site-check.ts fails the build if that ever changes.
 *
 * Routes are kept identical to src/App.tsx so links shared from either build
 * resolve the same way.
 */
import { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Navigate, Route, Routes } from 'react-router-dom';
import { AuthProvider } from './contexts/auth-context';
import { ThemeProvider } from './contexts/theme-context';
import Landing from './pages/Landing';
import PostQuantumMigrationPlatform from './pages/PostQuantumMigrationPlatform';
import QuantumTrustGovernanceCenter from './pages/QuantumTrustGovernanceCenter';
import PqcSolutions from './pages/PqcSolutions';
import QguardHelixFeatures from './pages/QguardHelixFeatures';
import TermsPage from './pages/Terms';
import PrivacyPage from './pages/Privacy';
import RefundPage from './pages/Refund';
import ContactPage from './pages/Contact';
import PlatformOnly from './pages/PlatformOnly';
import DocsPage from './app/docs/page';
import PqcChecklistPage from './app/resources/pqc-checklist/page';
import QuantumSimulationPage from './app/resources/quantum-simulation/page';
import QguardMessagingOverview from './app/qguard-messaging/page';
import QguardMessagingSecureChat from './app/qguard-messaging/secure-chat/page';
import QguardMessagingQuantumVault from './app/qguard-messaging/quantum-vault/page';
import QuantumReadinessAssessmentPage from './app/quantum-readiness-assessment/page';
import PublicScanPage from './app/public-scan/page';
import { SIGNUP_CONFIRMATION_PATH } from './lib/signup-confirmation';
import { PUBLIC_SCAN_CONFIRMATION_PATH } from './lib/public-scan-auth';

const LoginPage = lazy(() => import('./app/authentication/login/page'));
const RegisterPage = lazy(() => import('./app/authentication/register/page'));
const ConfirmEmailPage = lazy(() => import('./app/authentication/confirm-email/page'));
const OAuthCallbackPage = lazy(() => import('./app/authentication/oauth-callback/page'));
const ResetPasswordPage = lazy(() => import('./app/authentication/reset-password/page'));

export default function PublicApp() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Router>
          <Suspense fallback={<p role="status">Loading…</p>}>
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/docs/*" element={<DocsPage />} />
            <Route path="/qguard-messaging" element={<QguardMessagingOverview />} />
            <Route path="/qguard-messaging/secure-chat" element={<QguardMessagingSecureChat />} />
            <Route path="/qguard-messaging/quantum-vault" element={<QguardMessagingQuantumVault />} />
            <Route path="/quantum-readiness-assessment" element={<QuantumReadinessAssessmentPage />} />
            <Route path="/public-scan" element={<PublicScanPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/auth/callback" element={<OAuthCallbackPage />} />
            <Route path={SIGNUP_CONFIRMATION_PATH} element={<ConfirmEmailPage forPublicScan />} />
            <Route path={PUBLIC_SCAN_CONFIRMATION_PATH} element={<ConfirmEmailPage forPublicScan />} />
            <Route path="/reset-password" element={<ResetPasswordPage />} />
            <Route path="/public-scanner" element={<Navigate to="/public-scan" replace />} />
            <Route path="/scan" element={<Navigate to="/public-scan" replace />} />
            <Route path="/post-quantum-migration-platform" element={<PostQuantumMigrationPlatform />} />
            <Route path="/quantum-trust-governance-center" element={<QuantumTrustGovernanceCenter />} />
            <Route path="/pqc-solutions" element={<PqcSolutions />} />
            <Route path="/qguard-helix-features" element={<QguardHelixFeatures />} />
            <Route path="/features" element={<Navigate to="/qguard-helix-features" replace />} />
            <Route path="/terms" element={<TermsPage />} />
            <Route path="/terms-of-service" element={<Navigate to="/terms" replace />} />
            <Route path="/privacy" element={<PrivacyPage />} />
            <Route path="/privacy-policy" element={<Navigate to="/privacy" replace />} />
            <Route path="/refund" element={<RefundPage />} />
            <Route path="/refund-policy" element={<Navigate to="/refund" replace />} />
            <Route path="/refunds" element={<Navigate to="/refund" replace />} />
            <Route path="/contact" element={<ContactPage />} />
            <Route path="/support" element={<Navigate to="/contact" replace />} />
            <Route path="/resources/pqc-checklist" element={<PqcChecklistPage />} />
            <Route path="/resources/quantum-simulation" element={<QuantumSimulationPage />} />
            <Route path="/resources/quantum-emulation" element={<QuantumSimulationPage />} />
            <Route path="/quantum-emulation" element={<QuantumSimulationPage />} />
            <Route path="*" element={<PlatformOnly />} />
          </Routes>
          </Suspense>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}
