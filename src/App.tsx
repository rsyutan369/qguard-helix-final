import { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/auth-context';
import { ThemeProvider } from './contexts/theme-context';
import { UserPreferencesProvider } from './contexts/user-preferences-context';
import Landing from './pages/Landing';
import { SIGNUP_CONFIRMATION_PATH } from './lib/signup-confirmation';
import { PUBLIC_SCAN_CONFIRMATION_PATH } from './lib/public-scan-auth';

// Keep the landing page on the initial render path. Other routes load when matched.
const SubscriptionThankYou = lazy(() => import('./pages/SubscriptionThankYou'));
const VerifyReport = lazy(() => import('./pages/VerifyReport'));
const VerifyCertificate = lazy(() => import('./pages/VerifyCertificate'));
const Checkout = lazy(() => import('./pages/Checkout'));
const PostQuantumMigrationPlatform = lazy(() => import('./pages/PostQuantumMigrationPlatform'));
const QuantumTrustGovernanceCenter = lazy(() => import('./pages/QuantumTrustGovernanceCenter'));
const PqcSolutions = lazy(() => import('./pages/PqcSolutions'));
const TermsPage = lazy(() => import('./pages/Terms'));
const PrivacyPage = lazy(() => import('./pages/Privacy'));
const RefundPage = lazy(() => import('./pages/Refund'));
const ContactPage = lazy(() => import('./pages/Contact'));
const QguardHelixFeatures = lazy(() => import('./pages/QguardHelixFeatures'));
const Auth = lazy(() => import('./app/authentication/Auth'));
const LoginPage = lazy(() => import('./app/authentication/login/page'));
const RegisterPage = lazy(() => import('./app/authentication/register/page'));
const ConfirmEmailPage = lazy(() => import('./app/authentication/confirm-email/page'));
const OAuthCallbackPage = lazy(() => import('./app/authentication/oauth-callback/page'));
const ResetPasswordPage = lazy(() => import('./app/authentication/reset-password/page'));
const DocsPage = lazy(() => import('./app/docs/page'));
const PqcChecklistPage = lazy(() => import('./app/resources/pqc-checklist/page'));
const QuantumSimulationPage = lazy(() => import('./app/resources/quantum-simulation/page'));
const QguardMessagingOverview = lazy(() => import('./app/qguard-messaging/page'));
const QguardMessagingSecureChat = lazy(() => import('./app/qguard-messaging/secure-chat/page'));
const QguardMessagingQuantumVault = lazy(() => import('./app/qguard-messaging/quantum-vault/page'));
const QuantumReadinessAssessmentPage = lazy(() => import('./app/quantum-readiness-assessment/page'));
const PublicScanPage = lazy(() => import('./app/public-scan/page'));
const DownloadsPage = lazy(() => import('./app/downloads/page'));
const DashboardLayout = lazy(() => import('./app/dashboard/dashboard_layout/DashboardLayout'));
const DashboardPage = lazy(() => import('./app/dashboard/page'));
const DashboardOverview = lazy(() => import('./app/dashboard/dashboard_overview/page'));
const AssetsMap = lazy(() => import('./app/dashboard/assets_map/page'));
const MigrationPlanner = lazy(() => import('./app/dashboard/migration_planner/page'));
const MigrationIntelligencePage = lazy(() => import('./app/dashboard/migration-intelligence/page'));
const PqcOnboardingPage = lazy(() => import('./app/dashboard/pqc-onboarding/page'));
const CbomExplorer = lazy(() => import('./app/dashboard/cbom_explorer/page'));
const MigrationTimeline = lazy(() => import('./app/dashboard/migration_timeline/page'));
const CompliancePage = lazy(() => import('./app/dashboard/compliance/page'));
const LiveMigrationOps = lazy(() => import('./app/dashboard/live_migration_ops/page'));
const DriftDetection = lazy(() => import('./app/dashboard/drift_detection/page'));
const ScannerDashboard = lazy(() => import('./app/dashboard/scanner_dashboard/page'));
const AgentsCollectorPage = lazy(() => import('./app/dashboard/agents_collector/page'));
const RealTimeScanningPage = lazy(() => import('./app/dashboard/real_time_scanning/page'));
const ProfileSettingsPage = lazy(() => import('./app/dashboard/settings/page'));
const AdminDashboardPage = lazy(() => import('./app/dashboard/admin/page'));

// Revenue Intelligence™ (owner-only)
const RevenueIntelligenceLayout = lazy(() =>
  import('./app/dashboard/revenue-intelligence/_shared').then(({ RevenueIntelligenceLayout }) => ({ default: RevenueIntelligenceLayout })),
);
const RevenueOverviewPage = lazy(() => import('./app/dashboard/revenue-intelligence/page'));
const RevenueAnalyticsPage = lazy(() => import('./app/dashboard/revenue-intelligence/revenue/page'));
const RevenueSubscriptionsPage = lazy(() => import('./app/dashboard/revenue-intelligence/subscriptions/page'));
const RevenueCustomersPage = lazy(() => import('./app/dashboard/revenue-intelligence/customers/page'));
const RevenuePaymentsPage = lazy(() => import('./app/dashboard/revenue-intelligence/payments/page'));
const RevenueForecastPage = lazy(() => import('./app/dashboard/revenue-intelligence/forecast/page'));

// Quantum Tools Modules
const EncryptionKeysPage = lazy(() => import('./app/dashboard/keys/page'));
const OTPPage = lazy(() => import('./app/dashboard/otp/page'));
const PKIPage = lazy(() => import('./app/dashboard/pki/page'));
const TokenizePage = lazy(() => import('./app/dashboard/tokenize/page'));
const CommPage = lazy(() => import('./app/dashboard/comm/page'));
const CloudPage = lazy(() => import('./app/dashboard/cloud/page'));
const VaultPage = lazy(() => import('./app/dashboard/vault/page'));
const SharedFilePage = lazy(() => import('./app/vault/shared/[id]/page'));
const QuantumGovernancePage = lazy(() => import('./app/dashboard/quantum-governance/page'));
const QuantumQrngPage = lazy(() => import('./app/dashboard/qrng/page'));

// Newly Scaffolded Modules
const ShadowCryptoPage = lazy(() => import('./app/dashboard/shadow-crypto/page'));
const HarvestNowPage = lazy(() => import('./app/dashboard/harvest-now/page'));
const CryptoAgilityEnginePage = lazy(() => import('./app/dashboard/crypto-agility/page'));
const PqcOrchestrationPage = lazy(() => import('./app/dashboard/pqc-orchestration/page'));
const MigrationSandboxPage = lazy(() => import('./app/dashboard/migration-sandbox/page'));
const RuntimeCryptoIntelPage = lazy(() => import('./app/dashboard/runtime-crypto-intel/page'));
const TelemetryCorrelationPage = lazy(() => import('./app/dashboard/telemetry-correlation/page'));
const QuantumRiskScoringPage = lazy(() => import('./app/dashboard/quantum-risk-scoring/page'));
const TlsTelemetryPage = lazy(() => import('./app/dashboard/tls-telemetry/page'));
const TlsOrchestratorPage = lazy(() => import('./app/dashboard/tls-orchestrator/page'));
const PkiVisibilityPage = lazy(() => import('./app/dashboard/pki-visibility/page'));
const ProtocolAnalyticsPage = lazy(() => import('./app/dashboard/protocol-analytics/page'));
const EncryptionMonitoringPage = lazy(() => import('./app/dashboard/encryption-monitoring/page'));
const ZeroTrustPage = lazy(() => import('./app/dashboard/zero-trust/page'));
const AuditVaultPage = lazy(() => import('./app/dashboard/audit-vault/page'));
const RegulatoryMappingPage = lazy(() => import('./app/dashboard/regulatory-mapping/page'));
const RuntimeTelemetryPage = lazy(() => import('./app/dashboard/runtime-telemetry/page'));
const CertificateTelemetryPage = lazy(() => import('./app/dashboard/certificate-telemetry/page'));
const MultiCloudTelemetryPage = lazy(() => import('./app/dashboard/multi-cloud-telemetry/page'));
const QkmsOverviewPage = lazy(() => import('./app/dashboard/qkms/overview/page'));
const QkmsInventoryPage = lazy(() => import('./app/dashboard/qkms/inventory/page'));
const QkmsGovernancePage = lazy(() => import('./app/dashboard/qkms/governance/page'));
const QkmsReadinessPage = lazy(() => import('./app/dashboard/qkms/readiness/page'));
const QkmsLifecyclePage = lazy(() => import('./app/dashboard/qkms/lifecycle/page'));
const QkmsRotationPage = lazy(() => import('./app/dashboard/qkms/rotation/page'));
const QkmsRiskAnalysisPage = lazy(() => import('./app/dashboard/qkms/risk-analysis/page'));
const QFeaturesPage = lazy(() => import('./app/dashboard/q-features/page'));
const EcosystemDependencyMapPage = lazy(() => import('./app/dashboard/ecosystem-dependency-map/page'));
const VendorPqcReadinessPage = lazy(() => import('./app/dashboard/vendor-pqc-readiness/page'));
const TrustChainAnalyzerPage = lazy(() => import('./app/dashboard/trust-chain-analyzer/page'));
const EstateIntelligencePage = lazy(() => import('./app/dashboard/estate-intelligence/page'));
const TrustDashboardPage = lazy(() => import('./app/dashboard/trust-dashboard/page'));
const TrustStateDiscoveryPage = lazy(() => import('./app/dashboard/trust-state-discovery/page'));
const HybridCryptoCompatibilityLabPage = lazy(() => import('./app/dashboard/hybrid-crypto-lab/page'));
const PQAuthPage = lazy(() => import('./app/dashboard/pqauth/page'));
const PQAuthDiscoveryPage = lazy(() => import('./app/dashboard/pqauth/discovery/page'));
const PQAuthTrustGraphPage = lazy(() => import('./app/dashboard/pqauth/trust-graph/page'));
const PQAuthTokenIntelligencePage = lazy(() => import('./app/dashboard/pqauth/token-intelligence/page'));
const PQAuthExposureAnalysisPage = lazy(() => import('./app/dashboard/pqauth/exposure-analysis/page'));
const PQAuthCompatibilityPage = lazy(() => import('./app/dashboard/pqauth/compatibility/page'));
const PQAuthDigitalTwinPage = lazy(() => import('./app/dashboard/pqauth/digital-twin/page'));
const PQAuthMigrationCenterPage = lazy(() => import('./app/dashboard/pqauth/migration-center/page'));
const PQAuthRuntimeTelemetryPage = lazy(() => import('./app/dashboard/pqauth/runtime-telemetry/page'));
const PQAuthCompliancePage = lazy(() => import('./app/dashboard/pqauth/compliance/page'));
const PQAuthQkmsPage = lazy(() => import('./app/dashboard/pqauth/qkms/page'));
const QuantumReadinessLandingPage = lazy(() => import('./app/dashboard/quantum-readiness/page'));
const QuantumReadinessExposureGraphPage = lazy(() => import('./app/dashboard/quantum-readiness/exposure-graph/page'));
const QuantumReadinessRiskAnalysisPage = lazy(() => import('./app/dashboard/quantum-readiness/risk-analysis/page'));
const QuantumRemediationPage = lazy(() => import('./app/dashboard/quantum-readiness/remediation/page'));
const QuantumReadinessAiExecutiveAdvisorPage = lazy(() => import('./app/dashboard/quantum-readiness/ai-executive-advisor/page'));
const QuantumReadinessAiMigrationAdvisorPage = lazy(() => import('./app/dashboard/quantum-readiness/ai-migration-advisor/page'));
const QuantumReadinessReportsPage = lazy(() => import('./app/dashboard/quantum-readiness/reports/page'));
const QuantumCertificationPage = lazy(() => import('./app/dashboard/quantum-certification/page'));
const SophiaConsolePage = lazy(() => import('./app/dashboard/sophia/page'));

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
      <UserPreferencesProvider>
      <Router>
        <Suspense fallback={<p className="p-6 text-sm text-muted-foreground" role="status">Loading page…</p>}>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/auth" element={<Auth />} />
          <Route path="/authentication" element={<Auth />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/authentication/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path={SIGNUP_CONFIRMATION_PATH} element={<ConfirmEmailPage />} />
          <Route path={PUBLIC_SCAN_CONFIRMATION_PATH} element={<ConfirmEmailPage forPublicScan />} />
          <Route path="/auth/callback" element={<OAuthCallbackPage />} />
          <Route path="/authentication/register" element={<RegisterPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          <Route path="/authentication/reset-password" element={<ResetPasswordPage />} />
          <Route path="/docs/*" element={<DocsPage />} />
          <Route path="/qguard-messaging" element={<QguardMessagingOverview />} />
          <Route path="/qguard-messaging/secure-chat" element={<QguardMessagingSecureChat />} />
          <Route path="/qguard-messaging/quantum-vault" element={<QguardMessagingQuantumVault />} />
          <Route path="/quantum-readiness-assessment" element={<QuantumReadinessAssessmentPage />} />
          {/* Public Quantum Exposure Assessment™ — anonymous edge scanner. */}
          {/* Qguard Helix Agent Center - lightweight agent deployment (Pro+) */}
          <Route path="/downloads" element={<DownloadsPage />} />
          <Route path="/agent-center" element={<Navigate to="/downloads" replace />} />
          <Route path="/public-scan" element={<PublicScanPage />} />
          <Route path="/public-scanner" element={<Navigate to="/public-scan" replace />} />
          <Route path="/scan" element={<Navigate to="/public-scan" replace />} />
          <Route path="/post-quantum-migration-platform" element={<PostQuantumMigrationPlatform />} />
          <Route path="/quantum-trust-governance-center" element={<QuantumTrustGovernanceCenter />} />
          <Route path="/pqc-solutions" element={<PqcSolutions />} />
          {/* Platform features showcase — Qguard_Wiki/Qguard_Helix_Features_Page */}
          <Route path="/qguard-helix-features" element={<QguardHelixFeatures />} />
          <Route path="/features" element={<Navigate to="/qguard-helix-features" replace />} />
          {/* Public legal surfaces — required to be reachable for PayPal
              recurring billing; all four read src/lib/site-identity.ts. */}
          <Route path="/terms" element={<TermsPage />} />
          <Route path="/terms-of-service" element={<Navigate to="/terms" replace />} />
          <Route path="/privacy" element={<PrivacyPage />} />
          <Route path="/privacy-policy" element={<Navigate to="/privacy" replace />} />
          <Route path="/refund" element={<RefundPage />} />
          <Route path="/refund-policy" element={<Navigate to="/refund" replace />} />
          <Route path="/refunds" element={<Navigate to="/refund" replace />} />
          <Route path="/contact" element={<ContactPage />} />
          <Route path="/support" element={<Navigate to="/contact" replace />} />
          <Route path="/checkout" element={<Checkout />} />
          <Route path="/subscription/thank-you" element={<SubscriptionThankYou />} />
          <Route path="/verify-report" element={<VerifyReport />} />
          <Route path="/verify-certificate" element={<VerifyCertificate />} />
          <Route path="/verify-certificate/:certificateId" element={<VerifyCertificate />} />
          <Route path="/resources/pqc-checklist" element={<PqcChecklistPage />} />
          <Route path="/localhost/resources/pqc-checklist" element={<PqcChecklistPage />} />
          <Route path="/resources/quantum-simulation" element={<QuantumSimulationPage />} />
          <Route path="/resources/quantum-emulation" element={<QuantumSimulationPage />} />
          <Route path="/quantum-emulation" element={<QuantumSimulationPage />} />
          <Route path="/localhost/resources/quantum-simulation" element={<QuantumSimulationPage />} />
          <Route path="/localhost/resources/quantum-emulation" element={<QuantumSimulationPage />} />
          <Route path="/vault/shared/:id" element={<SharedFilePage />} />
          <Route path="/dashboard" element={<DashboardLayout />}>
          <Route index element={<DashboardPage />} />
          <Route path="dashboard_overview" element={<DashboardOverview />} />

          <Route path="assets" element={<AssetsMap />} />
          <Route path="assets_map" element={<AssetsMap />} />

          {/* The Vulnerability Center was retired as redundant — Quantum Risk Analysis
              owns finding triage. Keep old bookmarks and deep links working. */}
          <Route path="vulnerabilities" element={<Navigate to="/dashboard/quantum-readiness/risk-analysis" replace />} />

          <Route path="migration-intelligence" element={<MigrationIntelligencePage />} />
          <Route path="migration-planner" element={<MigrationPlanner />} />
          <Route path="migration_planner" element={<MigrationPlanner />} />
          <Route path="pqc-onboarding" element={<PqcOnboardingPage />} />
          <Route path="pqc-onboarding-migration-process" element={<PqcOnboardingPage />} />

          <Route path="cbom" element={<CbomExplorer />} />
          <Route path="cbom_explorer" element={<CbomExplorer />} />

          <Route path="timeline" element={<MigrationTimeline />} />
          <Route path="migration-timeline" element={<MigrationTimeline />} />
          <Route path="migration_timeline" element={<MigrationTimeline />} />

          <Route path="compliance" element={<CompliancePage />} />
          {/* Legacy path kept so bookmarks resolve to the Compliance Command Center. */}
          <Route path="compliance_dashboard" element={<CompliancePage />} />

          <Route path="live-ops" element={<LiveMigrationOps />} />
          <Route path="live-migration" element={<LiveMigrationOps />} />
          <Route path="live_migration_ops" element={<LiveMigrationOps />} />

          <Route path="drift" element={<DriftDetection />} />
          <Route path="drift_detection" element={<DriftDetection />} />

          <Route path="settings" element={<ProfileSettingsPage />} />
          <Route path="profile" element={<ProfileSettingsPage />} />
          <Route path="admin" element={<AdminDashboardPage />} />

          {/* Revenue Intelligence™ — owner-only (shell + API both enforce) */}
          <Route path="revenue-intelligence" element={<RevenueIntelligenceLayout />}>
            <Route index element={<RevenueOverviewPage />} />
            <Route path="revenue" element={<RevenueAnalyticsPage />} />
            <Route path="subscriptions" element={<RevenueSubscriptionsPage />} />
            <Route path="customers" element={<RevenueCustomersPage />} />
            <Route path="payments" element={<RevenuePaymentsPage />} />
            <Route path="forecast" element={<RevenueForecastPage />} />
          </Route>

          <Route path="scanner" element={<ScannerDashboard />} />
          <Route path="scanner/real-time" element={<RealTimeScanningPage />} />
          <Route path="scanner_dashboard" element={<ScannerDashboard />} />
          <Route path="agents" element={<AgentsCollectorPage />} />
          
          {/* Quantum Tools */}
          <Route path="keys" element={<EncryptionKeysPage />} />
          <Route path="encryption" element={<EncryptionKeysPage />} />

          <Route path="otp" element={<OTPPage />} />
          <Route path="auth-sec" element={<OTPPage />} />

          <Route path="pki" element={<PKIPage />} />
          <Route path="certificates" element={<PKIPage />} />

          <Route path="tokenize" element={<TokenizePage />} />
          <Route path="tokenization" element={<TokenizePage />} />

          <Route path="comm" element={<CommPage />} />
          <Route path="communications" element={<CommPage />} />

          <Route path="cloud" element={<CloudPage />} />
          <Route path="cloud-security" element={<CloudPage />} />

          <Route path="vault" element={<VaultPage />} />

          <Route path="quantum-governance" element={<QuantumGovernancePage />} />

          <Route path="qrng" element={<QuantumQrngPage />} />
          <Route path="quantum-qrng" element={<QuantumQrngPage />} />

          {/* New Scaffolding Routes */}
          <Route path="shadow-crypto" element={<ShadowCryptoPage />} />
          <Route path="harvest-now" element={<HarvestNowPage />} />
          <Route path="crypto-agility" element={<CryptoAgilityEnginePage />} />
          <Route path="pqc-orchestration" element={<PqcOrchestrationPage />} />
          <Route path="migration-sandbox" element={<MigrationSandboxPage />} />
          <Route path="ecosystem-supply-chain" element={<EcosystemDependencyMapPage />} />
          <Route path="ecosystem-dependency-map" element={<EcosystemDependencyMapPage />} />
          <Route path="vendor-pqc-readiness" element={<VendorPqcReadinessPage />} />
          <Route path="trust-chain-analyzer" element={<TrustChainAnalyzerPage />} />
          <Route path="estate-intelligence" element={<EstateIntelligencePage />} />
          <Route path="trust-dashboard" element={<TrustDashboardPage />} />
          <Route path="trust-state-discovery" element={<TrustStateDiscoveryPage />} />
          <Route path="hybrid-crypto-lab" element={<HybridCryptoCompatibilityLabPage />} />
          <Route path="pqauth" element={<PQAuthPage />} />
          <Route path="pqc-auth" element={<PQAuthPage />} />
          <Route path="pqc-auth-identity-migration-engine" element={<PQAuthPage />} />
          <Route path="pqauth/discovery" element={<PQAuthDiscoveryPage />} />
          <Route path="pqauth/trust-graph" element={<PQAuthTrustGraphPage />} />
          <Route path="pqauth/token-intelligence" element={<PQAuthTokenIntelligencePage />} />
          <Route path="pqauth/exposure-analysis" element={<PQAuthExposureAnalysisPage />} />
          <Route path="pqauth/compatibility" element={<PQAuthCompatibilityPage />} />
          <Route path="pqauth/digital-twin" element={<PQAuthDigitalTwinPage />} />
          <Route path="pqauth/migration-center" element={<PQAuthMigrationCenterPage />} />
          <Route path="pqauth/runtime-telemetry" element={<PQAuthRuntimeTelemetryPage />} />
          <Route path="pqauth/compliance" element={<PQAuthCompliancePage />} />
          <Route path="pqauth/qkms" element={<PQAuthQkmsPage />} />
          <Route path="runtime-crypto-intel" element={<RuntimeCryptoIntelPage />} />
          <Route path="telemetry-correlation" element={<TelemetryCorrelationPage />} />
          <Route path="quantum-risk-scoring" element={<QuantumRiskScoringPage />} />
          <Route path="tls-telemetry" element={<TlsTelemetryPage />} />
          <Route path="tls-orchestrator" element={<TlsOrchestratorPage />} />
          <Route path="pki-visibility" element={<PkiVisibilityPage />} />
          <Route path="protocol-analytics" element={<ProtocolAnalyticsPage />} />
          <Route path="encryption-monitoring" element={<EncryptionMonitoringPage />} />
          <Route path="zero-trust" element={<ZeroTrustPage />} />
          <Route path="audit-vault" element={<AuditVaultPage />} />
          <Route path="regulatory-mapping" element={<RegulatoryMappingPage />} />
          <Route path="runtime-telemetry" element={<RuntimeTelemetryPage />} />
          <Route path="certificate-telemetry" element={<CertificateTelemetryPage />} />
          <Route path="multi-cloud-telemetry" element={<MultiCloudTelemetryPage />} />
          {/* Quantum Readiness Assessment Engine™ */}
          <Route path="quantum-readiness" element={<QuantumReadinessLandingPage />} />
          {/* Assessment Command Center and Executive Dashboard were retired as
              redundant — the Overview owns the assessment snapshot and the AI
              Executive Advisor owns the board-ready view. Keep old bookmarks working. */}
          <Route path="quantum-readiness/command-center" element={<Navigate to="/dashboard/quantum-readiness" replace />} />
          <Route path="quantum-readiness/executive" element={<Navigate to="/dashboard/quantum-readiness/ai-executive-advisor" replace />} />
          <Route path="quantum-readiness/exposure-graph" element={<QuantumReadinessExposureGraphPage />} />
          <Route path="quantum-readiness/risk-analysis" element={<QuantumReadinessRiskAnalysisPage />} />
          <Route path="quantum-readiness/remediation" element={<QuantumRemediationPage />} />
          <Route path="quantum-readiness/ai-executive-advisor" element={<QuantumReadinessAiExecutiveAdvisorPage />} />
          <Route path="quantum-readiness/ai-migration-advisor" element={<QuantumReadinessAiMigrationAdvisorPage />} />
          {/* Digital Twin was retired in favor of Harvest Now — keep old bookmarks working. */}
          <Route path="quantum-readiness/digital-twin" element={<Navigate to="/dashboard/harvest-now" replace />} />
          <Route path="quantum-readiness/reports" element={<QuantumReadinessReportsPage />} />
          <Route path="quantum-certification" element={<QuantumCertificationPage />} />

          {/* Sophia — AI Security Copilot™ full console */}
          <Route path="sophia" element={<SophiaConsolePage />} />

          <Route path="qkms/overview" element={<QkmsOverviewPage />} />
          <Route path="qkms/inventory" element={<QkmsInventoryPage />} />
          <Route path="qkms/lifecycle" element={<QkmsLifecyclePage />} />
          <Route path="qkms/governance" element={<QkmsGovernancePage />} />
          <Route path="qkms/rotation" element={<QkmsRotationPage />} />
          <Route path="qkms/readiness" element={<QkmsReadinessPage />} />
          <Route path="qkms/risk-analysis" element={<QkmsRiskAnalysisPage />} />
          <Route path="q-features" element={<QFeaturesPage />} />
          </Route>
        </Routes>
        </Suspense>
      </Router>
      </UserPreferencesProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}
