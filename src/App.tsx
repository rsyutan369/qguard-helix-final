import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './contexts/auth-context';
import { ThemeProvider } from './contexts/theme-context';
import Landing from './pages/Landing';
import Auth from './app/authentication/Auth';
import LoginPage from './app/authentication/login/page';
import RegisterPage from './app/authentication/register/page';
import DocsPage from './app/docs/page';
import PqcChecklistPage from './app/resources/pqc-checklist/page';
import QuantumSimulationPage from './app/resources/quantum-simulation/page';
import DashboardLayout from './app/dashboard/dashboard_layout/DashboardLayout';
import DashboardPage from './app/dashboard/page';
import DashboardOverview from './app/dashboard/dashboard_overview/page';
import AssetsMap from './app/dashboard/assets_map/page';
import Vulnerabilities from './app/dashboard/vulnerabilities/page';
import MigrationPlanner from './app/dashboard/migration_planner/page';
import PqcOnboardingPage from './app/dashboard/pqc-onboarding/page';
import CbomExplorer from './app/dashboard/cbom_explorer/page';
import CryptoExposureMap from './app/dashboard/crypto_exposure_map/page';
import MigrationTimeline from './app/dashboard/migration_timeline/page';
import MigrationPhases from './app/dashboard/migration_phases/page';
import ComplianceDashboard from './app/dashboard/compliance_dashboard/page';
import LiveMigrationOps from './app/dashboard/live_migration_ops/page';
import DriftDetection from './app/dashboard/drift_detection/page';
import ScannerDashboard from './app/dashboard/scanner_dashboard/page';
import ProfileSettingsPage from './app/dashboard/settings/page';
import AdminDashboardPage from './app/dashboard/admin/page';

// Quantum Tools Modules
import EncryptionKeysPage from './app/dashboard/keys/page';
import OTPPage from './app/dashboard/otp/page';
import PKIPage from './app/dashboard/pki/page';
import TokenizePage from './app/dashboard/tokenize/page';
import CommPage from './app/dashboard/comm/page';
import CloudPage from './app/dashboard/cloud/page';
import VaultPage from './app/dashboard/vault/page';
import SharedFilePage from './app/vault/shared/[id]/page';
import QuantumGovernancePage from './app/dashboard/quantum-governance/page';
import QuantumQrngPage from './app/dashboard/qrng/page';

// Newly Scaffolded Modules
import ShadowCryptoPage from './app/dashboard/shadow-crypto/page';
import HarvestNowPage from './app/dashboard/harvest-now/page';
import CryptoAgilityEnginePage from './app/dashboard/crypto-agility/page';
import PqcOrchestrationPage from './app/dashboard/pqc-orchestration/page';
import MigrationSandboxPage from './app/dashboard/migration-sandbox/page';
import RuntimeCryptoIntelPage from './app/dashboard/runtime-crypto-intel/page';
import BehavioralAnalyticsPage from './app/dashboard/behavioral-analytics/page';
import TelemetryCorrelationPage from './app/dashboard/telemetry-correlation/page';
import QuantumRiskScoringPage from './app/dashboard/quantum-risk-scoring/page';
import TlsTelemetryPage from './app/dashboard/tls-telemetry/page';
import TlsOrchestratorPage from './app/dashboard/tls-orchestrator/page';
import PkiVisibilityPage from './app/dashboard/pki-visibility/page';
import ProtocolAnalyticsPage from './app/dashboard/protocol-analytics/page';
import EncryptionMonitoringPage from './app/dashboard/encryption-monitoring/page';
import ContinuousTrustPage from './app/dashboard/continuous-trust/page';
import IdentityTrustPage from './app/dashboard/identity-trust/page';
import DeviceTrustPage from './app/dashboard/device-trust/page';
import TrustAnalyticsPage from './app/dashboard/trust-analytics/page';
import ZeroTrustPage from './app/dashboard/zero-trust/page';
import CryptoPoliciesPage from './app/dashboard/crypto-policies/page';
import AuditVaultPage from './app/dashboard/audit-vault/page';
import RegulatoryMappingPage from './app/dashboard/regulatory-mapping/page';
import RuntimeTelemetryPage from './app/dashboard/runtime-telemetry/page';
import CertificateTelemetryPage from './app/dashboard/certificate-telemetry/page';
import KeyAnalyticsPage from './app/dashboard/key-analytics/page';
import ApiEncryptionPage from './app/dashboard/api-encryption/page';
import MultiCloudTelemetryPage from './app/dashboard/multi-cloud-telemetry/page';
import QkmsOverviewPage from './app/dashboard/qkms/overview/page';
import QkmsInventoryPage from './app/dashboard/qkms/inventory/page';
import QkmsGovernancePage from './app/dashboard/qkms/governance/page';
import QkmsReadinessPage from './app/dashboard/qkms/readiness/page';
import QFeaturesPage from './app/dashboard/q-features/page';
import EcosystemDependencyMapPage from './app/dashboard/ecosystem-dependency-map/page';
import VendorPqcReadinessPage from './app/dashboard/vendor-pqc-readiness/page';
import TrustChainAnalyzerPage from './app/dashboard/trust-chain-analyzer/page';
import TrustStateDiscoveryPage from './app/dashboard/trust-state-discovery/page';
import HybridCryptoCompatibilityLabPage from './app/dashboard/hybrid-crypto-lab/page';
import PQAuthPage from './app/dashboard/pqauth/page';
import PQAuthDiscoveryPage from './app/dashboard/pqauth/discovery/page';
import PQAuthTrustGraphPage from './app/dashboard/pqauth/trust-graph/page';
import PQAuthTokenIntelligencePage from './app/dashboard/pqauth/token-intelligence/page';
import PQAuthExposureAnalysisPage from './app/dashboard/pqauth/exposure-analysis/page';
import PQAuthCompatibilityPage from './app/dashboard/pqauth/compatibility/page';
import PQAuthDigitalTwinPage from './app/dashboard/pqauth/digital-twin/page';
import PQAuthMigrationCenterPage from './app/dashboard/pqauth/migration-center/page';
import PQAuthRuntimeTelemetryPage from './app/dashboard/pqauth/runtime-telemetry/page';
import PQAuthCompliancePage from './app/dashboard/pqauth/compliance/page';
import PQAuthQkmsPage from './app/dashboard/pqauth/qkms/page';
import QuantumReadinessLandingPage from './app/dashboard/quantum-readiness/page';
import QuantumReadinessCommandCenterPage from './app/dashboard/quantum-readiness/command-center/page';
import QuantumReadinessExecutivePage from './app/dashboard/quantum-readiness/executive/page';
import QuantumReadinessExposureGraphPage from './app/dashboard/quantum-readiness/exposure-graph/page';
import QuantumReadinessRiskAnalysisPage from './app/dashboard/quantum-readiness/risk-analysis/page';
import QuantumReadinessAiExecutiveAdvisorPage from './app/dashboard/quantum-readiness/ai-executive-advisor/page';
import QuantumReadinessAiMigrationAdvisorPage from './app/dashboard/quantum-readiness/ai-migration-advisor/page';
import QuantumReadinessDigitalTwinPage from './app/dashboard/quantum-readiness/digital-twin/page';
import QuantumReadinessReportsPage from './app/dashboard/quantum-readiness/reports/page';

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/auth" element={<Auth />} />
          <Route path="/authentication" element={<Auth />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/authentication/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/authentication/register" element={<RegisterPage />} />
          <Route path="/docs" element={<DocsPage />} />
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

          <Route path="vulnerabilities" element={<Vulnerabilities />} />

          <Route path="migration-planner" element={<MigrationPlanner />} />
          <Route path="migration_planner" element={<MigrationPlanner />} />
          <Route path="pqc-onboarding" element={<PqcOnboardingPage />} />
          <Route path="pqc-onboarding-migration-process" element={<PqcOnboardingPage />} />

          <Route path="cbom" element={<CbomExplorer />} />
          <Route path="cbom_explorer" element={<CbomExplorer />} />

          <Route path="exposure-map" element={<CryptoExposureMap />} />
          <Route path="crypto-exposure" element={<CryptoExposureMap />} />
          <Route path="crypto_exposure_map" element={<CryptoExposureMap />} />

          <Route path="timeline" element={<MigrationTimeline />} />
          <Route path="migration-timeline" element={<MigrationTimeline />} />
          <Route path="migration_timeline" element={<MigrationTimeline />} />
          <Route path="migration-phases" element={<MigrationPhases />} />
          <Route path="migration_phases" element={<MigrationPhases />} />

          <Route path="compliance" element={<ComplianceDashboard />} />
          <Route path="compliance_dashboard" element={<ComplianceDashboard />} />

          <Route path="live-ops" element={<LiveMigrationOps />} />
          <Route path="live-migration" element={<LiveMigrationOps />} />
          <Route path="live_migration_ops" element={<LiveMigrationOps />} />

          <Route path="drift" element={<DriftDetection />} />
          <Route path="drift_detection" element={<DriftDetection />} />

          <Route path="settings" element={<ProfileSettingsPage />} />
          <Route path="profile" element={<ProfileSettingsPage />} />
          <Route path="admin" element={<AdminDashboardPage />} />

          <Route path="scanner" element={<ScannerDashboard />} />
          <Route path="scanner_dashboard" element={<ScannerDashboard />} />
          
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
          <Route path="behavioral-analytics" element={<BehavioralAnalyticsPage />} />
          <Route path="telemetry-correlation" element={<TelemetryCorrelationPage />} />
          <Route path="quantum-risk-scoring" element={<QuantumRiskScoringPage />} />
          <Route path="tls-telemetry" element={<TlsTelemetryPage />} />
          <Route path="tls-orchestrator" element={<TlsOrchestratorPage />} />
          <Route path="pki-visibility" element={<PkiVisibilityPage />} />
          <Route path="protocol-analytics" element={<ProtocolAnalyticsPage />} />
          <Route path="encryption-monitoring" element={<EncryptionMonitoringPage />} />
          <Route path="continuous-trust" element={<ContinuousTrustPage />} />
          <Route path="identity-trust" element={<IdentityTrustPage />} />
          <Route path="device-trust" element={<DeviceTrustPage />} />
          <Route path="trust-analytics" element={<TrustAnalyticsPage />} />
          <Route path="zero-trust" element={<ZeroTrustPage />} />
          <Route path="crypto-policies" element={<CryptoPoliciesPage />} />
          <Route path="audit-vault" element={<AuditVaultPage />} />
          <Route path="regulatory-mapping" element={<RegulatoryMappingPage />} />
          <Route path="runtime-telemetry" element={<RuntimeTelemetryPage />} />
          <Route path="certificate-telemetry" element={<CertificateTelemetryPage />} />
          <Route path="key-analytics" element={<KeyAnalyticsPage />} />
          <Route path="api-encryption" element={<ApiEncryptionPage />} />
          <Route path="multi-cloud-telemetry" element={<MultiCloudTelemetryPage />} />
          {/* Quantum Readiness Assessment Engine™ */}
          <Route path="quantum-readiness" element={<QuantumReadinessLandingPage />} />
          <Route path="quantum-readiness/command-center" element={<QuantumReadinessCommandCenterPage />} />
          <Route path="quantum-readiness/executive" element={<QuantumReadinessExecutivePage />} />
          <Route path="quantum-readiness/exposure-graph" element={<QuantumReadinessExposureGraphPage />} />
          <Route path="quantum-readiness/risk-analysis" element={<QuantumReadinessRiskAnalysisPage />} />
          <Route path="quantum-readiness/ai-executive-advisor" element={<QuantumReadinessAiExecutiveAdvisorPage />} />
          <Route path="quantum-readiness/ai-migration-advisor" element={<QuantumReadinessAiMigrationAdvisorPage />} />
          <Route path="quantum-readiness/digital-twin" element={<QuantumReadinessDigitalTwinPage />} />
          <Route path="quantum-readiness/reports" element={<QuantumReadinessReportsPage />} />

          <Route path="qkms/overview" element={<QkmsOverviewPage />} />
          <Route path="qkms/inventory" element={<QkmsInventoryPage />} />
          <Route path="qkms/governance" element={<QkmsGovernancePage />} />
          <Route path="qkms/readiness" element={<QkmsReadinessPage />} />
          <Route path="q-features" element={<QFeaturesPage />} />
          </Route>
        </Routes>
      </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}
