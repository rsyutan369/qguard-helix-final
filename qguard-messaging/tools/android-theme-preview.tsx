// Local Vite-only visual harness. Not imported by the app or included in dist.
// Existing components use empty unauthenticated state; no operational data is fabricated.
import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import '../src/styles/globals.css';
import '../src/styles/mobile.css';
import '../src/styles/android-modernist.css';
import '../src/styles/android-modernist-pages.css';
import '../src/styles/android-premium.css';
import { AuthProvider } from '../src/lib/auth-context';
import { CallProvider } from '../src/components/call/CallProvider';
import { useDashboardData } from '../src/lib/use-dashboard-data';
import { useTheme } from '../src/lib/use-theme';
import MobileShell from '../src/components/mobile/MobileShell';
import MobileDashboard from '../src/components/mobile/MobileDashboard';
import SecureChatPage from '../src/pages/SecureChatPage';
import QuantumVaultPage from '../src/pages/QuantumVaultPage';
import QuantumSecurityDashboardPage from '../src/pages/QuantumSecurityDashboardPage';
import KeyManagementPage from '../src/pages/KeyManagementPage';
import DeviceTrustCenterPage from '../src/pages/DeviceTrustCenterPage';
import SecurityVerificationPage from '../src/pages/SecurityVerificationPage';
import AuditLogsPage from '../src/pages/AuditLogsPage';
import { InCallOverlay } from '../src/components/call/InCallOverlay';
import { INITIAL_CALL_STATE } from '../src/lib/call-state';
import SettingsPage from '../src/pages/SettingsPage';
import CallsPage from '../src/pages/CallsPage';
import LoginPage from '../src/pages/LoginPage';
import { WorkspaceLockGate } from '../src/components/workspace/WorkspaceLockGate';
import { AppLockScreen } from '../src/components/applock/AppLockScreen';
import type { Page, MessagingModule } from '../src/lib/types';
import { RadarConsole } from '../src/components/offline/OfflineDashboard';
import { MeshNotice } from '../src/components/offline/MeshNotice';
import '../src/components/offline/offline-guided-flow.css';
import type { OfflineStatus } from '../src/lib/offline';
// Empty local fixture: discovery stopped, no devices.
const stoppedOffline:OfflineStatus={running:false,lanDiscoveryRunning:false,autoStart:false,fingerprint:'0'.repeat(64),port:null,peers:[],networkError:null,platform:'android'};
const params=new URLSearchParams(location.search);
if(!params.has('desktop')) document.documentElement.setAttribute('data-qg-skin','modernist');
const noop=()=>{};
// Explicit local layout fixture: no messages, no trusted device and no security evidence.
const layoutConversation={id:'00000000-0000-0000-0000-000000000001',conversation_type:'direct',title:'Layout test contact',last_activity:'',unread_count:0,updated_at:'',member_user_ids:[],archived_at:null,hidden_at:null,deleted_at:null};
const unavailable=async()=>{throw new Error('Local visual preview: account operations are unavailable.');};
const modules:MessagingModule[]=[['dashboard','Home'],['chat','Chats'],['vault','Vault'],['quantum','Security'],['settings','Settings'],['calls','Calls'],['keys','Keys'],['devices','Devices'],['verification','Verification'],['audit','Audit']].map(([route,label],i)=>({module_id:route as Page,route:route as Page,icon:route,label,enabled:true,sort_order:i}));
function Preview(){
 const {data,liveStatus}=useDashboardData(null,null);
 const {theme,toggleTheme}=useTheme();
 const [page,setPage]=useState(params.get('page')||'dashboard');
 if(page==='call-display') return <InCallOverlay state={INITIAL_CALL_STATE} localStream={null} remoteStream={null} micEnabled={true} cameraEnabled={false} peerName="Local design preview" peerUserId={null} quality="auto" onSetQuality={noop} onHangup={noop} onToggleMic={noop} onToggleCamera={noop}/>;
 if(page==='unlock') return <AppLockScreen mode="unlock" onSubmit={unavailable} onUsePassword={noop}/>;
 if(page==='login') return <LoginPage loading={false} error={null} notice={null} pendingMfa={null} pendingPhone={null} onSignIn={unavailable} onVerifyMfa={unavailable} onCancelMfa={unavailable} onSignUp={unavailable} onRequestPhoneCode={unavailable} onVerifyPhoneCode={unavailable} onCancelPhone={noop} onLinkCredential={unavailable} onResendVerification={unavailable} onResetPassword={unavailable} onClearError={noop}/>;
 let content;
 switch(page){
 case 'chat-setup': case 'vault-setup': case 'chat-unlock': case 'vault-unlock': {
 const scope=page.startsWith('chat')?'chat':'vault';
 content=<WorkspaceLockGate scope={scope} status={{configured:page.endsWith('unlock'),hasPassword:true,hasPin:true,hasPattern:scope==='vault',unlocked:false,failedAttempts:0,lockoutUntil:null,lockdown:false}} recoveryEnabled={false} inactivityMinutes={15} onUnlock={unavailable} onSetup={unavailable} onPatternUnlock={unavailable} onCancel={noop}/>;break;}
 case 'chat-layout':content=<SecureChatPage userId="" conversations={[layoutConversation]} devices={[]} contacts={[]} onSent={noop}/>;break;
 case 'chat': case 'contacts': content=<SecureChatPage key={page} userId="" conversations={[]} devices={[]} contacts={[]} onSent={noop} openContacts={page==='contacts'}/>;break;
 case 'vault':content=<QuantumVaultPage userId="" telemetry={[]}/>;break;
 case 'quantum':content=<QuantumSecurityDashboardPage userId="" data={data} liveEvents={[]} liveStatus={liveStatus} onRefresh={noop}/>;break;
 case 'keys':content=<KeyManagementPage userId="" devices={[]} keyInventory={data.keyInventory} telemetry={[]} securityEvents={[]} liveEvents={[]} liveStatus={liveStatus} onRefresh={noop}/>;break;
 case 'devices':content=<DeviceTrustCenterPage userId="" devices={[]} telemetry={[]} securityEvents={[]} onRefresh={noop}/>;break;
 case 'verification':content=<SecurityVerificationPage userId="" devices={[]} telemetry={[]} securityEvents={[]} liveEvents={[]} liveStatus={liveStatus} onRefresh={noop}/>;break;
 case 'audit':content=<AuditLogsPage userId="" devices={[]} events={[]} securityEvents={[]} liveEvents={[]} liveStatus={liveStatus} onRefresh={noop}/>;break;
 case 'settings':content=<SettingsPage theme={theme} profile={null} telemetry={[]} securityEvents={[]} liveEvents={[]} liveStatus={liveStatus} onToggleTheme={toggleTheme} onRefresh={noop} inactivityMinutes={15} onSetInactivityMinutes={noop} workspaceStatus={null} onLockWorkspaces={noop}/>;break;
 case 'mesh': case 'xfer': content=<div className="offline-guided-flow" data-screen="discovery"><RadarConsole mode={page} status={stoppedOffline} selected={[]} busy={false} onSelect={noop} onToggleDiscovery={noop} onOpenSettings={noop} onOpenDevices={noop}/></div>;break;
 case 'calls':content=<CallsPage conversations={[]} contacts={[]} onCall={noop} onMessage={noop}/>;break;
 default:content=<MobileDashboard data={data} liveStatus={liveStatus} onNavigate={setPage}/>;
 }
 const meshNotice=params.has('meshNotice')?<div style={{position:'fixed',top:72,left:12,right:12,zIndex:60}}><MeshNotice notice={{id:'layout',sender:'0'.repeat(64),senderName:'Layout fixture sender',preview:'Layout fixture message text for the notice preview.',group:null,emergency:params.get('meshNotice')==='emergency',receivedAt:0}} more={1} onOpen={noop} onReply={noop} onDismiss={noop}/></div>:null;
 return <>{meshNotice}<MobileShell activePage={(page.startsWith('chat-')||page==='contacts'?'chat':page.startsWith('vault-')?'vault':page) as Page} title={page==='xfer'?'Qguard XFER':page==='mesh'?'Qguard Mesh':page.startsWith('vault-')?'Quantum Vault':page.startsWith('chat-')?'Secure Chat':modules.find(m=>m.route===page)?.label||'Secure Chat'} modules={modules} unreadMessages={0} liveStatus={liveStatus} theme={theme} onToggleTheme={toggleTheme} onNavigate={setPage} onSignOut={noop}>{content}</MobileShell></>;
}
createRoot(document.getElementById('root')!).render(<AuthProvider><CallProvider userId=""><Preview/></CallProvider></AuthProvider>);
