import type { DocArticle } from './types'

export const welcome: DocArticle = {
  id: 'welcome', category: 'start', title: 'QGuard Helix Knowledge Center',
  summary: 'Practical guides for discovering cryptography, assessing quantum exposure, planning a migration, and using QGuard Messaging.',
  product: 'QGuard Helix', updated: '2026-11-16',
  related: ['account-setup', 'migration-roadmap-tutorial', 'messaging-setup', 'developer-api'],
  sections: [
    { id: 'what-is-helix', title: 'What is QGuard Helix?', body: ['QGuard Helix helps security and platform teams find where cryptography is used, identify quantum exposure, and plan how to replace vulnerable algorithms without interrupting the services that depend on them. QGuard Messaging is a separate application for conversations, protected local storage and supported nearby workflows.'], flow: ['Discover cryptography', 'Assess exposure', 'Plan and test', 'Validate changes', 'Monitor and govern'] },
    { id: 'choose-your-start', title: 'Choose where to start', table: { headers: ['If your goal is…', 'Start here', 'What to look for'], rows: [
      ['Set up your workspace', 'Account setup', 'Successful sign-in and the right workspace or product access.'],
      ['Understand your security posture', 'Quantum Readiness Assessment Engine', 'Collected evidence, affected assets and observations that need review.'],
      ['Replace at-risk cryptography', 'Migration Planner and Migration Sandbox', 'A prioritized plan, compatibility checks and a recorded change decision.'],
      ['Use secure communications and storage', 'QGuard Messaging', 'Features and permissions supported by your installed build.'],
      ['Integrate or operate the platform', 'Developer reference and Administration', 'Verified API contracts, access boundaries and operational evidence.'],
    ] } },
    { id: 'how-the-platform-fits-together', title: 'How the platform fits together', flow: ['Browser dashboard', 'Authenticated Express API', 'Workspace-scoped services and records', 'Findings, workflows and reports'], body: ['The React dashboard presents data from services behind an Express API. Supabase provides browser authentication and backs workspace data, with access checks at the relevant service boundaries. Depending on the module and deployment, approved scans, enrolled agents or configured integrations provide observations; supported streams can update views as new events arrive.'], note: 'A blank inventory means there is no visible evidence for the current scope. Check the workspace, filters, permissions and data source before treating an empty view as a security result.' },
    { id: 'pqc-in-plain-language', title: 'Post-quantum cryptography in plain language', body: ['A sufficiently capable quantum computer could threaten public-key algorithms such as RSA and elliptic-curve cryptography. A post-quantum transition starts by finding where those algorithms are used and which data and services need the longest protection. It continues with standards-based replacements, rehearsed changes and new evidence from the affected environment.'], note: 'An inventory match, readiness score or successful simulation is one piece of evidence. Confirm the algorithm actually negotiated or used by your deployed service before closing a migration.' },
  ],
}
