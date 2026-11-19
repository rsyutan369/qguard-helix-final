import type { DocArticle } from './types'

const settings = 'src/app/dashboard/settings/'
const admin = 'src/app/dashboard/admin/'
const revenue = 'src/app/dashboard/revenue-intelligence/'

export const administrationArticles: DocArticle[] = [
  {
    id: 'account-setup',
    category: 'start',
    title: 'Create an account and open your workspace',
    summary: 'Register with a work email or Google, verify your account, and confirm which parts of QGuard Helix your subscription unlocks.',
    keywords: [
      'requirements',
      'onboarding',
      'register',
      'login',
      'sign up',
      'first-time setup',
      'Google OAuth',
      'workspace',
      'verification email',
    ],
    routes: ['/register', '/login', '/reset-password'],
    sources: [
      'src/app/authentication/register/page.tsx',
      'src/app/authentication/login/page.tsx',
      'src/app/authentication/reset-password/page.tsx',
      'src/contexts/auth-context.tsx',
      'src/lib/subscription-access.ts',
    ],
    status: 'implemented',
    related: ['account-settings', 'billing-and-subscriptions', 'troubleshooting'],
    sections: [
      {
        id: 'requirements',
        title: 'Before you begin',
        body: [
          'Use a browser with JavaScript and an internet connection. Have access to your work inbox if you register with email, or use your organization’s Google account if the deployment offers Google sign-in.',
          'A workspace is the dashboard view for the signed-in account and its authorized data. Organization membership, role, and subscription access are distinct. An account can exist before an owner assigns it to an organization.',
        ],
      },
      {
        id: 'authentication',
        title: 'Choose how to sign in',
        table: {
          headers: ['Method', 'What happens', 'What to check'],
          rows: [
            [
              'Work email and password',
              'Register with matching password entries, then follow any verification instructions shown. Sign in from the same site afterward.',
              'Use the inbox that received the verification link. If your address is already registered, sign in or request a reset.',
            ],
            [
              'Continue with Google',
              'Select the Google option and finish account selection and consent on Google. The platform returns you to the signed-in app.',
              'Select the work identity associated with your access or purchase.',
            ],
            [
              'Forgot password',
              'Request a single-use reset link for your account email, open it, then submit and confirm the new password.',
              'Use the latest reset email. After success, sign in again with the new password.',
            ],
          ],
        },
      },
      {
        id: 'first-session',
        title: 'What to check in your first session',
        bullets: [
          'Open Settings, confirm your email and profile, and choose your appearance and dashboard preferences.',
          'Review Billing for your plan, provider, and access status. Accounts without an active plan may land on a plan-selection screen. Starter has a dedicated dashboard for Messaging, profile, billing, and downloads.',
          'For team access, ask the platform owner to confirm your organization and role. If the right tab is missing, check the plan and role before troubleshooting the feature.',
        ],
      },
      {
        id: 'next-work',
        title: 'Choose a starting point',
        flow: [
          'Set up your profile',
          'Confirm workspace access',
          'Start an authorized inventory',
          'Review assessment evidence',
          'Plan the migration',
        ],
      },
    ],
    tutorial: {
      time: '5–10 minutes, plus email delivery',
      permissions: 'Access to your work inbox or Google identity. Team membership and plan access may require your administrator.',
      prerequisites: [
        'A browser and access to the sign-in page for your deployment',
        'The work email your organization or billing provider expects',
      ],
      steps: [
        'Open Create account. Enter your work email, choose a unique password, and re-enter it. Send the form and follow the inbox instructions if verification is requested.',
        'Open Sign in and enter the same email and password. If you enrolled through Google, select Continue with Google and choose the same identity.',
        'Open Settings from the dashboard and verify the email and access role displayed on Profile. Save your name and other details if they need updating.',
        'Open Billing and confirm the plan, provider, and access status. If you started from pricing, resume the checkout for this account and confirm that the plan appears after approval.',
        'Confirm organization membership with your administrator if team data is expected. Open an available dashboard module and confirm that the page loads for your account.',
      ],
      result: 'You can open your signed-in workspace, see the correct identity, and identify the plan and organization you are working under.',
      security: 'Use your own account. Store passwords privately and keep verification or reset links out of tickets, screenshots, and chat.',
      mistakes: 'Using a different Google account after checkout or signing in on a different deployment can leave you in a workspace without the expected access.',
      troubleshoot: 'For expired or missing email links, check the destination address and spam folder. Use Forgot password for an existing account and provide the timestamp to support if the new link still fails.',
    },
  },
  {
    id: 'account-settings',
    category: 'dashboard',
    title: 'Profile, preferences, and account activity',
    summary: 'Update your profile, control the dashboard experience, and review recent account activity from Settings.',
    keywords: [
      'user preferences',
      'notifications',
      'workspace',
      'account timeline',
      'profile',
      'browser notifications',
      'appearance',
    ],
    routes: ['/dashboard/settings', '/dashboard/profile'],
    sources: [
      `${settings}page.tsx`,
      `${settings}PreferencesTab.tsx`,
      'src/hooks/use-profile-settings.ts',
      'src/api-server/profile.ts',
      'supabase/profile-security-schema.sql',
    ],
    status: 'implemented',
    related: ['account-security', 'billing-and-subscriptions'],
    sections: [
      {
        id: 'profile',
        title: 'Edit your profile',
        steps: [
          'Open Settings and choose Profile. Review your email verification badge, account timeline, and displayed role.',
          'Edit full name, username, company, phone, location, department, or job title and save. The username field accepts 3–60 letters, digits, dots, underscores, or hyphens.',
          'Use the avatar or banner controls to add, replace, or remove an image. Choose images intended to appear on your profile and exclude sensitive material.',
          'Use the email-change form to request a new address, then complete the verification email. Reload Profile and check the resulting address and verification status.',
        ],
        note: 'Job title is editable profile text. The access role is controlled by platform administration.',
      },
      {
        id: 'preferences',
        title: 'Set your workspace preferences',
        table: {
          headers: ['Panel', 'Controls', 'How to verify'],
          rows: [
            [
              'Appearance',
              'Choose the available theme or follow system appearance.',
              'The page changes theme and the appearance panel reports save status.',
            ],
            [
              'Notifications',
              'Allow Browser push when prompted and choose whether to show Security alerts.',
              'Select Send test notification after permission is granted. Reset site notification permission from browser settings if it is denied.',
            ],
            [
              'Workspace',
              'Choose dashboard density, default view, and whether to stream live profile activity. Save changes.',
              'Reload or start a new session. A plan-restricted default falls back to Overview. With live sync off, refresh the page to update account activity.',
            ],
          ],
        },
      },
      {
        id: 'activity',
        title: 'Review account activity',
        body: [
          'Open Activity to review recorded account events, times, and statuses. Compare an event with the settings change or sign-in you expected. The panel reflects the available account data sources.',
        ],
        bullets: [
          'If you recognize the event, record its timestamp when you need an audit reference.',
          'If a sign-in or change looks unfamiliar, open Security, review Active Sessions and Trusted Devices, and follow your organization’s account incident procedure.',
          'Use Billing to inspect receipts and payment events. Open the administration console only if you hold the platform owner identity.',
        ],
      },
    ],
  },
  {
    id: 'account-security',
    category: 'dashboard',
    title: 'Protect your account and review sessions',
    summary: 'Enroll a time-based authenticator, manage recovery codes, and revoke an unfamiliar session from Settings.',
    keywords: ['TOTP', 'MFA', '2FA', 'recovery codes', 'trusted devices', 'password', 'active sessions'],
    sources: [
      `${settings}page.tsx`,
      'src/api-server/profile.ts',
      'supabase/settings-session-revocation.sql',
      'supabase/profile-security-schema.sql',
    ],
    status: 'partial',
    related: ['account-settings', 'account-setup', 'troubleshooting'],
    sections: [
      {
        id: 'security-controls',
        title: 'Security controls',
        table: {
          headers: ['Control', 'What to do'],
          rows: [
            [
              'Password',
              'Enter the current password and a matching new password. Use Forgot password from Sign in if you cannot confirm the current password.',
            ],
            [
              'Two-Factor Authentication',
              'Enroll a TOTP authenticator and verify the six-digit code. Keep the recovery codes shown after enrollment in protected storage.',
            ],
            [
              'Recovery codes',
              'Regenerate codes if the current set was exposed or lost. Store the replacement set and remove copies of previous codes. The disable flow can accept an unused recovery code.',
            ],
            [
              'Security Notifications',
              'Set suspicious-login and security email preferences. The MFA required control records a policy flag for reporting.',
            ],
            [
              'Active Sessions',
              'Inspect browser or device, recent activity, and current-session marker. Revoke a different session, or sign out to end the current one.',
            ],
            [
              'Trusted Devices',
              'Review recognized devices, change their trust status, and set the expiration period between 1 and 365 days.',
            ],
          ],
        },
        note: 'Authenticator enrollment and the recorded MFA policy are separate controls. Check any sign-in enforcement requirements with the administrator for your deployment.',
      },
    ],
    tutorial: {
      time: '5–10 minutes',
      permissions: 'Access to your own signed-in account and Settings.',
      prerequisites: ['A trusted device', 'A TOTP-compatible authenticator', 'Protected storage for recovery codes'],
      steps: [
        'Open Settings, then Security and Two-Factor Authentication.',
        'Start enrollment and scan the QR code with your authenticator, or add the displayed secret manually if needed.',
        'Enter the current six-digit code and verify. Save the displayed recovery codes privately before leaving the page.',
        'Refresh Security and confirm that enrollment is enabled. Review the session and trusted-device lists and follow your security process if you find an unfamiliar device.',
        'If you end another session, confirm that it disappears from the list and that the device is prompted to sign in again.',
      ],
      result: 'Settings records a verified TOTP factor and shows the available recovery-code count and session state.',
      security: 'Treat the authenticator secret, enrollment QR, and recovery codes as credentials. Keep them out of screen shares and support tickets.',
      mistakes: 'A policy flag by itself does not enroll your device. A code from a different account or an inaccurate clock can fail verification.',
      troubleshoot: 'Enable automatic date and time on the authenticator device, wait for a fresh code, and try again from the correct authenticator entry.',
    },
  },
  {
    id: 'billing-and-subscriptions',
    category: 'administration',
    title: 'Plans, subscriptions, and billing for your account',
    summary: 'Choose a plan, verify paid access, manage renewal with the right provider, and download your billing documents.',
    keywords: [
      'subscription management',
      'billing',
      'checkout',
      'PayPal',
      'Google Play',
      'invoice',
      'receipt',
      'usage',
      'cancel',
      'entitlement',
      'renew',
    ],
    routes: ['/checkout', '/subscription/thank-you'],
    sources: [
      `${settings}BillingTab.tsx`,
      'src/pages/Checkout.tsx',
      'src/pages/SubscriptionThankYou.tsx',
      'src/api-server/billing.ts',
      'src/lib/subscription-access.ts',
      'src/lib/billing/plan-pricing.ts',
      'supabase/billing-integrity-hardening.sql',
    ],
    status: 'partial',
    related: ['account-setup', 'account-settings', 'billing-troubleshooting'],
    sections: [
      {
        id: 'plans',
        title: 'Choose access for your work',
        body: [
          'All four tiers are paid. Each higher tier builds on the tiers below it. Check the live pricing and provider approval screens for the amount and currency. Yearly billing charges for a full year at once.',
        ],
        table: {
          headers: ['Plan', 'Access at a glance'],
          rows: [
            ['Starter', 'QGuard Messaging with the Starter dashboard, profile, billing, and downloads.'],
            ['Basic', 'Adds Overview, Quantum Readiness, Migration Planner, and Migration Sandbox.'],
            [
              'Pro',
              'Adds modules in Discovery, Operations, ecosystem and supply chain, intelligence, PQAuth, observability, and trust.',
            ],
            [
              'Elite',
              'Adds QKMS, governance, telemetry, and Quantum Tools. The owner consoles use a separate authorization check.',
            ],
          ],
        },
      },
      {
        id: 'purchase',
        title: 'Purchase and confirm access',
        steps: [
          'Choose a plan and billing period from site pricing or the Billing plan picker.',
          'Sign in with the identity that will hold the subscription. Complete PayPal approval for web checkout. For a Google Play purchase, use the same QGuard account and follow Messaging’s store flow.',
          'Open Settings, then Billing. Check the plan, provider, status, and current period. A pending activation stays pending until the service verifies the provider record.',
          'After a plan change or provider approval, refresh Billing before attempting the gated module. Active and pending-renewal records can grant access under the plan rules.',
        ],
      },
      {
        id: 'changes',
        title: 'Change a plan or stop renewal',
        table: {
          headers: ['Action', 'Provider behavior', 'Verify the result'],
          rows: [
            [
              'Upgrade, downgrade, switch cycle, renew, or reactivate on web',
              'The Billing action can open PayPal for a new checkout or a revision. Some existing PayPal revisions proceed without another approval screen.',
              'Confirm the plan, dates, and payment period after provider synchronization.',
            ],
            [
              'Cancel a PayPal plan',
              'Cancel Subscription requests cancellation at PayPal. Once accepted, a recorded remaining paid period can preserve access through its end.',
              'Check the cancellation banner and access-through date. Compare with PayPal if the action reports an error.',
            ],
            [
              'Manage a Google Play plan',
              'Use Payments & subscriptions in Google Play for renewal or cancellation.',
              'Check the Play Store status, then confirm the resulting period or cancellation in Billing.',
            ],
            [
              'Change auto-renew for a manually managed record',
              'The local auto-renew control applies to eligible manual records. Provider-billed plans follow the provider’s renewal controls.',
              'Review the saved setting and any next-renewal date in Billing.',
            ],
          ],
        },
      },
      {
        id: 'history',
        title: 'Review invoices, usage, and notifications',
        bullets: [
          'Open Billing History & Invoices. Use the date or status filters, open Details for a transaction, or choose the invoice or receipt PDF control when present.',
          'Review Usage & Consumption Analytics for measured activity and displayed limits. Interpret measurements alongside the available source and date range.',
          'In Payment Methods, use provider setup when configured and permissioned. Existing records can expose default, update, or remove controls. The metadata editor concerns billing details, and raw card details belong on the provider’s page.',
          'Use Notification Controls to edit supported preference fields. Confirm delivery separately for any channel on which you rely. The webhook URL preference alone provides no delivery confirmation.',
        ],
      },
    ],
  },
  {
    id: 'owner-administration',
    category: 'administration',
    title: 'Platform owner administration',
    summary: 'Use the owner console to oversee user access, organizations, billing operations, platform controls, and audit evidence.',
    keywords: [
      'admin dashboard',
      'overview',
      'owner',
      'usage monitoring',
      'system configuration',
      'users',
      'RBAC',
      'organizations',
      'audit logs',
    ],
    routes: ['/dashboard/admin'],
    sources: [
      `${admin}page.tsx`,
      'src/components/admin-route.tsx',
      'src/hooks/use-admin-dashboard.ts',
      'src/api-server/admin.ts',
      'supabase/admin-dashboard-schema.sql',
    ],
    status: 'implemented',
    related: ['admin-users', 'admin-roles-tenants', 'admin-billing', 'admin-controls-evidence', 'revenue-intelligence'],
    sections: [
      {
        id: 'access',
        title: 'Who can use this console?',
        body: [
          'Open Platform Administration with the configured platform owner identity. The page and its server endpoints both check that identity. Organization ownership, an assigned administrator role, and a paid tier are separate from this platform owner permission.',
        ],
      },
      {
        id: 'overview',
        title: 'Start with Overview',
        steps: [
          'Check the refresh and stream state before reading the KPIs. Refresh if a connection is recovering.',
          'Review the available user, subscription, security, and activity summaries. Open a linked count or the relevant tab to inspect the underlying records.',
          'Check unavailable-source notices. A dash signals an unavailable measurement, while a measured zero represents an empty count.',
          'Use History after an administrative change to review the event and outcome.',
        ],
      },
      {
        id: 'tabs',
        title: 'Choose the right tab',
        table: {
          headers: ['Tab', 'Use it to'],
          rows: [
            ['Users', 'Find the account, inspect directory data, manage access and security, or export matching users.'],
            ['Roles', 'Review role assignments and manage the custom role catalog.'],
            ['Tenants', 'Manage organization records, owners and quotas, and inspect member counts.'],
            [
              'Plans & Billing',
              'Review subscriptions, provider records, invoice evidence, payment metadata, and billing events.',
            ],
            ['Security', 'Review measured controls, event windows, affected accounts, and open findings.'],
            ['Governance', 'Review policy verification and create a fingerprinted evidence snapshot.'],
            ['History', 'Find and export recorded administrative, security, billing, or migration events.'],
          ],
        },
        note: 'Manage deployment configuration through your authorized operations process. The owner console exposes its specific account, tenant, billing, and governance controls.',
      },
    ],
  },
  {
    id: 'admin-users',
    category: 'administration',
    title: 'Manage user accounts and access',
    summary: 'Find a user, review their account and entitlements, and make auditable owner-approved access changes.',
    keywords: [
      'add user',
      'change role',
      'assign tenant',
      'reset password',
      'sign out everywhere',
      'suspend',
      'disable',
      'delete user',
    ],
    sources: [
      `${admin}_users/UsersTab.tsx`,
      `${admin}_users/UserDialogs.tsx`,
      `${admin}_users/UserDetailDrawer.tsx`,
      'src/api-server/admin.ts',
      'supabase/admin-user-directory.sql',
    ],
    status: 'implemented',
    related: ['owner-administration', 'admin-roles-tenants', 'admin-controls-evidence'],
    sections: [
      {
        id: 'directory',
        title: 'Find and inspect an account',
        steps: [
          'Open Platform Administration and select Users. Search by name or email, or use the account, plan, role, tenant, activity, and MFA filters to narrow the directory.',
          'Open View details from the row menu or select the account. Verify the email, organization, role, subscription provider, MFA state, and recent activity before making changes.',
          'Use the Export menu for matching users. CSV exports the matching rows across pages. JSON includes directory statistics and integrity information.',
        ],
      },
      {
        id: 'actions',
        title: 'Choose the account action',
        table: {
          headers: ['Action', 'Effect'],
          rows: [
            [
              'Add user',
              'Creates a confirmed account with a temporary password. Choose the initial role and any applicable tenant. Arrange secure credential delivery through your organization.',
            ],
            [
              'Change role or Assign tenant',
              'Sets the selected role or organization when the account and role are eligible. Protected owner and role rules may constrain choices.',
            ],
            [
              'Manage plan',
              'Reviews or adjusts manually managed access where supported. A live provider-managed plan has provider restrictions.',
            ],
            ['Sign out everywhere', 'Revokes the account’s sessions. The user must establish a new session to return.'],
            ['Reset password', 'Can send a reset email or generate a reset link. Handle any generated link as a credential.'],
            [
              'Require MFA or remove the requirement',
              'Updates the policy flag. Review the separate enrolled-factor state before recording MFA coverage.',
            ],
            [
              'Mark email verified',
              'Confirms an eligible account email from the owner console. Follow your identity-verification process before using it.',
            ],
            [
              'Suspend, disable, or restore',
              'Changes the account’s sign-in status. A block can end sessions. Restore lifts the modeled sign-in block.',
            ],
            [
              'Delete user',
              'Permanently removes an eligible account after the required confirmation. The console can block deletion when a provider-managed subscription still grants access.',
            ],
          ],
        },
        warning: 'Confirm the exact identity and scope first. A password reset link, temporary password, and directory export require the same care as other private account material.',
      },
      {
        id: 'verify',
        title: 'Verify the outcome',
        steps: [
          'Reload the affected user and confirm the new state.',
          'Find the corresponding event in History and record its outcome and timestamp.',
          'If the change concerns login or access, have the account holder verify using their own session. Compare the observed behavior with the recorded role, plan, and status.',
        ],
      },
    ],
  },
  {
    id: 'admin-roles-tenants',
    category: 'administration',
    title: 'Manage organizations and role assignments',
    summary: 'Create a tenant, assign members through the directory, and review role scope and active holders.',
    keywords: ['organization management', 'add tenant', 'member', 'quota', 'custom roles', 'RBAC', 'role scope', 'holders'],
    sources: [
      `${admin}_tenants/TenantsTab.tsx`,
      `${admin}_roles/RolesTab.tsx`,
      `${admin}_users/UserDialogs.tsx`,
      'src/api-server/admin.ts',
      'supabase/admin-dashboard-schema.sql',
    ],
    status: 'partial',
    related: ['owner-administration', 'admin-users', 'admin-controls-evidence'],
    sections: [
      {
        id: 'tenants',
        title: 'Create or review a tenant',
        steps: [
          'Open Tenants and select Add tenant. Provide the organization name and slug. Review the available owner, quota, domain, and region fields before saving.',
          'Open Users, locate the intended account, and use Assign tenant to select the organization. Return to Tenants and verify the member count or choose the action that opens its members in Users.',
          'Use the status and quota or ownership filters to find suspended, over-quota, or ownerless organizations.',
          'For a suspension, read the dialog and choose whether to apply the block to eligible members. Review the separately recorded member changes before restoring. Deletion is restricted while a tenant has members.',
        ],
      },
      {
        id: 'roles',
        title: 'Review or change catalog roles',
        steps: [
          'Open Roles. Search by name, key, description, or permission pattern. Filter by type, status, or usage, or open View holders in Users.',
          'Select Create role to enter a name, key, description, scope label, tenant, and permission patterns as applicable. Choose the initial active or inactive status.',
          'Assign an applicable active role from Users, then return to Roles and verify the expected holder count.',
          'Deactivate to stop new assignments, or archive a role when retiring it. Review existing holders separately. To delete an eligible custom role, move its holders first and confirm with the exact role key.',
        ],
        note: 'The custom permission patterns are governance records. Per-request access still depends on the platform’s implemented owner, subscription, or module-specific authorization rules. System and built-in roles are protected.',
      },
    ],
  },
  {
    id: 'admin-billing',
    category: 'administration',
    title: 'Owner billing operations',
    summary: 'Reconcile subscriptions and invoice history, process supported plan actions, and distinguish provider charges from manual access grants.',
    keywords: [
      'plans and billing',
      'subscription approval',
      'extend period',
      'notify customer',
      'payment management',
      'manual',
      'complimentary',
      'provider billed',
    ],
    sources: [
      `${admin}_billing/BillingTab.tsx`,
      `${admin}_users/UserDialogs.tsx`,
      'src/api-server/admin.ts',
      'src/lib/billing/revenue-model.ts',
      'supabase/billing-integrity-hardening.sql',
    ],
    status: 'implemented',
    related: ['owner-administration', 'billing-and-subscriptions', 'revenue-intelligence', 'revenue-subscriptions'],
    sections: [
      {
        id: 'reconcile',
        title: 'Review the source records',
        table: {
          headers: ['Section', 'What it shows'],
          rows: [
            [
              'Subscriptions',
              'Search the ledger or filter by status, plan, and revenue class. Review access, billing source, paid period, renewal intent, and measured monthly recurring revenue (MRR).',
            ],
            [
              'Invoices',
              'Inspect recorded charges, failures, and refunds received from configured provider flows. The console can show a limited recent list.',
            ],
            ['Plans', 'Review the catalog tiers and their listed values.'],
            [
              'Payment methods',
              'Review recorded payment method metadata. Customers add payment details through their provider checkout.',
            ],
            ['Billing events', 'Review recent activation, plan change, cancellation, and reminder events.'],
          ],
        },
      },
      {
        id: 'operations',
        title: 'Manage an eligible subscription',
        steps: [
          'Find the account and verify its plan, billing source, and access-through date.',
          'Open the row menu. Depending on eligibility, use Manage plan, Extend period, Notify customer, Approve, Cancel subscription, or Delete record. Review the dialog before confirming.',
          'Use the provider process for Google Play cancellation and respect provider restrictions on active records. Notify customer creates an in-app billing reminder.',
          'Refresh the subscription record and check Billing events or History for the recorded outcome.',
        ],
      },
      {
        id: 'billing-classes',
        title: 'Separate access and revenue',
        body: [
          'A manually granted or complimentary subscription can create access without collecting money. Verify collected payments from provider-backed invoice evidence, and use Revenue Intelligence for reconciled totals and exports.',
        ],
      },
    ],
  },
  {
    id: 'admin-controls-evidence',
    category: 'administration',
    title: 'Review security controls and export audit evidence',
    summary: 'Investigate measured control failures, check policy verification, generate a fingerprinted record, and locate the audit trail.',
    keywords: [
      'audit logs',
      'history',
      'security posture',
      'policy',
      'attestation',
      'governance',
      'SHA3-256',
      'evidence package',
    ],
    sources: [
      `${admin}_security/SecurityTab.tsx`,
      `${admin}_governance/GovernanceTab.tsx`,
      `${admin}_history/HistoryTab.tsx`,
      'src/api-server/admin.ts',
      'supabase/admin-dashboard-schema.sql',
    ],
    status: 'implemented',
    related: ['owner-administration', 'admin-users', 'admin-roles-tenants'],
    sections: [
      {
        id: 'security',
        title: 'Investigate from Security',
        bullets: [
          'Choose Last 24 hours, Last 7 days, or Last 30 days. Check measured controls, MFA coverage, open findings, event counts, and blocked access. Some summary cards use their own labeled time window.',
          'Expand your review to event types and critical or high events. Select an affected account where linked to open the matching Users view.',
          'Inspect a measured result and its remediation guidance before taking action. Treat Unknown or unmeasured fields as a gap in available evidence.',
        ],
      },
      {
        id: 'governance',
        title: 'Record and interpret governance policies',
        bullets: [
          'Use Add policy, then enter a name, a permanent key, a category, an enforcement level, and a description. Review the separate Verification result after saving.',
          'Manage enabled or disabled states from the policy menu. The platform protects built-in policies from deletion.',
          'A custom governance statement without an automated measurement is recorded as Attested. Use the verification state and source to interpret any claimed control outcome.',
        ],
      },
      {
        id: 'history',
        title: 'Find an audit event',
        steps: [
          'Open History. Select Administrator actions, Security events, Billing events, or Migration events.',
          'Set the time range and search for an action, target, or event. Administrator actions also support category and actor filters. Use Console views explicitly if you need view records, which are hidden by default.',
          'Open or review the matching result, then export the filtered records if you need an approved evidence copy.',
        ],
      },
    ],
    tutorial: {
      time: '10–15 minutes',
      permissions: 'Platform owner access and approval to handle exported audit records.',
      prerequisites: ['Access to Platform Administration', 'A defined time window and audit scope'],
      steps: [
        'Open Security and review controls and source coverage for your time window.',
        'Open Governance and check the verification states of the policies in scope.',
        'Select Generate evidence, enter an identifiable title, review the scope, and confirm Generate.',
        'Find the new evidence package and download it through the owner console. Compare its recorded SHA3-256 fingerprint with the recomputed fingerprint included in the download.',
        'Open History and find the evidence-generation action. Retain the package and audit reference according to your retention policy.',
      ],
      result: 'The console stores an independently checkable snapshot and records the owner action. Verification reports the evidence available at capture time.',
      security: 'Evidence packages and history exports can contain account and organization information. Share them only through the authorized audit process.',
      mistakes: 'The Enforcement level expresses policy intent. Use Verification to see whether a control was measured, enforced by the platform, or attested.',
      troubleshoot: 'If generation fails or sources are incomplete, check the console’s source notices and retry. Confirm a new package and its associated History record before treating the capture as complete.',
    },
  },
  {
    id: 'revenue-intelligence',
    category: 'administration',
    title: 'Revenue Intelligence executive overview',
    summary: 'Read owner-only revenue, recurring revenue, customer, subscription, and payment metrics from the billing ledger.',
    keywords: ['revenue intelligence', 'MRR', 'ARR', 'reconciliation', 'income', 'cash', 'payment ledger'],
    routes: ['/dashboard/revenue-intelligence'],
    sources: [`${revenue}page.tsx`, `${revenue}_shared.tsx`, 'src/api-server/revenue.ts', 'src/lib/billing/revenue-model.ts'],
    status: 'implemented',
    related: ['revenue-analytics', 'revenue-subscriptions', 'revenue-customers', 'revenue-payments', 'revenue-forecast'],
    sections: [
      {
        id: 'overview',
        title: 'Read the overview',
        steps: [
          'Sign in as the platform owner and open Revenue Intelligence, then Overview.',
          'Check the snapshot time, connection state, reconciliation indicator, and source coverage. Refresh if you see an old snapshot, and investigate incomplete source or read-ceiling notices before exporting.',
          'Review net revenue and activity for the reporting period. Check recurring revenue by plan and provider, and inspect new, expansion, contraction, and churn movement where shown.',
          'Use the page tabs to trace changes to an invoice, a subscription, or a customer. Open Forecast to export a report.',
        ],
      },
      {
        id: 'terms',
        title: 'Understand the metrics',
        table: {
          headers: ['Metric', 'Meaning'],
          rows: [
            [
              'Gross, refunded, and net revenue',
              'Recorded collected payments, recorded refunds, and the difference. Review currency coverage before comparing totals.',
            ],
            [
              'MRR and ARR',
              'Eligible provider-billed recurring revenue normalized to a month, and its annual run rate. A yearly charge contributes its monthly equivalent.',
            ],
            [
              'Churn and retention',
              'Movement in the eligible billed subscription cohort over the measured window. A missing baseline can leave a KPI blank.',
            ],
            [
              'ARPU and modeled LTV',
              'Monthly recurring revenue divided by paying customers, then ARPU divided by monthly churn when the necessary baseline exists.',
            ],
            [
              'Manual and complimentary access',
              'Classified separately from provider-billed revenue. A user can retain access with no contribution to MRR.',
            ],
          ],
        },
        note: 'USD totals exclude non-USD collections. Use the currency breakout before comparing a localized provider payment with the displayed USD total.',
      },
    ],
  },
  {
    id: 'revenue-analytics',
    category: 'administration',
    title: 'Analyze collected and refunded revenue',
    summary: 'Trace gross, refunded, and net revenue by month, provider, plan, and currency.',
    routes: ['/dashboard/revenue-intelligence/revenue'],
    sources: [`${revenue}revenue/page.tsx`, 'src/lib/billing/revenue-model.ts', 'src/api-server/revenue.ts'],
    status: 'implemented',
    related: ['revenue-intelligence', 'revenue-payments', 'revenue-forecast'],
    sections: [
      {
        id: 'reading-revenue',
        title: 'Compare time periods and breakdowns',
        steps: [
          'Open Revenue Intelligence, then Revenue. Check the snapshot timestamp and source coverage.',
          'Read the monthly gross, refund, and net series. Revenue windows include today, this week, this month, and longer comparisons. Compare periods using the reporting timezone.',
          'Inspect the plan, provider, and currency breakdowns. Refunds are recognized on the recorded refund date, which can differ from the original charge date.',
          'Open Payments for a specific ledger record. Export the Revenue Report from Forecast for monthly totals or the Payment Report for transaction rows.',
        ],
      },
    ],
  },
  {
    id: 'revenue-subscriptions',
    category: 'administration',
    title: 'Analyze subscription health and changes',
    summary: 'Review plan mix, the status ledger, billed churn and renewal, and provider verification signals.',
    keywords: ['subscription analytics', 'renewal pending', 'churn', 'plan changes', 'store verification', 'dead-letter events'],
    routes: ['/dashboard/revenue-intelligence/subscriptions'],
    sources: [
      `${revenue}subscriptions/page.tsx`,
      `${revenue}subscriptions/_billing-ops-panel.tsx`,
      'src/lib/billing/revenue-model.ts',
      'src/lib/billing/billing-ops.ts',
    ],
    status: 'implemented',
    related: ['revenue-intelligence', 'admin-billing', 'revenue-forecast'],
    sections: [
      {
        id: 'subscription-ledger',
        title: 'Investigate a subscription',
        steps: [
          'Open Revenue Intelligence, then Subscriptions. Review the status breakdown, plan access mix, and provider-billed recurring contribution.',
          'Search the ledger and filter by status or revenue class. Sort by a supported header to compare records and open a linked customer for full billing detail.',
          'Check billing class, provider, current status, and renewal date before interpreting MRR. Review the separately grouped manual and complimentary records.',
          'Check the billing operations panel when provider verification or delivery appears delayed. Use owner billing operations for eligible record changes.',
        ],
      },
    ],
  },
  {
    id: 'revenue-customers',
    category: 'administration',
    title: 'Analyze customers and account value',
    summary: 'Compare registered, paying, lapsed, and unbilled account segments, then drill into an individual customer record.',
    routes: ['/dashboard/revenue-intelligence/customers'],
    sources: [`${revenue}customers/page.tsx`, `${revenue}_shared.tsx`, 'src/api-server/revenue.ts'],
    status: 'implemented',
    related: ['revenue-intelligence', 'revenue-payments', 'admin-users'],
    sections: [
      {
        id: 'customer-ledger',
        title: 'Find the customer and review their record',
        steps: [
          'Open Revenue Intelligence, then Customers. Compare registered accounts, paying customers, new sign-ups, and customer value metrics using the stated basis.',
          'Search by email, name, or plan. Choose the paying, lapsed, or unbilled access segment when needed.',
          'Select a customer to inspect their subscription, lifetime net revenue, monthly recurring contribution, paid invoices, failed payments, and available activity. Use the account directory for role, tenant, and sign-in changes.',
          'Use the Customer Report export for the full finance ledger in scope. Share customer details only within approved finance or support channels.',
        ],
      },
    ],
  },
  {
    id: 'revenue-payments',
    category: 'administration',
    title: 'Review payments and refunds',
    summary: 'Locate a provider-backed charge or refund and verify its outcome against the payments ledger.',
    routes: ['/dashboard/revenue-intelligence/payments'],
    sources: [`${revenue}payments/page.tsx`, 'src/api-server/revenue.ts', 'src/lib/billing/revenue-model.ts'],
    status: 'implemented',
    related: ['revenue-analytics', 'revenue-customers', 'revenue-forecast', 'billing-troubleshooting'],
    sections: [
      {
        id: 'payments-ledger',
        title: 'Find a recorded transaction',
        steps: [
          'Open Revenue Intelligence, then Payments. Review collected, failed, refunded, and pending counts and check which providers populated the ledger.',
          'Search by invoice number, transaction reference, or email. Filter by outcome and provider, then compare the amount, currency, timestamp, and status with the source record.',
          'Treat failed attempts as attempted payments and pending records as awaiting settlement. Use the Payment Report if the on-screen ledger is truncated.',
          'Handle any payment dispute or refund through the provider and your finance process. Recheck the ledger after the verified provider event arrives.',
        ],
      },
    ],
  },
  {
    id: 'revenue-forecast',
    category: 'administration',
    title: 'Read forecasts and export finance reports',
    summary: 'Check actuals and forecast assumptions, review backtest performance, and export owner-only CSV or JSON reports.',
    keywords: ['forecasting', 'optimistic', 'conservative', 'scenario', 'MAPE', 'download revenue report'],
    routes: ['/dashboard/revenue-intelligence/forecast'],
    sources: [
      `${revenue}forecast/page.tsx`,
      `${revenue}_shared.tsx`,
      'src/lib/billing/revenue-model.ts',
      'src/api-server/revenue.ts',
    ],
    status: 'implemented',
    related: ['revenue-intelligence', 'revenue-analytics', 'admin-controls-evidence'],
    sections: [
      {
        id: 'forecast',
        title: 'Read the current forecast',
        bullets: [
          'Compare completed month actuals and current month to date with the forecast series. Check the source coverage, confidence reason, and projection availability message.',
          'When there is sufficient history, inspect conservative, base, and optimistic MRR scenarios. Read the new subscription and churn multipliers for each scenario.',
          'Review inputs labeled as measured or assumed. Compare the backtest’s predicted and actual values and read its mean absolute percentage error only when the page has an eligible baseline.',
        ],
      },
      {
        id: 'finance-exports',
        title: 'Export the report that supports your review',
        steps: [
          'Choose Executive Summary, Revenue Report, Subscription Report, Customer Report, or Payment Report.',
          'Select CSV for a spreadsheet or JSON for structured processing. Inspect the export status and downloaded file.',
          'Verify the report name, generation time, and rows. Review source completeness before sharing or reconciling totals.',
        ],
        note: 'The exports draw on the full computed report model rather than only the rows previewed in the dashboard. A source read gap can still leave affected figures incomplete.',
      },
    ],
  },
  {
    id: 'developer-api',
    category: 'developers',
    title: 'Platform API overview',
    summary: 'Find the API for your deployment, choose the correct authentication, and make a read-only request before integrating a module.',
    keywords: [
      'API overview',
      'architecture',
      'SDK',
      'REST',
      'Express',
      'Supabase Auth',
      'database integration',
      'API version',
      'health check',
    ],
    aliases: ['api'],
    sources: [
      'src/api-server/index.ts',
      'src/api-server/public-api.ts',
      'src/api-server/runtime/health.ts',
      'src/lib/supabase-server.ts',
      'src/api-server/subscription-guard.ts',
      'src/lib/billing/billing-api.ts',
    ],
    status: 'implemented',
    related: ['api-authentication', 'api-read-reference', 'api-realtime', 'api-errors'],
    sections: [
      {
        id: 'deployment',
        title: 'Choose the correct deployment',
        body: [
          'The React web client serves the dashboard and sends requests to the Node.js/Express API in the full platform deployment. Supabase supplies identity and row-scoped persistence. Server handlers enforce account, entitlement, and owner checks according to the route.',
          'A public-only deployment exposes a smaller route set for public assessment and demo requests, plus health probes. Some deployments use a separate billing service for checkout. Use the base URL given by your deployment owner for authenticated dashboard integrations.',
        ],
      },
      {
        id: 'architecture',
        title: 'How a dashboard API request flows',
        flow: [
          'Web client or authorized integration',
          'Express route',
          'Identity and access checks',
          'Scoped data or provider service',
          'JSON, file, or realtime stream',
        ],
      },
      {
        id: 'first-request',
        title: 'Check the API origin',
        body: [
          'Use the full platform API origin for this example. The response includes status, process start time, uptime in seconds, and drain state. Extra readiness fields vary by deployment.',
        ],
        code: { language: 'bash', value: 'curl -i "$QGUARD_URL/api/v1/healthz"' },
      },
      {
        id: 'readiness',
        title: 'Read liveness and readiness separately',
        table: {
          headers: ['Request', 'What it tells you'],
          rows: [
            ['GET /api/v1/healthz', 'Checks that the API process can respond. The JSON status is ok.'],
            [
              'GET /api/v1/readyz',
              'Reports whether the deployment can accept traffic. The full platform checks configured dependencies. A degraded state may have HTTP 200 depending on readiness policy.',
            ],
          ],
        },
        note: 'The paths in this reference describe the current application routes. Confirm availability and entitlement in your deployment before depending on a specific contract.',
      },
    ],
  },
  {
    id: 'api-authentication',
    category: 'developers',
    title: 'Authenticate API requests and respect scope',
    summary: 'Use a current authorized user session and understand how the API checks subscription and owner access.',
    keywords: ['authentication', 'authorization', 'JWT', 'bearer', 'RLS', 'tenant isolation', 'security'],
    aliases: ['api/authentication', 'api/security'],
    sources: [
      'src/lib/supabase-server.ts',
      'src/api-server/profile.ts',
      'src/api-server/subscription-guard.ts',
      'src/api-server/admin.ts',
      'supabase/profile-security-schema.sql',
      'supabase/billing-integrity-hardening.sql',
    ],
    status: 'implemented',
    related: ['developer-api', 'api-read-reference', 'api-errors'],
    sections: [
      {
        id: 'bearer',
        title: 'Use the signed-in account’s access token',
        body: [
          'Obtain a current access token from the authorized Supabase session for your application. Put it in the Authorization header over HTTPS. The example reads the value from your local test environment. Avoid printing or sharing the token.',
        ],
        code: {
          language: 'bash',
          value: 'curl --silent --show-error --fail-with-body \\\n  -H "Authorization: Bearer $QGUARD_ACCESS_TOKEN" \\\n  "$QGUARD_URL/api/v1/profile/preferences"',
        },
      },
      {
        id: 'response',
        title: 'Example shape for account preferences',
        body: [
          'This example shows the response fields with illustrative preference values. Each response reflects the signed-in account’s saved values or defaults.',
        ],
        code: {
          language: 'json',
          value: '{\n  "data": {\n    "preferences": {\n      "theme": "system",\n      "dashboardDensity": "comfortable",\n      "defaultDashboardView": "overview",\n      "notificationPush": false,\n      "securityAlerts": true,\n      "telemetryOptIn": true,\n      "updatedAt": null\n    }\n  }\n}',
        },
      },
      {
        id: 'scope',
        title: 'Understand separate access checks',
        bullets: [
          'User-scoped routes derive the identity from the validated session. Database row policies and route scoping limit account data. Do not route around the API using administrative database credentials.',
          'Plan-gated routes can reject a valid session with SUBSCRIPTION_REQUIRED. Check the active subscription and current tier through the authorized app.',
          'Owner-only administration and revenue endpoints require the designated platform owner identity. A paid tier or a general admin role does not grant that authorization.',
          'After a 401, acquire a valid session before retrying. Treat a 403 as a permission or entitlement finding. Inspect the specific error code.',
        ],
      },
    ],
    tutorial: {
      time: '5 minutes',
      permissions: 'An authorized application session and read access to your own account preferences.',
      prerequisites: [
        'An HTTPS API base URL for a full platform deployment',
        'An approved way to obtain the current user session',
        'A terminal or API client',
      ],
      steps: [
        'Use the liveness request from the API overview to verify the origin.',
        'Make the preferences request with your authorized session. Verify that the response contains data.preferences.',
        'Compare the preference fields with Settings. Make the same request without credentials and confirm that the API responds with 401 and UNAUTHORIZED.',
        'Remove the token from the local test environment when finished. Record only the request path, response status, and sanitized error details.',
      ],
      result: 'You have checked a signed-in read and the missing-authorization response without changing any account preference.',
      security: 'Handle the session token like a password. Use HTTPS and keep the token out of URLs, persistent logs, screenshots, and application bundles.',
      mistakes: 'A static marketing host may return an HTML page or a 404 for signed-in API routes. Use the platform API origin.',
      troubleshoot: 'Check the token expiry, Authorization header, and owning project. Sign in again if the session expired.',
    },
  },
  {
    id: 'api-read-reference',
    category: 'developers',
    title: 'Read-only endpoint reference',
    summary: 'Look up the current dashboard, billing, inventory, migration, and owner reporting read endpoints.',
    keywords: [
      'endpoints',
      'request',
      'response',
      'catalog',
      'keys API',
      'OTP API',
      'scanner API',
      'certificates',
      'cloud',
      'tokenization',
      'secure communications',
      'vault API',
    ],
    aliases: [
      'api/admin',
      'api/scanner',
      'api/keys',
      'api/otp',
      'api/pki',
      'api/tokenize',
      'api/comm',
      'api/cloud',
      'api/vault',
    ],
    sources: [
      'src/api-server/index.ts',
      'src/api-server/subscriptions.ts',
      'src/api-server/dashboard.ts',
      'src/api-server/scanner.ts',
      'src/api-server/quantum-readiness.ts',
      'src/api-server/quantum-certification.ts',
      'src/api-server/exposure-graph.ts',
      'src/api-server/migration-planner.ts',
      'src/api-server/reports.ts',
      'src/api-server/qkms-dashboard.ts',
      'src/api-server/service-records.ts',
      'src/api-server/admin.ts',
      'src/api-server/revenue.ts',
      'supabase/functions/billing/play-service.ts',
    ],
    status: 'implemented',
    related: ['developer-api', 'api-authentication', 'api-errors'],
    sections: [
      {
        id: 'account-reads',
        title: 'Account and subscription reads',
        table: {
          headers: ['Request', 'Response data'],
          rows: [
            ['GET /api/v1/profile/preferences', 'Current account’s normalized preferences under data.preferences.'],
            [
              'GET /api/v1/subscriptions/catalog',
              'Public catalog on the full API, with data.products, data.tiers, data.rules, and data.playProducts.',
            ],
            [
              'GET /api/v1/subscriptions/me',
              'Subscription summary, access, entitlements, and the signed-in account’s Play identifier.',
            ],
            ['GET /api/v1/subscriptions/entitlements', 'The signed-in account’s data.keys and data.validUntil.'],
            ['GET /api/v1/subscriptions/history', 'Recent invoices and billing events for the signed-in account.'],
          ],
        },
        note: 'The entitlements endpoint reflects the current materialized entitlement records. Use the dashboard and module-specific access checks to confirm availability.',
      },
      {
        id: 'workspace-reads',
        title: 'Workspace evidence reads',
        table: {
          headers: ['Request', 'Purpose'],
          rows: [
            ['GET /api/v1/dashboard/summary', 'Dashboard summary available for the authenticated workspace.'],
            ['GET /api/v1/scanner/history', 'Recorded scan history.'],
            ['GET /api/v1/scanner/cbom', 'Cryptographic component inventory.'],
            ['GET /api/v1/scanner/assets', 'Discovered asset records.'],
            ['GET /api/v1/quantum-readiness', 'Readiness assessment model.'],
            ['GET /api/v1/exposure-graph', 'Exposure nodes, relationships, and computed evidence.'],
            ['GET /api/v1/quantum-certification', 'Certification dashboard model.'],
            ['GET /api/v1/migration-planner/plans', 'Recorded migration plan data.'],
            ['GET /api/v1/reports/history', 'Report history.'],
          ],
        },
        note: 'These routes require a valid user session and the applicable plan or module access. An empty evidence collection can be valid when no records exist for the account.',
      },
      {
        id: 'tool-reads',
        title: 'Cryptographic tool and owner reads',
        table: {
          headers: ['Request', 'Purpose'],
          rows: [
            ['GET /api/v1/dashboard/qkms/keys', 'Managed key inventory with the applicable access checks.'],
            ['GET /api/v1/keys', 'User-scoped key records. Stored records alone provide no issuance assurance.'],
            ['GET /api/v1/pki', 'User-scoped recorded certificate metadata.'],
            ['GET /api/v1/otp', 'Current user’s OTP records. Handle any returned authentication material securely.'],
            ['GET /api/v1/tokenize', 'Current user’s tokenization records.'],
            ['GET /api/v1/comm and GET /api/v1/cloud', 'Current user’s communications and cloud records.'],
            ['GET /api/v1/admin/stats', 'Platform owner summary.'],
            ['GET /api/v1/revenue/snapshot', 'Platform owner revenue snapshot and coverage.'],
            [
              'GET /api/v1/revenue/export?report=summary&format=json',
              'Owner-only finance export. The JSON attachment includes report, generatedAt, reportingCurrency, timezone, headers, rows, kpis, and coverage.',
            ],
          ],
        },
        warning: 'Use approved exports and storage for owner and crypto data. The standard key and certificate issue actions currently return CRYPTO_ISSUANCE_UNAVAILABLE. Use the related product guides to validate supported operations.',
      },
    ],
  },
  {
    id: 'api-realtime',
    category: 'developers',
    title: 'Realtime data and provider webhooks',
    summary: 'Understand how settings and owner dashboards subscribe to data, how to reconnect, and which webhooks are provider-to-platform inputs.',
    keywords: [
      'SSE',
      'server-sent events',
      'EventSource',
      'WebSocket',
      'stream tickets',
      'Realtime',
      'webhooks',
      'Google Play RTDN',
      'PayPal',
    ],
    aliases: ['api/webhooks', 'api/architecture'],
    sources: [
      'src/api-server/runtime/stream-tickets.ts',
      'src/api-server/profile.ts',
      'src/api-server/billing.ts',
      'src/api-server/admin.ts',
      'src/api-server/revenue.ts',
      'src/api-server/paypal.ts',
      'src/api-server/subscriptions.ts',
      'src/hooks/use-profile-settings.ts',
      'src/hooks/use-billing-settings.ts',
      'supabase/functions/billing/play-service.ts',
    ],
    status: 'implemented',
    related: ['developer-api', 'api-authentication', 'api-errors'],
    sections: [
      {
        id: 'tickets',
        title: 'Subscribe to an authenticated stream',
        steps: [
          'Send POST /api/v1/stream-tickets with the current Authorization bearer header and JSON body containing the stream name. The supported names in this service are profile, billing, admin, and revenue.',
          'Read data.ticket, data.expiresAt, and data.path from the response. Open the returned same-origin stream path with the opaque value as its ticket query parameter.',
          'Handle events from that stream. For example, the profile stream emits connected, telemetry, activity, and heartbeat. The billing stream emits connected, billing-sync, and heartbeat.',
          'If the connection closes, fetch a new ticket with a current session. Tickets expire after 60 seconds and are single use. Admin and revenue still require owner authorization when the stream opens.',
        ],
      },
      {
        id: 'transports',
        title: 'Distinguish streaming and realtime subscriptions',
        body: [
          'SSE carries server events over a persistent HTTP connection. Profile and billing views also subscribe to scoped Supabase changes where configured. Their Realtime coverage depends on the allowed tables and account scope. Use the module’s documented transport and retain the last successful snapshot with its timestamp if updates stop.',
        ],
      },
      {
        id: 'provider-webhooks',
        title: 'Use the provider’s callback channel',
        table: {
          headers: ['Provider callback in the full API', 'Role'],
          rows: [
            [
              'POST /api/v1/paypal/webhook',
              'Receives PayPal billing events. The handler checks the provider’s webhook signature before applying verified subscription and invoice changes.',
            ],
            [
              'POST /api/v1/webhooks/google-play/rtdn',
              'Receives authenticated Google Play notifications. The handler rechecks provider purchase state before applying subscription changes.',
            ],
            [
              'POST /api/v1/billing/webhooks/stripe',
              'Receives Stripe events when configured. This route does not establish Stripe checkout availability.',
            ],
          ],
        },
        note: 'These are provider-to-platform callbacks. The account notification preferences alone do not confirm a general outbound webhook contract.',
      },
    ],
  },
  {
    id: 'api-errors',
    category: 'developers',
    title: 'Handle API errors and retries',
    summary: 'Read scoped error codes, distinguish authentication failures from entitlement issues, and recover without repeating a completed request.',
    keywords: ['error codes', '401', '403', '429', '503', 'rate limits', 'request ID', 'retry'],
    aliases: ['api/errors', 'api/sdk', 'api/sdks', 'api/changelog'],
    sources: [
      'src/api-server/profile.ts',
      'src/api-server/subscription-guard.ts',
      'src/api-server/revenue.ts',
      'src/api-server/billing.ts',
      'src/api-server/demo-request.ts',
      'src/api-server/runtime/observability.ts',
    ],
    status: 'implemented',
    related: ['developer-api', 'api-authentication', 'api-realtime'],
    sections: [
      {
        id: 'example',
        title: 'Read the error envelope',
        body: [
          'A profile request without an Authorization header returns 401 with this body. Other route groups can have different error shapes. Use the HTTP status and check the response content type before interpreting it.',
        ],
        code: {
          language: 'json',
          value: '{\n  "error": {\n    "code": "UNAUTHORIZED",\n    "message": "Authentication required"\n  }\n}',
        },
      },
      {
        id: 'recovery',
        title: 'Choose the right recovery action',
        table: {
          headers: ['Response', 'Next step'],
          rows: [
            [
              '400 VALIDATION_ERROR',
              'Correct the rejected fields or the request shape. Check the route-specific code and message.',
            ],
            [
              '401 UNAUTHORIZED',
              'Check that the bearer session is present and current. Sign in again or renew the session before retrying.',
            ],
            [
              '403 FORBIDDEN or SUBSCRIPTION_REQUIRED',
              'Check the role, owner access, plan, and active period. Changing credentials does not grant entitlement.',
            ],
            ['409 PROVIDER_MANAGED', 'For billing, complete a provider-managed change through the indicated provider.'],
            [
              '429 RATE_LIMITED',
              'Wait before retrying. Honor Retry-After when present. Limits vary by endpoint. Owner finance exports allow 30 per 60 seconds per owner.',
            ],
            [
              '503 ENTITLEMENT_UNAVAILABLE or provider configuration errors',
              'Check service status and retry an eligible read after recovery. Confirm account or provider state before resubmitting a write.',
            ],
          ],
        },
        note: 'For support, capture the HTTP method, route, response status, error code, timestamp, and request ID if present. Leave credentials and request bodies with personal data out of the report.',
      },
    ],
  },
  {
    id: 'troubleshooting',
    category: 'support',
    title: 'Recover access and troubleshoot the dashboard',
    summary: 'Start with your account, workspace, and data source when the dashboard is unavailable, empty, or stale.',
    keywords: [
      'dashboard loading',
      'login failure',
      'account recovery',
      'reset password',
      'missing data',
      'no data',
      'stale snapshot',
      'support',
      'permission denied',
    ],
    routes: ['/contact'],
    aliases: ['support'],
    sources: [
      'src/pages/Contact.tsx',
      'src/app/authentication/login/page.tsx',
      'src/app/authentication/reset-password/page.tsx',
      'src/app/dashboard/dashboard_layout/DashboardLayout.tsx',
      'src/hooks/use-profile-settings.ts',
      'src/lib/subscription-access.ts',
    ],
    status: 'implemented',
    related: ['account-setup', 'account-security', 'billing-troubleshooting', 'platform-data-troubleshooting', 'faq'],
    sections: [
      {
        id: 'sign-in',
        title: 'Sign-in fails or email recovery stalls',
        table: {
          headers: ['Check', 'What to do'],
          rows: [
            [
              'Symptoms',
              'Sign-in returns an error, redirects to the login page, or the recovery form reports an expired link.',
            ],
            [
              'Possible causes',
              'Wrong email identity, expired session or link, incomplete email confirmation, an account restriction, or provider consent blocked.',
            ],
            [
              'Diagnose',
              'Confirm the deployment URL and sign-in method. Check the intended inbox and spam folder for the latest email. For Google, confirm the selected account and provider consent.',
            ],
            [
              'Resolve',
              'Use the original sign-in method. Request a new recovery link if needed. For a suspended or disabled account, ask the platform owner to review account status.',
            ],
            ['Verify', 'Open the dashboard or Settings and check that the signed-in email is the expected account.'],
          ],
        },
      },
      {
        id: 'workspace',
        title: 'A page is missing, blank, or keeps loading',
        table: {
          headers: ['Check', 'What to do'],
          rows: [
            ['Symptoms', 'A module is missing from navigation, shows an upgrade screen, or fails to load.'],
            [
              'Possible causes',
              'A plan or role restriction, incorrect workspace, expired sign-in, or an unavailable API or data source.',
            ],
            [
              'Diagnose',
              'Open Settings and Billing to check identity, role, provider, plan, and status. For organization data, confirm tenant membership. Try a known available page to tell whether the issue affects one module or the whole workspace.',
            ],
            [
              'Resolve',
              'Refresh the session or correct the workspace. If access is expected, ask your administrator to verify the role and if necessary contact support with the module path and timestamp.',
            ],
            ['Verify', 'Reopen the exact route and confirm that it loads for the intended identity and approved tier.'],
          ],
        },
      },
      {
        id: 'report-an-issue',
        title: 'Ask for help with enough context',
        steps: [
          'Open Contact and choose the topic that matches your issue. Enter a short subject and describe the expected and actual result.',
          'Add the feature name, time and timezone, browser or app version, and a sanitized error code or reference. Include the account email only if needed to identify the subscription or workspace.',
          'Select Open in your email app. Review and send the draft through your email client.',
          'When support responds, repeat the original action with the same authorized scope and confirm the expected result.',
        ],
        warning: 'Remove secrets and personal data from screenshots and attachments. Keep session tokens, recovery codes, private keys, card numbers, and private files out of support requests.',
      },
    ],
  },
  {
    id: 'platform-data-troubleshooting',
    category: 'support',
    title: 'Diagnose missing evidence, failed assessments, and migration errors',
    summary: 'Trace a missing record from an authorized discovery source through the assessment, then verify any plan or sandbox result separately.',
    keywords: [
      'missing evidence',
      'asset discovery problems',
      'assessment failure',
      'migration planner errors',
      'sandbox failure',
      'compatibility',
      'no telemetry',
    ],
    sources: [
      'src/api-server/scanner.ts',
      'src/api-server/quantum-readiness.ts',
      'src/api-server/migration-planner.ts',
      'src/api-server/sandbox.ts',
      'src/api-server/sandbox-lab.ts',
      'src/api-server/crypto-agility.ts',
    ],
    status: 'implemented',
    related: ['troubleshooting', 'api-errors'],
    sections: [
      {
        id: 'evidence',
        title: 'An asset or finding is missing',
        table: {
          headers: ['Check', 'What to do'],
          rows: [
            ['Symptoms', 'Inventory or a graph has fewer assets than expected, or shows no observations.'],
            [
              'Possible causes',
              'The source has no saved evidence, a collector is stale, results are incomplete, or an active filter hides the record.',
            ],
            [
              'Diagnose',
              'Check the source run or last collector check-in, then confirm workspace, asset scope, filters, and observation time.',
            ],
            [
              'Resolve',
              'Correct filters and confirm the authorized source is connected and reporting. Run approved collection again only where your role and scope permit.',
            ],
            [
              'Verify',
              'Confirm a fresh timestamp and the expected evidence record on the asset. Check the same asset in CBOM or the readiness view.',
            ],
          ],
        },
      },
      {
        id: 'assessment',
        title: 'Assessment results are empty or outdated',
        table: {
          headers: ['Check', 'What to do'],
          rows: [
            ['Symptoms', 'A score is blank, an evidence warning appears, or the report references an earlier observation.'],
            [
              'Possible causes',
              'Incomplete input evidence, a different assessment time range, pending processing, or stale subscription updates.',
            ],
            [
              'Diagnose',
              'Compare the assessment or report timestamp with source scan or inventory timestamps. Look for warnings, scope filters, and unavailable source messages.',
            ],
            [
              'Resolve',
              'Refresh after collection completes. Fix source coverage and generate a report again only after the assessment reflects the intended inputs.',
            ],
            [
              'Verify',
              'Open the latest assessment and report. Confirm matching scope, recent inputs, and an evidence trail for the outcome.',
            ],
          ],
        },
      },
      {
        id: 'migration',
        title: 'A plan, sandbox test, or compatibility check fails',
        table: {
          headers: ['Check', 'What to do'],
          rows: [
            ['Symptoms', 'A plan cannot save, a simulation omits a result, or the sandbox reports a failed test.'],
            [
              'Possible causes',
              'The selected asset is out of scope, the input is incomplete, a proposed profile is unsupported, integration checks are unavailable, or a prerequisite failed.',
            ],
            [
              'Diagnose',
              'Confirm asset ownership and scope. Read the exact failed validation, available evidence, compatibility result, and selected proposed profile.',
            ],
            [
              'Resolve',
              'Correct the smallest input that differs from the expected plan, or test a supported alternative in an approved isolated environment. Record the failure and keep production change approval pending until the required validations pass.',
            ],
            [
              'Verify',
              'Find the saved plan or completed result and check the validation and compatibility records. Confirm the plan, simulation, and production state separately.',
            ],
          ],
        },
      },
    ],
  },
  {
    id: 'billing-troubleshooting',
    category: 'support',
    title: 'Resolve billing and paid-access problems',
    summary: 'Diagnose a pending activation, failed provider action, missing invoice, or inconsistent access status.',
    keywords: [
      'billing issues',
      'payPal charged',
      'Google Play',
      'payment declined',
      'subscription pending',
      'missing invoice',
      'provider managed',
    ],
    sources: [
      'src/pages/Checkout.tsx',
      'src/pages/SubscriptionThankYou.tsx',
      `${settings}BillingTab.tsx`,
      'src/api-server/billing.ts',
      'src/api-server/subscriptions.ts',
    ],
    status: 'implemented',
    related: ['troubleshooting', 'billing-and-subscriptions', 'faq'],
    sections: [
      {
        id: 'pending-payment',
        title: 'Payment completed and access is still pending',
        table: {
          headers: ['Check', 'What to do'],
          rows: [
            [
              'Symptoms',
              'The provider shows approval or payment while Billing still shows pending or the dashboard is locked.',
            ],
            [
              'Possible causes',
              'Provider confirmation is pending, or the subscription belongs to a different signed-in identity.',
            ],
            [
              'Diagnose',
              'Check the provider status and account email. Open Settings → Billing and record the plan, provider, and status shown.',
            ],
            [
              'Resolve',
              'Allow provider verification to complete, then refresh Billing or open the app again with the purchasing account. For Google Play, use the app’s restore flow where available. If the provider charged you and access stays locked, contact support before starting a second purchase.',
            ],
            ['Verify', 'The expected plan and period appear in Billing and the gated module opens for that account.'],
          ],
        },
      },
      {
        id: 'cycle',
        title: 'A renewal or cancellation control fails',
        table: {
          headers: ['Check', 'What to do'],
          rows: [
            ['Symptoms', 'Cancel or auto-renew reports a provider-managed error, or the date has not changed.'],
            [
              'Possible causes',
              'The chosen action belongs in the provider’s app, the provider has not confirmed it, or your account cannot manage billing.',
            ],
            [
              'Diagnose',
              'Check the current provider, status, next renewal, and access-through date. Read the action error before retrying.',
            ],
            [
              'Resolve',
              'Use Google Play for Play renewal changes and the PayPal cancellation flow for PayPal. If cancellation did not complete, verify its state with the provider before retrying.',
            ],
            [
              'Verify',
              'Provider status and the Billing renewal banner reflect the intended change. If a paid period remains, confirm its displayed end date.',
            ],
          ],
        },
      },
      {
        id: 'receipts',
        title: 'A charge or receipt is missing',
        table: {
          headers: ['Check', 'What to do'],
          rows: [
            ['Symptoms', 'A provider charge is visible outside QGuard Helix without a matching invoice or receipt.'],
            [
              'Possible causes',
              'The transaction is pending, synchronization is delayed, or filters exclude the date or payment state.',
            ],
            [
              'Diagnose',
              'Clear Billing History filters and compare the provider receipt reference, currency, date, and payment outcome.',
            ],
            [
              'Resolve',
              'Refresh after settlement. If the charge is confirmed and the record remains absent, send the non-secret provider reference and timestamp to support.',
            ],
            [
              'Verify',
              'Find the matching payment in Billing History and confirm that its detail page or available PDF shows the correct outcome.',
            ],
          ],
        },
      },
    ],
  },
  {
    id: 'faq',
    category: 'support',
    title: 'Frequently asked questions',
    summary: 'Find quick answers about access, data freshness, PQC evidence, testing, billing, and support.',
    keywords: ['FAQ', 'questions', 'upgrade', 'access code', 'PQC-ready', 'empty dashboard', 'support'],
    sources: [
      'src/lib/subscription-access.ts',
      'src/api-server/quantum-readiness.ts',
      'src/api-server/sandbox.ts',
      'src/api-server/billing.ts',
      'src/pages/Contact.tsx',
    ],
    status: 'implemented',
    related: ['troubleshooting', 'billing-troubleshooting', 'developer-api'],
    sections: [
      {
        id: 'access-faq',
        title: 'Accounts and access',
        questions: [
          {
            question: 'Why does a coworker see a different dashboard?',
            answer: 'Navigation depends on plan access, account state, and certain role or owner checks. Organization membership also affects which workspace evidence is available. Compare the account and Settings → Billing before escalating.',
          },
          {
            question: 'Does my paid plan grant access to Revenue Intelligence?',
            answer: 'The configured platform owner identity is required for Revenue Intelligence and Platform Administration.',
          },
          {
            question: 'How do I know if my account or checkout is using the right identity?',
            answer: 'Compare the signed-in email in Profile with the original purchase or enrollment identity. Confirm the plan and provider in Billing.',
          },
        ],
      },
      {
        id: 'evidence-faq',
        title: 'Evidence and migration',
        questions: [
          {
            question: 'Why does the dashboard show a dash or no data?',
            answer: 'A dash can indicate an unavailable measurement. Check the source status, filters, evidence date, and last successful snapshot. A zero applies to a metric the app could measure.',
          },
          {
            question: 'How do I confirm an asset is ready for a PQC change?',
            answer: 'Review the observed cryptography, dependencies, migration plan, validation results, and evidence timestamps for that asset. Confirm the intended configuration with a controlled test and reassess after the authorized change.',
          },
          {
            question: 'What happens when a Sandbox test completes?',
            answer: 'It records the test or simulation outcome for the selected scenario. Review the recorded scope and validations before deciding whether a controlled integration test or a production approval is appropriate.',
          },
        ],
      },
      {
        id: 'billing-faq',
        title: 'Billing and support',
        questions: [
          {
            question: 'How do I stop a Google Play subscription from renewing?',
            answer: 'Open Payments & subscriptions in Google Play with the purchasing identity. After making the change, confirm the recorded period and renewal state in the app.',
          },
          {
            question: 'Can I send logs or a screenshot to support?',
            answer: 'Yes. Include the feature, time and timezone, exact problem, and a sanitized code or screenshot. Use Contact to open a draft in your mail app and remove secrets or unrelated data before sending.',
          },
        ],
      },
    ],
  },
]
