import { visuals, type DocVisual } from './visuals'

function platformScreen(file: string, alt: string, caption: string, width = 1272, height = 716): DocVisual {
  return { src: `/docs-media/tutorial-${file}.jpg`, alt, caption, width, height }
}

// Keys are the numbered steps shown to the reader. More than one capture can
// document the same step, for example when Windows and Android differ.
export const walkthroughScreens: Record<string, Partial<Record<number, DocVisual[]>>> = {
  'account-setup': {
    1: [platformScreen('platform-register', 'QGuard Helix registration form with Work email, Password, Confirm password, and Create account', 'In Set up your access, enter your work email and confirm your password before choosing Create account.')],
    2: [platformScreen('platform-sign-in', 'QGuard Helix workspace sign-in with Work email, Password, Sign in, and Continue with Google', 'In Access your workspace, choose Sign in or Continue with Google using the identity you enrolled with.')],
  },
  'api-authentication': {
    1: [platformScreen('api-health', 'Browser response from the health endpoint showing status ok', 'The local API liveness endpoint returns a JSON response with status set to ok.', 850, 145)],
    3: [platformScreen('api-unauthorized', 'Unauthenticated preferences response with error code UNAUTHORIZED', 'The local preferences endpoint returns UNAUTHORIZED when the request has no credentials.', 850, 145)],
  },
  'first-readiness-assessment': {
    4: [platformScreen('asset-register', 'Asset Register search, data source, and risk filter controls in Asset Inventory & CBOM', 'In Asset Inventory & CBOM, use the Asset Register search and filters to find the asset from your scan. Cropped from an authenticated QA workspace.', 1130, 205)],
  },
  'inventory-workflow': {
    2: [platformScreen('asset-register', 'Asset Register with Discovery source, search, risk filter, and scanner risk sort controls', 'Search the Asset Register for your target. The Discovery source filter lets you narrow the evidence to a collection source. Cropped from an authenticated QA workspace.', 1130, 205)],
    5: [platformScreen('asset-inventory', 'Asset Inventory & CBOM header with Report Studio, Run scan, and Refresh', 'Open Report Studio from the Asset Inventory & CBOM header when preparing a scoped report. Cropped from an authenticated QA workspace.', 1100, 155)],
  },
  'messaging-setup': {
    2: [platformScreen('messaging-onboarding', 'Android introductory screen with Skip and a next arrow', 'The Android introduction offers Skip and a next arrow. Captured from the app’s product preview.', 450, 976), ...visuals['messaging-setup']],
    5: [...visuals.messaging, ...visuals['secure-chat']],
  },
  'quantum-vault-messaging': {
    1: [platformScreen('messaging-vault-lock', 'Locked Quantum Vault showing Password, PIN, and Pattern unlock tabs', 'The captured Android build offers Password, PIN, and Pattern. Available methods can vary by build and cryptographic mode. Product preview.', 450, 976)],
    2: visuals['quantum-vault-messaging'],
  },
  'messaging-offline-walkthrough': {
    1: visuals['offgrid-mesh'],
    3: [platformScreen('messaging-mesh-chat', 'Mesh conversation showing the message field, send button, and Delivered receipts', 'Use the message field and check the Delivered receipt. The conversation shown is example data from the Android product preview.', 450, 712)],
    5: visuals.xfer,
  },
}
