export type DocVisual = { src: string; alt: string; caption: string; width: number; height: number }

// Sign-in screens come from the Messaging release branding captures. The
// other images come from the Play Store capture harness, which renders the
// app's React screens with predefined data and a simulated native bridge.
export const visuals: Record<string, DocVisual[]> = {
  messaging: [
    { src: '/docs-media/messaging-dashboard-shortcuts.webp', width: 450, height: 263, alt: 'Android Dashboard shortcuts for Secure Chat and Calls above the Home, Chats, Vault, Security, and Settings tabs', caption: 'Android Dashboard shortcuts. Cropped product preview with example data.' },
  ],
  'messaging-setup': [
    { src: '/docs-media/messaging-windows-login.webp', width: 1120, height: 788, alt: 'Windows sign-in with email and password, registration, and Link with QR code', caption: 'Windows sign-in screen from the Messaging release branding review.' },
    { src: '/docs-media/messaging-android-login.webp', width: 360, height: 800, alt: 'Android sign-in showing Email, Mobile number, Sign in securely, and Link with QR code', caption: 'Android sign-in screen from the Messaging release branding review.' },
  ],
  'secure-chat': [
    { src: '/docs-media/messaging-secure-chat.webp', width: 450, height: 976, alt: 'Android Secure Chat conversation showing the call buttons, attachment, message status, and composer', caption: 'Android Secure Chat product preview with example data. The contact label and selected example text are obscured.' },
  ],
  'messaging-calls': [
    { src: '/docs-media/messaging-call.webp', width: 450, height: 976, alt: 'In-call verification panel with the safety number obscured and a button to continue after comparing', caption: 'Android call verification product preview with example data. The verification text and number are obscured.' },
  ],
  'quantum-vault-messaging': [
    { src: '/docs-media/messaging-vault.webp', width: 450, height: 976, alt: 'Quantum Vault with Vault Storage and Encrypt & Decrypt Tools tabs and library folders', caption: 'Android Quantum Vault Storage product preview with example data.' },
  ],
  'hidden-vault': [
    { src: '/docs-media/messaging-hidden-vault.webp', width: 450, height: 976, alt: 'An open Hidden Vault with Lock, Add files, New folder, and Recovery phrase controls', caption: 'Android Hidden Vault product preview. Example file details are obscured.' },
  ],
  'offgrid-mesh': [
    { src: '/docs-media/messaging-mesh.webp', width: 450, height: 976, alt: 'Qguard Mesh discovery radar with nearby device icons and discovery controls', caption: 'Android Mesh radar product preview. Example device names are obscured.' },
  ],
  xfer: [
    { src: '/docs-media/messaging-xfer.webp', width: 450, height: 976, alt: 'Qguard XFER transfer dashboard with sender and receiver, progress, Pause, and Stop', caption: 'Android XFER product preview. The progress is an example and identity and file details are obscured.' },
  ],
}
