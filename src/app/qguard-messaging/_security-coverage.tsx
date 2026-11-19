import { GlassCard, MESSAGING_INSTALLER } from './_shared';

const WORKFLOWS = [
  ['chat', 'Direct messages, small groups and attachments', 'X25519 + ML-KEM-1024 establishes envelope keys. Ed25519 + ML-DSA-65 authenticates envelopes; AES-256-GCM encrypts content.', 'Small groups seal separately to each member’s devices. The optional session ratchet uses per-message keys and periodic ML-KEM refreshes.'],
  ['chat', 'Channels and large groups', 'AES-256-GCM encrypts posts with a shared epoch key. Devices receive that key through hybrid envelopes.', 'Key rotation is per epoch. In large groups, an owner or admin device must distribute the new epoch key.'],
  ['chat', 'Voice, video and desktop screen sharing', 'Each peer link establishes fresh hybrid X25519 + ML-KEM-1024 key material. Encoded media frames use AES-256-GCM.', 'Calls require a supported media transform. The four-word phrase is an additional check for previously verified devices on 1:1 calls.'],
  ['vault', 'Messaging Quantum Vault', 'Standard .qvault v5 files use AES-256-GCM per file and Ed25519 + ML-DSA-87 signed headers.', 'Local access wraps the file key with the vault master key. Portable recipient sealing and enterprise recovery use hybrid X25519 + ML-KEM-1024. In-app shares use separate recipient device envelopes.'],
  ['vault', 'Hidden Vault', 'A separate local format uses AES-256-GCM, Argon2id and HKDF-SHA3-256. Unlocking with a pattern also uses a key from the device’s secure store.', 'An optional 12-word phrase resets the pattern only while the local vault files still exist. Hidden vaults have no cloud backup or sharing.'],
  ['local', 'Offgrid Mesh and XFER', 'Local sessions use X25519 + ML-KEM-768, Ed25519 + ML-DSA-65 for peer authentication, HKDF-SHA3-256 and AES-256-GCM.', 'Pair compatible devices first. Mesh relay hops carry a separate envelope sealed for the intended recipient. XFER verifies SHA3-256 file digests; file data uses a local IP link.'],
  ['helix', 'QGuard Helix', 'The Collector can import algorithms published by your active Messaging devices. Helix’s separate web Vault uses hybrid X25519 + ML-KEM-1024, AES-256-GCM and Ed25519 + ML-DSA-65 for new QGV1 files.', 'Device configuration is inventory evidence. It does not verify individual messages, calls, files or transfers, or unlock a Messaging vault.'],
] as const;

export function SecurityCoverage({ area }: { area?: 'chat' | 'vault' }) {
  const workflows = area ? WORKFLOWS.filter(([group]) => group === area || group === 'local' || group === 'helix') : WORKFLOWS;
  return (
    <GlassCard className="overflow-hidden" hover={false}>
      <dl className="divide-y divide-slate-200">
        {workflows.map(([, title, protection, scope]) => (
          <div key={title} className="grid gap-2 px-5 py-4 sm:grid-cols-[minmax(10rem,1fr)_3fr] sm:gap-5 sm:px-6">
            <dt className="text-sm font-bold text-slate-900">{title}</dt>
            <dd className="space-y-1 text-sm leading-relaxed text-slate-700">
              <p>{protection}</p>
              <p className="text-slate-600">{scope}</p>
            </dd>
          </div>
        ))}
      </dl>
      <p className="border-t border-slate-200 bg-slate-50 px-5 py-4 text-sm leading-relaxed text-slate-700 sm:px-6">
        ML-KEM (FIPS 203) establishes keys; ML-DSA (FIPS 204) signs data. SLH-DSA (FIPS 205) is tracked in Helix and exercised in its simulation lab; Messaging does not use it in these workflows. SHA-256 and SHA3-256 are different hashes. SHA-256 is used for compatibility checks, the Hidden Vault phrase checksum and Windows download verification. Use of these algorithms does not establish FIPS 140-3 module validation or independent protocol review.
      </p>
    </GlassCard>
  );
}

export function MessagingBuildScope() {
  return (
    <p className="mt-4 max-w-xl text-sm leading-relaxed text-slate-600">
      For compatible Android and Windows builds. The features below reflect the 1.5.3 source reviewed for this page. The Windows download here is v{MESSAGING_INSTALLER.version}; feature availability depends on the installed build and platform.
    </p>
  );
}
