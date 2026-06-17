'use client'

import { useState } from 'react'
import { createSharedLink } from '@/lib/vault/vault-service-enhanced'

interface ShareLinkModalProps {
  fileId: string
  fileName: string
  fileMimeType?: string
  isOpen: boolean
  onClose: () => void
  onShareCreated: () => void
  authHeaders: Record<string, string>
  /** Pre-decrypted plaintext bytes for the file to share */
  getFileData: () => Promise<Uint8Array>
}

type ExpirationOption = {
  label: string
  seconds: number | null
}

const EXPIRATION_OPTIONS: ExpirationOption[] = [
  { label: '15 minutes', seconds: 900 },
  { label: '1 hour', seconds: 3600 },
  { label: '24 hours', seconds: 86400 },
  { label: '7 days', seconds: 604800 },
]

const MAX_DOWNLOAD_OPTIONS = [
  { label: '1 download (one-time)', value: 1 },
  { label: '3 downloads', value: 3 },
  { label: '5 downloads', value: 5 },
  { label: '10 downloads', value: 10 },
]

const MIN_SHARE_PASSWORD_LENGTH = 12

function inferMimeType(fileName: string): string {
  const extension = fileName.split('.').pop()?.toLowerCase()
  const mimeByExtension: Record<string, string> = {
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    gif: 'image/gif',
    webp: 'image/webp',
    svg: 'image/svg+xml',
    pdf: 'application/pdf',
    txt: 'text/plain',
    json: 'application/json',
    csv: 'text/csv',
    zip: 'application/zip',
  }
  return extension ? mimeByExtension[extension] || 'application/octet-stream' : 'application/octet-stream'
}

function isSharePasswordStrong(value: string): boolean {
  if (value.length < MIN_SHARE_PASSWORD_LENGTH) return false
  const classes = [
    /[a-z]/.test(value),
    /[A-Z]/.test(value),
    /\d/.test(value),
    /[^A-Za-z0-9]/.test(value),
  ].filter(Boolean).length
  return classes >= 3
}

export default function ShareLinkModal({
  fileId,
  fileName,
  fileMimeType,
  isOpen,
  onClose,
  onShareCreated,
  authHeaders,
  getFileData,
}: ShareLinkModalProps) {
  const [step, setStep] = useState<'configure' | 'encrypting' | 'creating' | 'done' | 'error'>('configure')
  const [shareLink, setShareLink] = useState('')
  const [copied, setCopied] = useState(false)
  const [errorMsg, setErrorMsg] = useState('')

  // Options
  const [expiresIn, setExpiresIn] = useState<number | null>(900) // secure default: 15 minutes
  const [maxDownloads, setMaxDownloads] = useState<number | null>(1) // secure default: one-time
  // Sensitive shares default to recipient-bound: the file key is wrapped to the
  // recipient's ML-KEM-1024 public key, so an intercepted link cannot decrypt it.
  const [shareMode, setShareMode] = useState<'recipient' | 'password' | 'link'>('recipient')
  const [password, setPassword] = useState('')
  const [recipientPublicKey, setRecipientPublicKey] = useState('')
  const usePassword = shareMode === 'password'
  const useRecipientBinding = shareMode === 'recipient'

  if (!isOpen) return null

  const handleCreate = async () => {
    setErrorMsg('')
    const isRecipientBound = useRecipientBinding && recipientPublicKey.trim().length > 0
    const isPasswordProtected = usePassword && password.length > 0 && !isRecipientBound

    if (usePassword && !isSharePasswordStrong(password)) {
      setErrorMsg(`Use at least ${MIN_SHARE_PASSWORD_LENGTH} characters with 3 character types for password-protected shares.`)
      return
    }

    if (useRecipientBinding && !recipientPublicKey.trim()) {
      setErrorMsg('Paste the recipient public key bundle before creating a recipient-bound share.')
      return
    }

    setStep('encrypting')
    let fileData: Uint8Array | null = null

    try {
      // 1. Get plaintext file data
      fileData = await getFileData()

      // 2. Encrypt client-side for sharing (dynamic import to keep bundle lean)
      let result: {
        encryptedPayload: string
        iv: string
        integrityHash: string
        shareKey?: string
        passwordSalt?: string
        passwordHash?: string
        passwordKdf?: Record<string, unknown>
        recipientWrap?: Record<string, unknown>
      }

      // The real filename + MIME are sealed inside the encrypted payload (the
      // "token"), so the server stores only a placeholder. The recipient recovers
      // the name on decrypt with the fragment / password / recipient key.
      const shareMeta = { filename: fileName, mime: fileMimeType || inferMimeType(fileName) }

      if (isRecipientBound) {
        const { encryptForRecipientSharing } = await import('@/lib/vault/sharing-crypto')
        result = await encryptForRecipientSharing(fileData, recipientPublicKey, shareMeta)
      } else if (isPasswordProtected) {
        const { encryptForSharingWithPassword } = await import('@/lib/vault/sharing-crypto')
        result = await encryptForSharingWithPassword(fileData, password, shareMeta)
      } else {
        const { encryptForSharing } = await import('@/lib/vault/sharing-crypto')
        result = await encryptForSharing(fileData, shareMeta)
      }

      // 3. Create the share record (key NEVER leaves browser). Name + MIME are
      //    placeholders here — the real values live encrypted in the payload.
      const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000).toISOString() : undefined

      setStep('creating')
      const created = await createSharedLink({
        fileId,
        originalFilename: 'Encrypted share',
        originalSize: fileData.length,
        mimeType: 'application/octet-stream',
        encryptionMetadata: {
          iv: result.iv,
          integrityHash: result.integrityHash,
          encryptedPayload: result.encryptedPayload,
          passwordSalt: result.passwordSalt,
          passwordKdf: result.passwordKdf,
          recipientWrap: result.recipientWrap,
          sharingMode: isRecipientBound ? 'recipient-bound-public-key' : isPasswordProtected ? 'password-hardened' : 'url-fragment-key',
        },
        isPasswordProtected,
        passwordHash: result.passwordHash,
        maxDownloads: maxDownloads ?? 1,
        expiresAt,
        isOneTime: (maxDownloads ?? 1) === 1,
      })

      // 4. Build the share link. Password-protected and recipient-bound links
      // do not carry a decryption key in the URL fragment.
      const origin = window.location.origin
      if (!isPasswordProtected && !isRecipientBound && !result.shareKey) {
        throw new Error('Share key generation failed. Please try again.')
      }
      const link = isPasswordProtected || isRecipientBound
        ? `${origin}/vault/shared/${created.id}`
        : `${origin}/vault/shared/${created.id}#${result.shareKey}`

      setShareLink(link)
      setStep('done')
      onShareCreated()
    } catch (err) {
      console.error('Share creation failed:', err)
      setErrorMsg((err as Error).message || 'Failed to create share link')
      setStep('error')
    } finally {
      fileData?.fill(0)
    }
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(shareLink)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback
      const input = document.createElement('input')
      input.value = shareLink
      document.body.appendChild(input)
      input.select()
      document.execCommand('copy')
      document.body.removeChild(input)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const handleClose = () => {
    setStep('configure')
    setShareLink('')
    setCopied(false)
    setErrorMsg('')
    setPassword('')
    setShareMode('recipient')
    setRecipientPublicKey('')
    onClose()
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(0, 0, 0, 0.7)', backdropFilter: 'blur(4px)',
    }} onClick={(e) => { if (e.target === e.currentTarget) handleClose() }}>
      <div className="glass-panel" style={{ borderRadius: "var(--radius-lg, 12px)", padding: 28, maxWidth: 560, width: "90%", maxHeight: '90vh', overflowY: 'auto' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h3 style={{ fontSize: 16, margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
            🔗 Secure Share
          </h3>
          <button onClick={handleClose} className="q-btn q-btn-ghost"
            style={{ padding: '4px 8px', fontSize: 14, lineHeight: 1 }}>✕</button>
        </div>

        {/* File info */}
        <div style={{
          padding: '10px 14px', borderRadius: 'var(--radius-md, 8px)',
          background: 'rgba(212, 175, 55, 0.05)', border: '1px solid var(--qg-border, #1e293b)',
          marginBottom: 20, fontSize: 13,
        }}>
          <span style={{ color: 'var(--qg-text-muted)' }}>File: </span>
          <span style={{ fontWeight: 600 }}>{fileName}</span>
        </div>

        {/* ── Configure Step ─────────────────────────── */}
        {step === 'configure' && (
          <div>
            {/* Zero-knowledge notice */}
            <div style={{
              padding: '10px 14px', borderRadius: 'var(--radius-md, 8px)',
              background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.2)',
              marginBottom: 20, fontSize: 12, color: 'var(--qg-green, #10b981)',
            }}>
              {useRecipientBinding
                ? 'Recipient-bound sharing: the file key is wrapped to the recipient public JSON and never appears in the URL. The recipient must unlock it with their private .qgkey bundle.'
                : usePassword
                ? 'Password-protected sharing: the file is encrypted in your browser with AES-256-GCM using a key derived from the password. The generated link will not contain the file decryption key.'
                : 'Zero-knowledge link sharing: the file is encrypted in your browser with AES-256-GCM. The decryption key is placed in the URL fragment (#) and is never sent to the server.'}
            </div>

            {/* Expiration */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6, color: 'var(--qg-text-muted)' }}>
                Link Expiration
              </label>
              <select
                value={expiresIn ?? ''}
                onChange={(e) => setExpiresIn(e.target.value === '' ? null : Number(e.target.value))}
                style={{
                  width: '100%', padding: '8px 12px', fontSize: 13,
                  background: 'var(--qg-bg, #010409)', color: 'var(--qg-text, #e6edf3)',
                  border: '1px solid var(--qg-border, #1e293b)', borderRadius: 'var(--radius-md, 8px)',
                }}
              >
                {EXPIRATION_OPTIONS.map((opt) => (
                  <option key={opt.label} value={opt.seconds ?? ''}>{opt.label}</option>
                ))}
              </select>
            </div>

            {/* Max Downloads */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6, color: 'var(--qg-text-muted)' }}>
                Download Limit
              </label>
              <select
                value={maxDownloads ?? ''}
                onChange={(e) => setMaxDownloads(e.target.value === '' ? null : Number(e.target.value))}
                style={{
                  width: '100%', padding: '8px 12px', fontSize: 13,
                  background: 'var(--qg-bg, #010409)', color: 'var(--qg-text, #e6edf3)',
                  border: '1px solid var(--qg-border, #1e293b)', borderRadius: 'var(--radius-md, 8px)',
                }}
              >
                {MAX_DOWNLOAD_OPTIONS.map((opt) => (
                  <option key={opt.label} value={opt.value ?? ''}>{opt.label}</option>
                ))}
              </select>
            </div>

            {/* Security level — sensitive shares default to recipient-bound */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 8, color: 'var(--qg-text-muted)' }}>
                Security Level
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {([
                  { mode: 'recipient', icon: '🛡️', title: 'Recipient-bound', tag: 'Recommended', tagColor: 'green',
                    desc: 'Quantum-safe & interception-proof. The file key is wrapped to the recipient’s ML-KEM-1024 public key; the link carries no key.' },
                  { mode: 'password', icon: '🔑', title: 'Password-protected', tag: 'Strong', tagColor: 'green',
                    desc: 'Link + password (sent separately). Argon2id-hardened; the link carries no key.' },
                  { mode: 'link', icon: '🔗', title: 'Link only', tag: 'Convenience', tagColor: 'amber',
                    desc: 'Anyone with the full link can decrypt. Use only for non-sensitive files over trusted channels.' },
                ] as const).map((opt) => {
                  const active = shareMode === opt.mode
                  return (
                    <button
                      key={opt.mode}
                      type="button"
                      onClick={() => { setShareMode(opt.mode); setErrorMsg('') }}
                      style={{
                        textAlign: 'left', padding: '10px 12px', borderRadius: 'var(--radius-md, 8px)',
                        background: active ? 'rgba(0,212,255,0.07)' : 'var(--qg-bg, #010409)',
                        border: `1px solid ${active ? 'var(--qg-cyan, #22d3ee)' : 'var(--qg-border, #1e293b)'}`,
                        cursor: 'pointer', color: 'var(--qg-text, #e6edf3)', width: '100%',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                        <span>{opt.icon}</span>
                        <span style={{ fontSize: 13, fontWeight: 600 }}>{opt.title}</span>
                        <span style={{
                          fontSize: 9, padding: '1px 6px', borderRadius: 6, marginLeft: 'auto',
                          background: opt.tagColor === 'amber' ? 'rgba(245,158,11,0.15)' : 'rgba(16,185,129,0.15)',
                          color: opt.tagColor === 'amber' ? 'var(--qg-amber, #f59e0b)' : 'var(--qg-green, #10b981)',
                        }}>
                          {opt.tag}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--qg-text-muted)', lineHeight: 1.5 }}>{opt.desc}</div>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Link-only warning */}
            {shareMode === 'link' && (
              <div style={{
                marginBottom: 20, padding: '10px 14px', borderRadius: 'var(--radius-md, 8px)',
                background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)',
                fontSize: 12, color: 'var(--qg-amber, #f59e0b)', lineHeight: 1.5,
              }}>
                ⚠️ The decryption key is embedded in the link. Anyone who intercepts the full link can decrypt this file. For sensitive data, choose recipient-bound or password protection.
              </div>
            )}

            {/* Password input */}
            {shareMode === 'password' && (
              <div style={{ marginBottom: 20 }}>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); setErrorMsg('') }}
                  placeholder={`Enter at least ${MIN_SHARE_PASSWORD_LENGTH} characters`}
                  style={{
                    width: '100%', padding: '8px 12px', fontSize: 13,
                    background: 'var(--qg-bg, #010409)', color: 'var(--qg-text, #e6edf3)',
                    border: `1px solid ${password && !isSharePasswordStrong(password) ? 'rgba(245,158,11,0.55)' : 'var(--qg-border, #1e293b)'}`,
                    borderRadius: 'var(--radius-md, 8px)', boxSizing: 'border-box',
                  }}
                />
                <div style={{ marginTop: 6, fontSize: 11, color: 'var(--qg-text-muted)' }}>
                  Use at least {MIN_SHARE_PASSWORD_LENGTH} characters with 3 character types. Send the password to the recipient through a separate, trusted channel.
                </div>
              </div>
            )}

            {/* Recipient public key input */}
            {shareMode === 'recipient' && (
              <div style={{ marginBottom: 20 }}>
                <textarea
                  value={recipientPublicKey}
                  onChange={(e) => { setRecipientPublicKey(e.target.value); setErrorMsg('') }}
                  placeholder="Paste recipient public JSON or raw ML-KEM public key"
                  spellCheck={false}
                  style={{
                    width: '100%', minHeight: 92, resize: 'vertical', padding: '8px 12px', fontSize: 12,
                    background: 'var(--qg-bg, #010409)', color: 'var(--qg-text, #e6edf3)',
                    border: '1px solid var(--qg-border, #1e293b)',
                    borderRadius: 'var(--radius-md, 8px)', fontFamily: 'var(--font-mono)', boxSizing: 'border-box',
                  }}
                />
                <div style={{ marginTop: 6, fontSize: 11, color: 'var(--qg-text-muted)' }}>
                  Ask the recipient for their public recipient JSON. Never ask for their private .qgkey bundle.
                </div>
              </div>
            )}

            {errorMsg && (
              <div style={{
                padding: '8px 12px',
                borderRadius: 'var(--radius-md, 8px)',
                background: 'rgba(245,158,11,0.08)',
                border: '1px solid rgba(245,158,11,0.3)',
                color: 'var(--qg-amber, #f59e0b)',
                fontSize: 12,
                marginBottom: 14,
              }}>
                {errorMsg}
              </div>
            )}

            {/* Create button */}
            <button
              className="q-btn q-btn-primary"
              style={{ width: '100%', padding: '10px 20px', fontSize: 13 }}
              onClick={handleCreate}
              aria-disabled={(usePassword && !isSharePasswordStrong(password)) || (useRecipientBinding && !recipientPublicKey.trim())}
              title={usePassword && !isSharePasswordStrong(password)
                ? `Use at least ${MIN_SHARE_PASSWORD_LENGTH} characters with 3 character types.`
                : useRecipientBinding && !recipientPublicKey.trim()
                  ? 'Paste the recipient public key bundle first.'
                : 'Encrypt and generate secure share link'}
            >
              🔐 Encrypt & Generate Share Link
            </button>
          </div>
        )}

        {/* ── Encrypting Step ────────────────────────── */}
        {(step === 'encrypting' || step === 'creating') && (
          <div style={{ textAlign: 'center', padding: '30px 0' }}>
            <div style={{
              width: 48, height: 48, margin: '0 auto 16px',
              borderWidth: 3,
              borderStyle: 'solid',
              borderColor: 'var(--qg-border, #1e293b)',
              borderTopColor: 'var(--qg-cyan, #d4af37)',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite',
            }} />
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
              {step === 'encrypting' ? 'Encrypting file...' : 'Creating secure link...'}
            </div>
            <div style={{ fontSize: 12, color: 'var(--qg-text-muted)' }}>
              {step === 'encrypting'
                ? 'Client-side AES-256-GCM encryption in progress'
                : 'Registering the zero-knowledge share payload'}
            </div>
            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          </div>
        )}

        {/* ── Done Step ──────────────────────────────── */}
        {step === 'done' && (
          <div>
            <div style={{
              padding: '10px 14px', borderRadius: 'var(--radius-md, 8px)',
              background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.2)',
              marginBottom: 16, fontSize: 12, color: 'var(--qg-green, #10b981)',
            }}>
              {useRecipientBinding
                ? 'Recipient-bound share created. The link contains no decryption key; only the matching recipient private .qgkey bundle can unwrap the file key in the browser.'
                : usePassword
                ? 'Password-protected share created. The recipient needs this link and the password; the file decryption key is derived locally in their browser and is not embedded in the URL.'
                : 'Secure share link created. The decryption key is in the link fragment (#) and is never stored on or transmitted to our servers. Share this link only through trusted, secure channels.'}
            </div>

            {/* Share link display */}
            <div style={{
              padding: '10px 14px', borderRadius: 'var(--radius-md, 8px)',
              background: 'var(--qg-bg, #010409)', border: '1px solid var(--qg-border, #1e293b)',
              marginBottom: 16, wordBreak: 'break-all', fontSize: 12,
              fontFamily: 'var(--font-mono)', color: 'var(--qg-cyan, #d4af37)',
              maxHeight: 100, overflow: 'auto',
            }}>
              {shareLink}
            </div>

            {/* Copy button */}
            <button
              className="q-btn q-btn-primary"
              style={{ width: '100%', padding: '10px 20px', fontSize: 13, marginBottom: 12 }}
              onClick={handleCopy}
            >
              {copied ? '✅ Copied!' : '📋 Copy Link to Clipboard'}
            </button>

            {/* Security info */}
            <div style={{ fontSize: 11, color: 'var(--qg-text-muted)', lineHeight: 1.6 }}>
              <div>
                {expiresIn ? `Expires in ${EXPIRATION_OPTIONS.find(o => o.seconds === expiresIn)?.label}` : 'No expiration'}
                {maxDownloads ? ` · ${maxDownloads} download${maxDownloads === 1 ? '' : 's'} max` : ''}
                {usePassword ? ' · Password protected' : ''}
                {useRecipientBinding ? ' · Recipient-bound' : ''}
              </div>
              <div style={{ marginTop: 4, color: 'var(--qg-amber, #f59e0b)' }}>
                {useRecipientBinding
                  ? 'Only the matching recipient private key can unwrap this file key.'
                  : usePassword
                  ? 'Send the password separately. Anyone without the password cannot decrypt this file.'
                  : 'Anyone with the full link can decrypt the file. Share it securely.'}
              </div>
            </div>
          </div>
        )}

        {/* ── Error Step ─────────────────────────────── */}
        {step === 'error' && (
          <div>
            <div style={{
              padding: '12px 16px', borderRadius: 'var(--radius-md, 8px)',
              background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.3)',
              marginBottom: 16, fontSize: 13, color: 'var(--qg-red, #ef4444)',
            }}>
              {errorMsg || 'An unexpected error occurred'}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="q-btn q-btn-primary" style={{ flex: 1, padding: '8px 16px', fontSize: 12 }}
                onClick={() => setStep('configure')}>
                Try Again
              </button>
              <button className="q-btn q-btn-ghost" style={{ padding: '8px 16px', fontSize: 12 }}
                onClick={handleClose}>
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
