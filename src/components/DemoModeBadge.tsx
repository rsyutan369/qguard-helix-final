'use client';

/**
 * Persistent marker that the current session is the demo/test identity.
 *
 * Demo mode grants Elite access with no Supabase, no billing row and no real
 * tenant behind it. Anything shown while it is active is therefore NOT a
 * customer's posture, and a screenshot taken from it must never be mistaken for
 * one — so the state is visible on every page rather than only at sign-in.
 *
 * It is also the removal reminder: while this badge is on screen, the temporary
 * account described in `tasks/demo-account.md` is still installed.
 *
 * Renders nothing at all when the signed-in user is not the demo account.
 */

import React from 'react';
import { useAuth } from '@/contexts/auth-context';
import { isDemoEmail, isDemoModeEnabled } from '@/lib/demo-account';

export default function DemoModeBadge() {
  const { user } = useAuth();
  if (!isDemoModeEnabled() || !isDemoEmail(user?.email)) return null;

  return (
    <div
      role="status"
      aria-label="Demo session active"
      style={{
        position: 'fixed',
        left: 12,
        bottom: 12,
        zIndex: 2147483000,
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '6px 10px',
        borderRadius: 999,
        border: '1px solid rgba(234,179,8,0.55)',
        background: 'rgba(24,20,4,0.92)',
        color: '#fde68a',
        font: '700 10px/1 ui-monospace, SFMono-Regular, Menlo, monospace',
        letterSpacing: '0.14em',
        textTransform: 'uppercase',
        boxShadow: '0 6px 20px rgba(0,0,0,0.45)',
        pointerEvents: 'none',
        userSelect: 'none',
      }}
    >
      <span
        style={{
          width: 7,
          height: 7,
          borderRadius: '50%',
          background: '#facc15',
          boxShadow: '0 0 8px rgba(250,204,21,0.9)',
        }}
      />
      Demo session · not real tenant data
    </div>
  );
}
