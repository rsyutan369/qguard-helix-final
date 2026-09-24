// Side-effect module, imported FIRST by src/main.tsx: records a recovery-link
// landing before the Supabase client (created while App's imports evaluate)
// can consume and strip the URL hash. See ./password-recovery.ts.
import { capturePasswordRecoveryRedirect } from './password-recovery'

capturePasswordRecoveryRedirect()
