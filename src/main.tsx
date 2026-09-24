// MUST stay the first import: captures a password-recovery landing before the
// Supabase client (created while App's imports evaluate) strips the URL hash.
import './lib/password-recovery-capture';
import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
