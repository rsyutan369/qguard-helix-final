// Website edition entry (`npm run build:public`). vite.config.ts points
// index.html here instead of src/main.tsx when building in `public` mode.
//
// Before PublicApp: routes relative /api/ calls (the public scanner and the
// demo form) to VITE_API_ORIGIN — the static host has no API of its own.
import './lib/api-origin';
import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import PublicApp from './PublicApp.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <PublicApp />
  </StrictMode>,
);
