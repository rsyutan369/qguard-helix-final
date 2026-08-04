/**
 * Public Quantum Exposure Assessment™ — design atoms.
 *
 * The implementation now lives in `@/components/quantum-scan/ui` so the
 * authenticated Dashboard Scanner can render in the exact same design language
 * instead of maintaining a second copy of these tokens. This module stays as
 * the page-local entry point the rest of /public-scan already imports from.
 */
export * from '@/components/quantum-scan/ui';
