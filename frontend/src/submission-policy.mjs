// Safe submission default; restoring live diagnostics requires explicit flags
// in both the frontend build and the backend runtime.
export const diagnosticsPaused = import.meta.env.VITE_SECURITY_DIAGNOSTICS_PAUSED !== 'false'
