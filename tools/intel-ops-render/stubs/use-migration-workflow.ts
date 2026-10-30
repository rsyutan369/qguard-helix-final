// Render stand-in for src/hooks/use-migration-workflow.ts: returns
// `__HOOK_FIXTURES__.workflow` (a MigrationWorkflowState) when a case provides
// one; otherwise the hook's real initial state (loading, no workflow), which is
// what the WorkflowRail renders as nothing.
export type WorkflowLoadState = 'loading' | 'success' | 'error'

export function useMigrationWorkflow() {
  const fixtures = ((globalThis as Record<string, unknown>).__HOOK_FIXTURES__ || {}) as Record<string, unknown>
  const workflow = (fixtures.workflow ?? null) as never
  return { workflow, state: workflow ? ('success' as const) : ('loading' as const), refresh: async () => undefined }
}
