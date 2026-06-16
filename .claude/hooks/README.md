# Layer 3 — Hooks / Guardrail Layer

## Purpose

This layer provides deterministic project safety controls for Claude Code and agent-based development.

Hooks are used to enforce rules before and after tool execution.

## Files

| File | Purpose |
|---|---|
| `PreToolUse.sh` | Blocks unsafe commands before execution |
| `PostToolUse.sh` | Runs lint, typecheck, and secret checks after edits |
| `SessionStart.sh` | Loads safety context at the start of each session |

## Core Rules

- Block destructive shell commands
- Prevent accidental secret exposure
- Validate code after edits
- Enforce safe development workflow
- Keep QGuard Helix telemetry accurate
- Prevent fake production data
- Protect backend wiring, APIs, SSE, hooks, and Supabase logic

## Required Permissions

Make hooks executable:

```bash
chmod +x .claude/hooks/PreToolUse.sh
chmod +x .claude/hooks/PostToolUse.sh
chmod +x .claude/hooks/SessionStart.sh