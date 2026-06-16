#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# QGuard Helix Agent Dev Kit
# Layer 3: SessionStart Hook
# Purpose: Initialize safety context before agent work begins
# ============================================================

echo "=============================================="
echo " QGuard Helix Agent Dev Kit — Guardrail Layer"
echo "=============================================="

echo "[SessionStart] Loading project rules..."

if [[ -f "CLAUDE.md" ]]; then
  echo "[OK] CLAUDE.md found."
else
  echo "[WARNING] CLAUDE.md missing."
fi

if [[ -d ".claude/skills" ]]; then
  echo "[OK] Skills directory found."
else
  echo "[WARNING] .claude/skills directory missing."
fi

if [[ -d ".claude/hooks" ]]; then
  echo "[OK] Hooks directory found."
else
  echo "[WARNING] .claude/hooks directory missing."
fi

echo ""
echo "Guardrail Rules:"
echo "- Do not modify backend wiring unless explicitly requested."
echo "- Do not create fake production telemetry."
echo "- Do not bypass Supabase RLS."
echo "- Do not expose secrets."
echo "- Do not run destructive shell commands."
echo "- Verify APIs, SSE, hooks, telemetry, and UI before completion."
echo ""

echo "[SessionStart] Ready."
exit 0