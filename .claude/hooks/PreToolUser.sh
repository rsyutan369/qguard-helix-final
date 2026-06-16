#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# QGuard Helix Agent Dev Kit
# Layer 3: PreToolUse Hook
# Purpose: Block dangerous commands before tool execution
# ============================================================

COMMAND="${1:-}"

echo "[PreToolUse] Validating command..."

# Block destructive commands
BLOCKED_PATTERNS=(
  "rm -rf /"
  "rm -rf /*"
  "sudo rm -rf"
  "mkfs"
  "dd if="
  ":(){ :|:& };:"
  "chmod -R 777"
  "chown -R"
  "git push --force"
  "git reset --hard"
  "git clean -fdx"
)

for pattern in "${BLOCKED_PATTERNS[@]}"; do
  if [[ "$COMMAND" == *"$pattern"* ]]; then
    echo "[BLOCKED] Dangerous command detected: $pattern"
    exit 1
  fi
done

# Block direct production env edits
if [[ "$COMMAND" == *".env.production"* ]]; then
  echo "[BLOCKED] Direct modification of .env.production is not allowed."
  exit 1
fi

# Block secret exposure
if [[ "$COMMAND" == *"cat .env"* ]] || [[ "$COMMAND" == *"printenv"* ]]; then
  echo "[BLOCKED] Potential secret exposure detected."
  exit 1
fi

echo "[PreToolUse] Passed."
exit 0