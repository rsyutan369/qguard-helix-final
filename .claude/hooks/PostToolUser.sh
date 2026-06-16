#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# QGuard Helix Agent Dev Kit
# Layer 3: PostToolUse Hook
# Purpose: Run quality checks after write/edit commands
# ============================================================

echo "[PostToolUse] Running post-tool validation..."

# Run formatter if package.json exists
if [[ -f "package.json" ]]; then
  if npm run | grep -q "lint"; then
    echo "[PostToolUse] Running lint..."
    npm run lint || {
      echo "[FAILED] Lint check failed."
      exit 1
    }
  fi

  if npm run | grep -q "typecheck"; then
    echo "[PostToolUse] Running typecheck..."
    npm run typecheck || {
      echo "[FAILED] Typecheck failed."
      exit 1
    }
  fi
fi

# Secret scan basic check
echo "[PostToolUse] Checking for accidental secrets..."

if grep -RInE "(SUPABASE_SERVICE_ROLE|OPENAI_API_KEY|ANTHROPIC_API_KEY|PRIVATE_KEY|SECRET_KEY|JWT_SECRET)" \
  --exclude-dir=node_modules \
  --exclude-dir=.git \
  .; then
  echo "[FAILED] Possible secret detected in repository."
  exit 1
fi

echo "[PostToolUse] Passed."
exit 0