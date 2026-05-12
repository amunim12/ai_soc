#!/usr/bin/env bash
# Install all git hooks for this repository.
# Run once after cloning: bash deploy/hooks/install-hooks.sh

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_SRC="$REPO_ROOT/deploy/hooks"
HOOKS_DEST="$REPO_ROOT/.git/hooks"

echo "Installing git hooks from $HOOKS_SRC → $HOOKS_DEST"

for hook in "$HOOKS_SRC"/pre-commit; do
    name="$(basename "$hook")"
    cp "$hook" "$HOOKS_DEST/$name"
    chmod +x "$HOOKS_DEST/$name"
    echo "  ✓ $name"
done

echo "Done. Hooks will run automatically on every commit."
