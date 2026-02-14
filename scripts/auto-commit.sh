#!/bin/bash
# Auto-commit and push script for regular work backups

set -e

# Configuration
COMMIT_PREFIX="[WIP]"
BRANCH=$(git branch --show-current)

# Check if there are changes to commit
if [[ -z $(git status --porcelain) ]]; then
    echo "✓ No changes to commit"
    exit 0
fi

# Show what will be committed
echo "Changes to be committed:"
git status --short

# Create commit message with timestamp
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
COMMIT_MSG="${COMMIT_PREFIX} Auto-commit at ${TIMESTAMP}"

# Add all changes
git add -A

# Commit
git commit -m "$COMMIT_MSG"

echo "✓ Committed: $COMMIT_MSG"

# Push to remote
if git push origin "$BRANCH" 2>/dev/null; then
    echo "✓ Pushed to origin/$BRANCH"
else
    echo "⚠ Push failed - you may need to set upstream:"
    echo "  git push -u origin $BRANCH"
    exit 1
fi

echo "✓ Auto-commit complete"
