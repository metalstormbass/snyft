#!/bin/bash
# Check for uncommitted changes and remind to commit

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check for uncommitted changes
if [[ -n $(git status --porcelain) ]]; then
    echo -e "${YELLOW}⚠ You have uncommitted changes:${NC}"
    git status --short
    echo ""
    echo -e "Run ${GREEN}./scripts/auto-commit.sh${NC} to commit and push"
    echo -e "Or commit manually with a descriptive message"
    exit 1
else
    echo -e "${GREEN}✓ Working directory clean${NC}"
fi

# Check if local is ahead of remote
BRANCH=$(git branch --show-current)
LOCAL=$(git rev-parse @)
REMOTE=$(git rev-parse @{u} 2>/dev/null || echo "")

if [[ -z "$REMOTE" ]]; then
    echo -e "${YELLOW}⚠ No upstream branch set${NC}"
    echo -e "Run: ${GREEN}git push -u origin $BRANCH${NC}"
    exit 1
elif [[ "$LOCAL" != "$REMOTE" ]]; then
    AHEAD=$(git rev-list --count @{u}..@ 2>/dev/null || echo "0")
    if [[ "$AHEAD" -gt 0 ]]; then
        echo -e "${YELLOW}⚠ You have $AHEAD unpushed commit(s)${NC}"
        echo -e "Run: ${GREEN}git push${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ All changes committed and pushed${NC}"
