# Contributing

## Commit Workflow

Commit frequently (after each logical change, or every 30-60 min).

### Automated Scripts

```bash
./scripts/auto-commit.sh    # add, commit, push with timestamp
./scripts/commit-check.sh   # check for uncommitted/unpushed work
```

### Manual Workflow

```bash
git add <files>
git commit -m "feat: description"
git push
```

### Commit Messages

WIP commits: `[WIP] Working on feature`

Final commits: `feat: add feature` or `fix: resolve bug`

### For Multiclaude Workers

1. Commit after each significant change
2. Push before signaling completion
3. Create PR with detailed summary
4. Run `multiclaude agent complete`
