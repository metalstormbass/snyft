# Contributing Guidelines

## Commit and Push Workflow

To ensure work is never lost and progress is visible, follow these guidelines:

### Regular Commits

**Commit frequently** - aim to commit after each logical unit of work:
- After implementing a function
- After fixing a bug
- After writing tests
- At least every 30-60 minutes of active work

### Automated Tools

We provide scripts to help with regular commits:

#### Auto-commit Script
```bash
./scripts/auto-commit.sh
```
This will:
- Add all changes
- Create a timestamped WIP commit
- Push to your current branch

#### Commit Check Script
```bash
./scripts/commit-check.sh
```
This will:
- Check for uncommitted changes
- Check for unpushed commits
- Remind you to commit/push if needed

### Manual Workflow

If you prefer manual commits:

```bash
# Check status
git status

# Add specific files
git add <files>
# Or add all
git add -A

# Commit with descriptive message
git commit -m "feat: description of changes"

# Push to remote
git push
```

### Commit Message Format

For WIP commits, use `[WIP]` prefix:
```
[WIP] Working on authentication feature
```

For final commits before PR, use conventional commits:
```
feat: add user authentication
fix: resolve login timeout issue
docs: update README with setup instructions
```

### Best Practices

1. **Commit often** - small commits are better than large ones
2. **Push regularly** - don't let commits pile up locally
3. **Use descriptive messages** - future you will thank you
4. **Don't commit secrets** - use `.gitignore` for sensitive files

### Setting Up Auto-commit Hook

To automatically run commit checks, set up a git hook:

```bash
# Make scripts executable
chmod +x scripts/auto-commit.sh
chmod +x scripts/commit-check.sh

# Optional: Create a pre-push hook
cat > .git/hooks/pre-push << 'EOF'
#!/bin/bash
./scripts/commit-check.sh
EOF
chmod +x .git/hooks/pre-push
```

### For Multiclaude Workers

As a worker agent:
1. Commit after each significant change
2. Push before signaling completion
3. Always create a PR with detailed summary
4. Run `multiclaude agent complete` when done
