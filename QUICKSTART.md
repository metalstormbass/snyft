# Snyft Quick Start Guide

## Installation

```bash
git clone https://github.com/metalstormbass/snyft.git
cd snyft
make build
./snyft --help
```

## Basic Usage

```bash
# Scan current directory
./snyft scan

# Scan a specific directory
./snyft scan /path/to/project

# Try the included examples
./snyft scan examples/nodejs-example
./snyft scan examples/python-example
./snyft scan examples/java-example
```

## Understanding the Output

Risk levels:
- 🔴 **HIGH**: Critical issues (no source code, archived repo, suspicious reactivation)
- 🟡 **MEDIUM**: Concerning signals (inactive development, no CI, low engagement)
- 🟢 **LOW**: Minimal risk detected

## Improving Analysis Quality

```bash
# Set a GitHub token for higher rate limits
export GITHUB_TOKEN="your_github_token_here"

# Adjust concurrency
./snyft scan --workers 20  # faster
./snyft scan --workers 5   # fewer API requests
```

## Common Use Cases

### CI/CD Integration

```yaml
# .github/workflows/supply-chain-check.yml
jobs:
  snyft:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - run: go install github.com/metalstormbass/snyft@latest
      - run: snyft scan
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
if git diff --cached --name-only | grep -E '(package\.json|requirements\.txt|pom\.xml)'; then
  snyft scan
fi
```

## Troubleshooting

- **Rate limits**: Set `GITHUB_TOKEN` or reduce `--workers`
- **Package not found**: Verify package name and manifest formatting
- **Slow scans**: Increase `--workers` if not rate-limited

See [README.md](README.md) for full documentation.
