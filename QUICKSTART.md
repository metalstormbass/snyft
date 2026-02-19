# Snyft Quick Start Guide

<p align="center">
  <img src="assets/snyft.png" alt="Snyft Logo" width="400"/>
</p>

Snyft is a supply chain security analyzer that answers one question: **"What is the risk that this library gets compromised?"**

## Installation

```bash
# Using Go Install (Recommended)
go install github.com/metalstormbass/snyft@latest

# Or build from source (requires Go 1.24+)
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

## Understanding the Scoring System

Snyft uses a **22-point risk scoring system** across 11 categories. Each category scores 0-2 risk points (lower is better):

| Category | What It Assesses |
|----------|-----------------|
| **1. Publisher Control** | Account takeover risk (single maintainer, no 2FA/signing) |
| **2. Ownership Changes** | Malicious acquisition (recent maintainer changes) |
| **3. Release Anomalies** | Dormant reactivation (long dormancy then sudden release) |
| **4. Install Execution** | Direct compromise vectors (postinstall scripts, dangerous patterns) |
| **5. Dependency Sprawl** | Attack surface (transitive dependency count) |
| **6. Provenance** | Build integrity (source verification, SLSA/Sigstore attestations) |
| **7. Health** | Code review barriers (bus factor, review oversight) |
| **8. Governance** | Maintainer responsiveness (SECURITY.md, issue response times) |
| **9. Release Security** | Publishing pipeline integrity (branch protection, signed tags) |
| **10. Package Maturity** | Vetting and staleness (package age, update cadence) |
| **11. CI Pipeline Security** | Build environment risks (unpinned actions, script injection, dangerous triggers) |

### Risk Levels

| Total Score | Risk Level | Meaning |
|-------------|------------|---------|
| **0-9** | LOW | Minimal compromise risk detected |
| **10-13** | MEDIUM | Concerning signals warrant attention |
| **14+** | HIGH | Critical issues, high compromise likelihood |

## Output Formats

```bash
./snyft scan                              # Text output (default, colored tables)
./snyft scan --format json -o results.json  # JSON output to file
./snyft scan --format markdown -o REPORT.md # Markdown report
./snyft scan --format html -o report.html   # HTML report
```

## Improving Analysis Quality

```bash
# Set a GitHub token for higher rate limits (60 → 5,000 req/hour)
export GITHUB_TOKEN="your_github_token_here"

# Adjust concurrency
./snyft scan --workers 20  # faster
./snyft scan --workers 5   # fewer API requests

# Enable AI-powered analysis (requires Claude API key)
export CLAUDE_API_KEY="sk-ant-..."
./snyft scan --ai
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
