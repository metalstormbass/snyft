# Snyft Quick Start Guide

Get started with Snyft in 5 minutes!

## Installation

### Option 1: Build from source

```bash
# Clone the repository
git clone https://github.com/metalstormbass/snyft.git
cd snyft

# Build the binary
go build -o snyft

# Verify it works
./snyft --help
```

### Option 2: Using Make

```bash
# Clone and build
git clone https://github.com/metalstormbass/snyft.git
cd snyft
make build

# Run
./snyft --help
```

## Basic Usage

### Scan a project

```bash
# Scan current directory
./snyft scan

# Scan a specific directory
./snyft scan /path/to/your/project

# Verbose output with detailed findings
./snyft scan --verbose
```

### Example: Analyzing the included examples

Try it on the example projects included in this repo:

```bash
# Analyze Node.js example
./snyft scan examples/nodejs-example

# Analyze Python example
./snyft scan examples/python-example

# Analyze Java example
./snyft scan examples/java-example
```

## Understanding the Output

Snyft provides:

1. **Risk Summary**: Count of dependencies at each risk level
2. **Detailed Results**: Each dependency with its risk level and findings

### Risk Levels

- 🔴 **HIGH**: Critical issues (package not found, no source code, archived repo)
- 🟡 **MEDIUM**: Concerning signals (inactive development, no CI, low engagement)
- 🟢 **LOW**: Minimal risk detected

### Example Output

```
🔍 Scanning directory: ./examples/nodejs-example
📄 Found 1 manifest files
  Parsing: ./examples/nodejs-example/package.json
📦 Found 6 dependencies across all manifests
🔬 Analyzing: express@4.18.0 (npm)
🔬 Analyzing: lodash@4.17.21 (npm)
...

================================================================================
📊 Supply Chain Security Analysis Results
================================================================================

Risk Summary:
  🔴 HIGH:   0
  🟡 MEDIUM: 2
  🟢 LOW:    4

🟢 express@4.18.0 (npm) - LOW
🟢 axios@1.6.0 (npm) - LOW
🟡 lodash@4.17.21 (npm) - MEDIUM
...
```

## Improving Analysis Quality

### Set a GitHub Token

For better rate limits and more comprehensive analysis:

```bash
# Create a GitHub personal access token (no special permissions needed)
# Then set it as an environment variable
export GITHUB_TOKEN="your_github_token_here"

# Now run Snyft
./snyft scan
```

### Adjust Parallelism

Control the number of concurrent API requests:

```bash
# Use 20 concurrent workers (default is 10)
./snyft scan --workers 20

# Use fewer workers if hitting rate limits
./snyft scan --workers 5
```

## What Snyft Analyzes

For each dependency, Snyft examines:

### Repository Signals
- ✅ Source code availability
- ✅ Repository activity (last commit date)
- ✅ Community engagement (stars, forks, watchers)
- ✅ Maintenance status (archived/active)

### Build Infrastructure
- ✅ CI/CD system detection (GitHub Actions, Travis, CircleCI, etc.)
- ✅ Automated release process
- ✅ Build automation

### Security Indicators
- ✅ OpenSSF Scorecard integration
- ✅ License information
- ✅ Maintainer information
- ✅ Package registry metadata

## Common Use Cases

### CI/CD Integration

Add Snyft to your CI pipeline:

```yaml
# .github/workflows/supply-chain-check.yml
name: Supply Chain Security Check

on: [push, pull_request]

jobs:
  snyft:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - name: Install Snyft
        run: |
          git clone https://github.com/metalstormbass/snyft.git
          cd snyft && go build -o /usr/local/bin/snyft
      - name: Run Snyft
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: snyft scan --verbose
```

### Regular Security Audits

Schedule regular scans:

```bash
#!/bin/bash
# scan-dependencies.sh

# Scan all your projects
for project in ~/projects/*; do
  echo "Scanning $project..."
  snyft scan "$project" >> ~/audit-$(date +%Y%m%d).log
done
```

### Pre-commit Hook

Check dependencies before committing:

```bash
#!/bin/bash
# .git/hooks/pre-commit

if git diff --cached --name-only | grep -E '(package\.json|requirements\.txt|pom\.xml)'; then
  echo "Dependencies changed, running Snyft..."
  snyft scan
fi
```

## Troubleshooting

### Rate Limiting

If you see rate limit errors:
- Set a `GITHUB_TOKEN` environment variable
- Reduce `--workers` count
- Add delays between scans

### Package Not Found

If packages aren't found:
- Verify the package name is correct
- Check if it's a private package
- Ensure manifest files are properly formatted

### Slow Analysis

To speed up analysis:
- Increase `--workers` count (if not rate-limited)
- Focus on specific directories
- Use faster internet connection

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Explore the [examples/](examples/) directory
- Check out the codebase in [pkg/](pkg/) to understand the analysis logic
- Contribute improvements via pull requests!

## Support

- 🐛 Report bugs: [GitHub Issues](https://github.com/metalstormbass/snyft/issues)
- 💡 Feature requests: [GitHub Discussions](https://github.com/metalstormbass/snyft/discussions)
- 📖 Documentation: [README.md](README.md)
