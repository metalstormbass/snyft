# Snyft

**Snyft** is a supply chain security analyzer that evaluates dependencies from Python, JavaScript, and Java projects to identify potential compromise risks.

## Overview

Snyft scans manifest files (package.json, requirements.txt, pom.xml, etc.) and performs comprehensive supply chain security analysis on each dependency by examining:

- **Source Code Availability**: Verifies if public source code exists
- **Repository Health**: Analyzes GitHub metrics (stars, forks, activity, maintainer info)
- **Build Infrastructure**: Detects CI/CD systems and automated release processes
- **Security Signals**: Identifies archived repos, inactive development, low community adoption
- **OSSF Scorecards**: Integrates OpenSSF security scorecards for additional insights

Unlike traditional vulnerability scanners focused on CVEs, Snyft assesses the **likelihood of compromise** by analyzing repository metadata, build practices, and supply chain signals.

## Features

- **Multi-Ecosystem Support**: Analyzes dependencies from:
  - **JavaScript/Node.js**: package.json, package-lock.json, yarn.lock
  - **Python**: requirements.txt, Pipfile, pyproject.toml, setup.py
  - **Java/Maven**: pom.xml, build.gradle

- **Parallel Analysis**: Uses goroutines to analyze multiple dependencies concurrently

- **External API Integration**:
  - GitHub API for repository metadata
  - npm registry for JavaScript packages
  - PyPI for Python packages
  - Maven Central for Java packages
  - OpenSSF Scorecard API for security scores

- **Risk Scoring**: Assigns risk levels (HIGH/MEDIUM/LOW) based on multiple factors

## Installation

### Prerequisites

- Go 1.21 or later
- Optional: GitHub token for higher API rate limits (set `GITHUB_TOKEN` environment variable)

### Build from source

```bash
git clone https://github.com/metalstormbass/snyft.git
cd snyft
go build -o snyft
```

## Usage

### Basic scan

Scan the current directory:

```bash
./snyft scan
```

Scan a specific directory:

```bash
./snyft scan /path/to/project
```

### Options

- `-w, --workers <N>`: Number of concurrent workers for analysis (default: 10)
- `-v, --verbose`: Enable verbose output with detailed findings
- `-o, --output <file>`: Write results to a file instead of stdout

### Example

```bash
# Scan a project with verbose output
./snyft scan --verbose ./my-project

# Use more workers for faster analysis
./snyft scan --workers 20 ./my-project

# Save results to a file
./snyft scan --output results.txt ./my-project
```

## Architecture

Snyft is organized into several packages:

- **cmd/**: CLI commands using Cobra framework
- **pkg/models/**: Data structures for dependencies and analysis results
- **pkg/parser/**: Manifest file parsers for each ecosystem
- **pkg/fetcher/**: API clients for external services (GitHub, npm, PyPI, Maven, OSSF)
- **pkg/analyzer/**: Core analysis engine that evaluates supply chain security

### Analysis Flow

1. **Discovery**: Scan directory for manifest files
2. **Parsing**: Extract dependencies and versions from each manifest
3. **Deduplication**: Remove duplicate dependencies across manifests
4. **Parallel Analysis**: Spawn worker goroutines to analyze dependencies concurrently
5. **Risk Calculation**: Score each dependency based on findings
6. **Reporting**: Output results with risk levels

## Risk Factors

Snyft identifies several supply chain risk factors:

### High Severity
- Package not found in registry
- No public source code repository
- Archived/unmaintained repository

### Medium Severity
- Inactive development (no commits in 365+ days)
- No CI/CD detected
- Low community engagement
- Low OSSF security score (<5.0)

### Low Severity
- No automated release process detected

## API Rate Limits

Some external APIs have rate limits:

- **GitHub API**: 60 requests/hour (unauthenticated), 5000 requests/hour (with token)
- **npm registry**: Generally no strict limits
- **PyPI**: No strict limits
- **OSSF Scorecard**: No strict limits

**Recommendation**: Set a `GITHUB_TOKEN` environment variable for higher GitHub API limits:

```bash
export GITHUB_TOKEN="your-github-token"
./snyft scan
```

## Example Output

```
🔍 Scanning directory: /Users/mike/Projects/myapp
📄 Found 1 manifest files
  Parsing: /Users/mike/Projects/myapp/package.json
📦 Found 45 dependencies across all manifests
🔬 Analyzing: express@4.18.0 (npm)
🔬 Analyzing: lodash@4.17.21 (npm)
...

================================================================================
📊 Supply Chain Security Analysis Results
================================================================================

Risk Summary:
  🔴 HIGH:   2
  🟡 MEDIUM: 15
  🟢 LOW:    28

🔴 vulnerable-package@1.0.0 (npm) - HIGH
🟡 some-package@2.1.0 (npm) - MEDIUM
🟢 express@4.18.0 (npm) - LOW
...
```

## Contributing

Contributions are welcome! Please open issues or submit pull requests.

## License

MIT License - see LICENSE file for details

## Security

This tool is for security research and assessment purposes. Always verify findings and use responsibly.

## Roadmap

Future enhancements:
- [ ] Support for more package ecosystems (Ruby, Rust, PHP, etc.)
- [ ] JSON/HTML output formats
- [ ] Historical tracking of dependency risk over time
- [ ] Integration with CI/CD pipelines
- [ ] Custom risk scoring profiles
- [ ] Malware detection via code analysis
- [ ] SBOM (Software Bill of Materials) generation
