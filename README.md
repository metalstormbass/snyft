# Snyft

<p align="center">
  <img src="assets/snyft.png" alt="Snyft Logo" width="400"/>
</p>

**Snyft** is a supply chain security analyzer that evaluates dependencies from Python, JavaScript, and Java projects using a comprehensive 10-category scoring rubric to identify potential compromise risks.

## Overview

Unlike traditional vulnerability scanners focused on CVEs, Snyft assesses the **likelihood of supply chain compromise** by analyzing repository metadata, build practices, source code availability, and security signals. Each dependency is scored across 10 critical security categories, providing a **0-20 point risk assessment** (lower is better).

### Key Features

- **10-Category Risk Scoring**: Comprehensive supply chain security rubric (0-20 points)
- **Primary Source Verification**: Validates exact version source code availability before analysis
- **AI-Enhanced Analysis** (Optional): Claude AI-powered attack pattern detection and executive summaries
- **Executive Summaries**: Actionable key findings with specific package examples and evidence
- **Professional Reporting**: Multiple output formats (text, markdown, json, html)
- **Multi-Platform Support**: Works with GitHub, GitLab, Bitbucket, and self-hosted instances
- **Multi-Ecosystem Support**: JavaScript/Node.js, Python, Java/Maven
- **API Resilience**: Web scraping fallbacks when APIs are unavailable
- **Parallel Analysis**: Concurrent dependency scanning with progress indicators
- **Verbose Output**: Detailed findings enabled by default

## Installation

### Using Go Install (Recommended)

If you have Go 1.24 or later installed:

```bash
go install github.com/metalstormbass/snyft@latest
```

This will install the latest version of snyft to your `$GOPATH/bin` directory.

### Download Pre-built Binary

Download the latest release from the [releases page](https://github.com/metalstormbass/snyft/releases):

- **macOS**: `snyft_[version]_Darwin_x86_64.tar.gz` or `snyft_[version]_Darwin_arm64.tar.gz`
- **Linux**: `snyft_[version]_Linux_x86_64.tar.gz` or `snyft_[version]_Linux_arm64.tar.gz`

Extract and run:
```bash
tar -xzf snyft_*.tar.gz
./snyft version
```

### Build from Source

#### Prerequisites
- **Go 1.24 or later** (required for macOS compatibility)
- Optional: GitHub token for higher API rate limits (set `GITHUB_TOKEN` environment variable)
- Optional: GitLab token for GitLab repositories (set `GITLAB_TOKEN` environment variable)
- Optional: Bitbucket credentials for Bitbucket repositories (set `BITBUCKET_TOKEN` environment variable)
- Optional: Claude API key for AI-enhanced analysis (set `CLAUDE_API_KEY` environment variable)

#### Build Steps

```bash
git clone https://github.com/metalstormbass/snyft.git
cd snyft
make build
```

Or build manually:
```bash
CGO_ENABLED=0 go build -o snyft
```

**Note**: Go 1.24+ is required for macOS compatibility. Using `make build` ensures correct flags.

## Usage

### Basic Examples

```bash
# Scan current directory with default text output
./snyft scan

# Scan specific directory
./snyft scan /path/to/project

# Disable verbose output
./snyft scan --verbose=false

# Save results to file
./snyft scan --output report.txt
```

### Output Formats

```bash
# Professional text output with colors and tables (default)
./snyft scan --format text

# Markdown format for documentation
./snyft scan --format markdown --output SECURITY.md

# JSON format for CI/CD integration
./snyft scan --format json --output results.json

# HTML format for web reports
./snyft scan --format html --output report.html
```

### Advanced Options

```bash
# Increase concurrency for faster scans
./snyft scan --workers 20

# Enable AI-powered analysis (requires CLAUDE_API_KEY)
./snyft scan --ai

# AI analysis with custom API key
./snyft scan --ai --ai-api-key="sk-ant-..." --ai-timeout=90

# Combined example with AI
./snyft scan --format json --workers 15 --ai --output scan-results.json ./my-project
```

### Command Options

**Basic Options:**
- `-f, --format <type>`: Output format: `text` (default), `markdown`, `json`, `html`
- `-w, --workers <N>`: Number of concurrent workers (default: 10)
- `-v, --verbose`: Verbose output with detailed findings (default: `true`)
- `-o, --output <file>`: Write results to file instead of stdout

**AI Analysis Options:**
- `--ai`: Enable AI-powered analysis (requires API key)
- `--ai-api-key <key>`: Claude API key (alternative to `CLAUDE_API_KEY` env var)
- `--ai-timeout <seconds>`: Timeout for AI operations (default: 60)
- `--ai-disable-cache`: Disable AI response caching
- `--ai-disable-retry`: Disable retry on AI API failures

See [docs/AI_FEATURES.md](docs/AI_FEATURES.md) for detailed AI configuration.

## Supply Chain Scoring System

Snyft uses a **10-category rubric** where each category is scored 0-2 risk points:

| Category | Description | Risk Indicators |
|----------|-------------|-----------------|
| **1. Publisher Control** | Maintainer 2FA, signing, team structure, 8 critical checks | Single maintainer, no signing, no 2FA |
| **2. Ownership Changes** | Package transfer detection | Recent maintainer changes |
| **3. Release Anomalies** | Dormancy and sudden activity | Long gap → sudden release |
| **4. Install Execution** | Install-time script analysis | postinstall scripts, dangerous patterns |
| **5. Dependency Sprawl** | Transitive dependency count | Many transitive deps (50+) |
| **6. Provenance** | Build attestations and signatures | No SLSA/Sigstore/provenance |
| **7. Health** | Bus factor, CI quality, code review | Low bus factor, no CI/reviews |
| **8. Governance** | Governance docs, maintainer responsiveness | No SECURITY.md, slow response, abandoned |
| **9. Release Security** | CI publishing, branch protection, signed tags | Manual publishing, no branch protection |
| **10. Package Maturity** | Package age, update frequency, staleness | New/abandoned package, irregular updates |

**Total Score**: 0-20 points
- **0-5 points**: ✅ Low risk (good supply chain security)
- **6-14 points**: ⚠️ Medium risk (some concerns)
- **15-20 points**: 🔴 High risk (significant issues)

## AI-Enhanced Analysis (Optional)

Snyft can optionally use Claude AI to enhance supply chain security analysis with attack pattern detection and executive-friendly risk explanations.

### Enabling AI Analysis

```bash
export CLAUDE_API_KEY=your-anthropic-api-key
./snyft scan
```

Get an API key from: [Anthropic Console](https://console.anthropic.com/)

### What AI Analysis Provides

**Attack Pattern Matching**: Detects 8 documented supply chain attack patterns:
1. **Typosquatting** - Package name manipulation
2. **Account Takeover** - Maintainer compromise
3. **Dependency Confusion** - Namespace collision
4. **Malicious Install Script** - Installation code execution
5. **Abandoned Package Takeover** - Compromised unmaintained packages
6. **Build Chain Compromise** - CI/CD attacks
7. **Transitive Dependency Poisoning** - Indirect compromise
8. **Subdomain Takeover** - Repository URL hijacking

**Executive Summaries**: Stakeholder-friendly risk explanations with:
- Key risks identified
- Business impact assessment
- Recommended actions

### Configuration Options

Optional environment variables:
- `CLAUDE_RATE_LIMIT`: Requests per minute (default: 50)
- `CLAUDE_TIMEOUT`: Request timeout in seconds (default: 60)
- `CLAUDE_ENABLE_CACHE`: Enable response caching (default: true)

### Performance

- Adds ~2-5 seconds per package (with caching)
- Only runs when explicitly enabled
- Uses rate limiting (50 req/min by default)
- Responses cached for 24 hours

## Example Output

### Text Format (Default)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│              SNYFT SUPPLY CHAIN SECURITY REPORT                              │
│                   Generated: 2026-02-14 10:30:45                             │
└──────────────────────────────────────────────────────────────────────────────┘

────────────────────────────── EXECUTIVE SUMMARY ─────────────────────────────

  Total Packages Scanned: 42
  Manifest Files Found:   2
  Scan Path:             ./my-project

  Risk Distribution:
    ● HIGH Risk:     3 packages (7.1%)
    ● MEDIUM Risk:  12 packages (28.6%)
    ● LOW Risk:     27 packages (64.3%)

  Overall Risk Level: MEDIUM
  Scan Duration:      8.42s
  Average per Package: 200ms

──────────────────────────── DETAILED FINDINGS ───────────────────────────────

 🔴 ┌────────────────────────────────────────────────────────────────────────
│ Package: vulnerable-pkg@1.2.3 (npm)
│
│  Risk Level: HIGH
│  Supply Chain Score: 15/20 points (HIGH risk)
│  Repository: https://github.com/owner/vulnerable-pkg
│  Source Available: ✗ No
│
│  Supply Chain Security Analysis:
│
│    Category              Score  Risk  Status
│    ─────────────────────────────────────────────
│    Publisher Control     0/2    ●     ✓
│      Single maintainer with no commit/release signing
│    Ownership Changes     0/2    ●     ✓
│      Recent ownership transfer detected
│    Release Anomalies     0/2    ●     ✓
│      Dormant for 650 days, recent release 15 days ago
│    Install Execution     2/2    ●     ✓
│      No install-time scripts
│    Dependency Sprawl     0/2    ●     ✓
│      72 total dependencies (8 direct)
│    Provenance           0/2    ●     ✓
│      No provenance evidence
│    Health               1/2    ●     ✓
│      Limited health: few contributors or missing CI/reviews
│    Governance           0/2    ●     ✓
│      No SECURITY.md, slow issue response
│    Release Security     0/2    ●     ✓
│      Manual publishing, no branch protection
│
│  Risk Findings:
│    [HIGH] No verifiable source code found for this exact version
│       Evidence: No matching git tag; source package not found
│
│    [HIGH] Suspicious reactivation after dormancy
│       Evidence: Package dormant for 650 days, new release 15 days ago
│
│    [MEDIUM] No continuous integration system detected
│       Evidence: No CI config files found
└────────────────────────────────────────────────────────────────────────────

 🟢 ┌────────────────────────────────────────────────────────────────────────
│ Package: express@4.18.2 (npm)
│
│  Risk Level: LOW
│  Supply Chain Score: 3/20 points (LOW risk)
│  Repository: https://github.com/expressjs/express
│  Source Available: ✓ Yes
│  Build Infrastructure: CI detected: GitHub Actions, Travis CI
└────────────────────────────────────────────────────────────────────────────

────────────────────────────── RECOMMENDATIONS ───────────────────────────────

  1. Immediate Action Required: Review and address 3 HIGH risk packages.
     Consider finding alternative packages or implementing additional security
     controls.

  2. 3 packages lack publicly available source code. Verify these packages
     are from trusted publishers.

  3. 8 packages execute install-time scripts. Review these scripts for
     potentially dangerous operations.
```

### JSON Format

```json
{
  "scanPath": "./my-project",
  "timestamp": "2026-02-14T10:30:45Z",
  "results": [
    {
      "dependency": {
        "name": "express",
        "version": "4.18.2",
        "ecosystem": "npm"
      },
      "riskLevel": "LOW",
      "riskScore": 15,
      "supplyChainScore": {
        "totalScore": 2,
        "riskLevel": "LOW",
        "categoryScores": {
          "publisherControl": {"score": 2, "riskPoints": 0, "verified": true},
          "ownershipChanges": {"score": 2, "riskPoints": 0, "verified": true},
          "releaseAnomalies": {"score": 2, "riskPoints": 0, "verified": true},
          "installExecution": {"score": 2, "riskPoints": 0, "verified": true},
          "dependencySprawl": {"score": 2, "riskPoints": 0, "verified": true},
          "provenance": {"score": 1, "riskPoints": 1, "verified": true},
          "health": {"score": 1, "riskPoints": 1, "verified": true},
          "governance": {"score": 2, "riskPoints": 0, "verified": true},
          "releaseSecurity": {"score": 2, "riskPoints": 0, "verified": true},
          "packageMaturity": {"score": 2, "riskPoints": 0, "verified": true}
        }
      },
      "sourceCodeAvailable": true,
      "repositoryURL": "https://github.com/expressjs/express"
    }
  ],
  "statistics": {
    "totalPackages": 42,
    "highRisk": 3,
    "mediumRisk": 12,
    "lowRisk": 27
  }
}
```

## Supported Ecosystems

| Ecosystem | Manifest Files |
|-----------|---------------|
| **JavaScript/Node.js** | package.json, package-lock.json, yarn.lock |
| **Python** | requirements.txt, Pipfile, Pipfile.lock, pyproject.toml, setup.py |
| **Java/Maven** | pom.xml, build.gradle |

## Architecture

```
snyft/
├── cmd/           # CLI commands (Cobra framework)
├── pkg/
│   ├── analyzer/  # Core analysis engine with 10-category scoring
│   ├── fetcher/   # API clients + web scraping fallbacks
│   │              # Multi-platform support (GitHub, GitLab, Bitbucket)
│   ├── models/    # Data structures
│   ├── parser/    # Manifest file parsers
│   └── report/    # Multi-format report generators
```

### Multi-Platform Support

Snyft supports multiple Git hosting platforms through a unified `GitPlatformClient` interface:

- **GitHub**: Full support with API and web scraping fallbacks
- **GitLab**: Support for GitLab.com and self-hosted instances
- **Bitbucket**: Support for Bitbucket Cloud and self-hosted instances

The platform is automatically detected from repository URLs, ensuring seamless analysis across different hosting providers.

### Analysis Flow

1. **Discovery**: Recursively scan directory for manifest files
2. **Parsing**: Extract dependencies and versions from manifests
3. **Deduplication**: Remove duplicate dependencies across manifests
4. **Source Verification**: PRIMARY check - validate exact version source availability
5. **Parallel Analysis**: Spawn worker goroutines for concurrent analysis
6. **Scoring**: Calculate 10-category supply chain scores
7. **Reporting**: Generate formatted output with executive summaries (text/markdown/json/html)

## Troubleshooting

### API Rate Limits

Some APIs have rate limits that may affect large scans:

| API | Unauthenticated | Authenticated |
|-----|----------------|---------------|
| GitHub | 60 req/hour | 5,000 req/hour |
| GitLab | No strict limits | 5,000 req/hour |
| Bitbucket | No strict limits | Higher limits with auth |
| npm | No strict limits | - |
| PyPI | No strict limits | - |
| OSSF Scorecard | No strict limits | - |

**Solution**: Set platform tokens for higher rate limits:

```bash
# GitHub (recommended for GitHub-hosted projects)
export GITHUB_TOKEN="ghp_your_token_here"

# GitLab (for GitLab-hosted projects)
export GITLAB_TOKEN="glpat_your_token_here"

# Bitbucket (for Bitbucket-hosted projects)
export BITBUCKET_TOKEN="your_token_here"

./snyft scan
```

**Get tokens**:
- GitHub: [Settings → Developer settings → Personal access tokens](https://github.com/settings/tokens)
- GitLab: [User Settings → Access Tokens](https://gitlab.com/-/profile/personal_access_tokens)
- Bitbucket: [Personal settings → App passwords](https://bitbucket.org/account/settings/app-passwords/)

### Web Scraping Fallback

When APIs fail or rate limit, Snyft automatically falls back to web scraping:

- **npm**: Scrapes npmjs.com package pages
- **PyPI**: Scrapes pypi.org project pages
- **GitHub**: Scrapes github.com for release/tag information
- **GitLab**: Scrapes GitLab web interface for repository data
- **Bitbucket**: Scrapes Bitbucket web interface for repository data

This ensures analysis continues even with API restrictions or across different hosting platforms.

### Performance Tips

```bash
# Increase workers for faster scans (uses more memory)
./snyft scan --workers 30

# Disable verbose output for cleaner logs
./snyft scan --verbose=false

# Use JSON format for programmatic processing
./snyft scan --format json | jq '.statistics'
```

## Security

This tool is for security research and assessment purposes. Always verify findings and use responsibly.

## Contributing

Contributions are welcome! Please open issues or submit pull requests.

## License

MIT License - see LICENSE file for details.

## Roadmap

Future enhancements:
- [ ] Support for more package ecosystems (Ruby, Rust, PHP, Go)
- [ ] Historical tracking of dependency risk over time
- [ ] Integration with CI/CD pipelines (GitHub Actions, GitLab CI)
- [ ] Custom risk scoring profiles and policy enforcement
- [ ] SBOM (Software Bill of Materials) generation in CycloneDX/SPDX formats
