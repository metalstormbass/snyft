# Snyft

<p align="center">
  <img src="assets/snyft.png" alt="Snyft Logo" width="250"/>
</p>

<p align="center"><em>Does it pass the snyft test?</em></p>

**Snyft** is a supply chain security analyzer that evaluates dependencies from Python, JavaScript, and Java projects using a **20-point risk scoring system** across 10 categories to identify potential compromise risks.

Unlike vulnerability scanners focused on CVEs, Snyft assesses the **likelihood of supply chain compromise** by analyzing repository metadata, build practices, source code availability, and security signals.

## Installation

### Using Go Install (Recommended)

```bash
go install github.com/metalstormbass/snyft@latest
export PATH=${PATH}:`go env GOPATH`/bin
```

If it is your first time using `go` to install packages, you'll need to run the second line in the snippet above.

### Build from Source

Requires Go 1.24+.

```bash
git clone https://github.com/metalstormbass/snyft.git
cd snyft
make build
```

## Usage

```bash
snyft scan                                # Scan current directory
snyft scan /path/to/project               # Scan specific directory
snyft scan -v                             # Detailed output with findings
snyft scan --format html -o report.html   # HTML report (recommended)
snyft scan --format json -o results.json  # JSON output to file
snyft scan --format markdown -o SECURITY.md
snyft scan --workers 20                   # Increase concurrency
```

> **Suggested:** For the best experience, use the HTML report: `snyft scan --format html -o report.html`. It includes interactive scoring details, confidence indicators, evidence, and per-category findings.

### Dependency Deduplication

When a project references the same package at multiple versions across different manifest files, snyft **deduplicates by name and keeps the most recent version** by default. Packages sharing the same source repository are also grouped to avoid redundant analysis.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --format` | Output format: `text`, `markdown`, `json`, `html` | `text` |
| `-w, --workers` | Concurrent workers | 10 |
| `-v, --verbose` | Detailed output with findings and evidence | `false` |
| `-o, --output` | Write results to file | stdout |
| `--include-transitive` | Analyze transitive dependencies | `false` |
| `--all-versions` | Scan all versions of duplicate dependencies (skip deduplication) | `false` |
| `--check` | Run only specific checks (comma-separated) | all checks |

Valid check names: `publisher-control`, `ownership-changes`, `release-anomalies`, `install-execution`, `dependency-sprawl`, `provenance`, `health`, `governance`, `release-security`, `package-maturity`

```bash
snyft scan --check health,provenance,governance
```

## How It Works

Snyft collects data using two primary methods that require **no authentication**:

1. **Web scraping** — extracts repository metadata, contributor info, governance files, and CI/CD configuration directly from hosting platform pages (GitHub, GitLab, Bitbucket)
2. **Bare git clone** — clones repositories to analyze commit history, signed commits, release tags, and contributor patterns without needing API access

Package registry APIs (npm, PyPI, Maven Central) provide maintainer info, version history, and dependency data.

Setting `GITHUB_TOKEN` is optional — it supplements scraping with additional GitHub API data (organization verification, MFA enforcement) and is needed for cloning private repositories.

## Supply Chain Scoring System

Each dependency is scored across 10 categories (0-2 risk points each):

| Category | What It Checks |
|----------|---------------|
| **1. Publisher Control** | Single maintainer risk, account age, org vs personal, commit signing, MFA enforcement. High-download packages (1M+/week) get reduced single-maintainer penalty. |
| **2. Ownership Changes** | Recent maintainer or owner transitions |
| **3. Release Anomalies** | Dormancy reactivation (1yr+ gap then sudden release), unusual release spikes, cadence anomalies |
| **4. Install Execution** | npm install scripts (postinstall/preinstall), dangerous patterns (code injection, network calls, privilege escalation). Analyzes actual script files from cloned repos. |
| **5. Dependency Sprawl** | Transitive dependency count. Maven uses scope-aware thresholds (12/29) vs npm/PyPI (5/15). |
| **6. Provenance** | SLSA attestation, signed releases, build provenance, source code verification |
| **7. Health** | Bus factor, code review coverage, CI/CD presence |
| **8. Governance** | SECURITY.md presence, issue response time, abandonment detection (180+ days inactive), archived repos |
| **9. Release Security** | CI/CD automation vs manual publishing, signed tags, PR review rates, CI workflow security (unpinned actions, script injection, excessive permissions). Branch protection assessed via OSSF Scorecard. |
| **10. Package Maturity** | Package age (<6mo = high risk), staleness (>1yr = abandoned), release cadence regularity |

**Total Score**: 0-20 points
- **0-8**: Low risk
- **9-12**: Medium risk
- **13+**: High risk

### Missing Data & Confidence

When repository data is unavailable (e.g., no repo URL found), snyft applies a **floor score** (8-10/20) instead of defaulting to best-case scores. A **confidence indicator** (0-100%) shows what fraction of checks had real data vs defaults. The HTML report color-codes confidence: green (≥75%), amber (50-74%), red (<50%).

## Supported Ecosystems

| Ecosystem | Manifest Files |
|-----------|---------------|
| **JavaScript/Node.js** | package.json, package-lock.json, yarn.lock |
| **Python** | requirements.txt, Pipfile, Pipfile.lock, pyproject.toml, setup.py |
| **Java/Maven** | pom.xml, build.gradle |

## Multi-Platform Support

Repository analysis works across:
- **GitHub**, **GitLab**, **Bitbucket** (auto-detected from URLs)
- Additional support for Sourcehut, Codeberg, Apache/Eclipse Git
- Works out of the box with zero configuration — web scraping + git clone require no tokens

## License

MIT License - see LICENSE file for details.
