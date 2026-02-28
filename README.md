# Snyft

<p align="center">
  <img src="assets/snyft.png" alt="Snyft Logo" width="400"/>
</p>

**Snyft** is a supply chain security analyzer that evaluates dependencies from Python, JavaScript, and Java projects using a **22-point risk scoring system** across 11 categories to identify potential compromise risks.

Unlike vulnerability scanners focused on CVEs, Snyft assesses the **likelihood of supply chain compromise** by analyzing repository metadata, build practices, source code availability, and security signals.

## Installation

### Using Go Install (Recommended)

```bash
go install github.com/metalstormbass/snyft@latest
```

### Build from Source

Requires Go 1.24+.

```bash
git clone https://github.com/metalstormbass/snyft.git
cd snyft
make build
```

## Usage

```bash
./snyft scan                              # Scan current directory
./snyft scan /path/to/project             # Scan specific directory
./snyft scan --format json -o results.json  # JSON output to file
./snyft scan --format markdown -o SECURITY.md
./snyft scan --format html -o report.html
./snyft scan --workers 20                 # Increase concurrency
./snyft scan --verbose=false              # Quieter output
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --format` | Output format: `text`, `markdown`, `json`, `html` | `text` |
| `-w, --workers` | Concurrent workers | 10 |
| `-v, --verbose` | Verbose output | `false` |
| `-o, --output` | Write results to file | stdout |
| `--include-transitive` | Analyze transitive dependencies | `false` |

## Supply Chain Scoring System

Each dependency is scored across 11 categories (0-2 risk points each):

| Category | Risk Indicators |
|----------|----------------|
| **1. Publisher Control** | Single maintainer, no signing, no 2FA |
| **2. Ownership Changes** | Recent maintainer changes |
| **3. Release Anomalies** | Long dormancy followed by sudden release |
| **4. Install Execution** | postinstall scripts, dangerous patterns |
| **5. Dependency Sprawl** | Many transitive dependencies (50+) |
| **6. Provenance** | No source verification, no SLSA/Sigstore attestations |
| **7. Health** | Low bus factor, no review oversight |
| **8. Governance** | No SECURITY.md, slow issue response |
| **9. Release Security** | Manual publishing, no branch protection |
| **10. Package Maturity** | New/abandoned package, irregular updates |
| **11. CI Pipeline Security** | No CI, unpinned actions, script injection, dangerous triggers |

**Total Score**: 0-22 points
- **0-9**: Low risk
- **10-13**: Medium risk
- **14+**: High risk

## Typosquatting Detection

Snyft checks package names against curated lists of popular packages across npm, PyPI, and Maven to detect potential typosquatting attacks. Seven detection techniques are used:

- **Character omission/insertion** — `lodas` vs `lodash`
- **Character substitution** — `lodesh` vs `lodash`
- **Adjacent transposition** — `reqeusts` vs `requests`
- **Homoglyph substitution** — `1odash` vs `lodash`
- **Separator confusion** — `crossenv` vs `cross-env`
- **Scope manipulation** — `@evil/react` vs `react`
- **Repeated characters** — `expresss` vs `express`

Typosquatting findings are reported as informational warnings and do not affect the 0-20 risk score.

## Supported Ecosystems

| Ecosystem | Manifest Files |
|-----------|---------------|
| **JavaScript/Node.js** | package.json, package-lock.json, yarn.lock |
| **Python** | requirements.txt, Pipfile, Pipfile.lock, pyproject.toml, setup.py |
| **Java/Maven** | pom.xml, build.gradle |

## Multi-Platform Support

Repository analysis works across:
- **GitHub**, **GitLab**, **Bitbucket** (auto-detected from URLs)
- Works out of the box with zero configuration — web scraping is the primary data source
- Optional API tokens (`GITHUB_TOKEN`, `GITLAB_TOKEN`, `BITBUCKET_TOKEN`) for richer data and higher rate limits

## License

MIT License - see LICENSE file for details.
