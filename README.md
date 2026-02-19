# Snyft

<p align="center">
  <img src="assets/snyft.png" alt="Snyft Logo" width="400"/>
</p>

**Snyft** is a supply chain security analyzer that evaluates dependencies from Python, JavaScript, and Java projects using a 10-category scoring rubric to identify potential compromise risks.

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
./snyft scan --ai                         # Enable AI analysis (requires CLAUDE_API_KEY)
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --format` | Output format: `text`, `markdown`, `json`, `html` | `text` |
| `-w, --workers` | Concurrent workers | 10 |
| `-v, --verbose` | Verbose output | `true` |
| `-o, --output` | Write results to file | stdout |
| `--ai` | Enable AI analysis | disabled |
| `--ai-api-key` | Claude API key (or set `CLAUDE_API_KEY`) | - |
| `--ai-timeout` | AI timeout in seconds | 60 |

See [docs/AI_FEATURES.md](docs/AI_FEATURES.md) for full AI configuration.

## Supply Chain Scoring System

Each dependency is scored across 10 categories (0-2 risk points each):

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
| **9. Release Security** | Manual publishing, no branch protection, CI workflow risks |
| **10. Package Maturity** | New/abandoned package, irregular updates |

**Total Score**: 0-20 points
- **0-5**: Low risk
- **6-14**: Medium risk
- **15-20**: High risk

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
- Web scraping fallbacks when APIs are unavailable

## API Rate Limits

| API | Unauthenticated | Authenticated |
|-----|----------------|---------------|
| GitHub | 60 req/hour | 5,000 req/hour |
| npm/PyPI/OSSF | No strict limits | - |

Set tokens for higher limits:

```bash
export GITHUB_TOKEN="ghp_..."
export GITLAB_TOKEN="glpat_..."
export BITBUCKET_TOKEN="..."
```

## License

MIT License - see LICENSE file for details.

## Roadmap

- [ ] Support for more ecosystems (Ruby, Rust, PHP, Go)
- [ ] Historical tracking of dependency risk over time
- [ ] CI/CD pipeline integration (GitHub Actions, GitLab CI)
- [ ] Custom risk scoring profiles and policy enforcement
- [ ] SBOM generation (CycloneDX/SPDX)
