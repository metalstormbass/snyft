# Snyft Architecture

Snyft is a modular, concurrent CLI tool built in Go. It follows a pipeline architecture:

```
Discovery -> Parsing -> Deduplication -> Source Verification -> Parallel Analysis -> Risk Scoring -> Reporting
```

## Directory Structure

```
snyft/
├── cmd/                    # CLI commands (Cobra)
│   ├── root.go             # Root command, global flags
│   ├── scan.go             # Scan command, pipeline orchestration
│   └── version.go          # Version command
├── pkg/
│   ├── models/             # Data structures (Dependency, AnalysisResult, etc.)
│   ├── parser/             # Manifest parsers (JS, Python, Java)
│   ├── fetcher/            # API clients + web scraping fallbacks
│   │                       # (GitHub, GitLab, Bitbucket, npm, PyPI, Maven, OSSF)
│   ├── analyzer/           # 10-category scoring engine
│   ├── ai/                 # Claude AI integration (attack patterns, executive summaries)
│   └── report/             # Multi-format output (text, markdown, JSON, HTML)
├── examples/               # Example projects for testing
├── main.go                 # Entry point
├── go.mod / go.sum         # Dependencies
└── .goreleaser.yml         # Release configuration
```

## Core Components

### CLI Layer (cmd/)

Built with Cobra. The `scan` command orchestrates the full pipeline: discover manifests via `filepath.Walk`, parse, deduplicate, verify source, analyze in parallel, score, and report.

### Parser Layer (pkg/parser/)

Extracts dependencies from manifest files using a strategy/dispatcher pattern.

**Supported formats**: package.json, package-lock.json, yarn.lock, requirements.txt, Pipfile, pyproject.toml, setup.py, pom.xml, build.gradle

### Fetcher Layer (pkg/fetcher/)

Data collection via web scraping, bare git clones, and package registry APIs. No GitHub API keys required.

- **GitHub/GitLab/Bitbucket**: Repository metadata via web scraping and bare git clone (commits, tags, CI configs, contributors)
- **npm/PyPI/Maven**: Package metadata, version info, maintainer data via registry APIs

### Analyzer Layer (pkg/analyzer/)

Core scoring engine with 10 independent categories (0-2 points each, except Dependency Sprawl which is 0-1):

1. Publisher Control
2. Ownership Changes
3. Release Anomalies
4. Install Execution
5. Dependency Sprawl
6. Provenance
7. Health
8. Governance
9. Release Security
10. Package Maturity

Source code verification runs first (checks tarball/sdist/sources.jar + git tags), then each category is scored independently.

### Report Layer (pkg/report/)

Generates output in text (colored tables), markdown, JSON, and HTML formats.

## Concurrency Model

Worker pool pattern with configurable goroutine count. Each worker independently analyzes one dependency (fetch metadata, check source, score). Bounded concurrency respects API rate limits.

## Error Handling

Graceful degradation: if any API fails, analysis continues with available data. Per-package failures don't stop the scan.

## Extension Points

### Adding a New Ecosystem

1. Add ecosystem constant in `pkg/models/models.go`
2. Create parser in `pkg/parser/`
3. Register in `pkg/parser/parser.go`
4. Create API client in `pkg/fetcher/`
5. Integrate in `pkg/analyzer/analyzer.go`
6. Add tests and update docs

### Adding a New Risk Check

1. Implement check function in `pkg/analyzer/`
2. Call from `Analyze()` method
3. Add tests

## Performance

Primary bottleneck is external network calls. Mitigated by parallel workers, configurable concurrency, bare git clone pooling, and response caching. Web scraping and git clones are the sole data sources — no API keys or rate limits to manage.
