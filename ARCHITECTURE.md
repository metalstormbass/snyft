# Snyft Architecture

This document describes the internal architecture and design of Snyft.

## Overview

Snyft is designed as a modular, concurrent CLI tool built in Go. It follows a pipeline architecture:

```
Discovery → Parsing → Deduplication → Parallel Analysis → Risk Scoring → Reporting
```

## Directory Structure

```
snyft/
├── cmd/                    # CLI commands (Cobra)
│   ├── root.go            # Root command definition
│   └── scan.go            # Scan command implementation
├── pkg/                   # Core packages
│   ├── models/            # Data structures
│   │   └── models.go      # Dependency, AnalysisResult, etc.
│   ├── parser/            # Manifest file parsers
│   │   ├── parser.go      # Parser dispatcher
│   │   ├── javascript.go  # npm/yarn parser
│   │   ├── python.go      # pip/pipenv parser
│   │   └── java.go        # Maven/Gradle parser
│   ├── fetcher/           # External API clients
│   │   ├── github.go      # GitHub API client
│   │   ├── npm.go         # npm registry client
│   │   ├── pypi.go        # PyPI API client
│   │   ├── maven.go       # Maven Central client
│   │   ├── ossf.go        # OSSF Scorecard client
│   │   └── utils.go       # Shared utilities
│   └── analyzer/          # Analysis engine
│       └── analyzer.go    # Risk analysis logic
├── examples/              # Example projects for testing
│   ├── nodejs-example/
│   ├── python-example/
│   └── java-example/
├── main.go                # Application entry point
├── go.mod                 # Go module definition
└── go.sum                 # Dependency checksums
```

## Core Components

### 1. CLI Layer (cmd/)

Built using the Cobra framework for a clean CLI experience.

**Root Command** (`cmd/root.go`):
- Defines the base `snyft` command
- Handles global flags and configuration
- Delegates to subcommands

**Scan Command** (`cmd/scan.go`):
- Entry point for dependency scanning
- Orchestrates the entire pipeline:
  1. Discovers manifest files via `filepath.Walk`
  2. Parses each manifest using the parser package
  3. Deduplicates dependencies
  4. Spawns worker goroutines for parallel analysis
  5. Aggregates and displays results

### 2. Data Models (pkg/models/)

Core data structures used throughout the application.

**Dependency**:
```go
type Dependency struct {
    Name      string    // Package name
    Version   string    // Version string
    Ecosystem Ecosystem // npm, pypi, maven
    Source    string    // Manifest file path
}
```

**AnalysisResult**:
```go
type AnalysisResult struct {
    Dependency          Dependency
    RiskLevel           string   // HIGH, MEDIUM, LOW
    RiskScore           int      // 0-100
    RiskFactors         []string
    RepositoryURL       string
    SourceCodeAvailable bool
    BuildInfrastructure string
    Findings            []Finding
    Metadata            PackageMetadata
}
```

### 3. Parser Layer (pkg/parser/)

Responsible for extracting dependencies from manifest files.

**Design Pattern**: Strategy pattern with a dispatcher

**Supported Formats**:
- **JavaScript**: package.json, package-lock.json, yarn.lock
- **Python**: requirements.txt, Pipfile, pyproject.toml
- **Java**: pom.xml, build.gradle

**Parser Interface**:
```go
func ParseManifest(path string) ([]Dependency, error)
```

Each parser:
1. Reads the manifest file
2. Parses it (JSON, XML, TOML, or line-based)
3. Extracts dependency names and versions
4. Returns a slice of `Dependency` objects

**Example**: JavaScript Parser
```go
// Reads package.json
// Unmarshals JSON
// Extracts dependencies and devDependencies
// Cleans version strings (removes ^, ~, etc.)
```

### 4. Fetcher Layer (pkg/fetcher/)

API clients for external services, each with retry logic and rate limiting awareness.

**GitHub Client** (`github.go`):
- Repository metadata (stars, forks, activity)
- CI/CD system detection (checks for workflow files)
- Release information
- Uses GitHub REST API v3
- Supports authentication via `GITHUB_TOKEN`

**npm Client** (`npm.go`):
- Package metadata from npm registry
- Version information
- Repository URL extraction
- Maintainer information

**PyPI Client** (`pypi.go`):
- Package metadata from PyPI JSON API
- Version and release information
- Repository URL extraction from project URLs

**Maven Client** (`maven.go`):
- Package search via Maven Central
- POM file fetching for metadata
- SCM URL extraction
- License information

**OSSF Client** (`ossf.go`):
- OpenSSF Scorecard data
- Security check scores
- Supply chain security indicators

### 5. Analyzer Layer (pkg/analyzer/)

The core analysis engine that evaluates supply chain security.

**Analysis Pipeline**:
```
1. Fetch package metadata from registry (npm, PyPI, Maven)
2. Extract repository URL
3. Analyze repository (GitHub API)
4. Detect build infrastructure
5. Fetch OSSF Scorecard (if available)
6. Calculate risk score
7. Determine risk level
```

**Risk Factors Evaluated**:

| Factor | Severity | Score Impact |
|--------|----------|--------------|
| Package not found | HIGH | +30 |
| No source code | HIGH | +30 |
| Archived repository | HIGH | +30 |
| No commits in 365+ days | MEDIUM | +15 |
| No CI/CD detected | MEDIUM | +15 |
| Low community engagement | MEDIUM | +15 |
| Low OSSF score (<5.0) | MEDIUM | +15 |
| No automated releases | LOW | +5 |

**Risk Scoring**:
```
score >= 70  → HIGH
score >= 40  → MEDIUM
score < 40   → LOW
```

## Concurrency Model

Snyft uses goroutines for parallel analysis to maximize throughput.

### Worker Pool Pattern

```go
// Create job channel
jobs := make(chan int, len(deps))

// Spawn N workers
for w := 0; w < numWorkers; w++ {
    go func() {
        for idx := range jobs {
            results[idx] = analyzer.Analyze(deps[idx])
        }
    }()
}

// Queue all jobs
for i := range deps {
    jobs <- i
}
```

**Benefits**:
- Bounded concurrency (configurable worker count)
- Maximizes API throughput without overwhelming services
- Respects rate limits by controlling parallelism

## Data Flow

```
User runs: snyft scan /path/to/project
                  ↓
         [Scan Command Handler]
                  ↓
         [Manifest Discovery]
         (filepath.Walk)
                  ↓
         [Parse Each Manifest]
         (JavaScript, Python, Java parsers)
                  ↓
         [Deduplicate Dependencies]
         (Hash map by ecosystem+name+version)
                  ↓
         [Spawn Worker Pool]
         (N goroutines)
                  ↓
    ┌────────────┴────────────┐
    ↓                         ↓
[Worker 1]              [Worker N]
    ↓                         ↓
[Analyze Dependency]    [Analyze Dependency]
    ↓                         ↓
• Fetch from registry   • Fetch from registry
• Get GitHub metadata   • Get GitHub metadata
• Check CI/CD           • Check CI/CD
• Get OSSF score        • Get OSSF score
• Calculate risk        • Calculate risk
    ↓                         ↓
    └────────────┬────────────┘
                  ↓
         [Aggregate Results]
                  ↓
         [Display Output]
         (Risk summary + details)
```

## Extension Points

### Adding a New Ecosystem

To support a new package ecosystem (e.g., Ruby gems):

1. **Add Ecosystem Constant** (`pkg/models/models.go`):
```go
const EcosystemRubyGems Ecosystem = "rubygems"
```

2. **Create Parser** (`pkg/parser/ruby.go`):
```go
func parseGemfile(path string) ([]models.Dependency, error) {
    // Parse Gemfile
    // Extract dependencies
    // Return []Dependency
}
```

3. **Register Parser** (`pkg/parser/parser.go`):
```go
case "Gemfile", "Gemfile.lock":
    return parseGemfile(path)
```

4. **Create Fetcher** (`pkg/fetcher/rubygems.go`):
```go
type RubyGemsClient struct { ... }
func (c *RubyGemsClient) GetPackageInfo(name string) (*RubyGemsPackage, error) { ... }
```

5. **Integrate in Analyzer** (`pkg/analyzer/analyzer.go`):
```go
case models.EcosystemRubyGems:
    gemInfo, err := a.rubygemsClient.GetPackageInfo(dep.Name)
    // ...
```

### Adding New Risk Checks

To add a new security check:

1. **Implement Check** in `analyzer.go`:
```go
func (a *Analyzer) checkForMaliciousPatterns(result *AnalysisResult, repoURL string) {
    // Perform analysis
    if suspiciousPatternDetected {
        result.Findings = append(result.Findings, models.Finding{
            Severity: "HIGH",
            Category: "Malicious Pattern",
            Description: "Detected suspicious code pattern",
        })
        result.RiskFactors = append(result.RiskFactors, "Possible malicious code")
    }
}
```

2. **Call from Analyze()** method:
```go
func (a *Analyzer) Analyze(dep models.Dependency) models.AnalysisResult {
    // ... existing checks ...
    a.checkForMaliciousPatterns(&result, repoURL)
    a.calculateRiskScore(&result)
    return result
}
```

## Performance Considerations

### Bottlenecks

1. **External API Calls**: The primary bottleneck
   - Mitigated by parallel workers
   - Configurable concurrency

2. **GitHub Rate Limits**:
   - 60 requests/hour (unauthenticated)
   - 5000 requests/hour (with token)
   - Each dependency requires ~3-5 API calls

3. **Network Latency**:
   - Multiple external services queried
   - Serial per-dependency analysis

### Optimization Strategies

1. **Caching**: Future enhancement to cache API responses
2. **Batch APIs**: Use GraphQL for GitHub where applicable
3. **Parallel Fetching**: Already implemented via worker pool
4. **Skip Dev Dependencies**: Optional flag to reduce scope

## Error Handling

Snyft uses graceful degradation:
- If GitHub API fails, continue with registry data only
- If OSSF Scorecard unavailable, skip that check
- Per-package failures don't stop the scan
- Errors logged but don't crash the tool

## Testing Strategy

### Unit Tests
- Parser tests with fixture files
- Fetcher tests with mocked HTTP responses
- Analyzer tests with synthetic data

### Integration Tests
- End-to-end scans on example projects
- API integration tests (require network)

### Example:
```go
func TestParsePackageJSON(t *testing.T) {
    deps, err := parsePackageJSON("testdata/package.json")
    assert.NoError(t, err)
    assert.Len(t, deps, 4)
    assert.Equal(t, "express", deps[0].Name)
}
```

## Security Considerations

- **API Tokens**: Never log or expose tokens
- **Input Validation**: Sanitize file paths
- **Dependency Safety**: Minimal external dependencies
- **No Code Execution**: Only reads manifest files, doesn't execute code

## Future Enhancements

1. **Caching Layer**: Redis/local cache for API responses
2. **SBOM Generation**: Output Software Bill of Materials
3. **Historical Tracking**: Track risk changes over time
4. **Machine Learning**: Anomaly detection for suspicious packages
5. **Code Analysis**: Static analysis of dependency source code
6. **Malware Detection**: Hash checking, signature scanning
7. **Policy Engine**: Custom rules for acceptable risk levels
8. **Output Formats**: JSON, HTML, PDF reports
9. **Database Backend**: Store analysis results
10. **Web UI**: Dashboard for visualization

## Contributing

When contributing to Snyft:
1. Follow Go best practices
2. Add tests for new features
3. Update this architecture doc
4. Keep the README in sync
5. Use conventional commits

## Questions?

See [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue!
