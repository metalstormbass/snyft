# Contributing to Snyft

Thank you for your interest in contributing to Snyft! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, inclusive, and collaborative. We're all here to build better security tools.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected vs actual behavior**
- **Environment details** (OS, Go version, etc.)
- **Logs or error messages**

**Example Bug Report:**
```markdown
**Title:** Parser fails on pyproject.toml with poetry dependencies

**Description:**
When scanning a Python project using Poetry, the pyproject.toml parser crashes.

**Steps to Reproduce:**
1. Run `snyft scan examples/poetry-example`
2. Observe error message

**Expected:** Dependencies should be parsed successfully
**Actual:** Parser crashes with "index out of range" error

**Environment:**
- OS: macOS 14.0
- Go: 1.21.1
- Snyft: v0.1.0

**Logs:**
```
panic: runtime error: index out of range
```

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Use case**: Why is this enhancement needed?
- **Proposed solution**: How should it work?
- **Alternatives considered**: What other approaches did you think about?
- **Additional context**: Screenshots, examples, etc.

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Test thoroughly**
5. **Commit with clear messages**: `git commit -m 'Add amazing feature'`
6. **Push to your fork**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

## Development Setup

### Prerequisites

- Go 1.21 or later
- Git
- A GitHub account (for testing GitHub API integration)

### Getting Started

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/snyft.git
cd snyft

# Add upstream remote
git remote add upstream https://github.com/metalstormbass/snyft.git

# Install dependencies
go mod download

# Build
make build

# Run tests
make test
```

### Project Structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed architecture documentation.

```
snyft/
├── cmd/           # CLI commands
├── pkg/
│   ├── models/    # Data structures
│   ├── parser/    # Manifest parsers
│   ├── fetcher/   # API clients
│   └── analyzer/  # Analysis engine
├── examples/      # Test projects
└── main.go        # Entry point
```

## Coding Guidelines

### Go Style

Follow standard Go conventions:
- Use `gofmt` for formatting: `make fmt`
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use meaningful variable names
- Add comments for exported functions

### Code Structure

```go
// Good: Clear function with documentation
// FetchPackageInfo retrieves package metadata from the npm registry.
// Returns an error if the package is not found or the API is unavailable.
func (c *NPMClient) FetchPackageInfo(name string) (*Package, error) {
    // Implementation
}

// Bad: Unclear function without documentation
func get(n string) (*Package, error) {
    // Implementation
}
```

### Error Handling

- Always handle errors explicitly
- Provide context when wrapping errors
- Use `fmt.Errorf` for error wrapping

```go
// Good
if err != nil {
    return nil, fmt.Errorf("failed to parse package.json: %w", err)
}

// Bad
if err != nil {
    return nil, err
}
```

### Testing

Write tests for new features:

```go
func TestParsePackageJSON(t *testing.T) {
    // Arrange
    testFile := "testdata/package.json"

    // Act
    deps, err := parsePackageJSON(testFile)

    // Assert
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(deps) != 4 {
        t.Errorf("expected 4 dependencies, got %d", len(deps))
    }
}
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add support for Gradle Kotlin DSL
fix: correct pyproject.toml parser for poetry projects
docs: update architecture documentation
test: add integration tests for Maven parser
refactor: simplify GitHub API client
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Build/tooling changes

## Adding New Features

### Adding a New Ecosystem

To add support for a new package ecosystem (e.g., Ruby):

1. **Define the ecosystem** in `pkg/models/models.go`:
```go
const EcosystemRubyGems Ecosystem = "rubygems"
```

2. **Create a parser** in `pkg/parser/ruby.go`:
```go
func parseGemfile(path string) ([]models.Dependency, error) {
    // Implementation
}
```

3. **Register the parser** in `pkg/parser/parser.go`

4. **Create an API client** in `pkg/fetcher/rubygems.go`

5. **Integrate in analyzer** in `pkg/analyzer/analyzer.go`

6. **Add tests** for the new parser

7. **Update documentation**: README.md, ARCHITECTURE.md

8. **Add example project** in `examples/ruby-example/`

### Adding a New Risk Check

To add a new security check:

1. **Implement the check** in `pkg/analyzer/analyzer.go`:
```go
func (a *Analyzer) checkDependencyAge(result *AnalysisResult) {
    daysSinceRelease := time.Since(result.Metadata.PublishedAt).Hours() / 24
    if daysSinceRelease < 7 {
        result.Findings = append(result.Findings, models.Finding{
            Severity:    "MEDIUM",
            Category:    "Recent Release",
            Description: "Package was released less than 7 days ago",
        })
        result.RiskFactors = append(result.RiskFactors, "Very new release")
    }
}
```

2. **Call from Analyze()** method

3. **Add tests** for the new check

4. **Update documentation** explaining the check

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
go test -cover ./...

# Run tests for a specific package
go test ./pkg/parser

# Run a specific test
go test -run TestParsePackageJSON ./pkg/parser
```

### Writing Tests

#### Unit Tests

Test individual functions in isolation:

```go
func TestCleanVersion(t *testing.T) {
    tests := []struct {
        input    string
        expected string
    }{
        {"^1.2.3", "1.2.3"},
        {"~4.5.6", "4.5.6"},
        {">=7.8.9", "7.8.9"},
    }

    for _, tt := range tests {
        result := cleanVersion(tt.input)
        if result != tt.expected {
            t.Errorf("cleanVersion(%q) = %q, want %q",
                tt.input, result, tt.expected)
        }
    }
}
```

#### Integration Tests

Test multiple components together:

```go
func TestScanNodeJSProject(t *testing.T) {
    // Requires network access
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    deps, err := parseManifests("testdata/nodejs-project")
    assert.NoError(t, err)
    assert.NotEmpty(t, deps)
}
```

### Test Data

Place test fixtures in `testdata/` directories:

```
pkg/parser/testdata/
├── package.json
├── requirements.txt
└── pom.xml
```

## Documentation

### Code Documentation

- Add godoc comments for all exported functions and types
- Include examples in documentation where helpful
- Keep documentation up-to-date with code changes

```go
// GetRepositoryInfo fetches repository metadata from GitHub.
//
// It requires a valid GitHub repository URL and returns information
// including stars, forks, last commit date, and more.
//
// Example:
//     client := NewGitHubClient()
//     info, err := client.GetRepositoryInfo("https://github.com/owner/repo")
//     if err != nil {
//         log.Fatal(err)
//     }
//     fmt.Printf("Stars: %d\n", info.Stars)
func (c *GitHubClient) GetRepositoryInfo(repoURL string) (*RepositoryInfo, error) {
    // Implementation
}
```

### Project Documentation

Update relevant documentation files:
- `README.md`: User-facing documentation
- `ARCHITECTURE.md`: Technical architecture
- `QUICKSTART.md`: Getting started guide
- `CONTRIBUTING.md`: This file

## Pull Request Process

1. **Update documentation** for any changed functionality
2. **Add/update tests** to maintain coverage
3. **Run linters**: `make lint`
4. **Ensure tests pass**: `make test`
5. **Update CHANGELOG.md** with your changes
6. **Request review** from maintainers

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows project style guidelines
- [ ] Documentation is updated
- [ ] Commit messages are clear and descriptive
- [ ] No unnecessary dependencies added
- [ ] CHANGELOG.md is updated

## Release Process

(For maintainers)

1. Update version in relevant files
2. Update CHANGELOG.md
3. Create a git tag: `git tag -a v0.2.0 -m "Release v0.2.0"`
4. Push tag: `git push origin v0.2.0`
5. Create GitHub release with release notes

## Getting Help

- **Questions**: Open a [Discussion](https://github.com/metalstormbass/snyft/discussions)
- **Bugs**: Open an [Issue](https://github.com/metalstormbass/snyft/issues)
- **Chat**: Join our community (link TBD)

## Recognition

Contributors will be:
- Listed in the contributors section
- Mentioned in release notes
- Appreciated by the community!

Thank you for contributing to Snyft! 🎉
