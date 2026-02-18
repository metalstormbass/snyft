# Contributing to Snyft

## Code of Conduct

Be respectful, inclusive, and collaborative.

## How to Contribute

### Reporting Bugs

Include: clear title, steps to reproduce, expected vs actual behavior, environment details (OS, Go version), and error logs.

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make changes and test thoroughly
4. Commit with [conventional commits](https://www.conventionalcommits.org/): `git commit -m 'feat: add amazing feature'`
5. Push and open a Pull Request

## Development Setup

### Prerequisites

- Go 1.24 or later
- Git
- Optional: `GITHUB_TOKEN`, `GITLAB_TOKEN`, `BITBUCKET_TOKEN` for API access
- Optional: `CLAUDE_API_KEY` for AI features

### Getting Started

```bash
git clone https://github.com/YOUR_USERNAME/snyft.git
cd snyft
git remote add upstream https://github.com/metalstormbass/snyft.git
make build
make test
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for project structure and extension points.

## Coding Guidelines

- Format with `gofmt`: `make fmt`
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Always handle errors with context: `fmt.Errorf("failed to parse: %w", err)`
- Add godoc comments for exported functions
- Write table-driven tests using `testify`

### Commit Types

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Tests
- `refactor:` Refactoring
- `perf:` Performance
- `chore:` Build/tooling

## Testing

```bash
make test                            # Run all tests
go test -cover ./...                 # With coverage
go test -run TestParsePackageJSON ./pkg/parser  # Specific test
```

Place test fixtures in `testdata/` directories within each package.

## PR Checklist

- [ ] Tests pass locally (`make test`)
- [ ] Code formatted (`make fmt`)
- [ ] Linter passes (`make lint`)
- [ ] Documentation updated if needed
- [ ] Commit messages follow conventional format
