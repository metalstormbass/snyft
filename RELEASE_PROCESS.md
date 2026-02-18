# Release Process

Snyft uses GitHub Actions to automate releases. When a version tag is pushed, a GitHub release is created automatically.

## Creating a Release

### 1. Ensure Main Branch is Ready

```bash
git checkout main
git pull origin main
```

### 2. Create and Push a Version Tag

Use [semantic versioning](https://semver.org/) (MAJOR.MINOR.PATCH):

```bash
git tag -a v1.1.0 -m "Release v1.1.0"
git push origin v1.1.0
```

GitHub Actions triggers `.github/workflows/release.yml` to create the release.

## Installation After Release

### Using Go Install (Recommended)

```bash
go install github.com/metalstormbass/snyft@latest
```

## Changelog

Auto-generated from [conventional commits](https://www.conventionalcommits.org/):
- `feat:` -> New Features
- `fix:` -> Bug Fixes
- `perf:` -> Performance Improvements

## Troubleshooting

- Tag format must be `v*` (e.g., `v1.0.0`)
- To fix a bad release: delete the GitHub release, delete the tag (`git tag -d v1.0.0 && git push origin :refs/tags/v1.0.0`), fix, and re-tag
- Test locally with `goreleaser release --snapshot --clean`
