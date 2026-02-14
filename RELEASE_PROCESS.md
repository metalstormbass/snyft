# Release Process

This document describes the automated release process for Snyft.

## Overview

Snyft uses [GoReleaser](https://goreleaser.com/) and GitHub Actions to automate the release process. When a new version tag is pushed, the system automatically:

1. Builds binaries for multiple platforms (macOS, Linux, Windows)
2. Creates release archives with documentation
3. Generates checksums for verification
4. Creates a GitHub release with automated changelog
5. Makes the release installable via `go install`

## Supported Platforms

The release pipeline builds for:

- **macOS**: x86_64 (Intel) and arm64 (Apple Silicon)
- **Linux**: x86_64 and arm64
- **Windows**: x86_64

## Creating a Release

### 1. Ensure Main Branch is Ready

Make sure all changes are merged and tested on the `main` branch:

```bash
git checkout main
git pull origin main
```

### 2. Create and Push a Version Tag

Use semantic versioning (MAJOR.MINOR.PATCH):

```bash
# For a new major version (breaking changes)
git tag -a v2.0.0 -m "Release v2.0.0"

# For a new minor version (new features, backward compatible)
git tag -a v1.1.0 -m "Release v1.1.0"

# For a patch version (bug fixes)
git tag -a v1.0.1 -m "Release v1.0.1"

# Push the tag
git push origin v1.0.0
```

### 3. Automatic Release Process

Once the tag is pushed, GitHub Actions automatically:

1. Triggers the `.github/workflows/release.yml` workflow
2. Checks out the code at the tagged version
3. Sets up Go 1.24
4. Runs GoReleaser to:
   - Build binaries for all platforms
   - Create archives (tar.gz for Unix, zip for Windows)
   - Generate SHA256 checksums
   - Create GitHub release with changelog
   - Upload all artifacts

The release will be available at: `https://github.com/metalstormbass/snyft/releases`

## Installation Methods

After release, users can install Snyft in three ways:

### 1. Using Go Install (Recommended)

```bash
# Install latest version
go install github.com/metalstormbass/snyft@latest

# Install specific version
go install github.com/metalstormbass/snyft@v1.0.0
```

### 2. Download Pre-built Binary

Download from the [releases page](https://github.com/metalstormbass/snyft/releases) and extract:

```bash
# macOS/Linux
tar -xzf snyft_*.tar.gz
./snyft version

# Windows
# Extract the zip file and run snyft.exe
```

### 3. Build from Source

```bash
git clone https://github.com/metalstormbass/snyft.git
cd snyft
make build
```

## Semantic Versioning

Follow [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** version (v2.0.0): Incompatible API changes
- **MINOR** version (v1.1.0): New functionality, backward compatible
- **PATCH** version (v1.0.1): Backward compatible bug fixes

## Changelog Generation

The changelog is automatically generated from commit messages. Use conventional commit format:

- `feat:` New features → "New Features" section
- `fix:` Bug fixes → "Bug Fixes" section
- `perf:` Performance improvements → "Performance Improvements" section
- `docs:` Documentation → "Documentation Updates" section

Example:
```bash
git commit -m "feat: add support for Rust cargo dependencies"
git commit -m "fix: correct npm registry URL parsing"
```

## Release Notes

Each release includes:

- Installation instructions
- Changelog grouped by type (features, fixes, etc.)
- Links to full changelog comparing with previous version
- Checksums for binary verification
- Download links for all platform binaries

## Version Information

The version command displays build information:

```bash
$ snyft version
snyft version v1.0.0
  commit: a1b2c3d4
  built at: 2024-02-14T12:00:00Z
  go version: go1.24.0
  platform: darwin/arm64
```

This information is automatically injected during the build process via ldflags in `.goreleaser.yml`.

## Troubleshooting

### Release Failed

Check the GitHub Actions logs:
1. Go to: `https://github.com/metalstormbass/snyft/actions`
2. Find the failed "Release" workflow
3. Review the logs for errors

Common issues:
- Tag format must be `v*` (e.g., v1.0.0, not 1.0.0)
- Main branch must be in a clean state
- go.mod must be valid and tidy

### Fixing a Bad Release

If a release is created with issues:

1. Delete the GitHub release (if draft wasn't used)
2. Delete the tag locally and remotely:
   ```bash
   git tag -d v1.0.0
   git push origin :refs/tags/v1.0.0
   ```
3. Fix the issues
4. Create and push the tag again

## Testing Before Release

Test the build locally (optional):

```bash
# Install goreleaser
brew install goreleaser  # macOS
# or download from https://goreleaser.com/install/

# Test snapshot build (doesn't require a tag)
goreleaser release --snapshot --clean

# Check the dist/ directory for built binaries
ls -la dist/
```

## Pre-release Versions

For beta or release candidate versions, use:

```bash
git tag -a v1.0.0-beta.1 -m "Release v1.0.0-beta.1"
git push origin v1.0.0-beta.1
```

GoReleaser will automatically mark these as pre-releases on GitHub.
