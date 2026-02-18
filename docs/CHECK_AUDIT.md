# Snyft Check Audit Report

Generated: 2026-02-17

This document audits all scoring categories for checks that consistently return zero findings. Each issue is classified as **Broken** (data never flows correctly), **Stub** (not yet implemented), or **Working**.

---

## Category 1: Publisher Control — PARTIALLY BROKEN

### Bug: Email domain check silent for npm packages

**File:** `pkg/fetcher/npm.go:170-178`, `pkg/analyzer/publisher_control.go:287`

`extractMaintainers` returns `m.Name` (the npm username, e.g. `"sindresorhus"`), never `m.Email`. The email domain analysis in `publisher_control.go` splits on `@` and skips any string without `@`. **The email domain risk check produces no findings for any npm package.**

### Bug: GitLab/Bitbucket always over-penalized for signing

**File:** `pkg/fetcher/gitlab.go:508-518`, `pkg/fetcher/bitbucket.go:481-488`

`CheckSignedCommits` is a stub returning `(false, 0, nil)` for both platforms. This adds +0.5 (no signing) to every GitLab/Bitbucket package without checking actual practices.

**Recommendation:** Fix npm maintainer data to include email when available. Add NOOP signing stubs that return `(false, 0, fmt.Errorf("not supported"))` so the scoring treats it as unknown rather than penalizing.

---

## Category 2: Ownership Changes — BROKEN (PyPI)

### Bug: PyPI `Uploader` field never populated

**File:** `pkg/fetcher/pypi.go:437`

The `file.Uploader` field doesn't exist in PyPI's public API response. It's always `""`, so the `if author != ""` guard prevents any release entries from being recorded. **PyPI ownership transfer detection silently finds zero releases and zero author changes for every package.**

**Recommendation:** Use the `uploaded_via` field or the package `author` field from the top-level info object instead.

---

## Category 3: Release Anomalies — WORKING

Logic is structurally sound. Defaults to 1 risk point (`Verified: false`) when no repository URL is available, which is the correct conservative behavior.

---

## Category 4: Install Execution — PARTIALLY BROKEN

### Bug: PyPI `setup.py` analysis skipped for packages without repo URL

**File:** `pkg/analyzer/analyzer.go:181-189`

The `setup.py` analysis is gated behind `if repoURL != ""`. Packages without a repo URL — common for small packages — never have `setup.py` analyzed.

### Bug: Maven "single benign script" path unreachable

**File:** `pkg/analyzer/analyzer.go:212-218`

`metadata.HasInstallScripts = true` is only set when dangerous patterns are already found in `pom.xml`. The 1-risk-point path for a single benign install script is **structurally unreachable for Maven packages**.

**Recommendation:** Set `HasInstallScripts = true` whenever a `pom.xml` is found, before the dangerous pattern check.

---

## Category 5: Dependency Sprawl — BROKEN

### Bug: Lock file analysis always skipped for direct scans

**File:** `pkg/analyzer/analyzer.go:401-403`

`analyzeDependencySprawl` returns immediately when `dep.Source == ""`. When scanning a package by name (the typical CLI usage), `dep.Source` is always empty. **Lock file analysis is effectively always skipped.**

### Bug: npm download count always 0

**File:** `pkg/fetcher/npm.go:109`

`NPMPackage.Downloads` is hardcoded to `0`. The fallback check `DownloadCount > 1000000` at `analyzer.go:1197` is therefore **never true for npm packages**, making the fallback always produce "low popularity" results regardless of actual download counts.

**Recommendation:** Fetch download counts from the npm downloads API (`https://api.npmjs.org/downloads/point/last-month/{name}`). For the `dep.Source` issue, attempt to locate a lock file relative to the working directory when `dep.Source` is empty.

---

## Category 6: Provenance — BROKEN (GitLab/Bitbucket, PyPI sigs)

### Bug: GitLab/Bitbucket always score maximum provenance risk

**File:** `pkg/fetcher/gitlab.go:430-447`, `pkg/fetcher/bitbucket.go:410-424`

`GetProvenanceInfo` for both platforms only sets `BuildSystem` and returns. All boolean provenance fields (`HasSLSAAttestation`, `HasSigstoreSignature`, etc.) remain false. **GitLab and Bitbucket packages always receive 2 risk points (worst) for provenance.**

### Bug: SLSA check has unreachable positive path on GitHub

**File:** `pkg/fetcher/github.go:512-517`

The SLSA attestation check has an `// unreachable` comment followed by `return false, ""`. Repos with `.github/workflows` but no specific SLSA workflow file always return `HasSLSAAttestation = false`. This is intentional but worth noting — only actual SLSA attestation files trigger detection.

### Bug: PyPI `has_sig` deprecated and always false

PyPI deprecated GPG signatures in May 2023. The `has_sig` field now always returns `false`, making `CheckPyPISignatures` always return `(false, 0, 0, nil)`.

**Recommendation:** For GitLab, check for Sigstore/cosign config files or `.gitlab-ci.yml` patterns for signing steps. For PyPI, check for Sigstore attestations (new PyPI standard) instead of `has_sig`.

---

## Category 7: Health — STUB (GitLab/Bitbucket)

### Bug: PR stats stubs for GitLab/Bitbucket

**File:** `pkg/fetcher/gitlab.go:595-599`, `pkg/fetcher/bitbucket.go:555-557`

`GetPullRequestStats` returns empty `PRStats{}` for both platforms. `CodeReviewRate`, `RequiredReviewers`, and `HasBranchProtection` are always zero/false.

### Bug: CI quality always 5/10 for GitLab/Bitbucket

`AnalyzeCIQuality` returns a hardcoded `QualityScore = 5` when CI is found for these platforms. The health scoring requires `>= 7` to award a CI quality point. **GitLab/Bitbucket repos with CI can never earn the CI health point.**

**Recommendation:** Implement basic GitLab MR stats via `/projects/{id}/merge_requests` API. Implement Bitbucket PR stats via `/repositories/{owner}/{slug}/pullrequests` API.

---

## Category 8: Governance — PARTIALLY BROKEN

### Bug: Issue response time only measured for GitHub

**File:** `pkg/analyzer/governance.go:49-55`

Issue response time analysis is behind a `gitClient.GetPlatformName() == "GitHub"` guard. The responsiveness component is **structurally unavailable for all non-GitHub repos**, consistently contributing 0 toward governance score improvement.

**Recommendation:** Implement issue/MR response time for GitLab (`/projects/{id}/issues`) and Bitbucket (`/repositories/{owner}/{slug}/issues`).

---

## Category 9: Release Security — PARTIALLY BROKEN

### Bug: `HasReleaseProcess` uses release existence, not CI automation

**File:** `pkg/analyzer/analyzer.go:465-468`

`HasAutomatedReleases` checks if any GitHub releases exist — not whether they are CI-driven. Manual releases satisfy this check, defeating the intent of "CI publishing."

### Bug: Two components always false for GitLab/Bitbucket

`HasBranchProtection` and `SignedReleases` depend on `GetPullRequestStats` and `GetProvenanceInfo`, both stubs for GitLab/Bitbucket. **Two of the four scored components are always false for non-GitHub packages.**

**Recommendation:** Check for release automation by correlating CI files with release workflow patterns (e.g., `on: release:` trigger in GitHub Actions). Implement branch protection checks for GitLab (`/projects/{id}/protected_branches`) and Bitbucket.

---

## Cross-Cutting Issue: GitLab and Bitbucket Structural Bias

Any package hosted on GitLab or Bitbucket is biased toward higher risk scores regardless of actual security practices, because 6+ interface methods are stubs returning zero values. Data that would reduce risk is never collected.

**Affected categories for GitLab/Bitbucket:**
- PublisherControl: signing always marked absent (+0.5)
- Provenance: always max risk (+2)
- Health: PR stats absent, CI quality capped at 5/10
- Governance: issue response time unavailable
- ReleaseSecurity: branch protection and signed releases always false

**Recommendation:** Create a milestone to implement stub methods for GitLab and Bitbucket, prioritizing the highest-impact ones (PR stats, provenance, branch protection).

---

## Priority Fix List

| Priority | Category | Issue | Impact |
|----------|----------|-------|--------|
| P0 | Dependency Sprawl | `dep.Source` always empty → lock file always skipped | Core check never runs |
| P0 | Provenance | GitLab/Bitbucket always get max risk | All non-GitHub packages over-scored |
| P1 | Ownership Changes | PyPI `Uploader` field doesn't exist | PyPI ownership detection broken |
| P1 | Dependency Sprawl | npm download count always 0 | Fallback logic never works |
| P1 | Publisher Control | npm email domain check skipped | Email risk never evaluated |
| P2 | Health | GitLab/Bitbucket PR/CI stubs | Non-GitHub health always worst |
| P2 | Governance | Issue response only for GitHub | Non-GitHub governance incomplete |
| P2 | Release Security | `HasReleaseProcess` too broad | Manual releases count as CI |
| P3 | Install Execution | Maven `HasInstallScripts` unreachable | Benign Maven scripts not scored |
| P3 | Provenance | PyPI `has_sig` deprecated | PyPI sig check always false |
