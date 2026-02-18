# Snyft Check Audit Report

Generated: 2026-02-18 (updated from 2026-02-17)

This document audits all scoring categories for checks that consistently return zero findings. Each issue is classified as **Broken** (data never flows correctly), **Stub** (not yet implemented), **Fixed** (resolved), or **Working**.

---

## Category 1: Publisher Control — WORKING (with caveats)

### Fixed: Email domain check now includes email when available

**Status:** FIXED

`extractMaintainers` (npm.go:277-292) now formats maintainers as `"username <email@domain.com>"` when email is available, which the email domain analyzer can parse. However, npm's public API often returns empty emails due to privacy changes (~2022), so this check works when email data is present but may not produce findings for all packages. This is an API limitation, not a code bug.

### Fixed: GitLab/Bitbucket no longer over-penalized for signing

**Status:** FIXED

`CheckSignedCommits` and `CheckSignedReleases` for GitLab and Bitbucket now return errors instead of `(false, 0, nil)`. This causes `SigningChecked` to remain `false` in the publisher control analysis, which means no +0.5 signing penalty is applied. The scoring correctly treats these platforms as "unchecked" rather than "checked and found no signing."

**Files changed:** `pkg/fetcher/gitlab.go`, `pkg/fetcher/bitbucket.go`

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

## Category 4: Install Execution — PARTIALLY FIXED

### Bug: PyPI `setup.py` analysis skipped for packages without repo URL

**Status:** OPEN

**File:** `pkg/analyzer/analyzer.go:208-217`

The `setup.py` analysis is gated behind `if repoURL != ""`. Packages without a repo URL — common for small packages — never have `setup.py` analyzed.

### Fixed: Maven "single benign script" path now reachable

**Status:** FIXED

`metadata.HasInstallScripts = true` is now set whenever a `pom.xml` is found, regardless of whether dangerous patterns are detected. This makes the 1-risk-point path for "single benign install script" reachable for Maven packages.

**File changed:** `pkg/analyzer/analyzer.go`

---

## Category 5: Dependency Sprawl — PARTIALLY BROKEN

### Bug: Lock file analysis always skipped for direct scans

**Status:** OPEN

**File:** `pkg/analyzer/analyzer.go:401-403`

`analyzeDependencySprawl` returns immediately when `dep.Source == ""`. When scanning a package by name (the typical CLI usage), `dep.Source` is always empty. **Lock file analysis is effectively always skipped.**

**Recommendation:** Attempt to locate a lock file relative to the working directory when `dep.Source` is empty.

### Fixed: npm download count now fetched from API

**Status:** FIXED (prior to this audit)

`NPMClient.fetchDownloadCount()` (npm.go:132-154) fetches the last-month download count from `https://api.npmjs.org/downloads/point/last-month/{name}`. The `DownloadCount > 1000000` fallback check now works correctly.

---

## Category 6: Provenance — PARTIALLY FIXED

### Fixed: GitLab/Bitbucket provenance now checks CI config files

**Status:** FIXED (prior to this audit)

`GetProvenanceInfo` for both GitLab and Bitbucket now:
- Fetches `.gitlab-ci.yml` / `bitbucket-pipelines.yml` and checks for cosign/sigstore keywords
- Checks for SLSA generator usage in CI pipelines
- Checks for `cosign.pub` or `.cosign/` directory presence

Packages that use Sigstore or SLSA in their CI pipelines will now receive provenance credit. Packages without these tools still receive 2 risk points, which is correct (no verifiable provenance).

### Note: SLSA detection requires specific file patterns

**Status:** KNOWN LIMITATION

The SLSA attestation check on GitHub requires `.slsa-provenance.json` or `.github/workflows/slsa*.yml` files. Repos using SLSA generators without these specific naming patterns may not be detected.

### Fixed: PyPI signature check now includes Trusted Publisher attestations

**Status:** FIXED

`CheckPyPISignatures` now checks for PEP 740 Trusted Publisher attestations (the `provenance` field on release URLs) in addition to the deprecated PGP `has_sig` field. Packages using PyPI's Trusted Publisher mechanism will now receive provenance credit.

**File changed:** `pkg/fetcher/pypi.go`

---

## Category 7: Health — STUB (GitLab/Bitbucket)

### Bug: PR stats stubs for GitLab/Bitbucket

**Status:** OPEN

**File:** `pkg/fetcher/gitlab.go:616-620`, `pkg/fetcher/bitbucket.go:574-576`

`GetPullRequestStats` returns empty `PRStats{}` for both platforms. `CodeReviewRate`, `RequiredReviewers`, and `HasBranchProtection` are always zero/false.

### Bug: CI quality always 5/10 for GitLab/Bitbucket

**Status:** OPEN

`AnalyzeCIQuality` returns a hardcoded `QualityScore = 5` when CI is found for these platforms. The health scoring requires `>= 7` to award a CI quality point. **GitLab/Bitbucket repos with CI can never earn the CI health point.**

**Recommendation:** Implement basic GitLab MR stats via `/projects/{id}/merge_requests` API. Implement Bitbucket PR stats via `/repositories/{owner}/{slug}/pullrequests` API.

---

## Category 8: Governance — PARTIALLY BROKEN

### Bug: Issue response time only measured for GitHub

**Status:** OPEN

**File:** `pkg/analyzer/governance.go:49-55`

Issue response time analysis is behind a `gitClient.GetPlatformName() == "GitHub"` guard. The responsiveness component is **structurally unavailable for all non-GitHub repos**, consistently contributing 0 toward governance score improvement.

**Recommendation:** Implement issue/MR response time for GitLab (`/projects/{id}/issues`) and Bitbucket (`/repositories/{owner}/{slug}/issues`).

---

## Category 9: Release Security — PARTIALLY FIXED

### Bug: `HasReleaseProcess` uses release existence, not CI automation

**Status:** MITIGATED (OSSF fallback added)

**File:** `pkg/analyzer/analyzer.go:465-468`, `pkg/analyzer/release_security.go`

`HasAutomatedReleases` checks if any GitHub releases exist — not whether they are CI-driven. Manual releases satisfy this check, defeating the intent of "CI publishing." **Mitigated:** OSSF Scorecard "Packaging" check is now used as a fallback when `HasReleaseProcess` is false, which specifically evaluates automated packaging pipelines.

### Bug: Two components always false for GitLab/Bitbucket

**Status:** MITIGATED (OSSF fallbacks added)

`HasBranchProtection` and `SignedReleases` depend on `GetPullRequestStats` and `GetProvenanceInfo`. PR stats are still stubs for GitLab/Bitbucket, but provenance now checks CI config files for signing tooling. **Mitigated:** All four components now have OSSF Scorecard fallbacks: "Branch-Protection" for branch protection, "Signed-Releases" for signing, "Code-Review" for reviewers, and "Packaging" for release process. Additionally, code review rate (>= 75%) serves as a fallback for the required reviewers component.

**Remaining:** Direct GitLab/Bitbucket API implementations for branch protection (`/projects/{id}/protected_branches`) and PR stats would improve accuracy beyond OSSF fallbacks.

---

## Category 10: Package Maturity — WORKING

Logic is structurally sound. Three sub-checks (age, staleness, cadence regularity) independently assess risk and take the maximum. Defaults to 1 risk point when publish/commit data is missing.

---

## Cross-Cutting Issue: GitLab and Bitbucket Structural Bias

Any package hosted on GitLab or Bitbucket is biased toward higher risk scores, though the bias has been significantly reduced:

**Remaining affected categories for GitLab/Bitbucket:**
- ~~PublisherControl: signing always marked absent (+0.5)~~ → **FIXED** (now treated as unchecked)
- ~~Provenance: always max risk (+2)~~ → **PARTIALLY FIXED** (checks CI config for cosign/sigstore/SLSA)
- Health: PR stats absent, CI quality capped at 5/10
- Governance: issue response time unavailable
- ReleaseSecurity: branch protection always false

**Recommendation:** Create a milestone to implement remaining stub methods for GitLab and Bitbucket, prioritizing PR stats and branch protection.

---

## Priority Fix List

| Priority | Category | Issue | Status |
|----------|----------|-------|--------|
| ~~P0~~ | ~~Provenance~~ | ~~GitLab/Bitbucket always get max risk~~ | **FIXED** (CI config checks added) |
| ~~P1~~ | ~~Dependency Sprawl~~ | ~~npm download count always 0~~ | **FIXED** (fetchDownloadCount) |
| ~~P1~~ | ~~Publisher Control~~ | ~~npm email domain check skipped~~ | **FIXED** (email format) |
| ~~P1~~ | ~~Publisher Control~~ | ~~GitLab/Bitbucket signing penalty~~ | **FIXED** (return errors) |
| ~~P3~~ | ~~Install Execution~~ | ~~Maven HasInstallScripts unreachable~~ | **FIXED** (set before danger check) |
| ~~P3~~ | ~~Provenance~~ | ~~PyPI has_sig deprecated~~ | **FIXED** (PEP 740 attestations) |
| P0 | Dependency Sprawl | `dep.Source` always empty → lock file always skipped | OPEN |
| P1 | Ownership Changes | PyPI `Uploader` field doesn't exist | OPEN |
| P2 | Health | GitLab/Bitbucket PR/CI stubs | OPEN |
| P2 | Governance | Issue response only for GitHub | OPEN |
| ~~P2~~ | ~~Release Security~~ | ~~`HasReleaseProcess` too broad~~ | **MITIGATED** (OSSF Packaging fallback) |
| ~~P2~~ | ~~Release Security~~ | ~~GitLab/Bitbucket branch protection stubs~~ | **MITIGATED** (OSSF fallbacks for all 4 components) |
| P3 | Install Execution | PyPI setup.py skipped without repo URL | OPEN |

---

## Alignment with Project Mission

All 10 scoring categories have been validated against the project instructions (CLAUDE.md):

| Category | Assesses Compromise Likelihood? | Academic Source | Verdict |
|----------|--------------------------------|----------------|---------|
| Publisher Control | Yes — account takeover risk | Ohm et al. 2020 | Aligned |
| Ownership Changes | Yes — malicious acquisition | Ohm et al. 2020 | Aligned |
| Release Anomalies | Yes — dormant reactivation | Ohm et al. 2020 | Aligned |
| Install Execution | Yes — direct code execution | NDSS 2020 | Aligned |
| Dependency Sprawl | Yes — attack surface | Zimmermann et al. 2019 | Aligned |
| Provenance | Yes — build integrity | SLSA, Sigstore | Aligned |
| Health | Yes — code review barriers | OSSF Scorecard | Aligned |
| Governance | Yes — maintainer responsiveness | Ohm et al. 2020 | Aligned |
| Release Security | Yes — publishing pipeline | SLSA, NDSS 2020 | Aligned |
| Package Maturity | Yes — vetting & staleness | Ohm et al. 2020 | Aligned |

**No categories track CVEs or known vulnerabilities. All assess supply chain compromise likelihood.**
