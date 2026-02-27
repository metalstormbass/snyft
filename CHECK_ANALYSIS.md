# Snyft Risk Check Analysis — Real-World Accuracy Review

## Test Methodology

Ran `snyft scan` against 13 real-world packages across 3 ecosystems, without a `GITHUB_TOKEN`, to evaluate whether each risk check produces accurate and meaningful results.

**npm packages tested**: express, lodash, is-odd, event-stream, colors
**PyPI packages tested**: requests, flask, cryptography, pyyaml, urllib3
**Maven packages tested**: guava, commons-lang3, jackson-databind

Each package was analyzed against all 11 risk categories (0-2 points each, 0-22 total).

---

## Results Summary

| Package | Ecosystem | Score | Risk | Assessment |
|---------|-----------|-------|------|------------|
| express@4.18.2 | npm | 15/22 | HIGH | **WRONG** — Express is one of the most established npm packages |
| lodash@4.17.21 | npm | 9/22 | LOW | Plausible, but wrong sub-scores |
| is-odd@3.0.1 | npm | 12/22 | MEDIUM | Reasonable |
| event-stream@4.0.1 | npm | 12/22 | MEDIUM | Reasonable |
| colors@1.4.0 | npm | 11/22 | MEDIUM | Reasonable |
| requests@2.31.0 | pypi | 10/22 | MEDIUM | Slightly high |
| flask@3.0.0 | pypi | 11/22 | MEDIUM | Slightly high |
| cryptography@41.0.7 | pypi | 9/22 | LOW | Reasonable |
| pyyaml@6.0.1 | pypi | 9/22 | LOW | Reasonable |
| urllib3@2.1.0 | pypi | 9/22 | LOW | Reasonable |
| guava@32.1.3-jre | maven | 13/22 | MEDIUM | Too high — Guava is Google's core library |
| commons-lang3@3.14.0 | maven | 10/22 | MEDIUM | Slightly high |
| jackson-databind@2.16.1 | maven | 12/22 | MEDIUM | Too high — Jackson is extremely mature |

---

## Critical Issues Found

### ISSUE 1: `package_maturity` — Uses version publish date instead of package creation date [BUG]

**Severity**: Critical — produces completely wrong results
**Affected**: All ecosystems
**File**: `pkg/analyzer/package_maturity.go:45-67`, `pkg/fetcher/npm.go:116-118`

**Problem**: The `PublishedAt` field stores the publish date of the *specific version being checked*, not the package's original creation date. The `scorePackageMaturity()` function uses this value as "time since first publish" for the age check.

**Evidence**:
- Express: `published_at: 2025-12-01` → "Package age: 88 days (very new, <6 months)" → 2 risk points
  - Express was first published in **2010**, not 88 days ago. The date is for v5.2.1's latest release.
- Lodash: `published_at: 2026-01-21` → "Package age: 37 days (very new)" → 2 risk points
  - Lodash was first published in **2012**.

**Root cause in code**: `pkg/fetcher/npm.go:116-118`:
```go
if timeStr, ok := npmResp.Time[npmResp.DistTags.Latest]; ok {
    pkg.PublishedAt = t  // This is the LATEST VERSION's date, not the package creation date
}
```
The npm API `time` object has a `"created"` field with the original package creation timestamp, but it's not being used.

**Fix**: Use `npmResp.Time["created"]` for package age calculation. Similar fixes needed for PyPI and Maven.

---

### ISSUE 2: `ci_pipeline_security` — SHA-pinned actions flagged as "unpinned" [BUG]

**Severity**: Critical — penalizes the most secure CI practice
**Affected**: Any package using SHA-pinned GitHub Actions (industry best practice)
**File**: `pkg/fetcher/ci_workflow_parser.go:62-87`

**Problem**: Actions pinned to a full SHA with a trailing comment (e.g., `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2`) are flagged as "unpinned". The regex captures the entire `ref` including the YAML comment, making the SHA check fail.

**Evidence**:
- Express scores 2/2 with "8 unpinned actions" — but ALL 8 actions are SHA-pinned:
  ```
  actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
  actions/setup-node@6044e13b5dc448c55e2357c09f80417699197238 # v6.2.0
  ```
  These use full 40-char SHA pins, which is the **most secure practice** per GitHub's security hardening guide.

**Root cause in code**: `pkg/fetcher/ci_workflow_parser.go:78-86`:
```go
ref := strings.TrimSpace(matches[2])
// ref = "de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2"
//                                                 ^--- YAML comment included
if !isSHAPin(ref) {  // Fails because len > 40 due to comment
    risk.UnpinnedActions = append(...)
}
```

**Fix**: Strip YAML comments from `ref` before checking: `ref = strings.Split(ref, "#")[0]` then `TrimSpace`.

---

### ISSUE 3: `publisher_control` — Always scores 2/2 even for well-maintained packages [SCORING]

**Severity**: High — no differentiation between well-maintained and risky packages
**Affected**: All ecosystems
**File**: `pkg/analyzer/publisher_control.go:550-670`

**Problem**: The scoring accumulates penalties from multiple independent sub-factors that almost always apply to open-source packages. Even with 5 maintainers (good!), a package gets penalized for: personal account (+0.3), personal emails (+0.3), no signing (+0.5), high package concentration (+0.2). Total: 1.3 → maps to 2/2 (HIGH risk).

**Evidence**:
- Express (5 maintainers, 16+ years old, massive community): **2/2 — "personal account; personal email; high-value target; no signing"**
- `is-odd` (2 maintainers, archived, tiny): **2/2**
- Both score identically despite vastly different risk profiles.

**Root cause**: The threshold at line 664 (`if riskScore >= 1.3 → 2 points`) is too easy to reach. Personal emails and lack of GPG signing are the **norm** for open source, not risk signals. A package with 10 maintainers using gmail still gets the maximum penalty.

**Fix options**:
1. Don't penalize personal email domains at all (they're the norm in OSS)
2. Give a stronger reward for high maintainer counts (negative risk score) that offsets email/signing penalties
3. Only count signing penalty when combined with single maintainer
4. Raise the HIGH threshold from 1.3 to 1.8

---

### ISSUE 4: `health` — Bus factor always wrong (1 for all packages) [DATA]

**Severity**: High — health check has no useful data
**Affected**: All packages when running without GITHUB_TOKEN
**File**: `pkg/analyzer/health.go:35-74`

**Problem**: `BusFactor` is 1 and `TopContributorPct` is 100% for ALL packages, including express (300+ contributors) and flask (700+ contributors). The commit analysis API returns degraded data when rate-limited, producing "bus factor 1" for everything.

**Evidence**:
- Express: `bus_factor: 1, top_contributor_pct: 100` → "Poor health: concentrated development" → 2/2
  - Reality: Express has 296 contributors and distributed development
- All 13 tested packages: bus_factor=1 or 0, top_contributor_pct=100 or 0

**Root cause**: The GitHub API's commit endpoint returns rate-limit errors (429). The fetcher falls back to scraping which returns minimal data. Only last 100 commits are sampled even when the API works, which can misrepresent large projects.

Additionally, `CodeReviewRate` is 0 and `HasBranchProtection` is false for ALL packages. Branch protection requires admin API access (returns 404/401 for non-admins even with a token).

**Fix options**:
1. Use the OSSF Scorecard `Code-Review` and `Branch-Protection` scores as primary data source (these work without auth)
2. If bus factor data is unavailable AND the package has many maintainers (e.g., 5+), award the bus factor point
3. Clearly indicate when the health score is based on degraded data

---

### ISSUE 5: `provenance` — Always 1/2 because signature checks never find data [DATA]

**Severity**: Medium — check is correct but provides no differentiation
**Affected**: All 13 packages
**File**: `pkg/analyzer/provenance_scoring.go`

**Problem**: Every package scores 1/2 ("source code available but build provenance unverifiable"). All sub-checks fail:
- SLSA attestation: FAIL (13/13)
- Sigstore signatures: FAIL (13/13)
- npm/PyPI provenance: FAIL (13/13)
- Signed releases: FAIL (13/13)
- Reproducible build: FAIL (13/13)
- OSSF Signed-Releases: FAIL (11/13)

**Assessment**: Some of these are legitimately missing (SLSA/Sigstore adoption is still low). However, some packages DO have provenance data that Snyft isn't detecting:
- npm packages published after 2023 may have npm provenance attestations
- cryptography and urllib3 publish PGP signatures on PyPI

**Fix**: Verify that the npm provenance API endpoint and PyPI signature checks are actually querying the right endpoints. The "all packages fail" pattern suggests the fetcher may not be calling these APIs at all.

---

### ISSUE 6: `release_security` — Branch protection always fails [DATA]

**Severity**: Medium — entire sub-check is non-functional
**Affected**: All packages
**File**: `pkg/analyzer/release_security.go:85-107`

**Problem**: `HasBranchProtection` is false for ALL 13 packages. GitHub's branch protection API requires admin-level repository access, which public API users never have. This means the sub-check always fails.

**Evidence**: Express, flask, cryptography, guava — all major projects with mandatory branch protection and required reviewers — all score FAIL.

**Fix**: Use OSSF Scorecard's `Branch-Protection` score as the primary data source (it uses its own privileged access). The code already has fallback logic for this (line 93-100) but the OSSF score threshold (>= 7) may be too strict.

---

### ISSUE 7: `ownership_changes` — Commit author analysis always UNAVAILABLE [DATA]

**Severity**: Medium — check degrades to only checking npm ownership history
**Affected**: 12/13 packages
**File**: `pkg/analyzer/ownership_changes.go:115-142`

**Problem**: The `GetCommitAuthors()` function returns empty stats (not an error) on rate limit, so the caller can't distinguish "no data available" from "no ownership changes found."

**Fix**: When the GitHub API returns 429, `GetCommitAuthors()` should return `fetcher.ErrDataUnavailable` instead of empty stats. This lets the scoring code properly mark the check as UNAVAILABLE rather than silently passing.

---

## Checks That Work Well

### `dependency_sprawl` — GOOD
Correctly identifies: express has many deps (2/2), lodash has few (0/2), flask moderate (1/2). Uses registry metadata that doesn't require GitHub API.

### `install_execution` — GOOD
Correctly identifies: pyyaml has setup.py with cmdclass overrides (2/2), requests has setup.py (1/2), most packages have no install scripts (0/2). Low-frequency signal but accurate.

### `release_anomalies` — GOOD
Correctly identifies: is-odd is dormant (1/2), event-stream is dormant (1/2), express shows dormancy reactivation (2/2 — though this could be debated). Active packages score 0/2.

### `governance` — MOSTLY GOOD
Uses OSSF Scorecard data for SECURITY.md detection, which works without GitHub tokens. Correctly identifies archived repos. The "abandoned project" flag for `requests` (a very actively maintained package) seems incorrect — may be a false positive from OSSF data.

### `package_maturity` (staleness sub-check only) — GOOD
The staleness check using `RepoLastCommit` works correctly for detecting stale packages. The problem is only with the age sub-check (Issue 1 above).

---

## Cross-Cutting Observations

### 1. Universal Check Failures (13/13 packages)
These checks fail for EVERY package tested, providing zero differentiation:
- `health/Review oversight`: FAIL (13/13)
- `provenance/SLSA attestation`: FAIL (13/13)
- `provenance/Sigstore signatures`: FAIL (13/13)
- `provenance/Signed releases`: FAIL (13/13)
- `provenance/Reproducible build`: FAIL (13/13)
- `release_security/Branch protection`: FAIL (13/13)
- `release_security/Signed releases`: FAIL (13/13)

A check that fails for every package — including the most well-maintained packages in the ecosystem — provides no useful signal.

### 2. Personal Email/Account Penalties Are OSS-Hostile
The publisher_control check penalizes personal email domains (+0.3) and personal accounts (+0.3). In the open-source world, this is the norm. Even Express (backed by the OpenJS Foundation) shows as "personal account" because the GitHub repo owner is a personal account. This penalty should be removed or only applied when combined with single-maintainer risk.

### 3. No GitHub Token = Broken Analysis
Without a `GITHUB_TOKEN`, 5 of 11 checks produce meaningless results (health, provenance, release_security, ownership_changes, ci_pipeline_security). The tool should either:
- Warn prominently that results are degraded
- Require a token for meaningful results
- Fall back to OSSF Scorecard data more aggressively (it works without auth)

---

## Recommended Fixes (Priority Order)

### P0 — Bugs Producing Wrong Results
1. **Fix `PublishedAt` to use package creation date** instead of latest version date (`npm.go`, `pypi.go`, `maven.go`)
2. **Fix SHA-pinned action detection** to strip YAML comments before checking (`ci_workflow_parser.go`)

### P1 — Scoring That Doesn't Differentiate
3. **Recalibrate `publisher_control` thresholds** — personal emails/accounts shouldn't push well-maintained packages to HIGH
4. **Use OSSF Scorecard as primary data source for `health` and `release_security`** when GitHub API data is unavailable

### P2 — Data Quality
5. **Fix `GetCommitAuthors()` to return `ErrDataUnavailable` on rate limit** instead of empty stats
6. **Verify npm provenance and PyPI signature API calls** are actually being made
7. **Add prominent warning** when running without GITHUB_TOKEN

### P3 — Design Improvements
8. **Don't penalize personal email domains** in publisher_control (they're the norm for OSS)
9. **Add OSSF fallback for branch protection** in release_security (lower threshold from >= 7 to >= 5)
10. **Consider making health check score UNAVAILABLE** instead of MAX RISK when data is missing
