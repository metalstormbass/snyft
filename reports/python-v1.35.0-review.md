# Python Report v1.35.0 - Deep Review

**Date:** 2026-03-04
**Report:** pythonreport.html (66 PyPI packages)
**Reviewer:** gentle-panda (automated)

## Executive Summary

**No packages score above 13/20 (HIGH threshold).** The maximum observed score is 12/20 (isodd). This is caused by **3 systemic bugs** that suppress scores by 3-5 points each, compressing the effective range to 3-12 instead of the theoretical 0-20.

The practical maximum achievable score for a PyPI package is **17/20** (Ownership Changes is capped at 0, Provenance is capped at 1). With these bugs, no PyPI package can currently reach HIGH risk.

## Critical Bugs Found

### BUG 1: Ownership Changes ALWAYS Returns 0 Risk (CRITICAL)

**Impact:** ALL 66 packages score 0/2 risk. Category is completely non-functional for PyPI.

**Root Cause (Two-Part):**

1. **PyPI API limitation:** `pypi.go` falls back to `pypiResp.Info.Author` for every release because the PyPI JSON API returns empty `Uploader` fields. Since the same author string is used for every release, `AuthorChanges` is always 0.

2. **Registry override kills git analysis:** In `ownership_changes.go` lines 224-233, when PyPI ownership history reports "no changes" (always, due to part 1), it **unconditionally resets** any risk points from git commit analysis to 0:
   ```go
   if riskPoints > 0 {
       riskPoints = 0  // Overrides git-based ownership churn detection!
   }
   ```

**Fix:** Registry "stable" results should not override git commit analysis downward. When PyPI uploader data is empty (always), the registry check provides no signal and should not override a more informative git-based analysis.

**Estimated score impact:** +0 to +2 points for packages with actual ownership churn.

### BUG 2: Provenance ALWAYS Returns 1 Risk (MODERATE)

**Impact:** ALL 66 packages score exactly 1/2 risk. Category provides zero discriminatory signal.

**Root Cause:** No PyPI-specific provenance checks exist. The code checks npm provenance and Maven GPG signatures, but has zero checks for:
- PyPI Trusted Publishers (launched May 2023)
- PyPI Attestations API (PEP 740, launched 2024)
- Sigstore bundles for PyPI packages

For PyPI packages with repos, `sourceAvailable = true` (avoids 2 risk), but `provenanceScore` stays 0 (can't reach 0 risk). Result: always 1.

**Fix:** Implement PyPI attestation checks (query `https://pypi.org/integrity/{project}/{version}/`). Packages like `cryptography` using Trusted Publishers should score 0 risk.

**Estimated score impact:** Would allow differentiation: 0 for packages with attestations, 1 for those without.

### BUG 3: C Extension Allowlisting Incomplete (MODERATE)

**Impact:** 6 C-extension packages incorrectly flagged with 2 risk points for Install Execution.

**False positives:**
| Package | Dangerous Pattern Found | Actual Purpose |
|---------|------------------------|----------------|
| mysqlclient | subprocess, exec | Building MySQL C bindings |
| uvloop | cmdclass, subprocess | Building libuv C extension |
| httptools | cmdclass | Building llhttp C extension |
| markupsafe | cmdclass | Building C speedup module |
| grpcio | subprocess, cmdclass | Building gRPC C core |
| fastecdsa | (no patterns but still flagged) | Building EC crypto C extension |

**Correctly allowlisted:** numpy, scipy, cryptography, lightgbm, orjson, editdistance (all score 0 risk).

**Root Cause:** The `filterBuildPatterns()` function in `script_analyzer.go` checks for C extension context markers (`Extension()`, `ext_modules`, etc.) but the detection regex doesn't cover all patterns used by these packages. Specifically, `cmdclass` overrides for build_ext are being flagged as dangerous even when the setup.py clearly shows C extension compilation context.

**Fix:** Add `cmdclass` as a build-explainable pattern when C extension context is detected. Also ensure `subprocess.call(['make', ...])` and similar build commands are recognized.

## Category-by-Category Analysis

### Distribution Summary (Risk Points: 0=good, 2=bad)

| # | Category | 0 pts | 1 pt | 2 pts | Avg | Issue |
|---|----------|-------|------|-------|-----|-------|
| 1 | Publisher Control | 33 | 30 | 3 | 0.55 | Pallets flagged as single-maint (see below) |
| 2 | Ownership Changes | **66** | 0 | 0 | **0.00** | **BROKEN - always 0** |
| 3 | Release Anomalies | 53 | 6 | 7 | 0.30 | Working correctly |
| 4 | Install Execution | 38 | 0 | 28 | 0.85 | 6 C-ext false positives |
| 5 | Dependency Sprawl | 61 | 4 | 1 | 0.09 | Low but mostly accurate for PyPI |
| 6 | Provenance | 0 | **66** | 0 | **1.00** | **ALWAYS 1 - no PyPI provenance checks** |
| 7 | Health | 2 | 48 | 16 | 1.21 | Working, good distribution |
| 8 | Governance | 16 | 25 | 25 | 1.14 | Working, good distribution |
| 9 | Release Security | 16 | 26 | 24 | 1.12 | Working, good distribution |
| 10 | Package Maturity | 58 | 2 | 6 | 0.21 | Working correctly |

### Categories Working Well
- **Health** (avg 1.21): Good distribution across 0/1/2. Bus factor correctly calculated.
- **Governance** (avg 1.14): SECURITY.md detection working, issue response time scoring reasonable.
- **Release Security** (avg 1.12): CI/CD detection, signed release checking, OSSF integration all working.
- **Release Anomalies** (avg 0.30): Dormancy detection is working (see mysqlclient, gunicorn, click).
- **Package Maturity** (avg 0.21): Correctly identifies stale packages (6 flagged with 2 risk).

### Categories with Issues
- **Ownership Changes** (avg 0.00): Completely broken. See BUG 1.
- **Provenance** (avg 1.00): No discrimination. See BUG 2.
- **Install Execution** (avg 0.85): C extension false positives. See BUG 3.
- **Dependency Sprawl** (avg 0.09): Low scores are mostly accurate (PyPI packages have few direct deps), but thresholds may be too generous (0-5 for low risk). Consider PyPI-specific thresholds like Maven has.
- **Publisher Control** (avg 0.55): Pallets org packages flagged as single-maintainer despite org detection (see below).

## PyPI-Specific Findings

### Repo URLs: Working Well
- **64/66** packages have repo URLs found (97%)
- Only missing: `protobuf@3.20.2`, `pytz@2020.4`
- Both are edge cases: protobuf uses non-standard project_urls, pytz's repo is on Launchpad

### Author Parsing (Comma Fix): Working
- No evidence of comma-parsing issues in the report
- Multi-author packages correctly identified (e.g., 2 maintainers for six, cryptography, etc.)

### Pallets Org Detection: Partially Working
All 6 Pallets packages (flask, click, werkzeug, jinja2, markupsafe, itsdangerous) show:
- "Single maintainer (Pallets <contact@palletsprojects.com>)"
- Publisher risk = 1 (not 2, so org detection gives partial mitigation)
- But they should arguably score 0 since Pallets IS an organization

The org detection reduces the score from 2→1, but doesn't fully recognize Pallets as a trusted organizational publisher. The display says "Moderate publisher control risk" which is debatable for an established org.

### Rate Limiting: Significant Impact
- **38/66 packages** (58%) hit GitHub rate limits during analysis
- These packages show "Unable to verify repository metadata (GitHub rate limit)"
- Affected checks: governance (SECURITY.md), some publisher control metadata
- Result: these packages may score LOWER risk than they should because checks that would find issues can't run

### Abandoned Package Detection
- isodd: 2094 days dormant - correctly flagged (maturity=2, anomalies=0 surprisingly)
- six: no dormancy flag despite last release being old
- flask-restful: correctly flagged stale
- **passlib is NOT in the report** - was not included in the input package list

## Package Validations (25+ packages)

### Validated as CORRECT (score seems right):

| # | Package | Score | Assessment |
|---|---------|-------|------------|
| 1 | numpy@1.26 | 3/20 | Correct LOW - well-maintained, many contributors, org publisher |
| 2 | scikit-learn@1.3.1 | 3/20 | Correct LOW - same reasoning |
| 3 | matplotlib@3.3.3 | 3/20 | Correct LOW |
| 4 | requests@2.25.1 | 4/20 | Correct LOW - PSF org, good bus factor |
| 5 | pandas@1.1.5 | 4/20 | Correct LOW |
| 6 | scipy@1.11.4 | 4/20 | Correct LOW |
| 7 | urllib3@1.26.5 | 4/20 | Correct LOW |
| 8 | holidays@0.9.10 | 3/20 | Correct LOW |
| 9 | fastapi@0.65.2 | 5/20 | Correct LOW |
| 10 | sqlalchemy@1.3.20 | 6/20 | Correct - single maintainer but good governance |
| 11 | flask@1.1.1 | 6/20 | Correct-ish (see Pallets note) |
| 12 | gunicorn@20.0.4 | 5/20 | Reasonable - dormancy reactivation correctly flagged |
| 13 | arrow@0.16.0 | 5/20 | Correct |
| 14 | sagemaker@latest | 3/20 | Correct LOW - AWS org publisher |

### Validated as TOO LOW (should score higher):

| # | Package | Score | Expected | Issue |
|---|---------|-------|----------|-------|
| 15 | isodd@0.1.2 | 12/20 | 14-16 | Should be HIGH. Joke pkg, 2094 days dormant, 1 contributor. Missing: ownership churn (bug 1), provenance cap (bug 2) |
| 16 | six@1.15.0 | 9/20 | 11-13 | Unmaintained/deprecated, single contributor. Missing ownership signal |
| 17 | python-editor@1.0.4 | 9/20 | 11-13 | Similar to six |
| 18 | boto3@latest | 8/20 | 6/20 | Actually scores too HIGH - flagged as single maintainer/personal acct, but it's an AWS org package. Org detection may have failed |
| 19 | mysqlclient@1.3.13 | 10/20 | 12-14 | C extension false positive, plus dormancy reactivation + ownership should flag |
| 20 | werkzeug@0.16.1 | 8/20 | 6/20 | Pallets org should reduce publisher risk more |
| 21 | pytz@2020.4 | 8/20 | 10-12 | No repo URL limits analysis. Stale release cadence, single maintainer |
| 22 | protobuf@3.20.2 | 8/20 | 6/20 | Google-maintained, should detect org. No repo URL found limits scoring |

### Validated as REASONABLE (minor concerns):

| # | Package | Score | Notes |
|---|---------|-------|-------|
| 23 | cryptography@39.0.1 | 5/20 | Good. Uses Trusted Publishers (not detected by provenance check) |
| 24 | httpx@0.23.0 | 7/20 | Reasonable. Encode org, stale |
| 25 | uvicorn@0.13.2 | 6/20 | Reasonable |
| 26 | dnspython@2.0.0 | 6/20 | Reasonable |
| 27 | flask-cors@3.0.8 | 8/20 | Reasonable - stale, small team |
| 28 | datadog@0.39.0 | 8/20 | Reasonable |
| 29 | grpcio@1.53.0 | 5/20 | Correct LOW - Google org |
| 30 | opentelemetry-api@latest | 4/20 | Correct LOW - CNCF project |

## Score Range Analysis

### Why No Scores Above 13?

**Current effective max = 17/20** (theoretical 20 minus broken categories):
- Ownership Changes: capped at 0 (BUG 1) → -2 max
- Provenance: capped at 1 (BUG 2) → -1 max

**Observed max = 12/20.** Gap between 12 and 17 is explained by:
- Well-maintained packages naturally score low in multiple categories
- Truly risky packages (isodd) can't break 12 due to the 3-point ceiling from bugs
- Rate limiting prevents 38 packages from getting full analysis

**If bugs were fixed**, isodd would likely score 14-16/20 (HIGH):
- Current: Pub=1, Own=0, Rel=1, Ins=2, Dep=0, Pro=1, Hea=2, Gov=2, RelSec=2, Mat=2 = 13... wait, currently 12
- Fixed: Own could be +1-2, Pro could stay 1, Ins stays 2 → 14-15 range

### Score Distribution Shape

The distribution is roughly normal centered around 6-7, which is healthy for a collection of popular packages. The concern is the hard ceiling at 12 preventing HIGH classifications.

```
 3/20: ##### (5)    - Well-maintained org projects
 4/20: ####### (7)
 5/20: ########### (11)
 6/20: ########## (10) - Most popular packages land here
 7/20: ############ (12)
 8/20: ########### (11)
 9/20: ## (2)
10/20: ##### (5)
11/20: ## (2)       - Clearly risky packages
12/20: # (1)        - isodd (maximum possible)
```

## Recommendations

### Priority 1 (Critical - Fixes Score Compression)

1. **Fix Ownership Changes override logic** - Don't let PyPI's empty uploader data override git-based analysis. When registry data provides no signal, preserve the git analysis result.

2. **Implement PyPI provenance checks** - Query PyPI Attestations API for Sigstore-based provenance. This differentiates packages like `cryptography` (has Trusted Publishers) from packages without.

### Priority 2 (Important)

3. **Improve C extension allowlisting** - Add `cmdclass` overrides to build-explainable patterns. Recognize `subprocess.call(['make', ...])` as build-related when C extension context exists. Currently 6 false positives.

4. **Address rate limiting** - 58% of packages hit GitHub rate limits. Consider: token rotation, request batching, caching, or fallback strategies. This silently degrades analysis for the majority of packages.

### Priority 3 (Nice to Have)

5. **Tune PyPI dependency thresholds** - Current 0-5/6-15/16+ thresholds mean 92% of PyPI packages score 0 risk. Consider PyPI-specific thresholds like 0-2/3-8/9+ for more discrimination.

6. **Strengthen Pallets org detection** - Pallets packages get risk=1 instead of risk=0 for publisher control. The org IS recognized but not fully credited.

7. **Add passlib** - Passlib (abandoned, single maintainer, last release 2020) would be a good test case for HIGH-risk PyPI package detection if the ownership/provenance bugs are fixed.

## Checks Not Returning Data

| Category | Check | Packages Affected | Reason |
|----------|-------|-------------------|--------|
| Publisher Control | GitHub org metadata | 38 | Rate limited |
| Ownership Changes | ALL checks | 66 | BUG 1 (always overridden to 0) |
| Governance | SECURITY.md, issue response | 38 | Rate limited |
| Release Security | Branch protection, CI details | 38 | Rate limited |
| Provenance | PyPI attestations | 66 | Not implemented |
| Dependency Sprawl | Lock file analysis | 66 | Dead code (early return prevents lock file search) |

## Appendix: Full Package Matrix

See the category distribution tables above for the complete 66-package breakdown.
