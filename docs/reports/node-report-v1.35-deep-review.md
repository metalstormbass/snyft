# Deep Review: Node.js Report v1.35.0

**Report Date:** Mar 4, 2026 | **Packages:** 456 | **Max Score:** 13/20 | **Reviewer:** wise-otter

## Executive Summary

The report correctly identifies supply chain risk signals but **scores are compressed into a narrow 3-13 range** (out of a theoretical 0-20). The maximum score observed is 13/20, and 49% of packages cluster at 8-9/20. Three root causes explain this compression:

1. **Health category review oversight never detects data** — 0 of 456 packages score 2/2 (0 risk)
2. **Provenance category never reaches max risk (0/2)** — structurally capped at 1/2 minimum
3. **Download counts are not surfaced** — tooltip mentions them but no actual data appears

---

## 1. Score Distribution

| Score | Count | % | Visual |
|-------|-------|---|--------|
| 13 | 2 | 0.4% | ██ |
| 12 | 35 | 7.7% | ███████ |
| 11 | 25 | 5.5% | █████ |
| 10 | 46 | 10.1% | ██████████ |
| 9 | 110 | 24.1% | ████████████████████████ |
| 8 | 113 | 24.8% | █████████████████████████ |
| 7 | 68 | 14.9% | ██████████████ |
| 6 | 34 | 7.5% | ███████ |
| 5 | 12 | 2.6% | ██ |
| 4 | 4 | 0.9% | █ |
| 3 | 7 | 1.5% | █ |

**Key observation:** 73% of packages score 7-10. The HIGH threshold (13+) is only reached by 2 packages. The effective scoring range is 10 points (3-13), not 20.

---

## 2. Category-by-Category Analysis

### Frequency of Risk Points Per Category

| Category | 2 risk (0/2) | 1 risk (1/2) | 0 risk (2/2) | Dominant | Issue? |
|----------|-------------|-------------|-------------|----------|--------|
| Publisher Control | 53.1% | 39.7% | 7.2% | Spread | OK |
| Ownership Changes | 2.0% | 2.9% | **95.2%** | Always 0 | Skewed low |
| Release Anomalies | 11.4% | 17.8% | **70.8%** | Usually 0 | Skewed low |
| Install Execution | 0.4% | 0.0% | **99.6%** | Always 0 | Expected |
| Dependency Sprawl | 0.7% | 4.4% | **95.0%** | Always 0 | Suspect |
| Provenance | **0.0%** | **95.2%** | 4.8% | Always 1 | **BROKEN** |
| Health | **74.8%** | 25.2% | **0.0%** | Always ≥1 | **BROKEN** |
| Governance | 61.0% | 32.2% | 6.8% | Usually 2 | OK |
| Release Security | **85.1%** | 13.2% | 1.8% | Usually 2 | OK (harsh) |
| Package Maturity | 16.9% | 2.4% | 80.7% | Usually 0 | Skewed low |

### Categories with Systematic Issues

#### CRITICAL: Health — Never Reaches 0 Risk (2/2)

**Problem:** The `CodeReviewRate` field is **always 0** for all 456 packages. Every single package shows "No review oversight detected" in findings. This means Health can never achieve both bus factor + review oversight = 0 risk.

**Root cause:** The `CodeReviewRate` is populated from GitHub PR scraping (`pkg/fetcher/github.go:2220`). For this scan, it appears the PR sampling either failed silently or returned 0 for all packages. The code at `health.go:96` requires `CodeReviewRate >= 75` but no package achieves this.

**Impact:** Health maxes out at 1/2 (1 risk point). Packages with bus factor ≥2 get 1/2 instead of the 2/2 they should get, adding 1 point to every score unnecessarily.

**Fix needed:** Investigate why `CodeReviewRate` is always 0. Possible causes:
- GitHub API rate limiting causing PR fetch to silently return empty
- Scraping logic failing for the PR review endpoint
- Data not being propagated from fetcher to metadata

#### CRITICAL: Provenance — Never Reaches Max Risk (0/2)

**Problem:** 0 out of 456 packages score 0/2 (2 risk points). 95.2% score exactly 1/2.

**Root cause:** The provenance scoring logic at `provenance_scoring.go:17-24` shows that max risk (2) requires **no source available AND no attestations**. Since ALL 456 packages have a repository URL (confirmed: 456/456 have repo URLs), `sourceAvailable` is always `true`, which means provenance can only score 0 or 1 risk — never 2.

**Impact:** The theoretical max score is 19, not 20, for any package with a repo URL. This is arguably **correct behavior** — a package with public source code is genuinely more auditable. However, it means the 0-20 scale is effectively 0-19.

#### MODERATE: Dependency Sprawl — 95% Score 0 Risk

**Problem:** 95% of packages get 2/2 (0 risk). The tooltip says "Falls back to direct dependency count from registry metadata (thresholds at 5/15 for npm)."

**Root cause:** Most npm packages have ≤5 direct dependencies. The thresholds (0-5 = low, 6-15 = medium, 16+ = high) based on **direct** deps are reasonable, but since there's no lock file analysis for individual packages in this scan, transitive dependency explosion isn't captured. A package with 3 direct deps that pull in 200 transitive deps scores 0 risk.

**Impact:** 2 risk points systematically suppressed for most packages.

#### MODERATE: Ownership Changes — 95.2% Score 0 Risk

**Problem:** Nearly all packages get 2/2 (0 risk, stable ownership).

**Analysis:** This is likely **accurate** for established npm packages. Most packages in a mature Node.js project have stable ownership. The 2% that trigger (9 packages) include `slice-ansi` which legitimately had team turnover. This category is working correctly but rarely triggers.

#### EXPECTED: Install Execution — 99.6% Score 0 Risk

Only 2 packages have install scripts (`fsevents`, `node-sass`). This is **correct** — most npm packages don't use install hooks.

---

## 3. Download Counts: NOT Showing

**Finding:** The Publisher Control tooltip mentions "npm weekly download volume (1M+/week mitigates single-maintainer risk)" but **zero actual download numbers appear anywhere in the report**. No findings mention specific download counts.

**Analysis:** The code enriches with Libraries.io data (`analyzer.go:769-785`) which requires `LIBRARIES_IO_API_KEY`. The download count appears to be:
1. Either not fetched (missing API key)
2. Or fetched but not surfaced in findings text

**Impact:** High-download packages like `express` (30M+/week), `lodash` (50M+/week), `debug` (200M+/week) that have single maintainers aren't getting the download-volume risk mitigation mentioned in the tooltip. This means single-maintainer risk may be **over-scored** for extremely popular packages, or **under-mitigated** — the download count could reduce Publisher Control from 2→1 risk for these packages.

---

## 4. Silent Failures Inventory

| Check | Working? | Evidence |
|-------|----------|----------|
| Maintainer count | YES | 53% single-maintainer correctly flagged |
| Org vs personal account | YES | Findings distinguish org/personal |
| Bus factor | YES | Values 1-16 observed |
| Code review rate | **NO** | Always 0% — never detected |
| npm provenance | PARTIAL | Always "no provenance" — none detected even for packages that have it |
| Signed releases | YES | Correctly identifies unsigned |
| Git commit history | YES | Dormancy/staleness detected |
| Install scripts | YES | fsevents, node-sass correctly flagged |
| OSSF Scorecard | YES | Scores ranging 2.0-7.2 observed |
| Dependency count | PARTIAL | Direct count only, no transitive |
| Download counts | **NO** | Zero data surfaced |
| Governance files | YES | SECURITY.md detection working |
| CI/CD workflow analysis | YES | GitHub Actions, Travis CI detected |
| Branch protection | PARTIAL | Via OSSF only |
| Release tag signing | YES | Working |

**Checks returning no data: 3** (code review rate, download counts, npm provenance detection)

---

## 5. Actual Maximum Achievable Score

Given the working checks:

| Category | Max Risk Achievable | Blocked By |
|----------|-------------------|------------|
| Publisher Control | 2 | — |
| Ownership Changes | 2 | — |
| Release Anomalies | 2 | — |
| Install Execution | 2 | — |
| Dependency Sprawl | 2 | — |
| Provenance | **1** | All packages have repo URLs |
| Health | **2** | — (but review data missing inflates this) |
| Governance | 2 | — |
| Release Security | 2 | — |
| Package Maturity | 2 | — |
| **Total** | **19** | Provenance caps at 1 |

**With all checks working properly**, a truly dangerous package could theoretically score 19/20. The current max of 13 is artificially low because:
- Health category over-penalizes by ~1 point (review data missing) ≈ **+1 point inflation across all packages**
- But this actually helps scores go up, not down
- The real issue is that **few packages are simultaneously bad across all categories**

---

## 6. Package Validation (27 Packages)

### Validation Against Known Facts

| Package | Score | Assessment | Accurate? | Notes |
|---------|-------|-----------|-----------|-------|
| express@4.17.1 | 10/20 | MEDIUM | **Reasonable** | Org-maintained, many deps, dormancy flagged |
| lodash@4.17.21 | 7/20 | LOW | **Slightly low** | Single maintainer risk underweighted |
| chalk@2.4.2 | 8/20 | LOW | **Reasonable** | Personal account, but active project |
| debug@4.1.1 | 6/20 | LOW | **Good** | Org-maintained, low deps |
| uuid@3.4.0 | 5/20 | LOW | **Good** | Multi-maintainer, well-governed |
| semver@5.7.1 | 3/20 | LOW | **Good** | npm org, strong governance |
| node-sass@4.14.1 | 8/20 | LOW | **Too low** | Deprecated, install scripts, should be higher |
| fsevents@2.1.3 | 9/20 | MEDIUM | **Reasonable** | Install scripts correctly flagged |
| boxen@1.3.0 | 13/20 | HIGH | **Good** | Single maintainer, stale, no controls |
| has-flag@3.0.0 | 13/20 | HIGH | **Good** | Abandoned sindresorhus micro-package |
| glob@7.1.6 | 11/20 | MEDIUM | **Reasonable** | isaacs single maintainer, anomalies |
| rimraf@2.7.1 | 11/20 | MEDIUM | **Reasonable** | Same pattern as glob |
| request@2.88.2 | 6/20 | LOW | **Too low** | Deprecated/abandoned, should score higher |
| eslint@5.16.0 | 6/20 | LOW | **Good** | Strong org, many maintainers |
| moment@2.29.4 | 6/20 | LOW | **Debatable** | In maintenance mode, could be higher |
| minimist@1.2.8 | 6/20 | LOW | **Reasonable** | Active recent maintenance |
| commander@3.0.2 | 5/20 | LOW | **Good** | Well-maintained, multiple contributors |
| nodemon@1.19.4 | 8/20 | LOW | **Reasonable** | Personal account but active |
| yargs@13.3.2 | 7/20 | LOW | **Good** | Org-maintained |
| cookie@0.4.0 | 9/20 | MEDIUM | **Good** | Small, personal, some anomalies |
| body-parser@1.19.0 | 9/20 | MEDIUM | **Reasonable** | Expressjs org package |
| mkdirp@0.5.5 | 8/20 | LOW | **Reasonable** | |
| ms@2.1.1 | 5/20 | LOW | **Good** | Vercel org |
| qs@6.7.0 | 7/20 | LOW | **Good** | |
| depd@2.0.0 | 12/20 | MEDIUM | **Good** | Single maintainer, stale |
| slice-ansi@2.1.0 | 12/20 | MEDIUM | **Good** | Team turnover correctly flagged |
| wrap-ansi@5.1.0 | 12/20 | MEDIUM | **Good** | Same pattern as slice-ansi |

**Accuracy assessment:** 22/27 packages (81%) have reasonable or good scores. 3 packages are scored too low (node-sass, request, lodash), 2 are debatable.

---

## 7. Why No Scores Above 13

### Mathematical Explanation

To score 14+, a package would need 14 risk points across 10 categories. That requires at least 7 categories at max risk (2) or equivalent. Looking at the top-scoring packages:

**boxen@1.3.0 (13/20):**
- 7 categories at max risk (2): Publisher Control, Health, Governance, Release Security, Package Maturity, + partial from Release Anomalies and Dependency Sprawl
- Ownership Changes gives 0 risk (stable) — hard to simultaneously be abandoned AND recently transferred
- Provenance gives 1 risk max (repo exists)

**The fundamental constraint:** Categories are partially anti-correlated. A package that is:
- Abandoned (Maturity=2, Governance=2) is unlikely to have ownership transfers (Ownership=0)
- Active with new owners (Ownership=2) is unlikely to be stale (Maturity=0)
- Well-governed (Governance=0) usually has CI/CD (Release Security=0)

This natural anti-correlation limits scores to ~13 in practice.

### Fixable Issues That Would Expand Range

1. **Fix CodeReviewRate data collection** → Health could reach 0 risk for well-reviewed projects, widening the gap between good and bad packages. Currently adds ~1 unearned risk point to well-maintained packages.

2. **Surface download counts** → Would reduce Publisher Control risk for high-download single-maintainer packages (express, lodash, etc.), lowering their scores and widening the gap from risky packages.

3. **Fix npm provenance detection** → No package in this scan has provenance detected. Packages like `semver` (npm org) likely DO have provenance. Fixing this would reduce Provenance to 0 risk for these packages.

4. **Transitive dependency analysis** → Currently only counts direct deps. A package with 3 deps that explode into 200 transitive deps scores the same as one with 3 deps total.

---

## 8. Recommendations (Priority Order)

### P0: Fix Code Review Rate Detection
- **Impact:** Affects 100% of packages (all show 0%)
- **Root cause:** `CodeReviewRate` in metadata is always 0
- **Investigation needed:** Check GitHub PR scraping in `pkg/fetcher/github.go:2220`, verify API responses

### P0: Fix npm Provenance Detection
- **Impact:** 0 packages detected with provenance out of 456 npm packages
- **Expected:** Several npm org packages (semver, etc.) should have provenance
- **Investigation needed:** Check `HasNPMProvenance` population path

### P1: Surface Download Count Data
- **Impact:** Publisher Control scoring for popular packages
- **Current state:** Tooltip describes it, code references it, but no data appears
- **Likely cause:** Missing `LIBRARIES_IO_API_KEY` or data not propagated to findings

### P2: Transitive Dependency Analysis
- **Impact:** Dependency Sprawl more accurate
- **Current:** 95% of packages score 0 risk on direct deps alone
- **Needed:** Parse lock files or use npm registry transitive resolution

### P3: Consider Adjusting Anti-Correlation
- The score range compression is partly natural (anti-correlated categories)
- Consider whether Package Maturity and Governance should be partially decoupled from staleness
- A package can be old+stable (low maturity risk) but have zero governance (high governance risk)

---

## 9. Score Range With All Fixes Applied

| Scenario | Min | Max | Effective Range |
|----------|-----|-----|-----------------|
| Current (broken checks) | 3 | 13 | 10 points |
| With review rate fixed | 3 | 13 | 10 points (but better differentiation) |
| With provenance fixed | 2 | 13 | 11 points |
| With download counts | 2 | 13 | 11 points |
| All fixes combined | **1** | **14-15** | **13-14 points** |

The anti-correlation ceiling means 17+ is extremely unlikely even with perfect data. A realistic expanded range would be **1-15/20** with all fixes, which is a meaningful improvement from the current 3-13 range.
