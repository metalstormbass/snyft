# Score Compression Analysis: Why No Packages Score Above 13 (HIGH)

**Report Date:** 2026-03-04
**Analyzed Report:** Java/mixed report v1.35.0 (87 packages, 3 ecosystems)
**Analyst:** happy-koala worker agent

## Executive Summary

The scoring system has a **structural compression problem** that makes it effectively impossible for real-world packages to reach the HIGH threshold (13+/20). The observed score range is **3-12** out of a theoretical 0-20. The root causes are:

1. **Provenance never returns 0 risk points** (always ≥1) — removes 1 point from the effective max
2. **Four categories are too easy to pass** (Install Execution, Dependency Sprawl, Release Anomalies, Package Maturity) — they collectively contribute only ~1.25 risk points on average
3. **Health and Release Security are biased toward high risk** but can't compensate because 4 other categories almost always return 0 risk
4. **Ownership Changes has high false-positive rate** on mature projects with contributor rotation

**Effective maximum achievable score: ~14-15 for real packages** (not 20), but in practice no package exceeds 12 because the categories that flag high risk don't co-occur with the categories that are hard to pass.

---

## 1. Category Score Distribution (All 87 Packages)

| Category | 0/2 (HIGH risk) | 1/2 (MED risk) | 2/2 (LOW risk) | Avg Score | Avg Risk |
|----------|:---:|:---:|:---:|:---:|:---:|
| **Release Security** | **53 (61%)** | 24 (28%) | 10 (11%) | 0.51 | **1.49** |
| **Health** | **35 (40%)** | **51 (59%)** | 1 (1%) | 0.61 | **1.39** |
| Publisher Control | 12 (14%) | 48 (55%) | 27 (31%) | 1.17 | 0.83 |
| Governance | 15 (17%) | 42 (48%) | 30 (34%) | 1.17 | 0.83 |
| Ownership Changes | 23 (26%) | 5 (6%) | 59 (68%) | 1.41 | 0.59 |
| Provenance | **0 (0%)** | 49 (56%) | 38 (44%) | 1.44 | 0.56 |
| Release Anomalies | 16 (18%) | 2 (2%) | **69 (79%)** | 1.61 | 0.39 |
| Package Maturity | 7 (8%) | 19 (22%) | **61 (70%)** | 1.62 | 0.38 |
| Install Execution | 12 (14%) | 0 (0%) | **75 (86%)** | 1.72 | 0.28 |
| Dependency Sprawl | 1 (1%) | 15 (17%) | **71 (82%)** | 1.80 | **0.20** |

### Key Observations

**Categories that ALWAYS return 0 risk:** None technically always return 0, but:
- **Provenance NEVER returns 0/2** (0% of packages). Min is always 1/2. This category structurally cannot assign maximum risk (2 risk points).
- **Dependency Sprawl almost never returns 0/2** (only 1 of 87 packages = 1%). Effectively a free pass.
- **Install Execution** is binary — 86% score 2/2 (no install scripts = no risk). Only flags when scripts exist.

**Categories biased toward HIGH risk (but can't compensate):**
- **Release Security:** 61% of packages score 0/2 (2 risk points). This is the hardest category to pass.
- **Health:** 40% score 0/2, 59% score 1/2, and **only 1% score 2/2**. Almost no package achieves full health marks.

---

## 2. Silent Failures and Defaults

### Are checks failing silently and defaulting to low risk?

**Yes, in specific categories:**

| Category | Default When No Data | Risk Points | Effect |
|----------|---------------------|:-----------:|--------|
| Publisher Control | 1 (moderate) | 1 | Neutral — reasonable default |
| Ownership Changes | 1 (moderate) | 1 | Neutral — reasonable default |
| Release Anomalies | 1 (moderate) | 1 | Neutral — reasonable default |
| Install Execution | **0 (low risk)** | **0** | **Deflates score** — no scripts ≠ no risk |
| Dependency Sprawl | 1 (moderate) | 1 | Neutral — reasonable default |
| Provenance | 1 (moderate, never 0 or 2) | 1 | **Caps range** — never returns worst case |
| Health | 1 (moderate, with guard) | 1 | Neutral — guard prevents 0 risk |
| Governance | 1 (moderate) | 1 | Neutral — reasonable default |
| Release Security | 1 (moderate) | 1 | Neutral — reasonable default |
| Package Maturity | 1 (moderate) | 1 | Neutral — reasonable default |

### Specific Checks Not Returning Data (Defaulting)

Based on findings in the report:

1. **GitHub rate limiting** affected multiple packages — 14 packages show "Unable to verify repository metadata (GitHub rate limit)" finding. This impacts:
   - Governance (issue response time)
   - Health (code review rate scraping)
   - Package Maturity (stars/forks as engagement proxy)

2. **Code review rate** — Health category gets no review data for most packages, defaulting the review component to 0 points (or benefit-of-doubt if no repo). **51 of 87 packages (59%) score exactly 1/2 on Health**, suggesting the review component almost always fails to get data.

3. **Provenance attestations** — npm provenance and Maven GPG checks work, but **49 of 87 packages (56%) score 1/2**, meaning they have source code available but no build attestations. The category never returns 0/2 because even when source explicitly fails + no attestations, the code returns 2 risk points but this combination almost never occurs.

4. **OSSF Scorecard data** — Referenced as fallback for Branch Protection, Contributors, Code Review, Security Policy. Availability varies; when missing, categories fall back to less reliable signals.

**Count of checks defaulting to low risk across all packages:**
- Install Execution defaults to 0 risk for **75 packages** (no install scripts detected)
- Dependency Sprawl defaults to 0 risk for **71 packages** (few direct deps)
- These two alone account for ~146 "free passes" across all packages

---

## 3. Score Range Compression Analysis

### Score Distribution

| Score | Count | Percentage | Classification |
|:-----:|:-----:|:----------:|:--------------:|
| 3 | 2 | 2.3% | LOW |
| 4 | 9 | 10.3% | LOW |
| 5 | 8 | 9.2% | LOW |
| 6 | 14 | 16.1% | LOW |
| 7 | 14 | 16.1% | LOW |
| 8 | 27 | 31.0% | LOW |
| 9 | 8 | 9.2% | MEDIUM |
| 10 | 2 | 2.3% | MEDIUM |
| 11 | 1 | 1.1% | MEDIUM |
| 12 | 2 | 2.3% | MEDIUM |
| **13+** | **0** | **0%** | **HIGH** |

**Mean: 7.0 | Median: 7 | Std Dev: 2.1**

**85% of packages fall in the 4-8 range.** The distribution is heavily concentrated, confirming score compression.

### Why 13 is Unreachable

To score 13 risk points, a package needs 13 out of 20 possible risk points. Looking at the category groups:

**"Hard to pass" categories** (avg combined risk = 4.54):
| Category | Avg Risk | Max Risk |
|----------|:--------:|:--------:|
| Release Security | 1.49 | 2 |
| Health | 1.39 | 2 |
| Publisher Control | 0.83 | 2 |
| Governance | 0.83 | 2 |
| **Subtotal** | **4.54** | **8** |

**"Easy to pass" categories** (avg combined risk = 1.40):
| Category | Avg Risk | Max Risk |
|----------|:--------:|:--------:|
| Provenance | 0.56 | ~~2~~ **1 (effective max)** |
| Ownership Changes | 0.59 | 2 |
| Release Anomalies | 0.39 | 2 |
| Package Maturity | 0.38 | 2 |
| Install Execution | 0.28 | 2 |
| Dependency Sprawl | 0.20 | 2 |
| **Subtotal** | **2.40** | **~~12~~ 11 (effective max)** |

**Total average risk: 6.94** — less than half the HIGH threshold (13).

Even with ALL 4 "hard" categories maxed at 2 risk each (8 points), a package still needs 5 more from the "easy" categories. But those categories average only 2.40 combined. For a package to score 5+ risk from the "easy" categories, it would need 3+ of them at max risk — which almost never happens because these categories flag fundamentally different signals (install scripts vs. dependency count vs. dormancy vs. age).

### Effective Maximum Score

**Theoretical maximum: 20** (all categories at 0/2)
**Effective maximum with Provenance cap: 19** (Provenance never returns 0/2)
**Practical maximum for real packages: ~14-15** (limited by categories that rarely co-occur at max risk)
**Observed maximum: 12** (date-fns, H2 Database)

---

## 4. Maximum Achievable Score Given Working vs. Broken Checks

### Checks That Work Well (differentiate packages)
| Category | Range Used | Effective |
|----------|:---------:|:---------:|
| Release Security | 0-2 | Full range |
| Health | 0-2 | Full range (but skewed high-risk) |
| Publisher Control | 0-2 | Full range |
| Governance | 0-2 | Full range |
| Ownership Changes | 0-2 | Full range |
| Package Maturity | 0-2 | Full range |
| Release Anomalies | 0-2 | Full range (but 79% at low risk) |

### Checks That Are Compressed/Broken
| Category | Range Used | Issue |
|----------|:---------:|-------|
| **Provenance** | **1-2 only** | Never returns 0/2. Effective max risk = 1, not 2 |
| **Install Execution** | 0 and 2 only | Binary — never returns 1. Either has scripts (risk) or doesn't (safe) |
| **Dependency Sprawl** | 1-2 only (effectively) | Only 1 of 87 packages scored 0/2. Almost always low risk |

**Maximum achievable score given these constraints:**
- 7 working categories × 2 = 14
- Provenance max = 1
- Install Execution max = 2 (works but binary)
- Dependency Sprawl max = 2 (works but effectively capped)
- **Effective max = 14 + 1 + 2 + 2 = 19** (theoretical)
- **Practical max ≈ 14** (because Install/Deps/Anomalies rarely co-occur at max risk)

---

## 5. Package Validation (25+ Packages)

### Validation Summary

| # | Package | Eco | Score | Accurate? | Issues |
|---|---------|-----|:-----:|:---------:|--------|
| 1 | date-fns@3.0.6 | npm | 12 | Mostly | Bus factor=1 questionable (large project) |
| 2 | com.h2database:h2@2.2.224 | maven | 12 | Mostly | 100% team change likely false positive |
| 3 | pg@8.11.3 | npm | 11 | Yes | Single maintainer accurate, dormancy reactivation valid |
| 4 | joi@17.11.0 | npm | 10 | Yes | Dormancy gap accurate |
| 5 | psycopg2-binary@2.9.9 | pypi | 10 | Yes | Install scripts (C extension) reasonable |
| 6 | aws-sdk@2.1528.0 | npm | 9 | Questionable | Install scripts for AWS SDK seems wrong; Health=0 for Amazon project? |
| 7 | express@4.18.2 | npm | 9 | Mostly | Bus factor=1 questionable (multi-org project); 28 deps accurate |
| 8 | compression@1.7.4 | npm | 9 | Yes | Accurate for small utility |
| 9 | org.mapstruct:mapstruct@1.5.5.Final | maven | 9 | Mostly | Ownership change may be false positive |
| 10 | passport-jwt@4.0.1 | npm | 9 | Yes | Single maintainer, stale project |
| 11 | org.springdoc:springdoc-openapi | maven | 9 | Mostly | Ownership change flag likely legitimate |
| 12 | passlib@1.7.4 | pypi | 8 | Yes | Abandoned Python project, accurate |
| 13 | com.google.guava:guava | maven | 8 | **No** | **100% team change is FALSE POSITIVE** — Google Guava is actively maintained by Google. Bus factor=1 is wrong. |
| 14 | org.springframework.boot:spring-boot-starter-web | maven | 8 | **No** | **100% team change is FALSE POSITIVE** — Spring Boot is actively maintained by VMware/Broadcom. |
| 15 | com.squareup.okhttp3:okhttp | maven | 8 | Partly | 100% team change may be false positive for Square project |
| 16 | lodash@4.17.21 | npm | 7 | Yes | Genuinely dormant (1796 days), bus factor=1 accurate |
| 17 | sqlalchemy@2.0.25 | pypi | 7 | Mostly | Bus factor=1 is accurate (zzzeek is primary) |
| 18 | winston@3.11.0 | npm | 7 | Yes | Release gap accurate |
| 19 | mongoose@8.1.0 | npm | 6 | Yes | Bus factor=1 plausible, active project |
| 20 | celery@5.3.6 | pypi | 6 | Yes | Reasonable assessment |
| 21 | sharp@0.33.1 | npm | 6 | Yes | Install scripts (native addon) accurate |
| 22 | Flask@3.1.2 | pypi | 6 | Yes | Reasonable for Pallets project |
| 23 | fastapi@0.108.0 | pypi | 5 | Yes | Release Security=0 accurate (no signed releases) |
| 24 | org.postgresql:postgresql | maven | 5 | Partly | 100% team change likely false positive |
| 25 | cryptography@42.0.0 | pypi | 5 | Yes | Well-maintained, score reflects this |
| 26 | requests@2.32.4 | pypi | 4 | Yes | Accurately scored, setup.py reasonable |
| 27 | stripe@14.10.0 | npm | 4 | Partly | **Single maintainer is a corporate account** — should be mitigated |
| 28 | pandas@2.1.4 | pypi | 4 | Yes | Reasonable for large, well-maintained project |
| 29 | numpy@1.26.3 | pypi | 3 | Yes | Very well-maintained, low risk accurate |
| 30 | axios@1.6.5 | npm | 3 | Yes | Well-maintained, accurate |

### Key Validation Findings

**False Positive: Ownership Changes "100% team change"** — At least 5 packages (Guava, Spring Boot, OkHttp, PostgreSQL JDBC, H2) have false positive ownership change flags. The commit author turnover detection treats natural contributor rotation in large projects as ownership transfer. All 5 are mature, well-established projects with rotating contributors — not takeover signals.

**False Positive: Bus Factor=1 for large projects** — date-fns, express, Guava, and Spring Boot all show bus factor=1 despite having multi-contributor histories. This suggests the bus factor calculation may be too aggressive in counting "50% of commits" when one author dominates commit volume.

**False Positive: Stripe single maintainer** — Stripe publishes under a corporate npm account. The single maintainer flag doesn't distinguish between a personal single-maintainer and a corporate single-publisher account.

---

## 6. Root Causes and Specific Recommendations

### Priority 1: Fixes That Would Expand the Score Range

#### 1A. Fix Provenance to use full 0-2 range
**File:** `pkg/analyzer/provenance_scoring.go`
**Issue:** Provenance never assigns 0/2 (2 risk points). Even "source explicitly failed + no attestations" is rare in practice.
**Impact:** +1 potential risk point for all packages
**Fix:** When source code is unavailable (no repo URL, no source package in artifact) AND no attestations, assign 0/2 (2 risk points). Currently this path exists in code but almost never triggers because most packages have at least a repo URL.

#### 1B. Fix Health scoring bias (99% cannot reach 2/2)
**File:** `pkg/analyzer/health.go`
**Issue:** Only 1 of 87 packages scores 2/2 (0 risk). The category requires BOTH bus factor≥2 AND code review rate≥75% — a very high bar. Most packages fail the code review component because PR review data isn't available or isn't scraped successfully.
**Impact:** Would allow more differentiation in the 0-1 range
**Fix Options:**
- Lower the code review threshold from 75% to 50%
- Add additional positive signals (e.g., CODEOWNERS file, branch protection)
- Weight bus factor more heavily (bus factor≥3 could satisfy both components)

#### 1C. Make Dependency Sprawl actually differentiate packages
**File:** `pkg/analyzer/dependency_sprawl.go`
**Issue:** 82% of packages score 2/2 (0 risk). The thresholds are too generous (npm: 0-5=low, 6-15=medium, 16+=high; Maven: 0-12=low, 13-29=medium, 30+=high).
**Impact:** Would add 1-2 risk points to packages with dependency bloat
**Fix:** Lower thresholds — most packages have SOME dependencies. Consider: npm 0-2=low, 3-8=medium, 9+=high.

### Priority 2: Fixes That Would Improve Accuracy

#### 2A. Fix Ownership Changes false positives for mature projects
**File:** `pkg/analyzer/ownership_changes.go`
**Issue:** 23 packages (26%) flagged for ownership changes, but many are false positives from natural contributor rotation in large projects.
**Fix:** Add a minimum historical author threshold — if a project has 20+ historical authors, contributor rotation is expected. Only flag when the new authors are also new to the ecosystem (no prior packages).

#### 2B. Fix Bus Factor calculation for projects with dominant contributor
**File:** `pkg/analyzer/health.go`
**Issue:** Bus factor=1 for projects like express and Guava where one person dominates commits but many others are active.
**Fix:** Consider using "authors contributing 80% of commits" instead of 50%, or weight recent activity more than historical commit count.

#### 2C. Distinguish corporate vs. personal publisher accounts
**File:** `pkg/analyzer/publisher_control.go`
**Issue:** Corporate npm accounts (e.g., Stripe) are flagged as "single maintainer" despite being organizational.
**Fix:** Already partially implemented (org detection via scraping), but the npm publisher name heuristic should also check for known corporate publishers.

### Priority 3: Threshold Adjustments

#### 3A. Lower the HIGH threshold from 13 to 11
**File:** `pkg/analyzer/analyzer.go` (lines 738-755)
**Rationale:** Given the structural compression, 11 would capture the truly risky packages (date-fns at 12, H2 at 12, pg at 11) while keeping the false positive rate low. Adjust: LOW 0-7, MEDIUM 8-10, HIGH 11+.

#### 3B. Alternative: Weight categories differently
Instead of equal weights (all 0-2), weight the "differentiating" categories higher:
- Release Security, Health: 0-3 points (these differentiate most)
- Publisher Control, Governance, Ownership Changes: 0-2 points (these have good range)
- Install Execution, Dependency Sprawl: 0-1 point (binary/near-binary anyway)
- Provenance, Release Anomalies, Package Maturity: 0-2 points
- New max: 21 points, with more dynamic range

---

## 7. Summary of All Issues Found

| # | Issue | Category | Impact | Fix Priority |
|---|-------|----------|--------|:------------:|
| 1 | Provenance never returns 0/2 | Provenance | Removes 1pt from max | P1 |
| 2 | Health almost never returns 2/2 | Health | 99% packages get ≥1 risk | P1 |
| 3 | Dependency Sprawl thresholds too generous | Dependency Sprawl | 82% always 0 risk | P1 |
| 4 | Install Execution is binary (0 or 2 only) | Install Execution | No medium risk | P2 |
| 5 | False positive ownership changes | Ownership Changes | 5+ packages wrongly flagged | P2 |
| 6 | Bus factor=1 for large projects | Health | False high-risk scores | P2 |
| 7 | Corporate accounts flagged as single maintainer | Publisher Control | 2+ packages wrongly flagged | P2 |
| 8 | GitHub rate limiting causing data gaps | Multiple | 14 packages with degraded analysis | P2 |
| 9 | HIGH threshold too high for compressed range | Scoring | 0 packages ever reach HIGH | P3 |
| 10 | Equal category weights don't reflect differentiation | Scoring | Score compression | P3 |

### Quick Wins
1. Lower HIGH threshold to 11 → immediately classifies 3 packages as HIGH
2. Lower Dependency Sprawl thresholds → adds 1-2 risk points to ~50% of packages
3. Fix Provenance edge case → allows theoretical max to reach 20

### Medium-Term Fixes
4. Fix Ownership Changes contributor rotation detection
5. Improve bus factor calculation
6. Address GitHub rate limiting (use authenticated API, caching)

### Long-Term Architecture
7. Consider weighted category scoring for better dynamic range
8. Add more granular provenance checks (reproducible builds, SLSA levels)
