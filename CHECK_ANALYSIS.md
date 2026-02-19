# Snyft Check Usefulness Analysis

## Test Methodology

Ran `snyft scan` against `/Users/mike/Projects/mike-libraries` which contains 87 real-world packages across 3 ecosystems:
- **JavaScript (npm)**: 24 packages from `package.json` (express, mongoose, stripe, jest, etc.)
- **Python (PyPI)**: 25 packages from `requirements.txt` (Flask, Django, boto3, requests, etc.)
- **Java (Maven)**: 38 packages from `pom.xml` (Spring Boot, Hibernate, Jackson, etc.)

The scan was run **without a GitHub token**, which is an important factor (see Data Quality section below).

## Score Distribution Summary

| Category | Score Distribution (risk_points) | Unique Scores | Assessment |
|---|---|---|---|
| publisher_control | 0pts=4, 1pts=63, 2pts=20 | 3 | WEAK (72% score 1pt) |
| ownership_changes | 0pts=59, 1pts=28 | 2 | USEFUL (68/32 split) |
| release_anomalies | 0pts=60, 1pts=27 | 2 | USEFUL (69/31 split) |
| **install_execution** | **0pts=85, 1pts=2** | **2** | **SUSPECT (98% score 0pts)** |
| dependency_sprawl | 0pts=42, 1pts=16, 2pts=29 | 3 | USEFUL (good 3-way spread) |
| provenance | 1pts=11, 2pts=76 | 2 | WEAK (87% score 2pts) |
| health | 1pts=17, 2pts=70 | 2 | WEAK (80% score 2pts) |
| governance | 1pts=52, 2pts=35 | 2 | USEFUL (60/40 split) |
| release_security | 1pts=14, 2pts=73 | 2 | WEAK (84% score 2pts) |
| package_maturity | 0pts=43, 1pts=15, 2pts=29 | 3 | USEFUL (good 3-way spread) |

## Critical Finding: Data Quality Issues

**81 out of 87 packages (93%) were rate-limited by the GitHub API** (HTTP 429). This caused cascading failures:

| Data Point | Affected | Impact |
|---|---|---|
| Git tag verification | 81/87 (93%) | Provenance check couldn't verify source-to-tag match |
| Bus factor (commit analysis) | 87/87 (100%) | Health check entirely based on maintainer count only |
| Code review rate | 87/87 (100%) | No code review oversight data available |
| CI detection | 78/87 (90%) | Release security couldn't detect CI systems |

**Implication**: The checks scoring "WEAK" may be substantially better with a GitHub token (5000 req/hr vs 60 req/hr unauthenticated). The analysis below separates inherent check design issues from data availability issues.

---

## Per-Check Analysis

### 1. Publisher Control — WEAK (72% = 1pt)

**What it checks**: Maintainer count, account type, email domains, package concentration, signing, MFA.

**Finding**: Most packages (72%) score 1 risk point regardless of actual risk. The check detects meaningful differences (single maintainer vs multi-maintainer) but the scoring is compressed:
- Maven packages always score 1pt because Maven doesn't expose maintainer count
- npm packages with 3+ maintainers still score 1pt due to "personal email domains" and "no signing"
- The "account type unknown" and "MFA status unknown" messages appear on nearly every package

**Root cause**: Too many sub-signals are OR'd together. A package with 5 maintainers and no signing scores the same as one with 3 maintainers and personal emails.

**Recommendation**: The maintainer count signal is valuable and differentiates well. The other signals (email domains, signing, MFA) almost never vary and dilute the check's usefulness. Consider: weighting maintainer count more heavily, or splitting into sub-categories.

---

### 2. Ownership Changes — USEFUL (68% = 0pts, 32% = 1pt)

**What it checks**: Commit author history to detect team replacement patterns.

**Finding**: Provides meaningful differentiation. npm/PyPI packages with stable ownership correctly score 0pts. Maven packages and those without ownership data score 1pt ("no ownership data available"). The 68/32 split is driven by ecosystem differences (Maven lacks ownership data vs npm/PyPI which have it).

**Root cause of 1pt scores**: Maven doesn't expose ownership data, so it falls back to "unverifiable" = 1pt. This is actually correct behavior (unknown = moderate risk).

**Recommendation**: Check is useful. Could be improved by finding alternative ownership signals for Maven (e.g., POM developer history, group ID stability).

---

### 3. Release Anomalies — USEFUL (69% = 0pts, 31% = 1pt)

**What it checks**: Release history, commit frequency, dormancy detection.

**Finding**: Good differentiation. Packages with recent commits score 0pts. Packages with no commit history (API rate limited) or dormant repos correctly score 1pt. The check detected real dormancy signals (e.g., mapstruct with 467 days since last commit).

**Recommendation**: Check is useful. With GitHub API access, would likely show even better differentiation (dormant→reactivated patterns).

---

### 4. Install Execution — SUSPECT (98% = 0pts)

**What it checks**: preinstall/install/postinstall scripts, setup.py execution, dangerous patterns.

**Finding**: Only **2 out of 87 packages** (sharp, aws-sdk) had any install scripts at all. 98% of packages scored 0 risk points. The check provides almost zero differentiation.

**However**: This is by design. Install scripts are a direct compromise vector (the event-stream attack used postinstall). The check is like a smoke detector — it SHOULD be quiet most of the time, but when it fires, it's critical. The 2 packages it flagged (sharp with native compilation, aws-sdk) are genuine cases where install-time execution occurs.

**Root cause**: Most modern packages don't use install scripts. This is a GOOD thing. The check isn't broken — it's just that the attack surface it monitors is uncommon in well-maintained packages.

**Recommendation**: Keep the check. Despite low differentiation in aggregate, it catches a real attack vector. Consider:
- Not including it in "check effectiveness" metrics since it's designed to be an outlier detector
- Adding detection of more subtle install-time behaviors (e.g., lifecycle script chains)

---

### 5. Dependency Sprawl — USEFUL (good 3-way spread)

**What it checks**: Transitive/direct dependency count from lock files and registry metadata.

**Finding**: Good 3-way differentiation: 42 packages with few deps (0pts), 16 moderate (1pt), 29 heavy (2pts). This reflects real differences — packages like express (few deps) vs Spring Boot transitive trees (many deps).

**Note**: 87/87 packages show `verified: false` because lock file analysis wasn't available (no lock files in the test directory). All counts come from registry metadata (direct deps only). With lock files present, the check would have even richer data.

**Recommendation**: Check is useful. Consider encouraging lock file presence for more accurate transitive counts.

---

### 6. Provenance — WEAK (87% = 2pts)

**What it checks**: Source code verification (tarball + git tag), SLSA attestations, Sigstore signatures, npm provenance.

**Finding**: 76/87 packages (87%) score maximum risk (2pts). Only 11 packages scored 1pt (had some attestations). **No packages scored 0pts**.

**Root cause**: Two compounding factors:
1. **API rate limiting**: Git tag verification failed for 93% of packages (429 errors), so source code could never be fully verified
2. **Reality**: Very few packages have SLSA attestations or Sigstore signatures. The 11 packages with 1pt all had npm provenance or OSSF Signed-Releases signals.

**With GitHub token**: The check would likely improve significantly. Many of these packages DO have matching git tags, but the check couldn't verify them.

**Recommendation**:
- Re-run with GITHUB_TOKEN to get accurate results before concluding the check is weak
- The check's design is sound — provenance IS rare — but it may need more granularity (e.g., distinguish "no source at all" from "source exists but unverified" from "fully verified")

---

### 7. Health — WEAK (80% = 2pts)

**What it checks**: Bus factor (commit distribution), required reviewers, branch protection, code review rate.

**Finding**: 70/87 packages (80%) score maximum risk. The 17 packages scoring 1pt were ALL npm packages with multiple maintainers but no review oversight.

**Root cause**: **100% data quality issue**. Bus factor is 0 for ALL 87 packages. Code review rate is 0 for ALL 87 packages. The check is entirely dependent on GitHub API data that was never fetched due to rate limiting. It falls back to using maintainer count from registry metadata as a proxy.

**With GitHub token**: This check would have commit distribution data, code review rates, and branch protection info. It would almost certainly differentiate much better.

**Recommendation**:
- This check is **fundamentally broken without a GitHub token**
- Re-run with GITHUB_TOKEN — the check's design measures real signals (bus factor, code review oversight) but can't access them without API access
- Consider: should the check clearly communicate "insufficient data" vs "poor health"?

---

### 8. Governance — USEFUL (60% = 1pt, 40% = 2pts)

**What it checks**: SECURITY.md presence, issue response times, abandonment patterns.

**Finding**: Decent 60/40 split. Packages with SECURITY.md (via OSSF scorecard) score 1pt. Those without score 2pts. The check correctly identified abandoned projects (python-jose: 267 days, mapstruct: 467 days).

**Root cause of split**: The OSSF Scorecard data (which uses its own API) provides Security-Policy scores independently of GitHub API rate limits. This gives the check a data source that doesn't degrade.

**Recommendation**: Check is useful. The OSSF data provides a stable signal. Could be enhanced with more governance signals (CONTRIBUTING.md, CODE_OF_CONDUCT.md, governance documentation).

---

### 9. Release Security — WEAK (84% = 2pts)

**What it checks**: CI/CD publishing, branch protection, required PR reviews, signed tags, CI workflow risks.

**Finding**: 73/87 packages (84%) score maximum risk. The 14 packages scoring 1pt had some controls (OSSF Branch-Protection, Code-Review, or Packaging scores).

**Root cause**: CI detection failed for 90% of packages. Without being able to read `.github/workflows/` or `Jenkinsfile` from the repository, the check can't detect CI systems. It falls back to OSSF scorecard data where available.

**With GitHub token**: Would be able to detect CI systems, branch protection rules, and required reviewers. The check's design is comprehensive — it just can't access the data.

**Recommendation**:
- Re-run with GITHUB_TOKEN before concluding the check is weak
- The 14 packages that scored 1pt show the check CAN differentiate when OSSF data is available
- Consider: ensuring OSSF scorecard is always queried as a fallback even when GitHub API is available

---

### 10. Package Maturity — USEFUL (good 3-way spread)

**What it checks**: Time since first publish, last commit recency, release cadence consistency.

**Finding**: Good 3-way differentiation: 43 packages mature (0pts), 15 maturing (1pt), 29 immature/stale (2pts). This correctly separates well-established packages (boto3, Spring Framework) from newer or stale ones.

**Note**: Some packages show inaccurate "package age" because the first-publish date isn't available and it falls back to the last-commit date. E.g., jest shows "144 days (very new)" when it's actually 10+ years old.

**Recommendation**: Check is useful. The fallback to last-commit date for package age can be misleading for established packages. Consider: using registry creation date when available, or noting when the age calculation is approximate.

---

## Summary: Check Tiers

### Tier 1: Consistently Useful (good differentiation regardless of API access)
- **dependency_sprawl** — 3-way split, uses registry data
- **package_maturity** — 3-way split, uses registry + basic timestamps
- **governance** — 60/40 split, leverages OSSF data
- **ownership_changes** — 68/32 split, uses registry ownership data
- **release_anomalies** — 69/31 split, uses basic commit timestamps

### Tier 2: Useful But Data-Starved (would improve with GITHUB_TOKEN)
- **provenance** — 87% max risk, but git tag verification couldn't run
- **health** — 80% max risk, but bus_factor/code_review data is 100% missing
- **release_security** — 84% max risk, but CI detection couldn't access repos

### Tier 3: Inherently Low-Signal
- **publisher_control** — 72% score 1pt; scoring is too compressed
- **install_execution** — 98% score 0pts; correct but rare signal (outlier detector by design)

## Key Recommendations

1. **Re-run this analysis with GITHUB_TOKEN** to separate data-quality issues from check-design issues. Tier 2 checks may move to Tier 1.

2. **install_execution is fine as-is** — it's an outlier detector, not a differentiator. Consider documenting this distinction.

3. **publisher_control needs scoring refinement** — maintainer count is a strong signal being diluted by always-unknown signals (MFA, signing, account type).

4. **health check is meaningless without GitHub API** — consider either requiring a token for this check or finding alternative data sources.

5. **provenance scoring could be more granular** — distinguish "no source at all" vs "source exists, unverified" vs "partially verified" vs "fully verified".
