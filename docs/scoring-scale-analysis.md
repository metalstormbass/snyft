# Scoring Scale Analysis: Is 0-20 Appropriate?

**Research Report — No Code Changes**
**Date:** 2026-03-04

---

## Executive Summary

The current 20-point scale (10 categories × 0-2) has structural problems that prevent effective risk differentiation. Most real packages cluster in the 4-10 range, making the HIGH threshold (13+) nearly unreachable without extreme pathology. Several categories measure overlapping signals (dormancy is penalized in 3 places), while others are structurally unable to produce the full 0-2 range for typical packages. This report documents each category's realistic range, identifies overlaps, and recommends specific changes.

---

## 1. Realistic Score Ranges Per Category

### Category 1: Publisher Control (0-2)
**Realistic range: 0-2 ✓ (full range achievable)**

- **0:** Org-backed package with multiple maintainers + signing (e.g., `@angular/core`)
- **1:** 2-3 maintainers, personal account, or new account — this is the **most common score** for mid-tier packages
- **2:** Single maintainer + personal account + no signing

**Assessment:** This category works well. Most popular packages score 0-1; small personal projects score 2. Full range is realistically exercised.

### Category 2: Ownership Changes (0-2)
**Realistic range: 0-1 (2 is rare)**

- **0:** Stable team — the overwhelming majority of packages
- **1:** Moderate team turnover (50-79% new authors in 90 days) or limited history or repo-date mismatch
- **2:** ≥80% team replacement OR recent npm/PyPI transfer — this is a genuine attack signal but extremely rare

**Assessment:** Score of 2 is structurally rare because real hostile takeovers are rare. This category functions more as a binary alarm (0 or 1) in practice. The 50-79% moderate threshold catches some false positives from normal team growth.

### Category 3: Release Anomalies (0-2)
**Realistic range: 0-1 (2 requires specific dormancy+reactivation pattern)**

- **0:** Active, consistent release cadence — most maintained packages
- **1:** Dormant >365 days (no recent activity) — **capped at 1 point** by design
- **2:** Dormancy reactivation (>1yr gap then release <90 days ago) OR relative dormancy spike — requires a very specific temporal pattern

**Assessment:** The explicit cap at 1 point for pure dormancy means this category rarely reaches 2. A score of 2 requires not just dormancy but *reactivation*, which is the actual attack signal. This is correct behavior but means the category contributes less differentiation than its 0-2 range suggests.

### Category 4: Install Execution (0-2)
**Realistic range: 0 or 2 (binary in practice)**

- **0:** No install scripts — the vast majority of npm packages (~97% per ecosystem studies)
- **1:** Install scripts with benign patterns — narrow middle ground
- **2:** Install scripts with dangerous patterns (curl|sh, binary downloads)

**Assessment:** This is effectively binary. Most packages score 0 (no install scripts). Those with install scripts almost always contain patterns that trigger 2 (node-gyp compilations, binary downloads). The score-1 middle ground is rarely hit in practice.

### Category 5: Dependency Sprawl (0-2)
**Realistic range: 0-2 ✓ (full range achievable)**

- **0:** <10 transitive deps (lock file) or 0-5 direct deps (registry) — small utility packages
- **1:** 10-50 transitive or 6-15 direct — moderate packages like `express`
- **2:** >50 transitive or >15 direct — large frameworks

**Assessment:** Full range is exercised. However, the signal is weak — large dependency counts are common in the JavaScript ecosystem and don't strongly correlate with compromise risk. A package with 100 deps isn't 2x more likely to be compromised than one with 30.

### Category 6: Provenance (0-2)
**Realistic range: 0-1 (skewed toward 1)**

- **0:** Source available + strong attestations (npm provenance or GPG signatures + OSSF ≥7) — few packages achieve this
- **1:** Source available but weak/no attestations — **the default for most packages with a repo URL**
- **2:** No source available + no attestations — packages without public repos

**Assessment:** npm provenance adoption is still low (~2-5% of packages as of 2025). Maven GPG signing is more common but many packages still lack it. Most packages with a repo URL score 1. Score 0 is aspirational rather than common, and score 2 only hits packages without repos (which also get floor-scored).

### Category 7: Health (0-2)
**Realistic range: 0-2 ✓ (full range achievable)**

- **0:** Bus factor ≥2 + ≥75% PR review rate
- **1:** One signal present but not both
- **2:** Single contributor, no reviews

**Assessment:** Works well. Small projects score 2, mid-tier score 1, well-governed projects score 0. The bus factor ≥2 threshold is well-calibrated.

### Category 8: Governance (0-2)
**Realistic range: 1-2 (0 is rare, 2 is common)**

- **0:** SECURITY.md present + responsive issue handling (≤14 days avg) — only well-governed projects
- **1:** One signal present — many packages have either SECURITY.md or reasonable response times but not both
- **2:** No security policy + unresponsive OR archived OR >180 days inactive

**Assessment:** The >180-day abandonment early return is very aggressive. Many stable, feature-complete packages (e.g., `minimist`, `ms`, `once`) don't need frequent commits but get immediately penalized with 2 risk points. Meanwhile, score 0 requires both SECURITY.md and responsive issues — a bar that even many popular packages don't meet.

### Category 9: Release Security (0-2)
**Realistic range: 0-1 (skewed toward 1)**

- **0:** 3+ of 5 release security signals (CI publishing, branch protection, signed releases, PR reviews, documented process) — well-organized projects
- **1:** 1-2 signals present — **most packages with a repo**
- **2:** 0 signals — packages with no repo or extremely basic setup

**Assessment:** This category aggregates 5 sub-signals into a 0-2 range, which compresses valuable information. The difference between 1/5 signals and 2/5 signals is meaningful but invisible in the final score. Score 2 is mostly reserved for packages without repos (which are already floor-scored).

### Category 10: Package Maturity (0-2)
**Realistic range: 0-2 ✓ (full range achievable)**

- **0:** >2 years old + last commit <180 days + consistent cadence
- **1:** 6mo-2yr old, or 180-365 days since commit, or irregular cadence with single maintainer
- **2:** <6 months old or >365 days since last commit

**Assessment:** Works well for new packages (correctly flagged). The staleness check overlaps heavily with Governance and Release Anomalies (see Section 2).

---

## 2. Category Overlaps — Measuring the Same Signal

### Overlap A: Dormancy/Staleness (3-way overlap)
**Categories:** Governance, Release Anomalies, Package Maturity

All three penalize inactivity using `RepoLastCommit`:

| Category | Threshold | Penalty |
|----------|-----------|---------|
| Governance | >180 days | 2 points (hard early return) |
| Package Maturity | >180 days / >365 days | 1 or 2 points |
| Release Anomalies | >365 days (pure dormancy) | 1 point (capped) |

**Impact:** A package dormant for 1+ year gets penalized in all three:
- Governance: 2 pts (abandoned)
- Package Maturity: 2 pts (stale)
- Release Anomalies: 1 pt (dormant, no reactivation)
- **Combined: 5 points from one underlying signal**

This is the single largest source of score inflation for stable-but-quiet packages.

### Overlap B: Single Maintainer (4-way overlap)
**Categories:** Publisher Control, Health, Ownership Changes, Package Maturity

| Category | Usage | Typical Penalty |
|----------|-------|-----------------|
| Publisher Control | Primary signal | 1-2 points |
| Health | Fallback for bus factor | 0-1 points |
| Ownership Changes | Fallback heuristic | 0-1 points |
| Package Maturity | Enables cadence risk | 0-1 points |

**Impact:** A single-maintainer package can accumulate 2-5 points across these categories from one underlying reality: there's only one person.

### Overlap C: Code Review Rate (2-way overlap)
**Categories:** Health, Release Security

Both use `CodeReviewRate ≥ 75%` as a signal. A package without PR reviews loses points in both categories for the same deficiency.

### Overlap D: Signed Releases (2-way overlap)
**Categories:** Provenance, Release Security

Both check for signed releases / npm provenance. Provenance uses it as an attestation signal; Release Security uses it as one of 5 sub-signals. A package without signing loses partial points in both.

---

## 3. Categories Structurally Unable to Produce Full 0-2

| Category | Structural Limitation |
|----------|----------------------|
| **Ownership Changes** | Score 2 requires actual hostile takeover pattern — extremely rare by definition |
| **Release Anomalies** | Pure dormancy is capped at 1; score 2 requires dormancy+reactivation temporal pattern |
| **Install Execution** | Effectively binary (0 or 2); score 1 middle ground is rarely hit |
| **Provenance** | Score 0 requires attestations that <5% of packages have; most packages score 1 |
| **Governance** | Score 0 requires both SECURITY.md + responsive issues; rare even for popular packages |

**Net effect:** 5 of 10 categories have compressed or skewed ranges, meaning the effective scoring range is narrower than the theoretical 0-20.

---

## 4. Would Merging Weak Categories Produce Better Differentiation?

### Proposed Merges

#### Merge 1: Governance + Package Maturity → "Project Health & Maturity"
**Rationale:** Both measure "is this project actively maintained and well-governed?" The dormancy/staleness overlap is the strongest argument. Governance's >180-day abandonment check and Maturity's staleness check measure the same signal.

**Combined scoring (0-3, normalized to 0-2):**
- Security policy present (+1)
- Responsive maintenance / not abandoned (+1)
- Sufficient age and stable cadence (+1)
- Map: 0→2, 1→1, 2-3→0

**Benefit:** Eliminates the dormancy triple-count. One penalty for being inactive, not three.

#### Merge 2: Health + Publisher Control → "Maintainer Risk"
**Rationale:** Both measure "how concentrated is control and how vulnerable are the maintainers?" Bus factor, maintainer count, and org-backing are aspects of the same underlying question.

**Risk:** These categories are actually measuring subtly different things:
- Publisher Control = "how easy to compromise the publish credential?"
- Health = "how distributed is development oversight?"

**Recommendation: Don't merge these.** The overlap is in fallback paths, not primary signals. Keep separate but remove maintainer-count fallback from Health (let Publisher Control own that signal exclusively).

#### Merge 3: Provenance + Release Security → "Build & Release Integrity"
**Rationale:** Both assess "can we trust the artifact?" Signed releases appear in both. OSSF Signed-Releases check is used by both.

**Combined scoring (0-3 or 0-4, normalized to 0-2):**
- Source code verifiable (+1)
- Build attestations present (+1)
- CI-based publishing with branch protection (+1)
- Signed releases with PR reviews (+1)
- Map: 0-1→2, 2→1, 3-4→0

**Benefit:** Eliminates the signed-releases double-count and creates a more graduated assessment of release integrity.

---

## 5. What Would a Reduced Scale Look Like?

### Option A: 7 Categories × 0-2 = 0-14 Scale

Merge the three pairs identified above:

| # | Category | What It Measures |
|---|----------|-----------------|
| 1 | Publisher Control | Credential compromise risk |
| 2 | Ownership Changes | Hostile acquisition signals |
| 3 | Release Anomalies | Dormancy reactivation patterns |
| 4 | Install Execution | Direct compromise vectors |
| 5 | Dependency Sprawl | Transitive attack surface |
| 6 | **Project Viability** (Governance + Maturity) | Active maintenance + governance |
| 7 | **Build Integrity** (Provenance + Release Security) | Artifact trust chain |

**Remove:** Health (distribute bus factor to Publisher Control; distribute code review to Build Integrity)

**Thresholds:** LOW 0-5, MEDIUM 6-9, HIGH 10-14

**Pros:** Eliminates all major overlaps. Each point of score now represents a distinct signal.
**Cons:** Reduces granularity. Harder to explain changes to existing users.

### Option B: 8 Categories × 0-2 = 0-16 Scale

Keep Health separate (it does measure something distinct about development distribution), but merge Governance+Maturity and Provenance+Release Security:

| # | Category |
|---|----------|
| 1 | Publisher Control |
| 2 | Ownership Changes |
| 3 | Release Anomalies |
| 4 | Install Execution |
| 5 | Dependency Sprawl |
| 6 | Health (bus factor + review oversight) |
| 7 | **Project Viability** (Governance + Maturity) |
| 8 | **Build Integrity** (Provenance + Release Security) |

**Thresholds:** LOW 0-6, MEDIUM 7-10, HIGH 11-16

**Pros:** Cleaner than current 10, preserves Health's distinct signal.
**Cons:** Still has some maintainer-count overlap between Publisher Control and Health.

### Option C: Keep 10 Categories, Fix Overlaps In-Place

Don't merge categories. Instead:
1. Remove dormancy checks from Governance (let Maturity own staleness)
2. Remove maintainer-count fallback from Health (let Publisher Control own it)
3. Remove signed-releases from Provenance (let Release Security own it)
4. Lower HIGH threshold from 13 to 11

**Thresholds:** LOW 0-7, MEDIUM 8-10, HIGH 11-20

**Pros:** Minimal structural change. Backward-compatible category names.
**Cons:** Doesn't address the fundamental compression problem in categories like Install Execution and Ownership Changes.

---

## 6. Making HIGH Reachable Without Inflating Scores

### The Core Problem

HIGH requires 13/20 (65%). But:
- 5 categories have compressed ranges (rarely produce 2)
- 3 categories overlap on dormancy (inflating quiet-but-safe packages)
- A genuinely risky package (single maintainer, no signing, new, no repo) typically scores 10-12 — landing in MEDIUM, not HIGH

### Recommended Changes (can be applied independently)

#### Change 1: Lower HIGH threshold to 11/20 (55%)
**Rationale:** With 5 compressed categories, the realistic maximum for a suspicious-but-not-pathological package is ~12-14. A threshold of 11 would correctly classify packages with 5-6 risk signals as HIGH.

**Impact:** Some packages currently MEDIUM would become HIGH. This is desirable — the current MEDIUM bucket is too broad (9-12 spans packages with very different risk profiles).

#### Change 2: Remove dormancy triple-counting
**Specific change:** In Governance, remove the >180-day early return. Instead, only penalize for archived repos and missing security policy. Let Package Maturity and Release Anomalies handle staleness.

**Impact:** Feature-complete packages like `minimist`, `ms`, `once` lose 2 points they shouldn't have. Truly abandoned packages still get penalized via Maturity (2 pts) and Anomalies (1 pt).

#### Change 3: Weight categories differently (0-3 for critical, 0-1 for weak)
Instead of uniform 0-2, assign wider ranges to high-signal categories:

| Category | Current | Proposed | Rationale |
|----------|---------|----------|-----------|
| Publisher Control | 0-2 | 0-3 | Highest signal for compromise |
| Install Execution | 0-2 | 0-3 | Direct compromise vector |
| Ownership Changes | 0-2 | 0-2 | Keep (rare but critical alarm) |
| Release Anomalies | 0-2 | 0-2 | Keep (dormancy reactivation is key signal) |
| Provenance | 0-2 | 0-2 | Keep |
| Dependency Sprawl | 0-2 | 0-1 | Weak signal, reduce weight |
| Health | 0-2 | 0-2 | Keep |
| Governance | 0-2 | 0-1 | After removing dormancy check, less signal |
| Release Security | 0-2 | 0-2 | Keep |
| Package Maturity | 0-2 | 0-2 | Keep |

**New max:** 20 points (unchanged total, but redistributed weight)
**HIGH threshold:** 11/20

**Impact:** A single-maintainer package with dangerous install scripts could score 3+3=6 from just two categories, properly reflecting the compound risk. Meanwhile, dependency sprawl alone can't push a package into MEDIUM.

#### Change 4: Narrow the MEDIUM band
Current: LOW 0-8, MEDIUM 9-12, HIGH 13+
The MEDIUM band is only 4 points wide but contains the majority of packages.

**Proposed:** LOW 0-7, MEDIUM 8-10, HIGH 11+
This narrows MEDIUM to 3 points and pushes more risky packages into HIGH where they belong.

---

## 7. Specific Recommendations (Priority Order)

### Must Do (High Impact, Low Risk)
1. **Remove dormancy early-return from Governance** — eliminates the most impactful overlap
2. **Lower HIGH threshold from 13 to 11** — makes HIGH reachable for genuinely risky packages
3. **Remove maintainer-count fallback from Health** — let Publisher Control own this signal

### Should Do (Medium Impact, Moderate Risk)
4. **Merge Provenance + Release Security** into "Build Integrity" — eliminates signed-release double-count
5. **Reduce Dependency Sprawl weight to 0-1** — it's the weakest signal and doesn't correlate well with compromise risk
6. **Narrow MEDIUM band** to 8-10 (from 9-12)

### Consider (Larger Structural Changes)
7. **Merge Governance + Package Maturity** into "Project Viability" — significant refactor but eliminates fundamental overlap
8. **Variable category weights (0-3 for critical categories)** — most impactful but requires rethinking the entire scoring model
9. **Move to Option B (8-category model)** — cleanest long-term solution but breaking change

---

## Appendix: Score Scenarios Under Current vs Proposed Thresholds

### Scenario: Popular single-maintainer utility (e.g., `chalk`)
| Category | Current Score | Notes |
|----------|--------------|-------|
| Publisher Control | 1-2 | Single maintainer but popular |
| Ownership Changes | 0 | Stable ownership |
| Release Anomalies | 0 | Regular releases |
| Install Execution | 0 | No install scripts |
| Dependency Sprawl | 0 | Few deps |
| Provenance | 1 | Has repo, no attestations |
| Health | 1 | Low bus factor |
| Governance | 1 | May lack SECURITY.md |
| Release Security | 1 | Some CI, no signing |
| Package Maturity | 0 | Mature, active |
| **Total** | **5-6** | **LOW** (correct) |

### Scenario: Suspicious new package (compromise candidate)
| Category | Current Score | Notes |
|----------|--------------|-------|
| Publisher Control | 2 | Single maintainer, personal, new account |
| Ownership Changes | 0 | New package, no history |
| Release Anomalies | 0 | New package, no anomaly |
| Install Execution | 2 | Dangerous postinstall |
| Dependency Sprawl | 1 | Moderate deps |
| Provenance | 2 | No source, no attestations |
| Health | 2 | No reviews, single contributor |
| Governance | 2 | No security policy, new |
| Release Security | 2 | No CI, no signing |
| Package Maturity | 2 | <6 months old |
| **Total** | **15** | **HIGH** (correct, but requires ALL categories to fire) |

### Scenario: Stale feature-complete package (e.g., `ms`)
| Category | Current Score | Notes |
|----------|--------------|-------|
| Publisher Control | 1 | Few maintainers |
| Ownership Changes | 0 | Stable |
| Release Anomalies | 1 | Dormant >365 days |
| Install Execution | 0 | No scripts |
| Dependency Sprawl | 0 | Zero deps |
| Provenance | 1 | Has repo, no attestations |
| Health | 1 | Low bus factor |
| Governance | **2** | >180 days abandoned (harsh!) |
| Release Security | 1 | Basic CI |
| Package Maturity | **2** | Stale (feature-complete reduces to 1 if detected) |
| **Total** | **9-10** | **MEDIUM** — debatable; this is a stable, trusted package |

With proposed changes (remove Governance dormancy, threshold 11):
- Governance: 1 (no security policy, but not "abandoned")
- Total: **8** → **LOW** (more appropriate)
