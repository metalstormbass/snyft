# Snyft Report Audit: Java/Mixed Dependencies (report.html)

**Date:** 2026-03-03
**Report:** `/Users/mike/Projects/report.html`
**Packages audited:** 87 total (29 Maven, 30 npm, 28 PyPI)
**Risk distribution:** 27 MEDIUM (max 11/20), 60 LOW (min 2/20), 0 HIGH

---

## Executive Summary

The report has **serious systemic issues** that make it **not defensible** in its current form before a security team. Three critical bugs inflate scores and generate false findings across the majority of packages:

1. **BUG: All 29 Maven packages report "28 direct dependencies"** regardless of actual count (Lombok has 0, OkHttp has ~3, Guava has ~5). This is the project's total pom.xml dependency count being misattributed to each individual package.

2. **BUG: 40/87 packages (46%) falsely flagged "No git tag found"** when tags demonstrably exist. The tag checker fails to match common naming conventions (`v1.2.3`, `rel/commons-lang-3.13.0`, etc.).

3. **BUG: "No maintainer data found" appears for ALL Maven packages** due to Maven Central metadata limitations, not actual governance absence. Corporate projects (Spring Boot, Guava, Jackson) are penalized identically to truly unmaintained packages.

**Impact:** These three bugs alone account for 2-6 inflated risk points per Maven package. A Spring Boot starter scored 8/20 (MEDIUM) would likely score 4-5/20 (LOW) with accurate data. The report overstates risk for Maven packages by ~30-50%.

---

## Critical Systemic Issues

### Issue 1: "28 Direct Dependencies" Bug (CRITICAL)

**Affected:** ALL 29 Maven packages + express@4.18.2 (30 packages total)

**Evidence:** Every single Maven package in the report claims "28 direct dependencies found in registry metadata," including:
- `org.projectlombok:lombok@1.18.30` — actual dependencies: **0** (verified via Maven Central POM)
- `com.squareup.okhttp3:okhttp@4.12.0` — actual dependencies: **~3** (okio, kotlin-stdlib)
- `org.apache.commons:commons-lang3@3.13.0` — actual dependencies: **0**
- `com.google.guava:guava@32.1.3-jre` — actual dependencies: **~5-8**

**Root Cause (from source code analysis):**
In `pkg/analyzer/metadata.go:238`, when a local pom.xml is present, `parser.CountMavenDependencies(pomPath)` parses the PROJECT's pom.xml and counts all non-test dependencies. This count (28 for this particular project) then gets attributed to EACH individual Maven package via the `DependencyMetrics` override logic. The code at lines 246-256 can replace registry-accurate per-package counts with the project-wide total.

Additionally, for `express@4.18.2`, the same 28 count appears — suggesting the npm package.json dependency count from the project is also being misattributed.

**Scoring Impact:** Each affected package gets 1-2 risk points from Dependency Sprawl that may be completely undeserved. For packages with 0 real dependencies (Lombok, Commons-Lang3), this is a pure false positive.

**Verdict:** FALSE POSITIVE for all 30 packages

**Fix:** The dependency count must be per-package, not per-project. For Maven, each package's POM should be fetched individually from Maven Central, or the local pom.xml count should not override registry data when registry data is available and more specific.

---

### Issue 2: Git Tag Detection Failure (CRITICAL)

**Affected:** 40 out of 87 packages (46%)

**Evidence — Tags independently verified to exist:**

| Package | Version | Tag Exists? | Actual Tag Format |
|---------|---------|-------------|-------------------|
| psycopg2-binary | 2.9.9 | YES | `2.9.9` |
| httpx | 0.26.0 | YES | `0.26.0` |
| FastAPI | 0.108.0 | YES | `0.108.0` |
| Flask | 3.1.2 | YES | `3.1.2` |
| numpy | 1.26.3 | YES | `v1.26.3` |
| requests | 2.32.4 | YES | `v2.32.4` |
| redis (Python) | 5.0.1 | YES | `v5.0.1` |
| commons-lang3 | 3.13.0 | YES | `rel/commons-lang-3.13.0` |

**Root Cause:** The tag checker appears to look for exact version string matches only, failing on:
- `v` prefix tags (`v1.26.3` for `1.26.3`)
- `rel/` prefix tags (Apache convention: `rel/commons-lang-3.13.0`)
- Complex tag formats (may also miss `project-version` formats common in Maven multi-module projects)

**Scoring Impact:** Each false "no git tag" finding contributes to Release Anomalies scoring (up to 2 risk points).

**Verdict:** FALSE POSITIVE for at minimum the 8 verified packages above; likely false for most of the 40 flagged

**Fix:**
1. Try multiple tag patterns: `{version}`, `v{version}`, `{name}-{version}`, `rel/{name}-{version}`
2. Use `git tag -l "*{version}*"` as a fuzzy fallback
3. For Maven multi-module projects, check parent artifact tag conventions

---

### Issue 3: Missing Maintainer Data for Maven (SIGNIFICANT)

**Affected:** ALL 29 Maven packages

**Evidence:** Maven Central does not expose maintainer/owner data in the same way npm (`maintainers` field) or PyPI (`author`/`maintainer` fields) do. The POM `<developers>` section is optional and not consistently populated. The Snyft fetcher code (`pkg/fetcher/maven.go`) does extract `<developers>` but many POMs don't include this section (or inherit it from parent POMs which aren't always resolved).

**Packages wrongly flagged:**
- `com.google.guava:guava` — Google-maintained, extensive team
- `org.springframework.boot:*` — VMware/Broadcom, large corporate team
- `org.apache.commons:*` — Apache Software Foundation, documented governance
- `com.fasterxml.jackson.core:*` — FasterXML, Tatu Saloranta + community
- `com.squareup.okhttp3:okhttp` — Block Inc. (Square), corporate team

**Scoring Impact:** Triggers "High publisher control risk" (HIGH severity finding) which contributes to Publisher Control category scoring. For corporate/foundation projects, this is entirely misleading.

**Verdict:** MISLEADING — the data gap is real, but the risk conclusion is wrong for well-governed projects

**Fix:**
1. When maintainer data is unavailable for Maven, mark the category as "INSUFFICIENT DATA" instead of "HIGH RISK"
2. Check for organizational signals: GitHub org membership, verified org badge, SCM URL pointing to recognized org (apache/, spring-projects/, google/, etc.)
3. Consider adding a "corporate/foundation" heuristic: if the groupId matches known foundations (org.apache, org.springframework, com.google, com.squareup, etc.), reduce publisher control risk

---

### Issue 4: "100% Team Change" for Single-Maintainer Projects (SIGNIFICANT)

**Affected:** caffeine, pg, date-fns, joi, lodash, and others

**Evidence:** The report flags "1/1 recent authors are new (100% team change)" for projects like:
- **caffeine** — Ben Manes has been sole maintainer since creation (2015)
- **pg (node-postgres)** — Brian Carlson (brianc) has been sole maintainer since creation (2010)
- **date-fns** — Sasha Koss has been primary maintainer throughout

These projects haven't experienced "team change" — they've always had single maintainers. The finding implies malicious takeover risk, but the signal is completely misleading for established single-maintainer projects.

**Root Cause:** The "team change" detection likely compares recent commit authors against historical commit authors. For single-maintainer projects, if the sole maintainer's recent commits are compared against a window that also includes occasional contributors, it appears as if "historical authors stepped back" when in reality they were never core maintainers.

**Scoring Impact:** Contributes to Ownership Changes category (up to 2 risk points).

**Verdict:** MISLEADING — single maintainer IS a legitimate risk factor, but framing it as "team change" implies something that didn't happen

**Fix:**
1. Distinguish between "project has always been single-maintainer" vs "team replacement occurred"
2. Only flag "team change" when there's evidence of actual maintainer transition (new accounts publishing where different accounts previously published)
3. For established single-maintainer projects, the finding should be "Single-maintainer project — bus factor risk" not "100% team change"

---

### Issue 5: Install Execution Scoring for Maven (MODERATE)

**Affected:** Several Maven packages (caffeine scores Install Execution 2/2)

**Evidence:** Maven/Java packages fundamentally do not have install scripts (unlike npm's `preinstall`/`postinstall` hooks). The Install Execution category is designed to detect packages that execute arbitrary code during installation — this attack vector does not exist in the Maven ecosystem.

For packages like caffeine that show Install Execution 2/2, the finding states "No dependency data found in registry metadata" — conflating dependency sprawl with install execution risk.

**Scoring Impact:** 2 risk points added for a category that doesn't apply to the ecosystem.

**Verdict:** FALSE POSITIVE for Maven packages

**Fix:**
1. Skip or zero-out Install Execution for Maven packages (the attack vector doesn't exist)
2. Or repurpose for Maven-specific risks (e.g., Maven plugins with custom lifecycles)

---

### Issue 6: Dormancy Detection Inaccuracy (MODERATE)

**Affected:** psycopg2-binary, mapstruct, jjwt-impl, h2

**Evidence:**
- **psycopg2-binary**: Flagged as "0 recent authors; no active contributors in last 90 days (dormant)" — but psycopg2 released v2.9.11 in October 2025 and v2.9.10 in October 2024. PyPI classifies it as "Production/Stable." The project is actively maintained.
- **mapstruct**: Flagged as dormant, but the project has Filip Hrisafov as active lead and released 1.6.x versions.
- **h2**: Flagged as "Bus factor: 0 (critical)" — but H2 Database has active releases and Thomas Mueller continues development.

**Root Cause:** The dormancy check likely uses a fixed 90-day window on GitHub commit activity. Stable/mature projects may have longer release cycles without being "dormant." Additionally, Git clone may fail or have timeout issues, returning 0 authors.

**Verdict:** FALSE POSITIVE for psycopg2 and mapstruct; MISLEADING for others

**Fix:**
1. Check registry publish dates in addition to Git commit dates
2. Extend the "active" window to 180 or 365 days for mature projects
3. Distinguish "stable and low-activity" from "abandoned"
4. When Git clone fails, don't default to "0 authors (dormant)" — mark as UNVERIFIABLE

---

### Issue 7: Missing Data Defaults to Low Risk (MODERATE)

**Affected:** axios@1.6.5 (2/20 — lowest score)

**Evidence:** axios reports "Failed to fetch repository info: scraping fallback failed: context deadline exceeded" — the tool couldn't fetch ANY data about the repository. Yet it scores 2/20 (LOW), the lowest in the entire report.

This means missing data defaults to LOW risk rather than UNKNOWN, which is backwards. A package you can't verify should have HIGHER uncertainty, not lower risk.

**Scoring Impact:** Falsely reassuring — the score implies axios is safe when in reality we simply don't know.

**Verdict:** MISLEADING — low score due to data absence, not evidence of safety

**Fix:**
1. When data fetch fails, increase uncertainty (lower confidence score)
2. Consider a minimum floor score when key data sources are unavailable
3. The confidence percentage should drop significantly when scraping fails

---

## Per-Package Detailed Audit (22 Packages)

### HIGH-MEDIUM Risk Packages (Score 9-11)

#### 1. com.github.ben-manes.caffeine:caffeine@3.1.8 — Score: 11/20 MEDIUM

| Category | Score | Verdict |
|----------|-------|---------|
| Publisher Control | 0/2 | ACCURATE — Ben Manes is indeed sole maintainer |
| Ownership Changes | 0/2 | ACCURATE — no ownership transfer |
| Release Anomalies | 2/2 | UNVERIFIABLE — "no git tag" likely false positive |
| Install Execution | 2/2 | FALSE POSITIVE — Maven has no install scripts; "no dependency data" conflated |
| Provenance | 2/2 | ACCURATE — no build attestations |
| Health | 0/2 | ACCURATE — 15.3k stars, healthy project |
| Governance | 2/2 | MISLEADING — "no maintainer data" is Maven limitation |
| Release Security | 0/2 | Needs verification |
| Package Maturity | 0/2 | ACCURATE — mature project |

**Findings audit:**
- [HIGH] "Single maintainer" — **ACCURATE** but score impact exaggerated. Ben Manes is well-known in Java community.
- [HIGH] "100% team change" — **MISLEADING**. Project has always been single-maintainer.
- [HIGH] "Bus factor: 1" — **ACCURATE** as a risk factor.
- [HIGH] "No release security controls" — **PARTIALLY ACCURATE** but contradicts own evidence ("OSSF Branch-Protection: 8/10").
- [MEDIUM] "No git tag for 3.1.8" — **UNVERIFIABLE** (likely false positive given tag detection bugs).
- [MEDIUM] "No dependency data" — **MISLEADING** (Install Execution irrelevant for Maven).
- **Adjusted score estimate:** ~6-7/20 (LOW) after removing false positives

#### 2. pg@8.11.3 — Score: 11/20 MEDIUM

| Finding | Verdict |
|---------|---------|
| Single maintainer (brianc) | **ACCURATE** — brianc is sole npm maintainer |
| 100% team change | **MISLEADING** — brianc has always been the maintainer |
| Bus factor: 1 | **ACCURATE** |
| No git tag for 8.11.3 | **UNVERIFIABLE** — likely tag format issue |
| No release security controls | **ACCURATE** — no signing, no automated publish |

**Assessment:** Single-maintainer risk is real for pg, but "team change" framing is misleading. Score somewhat justified but inflated by tag false positive.

#### 3. express@4.18.2 — Score: 10/20 MEDIUM

| Finding | Verdict |
|---------|---------|
| 75% team change (6/8 new authors) | **MISLEADING** — Express moved to OpenJS Foundation; contributor rotation is normal |
| 2 npm maintainers | **NEEDS VERIFICATION** — Express is managed by OpenJS; npm maintainer count may not reflect governance |
| OSSF Branch-Protection: 3/10 | **NEEDS VERIFICATION** |
| 28 direct dependencies | **FALSE POSITIVE** — project-wide count misattributed |
| No git tag for 4.18.2 | **UNVERIFIABLE** — Express uses `v4.18.2` tag format |

**Assessment:** Express is foundation-governed but findings don't reflect this. The 28 dependency count is demonstrably wrong.

#### 4. date-fns@3.0.6 — Score: 10/20 MEDIUM

| Finding | Verdict |
|---------|---------|
| 100% team change | **MISLEADING** — Sasha Koss has been primary maintainer throughout |
| OSSF Branch-Protection: 0/10 | **CONCERNING if accurate** — warrants verification |
| Bus factor: 1 | **ACCURATE** |
| 2 npm maintainers | **NEEDS VERIFICATION** |

**Assessment:** The single-maintainer risk is real but findings overstate the situation.

#### 5. psycopg2-binary@2.9.9 — Score: 10/20 MEDIUM

| Finding | Verdict |
|---------|---------|
| "0 recent authors; dormant" | **FALSE POSITIVE** — released v2.9.11 in Oct 2025 |
| "Bus factor: 0 (critical)" | **FALSE POSITIVE** — Daniele Varrazzo is active maintainer |
| "No git tag for 2.9.9" | **FALSE POSITIVE** — tag `2.9.9` confirmed on GitHub |
| OSSF Scorecard 4.6/10 | **NEEDS VERIFICATION** |
| 4 maintainers, 1 new | **ACCURATE** (per PyPI metadata) |

**Assessment:** Severely inflated score. At least 3 findings are demonstrably false. Adjusted score: ~4-5/20.

#### 6. io.jsonwebtoken:jjwt-impl@0.12.3 — Score: 9/20 MEDIUM

| Finding | Verdict |
|---------|---------|
| No maintainer data | **MISLEADING** — Maven Central limitation; Les Hazlewood maintains it |
| 73 authors, none active (dormant) | **NEEDS VERIFICATION** — JJWT had v0.12.5 released |
| 28 direct dependencies | **FALSE POSITIVE** — jjwt-impl has ~1-2 dependencies (jjwt-api) |
| No git tag for 0.12.3 | **UNVERIFIABLE** — may use different tag convention |

#### 7. com.h2database:h2@2.2.224 — Score: 10/20 MEDIUM

| Finding | Verdict |
|---------|---------|
| Single maintainer, dormant | **NEEDS VERIFICATION** — Thomas Mueller is known maintainer |
| Bus factor: 0 (critical) | **MISLEADING** — "0" implies abandoned; more nuanced reality |
| 28 dependencies | **FALSE POSITIVE** |
| No git tag | **UNVERIFIABLE** |

#### 8. org.mapstruct:mapstruct@1.5.5.Final — Score: 10/20 MEDIUM

| Finding | Verdict |
|---------|---------|
| No maintainer data | **FALSE POSITIVE** — Filip Hrisafov is documented project lead; Gunnar Morling founded it |
| Dormant (0 recent authors) | **FALSE POSITIVE** — MapStruct released 1.6.x versions |
| 28 dependencies | **FALSE POSITIVE** — MapStruct 1.5.5.Final has 0 compile dependencies |
| Bus factor: 0 | **FALSE POSITIVE** |

**Assessment:** Nearly all findings are wrong. MapStruct has active governance, zero dependencies, and regular releases.

---

### LOW Risk Packages (Score 2-8)

#### 9. org.springframework.boot:spring-boot-starter-web@3.2.1 — Score: 8/20 MEDIUM

| Finding | Verdict |
|---------|---------|
| No maintainer data | **MISLEADING** — VMware/Broadcom corporate team |
| 28 direct dependencies | **MISLEADING** — Starters ARE dependency aggregators by design |
| No automated release process | **FALSE POSITIVE** — Spring has one of Java's most sophisticated release pipelines |
| No strong build attestations | **ACCURATE** (no Sigstore/in-toto attestations) |

**Assessment:** Spring Boot is among the most well-governed Java projects. Score of 8/20 is unfair. Adjusted: ~3-4/20.

#### 10. com.google.guava:guava@32.1.3-jre — Score: 7/20 LOW

| Finding | Verdict |
|---------|---------|
| No maintainer data | **MISLEADING** — Google-maintained |
| 28 direct dependencies | **FALSE POSITIVE** — Guava has ~5-8 real dependencies |
| No git tag for 32.1.3-jre | **UNVERIFIABLE** — Guava uses `v32.1.3` tag format |
| No build attestations | **ACCURATE** |

**Assessment:** Score inflated by Maven limitations. Adjusted: ~3-4/20.

#### 11. com.fasterxml.jackson.core:jackson-databind@2.15.3 — Score: 7/20 LOW

| Finding | Verdict |
|---------|---------|
| No maintainer data | **MISLEADING** — Tatu Saloranta + FasterXML community |
| 28 dependencies | **FALSE POSITIVE** — jackson-databind has ~3-4 compile deps |
| No git tag | **UNVERIFIABLE** — Jackson uses `jackson-databind-2.15.3` tag format |

#### 12. org.apache.commons:commons-lang3@3.13.0 — Score: 7/20 LOW

| Finding | Verdict |
|---------|---------|
| No maintainer data | **MISLEADING** — Apache Software Foundation governance |
| No git tag | **FALSE POSITIVE** — tag `rel/commons-lang-3.13.0` confirmed to exist |
| No dependency data | **ACCURATE** (commons-lang3 genuinely has 0 dependencies) |

#### 13. lodash@4.17.21 — Score: 6/20 LOW

| Finding | Verdict |
|---------|---------|
| Single maintainer (jdalton) | **ACCURATE** |
| No git tag for 4.17.21 | **NEEDS VERIFICATION** |
| Bus factor: 3 | **MISLEADING** — lodash is effectively unmaintained (last release 2021) |

**Note:** lodash's actual risk may be HIGHER than scored — it's effectively abandoned with 200M+ weekly downloads. The tool misses this because it focuses on active team metrics rather than abandonment signals.

#### 14. fastapi@0.108.0 — Score: 6/20 LOW

| Finding | Verdict |
|---------|---------|
| No git tag for 0.108.0 | **FALSE POSITIVE** — tag `0.108.0` confirmed on GitHub |
| Bus factor: 4 | **NEEDS VERIFICATION** |
| No build attestations | **ACCURATE** |

#### 15. Flask@3.1.2 — Score: 6/20 LOW

| Finding | Verdict |
|---------|---------|
| No git tag for 3.1.2 | **FALSE POSITIVE** — tag `3.1.2` confirmed on GitHub |
| Bus factor: 3 | **NEEDS VERIFICATION** |
| No build attestations | **ACCURATE** |

**Note:** Flask is a Pallets project with documented governance. Score is roughly appropriate but git tag finding is wrong.

#### 16. numpy@1.26.3 — Score: 4/20 LOW

| Finding | Verdict |
|---------|---------|
| No git tag for 1.26.3 | **FALSE POSITIVE** — tag `v1.26.3` confirmed on GitHub |
| Bus factor: 7 | **ACCURATE** (NumPy has many contributors) |
| No automated release process | **FALSE POSITIVE** — NumPy has well-documented, automated releases |

#### 17. jest@29.7.0 — Score: 4/20 LOW

| Finding | Verdict |
|---------|---------|
| No git tag for 29.7.0 | **NEEDS VERIFICATION** — Jest likely uses `v29.7.0` format |
| Bus factor: 8 | **ACCURATE** |
| No automated release process | **NEEDS VERIFICATION** |

#### 18. requests@2.32.4 — Score: 5/20 LOW

| Finding | Verdict |
|---------|---------|
| No git tag for 2.32.4 | **FALSE POSITIVE** — tag `v2.32.4` confirmed on GitHub |
| Bus factor: 2 | **ACCURATE** |
| No build attestations | **ACCURATE** |

#### 19. redis@4.6.12 (npm) — Score: 4/20 LOW

**Assessment:** Score seems reasonable. Limited findings. redis-py (Python) tag `v5.0.1` was confirmed to exist.

#### 20. axios@1.6.5 — Score: 2/20 LOW

| Finding | Verdict |
|---------|---------|
| Failed to fetch repository info (timeout) | **ACCURATE** (data collection failed) |
| No git tag for 1.6.5 | **UNVERIFIABLE** (couldn't even access repo) |
| Bus factor: 8 | **UNCLEAR** (how was this determined if repo fetch failed?) |

**Assessment:** **MISLEADING** — Score of 2/20 gives false confidence. The low score is because most checks couldn't run, not because axios is low-risk. Confidence should be near 0%.

#### 21. org.projectlombok:lombok@1.18.30 — Score: 8/20 MEDIUM

| Finding | Verdict |
|---------|---------|
| No maintainer data | **MISLEADING** — Lombok has known maintainers |
| 28 direct dependencies | **FALSE POSITIVE** — Lombok has **zero** compile dependencies (confirmed via Maven Central) |
| No git tag | **UNVERIFIABLE** |
| No build attestations | **ACCURATE** |

#### 22. com.squareup.okhttp3:okhttp@4.12.0 — Score: 8/20 MEDIUM

| Finding | Verdict |
|---------|---------|
| No maintainer data | **MISLEADING** — Square/Block Inc. corporate project |
| 28 dependencies | **FALSE POSITIVE** — OkHttp has ~3 dependencies (okio, kotlin-stdlib) |
| No git tag | **UNVERIFIABLE** — OkHttp uses `parent-4.12.0` tag format |
| No build attestations | **ACCURATE** |

---

## Summary Verdict Table

| Finding Type | Count | ACCURATE | FALSE POSITIVE | MISLEADING | UNVERIFIABLE |
|---|---|---|---|---|---|
| "28 direct dependencies" (Maven) | 29 | 0 | **29** | 0 | 0 |
| "No git tag found" | 40 | ~0 | **8+ confirmed** | 0 | ~32 |
| "No maintainer data" (Maven) | 29 | 0 | 0 | **29** | 0 |
| "100% team change" (single-maint) | ~8 | 0 | 0 | **~8** | 0 |
| Dormancy claims | ~5 | ~1 | **~3** | ~1 | 0 |
| Bus factor claims | ~15 | **~10** | ~2 | ~3 | 0 |
| "No build attestations" | ~20 | **~20** | 0 | 0 | 0 |
| Single maintainer | ~8 | **~8** | 0 | 0 | 0 |
| Install Execution for Maven | ~5 | 0 | **~5** | 0 | 0 |

---

## Recommendations

### P0 — Must Fix Before Production Use

1. **Fix Maven dependency count bug** — Per-package dependency counting instead of project-wide pom.xml total. The 28-for-all-Maven-packages is a data attribution error.

2. **Fix git tag detection** — Support multiple tag naming conventions:
   - `{version}`, `v{version}`, `V{version}`
   - `{artifactId}-{version}` (Maven convention)
   - `rel/{artifactId}-{version}` (Apache convention)
   - `{name}/{version}` (monorepo convention)

3. **Fix missing data → risk inflation** — When data is unavailable (maintainer data for Maven, failed scraping for axios), the score should reflect UNCERTAINTY, not risk. Options:
   - Mark category as "INSUFFICIENT DATA" (don't assign risk points)
   - Lower confidence percentage significantly
   - Add a minimum floor score when key data sources fail

### P1 — Should Fix Before Security Team Presentation

4. **Distinguish "always single-maintainer" from "team replacement"** — The "100% team change" finding should only fire when actual ownership transition is detected, not when a project has always had one maintainer.

5. **Skip Install Execution for Maven** — Java packages don't have install scripts. This category should be skipped or scored 0 for Maven ecosystem.

6. **Improve dormancy detection** — Check registry publish dates (not just Git commit dates). psycopg2 was falsely flagged as dormant despite releasing versions in 2024-2025.

7. **Add corporate/foundation recognition** — When groupId matches known organizations (org.apache.*, org.springframework.*, com.google.*, com.squareup.*), adjust publisher control and governance scores. The metadata gap is a tooling limitation, not a governance gap.

### P2 — Nice to Have

8. **Deduplicate findings across Spring Boot starters** — All 8 starters produce identical findings since they're from the same project. Consider grouping or noting "same source project."

9. **Abandoned project detection** — lodash (last release 2021, 200M+ weekly downloads) is a higher actual risk than most MEDIUM-scored packages, but the tool doesn't surface abandonment risk well.

10. **Contradictory evidence handling** — caffeine's Release Security states both "OSSF Branch-Protection: 8/10" AND "No release security controls detected" in the same finding. These contradict each other.

---

## Defensibility Assessment

**Could you present this to a security team and stand behind it?**

**No, not in its current form.** The three critical bugs (Maven dependency count, git tag detection, missing data handling) affect the majority of packages and would be quickly spotted by anyone familiar with Maven, Spring Boot, or other major Java frameworks. A security team member who knows that Lombok has zero dependencies would immediately question the tool's credibility.

**What would make it defensible:**
1. Fix the three P0 bugs
2. Add clear "data confidence" indicators so consumers understand when scores are based on incomplete data
3. Add ecosystem-appropriate scoring (Maven vs npm vs PyPI have fundamentally different metadata models)
4. Separate "we couldn't find data" from "data indicates risk"

The tool's core approach — assessing supply chain risk factors — is sound and valuable. The academic grounding (Backstabber's Knife Collection, Zimmermann et al.) is appropriate. But the implementation has data quality issues that undermine the output's reliability for Maven/Java ecosystems specifically. npm and PyPI scoring appears more reliable, though git tag detection issues affect all ecosystems.
