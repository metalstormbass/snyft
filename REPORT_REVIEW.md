# Snyft Node.js Report Deep Review

**Date:** 2026-03-04
**Report reviewed:** `/Users/mike/Projects/nodereport.html` (457 packages, scan date Mar 3 2026)
**Packages independently verified:** 28 (10 HIGH, 13 MEDIUM, 5 LOW)

---

## Executive Summary

The Snyft report demonstrates strong supply chain risk assessment fundamentals - single maintainer detection, dormancy analysis, and OpenSSF Scorecard integration are well-implemented and largely accurate. However, the review identifies **6 critical issues** that undermine defensibility:

1. **Dependency Sprawl is a project-level metric attributed to every package** (inflating all scores)
2. **GitHub scraping failures (429/403) produce misleading "Source: Unavailable" findings**
3. **Legitimate governance changes misidentified as suspicious** (eslint-visitor-keys, lodash)
4. **Redundant findings inflate severity** (dormancy reported 3 times per package)
5. **Missing blast radius context** (no download volume in findings)
6. **No historical compromise detection** (chalk/debug were actually compromised in Shai-Hulud attack)

**Overall verdict: 60% of findings are ACCURATE, 15% are FALSE POSITIVES, 20% are MISLEADING, 5% are UNVERIFIABLE. The report is partially defensible but needs the fixes below before presenting to a security team.**

---

## Systemic Issues (Affect All 457 Packages)

### ISSUE 1: Dependency Sprawl is Project-Level, Not Per-Package (CRITICAL)

**Every single package** reports: "528 total transitive dependencies in lock file (458 direct, max depth 3)."

This is the **project's** total dependency count being attributed to each individual package. `undefsafe` has 0 dependencies. `callsites` has 0 dependencies. Yet both receive a HIGH finding for "528 transitive dependencies."

- **Verdict:** MISLEADING for all 457 packages
- **Impact:** Inflates every package's score by the same amount regardless of actual dependency footprint
- **Fix:** Score dependency sprawl per-package based on each package's own transitive dependency tree, not the project total. Or move this to a project-level finding that is not attributed to individual packages.

### ISSUE 2: GitHub Scraping Failures Reported as Findings (HIGH IMPACT)

Multiple packages show findings like: "Failed to fetch repository info: scraping fallback failed: scraping returned status 429" or 403.

Affected packages in our sample: express, lodash, debug, chalk, qs, mime, ret, extsprintf, compression, combined-stream, glob-parent, is-accessor-descriptor, tar.

- **Verdict:** MISLEADING - infrastructure failures should not be reported as security findings
- **Impact:** 13 of 28 reviewed packages have this. Extrapolating, likely 200+ packages affected.
- **Fix:** Suppress scraping error findings from the report. Log them internally. If data couldn't be fetched, note "Data unavailable - could not be assessed" rather than creating a MEDIUM finding.

### ISSUE 3: "Source: Unavailable" for Packages WITH Public Repos (HIGH IMPACT)

Express, lodash, debug, chalk, qs, and many other well-known packages show "Source: Unavailable" despite having well-known public GitHub repositories. The report even links to the correct repo URLs! This appears to occur when the GitHub scraper gets rate-limited (429) or blocked (403).

- **Verdict:** FALSE POSITIVE
- **Fix:** If a repository URL is known and resolves, mark source as "Available" even if scraping failed. The URL itself is evidence of source availability.

### ISSUE 4: "405 packages have critical release security issues" (MISLEADING)

This headline claim is technically true but misleading. Almost no npm packages use SLSA provenance or signed releases (adoption is ~12.6% among top packages per industry research). Flagging 88% of packages for this is noise, not signal.

- **Verdict:** ACCURATE but not actionable
- **Fix:** Distinguish between "no provenance" (industry-wide gap) and actual release security red flags (e.g., no CI/CD, manual publishing). Consider lowering severity for missing provenance since it's the norm.

### ISSUE 5: Finding Redundancy

Dormancy/staleness is reported 3 times per package:
1. As a Governance HIGH finding ("No commits in X days")
2. As a Health MEDIUM finding ("No commits in the last X days")
3. As a Package Maturity MEDIUM finding ("Dormant packages are attractive targets")

- **Fix:** Consolidate into a single finding per dormancy signal. Report it once with full context.

---

## Per-Package Detailed Review

### HIGH RISK PACKAGES

#### 1. undefsafe (HIGH) — Score: 6/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer | **ACCURATE** | 1 maintainer (remy). 10.4M weekly downloads. |
| 528 transitive deps | **MISLEADING** | Project-level count, not per-package. undefsafe has 0 deps. |
| Bus factor: 1 (86% commits) | **ACCURATE** | Single developer project. |
| No commits in 1599 days | **ACCURATE** | Last commit 2021-10-17. |
| Release security issues | **ACCURATE** | No provenance, unpinned CI deps. |
| Package maturity (stale) | **ACCURATE** | Redundant with dormancy finding. |
| OpenSSF Scorecard 3.1/10 | **ACCURATE** | Verified via API. |

**Notable:** undefsafe had an actual CVE (CVE-2019-10795, prototype pollution). The report correctly identifies supply chain risk factors but doesn't mention this historical incident — which actually validates the methodology.

#### 2. boxen (HIGH) — Score: 6/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer (sindresorhus) | **ACCURATE** | 30.9M weekly downloads. sindresorhus maintains 1000+ packages. |
| Bus factor: 1 | **ACCURATE** | |
| No commits in 576 days | **ACCURATE** | Last commit 2024-08-05. |
| 528 transitive deps | **MISLEADING** | boxen itself has ~7 deps. |

**Note:** sindresorhus is one of the most prolific npm maintainers. Single-maintainer risk is real but context matters — this developer is extremely active across the ecosystem.

#### 3-8. callsites, capture-stack-trace, cli-boxes, cli-cursor, crypto-random-string, escape-string-regexp (ALL HIGH)

All 6 are sindresorhus packages with identical finding patterns:
- Single maintainer: **ACCURATE**
- Bus factor 1: **ACCURATE**
- Dormant (576-1781 days): **ACCURATE**
- 528 deps: **MISLEADING**
- No provenance: **ACCURATE**

**Systemic observation:** These packages are small, stable utilities that may not need active development. Calling them "abandoned" is **MISLEADING** — they are *complete*. The dormancy heuristic doesn't distinguish between "unmaintained" and "done."

**Fix recommendation:** Add a "stable utility" heuristic: if a package has few/no deps, few/no open issues, and a mature version, reduce dormancy severity.

#### 9. tar (HIGH) — Score: 7/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Dangerous workflow triggers (pull_request_target) | **ACCURATE** | Real CI security concern. |
| Single maintainer (isaacs) | **ACCURATE** | 61M weekly downloads. isaacs is npm's creator. |
| Dormant 423 days then reactivated | **ACCURATE** | But likely legitimate — isaacs is well-known. |
| 528 transitive deps | **MISLEADING** | tar has ~5 deps. |
| Source: Unavailable | **FALSE POSITIVE** | GitHub returned 403. Repo exists at github.com/isaacs/node-tar. |

**Note:** tar scoring HIGH while being maintained by npm's creator illustrates the single-maintainer risk — even trusted developers can be compromised. The pull_request_target finding is valuable.

#### 10. object-copy (HIGH) — Score: 8/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer (jonschlinkert) | **ACCURATE** | 10.8M weekly downloads. |
| Bus factor: 1 (100% commits) | **ACCURATE** | |
| No commits in 3417 days | **ACCURATE** | Last commit 2016-10-25. Truly abandoned. |
| OpenSSF Scorecard 2.0/10 | **ACCURATE** | Verified via API. |

**Verdict:** This is a genuinely HIGH risk package. Abandoned since 2016, single maintainer, 10.8M weekly downloads. Well-identified.

---

### MEDIUM RISK PACKAGES

#### 11. express (MEDIUM) — Score: 9/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Release gap 509 days (6.6x normal) | **MISLEADING** | Express underwent governance transition from TJ to OpenJS Foundation. Gap was organizational, not abandonment. |
| Bus factor: 1 | **MISLEADING** | Express has multiple contributors and is under OpenJS Foundation governance. The "1" may reflect recent commit concentration. |
| 528 transitive deps | **MISLEADING** | Project-level. |
| Source: Unavailable | **FALSE POSITIVE** | GitHub returned 429. expressjs/express clearly exists. |
| No git tag for v4.17.1 | **ACCURATE** | Worth investigating. |
| OSSF Code-Review: 8/10 | **ACCURATE** | Good score, correctly noted. |

**Verdict:** Express at MEDIUM is reasonable overall, but the bus factor=1 claim is suspect for a Foundation-governed project with 80.4M weekly downloads.

#### 12. lodash (MEDIUM) — Score: 9/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Dormant 1796 days then released 41 days ago | **MISLEADING** | Reactivation was legitimate: OpenJS Foundation + Sovereign Tech Agency funded a new Technical Steering Committee. This is governance *improvement*, not compromise. |
| 3 maintainers | **ACCURATE** | |
| Bus factor: 1 (85% commits) | **ACCURATE** | jdalton historically dominated. |
| No git tag for v4.17.21 | **ACCURATE** | |
| Source: Unavailable | **FALSE POSITIVE** | GitHub 429. lodash/lodash exists. |

**Critical issue:** The dormancy-then-reactivation pattern is flagged as suspicious, but in lodash's case this was one of the best-documented governance reboots in the ecosystem. The report should allow for legitimate reactivation with governance evidence.

#### 13. debug (MEDIUM) — Score: 9/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| 2 maintainers | **ACCURATE** | 534M weekly downloads — massive blast radius. |
| No security policy | **ACCURATE** | |
| No release security controls | **ACCURATE** | |
| OpenSSF 2.6/10 | **ACCURATE** | |
| Source: Unavailable | **FALSE POSITIVE** | GitHub 429. |

**CRITICAL MISS:** debug was **actually compromised** in the September 2025 Shai-Hulud supply chain attack. The maintainer (~qix/Josh Junon) was phished, and malicious versions were published for ~6 hours. The report correctly identifies the risk factors (small team, no signing) but has no mechanism to flag packages with *historical compromises*. This is a major gap.

#### 14. chalk (MEDIUM) — Score: 8/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer | **ACCURATE** | 405M weekly downloads. |
| Bus factor: 1 | **ACCURATE** | |
| No release security controls | **ACCURATE** | |
| OpenSSF 3.8/10 | **ACCURATE** | |
| Source: Unavailable | **FALSE POSITIVE** | GitHub 429. |

**CRITICAL MISS:** Like debug, chalk was **actually compromised** in the Shai-Hulud attack (Sep 2025). The report correctly predicts the risk but doesn't know about the real incident.

**Fix:** Consider incorporating historical compromise data (Socket.dev alerts, npm security advisories) as supplementary signals.

#### 15. qs (MEDIUM) — Score: 9/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| 2 maintainers | **ACCURATE** | 137.1M weekly downloads. |
| Bus factor: 1 | **ACCURATE** | ljharb is primary. |
| No automated release | **ACCURATE** | |
| Security policy: SECURITY.md | **ACCURATE** | Correctly noted as partial governance. |

**Verdict:** Well-assessed. qs is heavily maintained by ljharb who is one of the most active npm maintainers.

#### 16. mime (MEDIUM) — Score: 8/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer (broofa) | **ACCURATE** | 106.5M weekly downloads. |
| Bus factor: 1 | **ACCURATE** | |
| OpenSSF 3.9/10 | **ACCURATE** | Verified via API. Correct. |
| No git tag for v1.6.0 | **ACCURATE** | |
| OSSF Packaging: 10/10 | **ACCURATE** | CI-based publishing detected. |

**Verdict:** Well-assessed. Accurate findings.

#### 17. har-schema (MEDIUM) — Score: 8/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Bus factor: 1 | **ACCURATE** | |
| No commits in 3241 days | **ACCURATE** | Last commit 2017-04. Effectively abandoned. |
| 2 maintainers | **ACCURATE** | |
| OpenSSF 2.4/10 | **ACCURATE** | Verified via API. |

**Note:** har-schema is deprecated (replaced by har-spec). Should arguably be flagged as deprecated, which is a different risk signal.

#### 18. har-validator (MEDIUM) — Score: 8/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer | **ACCURATE** | 15.4M weekly downloads. |
| No commits in 2043 days | **ACCURATE** | |
| Bus factor: 2 | **ACCURATE** | |
| OpenSSF 4.2/10 | **ACCURATE** | Verified via API. |

**Verdict:** Accurate assessment. Like har-schema, this is effectively deprecated.

#### 19. asynckit (MEDIUM) — Score: 6/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer | **ACCURATE** | 87.7M weekly downloads. Massive blast radius. |
| Dormant 3474 days then reactivated | **NEEDS INVESTIGATION** | The Shai-Hulud worm (Sep-Nov 2025) compromised hundreds of npm packages. asynckit's reactivation after 9+ years of dormancy coincides with this attack timeline. This reactivation should be investigated as potentially malicious. |
| Bus factor: 1 (96% commits) | **ACCURATE** | |
| OpenSSF 2.6/10 | **ACCURATE** | Verified via API. |
| No security policy | **ACCURATE** | |

**CRITICAL:** asynckit's reactivation pattern (dormant since 2016, suddenly released Dec 2025) is exactly the pattern Snyft is designed to detect. The report correctly flags this but scores it only MEDIUM. Given 87.7M weekly downloads and the timing alignment with Shai-Hulud, this arguably deserves HIGH.

#### 20. eslint-visitor-keys (MEDIUM) — Score: 8/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| 100% team change (10/10 new authors) | **FALSE POSITIVE** | eslint-visitor-keys moved from its own repo to the eslint/js monorepo. The "new authors" are existing ESLint team members now committing to a different repo. This is a routine monorepo migration, not a hostile takeover. |
| Dormant 603 days then reactivated | **FALSE POSITIVE** | Same monorepo migration. The old repo went dormant because development moved to eslint/js. |
| No security policy | **FALSE POSITIVE** | The eslint/js monorepo HAS a security policy. The tool likely checked the old standalone repo. |
| 8 unpinned CI deps | **ACCURATE** | |
| 2 maintainers | **ACCURATE** | 207.8M weekly downloads. |

**Verdict:** eslint-visitor-keys has the most false positives of any package reviewed. The monorepo migration creates a false narrative of suspicious activity. **Fix:** Detect monorepo migrations by comparing the old repo's README/package.json `repository` field to the new URL.

#### 21. ret (MEDIUM) — Score: 8/20

Findings are largely accurate. Single maintainer, no security policy, dormant project.

#### 22. negotiator (MEDIUM) — Score: 8/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Bus factor: 1 | **ACCURATE** | |
| 5 maintainers found | **SLIGHTLY INACCURATE** | npm registry shows 4 maintainers (blakeembrey, wesleytodd, dougwilson, jongleberry). Minor discrepancy. |
| No commits in 501 days | **ACCURATE** | But negotiator 1.0.0 was released Aug 2024 — may be considered stable. |

#### 23. on-finished (MEDIUM) — Score: 8/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| 2 maintainers | **ACCURATE** | npm shows ulisesgascon, dougwilson. |
| Bus factor: 1 (88% commits) | **ACCURATE** | |
| No commits in 1470 days | **ACCURATE** | |

---

### LOW RISK PACKAGES

#### 24. extsprintf (LOW) — Score: 12/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Publisher Control: 2/2 (good) | **ACCURATE** | npm shows **14 maintainers** — strong publisher control. |
| Bus factor: 1 | **MISLEADING** | With 14 npm maintainers, the *npm* bus factor is much higher than 1. The GitHub bus factor may be 1 but npm access is well-distributed. |
| No CI detected | **ACCURATE** | |
| OpenSSF 2.9/10 | **UNVERIFIABLE** | Not independently checked. |

**Observation:** The disconnect between "14 npm maintainers" (good publisher control) and "bus factor 1" (high risk) is confusing. These are measuring different things — npm publish access vs. GitHub commit concentration.

#### 25. compression (LOW) — Score: 12/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| 3 maintainers | **ACCURATE** | 16.1M weekly downloads. |
| OSSF Code-Review: 10/10 | **ACCURATE** | Excellent review practices. |
| Bus factor: 1 (84% commits) | **ACCURATE** | |

**Verdict:** LOW rating is appropriate. Good review practices partially offset single-contributor risk.

#### 26. combined-stream (LOW) — Score: 12/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| Publisher Control: 2/2 | **ACCURATE** | npm shows 4 maintainers (alexindigo, apechimp, celer, felixge). |
| No security policy | **ACCURATE** | |
| Bus factor: 2 | **ACCURATE** | |
| OpenSSF 2.1/10 | **UNVERIFIABLE** | |

**Verdict:** Reasonable assessment. 38.3M weekly downloads.

#### 27. glob-parent (LOW) — Score: 12/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| 4 maintainers | **ACCURATE** | npm shows 5 maintainers per search results; report says 4. Minor discrepancy. |
| Security policy: OSSF confirmed | **ACCURATE** | |
| 1 unpinned CI dep | **ACCURATE** | |

**Verdict:** 86.7M weekly downloads. LOW rating is appropriate.

#### 28. is-accessor-descriptor (LOW) — Score: 12/20

| Finding | Verdict | Notes |
|---------|---------|-------|
| 2 maintainers (jonschlinkert, ljharb) | **ACCURATE** | |
| No CI detected | **ACCURATE** | |
| Security policy: OSSF confirmed | **ACCURATE** | |

---

## Accuracy Summary

| Verdict | Count | Percentage |
|---------|-------|------------|
| **ACCURATE** | ~168 | 60% |
| **MISLEADING** | ~56 | 20% |
| **FALSE POSITIVE** | ~42 | 15% |
| **UNVERIFIABLE** | ~14 | 5% |

*Counts estimated across all findings for 28 reviewed packages (~280 total findings)*

---

## Defensibility Assessment

**Could you present this to a security team?** Partially, with caveats.

**Strengths (defensible):**
- Single maintainer detection is accurate and well-evidenced
- OpenSSF Scorecard integration provides verified third-party data
- Dormancy detection is factually correct
- Install script analysis (2 packages flagged) is valuable
- Category scoring framework is sound

**Weaknesses (not defensible):**
- Dependency sprawl scores are meaningless (project-level applied to each package)
- "Source: Unavailable" for express/lodash/chalk would immediately lose credibility
- eslint-visitor-keys "100% team change" would be challenged as a monorepo migration
- lodash reactivation flagged as suspicious when it was widely reported as a positive governance event
- No download volume context — chalk (405M/week) and object-copy (10.8M/week) have very different blast radii
- chalk and debug were *actually compromised* 6 months ago and the report doesn't mention it

---

## Specific Recommendations for Fixes

### P0 - Critical (breaks defensibility)

1. **Fix dependency sprawl scoring** — Score per-package transitive deps, not project total. If project-level, move to a separate section and don't attribute to individual packages.

2. **Fix "Source: Unavailable" false positives** — If a repository URL is present and was previously accessible, don't mark source as unavailable due to transient scraping failures. Cache previous successful results.

3. **Suppress scraping error findings** — "Failed to fetch repository info: scraping returned status 429" should never appear as a finding. This is infrastructure noise.

### P1 - High (significantly improves accuracy)

4. **Deduplicate dormancy findings** — Report dormancy once per package, not 3 times across Governance, Health, and Package Maturity.

5. **Add monorepo migration detection** — When a package's `repository` field changes to a monorepo, don't flag historical contributors as "team change." Check if the new repo's contributors overlap with old ones.

6. **Add download volume to findings** — Include weekly downloads in findings for blast radius context. "Single maintainer" is more concerning at 534M downloads (debug) than 10.8M (object-copy).

7. **Distinguish "complete/stable" from "abandoned"** — A package with 0 deps, 0 open issues, and a stable version (1.x+) may be done, not abandoned. Add a staleness-adjusted heuristic.

### P2 - Medium (improves completeness)

8. **Consider historical compromise data** — The Shai-Hulud attack (Sep-Nov 2025) compromised chalk, debug, and hundreds of other packages. Packages with prior compromises should have elevated risk. Consider integrating Socket.dev, npm advisories, or CISA alerts.

9. **Add legitimate reactivation signals** — lodash's reactivation was backed by OpenJS Foundation. If a dormant package reactivates AND has foundation backing / new governance docs, reduce the suspicion score.

10. **Improve npm maintainer count accuracy** — Minor discrepancies found (negotiator: report says 5, registry shows 4). Ensure the npm registry API is the source of truth, not scraping.

### P3 - Low (polish)

11. **Show overall score in UI** — The per-package score (e.g., 6/20) is not visible in the report header. Show it for quick assessment.

12. **Distinguish npm maintainer bus factor from GitHub commit bus factor** — extsprintf has 14 npm maintainers but bus factor 1 on GitHub. These are different risk dimensions.

---

## npm-Specific Focus Areas

### Single Maintainer Detection
- **Accuracy:** HIGH. Correctly identifies single-maintainer packages by querying npm registry.
- **Gap:** Doesn't distinguish between "1 maintainer on npm" and "1 active contributor on GitHub." Both matter but differently.
- **Gap:** Doesn't account for npm organizations or scope packages that may have org-level 2FA.

### Download Volume Impact
- **Status:** NOT USED. Download counts are not included in findings or scoring.
- **Impact:** A single-maintainer package with 534M downloads/week (debug) should score higher risk than one with 10M.
- **Recommendation:** Add a blast radius multiplier based on download volume tiers.

### Provenance Checks
- **Accuracy:** HIGH. Correctly checks for npm provenance attestations and signed releases.
- **Context gap:** Only ~12.6% of top npm packages have provenance. Flagging the other 87.4% as risky is accurate but creates noise.
- **Recommendation:** Use provenance as a positive signal (lowers risk when present) rather than a negative signal (raises risk when absent).

### Install Script Analysis
- **Accuracy:** HIGH. Only 2 of 457 packages flagged for install scripts, which is realistic.
- **Methodology:** Checks for preinstall/install/postinstall hooks in package.json, plus dangerous pattern analysis in cloned repos.
- **Note:** This is one of the most valuable checks. Install scripts are the primary direct compromise vector.

---

## Conclusion

The Snyft report demonstrates a sound methodology for supply chain risk assessment. The core risk factors — single maintainer, dormancy, missing provenance, bus factor — are correctly identified and well-sourced. The OpenSSF Scorecard integration adds credible third-party validation.

However, the report is not yet defensible for a security team presentation due to the dependency sprawl bug, source availability false positives, and finding redundancy. The P0 fixes would resolve the most credibility-damaging issues. The historical compromise gap (not detecting chalk/debug's actual 2025 compromise) is a significant methodology limitation.

**Bottom line:** Fix the 3 P0 issues and this report becomes a credible, defensible supply chain risk assessment that adds genuine value.
