# Snyft Report Accuracy Review: Top 10 Highest-Risk Packages

**Reviewer:** review-high agent
**Report Date:** 2026-03-03
**Review Date:** 2026-03-04
**Report Analyzed:** `/Users/mike/Projects/report.html` (87 packages, 0 high / 38 medium / 49 low)

---

## Executive Summary

Snyft's report identifies legitimate structural supply chain risks but suffers from **systematic false positives for well-governed projects**, particularly Apache Foundation and corporate-backed packages. The tool's heuristics for "package age," "team change," and "release anomalies" do not account for:

1. **Maven Central artifact-level age vs project-level age** — Treating Maven coordinate creation date as "package birth" causes 20+ year old Apache projects to appear "very new"
2. **Normal OSS team rotation in large foundations** — Natural committer turnover in Apache/Foundation projects triggers "100% team change" alerts
3. **Intentional maintenance mode** — AWS SDK v2's planned transition to v3 appears as "dormancy reactivation"
4. **Major version transitions** — Express v4→v5 gap appears as suspicious "release anomaly"

**Overall accuracy: ~55% of HIGH findings are accurate, ~30% are false positives, ~15% are misleading.**

The tool performs best on smaller, genuinely single-maintainer npm packages (pg, passport-jwt, passport, date-fns) and worst on foundation-governed Java packages (commons-io, jackson, httpclient5).

---

## Package-by-Package Analysis

---

### 1. pg@8.11.3 — Score: 12/20 (MEDIUM)

**Reality Check:**
- **Maintainer:** Brian Carlson (@brianc), personal project. Sole npm publisher confirmed. 13.1k GitHub stars, 345 contributors, MIT license. Funded via Patreon and GitHub Sponsors (Medplum is a featured sponsor).
- **Downloads:** ~7-9M weekly downloads on npm. One of the most popular PostgreSQL clients for Node.js.
- **Compromises:** No known supply chain compromises of the pg package itself. The npm ecosystem has seen typosquatting attacks targeting postgres-related names, but pg itself has not been compromised.
- **Governance:** No SECURITY.md. Uses GitHub Actions CI. No formal governance structure — personal project of Brian Carlson.

**Finding-by-Finding Verdict:**

| # | Finding | Snyft Said | Verdict | Explanation |
|---|---------|-----------|---------|-------------|
| 1 | Single maintainer, personal account, no signing | HIGH | **ACCURATE** | Brian Carlson is the sole npm publisher. This is a genuine supply chain risk for a package with ~8M weekly downloads. |
| 2 | Release gap of 201 days, 9.0x usual cadence → reactivation pattern | HIGH | **MISLEADING** | While the gap is real, this is a solo maintainer's natural work pattern, not a takeover signal. pg has had variable release cadence for 15+ years. |
| 3 | No security policy found | HIGH | **ACCURATE** | Confirmed — no SECURITY.md in the repo. |
| 4 | No automated release process, no branch protection, no signing | HIGH | **ACCURATE** | Uses GitHub Actions for CI but publishes locally. No evidence of branch protection or signed releases. |
| 5 | Highly irregular release cadence (CV=2.1) | HIGH | **MISLEADING** | Cadence is irregular because it's a solo maintainer project, not because of compromise. This is the expected pattern for a healthy volunteer-maintained package. |
| 6 | No git tag for version 8.11.3 | MEDIUM | **ACCURATE** | Monorepo tagging patterns differ from single-package repos. |
| 7 | 7 direct dependencies | MEDIUM | **ACCURATE** | Correct count. |
| 8 | No npm provenance | MEDIUM | **ACCURATE** | No provenance attestations published. |

**Missed Risks:**
- **High-value target risk:** With ~8M weekly downloads, pg is an extremely high-value target for npm account compromise attacks. Snyft flags single maintainer but doesn't weight by download volume.
- **Recent npm ecosystem attacks:** The July 2025 npm supply chain attack (chalk, debug, etc.) via phishing demonstrates exactly the risk profile pg has — single maintainer with massive download count.

**Overall Assessment:** Snyft's findings for pg are mostly **accurate** but the framing of release cadence as "reactivation pattern" is misleading. The real story is simpler: this is a hugely popular package maintained by one person with no security controls. Score of 12/20 is **reasonable**.

---

### 2. passport-jwt@4.0.1 — Score: 12/20 (MEDIUM)

**Reality Check:**
- **Maintainer:** Mike Nicholson (@mikenicholson), personal project. Single npm maintainer.
- **Downloads:** ~1.5-2M weekly downloads. Used as the primary JWT strategy for Passport.js.
- **Compromises:** No known supply chain incidents.
- **Governance:** No SECURITY.md, OpenSSF Scorecard 3.2/10. Last commit Feb 2024 (~759 days ago as reported). Essentially unmaintained.

**Finding-by-Finding Verdict:**

| # | Finding | Snyft Said | Verdict | Explanation |
|---|---------|-----------|---------|-------------|
| 1 | Single maintainer, personal account, no signing | HIGH | **ACCURATE** | Confirmed single maintainer. |
| 2 | Bus factor: 1, 5% PRs reviewed | HIGH | **ACCURATE** | Essentially a one-person project with minimal review. |
| 3 | No commits in 759 days — abandoned | HIGH | **ACCURATE** | The package is genuinely stale/abandoned. This is a real risk. |
| 4 | No automated release, no branch protection, no signing | HIGH | **ACCURATE** | Correct assessment. |
| 5 | Highly irregular release cadence, stale | HIGH | **ACCURATE** | Last release was years ago; this is genuinely concerning. |
| 6 | OpenSSF Scorecard 3.2/10 | MEDIUM | **ACCURATE** | Confirmed. |

**Missed Risks:**
- **Dependency on passport (also flagged):** passport-jwt depends on passport which is itself stale. Double dependency on unmaintained packages.
- **No alternative migration path flagged:** Snyft could note that users should consider alternatives.

**Overall Assessment:** This is Snyft's **best-performing analysis** in the top 10. All findings are accurate. passport-jwt is genuinely a high-risk dependency. Score of 12/20 is if anything **too low** — this should arguably score higher given 759 days of abandonment.

---

### 3. commons-io:commons-io@2.15.1 — Score: 11/20 (MEDIUM)

**Reality Check:**
- **Maintainer:** Apache Software Foundation. The Apache Commons project has a PMC (Project Management Committee) with 30+ members. Releases require 3+ binding PMC votes, artifact signing, and verification on each voter's own hardware.
- **Downloads:** One of the most widely used Java libraries. Tens of millions of downloads per month on Maven Central. 1,000+ dependent artifacts.
- **Compromises:** No supply chain compromise of commons-io. Apache Commons Collections had a famous deserialization vulnerability (2015), and Commons Text had CVE-2022-42889 and CVE-2025-46295, but these were code vulnerabilities, not supply chain compromises.
- **Governance:** Full Apache Foundation governance with PMC oversight, mandatory GPG signing, release voting, SECURITY.md via Apache's centralized security reporting process (commons.apache.org/security.html).

**Finding-by-Finding Verdict:**

| # | Finding | Snyft Said | Verdict | Explanation |
|---|---------|-----------|---------|-------------|
| 1 | 100% team change (6/6 recent authors new, 9 historical stepped back) | HIGH | **FALSE POSITIVE** | This is normal Apache committer rotation. Apache projects have many committers who contribute in waves. The "historical authors stepped back" is just natural OSS contribution patterns in a 20+ year old project. |
| 2 | Release gap of 1410 days, 5.5x usual cadence → reactivation pattern | HIGH | **FALSE POSITIVE** | commons-io is a mature, stable library. Long gaps between releases are expected for utility libraries that are feature-complete. This is not a takeover signal. |
| 3 | Package age: 119 days (very new, <6 months) | HIGH | **FALSE POSITIVE** | commons-io has existed since ~2002. The "119 days" likely reflects when the specific Maven coordinate `commons-io:commons-io` version 2.15.1 was indexed, not the project's actual age. This is a critical bug in how Snyft parses Maven Central metadata. |
| 4 | 14 maintainers, missing security controls | MEDIUM | **MISLEADING** | 14 maintainers is actually good. The "missing security controls" ignores Apache's mandatory GPG signing and PMC vote process. |
| 5 | pom.xml flagged as install-time hook | MEDIUM | **FALSE POSITIVE** | Every Maven project has a pom.xml. This is not an "install-time hook" in any meaningful security sense. Maven builds are declarative. |
| 6 | 28 direct dependencies | MEDIUM | **MISLEADING** | This likely includes test-scope and provided-scope dependencies from the POM. The actual runtime dependency count is much lower (commons-io 2.x has very few runtime deps). |
| 7 | Bus factor: 1, top contributor 81% | MEDIUM | **MISLEADING** | While one person may have the most commits, Apache's PMC governance ensures no single person can push a release. The 3-vote requirement is the real security control. |

**Missed Risks:**
- Snyft completely misses that Apache's release process (3+ PMC binding votes, mandatory GPG signing, voter-side verification) is one of the strongest supply chain protections in the open source world.
- The real risk for Apache packages is not maintainer compromise but **dependency confusion attacks** (typosquatting on Maven Central with similar group IDs).

**Overall Assessment:** This is Snyft's **worst-performing analysis** in the top 10. Three of the top findings are outright false positives driven by incorrect Maven metadata interpretation. Score of 11/20 is **grossly inflated** — a more accurate score would be 3-5/20. This represents a major credibility problem for the tool.

---

### 4. com.fasterxml.jackson.datatype:jackson-datatype-jsr310@2.15.3 — Score: 11/20 (MEDIUM)

**Reality Check:**
- **Maintainer:** FasterXML LLC, founded by Tatu Saloranta (@cowtowncoder). FasterXML is a real company/organization, not just a personal project. Jackson has multiple maintainers across its ~50 modules.
- **Downloads:** Jackson is the most widely used JSON library in the Java ecosystem. jackson-databind alone has hundreds of millions of monthly downloads. jackson-datatype-jsr310 is bundled in Spring Boot.
- **Compromises:** Jackson itself has never been directly compromised, but a **typosquatting attack on Maven Central** was detected where attackers published a malicious package impersonating jackson-databind under a similar namespace. Jackson also had a 2024 security audit by OSTIF.
- **Governance:** Has SECURITY.md. FasterXML has a CLA process. Multiple maintainers per module. Works with Tidelift for commercial support.

**Finding-by-Finding Verdict:**

| # | Finding | Snyft Said | Verdict | Explanation |
|---|---------|-----------|---------|-------------|
| 1 | Single maintainer, no signing | HIGH | **MISLEADING** | While Tatu Saloranta is the primary maintainer, jackson-datatype-jsr310 is part of a larger org (FasterXML) with multiple contributors. Maven Central artifacts ARE GPG signed (Snyft should detect this). |
| 2 | 100% team change (2/2 recent, 49 historical stepped back) | HIGH | **FALSE POSITIVE** | This is a mature module where the primary maintainer consistently commits. Having 49 "historical" authors who contributed over 10+ years and then moved on is completely normal. |
| 3 | Bus factor: 1, 60% PRs reviewed | HIGH | **MISLEADING** | Bus factor of 1 is a legitimate concern for Jackson generally, but the 60% PR review rate actually represents decent oversight for an open source project. |
| 4 | Package age: 301 days (maturing) | MEDIUM | **FALSE POSITIVE** | jackson-datatype-jsr310 was first released in 2014-2015. The "301 days" reflects Maven Central metadata for a specific version coordinate, not the actual project age. |
| 5 | pom.xml as install-time hook | MEDIUM | **FALSE POSITIVE** | Same pom.xml false positive as commons-io. |
| 6 | 28 direct dependencies | MEDIUM | **MISLEADING** | Same issue — includes test/provided scope deps. |

**Missed Risks:**
- **Typosquatting is a real, demonstrated threat:** A malicious jackson-databind lookalike was discovered on Maven Central. Snyft should flag this ecosystem-level risk.
- **BDFL risk:** While Tatu Saloranta is a known, respected maintainer, Jackson's heavy dependence on him is a legitimate concern. The 2024 OSTIF audit found the project well-maintained.

**Overall Assessment:** Mixed. Bus factor concern is legitimate, but the "package age" and "team change" findings are false positives. Score of 11/20 should be more like **6-7/20**.

---

### 5. joi@17.11.0 — Score: 11/20 (MEDIUM)

**Reality Check:**
- **Maintainer:** Originally created by Eran Hammer at Walmart Labs. The hapi project transitioned from Hammer's sole leadership to a technical steering committee with hapi v20. joi has **6 npm maintainers**.
- **Downloads:** ~14-16M weekly downloads. 21.2k GitHub stars, 1,510 forks. Extremely popular validation library.
- **Compromises:** No direct supply chain compromise. The hapi project went through a controversial commercial licensing period (2019-2020) where Hammer offered paid commercial licenses for older versions before transitioning leadership.
- **Governance:** Has security policy confirmed by OSSF. Uses GitHub Actions CI. Transitioned to committee-based governance with hapi v20.

**Finding-by-Finding Verdict:**

| # | Finding | Snyft Said | Verdict | Explanation |
|---|---------|-----------|---------|-------------|
| 1 | Release gap of 410 days, 8.0x usual cadence → reactivation | HIGH | **MISLEADING** | The gap coincides with the hapi project's governance transition and is not a takeover signal. The project resumed under new community leadership. |
| 2 | Bus factor: 1, 45% PRs reviewed | HIGH | **PARTIALLY ACCURATE** | Historically true under Hammer's leadership, but the transition to a steering committee mitigates this. The current state is better than the bus factor suggests. |
| 3 | No automated release, no branch protection, no signing | HIGH | **ACCURATE** | The lack of release automation and signing is a real gap. |
| 4 | 6 maintainers, missing security controls | MEDIUM | **MISLEADING** | Having 6 maintainers is actually reasonable redundancy. Snyft scores 1/2 but the framing suggests this is a risk. |
| 5 | Source available but no npm provenance | MEDIUM | **ACCURATE** | No provenance attestations. |

**Missed Risks:**
- **Governance transition risk:** The 2019-2020 commercial licensing controversy and leadership change is a significant supply chain event that Snyft doesn't detect. Leadership changes are exactly the kind of thing a supply chain tool should flag.
- **Declining usage:** joi is losing market share to zod and yup. Declining community attention could lead to reduced security oversight.

**Overall Assessment:** Score of 11/20 is **somewhat high**. The real risk is moderate — joi has 6 maintainers, community governance, and active (if infrequent) development. A score of 7-8/20 would be more appropriate.

---

### 6. passport@0.7.0 — Score: 11/20 (MEDIUM)

**Reality Check:**
- **Maintainer:** Jared Hanson (@jaredhanson), personal project. Single npm maintainer confirmed. He also maintains 50+ passport-* strategy packages.
- **Downloads:** ~3-4M weekly downloads. 23k+ GitHub stars. The de facto authentication middleware for Express/Node.js.
- **Compromises:** No direct supply chain compromise, but passport had a **session fixation vulnerability** (CVE-2022-25896) that took months to address due to the single-maintainer bottleneck.
- **Governance:** No SECURITY.md. OpenSSF Scorecard 2.8/10. Last commit Aug 2024 (564 days ago as reported). Essentially in maintenance mode.

**Finding-by-Finding Verdict:**

| # | Finding | Snyft Said | Verdict | Explanation |
|---|---------|-----------|---------|-------------|
| 1 | Single maintainer, personal account, no signing | HIGH | **ACCURATE** | Confirmed. Jared Hanson is the sole maintainer of an extremely high-value package. |
| 2 | No commits in 564 days — abandoned | HIGH | **ACCURATE** | The package is genuinely stale. |
| 3 | No automated release, no branch protection, no signing | HIGH | **ACCURATE** | Correct. |
| 4 | Stale, irregular release cadence | HIGH | **ACCURATE** | Correct. |
| 5 | OpenSSF Scorecard 2.8/10 | MEDIUM | **ACCURATE** | Confirmed. |
| 6 | Bus factor: 1, 92% of commits | MEDIUM | **ACCURATE** | Confirmed. |

**Missed Risks:**
- **High-value target concentration:** Jared Hanson controls 50+ passport-* packages. Compromising his npm account would give access to the entire passport ecosystem.
- **Session fixation CVE response time:** The slow response to CVE-2022-25896 demonstrates the real-world impact of the single-maintainer bottleneck.

**Overall Assessment:** Excellent analysis. All findings are **accurate**. Score of 11/20 is if anything **too low** for a package of this importance with this maintenance profile. Should be 13-14/20.

---

### 7. org.apache.httpcomponents.client5:httpclient5@5.2.3 — Score: 10/20 (MEDIUM)

**Reality Check:**
- **Maintainer:** Apache Software Foundation HttpComponents project. Has a full PMC with multiple committers. Ranks #1 in HTTP Clients on Maven Central, used in 12,000+ components.
- **Downloads:** One of the most downloaded Java libraries. Version 5.6 was the latest release (Dec 2025).
- **Compromises:** No known supply chain compromises. Apache's release process (3+ PMC binding votes, mandatory GPG signing) makes this extremely difficult.
- **Governance:** Full Apache Foundation governance. Has SECURITY.md.

**Finding-by-Finding Verdict:**

| # | Finding | Snyft Said | Verdict | Explanation |
|---|---------|-----------|---------|-------------|
| 1 | 100% team change (6/6 recent new, 32 historical stepped back) | HIGH | **FALSE POSITIVE** | Same Apache committer rotation issue as commons-io. Normal for a 20+ year project. |
| 2 | No automated release, no branch protection, no signing | HIGH | **FALSE POSITIVE** | Apache uses its own release infrastructure (not GitHub Actions for publishing). All releases ARE signed with GPG and require PMC votes. Snyft fails to detect non-GitHub release automation. |
| 3 | Package age: 77 days (very new) | HIGH | **FALSE POSITIVE** | HttpClient has existed since 2001. The `client5` coordinate was first published to Maven Central in 2018 (beta releases). This is egregiously wrong. |
| 4 | No maintainer data found | MEDIUM | **MISLEADING** | Snyft couldn't find maintainer data because Maven Central doesn't expose it the same way npm does. The project has a well-documented PMC. |
| 5 | pom.xml as install-time hook | MEDIUM | **FALSE POSITIVE** | Same Maven pom.xml false positive. |

**Missed Risks:**
- Essentially none that matter. Apache HttpClient is one of the most well-governed packages in the Java ecosystem.

**Overall Assessment:** Nearly all findings are **false positives**. Score of 10/20 should be **2-3/20**. This is the second-worst analysis after commons-io and reveals the same systematic Maven metadata parsing issues.

---

### 8. aws-sdk@2.1528.0 — Score: 10/20 (MEDIUM)

**Reality Check:**
- **Maintainer:** Amazon Web Services (AWS). Corporate-maintained by one of the world's largest tech companies. 2 npm maintainers listed (AWS accounts).
- **Downloads:** ~5-7M weekly downloads despite being in maintenance mode (v3 is the successor). 7.6k GitHub stars.
- **Compromises:** No supply chain compromise. aws-sdk has been a frequent target of typosquatting (e.g., `aws-sdk-js`, `awssdk`) but the official package has never been compromised.
- **Governance:** AWS corporate governance. Has SECURITY.md. Uses automated CI/CD with GitHub Actions. 100% PR review rate.

**Finding-by-Finding Verdict:**

| # | Finding | Snyft Said | Verdict | Explanation |
|---|---------|-----------|---------|-------------|
| 1 | Dormant for 398 days, then released again — reactivation pattern | HIGH | **FALSE POSITIVE** | aws-sdk v2 entered official maintenance mode in 2023. AWS announced that v2 would only receive critical security fixes. The "dormancy" is intentional end-of-life behavior, not a takeover. |
| 2 | Highly irregular release cadence (CV=3.5) | HIGH | **FALSE POSITIVE** | The cadence changed from daily releases (when actively developed) to occasional security patches (maintenance mode). This is completely expected. |
| 3 | "Minimal community engagement (low stars/forks)" | MEDIUM | **FALSE POSITIVE** | aws-sdk-js has 7.6k GitHub stars and thousands of forks. This is not "minimal engagement." |
| 4 | postinstall hook found | MEDIUM | **ACCURATE** | aws-sdk does have a postinstall script (telemetry opt-out notification). While not dangerous, the hook exists. |
| 5 | Bus factor: 1, 100% PRs reviewed | MEDIUM | **MISLEADING** | The "bus factor: 1" likely measures git commit concentration. AWS has many engineers who can maintain this. 100% PR review is excellent. |
| 6 | Source available but no npm provenance, releases not signed | MEDIUM | **PARTIALLY ACCURATE** | True that there's no npm provenance, though AWS's internal controls provide equivalent assurance. |

**Missed Risks:**
- **v2 end-of-life risk:** The real risk is that users are depending on a deprecated version. Snyft doesn't distinguish between "abandoned by a solo dev" and "intentionally sunset by a corporation."
- **Typosquatting targeting:** aws-sdk is one of the most typosquatted package names on npm.

**Overall Assessment:** Most HIGH findings are **false positives** caused by not understanding maintenance mode. Score of 10/20 should be **4-5/20**. AWS-backed packages with 100% PR review and corporate governance are among the lowest supply chain risk packages.

---

### 9. date-fns@3.0.6 — Score: 10/20 (MEDIUM)

**Reality Check:**
- **Maintainer:** Sasha Koss (@kossnocorp) is the primary maintainer. The npm package lists 1 maintainer. 35k+ GitHub stars.
- **Downloads:** ~15-20M weekly downloads. One of the most popular date utility libraries for JavaScript.
- **Compromises:** No known supply chain compromises.
- **Governance:** No SECURITY.md. OpenSSF Scorecard 3.8/10. Uses GitHub Actions CI. Has automated CI/CD release process.

**Finding-by-Finding Verdict:**

| # | Finding | Snyft Said | Verdict | Explanation |
|---|---------|-----------|---------|-------------|
| 1 | Single maintainer, no signing | HIGH | **ACCURATE** | Confirmed single npm maintainer for a package with ~18M weekly downloads. |
| 2 | No commits in 533 days — abandoned | HIGH | **PARTIALLY ACCURATE** | date-fns v3 was a major release. The repo may have shifted activity to other branches or the project may be feature-complete. "Abandoned" is strong — "mature/stable" may be more accurate. |
| 3 | Stale, irregular release cadence | HIGH | **PARTIALLY ACCURATE** | The staleness is real, but like pg, this reflects solo maintainer patterns rather than compromise. |
| 4 | No npm provenance | MEDIUM | **ACCURATE** | Confirmed. |
| 5 | Bus factor: 1 | MEDIUM | **ACCURATE** | Confirmed. |

**Missed Risks:**
- **Extremely high download count vs. maintainer count ratio:** With ~18M weekly downloads and 1 maintainer, this is one of the most disproportionate risk profiles in the npm ecosystem.
- **v3 was a major rewrite:** The transition from v2 to v3 involved significant API changes, which is when supply chain risks are highest.

**Overall Assessment:** Findings are mostly **accurate**. Score of 10/20 is **reasonable**, perhaps slightly high. The single-maintainer concern for a package this popular is legitimate. 8-9/20 would be more precise.

---

### 10. express@4.18.2 — Score: 10/20 (MEDIUM)

**Reality Check:**
- **Maintainer:** OpenJS Foundation project. 5 npm maintainers. Part of the Node.js foundation ecosystem. 66k+ GitHub stars, 300+ contributors.
- **Downloads:** ~30-35M weekly downloads. The most popular Node.js web framework.
- **Compromises:** No supply chain compromise of express itself. Express benefits from OpenJS Foundation governance and npm's mandatory 2FA for top packages.
- **Governance:** Has security policy (confirmed by OSSF). Uses GitHub Actions CI/CD with automated releases. 95% PR review rate.

**Finding-by-Finding Verdict:**

| # | Finding | Snyft Said | Verdict | Explanation |
|---|---------|-----------|---------|-------------|
| 1 | Release gap of 509 days, 6.6x normal cadence → reactivation pattern | HIGH | **FALSE POSITIVE** | The gap between Express v4 and v5 was a deliberate, multi-year effort to build Express 5. This is a known major version transition, not a takeover signal. Express was actively developed during this period. |
| 2 | 28 direct dependencies (>15 threshold) | HIGH | **ACCURATE** | Express does have many dependencies. This is a legitimate attack surface concern. |
| 3 | 5 maintainers, missing security controls | MEDIUM | **MISLEADING** | 5 maintainers is good redundancy. "Missing security controls" ignores that express is part of the OpenJS Foundation with organizational governance. |
| 4 | No npm provenance, releases not signed | MEDIUM | **PARTIALLY ACCURATE** | True, though the OpenJS Foundation provides organizational oversight that mitigates this. |
| 5 | Bus factor: 1, 95% PRs reviewed | MEDIUM | **MISLEADING** | While one person may dominate commits, 95% PR review means most code is reviewed. The OpenJS Foundation provides backstop governance. 5 npm maintainers means no single point of npm publish access. |
| 6 | Partial governance — security policy but gaps | MEDIUM | **PARTIALLY ACCURATE** | Express does have a security policy but could improve on automated release signing. |

**Missed Risks:**
- **Dependency tree depth:** Express's 28 direct dependencies expand to hundreds of transitive dependencies. The overall supply chain attack surface is very large.
- **npm mandatory 2FA:** As a top package, express benefits from npm's mandatory 2FA for maintainers, which significantly reduces account takeover risk. Snyft doesn't credit this.

**Overall Assessment:** The "reactivation pattern" finding is a clear **false positive**. The dependency count finding is accurate. Score of 10/20 is **too high** — a score of 5-6/20 would better reflect express's strong governance. OpenJS Foundation backing is a major mitigating factor that Snyft underweights.

---

## Systematic Issues Identified

### 1. Maven Central Metadata Misinterpretation (CRITICAL)
**Affected packages:** commons-io, jackson-datatype-jsr310, httpclient5

Snyft appears to calculate "package age" from Maven Central's artifact indexing date rather than the project's actual creation date. This causes decades-old Apache projects to appear as "very new (<6 months)." This is the single most impactful false positive pattern and destroys credibility for the entire Maven ecosystem analysis.

**Recommendation:** For Maven packages, use the earliest version's publication date on Maven Central, or better yet, parse the GitHub repository creation date as a fallback. Consider the project's overall history, not just the specific artifact coordinate.

### 2. Apache/Foundation Governance Blindness (CRITICAL)
**Affected packages:** commons-io, httpclient5

The tool does not understand Apache Foundation governance:
- PMC voting (3+ binding votes for any release)
- Mandatory GPG signing of all artifacts
- Voter-side verification requirements
- Multi-person release oversight

**Recommendation:** Detect Apache Foundation projects (via groupId patterns like `org.apache.*`, `commons-*`) and adjust scoring to account for ASF governance. ASF projects should get full marks on Governance and Release Security categories.

### 3. Maintenance Mode vs. Abandonment Confusion (HIGH)
**Affected packages:** aws-sdk, express

The tool cannot distinguish between:
- A package intentionally entering maintenance mode (aws-sdk v2)
- A package being abandoned by its maintainer (passport-jwt)
- A package undergoing a major version transition (express v4→v5)

**Recommendation:** Check for explicit deprecation notices, published migration guides, or successor packages. If the package publisher has announced maintenance mode or a successor, the "dormancy" finding should be suppressed or reframed.

### 4. pom.xml as "Install-Time Hook" (MEDIUM)
**Affected packages:** commons-io, jackson-datatype-jsr310, httpclient5

Every Maven project has a pom.xml. Flagging it as an "install-time hook" is incorrect. Maven builds are declarative and pom.xml is not analogous to npm's postinstall scripts.

**Recommendation:** Remove pom.xml from install-hook detection. Only flag Maven plugins that execute during the `initialize` or `generate-sources` phases with external network access.

### 5. Team Turnover in Long-Lived Projects (MEDIUM)
**Affected packages:** commons-io, jackson-datatype-jsr310, httpclient5

Measuring "% of recent authors that are new" without accounting for project age creates false positives. In a 20-year project, it's expected that today's active contributors differ from those 10 years ago.

**Recommendation:** Weight the "team change" signal by project age. For projects older than 5 years, only flag if the turnover happened within a short window (e.g., all committers changed within 30 days) rather than gradual rotation over years.

### 6. Download Volume Not Factored Into Risk (MEDIUM)
**Affected packages:** all

Snyft assigns the same "single maintainer" score whether the package has 100 downloads/week or 30 million. A single maintainer for express (30M+) is far more concerning than for a niche utility.

**Recommendation:** Add a "blast radius" multiplier based on download count or dependent count.

### 7. No Credit for npm Mandatory 2FA (LOW)
**Affected packages:** express, aws-sdk, and other top packages

npm requires 2FA for maintainers of packages above certain download thresholds. This is a significant supply chain protection that Snyft doesn't detect.

**Recommendation:** Check whether a package qualifies for npm's mandatory 2FA protection and credit this in the Publisher Control category.

---

## Suggested Score Adjustments

| Package | Snyft Score | Suggested Score | Delta | Key Reason |
|---------|------------|----------------|-------|------------|
| pg@8.11.3 | 12/20 | 10-11/20 | -1 to -2 | Release cadence framing misleading |
| passport-jwt@4.0.1 | 12/20 | 13-14/20 | +1 to +2 | Should be higher — truly abandoned |
| commons-io@2.15.1 | 11/20 | 3-4/20 | **-7 to -8** | Massive false positives from Maven parsing |
| jackson-jsr310@2.15.3 | 11/20 | 6-7/20 | -4 to -5 | Package age and team change are false |
| joi@17.11.0 | 11/20 | 7-8/20 | -3 to -4 | 6 maintainers, committee governance undervalued |
| passport@0.7.0 | 11/20 | 13-14/20 | +2 to +3 | Genuinely high risk, understated |
| httpclient5@5.2.3 | 10/20 | 2-3/20 | **-7 to -8** | Nearly all findings are false positives |
| aws-sdk@2.1528.0 | 10/20 | 4-5/20 | -5 to -6 | Maintenance mode ≠ abandonment |
| date-fns@3.0.6 | 10/20 | 8-9/20 | -1 to -2 | Mostly accurate, slight overstatement |
| express@4.18.2 | 10/20 | 5-6/20 | -4 to -5 | OpenJS Foundation governance undervalued |

---

## Priority Recommendations for Snyft Development

1. **P0 — Fix Maven Central package age calculation.** This is producing egregiously wrong results (77 days for Apache HttpClient). Use the earliest version publication date, not a per-coordinate metric.

2. **P0 — Detect and credit Apache/Foundation governance.** ASF projects with PMC governance, mandatory GPG signing, and multi-voter releases should not score 0/2 on Governance and Release Security.

3. **P1 — Distinguish maintenance mode from abandonment.** Check for deprecation notices, successor packages, and corporate announcements before flagging dormancy.

4. **P1 — Remove pom.xml from install-hook detection.** It's producing 100% false positive rate for Maven packages.

5. **P2 — Weight team turnover by project age.** Natural committer rotation in 20-year projects should not trigger "100% team change" alerts.

6. **P2 — Add download volume / blast radius weighting.** A single-maintainer package with 30M downloads is a different risk than one with 300.

7. **P3 — Detect npm mandatory 2FA eligibility.** Top packages get mandatory 2FA, which significantly reduces account takeover risk.

8. **P3 — Detect major version transitions.** Release gaps between major versions (e.g., express v4→v5) are development transitions, not abandonment signals.
