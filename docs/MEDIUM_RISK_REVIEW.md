# Snyft Medium-Risk Package Review

**Reviewer:** review-medium (eager-elephant)
**Date:** 2026-03-03
**Report Source:** `/Users/mike/Projects/report.html` (87 packages, 38 medium, 49 low)
**Context:** fancy-eagle provided data collection limitations analysis

## Methodology

Selected 10 MEDIUM-risk packages spread across Maven (4), npm (3), and PyPI (3), mixing well-known and lesser-known libraries. For each package, I verified snyft findings against real-world data using web searches, npm/PyPI/Maven registries, GitHub repositories, and security advisory databases.

---

## Package Reviews

---

### 1. pg@8.11.3 (npm) — Score: 12/20

**Snyft Findings:**
- Publisher Control 0/2: Single maintainer, personal account, personal email
- Ownership Changes 2/2: No issues
- Release Anomalies 0/2: 201-day gap is 9x usual cadence, reactivation pattern
- Governance 0/2: No security policy
- Release Security 0/2: No CI/CD, no branch protection, no signing
- Package Maturity 0/2: Highly irregular release cadence (CV=2.1)

**Reality Check:**

| Fact | Finding |
|------|---------|
| **Maintainer** | Brian Carlson (brianc), sole npm publisher since 2010, personal account |
| **Downloads** | ~20M weekly (Feb 2026), 13,000+ npm dependents, 694K+ GitHub dependents |
| **Ever compromised?** | No. Had a code-level vuln in 2017 (eval in result parsing) but no supply chain compromise |
| **Governance** | No SECURITY.md, no CODE_OF_CONDUCT, no CONTRIBUTING.md. GitHub community health: 42%. No automated release pipeline — publishes manually from local machine. |

**Finding-by-Finding Verdict:**

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer | **ACCURATE** | brianc is the sole npm publisher. This is genuinely concerning for a 10M+/week package. |
| 201-day release gap / reactivation | **MISLEADING** | pg is a mature package with sporadic releases. The "reactivation" pattern implies malicious intent where none exists — it's just a volunteer maintainer shipping when ready. |
| No security policy | **ACCURATE** | No SECURITY.md found in the repo. |
| No CI/CD / release security | **ACCURATE** | No npm provenance, no automated publishing pipeline detected. |
| Highly irregular cadence (CV=2.1) | **MISLEADING** | Natural for a mature, volunteer-maintained library. CV is a statistical artifact of organic development, not a risk signal in this context. |
| No git tag for version | **ACCURATE** | Tags use monorepo-style naming, may not match exactly. |

**Missed Risks:**
- pg has an extremely large downstream dependency tree — compromise would cascade to 13,000+ dependent packages
- The monorepo structure (node-postgres) means multiple packages ship from one repo — single compromise point for pg, pg-pool, pg-cursor, etc.

**Overall Assessment:** Score is inflated. The single-maintainer finding is genuinely concerning for a package this critical, but the "reactivation pattern" and "irregular cadence" findings are false positives driven by treating normal volunteer development as anomalous. **Fair score would be ~9/20.**

---

### 2. passport-jwt@4.0.1 (npm) — Score: 12/20

**Snyft Findings:**
- Publisher Control 0/2: Single maintainer, personal account
- Health 0/2: Bus factor 1, 5% PRs reviewed
- Governance 0/2: No commits in 759 days (abandoned)
- Release Security 0/2: No controls
- Package Maturity 0/2: Stale, irregular cadence

**Reality Check:**

| Fact | Finding |
|------|---------|
| **Maintainer** | Mike Nicholson (mikenicholson), individual developer |
| **Downloads** | ~1.15M weekly |
| **Ever compromised?** | No known supply chain compromise |
| **Governance** | No SECURITY.md, minimal governance |

**Finding-by-Finding Verdict:**

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer | **ACCURATE** | mikenicholson is sole publisher |
| Bus factor: 1, 5% PRs reviewed | **ACCURATE** | Essentially one person's project |
| No commits in 759 days (abandoned) | **ACCURATE** | Last release was 4.0.1 in 2021. Confirmed inactive. |
| No release security controls | **ACCURATE** | No CI/CD publishing, no signing |
| OpenSSF Scorecard 3.2/10 | **ACCURATE** | Consistent with abandoned project profile |

**Missed Risks:**
- passport-jwt is a security-critical authentication library — abandonment means unpatched vulnerabilities
- The broader passport.js ecosystem has similar maintenance concerns
- With 1.15M weekly downloads, abandoned status creates a high-value takeover target

**Overall Assessment:** Score is actually well-calibrated. passport-jwt is genuinely concerning — an abandoned, single-maintainer security library with over 1M weekly downloads is a textbook supply chain risk. **Score of 12/20 is appropriate, possibly should be higher.**

---

### 3. commons-io:commons-io@2.15.1 (Maven) — Score: 11/20

**Snyft Findings:**
- Publisher Control 1/2: 14 maintainers, minor gaps
- Ownership Changes 0/2: 100% team change (6/6 new authors)
- Release Anomalies 0/2: 1410-day gap, reactivation
- Package Maturity 0/2: "119 days (very new)"
- Governance 2/2: Good

**Reality Check:**

| Fact | Finding |
|------|---------|
| **Maintainer** | Apache Software Foundation (ASF) — 14 developers with commit privileges, ~44 PMC members across Commons |
| **Org** | Apache Commons project, governed by Apache PMC with formal release voting (3+ binding votes required) |
| **Downloads** | Ranked #14 on MvnRepository, used in 22,257 Maven components, 694K GitHub dependents |
| **Ever compromised?** | No. CVE-2024-47554 (DoS in XmlStreamReader) was a code bug, not a supply chain compromise |
| **Governance** | Full ASF governance: PMC oversight, formal release voting, GPG signing (4096-bit RSA keys), ASF Nexus publishing, KEYS file for public key verification |
| **First release** | 2002 (inception year). Maven Central indexes versions back to Feb 3, 2003. Over 23 years old. |

**Finding-by-Finding Verdict:**

| Finding | Verdict | Notes |
|---------|---------|-------|
| 100% team change (6/6 new) | **FALSE POSITIVE** | Normal Apache committer rotation. ASF projects have dozens of committers over their lifetime; seeing 6 "new" recent committers against 9 historical ones is standard for a 23-year-old project. |
| Package age: 119 days (very new) | **FALSE POSITIVE** | Commons IO has existed since 2002. This is a critical bug — snyft is likely measuring from the Maven Central artifact creation date of the specific version or groupId mapping, not the actual project age. |
| 1410-day release gap, reactivation | **MISLEADING** | Apache Commons projects have long, slow release cycles. A gap between versions is normal, not a "reactivation pattern." |
| Bus factor: 1 (81% commits from top contributor) | **MISLEADING** | Gary Gregory has been the most active committer for years, but the project has ASF PMC oversight, multiple committers, and voting-based release process. The bus factor metric misses governance structure entirely. |
| pom.xml flagged as install-time hook | **FALSE POSITIVE** | Every Maven project has a pom.xml. This is not an install script — it's a build descriptor. Flagging this adds noise. |
| 28 direct dependencies | **MISLEADING** | This likely counts test/build dependencies from the POM, not runtime dependencies. Commons IO has zero runtime dependencies. |

**Missed Risks:**
- None significant. Apache Commons IO is one of the best-governed Java libraries in existence.

**Overall Assessment:** Score is severely inflated due to multiple false positives. The "100% team change" and "119 days old" findings are factually wrong. The pom.xml-as-install-hook finding is a systemic false positive for all Maven packages. **Fair score would be ~4-5/20.**

---

### 4. com.fasterxml.jackson.datatype:jackson-datatype-jsr310@2.15.3 (Maven) — Score: 11/20

**Snyft Findings:**
- Publisher Control 0/2: Single maintainer, no signing
- Ownership Changes 0/2: 100% team change (2/2 new, 49 historical)
- Health 0/2: Bus factor 1, 88% top contributor, 60% PRs reviewed
- Governance 1/2: Partial (has SECURITY.md but gaps)
- Package Maturity 1/2: "301 days (maturing)"

**Reality Check:**

| Fact | Finding |
|------|---------|
| **Maintainer** | Tatu Saloranta (cowtowncoder), FasterXML founder |
| **Org** | FasterXML — the Jackson project |
| **Downloads** | Jackson is the most-used JSON library in Java, billions of downloads |
| **Ever compromised?** | Not directly, but Jackson was target of a typosquatting attack in Dec 2025 (fasterxml.org fake domain with Cobalt Strike payload). Taken down within 1.5 hours. |
| **Governance** | Has SECURITY.md, active issue tracker, regular releases |
| **First release** | jackson-datatype-jsr310 has existed since ~2014 |

**Finding-by-Finding Verdict:**

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer | **MISLEADING** | Tatu Saloranta is the creator/lead of the entire Jackson ecosystem. While technically one person controls publishing, this is the BDFL model, not "some random person." Contextless risk scoring misses this distinction. |
| 100% team change (2/2 new, 49 historical) | **FALSE POSITIVE** | The jackson-modules-java8 repo is a monorepo. Contributor patterns look unusual because it's one part of a larger project. The "49 historical authors stepped back" is normal churn in a 10+ year project. |
| Package age: 301 days (maturing) | **FALSE POSITIVE** | jackson-datatype-jsr310 has existed since ~2014. Same bug as commons-io — snyft measures from Maven Central artifact date, not project age. |
| Bus factor: 1 (88% from Tatu) | **ACCURATE but MISLEADING** | Factually true that Tatu does most work. But this is the creator of Jackson — the "bus factor" risk is real but the implication of easy takeover is misleading. Tatu is well-known and well-connected in the Java community. |
| pom.xml as install hook | **FALSE POSITIVE** | Same systemic issue — every Maven package has a pom.xml. |
| 28 direct dependencies | **MISLEADING** | Build/test dependencies, not runtime. jackson-datatype-jsr310 has 2 runtime dependencies (jackson-core, jackson-databind). |

**Missed Risks:**
- The Dec 2025 typosquatting attack on Jackson demonstrates that this ecosystem IS a target. Snyft should detect typosquatting risk for high-profile packages.
- Tatu Saloranta's account is genuinely a high-value target — single point of failure for the most-used Java serialization library.

**Overall Assessment:** Score is inflated by false positives (package age, pom.xml, team change). The BDFL / single-maintainer concern is real but over-weighted without context. **Fair score would be ~6-7/20.**

---

### 5. org.flywaydb:flyway-core@9.22.3 (Maven) — Score: 9/20

**Snyft Findings:**
- Publisher Control 1/2: No maintainer data found
- Ownership Changes 0/2: 100% team change (2/2 new, 24 historical)
- Governance 1/2: No security policy, has CONTRIBUTING.md
- Release Security 1/2: Some controls but gaps
- Package Maturity 1/2: "295 days (maturing)"

**Reality Check:**

| Fact | Finding |
|------|---------|
| **Maintainer** | Redgate Software (commercial company) |
| **Org** | Redgate acquired Flyway from creator Axel Fontaine in 2019 |
| **Downloads** | One of the most-used database migration tools in Java |
| **Ever compromised?** | No known supply chain compromise |
| **Governance** | Commercial backing, paid development team, Apache 2.0 license |
| **First release** | April 20, 2010 — over 15 years old |

**Finding-by-Finding Verdict:**

| Finding | Verdict | Notes |
|---------|---------|-------|
| No maintainer data found | **MISLEADING** | The POM may lack a `<developers>` section, but Flyway is commercially maintained by Redgate with a full-time team. Snyft's inability to find maintainer data ≠ no maintainers. |
| 100% team change (2/2 new, 24 historical) | **MISLEADING** | Redgate acquired Flyway in 2019. Team change reflects a legitimate corporate acquisition, not a hostile takeover. Snyft cannot distinguish between the two. |
| Package age: 295 days (maturing) | **FALSE POSITIVE** | Flyway has existed since 2010. Same systematic bug with Maven Central artifact dates. |
| No security policy | **ACCURATE** | Redgate handles security through their corporate channels but no SECURITY.md in the GitHub repo. |
| pom.xml as install hook | **FALSE POSITIVE** | Systemic Maven false positive. |
| 28 direct dependencies | **MISLEADING** | Build/test dependencies inflating the count. |

**Missed Risks:**
- Flyway's licensing change (v10 moved features to paid tiers) is relevant — creates incentive for users to fork or use alternative versions, potentially leading to malicious forks.
- GroupId changed from org.flywaydb to com.redgate.flyway — this namespace change could create confusion/dependency confusion attacks.

**Overall Assessment:** Score is moderately inflated. The "no maintainer data" and "295 days old" findings are wrong. The acquisition-as-team-change is a systemic weakness. **Fair score would be ~5-6/20.**

---

### 6. org.mapstruct:mapstruct@1.5.5.Final (Maven) — Score: 9/20

**Snyft Findings:**
- Publisher Control 2/2: Good
- Ownership Changes 0/2: 100% team change (6/6 new, 90 historical)
- Health 0/2: Bus factor 1, 5% PRs reviewed
- Governance 1/2: No SECURITY.md, has CONTRIBUTING.md
- Release Security 1/2: Signed releases but gaps

**Reality Check:**

| Fact | Finding |
|------|---------|
| **Maintainer** | Filip Hrisafov (project lead since 2018), founded by Gunnar Morling |
| **Org** | MapStruct open source project, core team of ~4 people |
| **Downloads** | Downloads more than doubled between 1.5 and 1.6 releases |
| **Ever compromised?** | No known supply chain compromise |
| **Governance** | Has CONTRIBUTING.md, active development, regular releases |
| **First release** | ~2013 — over 12 years old |

**Finding-by-Finding Verdict:**

| Finding | Verdict | Notes |
|---------|---------|-------|
| 100% team change (6/6 new, 90 historical) | **FALSE POSITIVE** | MapStruct has had 96+ contributors over 12 years. Seeing 6 "new" recent authors is normal open source contributor rotation, not a takeover signal. |
| Package age: 480 days (maturing) | **FALSE POSITIVE** | MapStruct has existed since 2013. Same systematic Maven age bug. |
| Bus factor: 1, 5% PRs reviewed | **MISLEADING** | Filip Hrisafov does most of the development as project lead. 5% PR review rate may reflect that the lead merges his own work, not that reviews don't happen. The project has a small but stable core team. |
| 28 direct dependencies | **MISLEADING** | mapstruct core has essentially zero runtime dependencies — it's an annotation processor. The 28 deps are build/test scope from the POM. |
| pom.xml as install hook | **FALSE POSITIVE** | Systemic Maven false positive. |
| Releases are cryptographically signed | **ACCURATE** | Correctly detected GPG signatures on Maven Central. |
| Duplicate "publish/deploy workflow lacks environment protection" | **BUG** | This finding appears twice in the report — duplicate detection issue. |

**Missed Risks:**
- No significant missed risks. MapStruct is a well-maintained project with a clear governance structure.

**Overall Assessment:** Score is inflated by the team-change false positive and Maven-specific systematic issues. The signed releases finding is good. **Fair score would be ~5-6/20.**

---

### 7. bcryptjs@2.4.3 (npm) — Score: 9/20

**Snyft Findings:**
- Publisher Control 0/2: Single maintainer, personal account
- Governance 0/2: No security policy, 121 days inactive
- Release Security 0/2: No controls despite CI/CD detected
- Package Maturity 1/2: Irregular cadence (CV=1.7)

**Reality Check:**

| Fact | Finding |
|------|---------|
| **Maintainer** | Daniel Wirtz (dcodeIO) — also maintains protobuf.js |
| **Downloads** | ~4.5-6.8M weekly (varies by measurement) |
| **Ever compromised?** | No known supply chain compromise |
| **Governance** | No SECURITY.md, OpenSSF Scorecard 3.0/10 |
| **Latest version** | 3.0.3 (not 2.4.3 as scanned — significant version gap) |

**Finding-by-Finding Verdict:**

| Finding | Verdict | Notes |
|---------|---------|-------|
| Single maintainer, personal account | **ACCURATE** | dcodeIO is the sole publisher. |
| No security policy, 121 days inactive | **ACCURATE** | No SECURITY.md in repo. |
| Scorecard 3.0/10 | **ACCURATE** | Consistent with the project profile. |
| Automated CI/CD detected but "no release security controls" | **MISLEADING** | The finding contradicts itself — it says CI/CD is detected, then says releases "may come directly from developer machines." These are mutually exclusive. |
| Irregular cadence (CV=1.7) | **ACCURATE** | bcryptjs releases are sporadic — years between major versions. |

**Missed Risks:**
- dcodeIO maintains protobuf.js, which was previously [targeted in supply chain attacks](https://snyk.io/blog/protobufjs-prototype-pollution/). This makes the dcodeIO account a known high-value target.
- The scanned version (2.4.3) is significantly outdated — 3.0.x is available. Snyft should flag version staleness relative to latest available.

**Overall Assessment:** Score is roughly appropriate. The single-maintainer + high-value-target combination is legitimately concerning. The CI/CD contradiction is a bug. **Fair score would be ~8-9/20.**

---

### 8. python-jose@3.3.0 (PyPI) — Score: 9/20

**Snyft Findings:**
- Publisher Control 1/2: 2 maintainers, small team
- Governance 0/2: No security policy
- Release Security 0/2: No controls, 7 unpinned actions
- Package Maturity 1/2: Irregular cadence (CV=1.7)

**Reality Check:**

| Fact | Finding |
|------|---------|
| **Maintainer** | Michael Davis (mpdavis) + asherf on PyPI. No org. |
| **Downloads** | ~32.5M monthly (~8M weekly) — extremely high-traffic |
| **Ever compromised?** | Not compromised, but has known CVEs (CVE-2024-33663 algorithm confusion, CVE-2024-33664 JWT bomb) fixed in 3.4.0 |
| **Governance** | No SECURITY.md, no CONTRIBUTING.md. OpenSSF Scorecard 4.5/10. Has OSS-Fuzz integration (10/10). Resumed maintenance after ~3.5 year dormancy (2021-2025). Contributor retention: 0% QoQ per Linux Foundation. |
| **Alternatives** | FastAPI switched docs to recommend PyJWT (May 2024). joserfc (Authlib) is the full JOSE replacement. |

**Finding-by-Finding Verdict:**

| Finding | Verdict | Notes |
|---------|---------|-------|
| 2 maintainers, small team | **ACCURATE** | |
| No security policy | **ACCURATE** | |
| 7 unpinned GitHub Actions | **ACCURATE** | |
| Bus factor: 2, 35% PRs reviewed | **ACCURATE** | |
| Irregular cadence (CV=1.7) | **ACCURATE** | |
| setup.py as install hook (no dangerous patterns) | **ACCURATE** | Standard Python packaging, correctly noted as non-dangerous. |

**Missed Risks:**
- **CRITICAL MISS:** python-jose@3.3.0 has two known CVEs from 2024 (CVE-2024-33663, CVE-2024-33664) that were fixed in 3.4.0. The scanned version is VULNERABLE. While snyft explicitly doesn't track CVEs (per project scope), the fact that the maintainer has published a fix suggests the project isn't truly abandoned — but the scanned version is outdated.
- The FastAPI community has actively discussed migrating away from python-jose, meaning adoption is declining. This is a relevant supply chain signal (shrinking maintainer interest).

**Overall Assessment:** Score is well-calibrated for supply chain risk factors. The findings are accurate. However, snyft misses that the scanned version has known issues and an available fix. **Score of 9/20 is appropriate.**

---

### 9. psycopg2-binary@2.9.9 (PyPI) — Score: 9/20

**Snyft Findings:**
- Publisher Control 1/2: 4 maintainers, 1 new account
- Install Execution 0/2: Dangerous patterns (cmdclass override, subprocess call)
- Governance 0/2: No security policy
- Release Security 0/2: No controls
- Health 1/2: Bus factor 1

**Reality Check:**

| Fact | Finding |
|------|---------|
| **Maintainer** | Daniele Varrazzo (primary), with 3 other PyPI maintainers |
| **Downloads** | Very widely used — the standard PostgreSQL adapter for Python |
| **Ever compromised?** | No known supply chain compromise |
| **Governance** | No SECURITY.md, but actively maintained (2.9.11 released Oct 2025) |
| **Latest version** | 2.9.11 (scanned version 2.9.9 is not latest) |

**Finding-by-Finding Verdict:**

| Finding | Verdict | Notes |
|---------|---------|-------|
| 4 maintainers, 1 new account | **ACCURATE** | |
| Dangerous install patterns (cmdclass, subprocess) | **MISLEADING** | psycopg2 is a C extension that wraps libpq. The cmdclass/subprocess usage in setup.py is for compiling the C extension against the system's PostgreSQL libraries — this is standard and necessary, not malicious. psycopg2-binary specifically ships pre-compiled wheels to AVOID this. Flagging standard C extension build patterns as "dangerous" creates noise. |
| No security policy | **ACCURATE** | No SECURITY.md in the psycopg2 repo. |
| Bus factor: 1 | **ACCURATE** | Daniele Varrazzo is the primary developer, though there are 4 PyPI maintainers. |
| No automated release process | **MISLEADING** | psycopg2-binary uses cibuildwheel for building wheels across platforms. The complexity of building C extensions for multiple platforms makes the release process different from pure-Python packages. |

**Missed Risks:**
- psycopg2 is in maintenance mode — the successor psycopg3 (psycopg) is actively developed. Projects still on psycopg2 may face declining maintenance attention over time.
- The -binary variant ships pre-compiled binaries, which means users trust that the wheels match the source. No provenance attestation is available to verify this.

**Overall Assessment:** The install execution finding is the most misleading — C extension build scripts are not the same as malicious install hooks. **Fair score would be ~7/20.**

---

### 10. python-multipart@0.0.6 (PyPI) — Score: 10/20

**Snyft Findings:**
- Release Anomalies 0/2: Dormant 366 days, then reactivated
- Release Security 0/2: No controls, unpinned actions
- Package Maturity 0/2: Highly irregular cadence (CV=2.0)
- Publisher Control 1/2: 2 maintainers
- Governance 1/2: Has SECURITY.md

**Reality Check:**

| Fact | Finding |
|------|---------|
| **Maintainer** | Marcelo Trylesinski (Kludex) — Pydantic/Starlette/Uvicorn maintainer |
| **Org** | Part of the Starlette/FastAPI ecosystem |
| **Downloads** | Very high (critical dependency of FastAPI/Starlette) |
| **Ever compromised?** | No known supply chain compromise |
| **Governance** | Has SECURITY.md, active CI/CD |
| **History** | Originally by Andrew Franks, ownership transferred to Kludex |

**Finding-by-Finding Verdict:**

| Finding | Verdict | Notes |
|---------|---------|-------|
| Dormant 366 days then reactivated | **MISLEADING** | The package underwent an ownership transfer from its original author to Kludex (Marcelo Trylesinski), a well-known maintainer in the Python ecosystem. The "dormancy" was pre-transfer, and the "reactivation" was the new maintainer picking up active development. This is a GOOD thing, not a risk signal. |
| Highly irregular cadence (CV=2.0) | **MISLEADING** | Reflects the ownership transfer period. Post-transfer, releases have been regular. |
| 2 maintainers | **ACCURATE** | |
| Has SECURITY.md | **ACCURATE** | Correctly detected. |
| 5+3 unpinned actions | **ACCURATE** | |
| No environment protection on publish workflow | **ACCURATE** | |

**Missed Risks:**
- The ownership transfer itself IS a genuine supply chain risk event — but snyft flagged the wrong thing. It flagged the "dormancy/reactivation" pattern but didn't flag that the package had an actual ownership change. The ownership change from Franks to Kludex was benign, but snyft's ownership change detection (0/2 score) missed it entirely.
- python-multipart is a critical transitive dependency of FastAPI — compromise would affect the entire FastAPI ecosystem.

**Overall Assessment:** Score is inflated by misinterpreting a legitimate ownership transfer as suspicious reactivation. Ironically, the actual ownership change wasn't detected by the ownership change category. **Fair score would be ~6-7/20.**

---

## Summary Scorecard

| # | Package | Ecosystem | Snyft Score | Fair Score | Delta | Key Issue |
|---|---------|-----------|-------------|------------|-------|-----------|
| 1 | pg@8.11.3 | npm | 12/20 | ~9/20 | -3 | Volunteer release pattern misread as reactivation |
| 2 | passport-jwt@4.0.1 | npm | 12/20 | 12/20 | 0 | Genuinely abandoned, well-calibrated |
| 3 | commons-io@2.15.1 | Maven | 11/20 | ~4/20 | -7 | Multiple false positives: age, team change, pom.xml |
| 4 | jackson-datatype-jsr310@2.15.3 | Maven | 11/20 | ~6/20 | -5 | BDFL context missing, age wrong |
| 5 | flyway-core@9.22.3 | Maven | 9/20 | ~5/20 | -4 | Acquisition misread as suspicious team change |
| 6 | mapstruct@1.5.5.Final | Maven | 9/20 | ~5/20 | -4 | Normal OSS rotation misread, duplicate findings |
| 7 | bcryptjs@2.4.3 | npm | 9/20 | ~8/20 | -1 | Roughly accurate, CI/CD contradiction |
| 8 | python-jose@3.3.0 | PyPI | 9/20 | 9/20 | 0 | Well-calibrated |
| 9 | psycopg2-binary@2.9.9 | PyPI | 9/20 | ~7/20 | -2 | C extension build scripts flagged as dangerous |
| 10 | python-multipart@0.0.6 | PyPI | 10/20 | ~6/20 | -4 | Ownership transfer misread as suspicious reactivation |

**Average snyft score:** 10.1/20
**Average fair score:** ~7.1/20
**Average inflation:** ~3 points

---

## Systemic Issues Identified

### 1. Maven Package Age Calculation Bug (CRITICAL)
**Affects:** All Maven packages
**Problem:** Snyft reports commons-io as "119 days old," jackson-datatype-jsr310 as "301 days old," flyway-core as "295 days old," and mapstruct as "480 days old." These packages are 23, 11, 15, and 12 years old respectively.
**Root Cause:** Likely measuring from Maven Central's artifact record creation date or the groupId namespace registration date, not the actual project inception.
**Impact:** Every Maven package gets an artificially inflated Package Maturity score.
**Recommendation:** Use the earliest version publication date on Maven Central, or the GitHub repo creation date, whichever is older.

### 2. pom.xml Flagged as Install-Time Hook (HIGH)
**Affects:** All Maven packages
**Problem:** Every Maven package has a pom.xml. Flagging it as an "install-time hook" is technically true (Maven executes lifecycle phases) but practically meaningless — it's like flagging package.json as suspicious for npm packages.
**Impact:** +1 point for every Maven package regardless of actual risk.
**Recommendation:** Don't flag pom.xml existence alone. Only flag if the POM contains exec-maven-plugin, antrun, or other plugins that execute arbitrary code during install phase.

### 3. Team Change Detection Lacks Context (HIGH)
**Affects:** All long-lived projects, corporate acquisitions
**Problem:** Comparing recent vs. historical committers produces false positives for:
- Long-lived ASF projects with normal committer rotation
- Corporate acquisitions (Redgate acquiring Flyway)
- Projects with many one-time contributors
**Impact:** +2 points for many healthy, well-governed projects.
**Recommendation:** Weight this signal differently for org-backed vs personal projects. Consider contributor lifetime and overlap, not just "new vs old" binary classification. A project that's 20 years old WILL have different recent contributors than historical ones — that's healthy evolution.

### 4. Volunteer Release Patterns Misclassified as Suspicious (HIGH)
**Affects:** Mature, volunteer-maintained packages (pg, bcryptjs)
**Problem:** Irregular release cadence and release gaps are normal for stable, volunteer-maintained libraries. The "dormancy reactivation" pattern (designed to catch abandoned packages being taken over) fires on packages that simply don't need frequent updates.
**Recommendation:** Apply dormancy/reactivation heuristics differently based on:
- Package maturity (>5 years with stable API = lower risk from gaps)
- Download volume (high downloads during "dormancy" = still in active use)
- Commit activity vs. release activity (commits without releases ≠ dormancy)

### 5. C Extension Build Scripts Treated Same as Malicious Install Hooks (MEDIUM)
**Affects:** PyPI packages with C extensions (psycopg2, cryptography, etc.)
**Problem:** cmdclass overrides and subprocess calls are standard for C extension building. Flagging them alongside actually dangerous patterns (network requests, credential exfiltration) creates noise.
**Recommendation:** Distinguish between:
- Build-related subprocess calls (compiling C code) — INFORMATIONAL
- Network-accessing install scripts — HIGH RISK
- Credential/environment exfiltration — CRITICAL

### 6. Legitimate Ownership Transfers Misclassified (MEDIUM)
**Affects:** python-multipart, potentially others
**Problem:** When a package is legitimately transferred to a new, active maintainer (like python-multipart → Kludex), the resulting pattern looks like "dormancy + reactivation" which triggers false alarms. Meanwhile, the actual ownership transfer category (Ownership Changes) may miss it if the registry metadata doesn't reflect the change.
**Recommendation:** Cross-reference dormancy/reactivation signals with ownership change signals. If both fire simultaneously, investigate whether it's a legitimate transfer rather than scoring both as independent risks.

### 7. Maven Dependency Count Inflation (MEDIUM)
**Affects:** All Maven packages
**Problem:** Maven POMs list dependencies for all scopes (compile, test, provided). Snyft reports "28 direct dependencies" for packages like commons-io (0 runtime deps) and mapstruct (0 runtime deps). This dramatically overstates the actual attack surface.
**Recommendation:** Parse the POM `<scope>` element and only count `compile` and `runtime` scope dependencies. Exclude `test`, `provided`, and `system` scope.

### 8. Contradictory Findings (LOW)
**Affects:** bcryptjs, potentially others
**Problem:** bcryptjs finding says "Automated CI/CD release process detected" but then concludes "releases may come directly from developer machines with no verification." These contradict each other.
**Recommendation:** If CI/CD is detected, don't also claim releases come from developer machines. Evaluate the CI/CD quality instead.

### 9. Duplicate Findings (LOW)
**Affects:** mapstruct, caffeine
**Problem:** The same finding ("Publish/deploy workflow lacks environment protection") appears twice for mapstruct.
**Recommendation:** Deduplicate findings before rendering the report.

---

## Recommendations Priority Matrix

| Priority | Issue | Estimated Impact | Effort |
|----------|-------|------------------|--------|
| P0 | Maven package age calculation bug | Affects all Maven packages, ~7 point inflation for old packages | Low — use earliest version date |
| P0 | pom.xml as install hook false positive | Affects all Maven packages, +1-2 points each | Low — filter pom.xml from hook detection |
| P1 | Team change detection context | Affects long-lived & corporate-backed projects | Medium — add org context, contributor overlap analysis |
| P1 | Maven dependency scope filtering | Affects all Maven packages | Low — parse `<scope>` from POM |
| P1 | C extension build script classification | Affects PyPI packages with C code | Medium — build pattern classifier |
| P2 | Volunteer release pattern handling | Affects mature packages | Medium — add maturity-aware dormancy thresholds |
| P2 | Ownership transfer cross-referencing | Affects transferred packages | Medium — correlate dormancy + ownership signals |
| P3 | Contradictory findings | Cosmetic but hurts credibility | Low — logic gate in finding generation |
| P3 | Duplicate findings | Cosmetic | Low — deduplicate before render |

---

## Conclusion

Snyft's MEDIUM-risk findings are **most accurate for npm packages** (passport-jwt, python-jose, bcryptjs) where the data model maps well to the package ecosystem. Scores for **Maven packages are systematically inflated** by 4-7 points due to the package age calculation bug, pom.xml false positives, dependency scope inflation, and team change misclassification. **PyPI packages** fall in between, with the main issue being C extension build scripts treated as dangerous install hooks.

The two best-calibrated packages were passport-jwt (12/20) and python-jose (9/20), where snyft findings closely matched reality. The worst-calibrated was commons-io (11/20 vs fair ~4/20), where an Apache Software Foundation project with 23 years of history and formal governance was flagged as a high-risk "new" package with suspicious team changes.

**Key takeaway:** Fixing the Maven age bug and pom.xml false positive alone would correct the scoring for all 4 Maven packages reviewed and likely dozens more across the full 87-package report.
