# Snyft Data Collection Limitations Analysis

## Overview

This document catalogs what data snyft can reliably collect, what it sometimes gets, what it never gets, and what assumptions it makes when data is missing. This is critical context for interpreting risk scores.

---

## A. Data We CAN Reliably Get

### Registry Data (All Ecosystems)
- **Package name and latest version** — always available from registry APIs
- **Version history with timestamps** — npm `time` map, PyPI `releases` map, Maven Solr API
- **Direct dependency count** — npm `dependencies`, PyPI `requires_dist`, Maven POM `<dependencies>`
- **License** — all three registries expose this
- **Repository URL** — npm `repository` field, PyPI `project_urls`, Maven POM `<scm>` (with complex cascading fallback)

### npm-Specific (Reliable)
- **Maintainers list with emails** — always in registry JSON
- **Download counts** (last-month) — dedicated API endpoint
- **Install-time scripts** — `preinstall`, `install`, `postinstall` from `package.json`
- **Provenance attestations** — `dist.attestations` in registry JSON
- **Per-maintainer package count** — search API for blast radius

### PyPI-Specific (Reliable)
- **Author/maintainer info** — `author`, `author_email`, `maintainer`, `maintainer_email`
- **Source distribution existence** — `sdist` in `urls` array
- **Prerelease detection** — PEP 440 markers (alpha/beta/rc/dev)

### Maven-Specific (Reliable)
- **Developers list** — POM `<developers>` section
- **GPG signature existence** — `.asc` file HEAD check (Maven Central requires since 2010)
- **Dependency scope breakdown** — compile/runtime/test/provided/system
- **Version count** — `maven-metadata.xml`
- **Sources JAR existence** — HEAD check on `-sources.jar`

### GitHub Repository Data (Reliable when accessible)
- **Stars, forks, watchers** — via scraping (no API needed), API, or GraphQL
- **Repository description** — all three methods
- **Last push date** — scraping `relative-time`, API, GraphQL
- **File existence** — CDN raw URL (rate-limit-free), git clone file tree, API
- **Governance files** — SECURITY.md, CONTRIBUTING.md, CODEOWNERS (file existence check)
- **CI system detection** — file pattern matching across 15+ CI platforms
- **Release history** — scraping (3 pages), API (paginated), GraphQL (30 max)

### Git Clone Data (Reliable when clone succeeds)
- **Complete file tree** — `git ls-tree -r HEAD --name-only`
- **Commit authors** (last 500) — `git log --format="%aE|%aN|%aI"` with full email/name/date
- **Recent commit activity** (1 year) — `git log --since=1year`
- **CI workflow file contents** — pre-fetched for 32 well-known files
- **Signed commit ratio** (last 100) — `git log --format="%H %G?"`

---

## B. Data We SOMETIMES Get

### Depends on Authentication Token
- **Branch protection rules** — GitHub API requires admin access (403/404 common)
- **Required PR reviewers** — same admin-access issue
- **MFA enforcement** — GitHub org API; personal accounts always "unknown"
- **Verified organization badge** — API or scraping (scraping unreliable)
- **PR review statistics** — GraphQL (token required) or per-PR API calls (expensive)
- **Issue response times** — up to 11 API calls (10 issues + comments each)

### Depends on Rate Limits
- **Commit history beyond scraping** — REST API limited to 3 pages (300 commits)
- **Full release history** — API pagination may hit rate limits mid-fetch
- **Code review rate** — requires multiple API calls per repo
- **OSSF Scorecard data** — separate API that may be unavailable

### Depends on Repository Configuration
- **CI workflow security analysis** — only if GitHub Actions workflows exist
- **Release documentation** — only if RELEASING.md/RELEASE.md exists in repo
- **Lock files for dependency analysis** — only if committed to repo
- **setup.py content** — only if repo is cloned and file exists
- **pom.xml plugins** — only if repo URL resolved and file accessible

### Ecosystem Gaps
- **PyPI download counts** — NEVER from JSON API (requires BigQuery, not implemented)
- **PyPI per-release uploader** — always empty in public API
- **PyPI provenance (PEP 740)** — field exists in struct but NOT actively validated
- **Maven maintainer list** — only POM `<developers>`, not authoritative registry data
- **Maven download counts** — not exposed by Maven Central
- **Bitbucket commit author emails** — API doesn't expose them (uses display names only)

### Platform-Specific Gaps
- **GitLab signed commits** — returns `ErrDataUnavailable` (complex per-commit queries needed)
- **GitLab signed releases** — returns `ErrDataUnavailable`
- **GitLab PR/MR review stats** — stub implementation returning empty `PRStats{}`
- **GitLab CI quality analysis** — stub returning hardcoded score of 5
- **GitLab org/group checks** — stubs returning false
- **GitLab account creation dates** — not implemented
- **Bitbucket signed commits** — `ErrDataUnavailable`
- **Bitbucket signed releases** — `ErrDataUnavailable`
- **Bitbucket PR stats** — stub returning empty
- **Bitbucket CI quality** — stub returning hardcoded score of 5
- **Bitbucket org checks** — stubs returning false
- **Bitbucket account creation dates** — not implemented
- **Generic Git** — almost everything returns `ErrDataUnavailable`; only basic file existence and CI detection work

---

## C. Data We NEVER Get

### Fundamentally Unavailable
- **Full commit history** — clone limited to depth=500, API to 300 commits
- **Historical file changes** — only HEAD snapshot; cannot track when dangerous code was added
- **Non-default branches** — clone uses `--single-branch`; cannot detect branch-specific attacks
- **Tag mutation history** — cannot detect if tags were moved or deleted
- **Commit DAG/merge structure** — `--no-merges` excludes merge commits from stats
- **Reflog/history rewrites** — not available from remote clones
- **Deleted files** — only current HEAD state visible

### Not Exposed by Platforms
- **GitHub deploy keys, webhooks** — requires admin access
- **GitHub Actions GITHUB_TOKEN scopes** — not in workflow files
- **GitHub Dependabot status** — not queried
- **GitHub security advisories** — intentionally excluded (CVE tracking out of scope)
- **GitLab MFA enforcement** — admin-only API field
- **Bitbucket workspace security settings** — not in public API
- **Actual GPG key validation** — only file existence checked, never signature verification
- **npm historical ownership transfers** — partially available but only recent 10 sampled
- **PyPI ownership history** — no API endpoint
- **Maven ownership history** — no API endpoint

### Architectural Gaps
- **Transitive dependency tree** — only direct count from registry; lock file needed for full tree
- **Cross-ecosystem package correlation** — same package in npm + PyPI not linked
- **Build reproducibility** — presence of attestation checked but not verified
- **Artifact content validation** — tarball/JAR fetched but content not deeply analyzed
- **Signature chain verification** — only boolean "signed or not" with 50% threshold

---

## D. What We Assume When Data is Missing

### Scoring Defaults (Most Categories)
| Category | Default When Data Missing | Risk Points | Rationale |
|----------|--------------------------|-------------|-----------|
| Publisher Control | Moderate risk | 1/2 | Unknown ≠ unsafe; 0.3 weight for missing maintainer count |
| Ownership Changes | Moderate risk | 1/2 | Falls back to repository age heuristic |
| Release Anomalies | Moderate risk | 1/2 | Cannot check patterns = uncertain |
| Install Execution | Low risk | 0/2 | No scripts detected = no execution risk |
| Dependency Sprawl | Moderate risk | 1/2 | Cannot assess transitive exposure |
| Provenance | Varies | 1-2/2 | Source availability is primary factor |
| Health | Moderate risk | 1/2 | Override to 1 if ALL signals unknown |
| Governance | Moderate risk | 1/2 | Cannot verify = uncertain |
| Release Security | Moderate risk | 1/2 | Cannot verify = uncertain |
| Package Maturity | Moderate risk | 1/2 | Cannot verify age/staleness |

**Total worst-case score when NO data available: ~11/20 (MEDIUM risk)**

This is intentional: the system does NOT penalize data unavailability as evidence of compromise. Unknown ≠ unsafe.

### Specific Assumptions

1. **Single maintainer = 1.0 risk weight** — automatic HIGH concern for supply chain
2. **Personal accounts are normal** (~70% of OSS) — only 0.15 weight, not penalized
3. **Personal email is normal** (~95% of OSS) — only 0.15 weight
4. **MFA not enforced is common** — downweighted to 0.3
5. **Signing adoption <10% in OSS** — weight reduced to 0.3 to avoid dominating score
6. **Maven dependency thresholds are higher** (0-12 low vs npm 0-5) — BOM imports inflate counts
7. **Bus factor threshold = 2** (lowered from 3) — prevents over-classifying healthy projects
8. **Branch protection 403/404 = "unavailable"** — NOT "doesn't exist"; benefit of doubt
9. **Archived repos = automatic 2 risk** — no exceptions, no active governance
10. **>180 days without commits = automatic 2 risk for governance** — abandoned project
11. **Repository <1 year old = skip release anomaly analysis** — insufficient history
12. **Mature projects (5+ years) with commit spikes = likely data artifacts** — API pagination creates false positives

### Platform Fallback Hierarchy
```
GitHub (richest) → GitLab (moderate) → Bitbucket (limited) → Generic Git (minimal)
```

- **GitHub**: Full scraping + API + GraphQL + clone
- **GitLab**: API + scraping + raw URLs; stubs for: signed commits, signed releases, PR reviews, CI quality, org checks
- **Bitbucket**: API + scraping; stubs for: signed commits, signed releases, PR stats, CI quality, org checks; emails never available
- **Generic Git**: Only repo reachability + file content + CI detection; everything else returns `ErrDataUnavailable`

### OSSF Scorecard as Universal Fallback
When platform-specific data is unavailable, analyzers check OSSF Scorecard scores:
- Security-Policy ≥5 → governance security policy exists
- Branch-Protection ≥7 → branch protection is enforced
- Signed-Releases ≥7 → releases are signed
- Code-Review ≥7 → code review is practiced
- Contributors ≥5 → contributor diversity exists
- Packaging ≥7 → CI-based publishing exists

**Limitation**: OSSF only available for GitHub repositories and may be stale.

---

## Key Implications for Score Interpretation

1. **npm packages get the most accurate scores** — richest data (maintainers, downloads, provenance, scripts)
2. **PyPI packages score MEDIUM on download-dependent checks** — always 0 downloads
3. **Maven packages may appear to have no maintainers** — POM developers ≠ registry maintainers
4. **GitLab/Bitbucket repos always show "unknown" for signing** — stubs return ErrDataUnavailable
5. **Generic Git hosts produce mostly "moderate risk" scores** — almost all data unavailable
6. **Shallow clone (500 commits) means dormant reactivation detection is bounded** — cannot see beyond ~500 commits
7. **Rate-limited scans degrade to scraping** — less data fidelity but scan continues
8. **Branch protection is the most commonly "unavailable" check** — requires admin access
