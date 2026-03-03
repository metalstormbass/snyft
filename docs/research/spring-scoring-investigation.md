# Investigation: Why Spring Framework Scores Unnecessarily High Risk

**Date:** 2026-03-03
**Status:** Research complete — no code changes made
**Assignee:** cool-rabbit

## Summary

Well-known Java repos like Spring Framework are rated as unnecessarily high risk due to 4-6 inflated risk points across multiple scoring categories. This investigation identifies the root causes with specific file:line references and recommends targeted fixes.

**Estimated inflation:** 4-6 points, potentially pushing Spring from LOW (0-8) to MEDIUM (9-12) risk.

## Findings

### 1. Install Execution — +2 inflated points (HIGH IMPACT)

**Root cause:** Naive string matching flags legitimate Maven plugins as dangerous.

- `pkg/analyzer/script_analyzer.go:331-372` — Hardcoded list of "dangerous" plugins includes `maven-antrun-plugin`, `exec-maven-plugin`, `maven-exec-plugin`
- `pkg/analyzer/script_analyzer.go:365` — Detection is `strings.Contains(pomContent, plugin.pattern)` with zero context awareness
- `pkg/analyzer/analyzer.go:269-281` — Fetches root `pom.xml` and runs analysis on it
- `pkg/analyzer/install_execution.go:66-91` — Any dangerous pattern → automatic 2 risk points

Spring Framework uses `maven-antrun-plugin` legitimately for build tasks. The trust-weighting fix (PR #234, commit `893255a0`) that would have downgraded this to 1 point for popular repos was reverted in PR #244 (commit `1f5bc15`).

**Recommended fix options:**
- (a) Restore trust-weighting with refined criteria
- (b) Analyze what the plugin actually executes (check `<executable>`, `<tasks>` children)
- (c) Only flag plugins when bound to `install` or `deploy` lifecycle phases
- (d) Differentiate HIGH severity plugins in parent/aggregator POMs vs leaf module POMs

### 2. Publisher Control — 0.6 inflated risk score (MEDIUM IMPACT)

**Root cause:** Maven claims to have maintainer data but scraping fallback doesn't extract it.

- `pkg/models/models.go:372-377` — Maven declared `HasMaintainerList: true` based on POM `<developers>` section
- `pkg/analyzer/publisher_control.go:544-556` — When `MaintainerCount == 0` AND ecosystem "has" maintainer list: +0.6 risk
- `pkg/analyzer/publisher_control.go:544-556` — Compare: when ecosystem lacks the list: only +0.3 risk
- `pkg/fetcher/maven.go:915-973` — Scraping fallback does NOT extract developer data (only version, license, repo URL, usage stats)
- `pkg/fetcher/maven.go:288-294` — POM enrichment correctly parses `<developers>` but only runs when API/direct access works

Spring gets double the penalty (0.6 vs 0.3) because Maven says it has maintainer data but the scraping fallback drops it.

**Recommended fix options:**
- (a) Set `HasMaintainerList: false` for Maven (simplest, acknowledges partial support)
- (b) Add a "partial" capability level that scores 0.3 instead of 0.6
- (c) Extract `<developers>` from POM during scraping fallback
- (d) Do a secondary POM fetch when scraping is the primary source

### 3. Dependency Sprawl — +1-2 inflated points (MEDIUM IMPACT)

**Root cause:** npm-derived thresholds applied to Maven's fundamentally different dependency model.

- `pkg/analyzer/dependency_sprawl.go:59-92` — Registry fallback thresholds: 0-5 (0pts), 6-15 (1pt), 16+ (2pts)
- `pkg/parser/java.go:377-407` — `CountMavenDependencies()` counts non-test `<dependencies>` from pom.xml
- Maven has no lock file, so the "verified transitive" path (better thresholds: <10, 10-50, >50) is never used
- Spring Framework parent POMs aggregate many modules/dependencies, easily exceeding 16 direct deps
- Maven uses BOM imports and dependency management sections that inflate apparent "direct" count

**Recommended fix options:**
- (a) Use Maven-specific thresholds (e.g., 0-15, 16-40, 40+) for direct deps
- (b) Exclude `<dependencyManagement>` entries from count (they're declarations, not actual deps)
- (c) Exclude BOM imports (`<type>pom</type><scope>import</scope>`)
- (d) Weight verified=false counts differently in the scoring function

### 4. Provenance — +0-2 inflated points (CONDITIONAL)

**Root cause:** Missing data defaults to worst case; Maven GPG alone insufficient for best score.

- `pkg/analyzer/provenance_scoring.go:90` — Maven GPG signature earns only +1 provenance point
- `pkg/analyzer/provenance_scoring.go:162-166` — Best case (0 risk pts) requires ≥2 provenance points
- `pkg/analyzer/provenance_scoring.go:168-177` — Source available + <2 provenance points = 1 risk point
- `pkg/analyzer/provenance_scoring.go:191-194` — nil SourceVerification + 0 provenance = 2 risk points (worst case)

Spring publishes GPG-signed artifacts AND has signed GitHub releases, which should reach ≥2 points. But if either detection fails, it drops to 1 point. If source verification is nil (not attempted, not failed), it gets 2 points.

**Recommended fix options:**
- (a) Give Maven GPG +2 provenance points (it's the ecosystem standard, equivalent to npm provenance)
- (b) Distinguish "not checked" (nil) from "checked and missing" — nil should score 1, not 2
- (c) Always attempt source verification for Maven packages even when other data collection fails

### 5. Scraping Fallback Data Loss — Cascading effect (MEDIUM IMPACT)

**Root cause:** Maven scraping extracts insufficient data, causing downstream penalties.

- `pkg/fetcher/maven.go:915-973` — `scrapeMavenPackageInfo` only extracts: version, license, repo URL, usage stats
- Missing from scraping: developers/maintainers, dependency count, GPG signature status
- This causes cascading failures in Publisher Control (Finding 2) and potentially Provenance (Finding 4)

**Recommended fix:** Enhance Maven scraping to extract `<developers>` from POM, or perform a secondary POM fetch when scraping is the primary data source.

### 6. Systemic: Missing Data Defaults to High Risk

**Pattern across categories:**

| Category | Condition | Penalty | File:Line |
|----------|-----------|---------|-----------|
| Provenance | nil SourceVerification + 0 attestations | 2 risk points | `provenance_scoring.go:191-194` |
| Publisher Control | 0 maintainers + "has capability" | +0.6 risk score | `publisher_control.go:554` |
| Governance | No repository URL | 1 risk point | `governance.go` |

**Recommended fix:** Adopt a consistent "unknown" penalty (e.g., 1 point) across all categories when data is unavailable vs confirmed bad. Never assign maximum penalty for absence of data.

## Cumulative Impact Estimate

| Category | Expected Score | Inflated Score | Delta |
|----------|---------------|----------------|-------|
| Install Execution | 0 | 2 | +2 |
| Dependency Sprawl | 0-1 | 1-2 | +1 |
| Publisher Control | 0 | 0-1 | +0-1 |
| Provenance | 0 | 0-1 | +0-1 |
| Other 6 categories | ~2-4 | ~2-4 | 0 |
| **Total** | **~3-5** | **~7-11** | **+4-6** |

## Priority Order for Fixes

1. **Install Execution** (highest impact, clearest fix) — context-aware plugin analysis
2. **Publisher Control** (cascading from scraping) — fix Maven capability declaration or scraping
3. **Dependency Sprawl** (ecosystem-specific) — Maven-appropriate thresholds
4. **Provenance defaults** (systemic) — nil vs failed distinction
5. **Scraping enrichment** (root cause of #2) — extract more Maven metadata
6. **Maven GPG weight** (provenance) — adjust to +2 points
