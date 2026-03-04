package analyzer

import (
	"fmt"

	"github.com/metalstormbass/snyft/pkg/models"
)

// scoreDependencySprawl: dependency count (0-1 pts)
//
// Dependency count is a weak supply chain signal — having many dependencies
// increases attack surface but doesn't strongly correlate with compromise
// likelihood on its own. This category is capped at 1 risk point and only
// triggers for extreme sprawl.
//
// Three scoring paths, in priority order:
//  1. Lock file (Verified=true): score by total transitive count in project lock file
//     Threshold: >200 transitive deps = 1 risk point
//  2. Registry direct dep count (Verified=false, DirectCount known): score by direct dep count
//     from the published package metadata (npm `dependencies`, PyPI `requires_dist`).
//     Thresholds: 50+ for npm/PyPI, 100+ for Maven = 1 risk point
//     Source: "Small World with High Risks" (Zimmermann et al., 2019) — each direct dep
//     carries its own transitive tree, expanding the attack surface multiplicatively.
//  3. No data: 0 risk points (weak signal, don't penalize missing data)
func (a *Analyzer) scoreDependencySprawl(result *models.AnalysisResult) models.CategoryScore {
	// Path 1: lock file provides exact transitive count
	if result.Metadata.DependencyMetrics != nil && result.Metadata.DependencyMetrics.Verified {
		metrics := result.Metadata.DependencyMetrics
		transitiveCount := metrics.TransitiveCount
		methodology := "Parsed project lock file to count exact transitive dependency tree. Threshold: >200 transitive deps = 1 risk point (extreme sprawl only)."
		checks := []models.CheckResult{
			{Name: "Lock file analysis", Status: "PASS", Detail: fmt.Sprintf("Lock file found with %d total dependencies (%d direct, max depth %d)", transitiveCount, metrics.DirectCount, metrics.MaxDepth)},
		}

		if transitiveCount <= 200 {
			checks = append(checks, models.CheckResult{Name: "Dependency count threshold", Status: "PASS", Detail: fmt.Sprintf("%d transitive deps <= 200 threshold", transitiveCount)})
			return models.CategoryScore{
				Score: 1, RiskPoints: 0,
				Description: fmt.Sprintf("%d total transitive dependencies found in lock file (%d direct). Dependency count within normal range.", transitiveCount, metrics.DirectCount),
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified: true, DataAvailable: true, Methodology: methodology, ChecksPerformed: checks,
			}
		}
		checks = append(checks, models.CheckResult{Name: "Dependency count threshold", Status: "FAIL", Detail: fmt.Sprintf("%d transitive deps > 200 threshold (extreme sprawl)", transitiveCount)})
		return models.CategoryScore{
			Score: 0, RiskPoints: 1,
			Description: fmt.Sprintf("%d total transitive dependencies in lock file (%d direct, max depth %d). Extreme dependency sprawl increases the supply chain attack surface.", transitiveCount, metrics.DirectCount, metrics.MaxDepth),
			Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
			Verified: true, DataAvailable: true, Methodology: methodology, ChecksPerformed: checks,
		}
	}

	// Path 2: use direct dep count from registry (npm dependencies / PyPI requires_dist / Maven pom).
	//
	// Maven projects have fundamentally different dependency models: BOM imports,
	// dependency management sections, and multi-module aggregation inflate apparent
	// counts without representing actual attack surface. We apply higher thresholds
	// for Maven to avoid penalizing its idiomatic patterns.
	//
	// For Maven, only compile and runtime scoped dependencies count toward the
	// sprawl score — test, provided, and system scoped deps don't flow to consumers.
	//
	// Source: "Small World with High Risks" (Zimmermann et al., 2019) — each direct dep
	//         carries its own transitive tree, expanding the attack surface multiplicatively.
	//         Maven-specific adjustment accounts for managed/inherited dependencies that
	//         don't represent independent supply chain entry points.
	if result.Metadata.DependencyMetrics != nil && !result.Metadata.DependencyMetrics.Verified {
		directCount := result.Metadata.DependencyMetrics.DirectCount

		// Ecosystem-specific thresholds for direct dependency count.
		// Only extreme sprawl triggers 1 risk point. Maven uses higher thresholds
		// because BOM imports, dependency management sections, and multi-module
		// aggregation inflate apparent counts.
		highThreshold := 49 // inclusive upper bound for 0 risk (50+ = 1 risk point)
		thresholdNote := "0-49 normal, 50+ extreme sprawl"
		if result.Dependency.Ecosystem == models.EcosystemMaven {
			highThreshold = 99
			thresholdNote = "0-99 normal, 100+ extreme sprawl (Maven-adjusted: BOM/management imports inflate counts)"
		}

		// Build scope detail string for Maven packages
		scopeDetail := ""
		if sb := result.Metadata.DependencyMetrics.MavenScopeBreakdown; sb != nil {
			scopeDetail = mavenScopeDetail(sb)
		}

		methodology := fmt.Sprintf("No lock file available. Used direct dependency count from package registry metadata as proxy for transitive exposure. Thresholds: %s.", thresholdNote)
		if scopeDetail != "" {
			methodology += fmt.Sprintf(" Maven scope breakdown: %s. Only compile and runtime scoped dependencies are counted — test, provided, and system scoped deps don't flow to consumers.", scopeDetail)
		}
		checks := []models.CheckResult{
			{Name: "Lock file analysis", Status: "UNAVAILABLE", Detail: "No lock file found in project"},
			{Name: "Registry dependency count", Status: "PASS", Detail: fmt.Sprintf("%d direct dependencies found in registry metadata", directCount)},
		}
		if scopeDetail != "" {
			checks = append(checks, models.CheckResult{Name: "Maven scope analysis", Status: "PASS", Detail: fmt.Sprintf("Scope breakdown: %s", scopeDetail)})
		}

		descSuffix := ""
		evidenceSuffix := ""
		if scopeDetail != "" {
			descSuffix = fmt.Sprintf(" Scope breakdown: %s.", scopeDetail)
			evidenceSuffix = fmt.Sprintf("; scope: %s", scopeDetail)
		}

		if directCount <= highThreshold {
			checks = append(checks, models.CheckResult{Name: "Direct dependency threshold", Status: "PASS", Detail: fmt.Sprintf("%d direct deps <= %d threshold", directCount, highThreshold)})
			return models.CategoryScore{
				Score: 1, RiskPoints: 0,
				Description: fmt.Sprintf("%d direct dependencies found in registry metadata (no lock file available). Dependency count within normal range.%s", directCount, descSuffix),
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)%s", directCount, evidenceSuffix),
				Verified: false, DataAvailable: true, Methodology: methodology, ChecksPerformed: checks,
			}
		}
		checks = append(checks, models.CheckResult{Name: "Direct dependency threshold", Status: "FAIL", Detail: fmt.Sprintf("%d direct deps > %d threshold (extreme sprawl)", directCount, highThreshold)})
		return models.CategoryScore{
			Score: 0, RiskPoints: 1,
			Description: fmt.Sprintf("%d direct dependencies found in registry metadata (>%d threshold). Extreme dependency sprawl increases the supply chain attack surface.%s", directCount, highThreshold, descSuffix),
			Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)%s", directCount, evidenceSuffix),
			Verified: false, DataAvailable: true, Methodology: methodology, ChecksPerformed: checks,
		}
	}

	// Path 3: no dependency data available
	// Dependency count is a weak signal, so we don't penalize missing data.
	return models.CategoryScore{
		Score: 1, RiskPoints: 0,
		Description: "No lock file or registry dependency data available. Dependency count is a weak supply chain signal — not penalizing missing data.",
		Evidence:    "No lock file or registry dependency data found",
		Verified:    false,
		DataAvailable: false,
		Methodology: "Attempted to parse project lock file and query registry metadata for dependency count. Neither data source was available.",
		ChecksPerformed: []models.CheckResult{
			{Name: "Lock file analysis", Status: "UNAVAILABLE", Detail: "No lock file found in project"},
			{Name: "Registry dependency count", Status: "UNAVAILABLE", Detail: "No dependency data in registry metadata"},
		},
	}
}

// mavenScopeDetail formats a human-readable scope breakdown string
// from Maven scope counts, e.g. "8 compile, 3 runtime, 17 test".
// Only includes scopes with non-zero counts.
func mavenScopeDetail(sb *models.MavenScopeBreakdown) string {
	var parts []string
	if sb.Compile > 0 {
		parts = append(parts, fmt.Sprintf("%d compile", sb.Compile))
	}
	if sb.Runtime > 0 {
		parts = append(parts, fmt.Sprintf("%d runtime", sb.Runtime))
	}
	if sb.Test > 0 {
		parts = append(parts, fmt.Sprintf("%d test", sb.Test))
	}
	if sb.Provided > 0 {
		parts = append(parts, fmt.Sprintf("%d provided", sb.Provided))
	}
	if sb.System > 0 {
		parts = append(parts, fmt.Sprintf("%d system", sb.System))
	}
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += ", " + parts[i]
	}
	return result
}
