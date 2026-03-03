package analyzer

import (
	"fmt"

	"github.com/metalstormbass/snyft/pkg/models"
)

// scoreDependencySprawl: transitive dependencies (0-2 pts)
//
// Three scoring paths, in priority order:
//  1. Lock file (Verified=true): score by total transitive count in project lock file
//     Thresholds: <10 = low, 10-50 = moderate, >50 = high
//  2. Registry direct dep count (Verified=false, DirectCount known): score by direct dep count
//     from the published package metadata (npm `dependencies`, PyPI `requires_dist`).
//     Thresholds: 0-5 = low, 6-15 = moderate, >15 = high
//     Source: "Small World with High Risks" (Zimmermann et al., 2019) — each direct dep
//     carries its own transitive tree, expanding the attack surface multiplicatively.
//  3. No data: neutral 1-point score (unknown risk)
func (a *Analyzer) scoreDependencySprawl(result *models.AnalysisResult) models.CategoryScore {
	// Path 1: lock file provides exact transitive count
	if result.Metadata.DependencyMetrics != nil && result.Metadata.DependencyMetrics.Verified {
		metrics := result.Metadata.DependencyMetrics
		transitiveCount := metrics.TransitiveCount
		methodology := "Parsed project lock file to count exact transitive dependency tree. Thresholds: <10 low risk, 10-50 moderate, >50 high risk."
		checks := []models.CheckResult{
			{Name: "Lock file analysis", Status: "PASS", Detail: fmt.Sprintf("Lock file found with %d total dependencies (%d direct, max depth %d)", transitiveCount, metrics.DirectCount, metrics.MaxDepth)},
		}

		// Score based on total transitive dependency count from project lock file
		if transitiveCount < 10 {
			checks = append(checks, models.CheckResult{Name: "Dependency count threshold", Status: "PASS", Detail: fmt.Sprintf("%d transitive deps < 10 threshold", transitiveCount)})
			return models.CategoryScore{
				Score: 2, RiskPoints: 0,
				Description: fmt.Sprintf("%d total transitive dependencies found in lock file (%d direct). A small dependency tree limits the supply chain attack surface.", transitiveCount, metrics.DirectCount),
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified: true, DataAvailable: true, Methodology: methodology, ChecksPerformed: checks,
			}
		} else if transitiveCount <= 50 {
			checks = append(checks, models.CheckResult{Name: "Dependency count threshold", Status: "FAIL", Detail: fmt.Sprintf("%d transitive deps in 10-50 range (moderate)", transitiveCount)})
			return models.CategoryScore{
				Score: 1, RiskPoints: 1,
				Description: fmt.Sprintf("%d total transitive dependencies in lock file (%d direct). Each dependency is an additional supply chain entry point — a compromise in any one can propagate to your project.", transitiveCount, metrics.DirectCount),
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified: true, DataAvailable: true, Methodology: methodology, ChecksPerformed: checks,
			}
		} else {
			checks = append(checks, models.CheckResult{Name: "Dependency count threshold", Status: "FAIL", Detail: fmt.Sprintf("%d transitive deps > 50 threshold (high sprawl)", transitiveCount)})
			return models.CategoryScore{
				Score: 0, RiskPoints: 2,
				Description: fmt.Sprintf("%d total transitive dependencies in lock file (%d direct, max depth %d). Large dependency trees exponentially increase the supply chain attack surface — a compromise in any transitive dependency can propagate to your project.", transitiveCount, metrics.DirectCount, metrics.MaxDepth),
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified: true, DataAvailable: true, Methodology: methodology, ChecksPerformed: checks,
			}
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
		// Maven uses higher thresholds because BOM imports, dependency management
		// sections, and multi-module aggregation inflate apparent counts without
		// representing actual attack surface.
		lowThreshold := 5  // inclusive upper bound for low risk
		modThreshold := 15 // inclusive upper bound for moderate risk
		thresholdNote := "0-5 low, 6-15 moderate, 16+ high risk"
		if result.Dependency.Ecosystem == models.EcosystemMaven {
			lowThreshold = 12
			modThreshold = 29
			thresholdNote = "0-12 low, 13-29 moderate, 30+ high risk (Maven-adjusted: BOM/management imports inflate counts)"
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

		if directCount <= lowThreshold {
			checks = append(checks, models.CheckResult{Name: "Direct dependency threshold", Status: "PASS", Detail: fmt.Sprintf("%d direct deps <= %d threshold", directCount, lowThreshold)})
			return models.CategoryScore{
				Score: 2, RiskPoints: 0,
				Description: fmt.Sprintf("%d direct dependencies found in registry metadata (no lock file available). A small dependency count limits the supply chain attack surface.%s", directCount, descSuffix),
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)%s", directCount, evidenceSuffix),
				Verified: false, DataAvailable: true, Methodology: methodology, ChecksPerformed: checks,
			}
		} else if directCount <= modThreshold {
			checks = append(checks, models.CheckResult{Name: "Direct dependency threshold", Status: "FAIL", Detail: fmt.Sprintf("%d direct deps in %d-%d range (moderate)", directCount, lowThreshold+1, modThreshold)})
			return models.CategoryScore{
				Score: 1, RiskPoints: 1,
				Description: fmt.Sprintf("%d direct dependencies found in registry metadata. Each direct dependency carries its own transitive tree, expanding the attack surface multiplicatively.%s", directCount, descSuffix),
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)%s", directCount, evidenceSuffix),
				Verified: false, DataAvailable: true, Methodology: methodology, ChecksPerformed: checks,
			}
		} else {
			checks = append(checks, models.CheckResult{Name: "Direct dependency threshold", Status: "FAIL", Detail: fmt.Sprintf("%d direct deps > %d threshold (high sprawl)", directCount, modThreshold)})
			return models.CategoryScore{
				Score: 0, RiskPoints: 2,
				Description: fmt.Sprintf("%d direct dependencies found in registry metadata (>%d threshold). A large number of direct dependencies significantly increases the supply chain attack surface.%s", directCount, modThreshold, descSuffix),
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)%s", directCount, evidenceSuffix),
				Verified: false, DataAvailable: true, Methodology: methodology, ChecksPerformed: checks,
			}
		}
	}

	// Path 3: no dependency data available
	return models.CategoryScore{
		Score: 1, RiskPoints: 1,
		Description: "No lock file or registry dependency data available. Unable to assess dependency sprawl risk — the transitive dependency tree size is unknown.",
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
