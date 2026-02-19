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
				Description: "Few transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified: true, Methodology: methodology, ChecksPerformed: checks,
			}
		} else if transitiveCount <= 50 {
			checks = append(checks, models.CheckResult{Name: "Dependency count threshold", Status: "FAIL", Detail: fmt.Sprintf("%d transitive deps in 10-50 range (moderate)", transitiveCount)})
			return models.CategoryScore{
				Score: 1, RiskPoints: 1,
				Description: "Moderate transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified: true, Methodology: methodology, ChecksPerformed: checks,
			}
		} else {
			checks = append(checks, models.CheckResult{Name: "Dependency count threshold", Status: "FAIL", Detail: fmt.Sprintf("%d transitive deps > 50 threshold (high sprawl)", transitiveCount)})
			return models.CategoryScore{
				Score: 0, RiskPoints: 2,
				Description: "Many transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified: true, Methodology: methodology, ChecksPerformed: checks,
			}
		}
	}

	// Path 2: use direct dep count from registry (npm dependencies / PyPI requires_dist).
	if result.Metadata.DependencyMetrics != nil && !result.Metadata.DependencyMetrics.Verified {
		directCount := result.Metadata.DependencyMetrics.DirectCount
		methodology := "No lock file available. Used direct dependency count from package registry metadata as proxy for transitive exposure. Thresholds: 0-5 low, 6-15 moderate, 16+ high risk."
		checks := []models.CheckResult{
			{Name: "Lock file analysis", Status: "UNAVAILABLE", Detail: "No lock file found in project"},
			{Name: "Registry dependency count", Status: "PASS", Detail: fmt.Sprintf("%d direct dependencies found in registry metadata", directCount)},
		}

		if directCount <= 5 {
			checks = append(checks, models.CheckResult{Name: "Direct dependency threshold", Status: "PASS", Detail: fmt.Sprintf("%d direct deps <= 5 threshold", directCount)})
			return models.CategoryScore{
				Score: 2, RiskPoints: 0,
				Description: "Few direct dependencies",
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)", directCount),
				Verified: false, Methodology: methodology, ChecksPerformed: checks,
			}
		} else if directCount <= 15 {
			checks = append(checks, models.CheckResult{Name: "Direct dependency threshold", Status: "FAIL", Detail: fmt.Sprintf("%d direct deps in 6-15 range (moderate)", directCount)})
			return models.CategoryScore{
				Score: 1, RiskPoints: 1,
				Description: "Moderate direct dependencies",
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)", directCount),
				Verified: false, Methodology: methodology, ChecksPerformed: checks,
			}
		} else {
			checks = append(checks, models.CheckResult{Name: "Direct dependency threshold", Status: "FAIL", Detail: fmt.Sprintf("%d direct deps > 15 threshold (high sprawl)", directCount)})
			return models.CategoryScore{
				Score: 0, RiskPoints: 2,
				Description: "Many direct dependencies",
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)", directCount),
				Verified: false, Methodology: methodology, ChecksPerformed: checks,
			}
		}
	}

	// Path 3: no dependency data available
	return models.CategoryScore{
		Score: 1, RiskPoints: 1,
		Description: "Dependency count unavailable",
		Evidence:    "No lock file or registry dependency data found",
		Verified:    false,
		Methodology: "Attempted to parse project lock file and query registry metadata for dependency count. Neither data source was available.",
		ChecksPerformed: []models.CheckResult{
			{Name: "Lock file analysis", Status: "UNAVAILABLE", Detail: "No lock file found in project"},
			{Name: "Registry dependency count", Status: "UNAVAILABLE", Detail: "No dependency data in registry metadata"},
		},
	}
}
