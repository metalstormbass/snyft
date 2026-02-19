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

		// Score based on total transitive dependency count from project lock file
		// 0 points = few dependencies (< 10) = low risk
		// 1 point = moderate dependencies (10-50) = medium risk
		// 2 points = many dependencies (50+) = high risk
		if transitiveCount < 10 {
			return models.CategoryScore{
				Score:       2,
				RiskPoints:  0,
				Description: "Few transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified:    true,
			}
		} else if transitiveCount <= 50 {
			return models.CategoryScore{
				Score:       1,
				RiskPoints:  1,
				Description: "Moderate transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified:    true,
			}
		} else {
			return models.CategoryScore{
				Score:       0,
				RiskPoints:  2,
				Description: "Many transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified:    true,
			}
		}
	}

	// Path 2: use direct dep count from registry (npm dependencies / PyPI requires_dist).
	// DependencyMetrics is always pre-populated by packageMetadataFromNPM/PyPI, so
	// Verified=false && DependencyMetrics!=nil reliably means "registry data was fetched".
	// This distinguishes "genuinely zero deps" (DirectCount=0) from "no data at all" (nil).
	//
	// Justification: "Small World with High Risks" (Zimmermann et al., 2019) shows each
	// direct dependency carries its own transitive tree, multiplicatively expanding the
	// attack surface. Direct dep count from registry is a reliable proxy for total
	// transitive exposure when a lock file is unavailable.
	if result.Metadata.DependencyMetrics != nil && !result.Metadata.DependencyMetrics.Verified {
		directCount := result.Metadata.DependencyMetrics.DirectCount

		// Score based on direct dependency count from the package registry
		// 0 pts = 0-5 direct deps (minimal sprawl — small or no dep tree)
		// 1 pt  = 6-15 direct deps (moderate sprawl)
		// 2 pts = 16+ direct deps (high sprawl — each dep multiplies attack surface)
		if directCount <= 5 {
			return models.CategoryScore{
				Score:       2,
				RiskPoints:  0,
				Description: "Few direct dependencies",
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)", directCount),
				Verified:    false,
			}
		} else if directCount <= 15 {
			return models.CategoryScore{
				Score:       1,
				RiskPoints:  1,
				Description: "Moderate direct dependencies",
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)", directCount),
				Verified:    false,
			}
		} else {
			return models.CategoryScore{
				Score:       0,
				RiskPoints:  2,
				Description: "Many direct dependencies",
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)", directCount),
				Verified:    false,
			}
		}
	}

	// Path 3: no dependency data available (DependencyMetrics=nil means neither npm/pypi
	// nor lock file provided data). Assign neutral moderate risk.
	// Stars and download counts are NOT valid proxies for dependency sprawl.
	return models.CategoryScore{
		Score:       1,
		RiskPoints:  1,
		Description: "Dependency count unavailable",
		Evidence:    "No lock file or registry dependency data found",
		Verified:    false,
	}
}
