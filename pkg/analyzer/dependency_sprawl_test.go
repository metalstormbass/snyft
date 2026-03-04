package analyzer

import (
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ===== Dependency Sprawl Scoring Tests =====
//
// These tests verify that dependency sprawl is scored as a weak signal (0-1 pts)
// with only extreme sprawl triggering 1 risk point.

// Test: npm package with few direct dependencies scores 0 risk
// Justification: Dependency count is a weak signal; normal counts should not add risk
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=3, Verified=false for npm ecosystem
// Result: 0 risk points (normal count)
func TestScoreDependencySprawl_NPM_LowDirectCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "small-npm-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 3, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for npm with 3 direct deps, got %d", score.RiskPoints)
	}
}

// Test: npm package with moderate direct dependencies still scores 0 risk
// Justification: Dependency count is a weak signal; only extreme sprawl (50+) triggers risk
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=20, Verified=false for npm ecosystem
// Result: 0 risk points (below 50 threshold)
func TestScoreDependencySprawl_NPM_ModerateDirectCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "mid-npm-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 20, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for npm with 20 direct deps (below 50 threshold), got %d", score.RiskPoints)
	}
}

// Test: npm package with extreme direct dependencies scores 1 risk point
// Justification: 50+ direct deps for npm represents extreme sprawl worth flagging
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=55, Verified=false for npm ecosystem
// Result: 1 risk point (extreme sprawl, max for this category)
func TestScoreDependencySprawl_NPM_ExtremeDirectCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "big-npm-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 55, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for npm with 55 direct deps (extreme sprawl), got %d", score.RiskPoints)
	}
}

// Test: Maven package with 50 direct deps scores 0 risk (Maven-adjusted threshold)
// Justification: Maven BOM imports, dependency management sections, and multi-module
//                aggregation inflate apparent counts. 50 direct deps in Maven is normal.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=50, Verified=false for Maven ecosystem
// Result: 0 risk points (within Maven threshold of 100)
func TestScoreDependencySprawl_Maven_NormalDirectCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "com.example:mid-maven", Version: "1.0.0", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 50, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for Maven with 50 direct deps (within Maven threshold of 100), got %d", score.RiskPoints)
	}
}

// Test: Maven package with 105 deps scores 1 risk point (extreme sprawl)
// Justification: Even accounting for Maven's BOM/management inflation, 100+ direct
//                dependencies represents extreme sprawl.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=105, Verified=false for Maven ecosystem
// Result: 1 risk point (extreme sprawl, exceeds Maven threshold of 100)
func TestScoreDependencySprawl_Maven_ExtremeDirectCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "com.example:big-maven", Version: "1.0.0", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 105, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for Maven with 105 direct deps (exceeds Maven threshold of 100), got %d", score.RiskPoints)
	}
}

// Test: Same dependency count scores differently for npm vs Maven
// Justification: Maven's dependency model inflates counts via BOMs and managed deps.
//                A count of 55 direct deps represents extreme sprawl in npm (>=50 threshold)
//                but is normal in Maven (within 100 threshold). Failing to account for
//                this penalizes Maven projects for idiomatic dependency management.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Compare scoring for DirectCount=55 across npm and Maven ecosystems
// Result: npm=1 risk point (extreme), Maven=0 risk points (normal)
func TestScoreDependencySprawl_SameCount_DifferentEcosystem(t *testing.T) {
	analyzer := NewAnalyzer()

	npmResult := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "npm-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 55, Verified: false},
		},
	}

	mavenResult := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "com.example:maven-pkg", Version: "1.0.0", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 55, Verified: false},
		},
	}

	npmScore := analyzer.scoreDependencySprawl(npmResult)
	mavenScore := analyzer.scoreDependencySprawl(mavenResult)

	if npmScore.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for npm with 55 direct deps, got %d", npmScore.RiskPoints)
	}
	if mavenScore.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for Maven with 55 direct deps (within Maven threshold), got %d", mavenScore.RiskPoints)
	}
}

// Test: PyPI uses default (npm-like) thresholds
// Justification: PyPI's dependency model is similar to npm — requires_dist entries
//                represent actual transitive exposure. No threshold adjustment needed.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=55, Verified=false for PyPI ecosystem
// Result: 1 risk point (same as npm, default thresholds apply)
func TestScoreDependencySprawl_PyPI_UsesDefaultThresholds(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "pypi-pkg", Version: "1.0.0", Ecosystem: models.EcosystemPyPI,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 55, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for PyPI with 55 direct deps (default thresholds), got %d", score.RiskPoints)
	}
}

// Test: Lock file path uses transitive count with extreme threshold
// Justification: Lock file provides exact transitive counts regardless of ecosystem.
//                Only extreme sprawl (>200 transitive deps) triggers 1 risk point.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set TransitiveCount=250, Verified=true for Maven ecosystem
// Result: 1 risk point (lock file extreme threshold is ecosystem-agnostic)
func TestScoreDependencySprawl_LockFile_ExtremeSprawl(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "com.example:locked-maven", Version: "1.0.0", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				TransitiveCount: 250, DirectCount: 30, MaxDepth: 8, Verified: true,
			},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for lock file with 250 transitive deps, got %d", score.RiskPoints)
	}
	if !score.Verified {
		t.Error("Expected Verified=true for lock file path")
	}
}

// Test: Lock file with normal transitive count scores 0 risk
// Justification: Lock file with moderate count should not trigger risk for weak signal.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set TransitiveCount=60, Verified=true
// Result: 0 risk points (60 is well within 200 threshold)
func TestScoreDependencySprawl_LockFile_NormalCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "com.example:locked-maven", Version: "1.0.0", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				TransitiveCount: 60, DirectCount: 15, MaxDepth: 5, Verified: true,
			},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for lock file with 60 transitive deps (within 200 threshold), got %d", score.RiskPoints)
	}
}

// Test: Maven scope breakdown appears in description and evidence
// Justification: Packages like Lombok declare many test/provided deps that inflate
//                apparent dependency counts. Scope-aware counting gives accurate risk
//                assessment, and the breakdown helps users understand why the score
//                differs from the raw dependency count visible in the POM.
// Source: Maven Dependency Scope reference — https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Dependency_Scope
//         "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=3 with MavenScopeBreakdown showing 3 compile, 2 runtime, 17 test, 2 provided.
//              Verify description includes scope breakdown.
// Result: Description includes "3 compile, 2 runtime, 17 test, 2 provided" breakdown
func TestScoreDependencySprawl_Maven_ScopeBreakdownInDescription(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "com.example:scope-test", Version: "1.0.0", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				DirectCount: 5,
				Verified:    false,
				MavenScopeBreakdown: &models.MavenScopeBreakdown{
					Compile:  3,
					Runtime:  2,
					Test:     17,
					Provided: 2,
				},
			},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	// 5 compile+runtime deps is well within Maven threshold (≤99)
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for Maven with 5 compile+runtime deps, got %d", score.RiskPoints)
	}

	// Description should contain scope breakdown
	if !contains(score.Description, "3 compile") {
		t.Errorf("Description should contain '3 compile', got: %s", score.Description)
	}
	if !contains(score.Description, "2 runtime") {
		t.Errorf("Description should contain '2 runtime', got: %s", score.Description)
	}
	if !contains(score.Description, "17 test") {
		t.Errorf("Description should contain '17 test', got: %s", score.Description)
	}
	if !contains(score.Description, "2 provided") {
		t.Errorf("Description should contain '2 provided', got: %s", score.Description)
	}

	// Evidence should also contain scope info
	if !contains(score.Evidence, "scope:") {
		t.Errorf("Evidence should contain scope breakdown, got: %s", score.Evidence)
	}
}

// Test: Maven package with many test/provided deps but few compile+runtime scores low risk
// Justification: This is the Lombok scenario — 28 total POM deps but zero runtime deps.
//                Without scope awareness, this would score as high sprawl. With scope
//                awareness, only compile+runtime deps count, giving an accurate low score.
// Source: Maven Dependency Scope reference — https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Dependency_Scope
//         "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=0 with scope breakdown showing all deps are test/provided.
// Result: 0 risk points (no compile+runtime deps = no supply chain sprawl)
func TestScoreDependencySprawl_Maven_LombokScenario(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "org.projectlombok:lombok", Version: "1.18.30", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				DirectCount: 0,
				Verified:    false,
				MavenScopeBreakdown: &models.MavenScopeBreakdown{
					Compile:  0,
					Runtime:  0,
					Test:     25,
					Provided: 3,
				},
			},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	// 0 compile+runtime deps = low risk
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for Maven with 0 compile+runtime deps (Lombok scenario), got %d", score.RiskPoints)
	}
}

// Test: npm packages do not get Maven scope breakdown (only Maven uses scopes)
// Justification: Scope breakdown is Maven-specific and should not appear for other ecosystems.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=10 for npm without MavenScopeBreakdown.
//              Verify description does not contain scope information.
// Result: No scope breakdown in description for non-Maven ecosystems
func TestScoreDependencySprawl_NPM_NoScopeBreakdown(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "npm-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 10, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if contains(score.Description, "compile") {
		t.Errorf("npm description should not contain Maven scope info, got: %s", score.Description)
	}
}

// Test: No data available gives 0 risk (weak signal, don't penalize missing data)
// Justification: Dependency count is the weakest supply chain signal. Missing data
//                should not inflate the risk score for this category.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: No DependencyMetrics provided
// Result: 0 risk points, DataAvailable=false
func TestScoreDependencySprawl_NoData(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "unknown-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for no data (weak signal), got %d", score.RiskPoints)
	}
	if score.DataAvailable {
		t.Error("Expected DataAvailable=false for no data path")
	}
}
