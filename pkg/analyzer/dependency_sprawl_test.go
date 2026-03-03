package analyzer

import (
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ===== Dependency Sprawl Scoring Tests =====
//
// These tests verify that ecosystem-specific thresholds correctly assess
// supply chain attack surface from dependency counts.

// Test: npm package with few direct dependencies scores low risk
// Justification: A small dependency count limits supply chain entry points
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=3, Verified=false for npm ecosystem
// Result: 0 risk points (low sprawl)
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

// Test: npm package with moderate direct dependencies scores moderate risk
// Justification: Each direct dependency carries its own transitive tree
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=10, Verified=false for npm ecosystem
// Result: 1 risk point (moderate sprawl)
func TestScoreDependencySprawl_NPM_ModerateDirectCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "mid-npm-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 10, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for npm with 10 direct deps, got %d", score.RiskPoints)
	}
}

// Test: npm package with many direct dependencies scores high risk
// Justification: >15 direct deps for npm represents high attack surface
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=20, Verified=false for npm ecosystem
// Result: 2 risk points (high sprawl)
func TestScoreDependencySprawl_NPM_HighDirectCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "big-npm-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 20, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for npm with 20 direct deps, got %d", score.RiskPoints)
	}
}

// Test: Maven package with 20 direct deps scores low risk (Maven-adjusted threshold)
// Justification: Maven BOM imports, dependency management sections, and multi-module
//                aggregation inflate apparent counts without representing actual attack
//                surface. 20 direct deps in Maven is typical for a well-structured
//                project using managed dependencies, unlike npm where 20 is high sprawl.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
//         Maven-specific adjustment for BOM/managed dependency inflation
// Methodology: Set DirectCount=10, Verified=false for Maven ecosystem
// Result: 0 risk points (low sprawl, within Maven-adjusted threshold)
func TestScoreDependencySprawl_Maven_LowDirectCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "com.example:small-maven", Version: "1.0.0", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 10, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for Maven with 10 direct deps (within Maven low threshold of 12), got %d", score.RiskPoints)
	}
}

// Test: Maven package with 20 deps scores moderate (not high) thanks to Maven-adjusted thresholds
// Justification: 20 direct deps in Maven is moderate due to BOM/management inflation,
//                whereas the same count in npm would be high risk. Maven's dependency
//                management model means many declared deps are managed/inherited and
//                don't represent independent supply chain entry points.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
//         Maven-specific adjustment for BOM/managed dependency inflation
// Methodology: Set DirectCount=20, Verified=false for Maven ecosystem
// Result: 1 risk point (moderate sprawl) — same count would be 2 risk points for npm
func TestScoreDependencySprawl_Maven_ModerateDirectCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "com.example:mid-maven", Version: "1.0.0", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 20, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for Maven with 20 direct deps (moderate in Maven range 13-29), got %d", score.RiskPoints)
	}
}

// Test: Maven package with 35 deps scores high risk even with Maven-adjusted thresholds
// Justification: Even accounting for Maven's BOM/management inflation, 35+ direct
//                dependencies represents genuine sprawl with significant attack surface.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=35, Verified=false for Maven ecosystem
// Result: 2 risk points (high sprawl, exceeds Maven threshold of 30)
func TestScoreDependencySprawl_Maven_HighDirectCount(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "com.example:big-maven", Version: "1.0.0", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 35, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for Maven with 35 direct deps (exceeds Maven threshold of 29), got %d", score.RiskPoints)
	}
}

// Test: Same dependency count scores differently for npm vs Maven
// Justification: Maven's dependency model inflates counts via BOMs and managed deps.
//                A count of 16 direct deps represents high sprawl in npm (>15 threshold)
//                but is moderate in Maven (within 13-29 range). Failing to account for
//                this penalizes Maven projects for idiomatic dependency management.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Compare scoring for DirectCount=16 across npm and Maven ecosystems
// Result: npm=2 risk points (high), Maven=1 risk point (moderate)
func TestScoreDependencySprawl_SameCount_DifferentEcosystem(t *testing.T) {
	analyzer := NewAnalyzer()

	npmResult := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "npm-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 16, Verified: false},
		},
	}

	mavenResult := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "com.example:maven-pkg", Version: "1.0.0", Ecosystem: models.EcosystemMaven,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 16, Verified: false},
		},
	}

	npmScore := analyzer.scoreDependencySprawl(npmResult)
	mavenScore := analyzer.scoreDependencySprawl(mavenResult)

	if npmScore.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for npm with 16 direct deps, got %d", npmScore.RiskPoints)
	}
	if mavenScore.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for Maven with 16 direct deps (within Maven moderate range), got %d", mavenScore.RiskPoints)
	}
}

// Test: PyPI uses default (npm-like) thresholds
// Justification: PyPI's dependency model is similar to npm — requires_dist entries
//                represent actual transitive exposure. No threshold adjustment needed.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set DirectCount=16, Verified=false for PyPI ecosystem
// Result: 2 risk points (same as npm, default thresholds apply)
func TestScoreDependencySprawl_PyPI_UsesDefaultThresholds(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name: "pypi-pkg", Version: "1.0.0", Ecosystem: models.EcosystemPyPI,
		},
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{DirectCount: 16, Verified: false},
		},
	}

	score := analyzer.scoreDependencySprawl(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for PyPI with 16 direct deps (default thresholds), got %d", score.RiskPoints)
	}
}

// Test: Lock file path is ecosystem-agnostic (not affected by Maven thresholds)
// Justification: Lock file provides exact transitive counts regardless of ecosystem.
//                BOM/management inflation is irrelevant when we have actual resolved deps.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set TransitiveCount=60, Verified=true for Maven ecosystem
// Result: 2 risk points (lock file thresholds are ecosystem-agnostic)
func TestScoreDependencySprawl_LockFile_EcosystemAgnostic(t *testing.T) {
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

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for lock file with 60 transitive deps, got %d", score.RiskPoints)
	}
	if !score.Verified {
		t.Error("Expected Verified=true for lock file path")
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

	// 5 compile+runtime deps is well within Maven low threshold (≤12)
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

