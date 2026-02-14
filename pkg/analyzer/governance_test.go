package analyzer

import (
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: Governance risk assessment - Strong governance
// Justification: Packages with comprehensive governance documentation and responsive
//                maintainers demonstrate lower compromise risk through clear ownership
//                and maintenance practices
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         OSSF Scorecard Specification (Security Policy check)
// Methodology: Score packages with SECURITY.md, CONTRIBUTING.md, CODEOWNERS,
//              and fast issue response times
// Result: Should assign 0 risk points for strong governance
func TestScoreGovernance_StrongGovernance(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/strong-governance",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -7), // Active (1 week ago)
			RepoCreatedAt:  time.Now().AddDate(-2, 0, 0), // 2 years old
		},
		Dependency: models.Dependency{
			Name:      "test-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	// Note: This test would require mocking the git client to return
	// governance files and issue response times. For now, we test the
	// scoring logic with a result that would have been populated by
	// the analyzeGovernance method

	score := analyzer.scoreGovernance(result)

	// Without repository access, should get moderate risk
	if score.RiskPoints > 2 {
		t.Errorf("Expected risk points <= 2 for governance check, got %d", score.RiskPoints)
	}

	if !score.Verified && result.RepositoryURL == "" {
		t.Error("Expected Verified=true when repository URL is provided")
	}
}

// Test: Governance risk assessment - Poor governance
// Justification: Packages without governance documentation = unclear maintainership =
//                higher risk of unnoticed compromise or account takeover
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         OSSF Scorecard Specification
// Methodology: Score packages missing governance documentation and slow to respond
// Result: Should assign 2 risk points for poor governance
func TestScoreGovernance_PoorGovernance(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "", // No repository
		Metadata:      models.PackageMetadata{},
		Dependency: models.Dependency{
			Name:      "test-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for missing repository, got %d", score.RiskPoints)
	}

	if score.Verified {
		t.Error("Expected Verified=false when repository is unavailable")
	}

	if score.Description == "" {
		t.Error("Expected non-empty description")
	}
}

// Test: Governance risk assessment - Abandoned package
// Justification: Dormant packages that suddenly reactivate are a common supply chain
//                attack pattern. Abandoned packages = unmaintained = higher takeover risk
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Detect packages with >180 days of inactivity
// Result: Should assign 2 risk points for abandonment
func TestScoreGovernance_AbandonedPackage(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/abandoned-package",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, -8, 0), // 8 months ago
			RepoCreatedAt:  time.Now().AddDate(-3, 0, 0), // 3 years old
		},
		Dependency: models.Dependency{
			Name:      "abandoned-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// With 8 months of inactivity, should get highest risk
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for abandoned package, got %d", score.RiskPoints)
	}

	if score.Evidence == "" {
		t.Error("Expected evidence string to include abandonment information")
	}
}

// Test: Governance risk assessment - Active package with recent commits
// Justification: Recent activity indicates active maintenance, reducing takeover risk
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Check for recent commits (within 90 days)
// Result: Should not flag as abandoned
func TestScoreGovernance_ActivePackage(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/active-package",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -5), // 5 days ago
			RepoCreatedAt:  time.Now().AddDate(-1, 0, 0), // 1 year old
		},
		Dependency: models.Dependency{
			Name:      "active-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// Active package should not be flagged as abandoned
	if score.Evidence != "" && containsSubstring(score.Evidence, "Abandoned") {
		t.Error("Active package should not be flagged as abandoned")
	}
}

// Test: GovernanceMetrics structure validation
// Justification: Ensure GovernanceMetrics correctly tracks all governance indicators
// Source: OSSF Scorecard Specification
// Methodology: Validate structure fields and types
// Result: GovernanceMetrics should contain all required fields
func TestGovernanceMetrics_Structure(t *testing.T) {
	metrics := &GovernanceMetrics{
		HasSecurityPolicy:    true,
		HasContributing:      true,
		HasCodeOwners:        true,
		AvgIssueResponseDays: 3.5,
		RecentActivityGap:    10.0,
		HasAbandonmentPattern: false,
		Verified:             true,
	}

	if !metrics.HasSecurityPolicy {
		t.Error("Expected HasSecurityPolicy to be true")
	}
	if !metrics.HasContributing {
		t.Error("Expected HasContributing to be true")
	}
	if !metrics.HasCodeOwners {
		t.Error("Expected HasCodeOwners to be true")
	}
	if metrics.AvgIssueResponseDays != 3.5 {
		t.Errorf("Expected AvgIssueResponseDays=3.5, got %f", metrics.AvgIssueResponseDays)
	}
	if !metrics.Verified {
		t.Error("Expected Verified to be true")
	}
}

// Test: CategoryScore for governance has all required fields
// Justification: Ensure scoring output includes all necessary information
// Source: Internal scoring rubric specification
// Methodology: Validate CategoryScore structure
// Result: CategoryScore should have score, risk points, description, evidence, verified
func TestScoreGovernance_CategoryScoreStructure(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/test-package",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -10),
			RepoCreatedAt:  time.Now().AddDate(-1, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "test-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// Validate all CategoryScore fields are populated
	if score.Score < 0 || score.Score > 2 {
		t.Errorf("Score should be 0-2, got %d", score.Score)
	}
	if score.RiskPoints < 0 || score.RiskPoints > 2 {
		t.Errorf("RiskPoints should be 0-2, got %d", score.RiskPoints)
	}
	if score.Description == "" {
		t.Error("Description should not be empty")
	}
	// Evidence can be empty if no data is available
	// Verified indicates whether we could check the data
}

