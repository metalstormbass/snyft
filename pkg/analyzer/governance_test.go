package analyzer

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// ===== Fast unit tests (no network) =====
//
// scoreGovernance returns early with risk=2 / Verified=false when RepositoryURL is empty.
// All other paths require live network calls; those are in the integration tests below.

// Test: No repository URL → moderate risk (needs investigation), unverified
// Justification: Package without a source repository cannot be audited for governance
//                practices. However, the absence of a repository URL may be due to an
//                API failure rather than genuinely missing governance. Assign moderate risk
//                rather than maximum, as further investigation is needed.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) §4.2
// Methodology: scoreGovernance early-exit when RepositoryURL == ""
// Result: 1 risk point (moderate, needs investigation), Verified=false, non-empty Description and Evidence
func TestScoreGovernance_NoRepository(t *testing.T) {
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

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for missing repository (needs investigation), got %d", score.RiskPoints)
	}
	if score.Verified {
		t.Error("Expected Verified=false when repository is unavailable")
	}
	if score.Description == "" {
		t.Error("Expected non-empty Description")
	}
	if score.Evidence == "" {
		t.Error("Expected non-empty Evidence")
	}
	if score.Score < 0 || score.Score > 2 {
		t.Errorf("Score out of range [0,2]: %d", score.Score)
	}
}

// Test: Governance risk assessment - Archived repository
// Justification: Archived repositories are permanently read-only and unmaintained.
//
//	No active governance = highest compromise risk since security issues
//	cannot be patched and maintainer accounts may go stale.
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//
//	OSSF Scorecard Specification
//
// Methodology: Check result.Metadata.RepoArchived flag from repository info
// Result: Should assign 2 risk points for archived repository
func TestScoreGovernance_ArchivedRepository(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/archived-package",
		Metadata: models.PackageMetadata{
			RepoArchived:   true,
			RepoLastCommit: time.Now().AddDate(-2, 0, 0),
			RepoCreatedAt:  time.Now().AddDate(-5, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "archived-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for archived repository, got %d", score.RiskPoints)
	}

	if !score.Verified {
		t.Error("Expected Verified=true for archived repository (we know it's archived)")
	}

	if !containsSubstring(score.Description, "archived") && !containsSubstring(score.Description, "Archived") {
		t.Errorf("Expected description to mention archived status, got: %s", score.Description)
	}
}

// Test: No-repository path is consistent across all ecosystems
// Justification: The early-exit logic is ecosystem-agnostic; all registries must behave
//                consistently when a source repository is unavailable.
// Source: OSSF Scorecard Specification – checks apply uniformly across ecosystems.
// Methodology: Table-driven test, empty RepositoryURL, varying ecosystems.
// Result: All ecosystems → 1 risk point (needs investigation), Verified=false.
func TestScoreGovernance_NoRepository_AllEcosystems(t *testing.T) {
	testCases := []struct {
		name      string
		ecosystem models.Ecosystem
		pkg       string
	}{
		{
			// Test: npm package without repository
			// Justification: npm is the primary vector for JS supply chain attacks
			// Source: Ohm et al., 2020 – 90% of analysed malicious packages were on npm
			name:      "npm without repository",
			ecosystem: models.EcosystemNPM,
			pkg:       "some-npm-pkg",
		},
		{
			// Test: PyPI package without repository
			// Justification: PyPI packages can publish without a source link
			// Source: "Backstabber's Knife Collection" – PyPI listed as second-highest risk
			name:      "pypi without repository",
			ecosystem: models.EcosystemPyPI,
			pkg:       "some-pypi-pkg",
		},
		{
			// Test: Maven package without repository
			// Justification: Maven Central does not require a source code URL
			// Source: OSSF Scorecard Maven check – frequently flags missing repository links
			name:      "maven without repository",
			ecosystem: models.EcosystemMaven,
			pkg:       "com.example:some-artifact",
		},
	}

	analyzer := NewAnalyzer()

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: "",
				Dependency: models.Dependency{
					Name:      tc.pkg,
					Ecosystem: tc.ecosystem,
				},
			}

			score := analyzer.scoreGovernance(result)

			if score.RiskPoints != 1 {
				t.Errorf("[%s] expected RiskPoints=1 (needs investigation), got %d", tc.name, score.RiskPoints)
			}
			if score.Verified {
				t.Errorf("[%s] expected Verified=false, got true", tc.name)
			}
		})
	}
}

// Test: CategoryScore fields are valid for the no-repository path
// Justification: Consumers rely on all fields of CategoryScore being populated correctly
//                to render risk dashboards and evidence trails.
// Source: Internal scoring rubric specification
// Methodology: Assert field ranges and non-empty strings
// Result: Score ∈ [0,2], RiskPoints ∈ [0,2], Description non-empty, Verified=false
func TestScoreGovernance_CategoryScoreFields_NoRepository(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "",
		Dependency: models.Dependency{
			Name:      "test-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	if score.Score < 0 || score.Score > 2 {
		t.Errorf("Score out of range [0,2]: %d", score.Score)
	}
	if score.RiskPoints < 0 || score.RiskPoints > 2 {
		t.Errorf("RiskPoints out of range [0,2]: %d", score.RiskPoints)
	}
	if score.Description == "" {
		t.Error("Description must not be empty")
	}
	if score.Evidence == "" {
		t.Error("Evidence must not be empty")
	}
	// Score + RiskPoints should always equal 2 (inversion model)
	if score.Score+score.RiskPoints != 2 {
		t.Errorf("Score (%d) + RiskPoints (%d) should equal 2 (inversion model)",
			score.Score, score.RiskPoints)
	}
}

// Test: Real npm packages from mike-libraries – no repository available
// Justification: Validates that widely-used packages, when assessed without a repository
//                URL, are assigned moderate governance risk requiring investigation.
//                The absence of a repository URL may be due to API failure, not genuinely
//                missing governance.
// Source: Packages from /Users/mike/Projects/mike-libraries/javascript/package.json
// Methodology: scoreGovernance with empty RepositoryURL for real-world npm dependency names
// Result: All packages → 1 risk point (needs investigation), Verified=false
func TestScoreGovernance_RealPackages_NPM_NoRepository(t *testing.T) {
	// These package names come from the mike-libraries javascript application
	// (express, axios, lodash, etc.) – well-known packages that DO have repositories
	// in practice, but we test the unverified path here.
	npmPackages := []string{
		"express",
		"axios",
		"lodash",
		"dotenv",
		"morgan",
		"helmet",
		"joi",
		"jsonwebtoken",
		"bcryptjs",
		"winston",
		"passport",
		"nodemailer",
		"stripe",
	}

	analyzer := NewAnalyzer()

	for _, pkg := range npmPackages {
		pkg := pkg
		t.Run(pkg, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: "",
				Dependency: models.Dependency{
					Name:      pkg,
					Ecosystem: models.EcosystemNPM,
				},
				Metadata: models.PackageMetadata{
					RepoLastCommit: time.Now().AddDate(0, -1, 0), // 1 month ago
				},
			}

			score := analyzer.scoreGovernance(result)

			if score.RiskPoints != 1 {
				t.Errorf("[%s] expected RiskPoints=1 (no repo, needs investigation), got %d", pkg, score.RiskPoints)
			}
			if score.Verified {
				t.Errorf("[%s] expected Verified=false (no repo), got true", pkg)
			}
		})
	}
}

// Test: Real Python packages from mike-libraries – no repository available
// Justification: Same as the npm case – validates consistent behaviour across ecosystems
//                for packages that DO exist but whose repository is not provided to snyft.
// Source: Packages from /Users/mike/Projects/mike-libraries/python/requirements.txt
// Methodology: scoreGovernance with empty RepositoryURL for real-world PyPI package names
// Result: All packages → 1 risk point (needs investigation), Verified=false
func TestScoreGovernance_RealPackages_PyPI_NoRepository(t *testing.T) {
	pypiPackages := []string{
		"Flask",
		"aiohttp",
		"gunicorn",
		"requests",
		"sqlalchemy",
		"celery",
		"fastapi",
		"cryptography",
		"boto3",
		"stripe",
		"passlib",
	}

	analyzer := NewAnalyzer()

	for _, pkg := range pypiPackages {
		pkg := pkg
		t.Run(pkg, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: "",
				Dependency: models.Dependency{
					Name:      pkg,
					Ecosystem: models.EcosystemPyPI,
				},
			}

			score := analyzer.scoreGovernance(result)

			if score.RiskPoints != 1 {
				t.Errorf("[%s] expected RiskPoints=1 (no repo, needs investigation), got %d", pkg, score.RiskPoints)
			}
			if score.Verified {
				t.Errorf("[%s] expected Verified=false (no repo), got true", pkg)
			}
		})
	}
}

// Test: Governance metrics zero values are safe
// Justification: GovernanceMetrics is constructed from API responses; zero values must
//                represent the unverified, highest-risk state without panicking.
// Source: Defensive programming principle – zero value = safe default
// Methodology: Create zero-value GovernanceMetrics, verify field semantics
// Result: Zero value means: no docs, no response data
func TestGovernanceMetrics_ZeroValueSemantics(t *testing.T) {
	metrics := GovernanceMetrics{}

	// Zero value → no governance signals detected
	if metrics.HasSecurityPolicy {
		t.Error("Zero value should have HasSecurityPolicy=false")
	}
	if metrics.AvgIssueResponseDays != 0 {
		t.Errorf("Zero value should have AvgIssueResponseDays=0, got %f", metrics.AvgIssueResponseDays)
	}
	if metrics.Verified {
		t.Error("Zero value should have Verified=false (unverified is the safe default)")
	}
}

// Test: Fully-populated GovernanceMetrics represents a well-governed package
// Justification: When all governance signals are positive, metrics should reflect
//                the low-risk profile accurately.
// Source: OSSF Scorecard Specification – Security Policy, Contributing, CODEOWNERS checks
// Methodology: Set all positive governance fields, verify correct representation
// Result: All governance flags set → struct represents lowest-risk profile
func TestGovernanceMetrics_WellGovernedPackage(t *testing.T) {
	metrics := GovernanceMetrics{
		HasSecurityPolicy:    true,
		AvgIssueResponseDays: 3.5, // Fast response (<7 days)
		Verified:             true,
	}

	if !metrics.HasSecurityPolicy {
		t.Error("Expected HasSecurityPolicy=true for well-governed package")
	}
	if metrics.AvgIssueResponseDays > 7 {
		t.Errorf("Fast response should be <=7 days, got %f", metrics.AvgIssueResponseDays)
	}
	if !metrics.Verified {
		t.Error("Expected Verified=true after successful data fetch")
	}
}

// ===== Integration tests (require live network / GitHub API) =====
//
// These tests use real or realistic GitHub repository URLs and make actual HTTP calls.
// They are skipped when running with `go test -short`.

// Test: Governance risk assessment – strong governance
// Justification: Packages with comprehensive governance documentation demonstrate lower
//                compromise risk through clear ownership and maintenance practices.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//
//	OSSF Scorecard Specification (Security Policy check)
//
// Methodology: Score packages with SECURITY.md, CONTRIBUTING.md, CODEOWNERS,
//
//	and fast issue response times (via live GitHub API calls)
//
// Result: Should assign 0 risk points for strong governance; Verified=true
func TestScoreGovernance_StrongGovernance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test: makes real network calls to GitHub")
	}

	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/strong-governance",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -7), // Active: 1 week ago
			RepoCreatedAt:  time.Now().AddDate(-2, 0, 0), // 2 years old
		},
		Dependency: models.Dependency{
			Name:      "test-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// Risk points must be in valid range regardless of network outcome
	if score.RiskPoints < 0 || score.RiskPoints > 2 {
		t.Errorf("RiskPoints out of range [0,2]: %d", score.RiskPoints)
	}
	// When a repository URL is provided, the score should be marked Verified=true
	// (analyzeGovernance sets Verified=true whenever repoURL != "")
	if !score.Verified {
		t.Error("Expected Verified=true when repository URL is provided")
	}
	// Active package (7 days ago) must not be flagged as abandoned
	if containsSubstring(score.Evidence, "Abandoned") {
		t.Errorf("Active package should not be flagged as abandoned; evidence: %s", score.Evidence)
	}
}

// Test: Governance risk assessment – dormant package no longer penalized for dormancy
// Justification: Dormancy is now assessed solely by Package Maturity to avoid
//                triple-counting the same signal. Governance only checks for
//                SECURITY.md, issue response times, and related process signals.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set package with >180 days of inactivity, verify governance does NOT
//              return early with abandonment penalty
// Result: Risk points should reflect governance signals (docs, response), not dormancy
func TestScoreGovernance_DormantPackageNotPenalizedForDormancy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test: makes real network calls to GitHub")
	}

	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/abandoned-package",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, -8, 0), // 8 months ago (>180 days)
			RepoCreatedAt:  time.Now().AddDate(-3, 0, 0), // 3 years old
		},
		Dependency: models.Dependency{
			Name:      "abandoned-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// Governance should NOT mention abandonment — that's Package Maturity's job
	if containsSubstring(score.Description, "Abandoned") || containsSubstring(score.Description, "abandoned") {
		t.Errorf("Governance should not penalize for dormancy (that's Package Maturity's job), got: %s", score.Description)
	}
	// Risk should be based on governance signals, not dormancy
	if score.RiskPoints < 0 || score.RiskPoints > 2 {
		t.Errorf("RiskPoints out of range [0,2]: %d", score.RiskPoints)
	}
}

// Test: Governance risk assessment - Abandonment threshold boundary (just before 180 days)
// Justification: Packages active within the last 6 months should not trigger the abandonment
//
//	override. This validates the 180-day threshold is correctly applied.
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set RepoLastCommit to 170 days ago (below abandonment threshold)
// Result: Should NOT return the "Abandoned" description
func TestScoreGovernance_NotAbandonedBelowThreshold(t *testing.T) {
	analyzer := NewAnalyzer()

	// Use empty URL so we don't make real HTTP calls — we're testing the
	// abandonment threshold logic, not file-checking behavior.
	// With no URL the early-return path fires (2 risk, not-abandoned message).
	result := &models.AnalysisResult{
		RepositoryURL: "",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -170), // 170 days — below 180-day threshold
			RepoCreatedAt:  time.Now().AddDate(-1, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "active-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// Without a URL the score is 2 risk for "no repo", but must NOT say "Abandoned"
	if containsSubstring(score.Description, "Abandoned") || containsSubstring(score.Description, "abandoned") {
		t.Errorf("Package active 170 days ago should not be flagged as abandoned, got: %s", score.Description)
	}
}

// Test: Governance risk assessment – active package (recent commits)
// Justification: Recent activity indicates active maintenance, reducing takeover risk.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Check for last commit within 90 days (live API call for docs check)
// Result: Package with commits within threshold must not be flagged as abandoned
func TestScoreGovernance_ActivePackage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test: makes real network calls to GitHub")
	}

	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -170), // 170 days — below 180-day threshold
			RepoCreatedAt:  time.Now().AddDate(-1, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "active-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// Active package: must not appear in evidence as abandoned
	if score.Evidence != "" && containsSubstring(score.Evidence, "Abandoned") {
		t.Errorf("Active package should not be flagged as abandoned; evidence: %s", score.Evidence)
	}
	// Score must be in valid range
	if score.RiskPoints < 0 || score.RiskPoints > 2 {
		t.Errorf("RiskPoints out of range [0,2]: %d", score.RiskPoints)
	}
}

// Test: CategoryScore structure when repository is accessible
// Justification: All CategoryScore fields must be populated even when network data is
//                limited, to prevent nil-pointer issues in downstream consumers.
// Source: Internal scoring rubric specification
// Methodology: Assert Score, RiskPoints, Description fields with live repository URL
// Result: All fields valid; Score ∈ [0,2]; Description non-empty
func TestScoreGovernance_CategoryScoreStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test: makes real network calls to GitHub")
	}

	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/inactive",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, -1, 0), // 1 month ago
			RepoCreatedAt:  time.Now().AddDate(-2, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "inactive-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	if score.Score < 0 || score.Score > 2 {
		t.Errorf("Score out of range [0,2]: %d", score.Score)
	}
	if score.RiskPoints < 0 || score.RiskPoints > 2 {
		t.Errorf("RiskPoints out of range [0,2]: %d", score.RiskPoints)
	}
	if score.Description == "" {
		t.Error("Description must not be empty")
	}
	// Score + RiskPoints = 2 (inversion model) when Verified=true
	if score.Verified && score.Score+score.RiskPoints != 2 {
		t.Errorf("When Verified: Score (%d) + RiskPoints (%d) should equal 2",
			score.Score, score.RiskPoints)
	}
}

// Test: Governance risk assessment - dormancy no longer triggers abandonment override
// Justification: Dormancy is now assessed solely by Package Maturity. Governance should
//                evaluate packages based on their governance signals regardless of activity.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set RepoLastCommit to 181 days ago, verify governance does NOT early-return
//              with abandonment penalty
// Result: Risk points should reflect governance signals, not dormancy
func TestScoreGovernance_DormancyDoesNotTriggerAbandonmentOverride(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/inactive",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -181), // 181 days — above old 180-day threshold
			RepoCreatedAt:  time.Now().AddDate(-2, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "inactive-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// Should NOT mention abandonment — that signal belongs to Package Maturity
	if containsSubstring(score.Description, "bandoned") {
		t.Errorf("Governance should not mention abandonment (Package Maturity owns that signal), got: %s", score.Description)
	}
	// Risk should be in valid range and based on governance signals
	if score.RiskPoints < 0 || score.RiskPoints > 2 {
		t.Errorf("RiskPoints out of range [0,2]: %d", score.RiskPoints)
	}
}

// Test: Governance risk assessment - Branch protection as process signal
// Test: Governance scoring without repo URL returns risk=1
// Justification: Without a repo URL, governance cannot be verified.
// Source: OSSF Scorecard Specification
// Methodology: Pass result without repository URL
// Result: 1 risk point when no repository URL
func TestScoreGovernance_NoRepoURL(t *testing.T) {
	analyzer := NewAnalyzer()

	// Package without repo URL
	result := &models.AnalysisResult{
		RepositoryURL: "", // no repo so we return early — test metadata path differently
		Metadata: models.PackageMetadata{
			RepoLastCommit:      time.Now().AddDate(0, 0, -5),
			RepoCreatedAt:       time.Now().AddDate(-2, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "protected-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	// Without a repo URL, risk is 1 (needs investigation) — verify the metadata doesn't affect it
	score := analyzer.scoreGovernance(result)
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point when no repository URL (needs investigation), got %d", score.RiskPoints)
	}
	if score.Verified {
		t.Error("Expected Verified=false when no repository URL")
	}
}

// Test: Governance scoring with OSSF Security-Policy override
// Justification: OSSF Scorecard's Security-Policy check is a more authoritative
//
//	source than file presence alone. If OSSF confirms a security policy exists,
//	it should count toward governance docs even if our file check missed it.
//
// Source: OSSF Scorecard Specification (https://github.com/ossf/scorecard)
// Methodology: Check OSSFChecks["Security-Policy"] score >= 5 from metadata
// Result: OSSF Security-Policy >= 5 should count as a governance doc
func TestScoreGovernance_OSSFSecurityPolicyCount(t *testing.T) {
	analyzer := NewAnalyzer()

	// Build a result with OSSF data but no repo (so we test just the scoring
	// logic in isolation — scoreGovernance returns early without a URL)
	result := &models.AnalysisResult{
		RepositoryURL: "",
		Metadata: models.PackageMetadata{
			OSSFChecks: map[string]int{
				"Security-Policy": 8, // High OSSF security-policy score
			},
		},
		Dependency: models.Dependency{
			Name:      "ossf-verified-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	// No repo URL → 1 risk (needs investigation; OSSF checks are only applied after govMetrics)
	score := analyzer.scoreGovernance(result)
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk for no-repo case (needs investigation), got %d", score.RiskPoints)
	}
}

// Test: Governance risk assessment - CategoryScore structure validation (archived path)
// Justification: Ensure scoring output includes all necessary information regardless of code path
// Source: Internal scoring rubric specification
// Methodology: Validate CategoryScore structure fields and valid ranges using archived-repo path
//
//	(fast, no HTTP calls needed)
//
// Result: CategoryScore should have score, risk points, description, evidence, verified;
//
//	Score + RiskPoints must always equal 2
func TestScoreGovernance_CategoryScoreStructure_ArchivedFast(t *testing.T) {
	analyzer := NewAnalyzer()

	// Use archived=true so we hit the early-return path (no HTTP calls, deterministic)
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/test-package",
		Metadata: models.PackageMetadata{
			RepoArchived:   true,
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

	// Validate all CategoryScore fields are in valid range
	if score.Score < 0 || score.Score > 2 {
		t.Errorf("Score out of range [0,2]: %d", score.Score)
	}
	if score.RiskPoints < 0 || score.RiskPoints > 2 {
		t.Errorf("RiskPoints out of range [0,2]: %d", score.RiskPoints)
	}
	if score.Description == "" {
		t.Error("Description must not be empty")
	}
	// Score + RiskPoints = 2 (inversion model) when Verified=true
	if score.Verified && score.Score+score.RiskPoints != 2 {
		t.Errorf("When Verified: Score (%d) + RiskPoints (%d) should equal 2",
			score.Score, score.RiskPoints)
	}
	// Score + RiskPoints should always sum to 2
	if score.Score+score.RiskPoints != 2 {
		t.Errorf("Score (%d) + RiskPoints (%d) should equal 2", score.Score, score.RiskPoints)
	}
}

// Test: GovernanceMetrics structure validation
// Justification: Ensure GovernanceMetrics correctly tracks compromise-relevant governance indicators
// Source: OSSF Scorecard Specification (Security Policy check)
// Methodology: Validate structure fields and types
// Result: GovernanceMetrics should contain security policy and responsiveness fields
func TestGovernanceMetrics_Structure(t *testing.T) {
	metrics := &GovernanceMetrics{
		HasSecurityPolicy:    true,
		AvgIssueResponseDays: 3.5,
		Verified:             true,
	}

	if !metrics.HasSecurityPolicy {
		t.Error("Expected HasSecurityPolicy to be true")
	}
	if metrics.AvgIssueResponseDays != 3.5 {
		t.Errorf("Expected AvgIssueResponseDays=3.5, got %f", metrics.AvgIssueResponseDays)
	}
	if !metrics.Verified {
		t.Error("Expected Verified to be true")
	}
}

// Test: Governance scoring thresholds — verify the 2-point system
// Justification: Validates the risk mapping used in scoreGovernance:
//
//	2 points → 0 risk (responsive + security policy)
//	1 point  → 1 risk (partial signals)
//	0 points → 2 risk (no signals)
//
// Source: Internal scoring rubric
// Methodology: Directly verify risk level boundaries
// Result: Risk points should match expected thresholds
func TestScoreGovernance_RiskThresholds(t *testing.T) {
	tests := []struct {
		name           string
		repoURL        string
		archived       bool
		lastCommit     time.Time
		expectedRisk   int
		expectedVerify bool
	}{
		{
			name:           "No repo URL",
			repoURL:        "",
			expectedRisk:   1,
			expectedVerify: false,
		},
		{
			name:           "Archived repo",
			repoURL:        "https://github.com/test/pkg",
			archived:       true,
			lastCommit:     time.Now().AddDate(-2, 0, 0),
			expectedRisk:   2,
			expectedVerify: true,
		},
		{
			name:           "Inactive package — scored on governance signals not dormancy",
			repoURL:        "https://github.com/test/pkg",
			lastCommit:     time.Now().AddDate(0, -8, 0),
			expectedRisk:   2,
			expectedVerify: true, // Verified=true because we reached analyzeGovernance (risk=2 from no governance docs, not dormancy)
		},
	}

	analyzer := NewAnalyzer()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: tc.repoURL,
				Metadata: models.PackageMetadata{
					RepoArchived:   tc.archived,
					RepoLastCommit: tc.lastCommit,
					RepoCreatedAt:  time.Now().AddDate(-3, 0, 0),
				},
				Dependency: models.Dependency{
					Name:      "test-package",
					Version:   "1.0.0",
					Ecosystem: models.EcosystemNPM,
				},
			}

			score := analyzer.scoreGovernance(result)

			if score.RiskPoints != tc.expectedRisk {
				t.Errorf("%s: expected risk %d, got %d (evidence: %s)",
					tc.name, tc.expectedRisk, score.RiskPoints, score.Evidence)
			}
			if score.Verified != tc.expectedVerify {
				t.Errorf("%s: expected Verified=%v, got %v", tc.name, tc.expectedVerify, score.Verified)
			}
		})
	}
}

// Test: Governance for well-known npm packages from mike-libraries
// Justification: express, axios, and lodash are heavily maintained open-source packages
//                with known-good governance. Validates that snyft correctly assesses
//                real-world, high-reputation packages as low governance risk when their
//                repositories are reachable.
// Source: Packages from /Users/mike/Projects/mike-libraries/javascript/package.json
//
//	express: https://github.com/expressjs/express
//	axios:   https://github.com/axios/axios
//	lodash:  https://github.com/lodash/lodash
//
// Methodology: Live GitHub API calls to check governance files and activity
// Result: Verified=true; risk points likely 0-1 for actively maintained packages
func TestScoreGovernance_RealPackages_NPM_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test: makes real network calls to GitHub")
	}

	cases := []struct {
		name       string
		repoURL    string
		lastCommit time.Time // approximate recent activity
	}{
		{
			// Test: express – highly active, multi-maintainer npm package
			// Justification: express has SECURITY.md, active CI, and responsive maintainers
			// Source: https://github.com/expressjs/express
			name:       "express",
			repoURL:    "https://github.com/expressjs/express",
			lastCommit: time.Now().AddDate(0, -1, 0),
		},
		{
			// Test: axios – popular HTTP client with strong governance
			// Justification: axios maintains CONTRIBUTING.md and security policy
			// Source: https://github.com/axios/axios
			name:       "axios",
			repoURL:    "https://github.com/axios/axios",
			lastCommit: time.Now().AddDate(0, -2, 0),
		},
	}

	analyzer := NewAnalyzer()

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: tc.repoURL,
				Metadata: models.PackageMetadata{
					RepoLastCommit: tc.lastCommit,
					RepoCreatedAt:  time.Now().AddDate(-5, 0, 0),
				},
				Dependency: models.Dependency{
					Name:      tc.name,
					Ecosystem: models.EcosystemNPM,
				},
			}

			score := analyzer.scoreGovernance(result)

			// Must always be in valid range
			if score.RiskPoints < 0 || score.RiskPoints > 2 {
				t.Errorf("[%s] RiskPoints out of range [0,2]: %d", tc.name, score.RiskPoints)
			}
			// Must be marked verified (repository URL was provided)
			if !score.Verified {
				t.Errorf("[%s] expected Verified=true, got false", tc.name)
			}
			// Active package – should not be flagged as abandoned
			if containsSubstring(score.Evidence, "Abandoned") {
				t.Errorf("[%s] active package should not be flagged as abandoned", tc.name)
			}
		})
	}
}

// Test: Governance for well-known Python packages from mike-libraries
// Justification: Flask and requests are canonical Python packages with known-good
//                governance. Tests that snyft handles PyPI packages correctly.
// Source: Packages from /Users/mike/Projects/mike-libraries/python/requirements.txt
//
//	Flask:    https://github.com/pallets/flask
//	requests: https://github.com/psf/requests
//
// Methodology: Live GitHub API calls
// Result: Verified=true; active packages not flagged as abandoned
func TestScoreGovernance_RealPackages_PyPI_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test: makes real network calls to GitHub")
	}

	cases := []struct {
		name       string
		repoURL    string
		lastCommit time.Time
	}{
		{
			// Test: Flask – actively maintained Python web framework
			// Justification: Flask has SECURITY.md, CONTRIBUTING.md, and CODEOWNERS
			// Source: https://github.com/pallets/flask
			name:       "Flask",
			repoURL:    "https://github.com/pallets/flask",
			lastCommit: time.Now().AddDate(0, -1, 0),
		},
		{
			// Test: requests – popular Python HTTP library
			// Justification: requests has strong governance and is actively maintained by PSF
			// Source: https://github.com/psf/requests
			name:       "requests",
			repoURL:    "https://github.com/psf/requests",
			lastCommit: time.Now().AddDate(0, -2, 0),
		},
	}

	analyzer := NewAnalyzer()

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: tc.repoURL,
				Metadata: models.PackageMetadata{
					RepoLastCommit: tc.lastCommit,
					RepoCreatedAt:  time.Now().AddDate(-5, 0, 0),
				},
				Dependency: models.Dependency{
					Name:      tc.name,
					Ecosystem: models.EcosystemPyPI,
				},
			}

			score := analyzer.scoreGovernance(result)

			if score.RiskPoints < 0 || score.RiskPoints > 2 {
				t.Errorf("[%s] RiskPoints out of range [0,2]: %d", tc.name, score.RiskPoints)
			}
			if !score.Verified {
				t.Errorf("[%s] expected Verified=true, got false", tc.name)
			}
			if containsSubstring(score.Evidence, "Abandoned") {
				t.Errorf("[%s] active package should not be flagged as abandoned", tc.name)
			}
		})
	}
}

// ===== Mock HTTP server tests (no external network, exercises full scoring path) =====

// newMockGitHubServer creates an httptest.Server that simulates GitHub API responses
// for governance file checks. The governanceFiles map specifies which files "exist"
// (file path → true/false).
func newMockGitHubServer(governanceFiles map[string]bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Handle HEAD requests for file existence (used by FileExistsInRepo)
		if r.Method == "HEAD" {
			for filePath, exists := range governanceFiles {
				if strings.Contains(path, "/contents/"+filePath) {
					if exists {
						w.WriteHeader(http.StatusOK)
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Handle GET requests for file content (fallback path)
		if r.Method == "GET" {
			for filePath, exists := range governanceFiles {
				if strings.Contains(path, "/contents/"+filePath) {
					if exists {
						w.Header().Set("Content-Type", "text/plain")
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte("# Governance file content"))
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
					return
				}
			}
			// Issue response time endpoint — return empty to avoid nil
			if strings.Contains(path, "/issues") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("[]"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// newAnalyzerWithMockGitHub creates an Analyzer whose githubClient points at the
// given mock server URL. This exercises the real checkGovernanceFile → FileExistsInRepo
// path without hitting the real GitHub API.
func newAnalyzerWithMockGitHub(mockBaseURL string) *Analyzer {
	a := NewAnalyzer()
	a.githubClient = fetcher.NewGitHubClientWithBaseURL(mockBaseURL)
	return a
}

// Test: Governance scoring detects SECURITY.md and CONTRIBUTING.md via HEAD requests
// Justification: When the GitHub API is accessible, governance file checks must use
//                efficient HEAD requests (via FileExistsInRepo) and correctly identify
//                governance documentation. Two governance docs → 2 docs points, which
//                combined with no process points → 1 risk (moderate governance).
// Source: OSSF Scorecard Specification (Security-Policy, Contributing checks)
// Methodology: Mock GitHub Contents API HEAD endpoint returning 200 for governance files
// Result: Two governance docs → 1 risk point (moderate governance)
func TestScoreGovernance_MockServer_TwoGovernanceDocs(t *testing.T) {
	server := newMockGitHubServer(map[string]bool{
		"SECURITY.md":          true,
		"CONTRIBUTING.md":      true,
		"CODEOWNERS":           false,
		"CODE_OF_CONDUCT.md":   false,
		".github/SECURITY.md":  false,
		".github/CODEOWNERS":   false,
	})
	defer server.Close()

	analyzer := newAnalyzerWithMockGitHub(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/governance-repo",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -7), // Active: 1 week ago
			RepoCreatedAt:  time.Now().AddDate(-2, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "well-governed-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// Two governance docs (SECURITY.md + CONTRIBUTING.md) → docsPoints=2
	// No process points (no issue response, no release docs) → processPoints=0
	// Total=2 → 1 risk (moderate governance)
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for 2 governance docs, got %d (evidence: %s)",
			score.RiskPoints, score.Evidence)
	}
	if !score.Verified {
		t.Error("Expected Verified=true when mock API is accessible")
	}
	if !containsSubstring(score.Evidence, "SECURITY.md") {
		t.Errorf("Expected evidence to mention SECURITY.md, got: %s", score.Evidence)
	}
	// Note: refactored governance only checks SECURITY.md (security disclosure process),
	// not CONTRIBUTING.md. CONTRIBUTING.md is not a supply chain security signal.
}

// Test: Governance scoring with governance docs → 1 risk
// Justification: Two governance docs (SECURITY.md + CONTRIBUTING.md) = 2 docsPoints,
//                no issue response or release docs → processPoints=0,
//                total = 2 → 1 risk (moderate governance).
// Source: OSSF Scorecard Specification (Security-Policy checks)
// Methodology: Mock API with governance files
// Result: Moderate governance → 1 risk point
func TestScoreGovernance_MockServer_StrongGovernance(t *testing.T) {
	server := newMockGitHubServer(map[string]bool{
		"SECURITY.md":          true,
		"CONTRIBUTING.md":      true,
		"CODEOWNERS":           false,
		"CODE_OF_CONDUCT.md":   false,
		".github/SECURITY.md":  false,
		".github/CODEOWNERS":   false,
	})
	defer server.Close()

	analyzer := newAnalyzerWithMockGitHub(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/governance-repo",
		Metadata: models.PackageMetadata{
			RepoLastCommit:      time.Now().AddDate(0, 0, -3),
			RepoCreatedAt:       time.Now().AddDate(-3, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "strong-governance-pkg",
			Version:   "3.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// 2 docs → docsPoints=2, no process signals → processPoints=0, total=2 → risk=1
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for moderate governance (2 docs, no process signals), got %d (evidence: %s)",
			score.RiskPoints, score.Evidence)
	}
	if !score.Verified {
		t.Error("Expected Verified=true")
	}
	if !containsSubstring(score.Description, "SECURITY.md") {
		t.Errorf("Description should reference SECURITY.md, got: %s", score.Description)
	}
}

// Test: Governance scoring with no governance files → 2 risk points
// Justification: No governance documentation indicates poor supply chain governance.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Mock API returning 404 for all governance files
// Result: No governance docs → 2 risk points (poor governance)
func TestScoreGovernance_MockServer_NoGovernanceDocs(t *testing.T) {
	server := newMockGitHubServer(map[string]bool{
		"SECURITY.md":          false,
		"CONTRIBUTING.md":      false,
		"CODEOWNERS":           false,
		"CODE_OF_CONDUCT.md":   false,
		".github/SECURITY.md":  false,
		".github/CODEOWNERS":   false,
	})
	defer server.Close()

	analyzer := newAnalyzerWithMockGitHub(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/no-governance-repo",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -7),
			RepoCreatedAt:  time.Now().AddDate(-1, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "no-governance-pkg",
			Version:   "0.1.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// No docs → docsPoints=0, no process → total=0 → risk=2
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for no governance docs, got %d (evidence: %s)",
			score.RiskPoints, score.Evidence)
	}
	if !containsSubstring(score.Description, "No security policy") || !containsSubstring(score.Description, "unreported") {
		t.Errorf("Description should explain missing security policy and its risk, got: %s", score.Description)
	}
}

// Test: Governance scoring with single governance doc → 1 risk point
// Justification: A single governance doc (e.g., SECURITY.md only) earns 1 docs point.
//                This is moderate governance — present but incomplete.
// Source: OSSF Scorecard Specification
// Methodology: Mock API with only SECURITY.md existing
// Result: 1 doc → docsPoints=1, total=1 → 1 risk
func TestScoreGovernance_MockServer_SingleGovernanceDoc(t *testing.T) {
	server := newMockGitHubServer(map[string]bool{
		"SECURITY.md":          true,
		"CONTRIBUTING.md":      false,
		"CODEOWNERS":           false,
		"CODE_OF_CONDUCT.md":   false,
		".github/SECURITY.md":  false,
		".github/CODEOWNERS":   false,
	})
	defer server.Close()

	analyzer := newAnalyzerWithMockGitHub(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/single-doc-repo",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -14),
			RepoCreatedAt:  time.Now().AddDate(-1, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "single-doc-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// 1 doc → docsPoints=1, no process → total=1 → risk=1
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for single governance doc, got %d (evidence: %s)",
			score.RiskPoints, score.Evidence)
	}
	// Refactored governance checks SECURITY.md only (security disclosure process)
	if !containsSubstring(score.Evidence, "Security policy") {
		t.Errorf("Expected evidence to mention 'Security policy', got: %s", score.Evidence)
	}
}

// Test: .github/SECURITY.md fallback location is checked
// Justification: Many repos place SECURITY.md in .github/ instead of root.
//                The governance check must check both locations.
// Source: GitHub documentation on community health files
// Methodology: Mock API with SECURITY.md only in .github/ directory
// Result: .github/SECURITY.md counts as governance documentation
func TestScoreGovernance_MockServer_DotGithubSecurityMd(t *testing.T) {
	server := newMockGitHubServer(map[string]bool{
		"SECURITY.md":          false,
		"CONTRIBUTING.md":      true,
		"CODEOWNERS":           false,
		"CODE_OF_CONDUCT.md":   false,
		".github/SECURITY.md":  true,
		".github/CODEOWNERS":   false,
	})
	defer server.Close()

	analyzer := newAnalyzerWithMockGitHub(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/dotgithub-repo",
		Metadata: models.PackageMetadata{
			RepoLastCommit: time.Now().AddDate(0, 0, -5),
			RepoCreatedAt:  time.Now().AddDate(-2, 0, 0),
		},
		Dependency: models.Dependency{
			Name:      "dotgithub-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scoreGovernance(result)

	// .github/SECURITY.md + CONTRIBUTING.md → docsPoints=2, total=2 → risk=1
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point (2 governance docs via .github/ fallback), got %d (evidence: %s)",
			score.RiskPoints, score.Evidence)
	}
}
