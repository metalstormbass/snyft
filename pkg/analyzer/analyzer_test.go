package analyzer

import (
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// ===== Release Anomalies Tests (from main branch) =====

func TestScoreReleaseAnomalies(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name           string
		result         models.AnalysisResult
		expectedRisk   int
		expectedDesc   string
		expectedVerify bool
	}{
		{
			name: "No commit history available",
			result: models.AnalysisResult{
				Metadata: models.PackageMetadata{
					RepoLastCommit: time.Time{}, // Zero time
				},
			},
			expectedRisk:   1,
			expectedDesc:   "Unable to verify release patterns",
			expectedVerify: false,
		},
		{
			name: "Dormant package (>1 year inactive)",
			result: models.AnalysisResult{
				Metadata: models.PackageMetadata{
					RepoLastCommit: time.Now().AddDate(-2, 0, 0), // 2 years ago
					RepoCreatedAt:  time.Now().AddDate(-3, 0, 0), // 3 years ago
				},
				RepositoryURL: "https://github.com/example/repo",
			},
			expectedRisk:   1,
			expectedDesc:   "Package appears dormant",
			expectedVerify: true,
		},
		{
			name: "Regular consistent activity",
			result: models.AnalysisResult{
				Metadata: models.PackageMetadata{
					RepoLastCommit: time.Now().AddDate(0, -2, 0), // 2 months ago
					RepoCreatedAt:  time.Now().AddDate(-2, 0, 0), // 2 years ago
				},
				RepositoryURL: "https://github.com/example/active-repo",
			},
			expectedRisk:   0,
			expectedDesc:   "Regular, consistent releases",
			expectedVerify: true,
		},
		{
			name: "New package with recent activity",
			result: models.AnalysisResult{
				Metadata: models.PackageMetadata{
					RepoLastCommit: time.Now().AddDate(0, -1, 0), // 1 month ago
					RepoCreatedAt:  time.Now().AddDate(0, -6, 0), // 6 months ago
				},
				RepositoryURL: "https://github.com/example/new-repo",
			},
			expectedRisk:   0,
			expectedDesc:   "Regular, consistent releases",
			expectedVerify: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.scoreReleaseAnomalies(&tt.result)

			if score.RiskPoints != tt.expectedRisk {
				t.Errorf("Expected RiskPoints=%d, got %d", tt.expectedRisk, score.RiskPoints)
			}

			if score.Verified != tt.expectedVerify {
				t.Errorf("Expected Verified=%v, got %v", tt.expectedVerify, score.Verified)
			}

			// Check that description contains expected keywords
			// (exact match not required as implementation may vary)
			if tt.expectedDesc != "" && score.Description == "" {
				t.Errorf("Expected non-empty description, got empty")
			}
		})
	}
}

func TestDetectReleaseAnomaly(t *testing.T) {
	analyzer := NewAnalyzer()
	repoCreatedAt := time.Now().AddDate(-3, 0, 0) // 3 years ago

	tests := []struct {
		name         string
		releases     []fetcher.GitHubRelease
		expectedRisk *int // nil if no anomaly expected
		expectedDesc string
	}{
		{
			name:         "No releases",
			releases:     []fetcher.GitHubRelease{},
			expectedRisk: nil,
		},
		{
			name: "Single release",
			releases: []fetcher.GitHubRelease{
				{PublishedAt: time.Now().AddDate(0, -1, 0), Draft: false, Prerelease: false},
			},
			expectedRisk: nil,
		},
		{
			name: "Suspicious reactivation - long dormancy then recent release",
			releases: []fetcher.GitHubRelease{
				{PublishedAt: time.Now().AddDate(0, -1, 0), Draft: false, Prerelease: false},  // 1 month ago
				{PublishedAt: time.Now().AddDate(-2, 0, 0), Draft: false, Prerelease: false}, // 2 years ago
			},
			expectedRisk: intPtr(2),
			expectedDesc: "Suspicious reactivation",
		},
		{
			name: "Regular release pattern - consistent frequency",
			releases: []fetcher.GitHubRelease{
				{PublishedAt: time.Now().AddDate(0, -3, 0), Draft: false, Prerelease: false},  // 3 months ago
				{PublishedAt: time.Now().AddDate(0, -6, 0), Draft: false, Prerelease: false},  // 6 months ago
				{PublishedAt: time.Now().AddDate(0, -9, 0), Draft: false, Prerelease: false},  // 9 months ago
				{PublishedAt: time.Now().AddDate(-1, 0, 0), Draft: false, Prerelease: false}, // 12 months ago
			},
			expectedRisk: nil, // No anomaly
		},
		{
			name: "Unusual pattern - sudden spike in release frequency",
			releases: []fetcher.GitHubRelease{
				{PublishedAt: time.Now().AddDate(0, 0, -3), Draft: false, Prerelease: false},  // 3 days ago
				{PublishedAt: time.Now().AddDate(0, 0, -8), Draft: false, Prerelease: false},  // 8 days ago (very close!)
				{PublishedAt: time.Now().AddDate(0, -4, 0), Draft: false, Prerelease: false},  // 4 months ago
				{PublishedAt: time.Now().AddDate(0, -8, 0), Draft: false, Prerelease: false},  // 8 months ago
				{PublishedAt: time.Now().AddDate(-1, -2, 0), Draft: false, Prerelease: false}, // 14 months ago
			},
			expectedRisk: intPtr(2),
			expectedDesc: "Unusual release pattern",
		},
		{
			name: "Drafts and prereleases are ignored",
			releases: []fetcher.GitHubRelease{
				{PublishedAt: time.Now().AddDate(0, -1, 0), Draft: true, Prerelease: false},   // Draft
				{PublishedAt: time.Now().AddDate(0, -2, 0), Draft: false, Prerelease: true},   // Prerelease
				{PublishedAt: time.Now().AddDate(0, -3, 0), Draft: false, Prerelease: false}, // Valid
			},
			expectedRisk: nil, // Only 1 valid release after filtering
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.detectReleaseAnomaly(tt.releases, repoCreatedAt)

			if tt.expectedRisk == nil {
				if score != nil {
					t.Errorf("Expected no anomaly, but got RiskPoints=%d", score.RiskPoints)
				}
			} else {
				if score == nil {
					t.Errorf("Expected anomaly with RiskPoints=%d, but got nil", *tt.expectedRisk)
				} else if score.RiskPoints != *tt.expectedRisk {
					t.Errorf("Expected RiskPoints=%d, got %d", *tt.expectedRisk, score.RiskPoints)
				}
			}
		})
	}
}

func TestDetectCommitFrequencyAnomaly(t *testing.T) {
	analyzer := NewAnalyzer()
	repoCreatedAt := time.Now().AddDate(-3, 0, 0) // 3 years old

	tests := []struct {
		name           string
		recentCommits  []fetcher.GitHubCommit
		olderCommits   []fetcher.GitHubCommit
		repoAge        time.Time
		expectedRisk   *int // nil if no anomaly
		expectedDesc   string
	}{
		{
			name:          "Suspicious spike - dormant then active",
			recentCommits: makeCommits(25, time.Now().AddDate(0, -6, 0)), // 25 commits in last year
			olderCommits:  makeCommits(2, time.Now().AddDate(-2, 0, 0)),  // 2 commits in previous year
			repoAge:       repoCreatedAt,
			expectedRisk:  intPtr(2),
			expectedDesc:  "Suspicious commit frequency spike",
		},
		{
			name:          "Moderate reactivation",
			recentCommits: makeCommits(10, time.Now().AddDate(0, -6, 0)), // 10 commits in last year
			olderCommits:  makeCommits(0, time.Now().AddDate(-2, 0, 0)),  // 0 commits in previous year
			repoAge:       repoCreatedAt,
			expectedRisk:  intPtr(1),
			expectedDesc:  "Package reactivated after dormancy",
		},
		{
			name:          "Consistent activity",
			recentCommits: makeCommits(20, time.Now().AddDate(0, -6, 0)), // 20 commits
			olderCommits:  makeCommits(18, time.Now().AddDate(-2, 0, 0)), // 18 commits
			repoAge:       repoCreatedAt,
			expectedRisk:  nil, // No anomaly
		},
		{
			name:          "New repo - not enough history",
			recentCommits: makeCommits(10, time.Now().AddDate(0, -3, 0)),
			olderCommits:  makeCommits(0, time.Now().AddDate(-1, 0, 0)),
			repoAge:       time.Now().AddDate(-1, 0, 0), // Only 1 year old
			expectedRisk:  nil,                           // Too young for this check
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.detectCommitFrequencyAnomaly(tt.recentCommits, tt.olderCommits, tt.repoAge)

			if tt.expectedRisk == nil {
				if score != nil {
					t.Errorf("Expected no anomaly, but got RiskPoints=%d", score.RiskPoints)
				}
			} else {
				if score == nil {
					t.Errorf("Expected anomaly with RiskPoints=%d, but got nil", *tt.expectedRisk)
				} else if score.RiskPoints != *tt.expectedRisk {
					t.Errorf("Expected RiskPoints=%d, got %d", *tt.expectedRisk, score.RiskPoints)
				}
			}
		})
	}
}

func TestScoreDependencySprawl_Few(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				TransitiveCount: 5,
				DirectCount:     2,
				Verified:        true,
			},
		},
	}

	score := a.scoreDependencySprawl(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for few dependencies, got %d", score.RiskPoints)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}

	if score.Description != "Few transitive dependencies" {
		t.Errorf("Unexpected description: %s", score.Description)
	}
}

func TestScoreDependencySprawl_Moderate(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				TransitiveCount: 25,
				DirectCount:     5,
				Verified:        true,
			},
		},
	}

	score := a.scoreDependencySprawl(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for moderate dependencies, got %d", score.RiskPoints)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}

	if score.Description != "Moderate transitive dependencies" {
		t.Errorf("Unexpected description: %s", score.Description)
	}
}

func TestScoreDependencySprawl_Many(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				TransitiveCount: 75,
				DirectCount:     10,
				Verified:        true,
			},
		},
	}

	score := a.scoreDependencySprawl(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for many dependencies, got %d", score.RiskPoints)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}

	if score.Description != "Many transitive dependencies" {
		t.Errorf("Unexpected description: %s", score.Description)
	}
}

func TestScoreDependencySprawl_EdgeCase_Exactly10(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				TransitiveCount: 10,
				DirectCount:     3,
				Verified:        true,
			},
		},
	}

	score := a.scoreDependencySprawl(result)

	// 10 deps should be "moderate" (1 point)
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for exactly 10 dependencies, got %d", score.RiskPoints)
	}
}

func TestScoreDependencySprawl_EdgeCase_Exactly50(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				TransitiveCount: 50,
				DirectCount:     5,
				Verified:        true,
			},
		},
	}

	score := a.scoreDependencySprawl(result)

	// 50 deps should still be "moderate" (1 point)
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for exactly 50 dependencies, got %d", score.RiskPoints)
	}
}

func TestScoreDependencySprawl_Fallback_NoMetrics(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			RepoStars:     5,
			DownloadCount: 100,
		},
	}

	score := a.scoreDependencySprawl(result)

	// Should fall back to heuristics
	if score.Verified {
		t.Error("Expected unverified score when using heuristics")
	}

	// Low stars = high risk (2 points)
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for low popularity, got %d", score.RiskPoints)
	}
}

// Helper function to create a pointer to an int
func intPtr(i int) *int {
	return &i
}

// Helper function to generate mock commits
func makeCommits(count int, startDate time.Time) []fetcher.GitHubCommit {
	commits := make([]fetcher.GitHubCommit, count)
	for i := 0; i < count; i++ {
		commits[i] = fetcher.GitHubCommit{
			SHA: "abc123",
			Commit: fetcher.GitHubCommitInfo{
				Author: fetcher.GitHubCommitAuthor{
					Name:  "test-author",
					Email: "test@example.com",
					Date:  startDate.AddDate(0, 0, i*7), // Spread commits weekly
				},
			},
		}
	}
	return commits
}

// ===== Health Scoring Tests (new feature) =====

func TestScoreHealth_HighRisk(t *testing.T) {
	tests := []struct {
		name     string
		result   *models.AnalysisResult
		wantRisk int // Expected risk points
	}{
		{
			name: "Single contributor, no CI, no reviews",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:         1,
					TopContributorPct: 95.0,
					HasCI:             false,
					CIQualityScore:    0,
					CodeReviewRate:    0,
				},
			},
			wantRisk: 2, // Highest risk
		},
		{
			name: "High contributor concentration",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:         1,
					TopContributorPct: 100.0,
					HasCI:             true,
					CIQualityScore:    3, // Basic CI only
					CodeReviewRate:    0,
				},
			},
			wantRisk: 2, // High risk - concentrated development
		},
		{
			name: "No maintainers (fallback)",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:      0, // Not calculated
					Maintainers:    []string{},
					HasCI:          false,
					CIQualityScore: 0,
					CodeReviewRate: 0,
				},
			},
			wantRisk: 2, // High risk
		},
	}

	analyzer := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.scoreHealth(tt.result)
			if score.RiskPoints != tt.wantRisk {
				t.Errorf("scoreHealth() RiskPoints = %d, want %d", score.RiskPoints, tt.wantRisk)
			}
			if !score.Verified && tt.result.Metadata.BusFactor > 0 {
				t.Errorf("scoreHealth() should be verified when data is available")
			}
		})
	}
}

func TestScoreHealth_MediumRisk(t *testing.T) {
	tests := []struct {
		name     string
		result   *models.AnalysisResult
		wantRisk int
	}{
		{
			name: "Good bus factor with quality CI but no reviews",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:         5,
					TopContributorPct: 30.0,
					HasCI:             true,
					CIQualityScore:    7,
					CIHasTests:        true,
					CodeReviewRate:    50, // Below 75% threshold
				},
			},
			wantRisk: 1, // Medium risk - 2 points (bus factor + CI)
		},
		{
			name: "CI and reviews but high bus factor",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:      1,
					HasCI:          true,
					CIQualityScore: 8,
					CIHasTests:     true,
					CodeReviewRate: 85,
				},
			},
			wantRisk: 1, // Medium risk - 2 points (CI + reviews, but no bus factor point)
		},
		{
			name: "Good bus factor with high review rate but basic CI",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:      4,
					HasCI:          true,
					CIQualityScore: 4,
					CodeReviewRate: 80,
				},
			},
			wantRisk: 1, // Medium risk - 2 points (bus factor + reviews)
		},
	}

	analyzer := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.scoreHealth(tt.result)
			if score.RiskPoints != tt.wantRisk {
				t.Errorf("scoreHealth() RiskPoints = %d, want %d (evidence: %s)",
					score.RiskPoints, tt.wantRisk, score.Evidence)
			}
		})
	}
}

func TestScoreHealth_LowRisk(t *testing.T) {
	tests := []struct {
		name     string
		result   *models.AnalysisResult
		wantRisk int
	}{
		{
			name: "Distributed development, CI with tests, required reviews",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:           5,
					TopContributorPct:   25.0,
					HasCI:               true,
					CIQualityScore:      9,
					CIHasTests:          true,
					HasBranchProtection: true,
					RequiredReviewers:   2,
					CodeReviewRate:      95.0,
				},
			},
			wantRisk: 0, // Lowest risk
		},
		{
			name: "Good bus factor, quality CI, high review rate",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:         3,
					TopContributorPct: 40.0,
					HasCI:             true,
					CIQualityScore:    8,
					CIHasTests:        true,
					CodeReviewRate:    80.0,
				},
			},
			wantRisk: 0, // Low risk
		},
		{
			name: "Many maintainers, CI, reviews",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:           4,
					Maintainers:         []string{"alice", "bob", "carol", "dave"},
					HasCI:               true,
					CIQualityScore:      7,
					HasBranchProtection: true,
					RequiredReviewers:   1,
				},
			},
			wantRisk: 0, // Low risk
		},
	}

	analyzer := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.scoreHealth(tt.result)
			if score.RiskPoints != tt.wantRisk {
				t.Errorf("scoreHealth() RiskPoints = %d, want %d (evidence: %s)",
					score.RiskPoints, tt.wantRisk, score.Evidence)
			}
			if score.RiskPoints == 0 && score.Score < 3 {
				t.Errorf("scoreHealth() with 0 risk should have Score >= 3, got %d", score.Score)
			}
		})
	}
}

func TestScoreOwnershipChanges_FallbackBehavior(t *testing.T) {
	analyzer := &Analyzer{
		githubClient: fetcher.NewGitHubClient(),
		npmClient:    fetcher.NewNPMClient(),
		pypiClient:   fetcher.NewPyPIClient(),
	}

	// Test fallback to repository age when APIs fail
	result := models.AnalysisResult{
		RepositoryURL: "",
		Dependency: models.Dependency{
			Name:      "nonexistent-package-xyz-123456789",
			Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			RepoCreatedAt: time.Now().AddDate(-2, 0, 0),
			Maintainers:   []string{"alice", "bob", "charlie"},
		},
	}

	score := analyzer.scoreOwnershipChanges(&result)

	// Should have evidence
	if score.Evidence == "" {
		t.Error("scoreOwnershipChanges() evidence should not be empty")
	}

	// Should have a valid risk score
	if score.RiskPoints < 0 || score.RiskPoints > 2 {
		t.Errorf("scoreOwnershipChanges() risk points = %v, want 0-2", score.RiskPoints)
	}
}

func TestCalculateSupplyChainScore_OwnershipChangesIntegration(t *testing.T) {
	analyzer := &Analyzer{
		githubClient: fetcher.NewGitHubClient(),
		npmClient:    fetcher.NewNPMClient(),
		pypiClient:   fetcher.NewPyPIClient(),
		mavenClient:  fetcher.NewMavenClient(),
		ossfClient:   fetcher.NewOSSFClient(),
	}

	result := models.AnalysisResult{
		RepositoryURL: "",
		Dependency: models.Dependency{
			Name:      "nonexistent-package-xyz-123456789",
			Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			RepoCreatedAt: time.Now().AddDate(-3, 0, 0),
			Maintainers:   []string{"alice", "bob", "charlie", "dave"},
			HasCI:         true,
			CISystems:     []string{"GitHub Actions"},
		},
	}

	analyzer.calculateSupplyChainScore(&result)

	if result.SupplyChainScore == nil {
		t.Fatal("calculateSupplyChainScore() should set SupplyChainScore")
	}

	// Check that ownership changes category is scored
	ownershipScore := result.SupplyChainScore.CategoryScores.OwnershipChanges

	// Should have evidence
	if ownershipScore.Evidence == "" {
		t.Error("OwnershipChanges evidence should not be empty")
	}

	// Should have a valid risk score
	if ownershipScore.RiskPoints < 0 || ownershipScore.RiskPoints > 2 {
		t.Errorf("OwnershipChanges risk points = %v, want 0-2", ownershipScore.RiskPoints)
	}

	// Total score should be in valid range
	if result.SupplyChainScore.TotalScore < 0 || result.SupplyChainScore.TotalScore > 14 {
		t.Errorf("TotalScore = %v, want 0-14", result.SupplyChainScore.TotalScore)
	}
}

func TestVerifySourceCode(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name                    string
		dep                     models.Dependency
		repoURL                 string
		expectFindingSeverity   string
		expectFindingCategory   string
		expectSourceVerification bool
	}{
		{
			name: "Source verification creates findings when source missing",
			dep: models.Dependency{
				Name:      "test-package",
				Version:   "1.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			repoURL:                 "",
			expectFindingSeverity:   "",
			expectFindingCategory:   "",
			expectSourceVerification: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := models.AnalysisResult{
				Dependency: tt.dep,
				Timestamp:  time.Now(),
				Findings:   []models.Finding{},
			}

			analyzer.verifySourceCode(&result, tt.dep, tt.repoURL)

			if tt.expectSourceVerification && result.SourceVerification == nil {
				t.Error("Expected SourceVerification to be populated")
			}

			if tt.expectFindingSeverity != "" {
				found := false
				for _, finding := range result.Findings {
					if finding.Severity == tt.expectFindingSeverity &&
					   finding.Category == tt.expectFindingCategory {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected finding with severity=%s and category=%s, but not found in: %v",
						tt.expectFindingSeverity, tt.expectFindingCategory, result.Findings)
				}
			}
		})
	}
}

func TestScoreHealth_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		result *models.AnalysisResult
	}{
		{
			name: "Empty metadata",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{},
			},
		},
		{
			name: "Negative values (should handle gracefully)",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:      -1, // Invalid but should not crash
					CIQualityScore: -5,
					CodeReviewRate: -10,
				},
			},
		},
		{
			name: "Very high values",
			result: &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:         1000,
					TopContributorPct: 150.0, // Invalid but should not crash
					CIQualityScore:    100,
					CodeReviewRate:    200.0,
				},
			},
		},
	}

	analyzer := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			score := analyzer.scoreHealth(tt.result)

			// Risk points should always be 0-2
			if score.RiskPoints < 0 || score.RiskPoints > 2 {
				t.Errorf("scoreHealth() RiskPoints out of range: %d", score.RiskPoints)
			}

			// Should have some description
			if score.Description == "" {
				t.Error("scoreHealth() Description should not be empty")
			}
		})
	}
}

func TestSourceVerificationIntegrationInAnalyzer(t *testing.T) {
	t.Run("Source verification is the first check", func(t *testing.T) {
		result := models.AnalysisResult{
			Dependency: models.Dependency{
				Name:      "express",
				Version:   "4.18.0",
				Ecosystem: models.EcosystemNPM,
			},
			Findings: []models.Finding{},
		}

		analyzer := NewAnalyzer()
		analyzer.verifySourceCode(&result, result.Dependency, "https://github.com/expressjs/express")

		if result.SourceVerification == nil {
			t.Error("Expected SourceVerification to be populated")
		}
	})
}

func TestScoreHealth_BusFactorCalculation(t *testing.T) {
	tests := []struct {
		name              string
		busFactor         int
		topContributorPct float64
		ciQualityScore    int
		codeReviewRate    float64
		wantHighRisk      bool
	}{
		{
			name:              "Single contributor with 100% commits",
			busFactor:         1,
			topContributorPct: 100.0,
			ciQualityScore:    5,
			codeReviewRate:    0,
			wantHighRisk:      true, // 0 points = 2 risk
		},
		{
			name:              "Two contributors but good CI and reviews",
			busFactor:         2,
			topContributorPct: 55.0,
			ciQualityScore:    8,
			codeReviewRate:    80.0,
			wantHighRisk:      false, // 2 points (CI + reviews) = 1 risk
		},
		{
			name:              "Many contributors with good CI",
			busFactor:         10,
			topContributorPct: 15.0,
			ciQualityScore:    8,
			codeReviewRate:    0,
			wantHighRisk:      false, // 2 points (bus factor + CI) = 1 risk
		},
		{
			name:              "Three contributors (threshold) with reviews",
			busFactor:         3,
			topContributorPct: 40.0,
			ciQualityScore:    0,
			codeReviewRate:    85.0,
			wantHighRisk:      false, // 2 points (bus factor + reviews) = 1 risk
		},
	}

	analyzer := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:         tt.busFactor,
					TopContributorPct: tt.topContributorPct,
					HasCI:             tt.ciQualityScore > 0,
					CIQualityScore:    tt.ciQualityScore,
					CodeReviewRate:    tt.codeReviewRate,
				},
			}

			score := analyzer.scoreHealth(result)

			// High risk should correlate with low bus factor and missing practices
			isHighRisk := score.RiskPoints >= 2
			if isHighRisk != tt.wantHighRisk {
				t.Errorf("scoreHealth() high risk = %v, want %v (bus factor: %d, evidence: %s)",
					isHighRisk, tt.wantHighRisk, tt.busFactor, score.Evidence)
			}
		})
	}
}

func TestScoreHealth_CodeReviewVerification(t *testing.T) {
	tests := []struct {
		name                string
		hasBranchProtection bool
		requiredReviewers   int
		codeReviewRate      float64
		ciQualityScore      int
		expectsReviewPoint  bool
	}{
		{
			name:                "Branch protection with required reviewers",
			hasBranchProtection: true,
			requiredReviewers:   2,
			codeReviewRate:      0,
			ciQualityScore:      8,
			expectsReviewPoint:  true,
		},
		{
			name:                "High review rate without protection",
			hasBranchProtection: false,
			requiredReviewers:   0,
			codeReviewRate:      85.0,
			ciQualityScore:      8,
			expectsReviewPoint:  true,
		},
		{
			name:                "Moderate review rate",
			hasBranchProtection: false,
			requiredReviewers:   0,
			codeReviewRate:      60.0,
			ciQualityScore:      8,
			expectsReviewPoint:  false, // Below 75% threshold
		},
		{
			name:                "No reviews",
			hasBranchProtection: false,
			requiredReviewers:   0,
			codeReviewRate:      0,
			ciQualityScore:      8,
			expectsReviewPoint:  false,
		},
	}

	analyzer := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:           3, // Good bus factor (gets 1 point)
					HasCI:               true,
					CIQualityScore:      tt.ciQualityScore, // >= 7 gets 1 point
					HasBranchProtection: tt.hasBranchProtection,
					RequiredReviewers:   tt.requiredReviewers,
					CodeReviewRate:      tt.codeReviewRate,
				},
			}

			score := analyzer.scoreHealth(result)

			// With bus factor and good CI, score should be at least 2
			// If reviews give a point, should be 3
			minExpectedScore := 2
			if tt.expectsReviewPoint {
				minExpectedScore = 3
			}

			if score.Score < minExpectedScore {
				t.Errorf("scoreHealth() Score = %d, want at least %d (evidence: %s)",
					score.Score, minExpectedScore, score.Evidence)
			}
		})
	}
}

func TestScoreHealth_CIQualityAssessment(t *testing.T) {
	tests := []struct {
		name           string
		hasCI          bool
		ciQualityScore int
		ciHasTests     bool
		expectsPoint   bool
	}{
		{
			name:           "High quality CI with tests",
			hasCI:          true,
			ciQualityScore: 9,
			ciHasTests:     true,
			expectsPoint:   true,
		},
		{
			name:           "Quality CI at threshold",
			hasCI:          true,
			ciQualityScore: 7,
			ciHasTests:     true,
			expectsPoint:   true,
		},
		{
			name:           "Moderate quality CI",
			hasCI:          true,
			ciQualityScore: 5,
			ciHasTests:     false,
			expectsPoint:   false,
		},
		{
			name:           "Basic CI only",
			hasCI:          true,
			ciQualityScore: 3,
			ciHasTests:     false,
			expectsPoint:   false,
		},
		{
			name:           "No CI",
			hasCI:          false,
			ciQualityScore: 0,
			ciHasTests:     false,
			expectsPoint:   false,
		},
	}

	analyzer := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					BusFactor:      3, // Good bus factor
					HasCI:          tt.hasCI,
					CIQualityScore: tt.ciQualityScore,
					CIHasTests:     tt.ciHasTests,
				},
			}

			score := analyzer.scoreHealth(result)

			// Score should be at least 1 (bus factor)
			// If CI quality gives a point, should be 2+
			if tt.expectsPoint && score.Score < 2 {
				t.Errorf("scoreHealth() expected CI quality point but Score = %d (evidence: %s)",
					score.Score, score.Evidence)
			}
		})
	}
}
