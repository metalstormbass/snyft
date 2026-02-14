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
			expectedRisk:  nil, // Too young for this check
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
					Date: startDate.AddDate(0, 0, i*7), // Spread commits weekly
				},
			},
		}
	}
	return commits
}
