package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ===== Feature-complete detection tests =====

// Test: Feature-complete package with stale commits gets reduced penalty
// Justification: Packages like "six" (Python 2/3 compat) are intentionally stable.
//                Conflating feature-complete with abandoned inflates risk scores and
//                creates false positives. A non-archived repo with stability keywords
//                in the description signals intentional maintenance-mode, not neglect.
// Source: "Small World with High Risks" (Zimmermann et al., 2019) — distinguishes
//         intentional stability from neglect when assessing maintenance risk.
// Methodology: Set RepoDescription to contain "stable" keyword, last commit >1yr ago,
//              repo NOT archived, and verify staleness penalty is reduced from 2 to 1.
// Result: Risk points should be 1 (not 2) for feature-complete stale packages.
func TestScorePackageMaturity_FeatureCompleteReducesPenalty(t *testing.T) {
	analyzer := NewAnalyzer()
	now := time.Now()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			RepoCreatedAt:   now.AddDate(-5, 0, 0),  // 5 years old (established)
			RepoLastCommit:  now.AddDate(-2, 0, 0),   // 2 years since last commit (stale)
			RepoArchived:    false,                    // NOT archived
			RepoDescription: "Python 2 and 3 compatibility utilities. Stable and feature-complete.",
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints > 1 {
		t.Errorf("Expected risk points <= 1 for feature-complete package, got %d", score.RiskPoints)
	}
	if score.RiskPoints == 2 {
		t.Error("Feature-complete package should NOT receive maximum staleness penalty of 2")
	}
}

// Test: Stale package without feature-complete keywords still gets full penalty
// Justification: A stale package without any indication of intentional stability
//                should be treated as potentially abandoned — higher takeover risk.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set last commit >1yr ago, no feature-complete keywords in description,
//              repo NOT archived. Verify full staleness penalty applies.
// Result: Risk points should be 2 for a truly stale/abandoned package.
func TestScorePackageMaturity_StaleWithoutFeatureCompleteKeywords(t *testing.T) {
	analyzer := NewAnalyzer()
	now := time.Now()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			RepoCreatedAt:   now.AddDate(-5, 0, 0),  // 5 years old
			RepoLastCommit:  now.AddDate(-2, 0, 0),   // 2 years since last commit
			RepoArchived:    false,
			RepoDescription: "A utility library for parsing JSON",
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected risk points = 2 for stale non-feature-complete package, got %d", score.RiskPoints)
	}
}

// Test: Archived repo with feature-complete keywords does NOT get reduced penalty
// Justification: An archived repository is truly unmaintained regardless of description
//                keywords. Archived repos cannot receive security patches, so they remain
//                high risk even if the description says "stable".
// Source: OSSF Scorecard specification — archived repos score 0 on maintenance checks.
// Methodology: Set repo as archived with "stable" in description and stale commits.
//              Verify the feature-complete detection does NOT apply.
// Result: Risk points should be 2 (full staleness penalty) for archived repos.
func TestScorePackageMaturity_ArchivedRepoNotReducedEvenWithKeywords(t *testing.T) {
	analyzer := NewAnalyzer()
	now := time.Now()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			RepoCreatedAt:   now.AddDate(-5, 0, 0),
			RepoLastCommit:  now.AddDate(-2, 0, 0),
			RepoArchived:    true,  // Archived — truly unmaintained
			RepoDescription: "A stable, production-ready library",
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected risk points = 2 for archived repo (even with stable keywords), got %d", score.RiskPoints)
	}
}

// Test: Feature-complete detection uses softer language in description
// Justification: Users should understand the distinction between abandoned and
//                feature-complete. The risk description should reflect reduced concern.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Check that the description for a feature-complete package contains
//              "feature-complete" language rather than "abandoned" or "takeover" language.
// Result: Description should mention "feature-complete" or "intentionally low activity".
func TestScorePackageMaturity_FeatureCompleteSofterLanguage(t *testing.T) {
	analyzer := NewAnalyzer()
	now := time.Now()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			RepoCreatedAt:   now.AddDate(-5, 0, 0),
			RepoLastCommit:  now.AddDate(-2, 0, 0),
			RepoArchived:    false,
			RepoDescription: "Mature, feature-complete HTTP client library",
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if !strings.Contains(score.Description, "feature-complete") {
		t.Errorf("Expected description to mention 'feature-complete', got: %s", score.Description)
	}
	if strings.Contains(score.Description, "may be abandoned") {
		t.Errorf("Feature-complete description should NOT say 'may be abandoned', got: %s", score.Description)
	}
}

// Test: Various feature-complete keywords are recognized
// Justification: Different projects use different terminology to indicate stability.
//                The detection should cover common variations.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Test each keyword variant against isFeatureCompleteDescription.
// Result: All expected keywords should be recognized.
func TestIsFeatureCompleteDescription(t *testing.T) {
	tests := []struct {
		desc     string
		expected bool
	}{
		{"a stable library for http", true},
		{"this project is feature-complete", true},
		{"this project is feature complete", true},
		{"library in maintenance mode", true},
		{"a mature project", true},
		{"production-ready toolkit", true},
		{"production ready toolkit", true},
		{"no longer actively developed but still usable", true},
		{"considered complete implementation of the spec", true},
		{"fully implemented rfc 1234", true},
		// Negative cases
		{"a cool new library", false},
		{"fast json parser", false},
		{"", false},
		{"actively developed framework", false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := isFeatureCompleteDescription(strings.ToLower(tc.desc))
			if got != tc.expected {
				t.Errorf("isFeatureCompleteDescription(%q) = %v, want %v", tc.desc, got, tc.expected)
			}
		})
	}
}

// Test: Feature-complete check is recorded in ChecksPerformed
// Justification: Evidence trail must document that feature-complete detection was applied,
//                per project guidelines requiring methodology documentation.
// Source: Project CLAUDE.md — every risk point must have clear justification and evidence trail.
// Methodology: Verify ChecksPerformed includes a "Feature-complete detection" entry.
// Result: ChecksPerformed should contain the feature-complete check with PASS status.
func TestScorePackageMaturity_FeatureCompleteCheckRecorded(t *testing.T) {
	analyzer := NewAnalyzer()
	now := time.Now()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			RepoCreatedAt:   now.AddDate(-5, 0, 0),
			RepoLastCommit:  now.AddDate(-2, 0, 0),
			RepoArchived:    false,
			RepoDescription: "A stable compatibility layer",
		},
	}

	score := analyzer.scorePackageMaturity(result)

	found := false
	for _, check := range score.ChecksPerformed {
		if check.Name == "Feature-complete detection" {
			found = true
			if check.Status != "PASS" {
				t.Errorf("Expected Feature-complete detection status=PASS, got %s", check.Status)
			}
		}
	}
	if !found {
		t.Error("Expected 'Feature-complete detection' in ChecksPerformed")
	}
}

// Test: Package that is only moderately stale (180-365 days) is not affected by feature-complete
// Justification: Feature-complete detection only applies to packages with staleness risk >= 2
//                (>365 days). Moderately stale packages already get a fair risk=1 score.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set last commit to 200 days ago (moderate staleness) with stable keywords.
//              Verify risk stays at 1 and feature-complete check is not triggered.
// Result: Risk points = 1 (from moderate staleness), no feature-complete adjustment needed.
func TestScorePackageMaturity_ModerateStaleNotAffectedByFeatureComplete(t *testing.T) {
	analyzer := NewAnalyzer()
	now := time.Now()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			RepoCreatedAt:   now.AddDate(-5, 0, 0),
			RepoLastCommit:  now.Add(-200 * 24 * time.Hour), // 200 days (moderate)
			RepoArchived:    false,
			RepoDescription: "A stable library",
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected risk points = 1 for moderately stale package, got %d", score.RiskPoints)
	}

	// Feature-complete detection should NOT be in checks (staleness was only 1, not 2)
	for _, check := range score.ChecksPerformed {
		if check.Name == "Feature-complete detection" {
			t.Error("Feature-complete detection should not trigger for moderate staleness (risk=1)")
		}
	}
}
