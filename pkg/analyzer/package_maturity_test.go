package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ===== Package Maturity Tests =====
//
// These tests validate that scorePackageMaturity correctly assesses supply chain
// compromise risk from package lifecycle signals: abandonment duration, deprecation
// notices, archived status, package age, staleness, and release cadence.

// Test: Package abandoned for 3+ years gets HIGH risk
// Justification: Packages with no activity for 3+ years are silently abandoned.
//                Maintainer accounts may be unmonitored, making them prime targets
//                for account takeover attacks. The longer the abandonment, the more
//                likely credentials have rotted or been compromised.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) §4.2 — account takeover
//         is the primary vector for compromising established packages.
//         "Small World with High Risks" (Zimmermann et al., 2019) — abandoned packages
//         remain in dependency trees indefinitely.
// Methodology: Set RepoLastCommit to >3 years ago, verify 2 risk points and "abandoned" evidence
// Result: 2 risk points (HIGH), description mentions abandonment
func TestScorePackageMaturity_AbandonedThreeYears(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/abandoned-pkg",
		Metadata: models.PackageMetadata{
			RepoCreatedAt:  time.Now().AddDate(-8, 0, 0),  // 8 years old
			RepoLastCommit: time.Now().AddDate(-4, 0, 0),  // 4 years since last commit
			Maintainers:    []string{"solo-dev"},
		},
		Dependency: models.Dependency{
			Name:      "abandoned-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for 3+ year abandoned package, got %d", score.RiskPoints)
	}

	if !strings.Contains(strings.ToLower(score.Description), "abandoned") {
		t.Errorf("Expected description to mention 'abandoned', got: %s", score.Description)
	}

	// Should be labelled as abandoned, not deprecated (the description may
	// reference "deprecated" for comparison purposes like "unlike deprecated",
	// but the primary label should be "abandoned")
	if !strings.Contains(strings.ToLower(score.Evidence), "abandoned") {
		t.Errorf("Abandoned package evidence should contain 'abandoned', got: %s", score.Evidence)
	}

	if !score.Verified {
		t.Error("Expected Verified=true when commit history is available")
	}

	// Check that abandonment detection check is present
	hasAbandonmentCheck := false
	for _, check := range score.ChecksPerformed {
		if check.Name == "Abandonment detection" && check.Status == "FAIL" {
			hasAbandonmentCheck = true
		}
	}
	if !hasAbandonmentCheck {
		t.Error("Expected an 'Abandonment detection' check with FAIL status")
	}
}

// Test: Package with 1.5 years of inactivity is stale but NOT abandoned
// Justification: Packages inactive for 1-3 years are stale but haven't crossed the
//                abandonment threshold. They still score HIGH risk for staleness but
//                should not be labelled as abandoned — some projects have legitimate
//                long maintenance cycles.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set RepoLastCommit to 1.5 years ago, verify staleness risk without abandonment label
// Result: 2 risk points (staleness), but no abandonment label
func TestScorePackageMaturity_StaleButNotAbandoned(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/stale-pkg",
		Metadata: models.PackageMetadata{
			RepoCreatedAt:  time.Now().AddDate(-5, 0, 0),  // 5 years old
			RepoLastCommit: time.Now().AddDate(-1, -6, 0), // 1.5 years since last commit
			Maintainers:    []string{"dev1", "dev2"},
		},
		Dependency: models.Dependency{
			Name:      "stale-pkg",
			Version:   "2.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for stale package (>1yr), got %d", score.RiskPoints)
	}

	// Should NOT be labelled as abandoned (under 3 years)
	if strings.Contains(strings.ToLower(score.Evidence), "abandoned") {
		t.Errorf("Package with 1.5 years inactivity should NOT be labelled abandoned, got evidence: %s", score.Evidence)
	}
}

// Test: Deprecated package detected from description keywords
// Justification: Packages whose description explicitly mentions "deprecated" have been
//                intentionally abandoned by their maintainers. This is a clear signal
//                that the package will not receive security patches. Deprecated packages
//                should be reported differently from silently abandoned ones — the
//                maintainer has explicitly warned users.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) — deprecated packages
//         that remain in dependency trees are attack vectors.
// Methodology: Set RepoDescription with deprecation keyword, verify early return with deprecation label
// Result: 2 risk points (HIGH), description mentions "deprecated" not "abandoned"
func TestScorePackageMaturity_DeprecatedPackage(t *testing.T) {
	analyzer := NewAnalyzer()

	testCases := []struct {
		name        string
		description string
		keyword     string
	}{
		{"deprecated keyword", "This package is deprecated. Use new-package instead.", "deprecated"},
		{"unmaintained keyword", "UNMAINTAINED - no longer receiving updates", "unmaintained"},
		{"archived keyword", "This project is archived and read-only", "archived"},
		{"end of life", "This library has reached end of life", "end of life"},
		{"no longer maintained", "WARNING: This package is no longer maintained", "no longer maintained"},
		{"moved to keyword", "This package has moved to @scope/new-name", "moved to"},
		{"superseded by", "Superseded by better-package", "superseded by"},
		{"replaced by", "This has been replaced by modern-lib", "replaced by"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: "https://github.com/test/deprecated-pkg",
				Metadata: models.PackageMetadata{
					RepoDescription: tc.description,
					RepoCreatedAt:   time.Now().AddDate(-5, 0, 0),
					RepoLastCommit:  time.Now().AddDate(-2, 0, 0),
					Maintainers:     []string{"dev1"},
				},
				Dependency: models.Dependency{
					Name:      "deprecated-pkg",
					Version:   "1.0.0",
					Ecosystem: models.EcosystemNPM,
				},
			}

			score := analyzer.scorePackageMaturity(result)

			if score.RiskPoints != 2 {
				t.Errorf("[%s] Expected 2 risk points for deprecated package, got %d", tc.name, score.RiskPoints)
			}

			if !strings.Contains(strings.ToLower(score.Description), "deprecated") {
				t.Errorf("[%s] Expected description to mention 'deprecated', got: %s", tc.name, score.Description)
			}

			if !strings.Contains(strings.ToLower(score.Evidence), tc.keyword) {
				t.Errorf("[%s] Expected evidence to contain keyword '%s', got: %s", tc.name, tc.keyword, score.Evidence)
			}

			if !score.Verified {
				t.Errorf("[%s] Expected Verified=true for deprecated package", tc.name)
			}
		})
	}
}

// Test: Non-deprecated description does not trigger false positive
// Justification: Descriptions that happen to contain words like "archive" in a
//                non-deprecation context (e.g., "archive utilities") should not
//                trigger false positives. Only clear deprecation signals should match.
// Source: Defensive testing against false positives
// Methodology: Set RepoDescription to normal descriptions, verify no deprecation detection
// Result: Should not return 2 risk points for deprecation
func TestScorePackageMaturity_NormalDescriptionNoFalsePositive(t *testing.T) {
	analyzer := NewAnalyzer()

	normalDescriptions := []string{
		"A fast, lightweight utility library for JavaScript",
		"HTTP client for making API requests",
		"Tools for data processing and transformation",
		"", // empty description
	}

	for _, desc := range normalDescriptions {
		result := &models.AnalysisResult{
			RepositoryURL: "https://github.com/test/normal-pkg",
			Metadata: models.PackageMetadata{
				RepoDescription: desc,
				RepoCreatedAt:   time.Now().AddDate(-3, 0, 0),
				RepoLastCommit:  time.Now().AddDate(0, -1, 0), // 1 month ago
				Maintainers:     []string{"dev1", "dev2"},
			},
			Dependency: models.Dependency{
				Name:      "normal-pkg",
				Version:   "3.0.0",
				Ecosystem: models.EcosystemNPM,
			},
		}

		score := analyzer.scorePackageMaturity(result)

		// Active, established packages should not get deprecation-level risk
		hasDeprecationCheck := false
		for _, check := range score.ChecksPerformed {
			if check.Name == "Deprecation detection" {
				hasDeprecationCheck = true
			}
		}
		if hasDeprecationCheck {
			t.Errorf("Normal description %q should not trigger deprecation detection", desc)
		}
	}
}

// Test: Archived repository gets HIGH risk in maturity
// Justification: Archived GitHub repositories are permanently read-only — no security
//                patches can be applied. The archived status is an explicit maintainer
//                signal that the project is end-of-life. This is similar to deprecation
//                but enforced at the platform level.
// Source: OSSF Scorecard Specification — archived repos score 0 across all checks.
//         "Backstabber's Knife Collection" (Ohm et al., 2020) — unmaintained packages
//         are prime targets for supply chain attacks.
// Methodology: Set RepoArchived=true, verify 2 risk points and archived evidence
// Result: 2 risk points (HIGH), description mentions "archived"
func TestScorePackageMaturity_ArchivedRepository(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/archived-pkg",
		Metadata: models.PackageMetadata{
			RepoArchived:   true,
			RepoCreatedAt:  time.Now().AddDate(-5, 0, 0),
			RepoLastCommit: time.Now().AddDate(-2, 0, 0),
			Maintainers:    []string{"dev1"},
		},
		Dependency: models.Dependency{
			Name:      "archived-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for archived repository, got %d", score.RiskPoints)
	}

	if !strings.Contains(strings.ToLower(score.Description), "archived") {
		t.Errorf("Expected description to mention 'archived', got: %s", score.Description)
	}

	if !score.Verified {
		t.Error("Expected Verified=true for archived repository")
	}

	// Check that archived check is present
	hasArchivedCheck := false
	for _, check := range score.ChecksPerformed {
		if check.Name == "Archived status" && check.Status == "FAIL" {
			hasArchivedCheck = true
		}
	}
	if !hasArchivedCheck {
		t.Error("Expected an 'Archived status' check with FAIL status")
	}
}

// Test: Deprecation takes priority over archived status
// Justification: When both deprecation notice and archived status are present,
//                the deprecation notice should take priority because it provides
//                more specific context (e.g., which replacement package to use).
// Source: Defense in depth — prefer the more informative signal
// Methodology: Set both RepoDescription with deprecation keyword AND RepoArchived=true
// Result: 2 risk points, description mentions deprecated (not just archived)
func TestScorePackageMaturity_DeprecationPriorityOverArchived(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/both-pkg",
		Metadata: models.PackageMetadata{
			RepoDescription: "DEPRECATED: Use new-package instead",
			RepoArchived:    true,
			RepoCreatedAt:   time.Now().AddDate(-5, 0, 0),
			RepoLastCommit:  time.Now().AddDate(-3, 0, 0),
			Maintainers:     []string{"dev1"},
		},
		Dependency: models.Dependency{
			Name:      "both-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points, got %d", score.RiskPoints)
	}

	// Should mention deprecated, since that's the more specific signal
	if !strings.Contains(strings.ToLower(score.Description), "deprecated") {
		t.Errorf("Expected description to mention 'deprecated' when both deprecated and archived, got: %s", score.Description)
	}
}

// Test: Actively maintained package with recent commits scores LOW risk
// Justification: Packages with recent activity, established age, and active
//                maintenance indicate healthy projects with low compromise risk.
//                The maintainer is actively watching for issues.
// Source: "Small World with High Risks" (Zimmermann et al., 2019) — active
//         projects with multiple maintainers have lowest compromise probability.
// Methodology: Set RepoLastCommit to recent, RepoCreatedAt to >2 years, verify 0 risk points
// Result: 0 risk points (LOW), no abandonment or deprecation signals
func TestScorePackageMaturity_ActivePackageLowRisk(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/active-pkg",
		Metadata: models.PackageMetadata{
			RepoCreatedAt:  time.Now().AddDate(-5, 0, 0),
			RepoLastCommit: time.Now().AddDate(0, 0, -14), // 2 weeks ago
			Maintainers:    []string{"dev1", "dev2", "dev3"},
		},
		Dependency: models.Dependency{
			Name:      "active-pkg",
			Version:   "5.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for actively maintained package, got %d", score.RiskPoints)
	}

	// Should not mention abandoned or deprecated
	descLower := strings.ToLower(score.Description)
	if strings.Contains(descLower, "abandoned") {
		t.Errorf("Active package should not mention 'abandoned', got: %s", score.Description)
	}
	if strings.Contains(descLower, "deprecated") {
		t.Errorf("Active package should not mention 'deprecated', got: %s", score.Description)
	}
}

// Test: Abandoned package via registry fallback (no commit data)
// Justification: When commit data is unavailable but registry update timestamps
//                show 3+ years of inactivity, the package should still be detected
//                as abandoned. This handles cases where repository access fails but
//                registry data is available.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set RepoUpdatedAt to >3 years ago with no RepoLastCommit, verify abandonment
// Result: 2 risk points (HIGH), abandonment detected via registry fallback
func TestScorePackageMaturity_AbandonedViaRegistryFallback(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/registry-abandoned",
		Metadata: models.PackageMetadata{
			RepoCreatedAt: time.Now().AddDate(-6, 0, 0),
			RepoUpdatedAt: time.Now().AddDate(-4, 0, 0), // 4 years since registry update
			Maintainers:   []string{"dev1"},
		},
		Dependency: models.Dependency{
			Name:      "registry-abandoned",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for registry-abandoned package, got %d", score.RiskPoints)
	}

	if !strings.Contains(strings.ToUpper(score.Evidence), "ABANDONED") {
		t.Errorf("Expected evidence to contain 'ABANDONED' for 3+ year inactive package, got: %s", score.Evidence)
	}

	// Check that abandonment detection check is present
	hasAbandonmentCheck := false
	for _, check := range score.ChecksPerformed {
		if check.Name == "Abandonment detection" && check.Status == "FAIL" {
			hasAbandonmentCheck = true
		}
	}
	if !hasAbandonmentCheck {
		t.Error("Expected an 'Abandonment detection' check with FAIL status for registry fallback")
	}
}

// Test: Deprecated vs abandoned distinction in descriptions
// Justification: Users need to distinguish between packages that have been explicitly
//                deprecated (maintainer communicated end-of-life) and packages that
//                have been silently abandoned (no maintainer communication). The risk
//                is similar (2 points) but the context and recommended action differ.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Compare descriptions of deprecated vs abandoned packages
// Result: Both get 2 risk points but with distinct descriptions
func TestScorePackageMaturity_DeprecatedVsAbandonedDistinction(t *testing.T) {
	analyzer := NewAnalyzer()

	// Deprecated package
	deprecatedResult := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/deprecated",
		Metadata: models.PackageMetadata{
			RepoDescription: "DEPRECATED - use better-lib instead",
			RepoCreatedAt:   time.Now().AddDate(-5, 0, 0),
			RepoLastCommit:  time.Now().AddDate(-2, 0, 0),
		},
		Dependency: models.Dependency{Name: "deprecated", Ecosystem: models.EcosystemNPM},
	}

	// Abandoned package (no deprecation notice)
	abandonedResult := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/abandoned",
		Metadata: models.PackageMetadata{
			RepoCreatedAt:  time.Now().AddDate(-8, 0, 0),
			RepoLastCommit: time.Now().AddDate(-4, 0, 0), // 4 years
		},
		Dependency: models.Dependency{Name: "abandoned", Ecosystem: models.EcosystemNPM},
	}

	deprecatedScore := analyzer.scorePackageMaturity(deprecatedResult)
	abandonedScore := analyzer.scorePackageMaturity(abandonedResult)

	// Both should get maximum risk
	if deprecatedScore.RiskPoints != 2 {
		t.Errorf("Deprecated package: expected 2 risk points, got %d", deprecatedScore.RiskPoints)
	}
	if abandonedScore.RiskPoints != 2 {
		t.Errorf("Abandoned package: expected 2 risk points, got %d", abandonedScore.RiskPoints)
	}

	// Descriptions should be distinct
	deprecatedDesc := strings.ToLower(deprecatedScore.Description)
	abandonedDesc := strings.ToLower(abandonedScore.Description)

	if !strings.Contains(deprecatedDesc, "deprecated") {
		t.Errorf("Deprecated package description should mention 'deprecated', got: %s", deprecatedScore.Description)
	}
	if !strings.Contains(abandonedDesc, "abandoned") {
		t.Errorf("Abandoned package description should mention 'abandoned', got: %s", abandonedScore.Description)
	}

	// Deprecated description should mention "explicit signal"
	if !strings.Contains(deprecatedDesc, "explicit") {
		t.Errorf("Deprecated description should mention 'explicit signal', got: %s", deprecatedScore.Description)
	}

	// Abandoned description should mention "silently"
	if !strings.Contains(abandonedDesc, "silently") {
		t.Errorf("Abandoned description should mention 'silently', got: %s", abandonedScore.Description)
	}
}

// Test: detectDeprecation function directly
// Justification: Unit test the deprecation detection logic to ensure all keywords
//                are properly matched case-insensitively and that empty/normal
//                descriptions return no signal.
// Source: Defensive unit testing
// Methodology: Call detectDeprecation with various descriptions
// Result: Correct keyword detection across all variants
func TestDetectDeprecation(t *testing.T) {
	testCases := []struct {
		name        string
		description string
		shouldMatch bool
		keyword     string
	}{
		{"deprecated lowercase", "this package is deprecated", true, "deprecated"},
		{"deprecated mixed case", "DEPRECATED: use something else", true, "deprecated"},
		{"unmaintained", "This project is unmaintained", true, "unmaintained"},
		{"archived in description", "This project is archived", true, "archived"},
		{"end of life", "Reached end of life in 2023", true, "end of life"},
		{"end-of-life hyphenated", "This is end-of-life software", true, "end-of-life"},
		{"no longer maintained", "No longer maintained by the original author", true, "no longer maintained"},
		{"no longer supported", "no longer supported as of v5", true, "no longer supported"},
		{"moved to", "This package has moved to @scope/new-pkg", true, "moved to"},
		{"superseded by", "Superseded by modern-alternative", true, "superseded by"},
		{"replaced by", "This library has been replaced by new-lib", true, "replaced by"},
		{"normal description", "A fast HTTP client library", false, ""},
		{"empty description", "", false, ""},
		{"contains archive word normally", "File archive utility tools", false, ""}, // "archive" does not match "archived" — correctly avoids false positive
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				Metadata: models.PackageMetadata{
					RepoDescription: tc.description,
				},
			}

			signal := detectDeprecation(result)

			if tc.shouldMatch && signal == "" {
				t.Errorf("Expected deprecation signal for description %q, got empty string", tc.description)
			}
			if !tc.shouldMatch && signal != "" {
				t.Errorf("Expected no deprecation signal for description %q, got: %s", tc.description, signal)
			}
			if tc.shouldMatch && tc.keyword != "" && !strings.Contains(strings.ToLower(signal), tc.keyword) {
				t.Errorf("Expected signal to contain keyword %q, got: %s", tc.keyword, signal)
			}
		})
	}
}

// Test: truncateString helper function
// Justification: Ensures description truncation works correctly for evidence display
// Source: Utility function testing
// Methodology: Test short, exact-length, and long strings
// Result: Correct truncation behavior
func TestTruncateString(t *testing.T) {
	if result := truncateString("short", 10); result != "short" {
		t.Errorf("Short string should not be truncated, got: %s", result)
	}

	if result := truncateString("exact len!", 10); result != "exact len!" {
		t.Errorf("Exact length string should not be truncated, got: %s", result)
	}

	if result := truncateString("this is a longer string that should be truncated", 10); result != "this is a ..." {
		t.Errorf("Long string should be truncated to 10 chars + ..., got: %s", result)
	}
}

// Test: Package maturity methodology includes abandonment and deprecation checks
// Justification: The methodology string should document all checks performed,
//                including the new abandonment duration and deprecation detection checks.
// Source: Evidence trail requirement from CLAUDE.md
// Methodology: Verify methodology string contains expected check descriptions
// Result: Methodology mentions abandonment, deprecation, and archived status
func TestScorePackageMaturity_MethodologyDocumented(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/any-pkg",
		Metadata: models.PackageMetadata{
			RepoCreatedAt:  time.Now().AddDate(-3, 0, 0),
			RepoLastCommit: time.Now().AddDate(0, -1, 0),
			Maintainers:    []string{"dev1"},
		},
		Dependency: models.Dependency{
			Name:      "any-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	methodology := strings.ToLower(score.Methodology)
	expectedTerms := []string{"abandonment", "deprecation", "archived", "staleness", "cadence"}
	for _, term := range expectedTerms {
		if !strings.Contains(methodology, term) {
			t.Errorf("Methodology should mention '%s', got: %s", term, score.Methodology)
		}
	}
}
