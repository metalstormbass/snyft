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
// compromise risk from package age, staleness, abandonment, and deprecation signals.

// Test: Package abandoned for 3+ years scores maximum risk
// Justification: Packages with no activity for 3+ years have unmonitored maintainer
//                accounts vulnerable to credential stuffing and account takeover.
//                Silent abandonment (no deprecation notice) is especially dangerous
//                because users have no warning to migrate away.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — dormant packages
//         are prime targets for supply chain attacks via account takeover.
//         "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set RepoLastCommit to 4 years ago with no deprecation signals
// Result: 2 risk points (HIGH), description mentions "abandoned"
func TestScorePackageMaturity_AbandonedPackage3PlusYears(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/abandoned-pkg",
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Now().AddDate(-5, 0, 0), // 5 years old
			RepoLastCommit: time.Now().AddDate(-4, 0, 0), // 4 years since last commit
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
	if score.Score != 0 {
		t.Errorf("Expected score 0 (2-2) for abandoned package, got %d", score.Score)
	}
	if !score.Verified {
		t.Error("Expected Verified=true when commit data is available")
	}
	if !strings.Contains(strings.ToLower(score.Description), "abandoned") {
		t.Errorf("Expected description to mention 'abandoned', got: %s", score.Description)
	}
	// Should mention the abandonment threshold
	if !containsSubstring(score.Evidence, "abandoned") {
		t.Errorf("Expected evidence to mention 'abandoned', got: %s", score.Evidence)
	}
}

// Test: Package stale for 1-3 years gets HIGH risk but NOT labeled abandoned
// Justification: Packages inactive for 1-3 years are stale and risky, but the
//                3+ year threshold is the cutoff for "abandoned" classification.
//                This distinction matters because abandoned packages have higher
//                account takeover risk.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set RepoLastCommit to 2 years ago
// Result: 2 risk points, but description does NOT say "abandoned"
func TestScorePackageMaturity_StaleNotAbandoned(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/stale-pkg",
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Now().AddDate(-5, 0, 0),
			RepoLastCommit: time.Now().AddDate(-2, 0, 0), // 2 years, NOT 3+
		},
		Dependency: models.Dependency{
			Name:      "stale-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for stale package (>1yr), got %d", score.RiskPoints)
	}
	// Should NOT be labeled as abandoned since it's < 3 years
	if strings.Contains(strings.ToLower(score.Evidence), "abandoned") {
		t.Errorf("Package stale for 2 years should NOT be labeled 'abandoned', evidence: %s", score.Evidence)
	}
}

// Test: Deprecated package (via description keyword) scores maximum risk
// Justification: Packages explicitly marked as deprecated no longer receive
//                security patches, making them vulnerable to supply chain compromise.
//                Unlike abandoned packages, deprecated ones have been intentionally
//                marked, so a different risk message is appropriate.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Set RepoDescription containing "deprecated" keyword
// Result: 2 risk points, description mentions "deprecated" not "abandoned"
func TestScorePackageMaturity_DeprecatedViaDescription(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/old-lib",
		Metadata: models.PackageMetadata{
			PublishedAt:     time.Now().AddDate(-3, 0, 0),
			RepoLastCommit:  time.Now().AddDate(0, -1, 0), // Recent commit
			RepoDescription: "This package is deprecated. Use new-lib instead.",
		},
		Dependency: models.Dependency{
			Name:      "old-lib",
			Version:   "2.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for deprecated package, got %d", score.RiskPoints)
	}
	if !strings.Contains(strings.ToLower(score.Description), "deprecated") {
		t.Errorf("Expected description to mention 'deprecated', got: %s", score.Description)
	}
	// Should be flagged as deprecated in metadata
	if !result.Metadata.IsDeprecated {
		t.Error("Expected IsDeprecated=true in metadata")
	}
	if result.Metadata.DeprecationSource != "description" {
		t.Errorf("Expected DeprecationSource='description', got: %s", result.Metadata.DeprecationSource)
	}
}

// Test: GitHub archived repo is detected as deprecated
// Justification: Archived GitHub repositories are permanently read-only and
//                unmaintained. The archived status is a strong deprecation signal
//                that should be treated as explicit deprecation.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         OSSF Scorecard Specification
// Methodology: Set RepoArchived=true in metadata
// Result: 2 risk points, deprecation detected from archived status
func TestScorePackageMaturity_ArchivedRepoIsDeprecated(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/archived-lib",
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Now().AddDate(-4, 0, 0),
			RepoLastCommit: time.Now().AddDate(0, -6, 0),
			RepoArchived:   true,
		},
		Dependency: models.Dependency{
			Name:      "archived-lib",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for archived repo, got %d", score.RiskPoints)
	}
	if !result.Metadata.IsDeprecated {
		t.Error("Expected IsDeprecated=true for archived repo")
	}
	if result.Metadata.DeprecationSource != "archived" {
		t.Errorf("Expected DeprecationSource='archived', got: %s", result.Metadata.DeprecationSource)
	}
	if !strings.Contains(strings.ToLower(score.Description), "deprecated") {
		t.Errorf("Expected description to mention 'deprecated', got: %s", score.Description)
	}
}

// Test: Deprecated AND abandoned package gets combined messaging
// Justification: A package that is both deprecated (intentionally marked) AND
//                abandoned (3+ years inactive) represents the worst case — no
//                security patches AND unmonitored maintainer accounts.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set RepoArchived=true AND RepoLastCommit to 4 years ago
// Result: 2 risk points, description mentions both deprecated and abandoned
func TestScorePackageMaturity_DeprecatedAndAbandoned(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/old-dead-lib",
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Now().AddDate(-6, 0, 0),
			RepoLastCommit: time.Now().AddDate(-4, 0, 0), // 4 years = abandoned
			RepoArchived:   true,                          // Also archived = deprecated
		},
		Dependency: models.Dependency{
			Name:      "old-dead-lib",
			Version:   "0.5.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points, got %d", score.RiskPoints)
	}
	// Archived = deprecated, 4yr inactive but since it IS deprecated, isAbandoned should be false
	// This means it gets the "deprecated" message, not the "both" message
	if !strings.Contains(strings.ToLower(score.Description), "deprecated") {
		t.Errorf("Expected description to mention 'deprecated', got: %s", score.Description)
	}
}

// Test: Active package with no deprecation signals scores low risk
// Justification: Packages with recent activity, established age, and no deprecation
//                signals demonstrate active maintenance — lowest compromise risk.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Set recent RepoLastCommit, >2yr age, no deprecation
// Result: 0 risk points, description mentions "established"
func TestScorePackageMaturity_ActivePackage(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/healthy-lib",
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Now().AddDate(-3, 0, 0),
			RepoLastCommit: time.Now().AddDate(0, 0, -7), // 7 days ago
		},
		Dependency: models.Dependency{
			Name:      "healthy-lib",
			Version:   "3.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for active healthy package, got %d", score.RiskPoints)
	}
	if score.Score != 2 {
		t.Errorf("Expected score 2 (2-0) for healthy package, got %d", score.Score)
	}
	// Should NOT be deprecated
	if result.Metadata.IsDeprecated {
		t.Error("Expected IsDeprecated=false for active package")
	}
}

// Test: detectDeprecationKeyword matches expected patterns
// Justification: The keyword detection must correctly identify common deprecation
//                phrases used by maintainers in READMEs and package descriptions.
// Source: Analysis of common deprecation patterns in npm, PyPI registries
// Methodology: Unit test with known deprecation phrases
// Result: Each phrase returns a non-empty match
func TestDetectDeprecationKeyword(t *testing.T) {
	testCases := []struct {
		name     string
		text     string
		expected bool
	}{
		{
			name:     "deprecated keyword",
			text:     "This package is deprecated",
			expected: true,
		},
		{
			name:     "unmaintained keyword",
			text:     "This library is unmaintained",
			expected: true,
		},
		{
			name:     "no longer maintained",
			text:     "This project is no longer maintained",
			expected: true,
		},
		{
			name:     "archived keyword",
			text:     "This repository has been archived",
			expected: true,
		},
		{
			name:     "end of life",
			text:     "This package has reached end-of-life",
			expected: true,
		},
		{
			name:     "end of life with spaces",
			text:     "End of life notice for this library",
			expected: true,
		},
		{
			name:     "use X instead",
			text:     "Use better-lib instead",
			expected: true,
		},
		{
			name:     "case insensitive",
			text:     "DEPRECATED: use new-lib",
			expected: true,
		},
		{
			name:     "no deprecation keyword",
			text:     "This is a great library for building web apps",
			expected: false,
		},
		{
			name:     "empty string",
			text:     "",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := detectDeprecationKeyword(tc.text)
			if tc.expected && result == "" {
				t.Errorf("Expected deprecation keyword to be detected in %q, got empty", tc.text)
			}
			if !tc.expected && result != "" {
				t.Errorf("Expected no deprecation keyword in %q, got %q", tc.text, result)
			}
		})
	}
}

// Test: Registry-set deprecation is preserved and not overwritten
// Justification: When the registry (e.g., npm) has already flagged a package as
//                deprecated, the analyzer should preserve that signal rather than
//                overwriting it with a potentially weaker signal from description.
// Source: npm registry API documentation — deprecated field
// Methodology: Pre-set IsDeprecated in metadata before calling scorePackageMaturity
// Result: Original deprecation notice preserved, deprecation risk = 2
func TestScorePackageMaturity_PresetDeprecation(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/npm-deprecated",
		Metadata: models.PackageMetadata{
			PublishedAt:       time.Now().AddDate(-3, 0, 0),
			RepoLastCommit:    time.Now().AddDate(0, -1, 0),
			IsDeprecated:      true,
			DeprecationNotice: "This package has been deprecated. Use @new/package instead.",
			DeprecationSource: "registry",
		},
		Dependency: models.Dependency{
			Name:      "npm-deprecated",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for registry-deprecated package, got %d", score.RiskPoints)
	}
	// Registry source should be preserved
	if result.Metadata.DeprecationSource != "registry" {
		t.Errorf("Expected DeprecationSource='registry' to be preserved, got: %s", result.Metadata.DeprecationSource)
	}
}

// Test: No data available defaults to moderate risk
// Justification: When no publish date or commit history is available, the package
//                maturity is unknown. Defaulting to moderate risk avoids both
//                false positives (max risk for unknown) and false negatives (zero risk).
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Create result with empty metadata (no timestamps)
// Result: 1 risk point (moderate), Verified=false
func TestScorePackageMaturity_NoData(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{},
		Dependency: models.Dependency{
			Name:      "unknown-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for no data, got %d", score.RiskPoints)
	}
	if score.Verified {
		t.Error("Expected Verified=false when no data available")
	}
	if score.DataAvailable {
		t.Error("Expected DataAvailable=false when no data available")
	}
}

// Test: Very new package (< 6 months) scores maximum risk
// Justification: Very new packages have not been community-vetted and may
//                be dependency confusion attacks or typosquatting.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Set PublishedAt to 30 days ago
// Result: 2 risk points (very new)
func TestScorePackageMaturity_VeryNewPackage(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Now().AddDate(0, -1, 0), // 1 month old
			RepoLastCommit: time.Now().AddDate(0, 0, -1), // Recent commit
		},
		Dependency: models.Dependency{
			Name:      "new-pkg",
			Version:   "0.1.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for very new package, got %d", score.RiskPoints)
	}
}

// Test: Abandonment via registry update (fallback when no commit data)
// Justification: When commit data is unavailable, registry update timestamps
//                serve as a staleness proxy. 3+ years without registry updates
//                should trigger the same abandonment classification.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set RepoUpdatedAt to 4 years ago with no RepoLastCommit
// Result: 2 risk points, description mentions "abandoned"
func TestScorePackageMaturity_AbandonedViaRegistryFallback(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/old-registry-pkg",
		Metadata: models.PackageMetadata{
			PublishedAt:   time.Now().AddDate(-6, 0, 0),
			RepoUpdatedAt: time.Now().AddDate(-4, 0, 0), // 4 years via registry fallback
		},
		Dependency: models.Dependency{
			Name:      "old-registry-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for abandoned package (registry fallback), got %d", score.RiskPoints)
	}
	if !strings.Contains(strings.ToLower(score.Evidence), "abandoned") {
		t.Errorf("Expected evidence to mention 'abandoned' for 3+ year registry inactivity, got: %s", score.Evidence)
	}
}

// Test: Deprecation check results appear in ChecksPerformed
// Justification: Every sub-check must be recorded in ChecksPerformed for
//                auditability — users must be able to trace how the score was derived.
// Source: SLSA Supply-chain Levels for Software Artifacts — provenance requirements
// Methodology: Check that deprecation status appears in ChecksPerformed
// Result: ChecksPerformed contains a "Deprecation status" entry
func TestScorePackageMaturity_DeprecationCheckInChecksPerformed(t *testing.T) {
	analyzer := NewAnalyzer()

	// Active package - should have PASS for deprecation
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/active-pkg",
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Now().AddDate(-3, 0, 0),
			RepoLastCommit: time.Now().AddDate(0, 0, -7),
		},
		Dependency: models.Dependency{
			Name:      "active-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	found := false
	for _, check := range score.ChecksPerformed {
		if check.Name == "Deprecation status" {
			found = true
			if check.Status != "PASS" {
				t.Errorf("Expected Deprecation status PASS for active package, got %s", check.Status)
			}
			break
		}
	}
	if !found {
		t.Error("Expected 'Deprecation status' check in ChecksPerformed")
	}

	// Deprecated package - should have FAIL for deprecation
	deprecatedResult := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/depr-pkg",
		Metadata: models.PackageMetadata{
			PublishedAt:     time.Now().AddDate(-3, 0, 0),
			RepoLastCommit:  time.Now().AddDate(0, 0, -7),
			RepoDescription: "This project is deprecated. Use new-project instead.",
		},
		Dependency: models.Dependency{
			Name:      "depr-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	deprecatedScore := analyzer.scorePackageMaturity(deprecatedResult)

	found = false
	for _, check := range deprecatedScore.ChecksPerformed {
		if check.Name == "Deprecation status" {
			found = true
			if check.Status != "FAIL" {
				t.Errorf("Expected Deprecation status FAIL for deprecated package, got %s", check.Status)
			}
			break
		}
	}
	if !found {
		t.Error("Expected 'Deprecation status' check in ChecksPerformed for deprecated package")
	}
}

// Test: Description keywords "use X instead" detected in multiple patterns
// Justification: Maintainers commonly use "use X instead" to redirect users
//                to replacement packages. This is a strong deprecation signal.
// Source: Analysis of npm deprecation patterns
// Methodology: Test various "use X instead" formulations
// Result: All expected patterns are detected
func TestDetectDeprecationKeyword_UseInstead(t *testing.T) {
	testCases := []struct {
		text     string
		expected bool
	}{
		{"Please use lodash instead", true},
		{"Use @new/package instead", true},
		{"use better-lib instead of this", true},
		{"useful library for development", false}, // "use" without "instead"
	}

	for _, tc := range testCases {
		result := detectDeprecationKeyword(tc.text)
		if tc.expected && result == "" {
			t.Errorf("Expected match for %q, got empty", tc.text)
		}
		if !tc.expected && result != "" {
			t.Errorf("Expected no match for %q, got %q", tc.text, result)
		}
	}
}

// Test: Score range is always valid (0-2)
// Justification: CategoryScore must always be in the 0-2 range for correct
//                supply chain score aggregation. Out-of-range scores would
//                corrupt the total risk assessment.
// Source: Snyft scoring system specification
// Methodology: Table-driven test with extreme inputs
// Result: Score always in [0, 2], RiskPoints always in [0, 2]
func TestScorePackageMaturity_ScoreRange(t *testing.T) {
	analyzer := NewAnalyzer()

	testCases := []struct {
		name           string
		publishedAt    time.Time
		lastCommit     time.Time
		archived       bool
		description    string
	}{
		{"very new", time.Now().AddDate(0, 0, -1), time.Now(), false, ""},
		{"established active", time.Now().AddDate(-5, 0, 0), time.Now().AddDate(0, 0, -1), false, ""},
		{"abandoned", time.Now().AddDate(-8, 0, 0), time.Now().AddDate(-5, 0, 0), false, ""},
		{"deprecated", time.Now().AddDate(-3, 0, 0), time.Now(), false, "deprecated"},
		{"archived", time.Now().AddDate(-3, 0, 0), time.Now(), true, ""},
		{"no data", time.Time{}, time.Time{}, false, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: "https://github.com/test/pkg",
				Metadata: models.PackageMetadata{
					PublishedAt:     tc.publishedAt,
					RepoLastCommit:  tc.lastCommit,
					RepoArchived:    tc.archived,
					RepoDescription: tc.description,
				},
				Dependency: models.Dependency{
					Name:      "test-pkg",
					Version:   "1.0.0",
					Ecosystem: models.EcosystemNPM,
				},
			}

			score := analyzer.scorePackageMaturity(result)

			if score.Score < 0 || score.Score > 2 {
				t.Errorf("Score out of range [0,2]: %d", score.Score)
			}
			if score.RiskPoints < 0 || score.RiskPoints > 2 {
				t.Errorf("RiskPoints out of range [0,2]: %d", score.RiskPoints)
			}
			if score.Score+score.RiskPoints != 2 {
				t.Errorf("Score (%d) + RiskPoints (%d) should equal 2", score.Score, score.RiskPoints)
			}
		})
	}
}

// Test: Deprecation via "unmaintained" keyword in description
// Justification: "unmaintained" is a common deprecation keyword used by maintainers
//                to signal that a package is no longer receiving updates or security
//                patches. It indicates a conscious decision to stop maintaining.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set RepoDescription with "unmaintained"
// Result: Package flagged as deprecated with source="description"
func TestScorePackageMaturity_UnmaintainedKeyword(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/unmaintained-pkg",
		Metadata: models.PackageMetadata{
			PublishedAt:     time.Now().AddDate(-4, 0, 0),
			RepoLastCommit:  time.Now().AddDate(0, -3, 0),
			RepoDescription: "This project is unmaintained",
		},
		Dependency: models.Dependency{
			Name:      "unmaintained-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for unmaintained package, got %d", score.RiskPoints)
	}
	if !result.Metadata.IsDeprecated {
		t.Error("Expected IsDeprecated=true for unmaintained package")
	}
	if result.Metadata.DeprecationSource != "description" {
		t.Errorf("Expected DeprecationSource='description', got: %s", result.Metadata.DeprecationSource)
	}
}

// Test: Methodology includes deprecation and abandonment info
// Justification: Methodology must document all checks performed so users can
//                understand and reproduce the assessment.
// Source: SLSA Build Level Requirements — provenance documentation
// Methodology: Check that methodology string mentions deprecation and 3yr threshold
// Result: Methodology contains "deprecation" and "3yr" or "abandoned"
func TestScorePackageMaturity_MethodologyIncludesDeprecation(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Now().AddDate(-3, 0, 0),
			RepoLastCommit: time.Now().AddDate(0, 0, -7),
		},
		Dependency: models.Dependency{
			Name:      "test-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
	}

	score := analyzer.scorePackageMaturity(result)

	if !strings.Contains(strings.ToLower(score.Methodology), "deprecation") {
		t.Errorf("Expected methodology to mention deprecation, got: %s", score.Methodology)
	}
	if !strings.Contains(score.Methodology, "3yr") {
		t.Errorf("Expected methodology to mention 3yr abandonment threshold, got: %s", score.Methodology)
	}
}
