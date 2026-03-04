package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// mustParseTime parses an RFC3339 time string, panicking on error.
// Used only in tests to construct time values for AnalysisResult fields.
func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic("mustParseTime: " + err.Error())
	}
	return t
}

// ===== Release Documentation Tests =====
// Category: Release Documentation Analysis
// Purpose: Verify that release/contributing documentation is correctly parsed for
//          supply chain risk signals (multi-approval, CI/CD automation, checklists)

// Test: Parse content with multi-approval requirement
// Justification: Projects requiring multiple approvals for releases create a barrier
//                that an attacker must bypass beyond just compromising one account.
//                This significantly reduces the risk of a single-point-of-compromise.
// Source: SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
//         "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Parse CONTRIBUTING.md content for multi-approval keyword patterns
// Result: HasMultiApprovalRequirement should be true
func TestParseReleaseDocContent_MultiApproval(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "two approvals",
			content: "Releases require two approvals from core maintainers before merging.",
			want:    true,
		},
		{
			name:    "2 approvals",
			content: "All PRs need 2 approvals before being merged.",
			want:    true,
		},
		{
			name:    "requires approval from",
			content: "The release process requires approval from at least two team leads.",
			want:    true,
		},
		{
			name:    "LGTM from",
			content: "Need LGTM from two reviewers to merge.",
			want:    true,
		},
		{
			name:    "no multi-approval",
			content: "Just push to main and the release will be created automatically.",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := &models.ReleaseDocumentation{}
			parseReleaseDocContent(tt.content, "CONTRIBUTING.md", docs)
			if docs.HasMultiApprovalRequirement != tt.want {
				t.Errorf("HasMultiApprovalRequirement = %v, want %v", docs.HasMultiApprovalRequirement, tt.want)
			}
		})
	}
}

// Test: Parse content with release checklist
// Justification: A structured release checklist indicates a formalized process
//                that is harder to subvert than ad-hoc publishing. It forces
//                maintainers to follow steps that may include security checks.
// Source: SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
// Methodology: Parse RELEASING.md content for checklist keyword patterns
// Result: HasReleaseChecklist should be true
func TestParseReleaseDocContent_Checklist(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "markdown checkbox",
			content: "## Release checklist\n- [ ] Update version\n- [ ] Run tests\n- [ ] Create tag",
			want:    true,
		},
		{
			name:    "completed checkbox",
			content: "- [x] Version bumped\n- [x] Changelog updated",
			want:    true,
		},
		{
			name:    "release process keyword",
			content: "# Release Process\n\nFollow these steps to create a new release.",
			want:    true,
		},
		{
			name:    "how to release",
			content: "## How to release\n\n1. Update the version\n2. Push a tag",
			want:    true,
		},
		{
			name:    "cutting a release",
			content: "## Cutting a release\n\nWhen it's time to release...",
			want:    true,
		},
		{
			name:    "no checklist",
			content: "This project welcomes contributions! Please fork and submit a PR.",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := &models.ReleaseDocumentation{}
			parseReleaseDocContent(tt.content, "RELEASING.md", docs)
			if docs.HasReleaseChecklist != tt.want {
				t.Errorf("HasReleaseChecklist = %v, want %v", docs.HasReleaseChecklist, tt.want)
			}
		})
	}
}

// Test: Parse content with automated release process
// Justification: CI/CD-automated releases remove humans from the publish path,
//                preventing local machine compromise from affecting published artifacts.
//                This is the highest-quality release security signal.
// Source: SLSA Build Level 2+ requires automated build process
//         https://slsa.dev/spec/v1.0/levels
// Methodology: Parse RELEASING.md content for CI/CD automation keyword patterns
// Result: HasAutomatedReleaseProcess should be true
func TestParseReleaseDocContent_AutomatedRelease(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "github actions",
			content: "Releases are handled by GitHub Actions when a tag is pushed.",
			want:    true,
		},
		{
			name:    "ci/cd pipeline",
			content: "Our CI/CD pipeline automatically publishes to npm on tagged commits.",
			want:    true,
		},
		{
			name:    "semantic-release",
			content: "We use semantic-release for automated versioning and publishing.",
			want:    true,
		},
		{
			name:    "goreleaser",
			content: "GoReleaser handles cross-compilation and publishing.",
			want:    true,
		},
		{
			name:    "release-please",
			content: "Release-please creates release PRs automatically.",
			want:    true,
		},
		{
			name:    "continuous delivery",
			content: "We practice continuous delivery with automated releases.",
			want:    true,
		},
		{
			name:    "no automation mentioned",
			content: "To release, run `npm publish` from your local machine.",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := &models.ReleaseDocumentation{}
			parseReleaseDocContent(tt.content, "RELEASING.md", docs)
			if docs.HasAutomatedReleaseProcess != tt.want {
				t.Errorf("HasAutomatedReleaseProcess = %v, want %v", docs.HasAutomatedReleaseProcess, tt.want)
			}
		})
	}
}

// Test: Parse content with release manager role
// Justification: A designated release manager indicates the project has assigned
//                accountability for the release process, making unauthorized releases
//                more detectable.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Parse CONTRIBUTING.md content for release manager role patterns
// Result: HasReleaseManagerRole should be true
func TestParseReleaseDocContent_ReleaseManager(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "release manager",
			content: "The release manager is responsible for cutting new releases.",
			want:    true,
		},
		{
			name:    "release captain",
			content: "A release captain is designated for each release cycle.",
			want:    true,
		},
		{
			name:    "release shepherd",
			content: "The release shepherd guides the release through the process.",
			want:    true,
		},
		{
			name:    "no manager role",
			content: "Anyone can make a release by pushing a tag.",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := &models.ReleaseDocumentation{}
			parseReleaseDocContent(tt.content, "CONTRIBUTING.md", docs)
			if docs.HasReleaseManagerRole != tt.want {
				t.Errorf("HasReleaseManagerRole = %v, want %v", docs.HasReleaseManagerRole, tt.want)
			}
		})
	}
}

// Test: Multiple signals from a single document
// Justification: A comprehensive release document that covers multiple controls
//                (CI automation, checklist, multi-approval) indicates a well-governed
//                project with multiple barriers to supply chain compromise.
// Source: SLSA Build Level Requirements; OSSF Scorecard
// Methodology: Parse a realistic RELEASING.md with multiple control signals
// Result: Multiple signal fields should be true
func TestParseReleaseDocContent_MultipleSignals(t *testing.T) {
	content := `# Release Process

## Prerequisites
- [ ] All tests pass on CI
- [ ] Changelog updated
- [ ] Version bumped

## Steps
1. Create a release PR
2. Get LGTM from at least two maintainers
3. The release manager merges the PR
4. GitHub Actions will automatically create the release and publish to npm

## Release Manager
The release manager for each cycle is designated in the team calendar.
`
	docs := &models.ReleaseDocumentation{}
	parseReleaseDocContent(content, "RELEASING.md", docs)

	if !docs.HasReleaseChecklist {
		t.Error("Expected HasReleaseChecklist=true (contains checkboxes and 'Release Process')")
	}
	if !docs.HasMultiApprovalRequirement {
		t.Error("Expected HasMultiApprovalRequirement=true (contains 'lgtm from')")
	}
	if !docs.HasReleaseManagerRole {
		t.Error("Expected HasReleaseManagerRole=true (contains 'release manager')")
	}
	if !docs.HasAutomatedReleaseProcess {
		t.Error("Expected HasAutomatedReleaseProcess=true (contains 'GitHub Actions')")
	}
	if len(docs.Evidence) < 4 {
		t.Errorf("Expected at least 4 evidence entries, got %d", len(docs.Evidence))
	}
}

// Test: Governance scoring with release documentation as fallback
// Justification: When issue response data and branch protection are unavailable,
//                documented contributing/release process is a valid alternative
//                governance signal. A project with CONTRIBUTING.md showing a
//                formalized process is better governed than one without any docs.
// Source: OSSF Scorecard Specification (governance health signals)
//         "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set up AnalysisResult with no issue response data, no branch protection,
//              but with ReleaseDocumentation present → scoreGovernance should award
//              responsiveness point via the release docs fallback
// Result: Package with release docs should score 1 risk point (vs 2 without)
func TestScoreGovernance_WithReleaseDocs_ResponsivenessFallback(t *testing.T) {
	analyzer := NewAnalyzer()

	// Result with no issue response, no branch protection, but WITH release docs
	resultWithDocs := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/repo",
		Metadata: models.PackageMetadata{
			RepoLastCommit:      mustParseTime("2025-12-01T00:00:00Z"),
			ReleaseDocumentation: &models.ReleaseDocumentation{
				HasDocumentedReleaseProcess: true,
				FilesFound:                  []string{"CONTRIBUTING.md"},
			},
		},
	}

	// Same result but WITHOUT release docs
	resultWithoutDocs := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/repo",
		Metadata: models.PackageMetadata{
			RepoLastCommit:      mustParseTime("2025-12-01T00:00:00Z"),
		},
	}

	scoreWithDocs := analyzer.scoreGovernance(resultWithDocs)
	scoreWithoutDocs := analyzer.scoreGovernance(resultWithoutDocs)

	// With release docs: should get responsiveness point → lower risk
	// Without release docs: should NOT get responsiveness point → higher risk
	if scoreWithDocs.RiskPoints >= scoreWithoutDocs.RiskPoints {
		t.Errorf("Package WITH release docs (risk=%d) should have lower risk than WITHOUT (risk=%d)",
			scoreWithDocs.RiskPoints, scoreWithoutDocs.RiskPoints)
	}

	// Verify release documentation check appears in checks performed
	foundDocCheck := false
	for _, check := range scoreWithDocs.ChecksPerformed {
		if check.Name == "Release documentation" && check.Status == "PASS" {
			foundDocCheck = true
			break
		}
	}
	if !foundDocCheck {
		t.Error("Expected 'Release documentation' PASS check in ChecksPerformed")
	}
}

// Test: Release security scoring with documented automated release process
// Justification: When release docs describe CI/CD automation for releases,
//                this provides additional confidence in the release security
//                beyond just detecting CI config files.
// Source: SLSA Build Level 2+ requires automated build process
// Methodology: Set up AnalysisResult with ReleaseDocumentation showing
//              automated release process → scoreReleaseSecurity should
//              earn an additional point
// Result: Documented CI/CD release process should contribute to release security score
func TestScoreReleaseSecurity_WithDocumentedAutomatedRelease(t *testing.T) {
	analyzer := NewAnalyzer()

	// Result with release docs describing CI automation
	resultWithDocs := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/repo",
		Metadata: models.PackageMetadata{
			ReleaseDocumentation: &models.ReleaseDocumentation{
				HasDocumentedReleaseProcess: true,
				HasAutomatedReleaseProcess:  true,
				FilesFound:                  []string{"RELEASING.md"},
			},
		},
	}

	// Same result without release docs
	resultWithoutDocs := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/repo",
		Metadata:      models.PackageMetadata{},
	}

	scoreWithDocs := analyzer.scoreReleaseSecurity(resultWithDocs)
	scoreWithoutDocs := analyzer.scoreReleaseSecurity(resultWithoutDocs)

	// With documented automated release: should have lower risk than without
	if scoreWithDocs.RiskPoints > scoreWithoutDocs.RiskPoints {
		t.Errorf("Package WITH documented automated release (risk=%d) should not have higher risk than WITHOUT (risk=%d)",
			scoreWithDocs.RiskPoints, scoreWithoutDocs.RiskPoints)
	}

	// Verify documented release process check appears in checks performed
	foundDocCheck := false
	for _, check := range scoreWithDocs.ChecksPerformed {
		if check.Name == "Documented release process" && check.Status == "PASS" {
			foundDocCheck = true
			break
		}
	}
	if !foundDocCheck {
		t.Error("Expected 'Documented release process' PASS check in ChecksPerformed")
	}
}

// Test: Release security scoring with documented multi-approval requirement
// Justification: Multi-approval requirements in release docs indicate that
//                releasing requires coordination between multiple people,
//                making it harder for a single compromised account to push
//                malicious code.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Set up ReleaseDocumentation with HasMultiApprovalRequirement
// Result: Should earn a point for documented release process
func TestScoreReleaseSecurity_WithMultiApprovalDocs(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/repo",
		Metadata: models.PackageMetadata{
			ReleaseDocumentation: &models.ReleaseDocumentation{
				HasDocumentedReleaseProcess: true,
				HasMultiApprovalRequirement: true,
				FilesFound:                  []string{"CONTRIBUTING.md"},
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Verify documented release process check appears
	foundDocCheck := false
	for _, check := range score.ChecksPerformed {
		if check.Name == "Documented release process" && check.Status == "PASS" {
			foundDocCheck = true
			if !strings.Contains(check.Detail, "multi-approval") {
				t.Errorf("Expected 'multi-approval' in check detail, got: %s", check.Detail)
			}
			break
		}
	}
	if !foundDocCheck {
		t.Error("Expected 'Documented release process' PASS check in ChecksPerformed")
	}
}

// Test: No release documentation results in FAIL check
// Justification: Absence of release/contributing documentation means no
//                documented release controls exist, which is a negative signal
//                for release security.
// Source: OSSF Scorecard Specification
// Methodology: Set up AnalysisResult with nil ReleaseDocumentation
// Result: Should have FAIL check for documented release process
func TestScoreReleaseSecurity_NoReleaseDocs(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/repo",
		Metadata:      models.PackageMetadata{},
	}

	score := analyzer.scoreReleaseSecurity(result)

	foundDocCheck := false
	for _, check := range score.ChecksPerformed {
		if check.Name == "Documented release process" && check.Status == "FAIL" {
			foundDocCheck = true
			break
		}
	}
	if !foundDocCheck {
		t.Error("Expected 'Documented release process' FAIL check when no release docs exist")
	}
}

// Test: Release doc files list contains expected files
// Justification: We must check all common locations where projects place
//                release/contributing documentation to avoid false negatives.
// Source: Common open-source conventions
// Methodology: Verify releaseDocFiles slice contains expected paths
// Result: Must include CONTRIBUTING.md, RELEASING.md, RELEASE.md, and their common locations
func TestReleaseDocFiles_ContainsExpectedPaths(t *testing.T) {
	expectedFiles := []string{
		"CONTRIBUTING.md",
		"RELEASING.md",
		"RELEASE.md",
		".github/CONTRIBUTING.md",
	}

	for _, expected := range expectedFiles {
		found := false
		for _, f := range releaseDocFiles {
			if f == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("releaseDocFiles is missing expected file: %s", expected)
		}
	}
}
