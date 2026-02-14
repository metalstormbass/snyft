package analyzer

import (
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ===== Release Security Tests =====
// Category: Release Security Controls
// Purpose: Assess the security of the release pipeline to identify where attackers could inject malicious payloads
// Key Risk Factors: Local publishing, lack of branch protection, unsigned releases, no code review requirements

// Test: Package with comprehensive release security controls
// Justification: CI-based publishing with branch protection, signed releases, and required reviews
//                creates multiple defense layers against supply chain attacks
// Source: SLSA Build Level 3 requirements (https://slsa.dev/spec/v1.0/levels)
//         "Backstabber's Knife Collection" (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535
// Methodology: Check HasReleaseProcess, HasBranchProtection, SignedReleases, RequiredReviewers via API
// Result: 0 risk points - strong release security with multiple controls
func TestScoreReleaseSecurity_LowRisk_ComprehensiveControls(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/secure/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true, // Automated CI/CD releases
			HasBranchProtection: true, // Branch protection enabled
			SignedReleases:      true, // Releases are cryptographically signed
			RequiredReviewers:   2,    // Requires 2 PR reviews before merge
			CISystems:           []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for comprehensive controls, got %d", score.RiskPoints)
	}

	if score.Score < 4 {
		t.Errorf("Expected score >= 4 for comprehensive controls, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Package with local publishing and no protections
// Justification: Local publishing from developer machines is the highest risk release method.
//                Attacker who compromises a developer's machine or credentials can inject
//                malicious code directly into published packages. No branch protection or
//                reviews means no oversight or verification.
// Source: "Towards Measuring Supply Chain Attacks on Package Managers" (NDSS 2020)
//         npm security advisories on compromised maintainer accounts
// Methodology: Check absence of HasReleaseProcess, HasBranchProtection, SignedReleases, RequiredReviewers
// Result: 2 risk points - critical release security gaps
func TestScoreReleaseSecurity_HighRisk_LocalPublishingNoProtections(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/insecure/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   false, // Manual/local publishing
			HasBranchProtection: false, // No branch protection
			SignedReleases:      false, // Unsigned releases
			RequiredReviewers:   0,     // No required reviews
			CISystems:           []string{},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for local publishing with no protections, got %d", score.RiskPoints)
	}

	if score.Score > 1 {
		t.Errorf("Expected score <= 1 for high risk configuration, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Package with some controls but gaps
// Justification: Partial security controls reduce but don't eliminate risk.
//                CI publishing without branch protection allows direct pushes.
//                No signed releases means package authenticity cannot be verified.
// Source: SLSA Build Level 2 requirements (https://slsa.dev/spec/v1.0/levels)
// Methodology: Check for partial presence of security controls
// Result: 1 risk point - moderate risk with gaps in release security
func TestScoreReleaseSecurity_ModerateRisk_PartialControls(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/partial/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,  // Has CI/CD
			HasBranchProtection: true,  // Has branch protection
			SignedReleases:      false, // But no signed releases
			RequiredReviewers:   0,     // And no required reviews
			CISystems:           []string{"Travis CI"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for partial controls, got %d", score.RiskPoints)
	}

	if score.Score < 2 || score.Score > 3 {
		t.Errorf("Expected score 2-3 for moderate risk, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Package without repository URL
// Justification: Cannot verify release security controls without repository access.
//                This creates uncertainty about release process security.
// Source: OSSF Scorecard methodology - requires repository access for assessment
// Methodology: Check for missing repository URL
// Result: 2 risk points - unable to verify any release security controls
func TestScoreReleaseSecurity_HighRisk_NoRepository(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "", // No repository URL
		Metadata:      models.PackageMetadata{},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for missing repository, got %d", score.RiskPoints)
	}

	if score.Verified {
		t.Error("Expected unverified score when repository URL is missing")
	}
}

// Test: Package with CI publishing but no other controls
// Justification: CI-based publishing is better than local, but without branch protection,
//                code reviews, or signed releases, an attacker can still inject malicious
//                code through various attack vectors (compromised CI credentials, direct pushes).
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         GitHub security best practices for CI/CD
// Methodology: Check HasReleaseProcess=true but other controls absent
// Result: 2 risk points - CI alone is insufficient without additional protections
func TestScoreReleaseSecurity_HighRisk_CIOnlyNoOtherControls(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/ci-only/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,  // Has CI/CD
			HasBranchProtection: false, // No branch protection
			SignedReleases:      false, // No signed releases
			RequiredReviewers:   0,     // No required reviews
			CISystems:           []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for CI-only with no other controls, got %d", score.RiskPoints)
	}

	if score.Score > 1 {
		t.Errorf("Expected low score for minimal controls, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Package with GitHub Actions but no release process
// Justification: Having CI/CD infrastructure without using it for releases means
//                packages are still published manually, creating a compromise vector.
// Source: SLSA Build Levels - Level 1 requires automated build process
// Methodology: Check for CI systems present but HasReleaseProcess=false
// Result: 2 risk points - infrastructure exists but not used for secure releases
func TestScoreReleaseSecurity_HighRisk_GitHubActionsNoAutomatedRelease(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/manual-release/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   false, // Manual releases despite having CI
			HasBranchProtection: false,
			SignedReleases:      false,
			RequiredReviewers:   0,
			CISystems:           []string{"GitHub Actions"}, // CI exists but not used for releases
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for manual releases, got %d", score.RiskPoints)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Package with branch protection and reviews but no CI publishing
// Justification: Branch protection and code reviews help but if releases are still
//                manual/local, an attacker who compromises a maintainer's local machine
//                or npm credentials can publish malicious versions directly to registry.
// Source: npm security incidents - compromised local credentials used to publish malicious updates
// Methodology: Check HasBranchProtection=true, RequiredReviewers>0 but HasReleaseProcess=false
// Result: 1 risk point - good repository practices but insecure publishing method
func TestScoreReleaseSecurity_ModerateRisk_ProtectedRepoManualPublish(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/protected-manual/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   false, // Still manual publishing
			HasBranchProtection: true,  // Branch is protected
			SignedReleases:      false,
			RequiredReviewers:   2, // Requires reviews
			CISystems:           []string{},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for protected repo but manual publishing, got %d", score.RiskPoints)
	}

	if score.Score < 2 || score.Score > 3 {
		t.Errorf("Expected score 2-3 for moderate risk, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Package with all controls except signed releases
// Justification: Without signed releases, package authenticity cannot be cryptographically verified.
//                An attacker could potentially compromise the CI/CD pipeline or registry to inject
//                malicious packages. Signatures provide non-repudiation and tamper detection.
// Source: Sigstore documentation (https://www.sigstore.dev/)
//         npm provenance attestations (https://github.blog/2023-04-19-introducing-npm-package-provenance/)
// Methodology: Check all controls present except SignedReleases=false
// Result: 1 risk point - good security posture but missing cryptographic verification
func TestScoreReleaseSecurity_ModerateRisk_AllControlsExceptSigning(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/unsigned/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,
			HasBranchProtection: true,
			SignedReleases:      false, // Missing signatures
			RequiredReviewers:   2,
			CISystems:           []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for missing signatures, got %d", score.RiskPoints)
	}

	if score.Score < 3 || score.Score > 4 {
		t.Errorf("Expected score 3-4, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}
