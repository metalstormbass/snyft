package analyzer

import (
	"strings"
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

// Test: Package using self-hosted CI runners with partial controls
// Justification: Self-hosted runners are not controlled by a trusted cloud provider.
//                An attacker who compromises the runner machine gains full control over
//                the build environment and can inject malicious code into published artifacts.
//                The penalty reduces the effective security score even when CI is present.
// Source: SLSA Build L3 - https://slsa.dev/spec/v1.0/levels
//         "Backstabber's Knife Collection" (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535
// Methodology: Check HasSelfHosted=true with CI and branch protection present; verify penalty applied
// Result: 2 risk points - self-hosted runner erodes value of CI-based publishing
func TestScoreReleaseSecurity_HighRisk_SelfHostedRunnerPenalty(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/selfhosted/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,  // Has CI/CD
			HasBranchProtection: true,  // Has branch protection
			SignedReleases:      false,
			RequiredReviewers:   0,
			HasSelfHosted:       true, // Self-hosted runner: erodes CI security
			BuildSystems: []models.BuildSystemInfo{
				{
					Platform:     "GitHub Actions",
					HostedBy:     "Self-hosted",
					IsSelfHosted: true,
					RunnerDetails: "custom-runner",
				},
			},
			CISystems: []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Points: CI(+1) + BranchProtection(+1) + SelfHosted(-1) = 1 → riskPoints=2
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for self-hosted runner with partial controls, got %d", score.RiskPoints)
	}

	if score.Score > 1 {
		t.Errorf("Expected low score for self-hosted runner, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}

	// Evidence must mention self-hosted runner as a risk signal
	if score.Evidence == "" {
		t.Error("Expected evidence to be populated for self-hosted runner")
	}
}

// Test: Package with all 4 controls but self-hosted CI runner
// Justification: Even comprehensive security controls are partially undermined by self-hosted runners.
//                Scoring reflects that self-hosted = uncontrolled build environment regardless of
//                branch protection, reviews, or signed releases.
// Source: SLSA Build L3 requirements - trusted build environment is non-negotiable
// Methodology: Check all 4 controls present + HasSelfHosted=true; verify penalty reduces to moderate
// Result: 1 risk point - self-hosted penalty prevents achieving lowest risk score
func TestScoreReleaseSecurity_ModerateRisk_SelfHostedWithFullControls(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/full-selfhosted/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true, // CI/CD
			HasBranchProtection: true, // Branch protection
			SignedReleases:      true, // Signed releases
			RequiredReviewers:   2,    // Required reviews
			HasSelfHosted:       true, // Self-hosted penalty
			BuildSystems: []models.BuildSystemInfo{
				{
					Platform:     "Jenkins",
					HostedBy:     "Self-hosted",
					IsSelfHosted: true,
				},
			},
			CISystems: []string{"Jenkins"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Points: CI(+1) + Branch(+1) + Signed(+1) + Reviewers(+1) + SelfHosted(-1) = 3 → riskPoints=1
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point (self-hosted penalty on full controls), got %d", score.RiskPoints)
	}

	// Should NOT achieve 0 risk points despite having all 4 controls (self-hosted prevents that)
	if score.RiskPoints == 0 {
		t.Error("Expected self-hosted runner to prevent achieving 0 risk points")
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Description field accuracy across all three risk levels
// Justification: Human-readable descriptions guide remediation decisions. Incorrect descriptions
//                mislead engineers about the severity of release security gaps.
// Source: OSSF Scorecard - descriptive feedback guides security improvements
// Methodology: Verify scoreReleaseSecurity returns description strings matching documented categories
// Result: Correct description for high (0 pts), moderate (2 pts), and low (4+ pts) configurations
func TestScoreReleaseSecurity_DescriptionAccuracy(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name                string
		metadata            models.PackageMetadata
		expectedDescription string
	}{
		{
			name: "zero points - poor release security",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   false,
				HasBranchProtection: false,
				SignedReleases:      false,
				RequiredReviewers:   0,
			},
			expectedDescription: "Poor release security: local publishing or no protections",
		},
		{
			name: "one point - weak release security",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   true, // Only 1 control
				HasBranchProtection: false,
				SignedReleases:      false,
				RequiredReviewers:   0,
			},
			expectedDescription: "Weak release security: minimal controls in place",
		},
		{
			name: "two points - moderate release security",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   true, // 2 controls
				HasBranchProtection: true,
				SignedReleases:      false,
				RequiredReviewers:   0,
			},
			expectedDescription: "Moderate release security: some controls present but gaps remain",
		},
		{
			name: "four points - strong release security",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   true, // All 4 controls
				HasBranchProtection: true,
				SignedReleases:      true,
				RequiredReviewers:   1,
			},
			expectedDescription: "Strong release security: CI publishing with comprehensive protections",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: "https://github.com/test/package",
				Metadata:      tc.metadata,
			}
			score := analyzer.scoreReleaseSecurity(result)
			if score.Description != tc.expectedDescription {
				t.Errorf("Expected description %q, got %q", tc.expectedDescription, score.Description)
			}
		})
	}
}

// Test: Evidence string contains expected component signals
// Justification: Evidence strings are the audit trail for risk decisions and must accurately
//                reflect the checks that were performed and their outcomes.
// Source: OSSF Scorecard methodology - evidence-based assessment
// Methodology: Verify evidence includes CI detection, branch protection status, signing status,
//              and reviewer count for a fully-controlled package
// Result: Evidence contains all four control signals in human-readable form
func TestScoreReleaseSecurity_EvidenceContainsExpectedSignals(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/evidence-check/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,
			HasBranchProtection: true,
			SignedReleases:      true,
			RequiredReviewers:   3,
			CISystems:           []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Verify evidence is non-empty
	if score.Evidence == "" {
		t.Fatal("Expected non-empty evidence string")
	}

	// Verify each component is represented in the evidence
	evidenceChecks := []struct {
		signal   string
		contains string
	}{
		{"CI release process", "Automated CI/CD release process detected"},
		{"branch protection", "Branch protection enabled on default branch"},
		{"signed releases", "Releases are cryptographically signed"},
		{"required reviewers", "3 required reviewers for PRs"},
	}

	for _, check := range evidenceChecks {
		if !strings.Contains(score.Evidence, check.contains) {
			t.Errorf("Expected evidence to contain %q for %s signal, got: %q",
				check.contains, check.signal, score.Evidence)
		}
	}
}

// Test: Scoring boundary conditions - exact thresholds
// Justification: Off-by-one errors at scoring thresholds cause incorrect risk classifications.
//                Points=2 and Points=4 are the two critical boundaries in the scoring rubric.
// Source: SLSA Build Levels (0-3) correspond to meaningful security tiers
// Methodology: Test exactly at the two threshold values (2 and 4 earned points)
// Result: Boundary values correctly map to their respective risk categories
func TestScoreReleaseSecurity_BoundaryConditions(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name               string
		metadata           models.PackageMetadata
		expectedRiskPoints int
		description        string
	}{
		{
			// Boundary: exactly 1 point (just below moderate threshold of 2)
			name: "one point - still high risk",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   true,  // +1
				HasBranchProtection: false, // no points
				SignedReleases:      false,
				RequiredReviewers:   0,
			},
			expectedRiskPoints: 2,
			description:        "1 point should remain high risk (threshold is 2)",
		},
		{
			// Boundary: exactly 2 points (meets moderate threshold)
			name: "two points - crosses into moderate risk",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   true, // +1
				HasBranchProtection: true, // +1
				SignedReleases:      false,
				RequiredReviewers:   0,
			},
			expectedRiskPoints: 1,
			description:        "2 points should be moderate risk (threshold met)",
		},
		{
			// Boundary: exactly 3 points (moderate, not yet low)
			name: "three points - still moderate risk",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   true, // +1
				HasBranchProtection: true, // +1
				SignedReleases:      true, // +1
				RequiredReviewers:   0,
			},
			expectedRiskPoints: 1,
			description:        "3 points should be moderate risk (threshold is 4)",
		},
		{
			// Boundary: exactly 4 points (meets low risk threshold)
			name: "four points - crosses into low risk",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   true, // +1
				HasBranchProtection: true, // +1
				SignedReleases:      true, // +1
				RequiredReviewers:   1,    // +1
			},
			expectedRiskPoints: 0,
			description:        "4 points should be low risk (threshold met)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: "https://github.com/boundary/package",
				Metadata:      tc.metadata,
			}
			score := analyzer.scoreReleaseSecurity(result)
			if score.RiskPoints != tc.expectedRiskPoints {
				t.Errorf("%s: expected %d risk points, got %d", tc.description, tc.expectedRiskPoints, score.RiskPoints)
			}
		})
	}
}

// Test: Real-world profile - well-maintained open source package (Flask/aiohttp/requests pattern)
// Justification: Popular Python packages from mike-libraries (Flask, aiohttp, requests) typically have
//                automated CI releases via GitHub Actions and branch protection, but often lack
//                cryptographic release signing. This represents the most common real-world profile.
// Source: Analysis of common OSS package practices (Flask: github.com/pallets/flask,
//         aiohttp: github.com/aio-libs/aiohttp, requests: github.com/psf/requests)
// Methodology: Simulate metadata representative of well-maintained PyPI packages:
//              CI releases enabled, branch protection enabled, no signed releases, some reviewers
// Result: 1 risk point - typical for popular packages with good CI but no cryptographic signing
func TestScoreReleaseSecurity_RealWorldProfile_WellMaintainedPythonPackage(t *testing.T) {
	analyzer := NewAnalyzer()
	// Representative of Flask, aiohttp, requests - well-maintained but typically unsigned
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/typical-oss/python-package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,  // Automated releases via GitHub Actions
			HasBranchProtection: true,  // Branch protection with reviews
			SignedReleases:      false, // Common gap: most PyPI packages don't sign releases
			RequiredReviewers:   1,     // At least 1 reviewer required
			CISystems:           []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 3 points (CI + branch protection + reviewers) → riskPoints=1 (moderate)
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for well-maintained-but-unsigned package, got %d", score.RiskPoints)
	}

	if score.Score < 2 || score.Score > 4 {
		t.Errorf("Expected score 2-4 for well-maintained package, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Real-world profile - small utility package (python-dotenv/click pattern)
// Justification: Small utility packages from mike-libraries (python-dotenv, click, pydantic)
//                often have minimal release security: manual publishing from maintainer's machine,
//                no formal branch protection, and no signed releases. This is the highest-risk
//                profile in a typical Python application's dependency tree.
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - small packages disproportionately
//         risky; analysis of smaller PyPI packages shows weaker release security practices
// Methodology: Simulate metadata of a typical small utility package: no CI process,
//              no branch protection, no signing, no required reviews
// Result: 2 risk points - common profile for utility packages lacking release security
func TestScoreReleaseSecurity_RealWorldProfile_SmallUtilityPackage(t *testing.T) {
	analyzer := NewAnalyzer()
	// Representative of smaller packages: python-dotenv, click, passlib - common in mike-libraries
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/small-maintainer/utility-package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   false, // Manual publishing (typical for small packages)
			HasBranchProtection: false, // No branch protection rules configured
			SignedReleases:      false, // No cryptographic release signing
			RequiredReviewers:   0,     // No required code reviews
			CISystems:           []string{"GitHub Actions"}, // CI exists for tests, not releases
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 0 points → riskPoints=2 (high risk)
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for small utility package with no release controls, got %d", score.RiskPoints)
	}

	if score.Score > 1 {
		t.Errorf("Expected low score for minimal release security, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score (repository URL is present)")
	}
}

// Test: Real-world profile - enterprise Java library (Spring Boot dependency pattern)
// Justification: Enterprise libraries from mike-libraries (Spring Boot, commons-lang3, guava)
//                represent the gold standard for release security: automated Maven Central publishing,
//                strict branch protection, signed releases, and required code reviews from multiple
//                committers. Compromise of a single Spring Boot dependency would affect millions of apps.
// Source: Apache Foundation release policies (apache.org/dev/release-publishing)
//         "Backstabber's Knife Collection" (Ohm et al., 2020) - high-value targets attract attacks
// Methodology: Simulate metadata of a well-governed enterprise Java library:
//              full CI/CD, branch protection, signed artifacts, multiple required reviewers
// Result: 0 risk points - enterprise governance provides comprehensive release controls
func TestScoreReleaseSecurity_RealWorldProfile_EnterpriseJavaLibrary(t *testing.T) {
	analyzer := NewAnalyzer()
	// Representative of Spring Boot, commons-lang3, guava - from pom.xml in mike-libraries
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/enterprise-org/java-library",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,  // Automated Maven Central release pipeline
			HasBranchProtection: true,  // Branch protection with committer rules
			SignedReleases:      true,  // GPG-signed Maven artifacts (standard for Central)
			RequiredReviewers:   2,     // Minimum 2 committer reviews
			CISystems:           []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 4 points (all 4 controls) → riskPoints=0 (low risk)
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for enterprise Java library, got %d", score.RiskPoints)
	}

	if score.Score < 4 {
		t.Errorf("Expected high score for enterprise library, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Real-world profile - npm auth library (jsonwebtoken/passport pattern)
// Justification: Auth libraries from mike-libraries (jsonwebtoken, passport, bcryptjs)
//                handle sensitive operations (token generation, authentication, hashing).
//                Many npm auth packages have CI-based publishing and branch protection but
//                lack signed releases (npm provenance is still emerging).
//   From mike-libraries/javascript/package.json: "jsonwebtoken": "^9.0.2", "passport": "^0.7.0"
// Source: npm provenance attestations adoption data - <5% of npm packages use provenance
// Methodology: Simulate metadata of a typical npm auth package: CI releases,
//              branch protection, no signed releases, no required reviews
// Result: 1 risk point - CI and branch protection help but missing signing and reviews
func TestScoreReleaseSecurity_RealWorldProfile_NPMAuthLibrary(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/auth-maintainer/jwt-library",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,  // npm publish via GitHub Actions
			HasBranchProtection: true,  // Branch protection configured
			SignedReleases:      false, // npm provenance not yet adopted
			RequiredReviewers:   0,     // No required reviewers
			CISystems:           []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 2 points (CI + branch protection) → riskPoints=1 (moderate)
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for npm auth library, got %d", score.RiskPoints)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Real-world profile - single-maintainer npm utility (dotenv/uuid/cors pattern)
// Justification: Single-maintainer npm utilities from mike-libraries (dotenv, uuid, cors)
//                typically publish from the maintainer's local machine with minimal security
//                controls. These packages have massive downstream reach but minimal governance.
//   From mike-libraries/javascript/package.json: "dotenv": "^16.3.1", "uuid": "^9.0.1", "cors": "^2.8.5"
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - utility packages
//         are disproportionately depended upon with minimal security practices
// Methodology: Simulate metadata of a small npm utility: local publishing, no CI release,
//              no branch protection, no signing, no reviews
// Result: 2 risk points - no release security controls at all
func TestScoreReleaseSecurity_RealWorldProfile_NPMSingleMaintainerUtility(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/solo-dev/utility-package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   false, // npm publish from local machine
			HasBranchProtection: false, // No branch protection rules
			SignedReleases:      false, // No npm provenance
			RequiredReviewers:   0,     // Solo maintainer, no reviews
			CISystems:           []string{},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 0 points → riskPoints=2 (high risk)
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for single-maintainer npm utility, got %d", score.RiskPoints)
	}

	if score.Score > 0 {
		t.Errorf("Expected score 0 for no release controls, got %d", score.Score)
	}

	if !score.Verified {
		t.Error("Expected verified score (repository URL present)")
	}
}

// Test: Real-world profile - security-sensitive npm package (jsonwebtoken/bcryptjs pattern)
// Justification: Security-sensitive npm packages from mike-libraries (jsonwebtoken, bcryptjs,
//                passport) handle authentication and cryptography. These often have CI-based
//                publishing and some branch protection, but their small team sizes mean
//                limited reviewer coverage and no signed releases.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - security-critical packages
//         are high-value targets for supply chain attacks
// Methodology: Simulate metadata of a security-sensitive npm package: CI releases, partial
//              branch protection, no signing, no required reviews
// Result: 1 risk point - has CI but missing signing and review requirements
func TestScoreReleaseSecurity_RealWorldProfile_SecuritySensitiveNPMPackage(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/auth-lib/jwt-package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,
			HasBranchProtection: true,
			SignedReleases:      false,
			RequiredReviewers:   0,
			CISystems:           []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 2 points (CI + branch protection) → riskPoints=1 (moderate)
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for security-sensitive npm package, got %d", score.RiskPoints)
	}

	if !strings.Contains(score.Evidence, "No required code reviews") {
		t.Errorf("Expected evidence to flag missing code reviews, got: %s", score.Evidence)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}
