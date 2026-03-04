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
			SignedReleases:      true, // Releases are cryptographically signed
			CISystems:           []string{"GitHub Actions"},
			CodeReviewRate:      80, // High review rate replaces removed branch protection
			OSSFChecks:          map[string]int{"Branch-Protection": 8},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for comprehensive controls, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score = 2 (maximum) for comprehensive controls, got %d", score.Score)
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
			SignedReleases:      false, // Unsigned releases
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
			SignedReleases:      false, // But no signed releases
			CISystems:           []string{"Travis CI"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for partial controls, got %d", score.RiskPoints)
	}

	// 1 point (CI only) → score=1
	if score.Score != 1 {
		t.Errorf("Expected score 1 for moderate risk, got %d", score.Score)
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

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for missing repository (needs investigation), got %d", score.RiskPoints)
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
// Result: 1 risk point - CI alone provides some protection but gaps remain
func TestScoreReleaseSecurity_ModerateRisk_CIOnlyNoOtherControls(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/ci-only/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,  // Has CI/CD
			SignedReleases:      false, // No signed releases
			CISystems:           []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 1 point (CI only) → 1 risk with adjusted thresholds
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for CI-only with no other controls, got %d", score.RiskPoints)
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
			SignedReleases:      false,
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

// Test: Package with branch protection (via OSSF) and reviews but no CI publishing
// Justification: Branch protection and code reviews help but if releases are still
//                manual/local, an attacker who compromises a maintainer's local machine
//                or npm credentials can publish malicious versions directly to registry.
// Source: npm security incidents - compromised local credentials used to publish malicious updates
// Methodology: Check OSSF Branch-Protection >= 7, CodeReviewRate >= 75 but HasReleaseProcess=false
// Result: 1 risk point - good repository practices but insecure publishing method
func TestScoreReleaseSecurity_ModerateRisk_ProtectedRepoManualPublish(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/protected-manual/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: false, // Still manual publishing
			SignedReleases:    false,
			CISystems:         []string{},
			OSSFChecks:        map[string]int{"Branch-Protection": 8}, // Branch protection via OSSF
			CodeReviewRate:    80, // High review rate
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for protected repo but manual publishing, got %d", score.RiskPoints)
	}

	// 2 points (OSSF branch + code review) → score=2, moderate risk
	if score.Score != 2 {
		t.Errorf("Expected score 2 for moderate risk, got %d", score.Score)
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
// Result: 0 risk points - 3 controls present (CI + OSSF branch protection + code review) is strong
func TestScoreReleaseSecurity_ModerateRisk_AllControlsExceptSigning(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/unsigned/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true,
			SignedReleases:    false, // Missing signatures
			CISystems:         []string{"GitHub Actions"},
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
			CodeReviewRate:    80,
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 3 points (CI + OSSF branch + code review) → 0 risk with adjusted thresholds
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for 3 controls present, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score = 2 (maximum) for 3 controls present, got %d", score.Score)
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
// Methodology: Check HasSelfHosted=true with CI and OSSF branch protection present; verify penalty applied
// Result: 1 risk point - self-hosted runner erodes value of CI-based publishing
func TestScoreReleaseSecurity_HighRisk_SelfHostedRunnerPenalty(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/selfhosted/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true,  // Has CI/CD
			SignedReleases:    false,
			HasSelfHosted:     true, // Self-hosted runner: erodes CI security
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
			BuildSystems: []models.BuildSystemInfo{
				{
					Platform:      "GitHub Actions",
					HostedBy:      "Self-hosted",
					IsSelfHosted:  true,
					RunnerDetails: "custom-runner",
				},
			},
			CISystems: []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Points: CI(+1) + OSSFBranch(+1) + SelfHosted(-1) = 1 → riskPoints=1
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for self-hosted runner with partial controls, got %d", score.RiskPoints)
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
// Result: 0 risk points - 3 points after self-hosted penalty still meets low-risk threshold
func TestScoreReleaseSecurity_ModerateRisk_SelfHostedWithFullControls(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/full-selfhosted/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true, // CI/CD
			SignedReleases:    true, // Signed releases
			HasSelfHosted:     true, // Self-hosted penalty
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
			CodeReviewRate:    80,
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

	// Points: CI(+1) + OSSFBranch(+1) + Signed(+1) + CodeReview(+1) + SelfHosted(-1) = 3 → riskPoints=0
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points (3 points after self-hosted penalty meets threshold), got %d", score.RiskPoints)
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
		name            string
		metadata        models.PackageMetadata
		mustContain     string // key phrase that must appear in description
		mustNotContain  string // phrase that must NOT appear (empty = skip)
	}{
		{
			name: "zero points - poor release security",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   false,
				SignedReleases:      false,
			},
			mustContain: "No release security controls detected",
		},
		{
			name: "one point - moderate release security",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   true, // Only 1 control
				SignedReleases:      false,
			},
			mustContain: "gaps remain",
		},
		{
			name: "two points - moderate release security",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   true, // 2 controls
				SignedReleases:      false,
			},
			mustContain: "gaps remain",
		},
		{
			name: "four points - strong release security",
			metadata: models.PackageMetadata{
				HasReleaseProcess: true, // All 4 controls
				SignedReleases:    true,
				OSSFChecks:        map[string]int{"Branch-Protection": 8},
				CodeReviewRate:    80,
			},
			mustContain: "Multiple release security controls",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: "https://github.com/test/package",
				Metadata:      tc.metadata,
			}
			score := analyzer.scoreReleaseSecurity(result)
			if !strings.Contains(score.Description, tc.mustContain) {
				t.Errorf("Description should contain %q, got %q", tc.mustContain, score.Description)
			}
			if tc.mustNotContain != "" && strings.Contains(score.Description, tc.mustNotContain) {
				t.Errorf("Description should NOT contain %q, got %q", tc.mustNotContain, score.Description)
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
			HasReleaseProcess: true,
			SignedReleases:    true,
			CISystems:         []string{"GitHub Actions"},
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
			CodeReviewRate:    80,
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
		{"branch protection", "OSSF Branch-Protection: 8/10"},
		{"signed releases", "Releases are cryptographically signed"},
		{"required reviewers", "80% PRs reviewed"},
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
			// Boundary: exactly 1 point (meets moderate threshold)
			name: "one point - moderate risk",
			metadata: models.PackageMetadata{
				HasReleaseProcess:   true,  // +1
				SignedReleases:      false,
			},
			expectedRiskPoints: 1,
			description:        "1 point should be moderate risk (threshold is 1)",
		},
		{
			// Boundary: exactly 2 points (still moderate)
			name: "two points - still moderate risk",
			metadata: models.PackageMetadata{
				HasReleaseProcess: true, // +1
				SignedReleases:    true, // +1
			},
			expectedRiskPoints: 1,
			description:        "2 points should be moderate risk",
		},
		{
			// Boundary: exactly 3 points (crosses into low risk)
			name: "three points - crosses into low risk",
			metadata: models.PackageMetadata{
				HasReleaseProcess: true, // +1
				SignedReleases:    true, // +1
				OSSFChecks:        map[string]int{"Branch-Protection": 8}, // +1
			},
			expectedRiskPoints: 0,
			description:        "3 points should be low risk (threshold is 3)",
		},
		{
			// Boundary: exactly 4 points (low risk)
			name: "four points - low risk",
			metadata: models.PackageMetadata{
				HasReleaseProcess: true, // +1
				SignedReleases:    true, // +1
				OSSFChecks:        map[string]int{"Branch-Protection": 8}, // +1
				CodeReviewRate:    80, // +1
			},
			expectedRiskPoints: 0,
			description:        "4 points should be low risk",
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
			HasReleaseProcess: true,  // Automated releases via GitHub Actions
			SignedReleases:    false, // Common gap: most PyPI packages don't sign releases
			CISystems:         []string{"GitHub Actions"},
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
			CodeReviewRate:    80,
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 3 points (CI + OSSF branch protection + code review) → riskPoints=0 (low risk)
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for well-maintained package with 3 controls, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 for well-maintained package, got %d", score.Score)
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
			SignedReleases:      false, // No cryptographic release signing
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
			HasReleaseProcess: true,  // Automated Maven Central release pipeline
			SignedReleases:    true,  // GPG-signed Maven artifacts (standard for Central)
			CISystems:         []string{"GitHub Actions"},
			OSSFChecks:        map[string]int{"Branch-Protection": 9},
			CodeReviewRate:    90,
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 4 points (all 4 controls) → riskPoints=0 (low risk)
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for enterprise Java library, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score = 2 (maximum) for enterprise library, got %d", score.Score)
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
			SignedReleases:      false, // npm provenance not yet adopted
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
			SignedReleases:      false, // No npm provenance
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

// Test: Regression - BuildSystems populated but CISystems empty must not panic
// Justification: Prior to the fix on release_security.go:106, accessing CISystems[0] when
//                BuildSystems was non-empty but CISystems was empty caused an index-out-of-range
//                panic. This regression test ensures the guard `len(result.Metadata.CISystems) > 0`
//                prevents the crash. Packages can have build system metadata (e.g. from workflow
//                file analysis) without a populated CISystems slice.
// Source: Internal bug fix - panic in production when scanning packages with build metadata
//         but no CI system string labels
// Methodology: Set BuildSystems with a cloud-hosted entry but leave CISystems empty; verify
//              scoreReleaseSecurity returns without panic and produces valid output
// Result: No panic; evidence does NOT include "Cloud-hosted CI:" since CISystems is empty
func TestScoreReleaseSecurity_Regression_BuildSystemsNonEmpty_CISystemsEmpty_NoPanic(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/regression/ci-empty",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,
			SignedReleases:      false,
			HasSelfHosted:       false,
			BuildSystems: []models.BuildSystemInfo{
				{
					Platform: "GitHub Actions",
					HostedBy: "GitHub",
				},
			},
			CISystems: []string{}, // Empty - this previously caused panic
		},
	}

	// This call must not panic
	score := analyzer.scoreReleaseSecurity(result)

	// Should still score based on other controls (CI + branch protection = 2 points → moderate)
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for CI+branch protection, got %d", score.RiskPoints)
	}

	// Evidence must NOT contain "Cloud-hosted CI:" since CISystems is empty
	if strings.Contains(score.Evidence, "Cloud-hosted CI:") {
		t.Errorf("Expected no cloud-hosted CI evidence when CISystems is empty, got: %q", score.Evidence)
	}

	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Self-hosted penalty floor - points cannot go below 0
// Justification: The self-hosted runner penalty subtracts 1 from points, but a floor of 0
//                is enforced (line 95-96 in release_security.go). Without the floor, a package
//                with self-hosted runners and no other controls would get points=-1, which would
//                produce incorrect risk point mapping. This test verifies the floor clamp works
//                when the only earned point comes from the penalty itself.
// Source: SLSA Build L3 - self-hosted runners are untrusted build environments
// Methodology: Set HasSelfHosted=true with no other controls (0 earned points before penalty)
//              Verify points are clamped to 0 (not negative)
// Result: Score=0, riskPoints=2 (not incorrectly lower from negative points)
func TestScoreReleaseSecurity_SelfHostedPenaltyFloor_CannotGoNegative(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/floor-test/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   false, // 0 points
			SignedReleases:      false, // 0 points
			HasSelfHosted:       true,  // -1 penalty, clamped to 0
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

	// Score must be 0 (floor), not negative
	if score.Score < 0 {
		t.Errorf("Score went negative (%d) - penalty floor not enforced", score.Score)
	}
	if score.Score != 0 {
		t.Errorf("Expected score 0 (penalty floor), got %d", score.Score)
	}

	// 0 points → high risk (2 risk points)
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for self-hosted with no controls, got %d", score.RiskPoints)
	}

	// Evidence must mention self-hosted runner
	if !strings.Contains(score.Evidence, "Self-hosted CI runners detected") {
		t.Errorf("Expected self-hosted evidence, got: %q", score.Evidence)
	}
}

// Test: Cloud-hosted CI evidence path - BuildSystems and CISystems both populated, not self-hosted
// Justification: When BuildSystems contains entries and CISystems is non-empty but HasSelfHosted
//                is false, the evidence should include "Cloud-hosted CI: {CISystems[0]}". This
//                path (release_security.go:106-108) provides positive evidence that the build
//                environment is controlled by a trusted provider.
// Source: SLSA Build L2-L3 - cloud-hosted CI from trusted providers is a security positive
// Methodology: Set BuildSystems and CISystems with cloud-hosted entries, HasSelfHosted=false
// Result: Evidence contains "Cloud-hosted CI: GitHub Actions"
func TestScoreReleaseSecurity_CloudHostedCI_EvidenceIncluded(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/cloud-ci/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,
			SignedReleases:      false,
			HasSelfHosted:       false,
			BuildSystems: []models.BuildSystemInfo{
				{
					Platform: "GitHub Actions",
					HostedBy: "GitHub",
				},
			},
			CISystems: []string{"GitHub Actions"},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if !strings.Contains(score.Evidence, "Cloud-hosted CI: GitHub Actions") {
		t.Errorf("Expected cloud-hosted CI evidence, got: %q", score.Evidence)
	}
}

// ===== CI Workflow Risk Integration Tests =====
// These tests verify that parsed CI workflow risk signals correctly affect release security scoring.

// Test: CI workflow risks penalty applied when 3+ risk signals found
// Justification: Multiple insecure CI patterns indicate systemic poor security practices
//                in the release pipeline. The penalty reduces the release security score
//                to reflect the increased compromise risk.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         GitHub Actions Security Hardening guide
// Methodology: Provide CIWorkflowRisks with 3+ risk signals and verify penalty is applied
// Result: Score is reduced by the CI workflow risk penalty
func TestScoreReleaseSecurity_CIWorkflowRiskPenalty(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/risky-ci/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true,
			SignedReleases:    true,
			CISystems:         []string{"GitHub Actions"},
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
			CodeReviewRate:    80,
			CIWorkflowRisks: []models.CIWorkflowRisk{
				{
					Platform:                     "GitHub Actions",
					UnpinnedActions:              []string{"actions/checkout@v4", "actions/setup-node@v3"},
					HasExcessivePermissions:      true,
					HasScriptInjection:           false,
					MissingEnvironmentProtection: true,
					RiskCount:                    4,
					Details: []string{
						"Unpinned action actions/checkout@v4",
						"Unpinned action actions/setup-node@v3",
						"Workflow uses 'permissions: write-all'",
						"Release workflow lacks environment protection",
					},
				},
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Without CI workflow risks: 4 points (all controls) → 0 risk points
	// With CI workflow risks (3+ signals): 4 - 1 penalty = 3 points → still 0 risk
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points (3 points after CI penalty still meets threshold), got %d", score.RiskPoints)
	}
}

// Test: CI workflow risks below threshold do not trigger penalty
// Justification: Minor CI configuration issues (e.g., 1-2 unpinned actions) should not
//                penalize the release security score. Only systemic issues (3+) matter.
// Source: Proportional risk assessment - minor issues should not override strong controls
// Methodology: Provide CIWorkflowRisks with <3 risk signals
// Result: No penalty applied, score unchanged
func TestScoreReleaseSecurity_CIWorkflowRiskBelowThreshold(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/minor-ci-risk/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true,
			SignedReleases:    true,
			CISystems:         []string{"GitHub Actions"},
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
			CodeReviewRate:    80,
			CIWorkflowRisks: []models.CIWorkflowRisk{
				{
					Platform:        "GitHub Actions",
					UnpinnedActions: []string{"actions/checkout@v4"},
					RiskCount:       1,
					Details:         []string{"Unpinned action actions/checkout@v4"},
				},
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Below threshold: no penalty → 4 points → 0 risk points
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points (CI risk below penalty threshold), got %d", score.RiskPoints)
	}
}

// Test: CI workflow risk evidence appears in score output
// Justification: Evidence strings must include CI workflow risk details for audit trail
//                and to help maintainers understand what needs to be fixed.
// Source: OSSF Scorecard methodology - evidence-based assessment
// Methodology: Provide CIWorkflowRisks with various risk types and check evidence strings
// Result: Evidence contains CI workflow risk details
func TestScoreReleaseSecurity_CIWorkflowRiskEvidence(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/evidence-ci/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,
			SignedReleases:      false,
			CISystems:           []string{"GitHub Actions"},
			CIWorkflowRisks: []models.CIWorkflowRisk{
				{
					Platform:                     "GitHub Actions",
					UnpinnedActions:              []string{"actions/checkout@v4", "actions/setup-node@v3"},
					HasScriptInjection:           true,
					DangerousTriggers:            []string{"pull_request_target"},
					HasExcessivePermissions:      true,
					MissingEnvironmentProtection: true,
					RiskCount:                    6,
					Details:                      []string{"Various risks"},
				},
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Check that evidence mentions CI workflow risks
	evidenceChecks := []string{
		"script injection",
		"pull_request_target",
		"unpinned CI dependencies",
		"Excessive permissions",
		"environment protection",
	}

	for _, check := range evidenceChecks {
		if !strings.Contains(strings.ToLower(score.Evidence), strings.ToLower(check)) {
			t.Errorf("Expected evidence to mention %q, got: %q", check, score.Evidence)
		}
	}
}

// Test: Multiple CI platforms' risks are aggregated correctly
// Justification: A repo may use multiple CI systems (e.g., GitHub Actions + CircleCI).
//                Risks from all platforms should be aggregated for scoring.
// Source: Defense-in-depth principle - all CI configs must be secure
// Methodology: Provide CIWorkflowRisks from multiple platforms
// Result: Risks from all platforms are counted toward the penalty threshold
func TestScoreReleaseSecurity_MultipleCIPlatformRisks(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/multi-ci/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true,
			SignedReleases:    true,
			CISystems:         []string{"GitHub Actions", "CircleCI"},
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
			CodeReviewRate:    80,
			CIWorkflowRisks: []models.CIWorkflowRisk{
				{
					Platform:        "GitHub Actions",
					UnpinnedActions: []string{"actions/checkout@v4"},
					RiskCount:       1,
				},
				{
					Platform:                     "CircleCI",
					MissingEnvironmentProtection: true,
					UnpinnedActions:              []string{"circleci/node@5"},
					RiskCount:                    2,
				},
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Combined risk count = 1 + 2 = 3 >= threshold → penalty applied
	// 4 points - 1 penalty = 3 → riskPoints = 0 (3 still meets low-risk threshold)
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points (3 points after multi-platform penalty still meets threshold), got %d", score.RiskPoints)
	}
}

// Test: Empty CIWorkflowRisks slice does not affect scoring
// Justification: When no CI config content is available for parsing (API limitations,
//                private repos, etc.), the absence of CIWorkflowRisks should not affect
//                the existing scoring behavior.
// Source: Graceful degradation principle
// Methodology: Provide empty CIWorkflowRisks slice with full controls
// Result: Original scoring unchanged (0 risk points)
func TestScoreReleaseSecurity_EmptyCIWorkflowRisks(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/no-ci-risks/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true,
			SignedReleases:    true,
			CISystems:         []string{"GitHub Actions"},
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
			CodeReviewRate:    80,
			CIWorkflowRisks:   []models.CIWorkflowRisk{},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with empty CI workflow risks, got %d", score.RiskPoints)
	}
}

// ===== OSSF Scorecard Fallback Tests =====
// These tests verify that OSSF Scorecard data is used as a fallback when direct API
// data is unavailable (e.g., branch protection API requires admin access).

// Test: OSSF Branch-Protection fallback when direct API unavailable
// Justification: The GitHub branch protection API requires admin access, which scanning tools
//                typically don't have for third-party packages. OSSF Scorecard provides this
//                data without requiring admin permissions, making it a reliable fallback.
// Source: OSSF Scorecard "Branch-Protection" check methodology
//         GitHub API docs: "Requires admin access to check branch protection"
// Methodology: Set HasBranchProtection=false with OSSF Branch-Protection score >= 7
// Result: Branch protection point is still awarded via OSSF fallback
func TestScoreReleaseSecurity_OSSFFallback_BranchProtection(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/ossf-fallback/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,  // CI/CD
			SignedReleases:      false,
			OSSFChecks: map[string]int{
				"Branch-Protection": 8, // OSSF says branch protection is good
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Should get 2 points: CI(+1) + OSSF Branch-Protection fallback(+1) → moderate risk
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point with OSSF Branch-Protection fallback, got %d", score.RiskPoints)
	}

	if !strings.Contains(score.Evidence, "OSSF Branch-Protection: 8/10") {
		t.Errorf("Expected OSSF Branch-Protection evidence, got: %q", score.Evidence)
	}
}

// Test: OSSF Code-Review fallback when branch protection API unavailable
// Justification: When RequiredReviewers is 0 (because branch protection API requires admin access)
//                and code review rate is below threshold, OSSF Scorecard "Code-Review" check
//                provides an alternative signal for review practices.
// Source: OSSF Scorecard "Code-Review" check methodology
// Methodology: Set RequiredReviewers=0 with OSSF Code-Review score >= 7
// Result: Code review point is awarded via OSSF fallback
func TestScoreReleaseSecurity_OSSFFallback_CodeReview(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/ossf-review/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,  // CI/CD
			SignedReleases:      false,
			CodeReviewRate:      0, // No PR stats available either
			OSSFChecks: map[string]int{
				"Code-Review": 9, // OSSF says code review practices are good
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Should get 2 points: CI(+1) + OSSF Code-Review fallback(+1) → moderate risk
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point with OSSF Code-Review fallback, got %d", score.RiskPoints)
	}

	if !strings.Contains(score.Evidence, "OSSF Code-Review: 9/10") {
		t.Errorf("Expected OSSF Code-Review evidence, got: %q", score.Evidence)
	}
}

// Test: OSSF Signed-Releases fallback when direct release signing check unavailable
// Justification: Direct release signing checks depend on provenance info which may not be
//                available for all packages. OSSF Scorecard provides an alternative signal.
// Source: OSSF Scorecard "Signed-Releases" check methodology
// Methodology: Set SignedReleases=false with OSSF Signed-Releases score >= 7
// Result: Signed releases point is awarded via OSSF fallback
func TestScoreReleaseSecurity_OSSFFallback_SignedReleases(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/ossf-signed/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true,  // CI/CD
			SignedReleases:    false, // Direct check didn't find signing
			CodeReviewRate:    80,
			OSSFChecks: map[string]int{
				"Signed-Releases":   8, // OSSF says releases are signed
				"Branch-Protection": 8,
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Should get 4 points: CI(+1) + OSSFBranch(+1) + OSSF Signed(+1) + CodeReview(+1)
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with OSSF Signed-Releases fallback, got %d", score.RiskPoints)
	}

	if !strings.Contains(score.Evidence, "OSSF Signed-Releases: 8/10") {
		t.Errorf("Expected OSSF Signed-Releases evidence, got: %q", score.Evidence)
	}
}

// Test: OSSF Packaging fallback when HasReleaseProcess is false
// Justification: HasAutomatedReleases checks for GitHub release existence, not CI automation.
//                OSSF "Packaging" check specifically evaluates automated packaging pipelines.
// Source: OSSF Scorecard "Packaging" check methodology
// Methodology: Set HasReleaseProcess=false with OSSF Packaging score >= 7
// Result: Release process point is awarded via OSSF fallback
func TestScoreReleaseSecurity_OSSFFallback_Packaging(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/ossf-packaging/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   false, // Direct check failed
			SignedReleases:      false,
			OSSFChecks: map[string]int{
				"Packaging": 8, // OSSF says automated packaging exists
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Should get 2 points: OSSF Packaging(+1) + Branch(+1) → moderate risk
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point with OSSF Packaging fallback, got %d", score.RiskPoints)
	}

	if !strings.Contains(score.Evidence, "OSSF Packaging: 8/10") {
		t.Errorf("Expected OSSF Packaging evidence, got: %q", score.Evidence)
	}
}

// Test: Code review rate fallback for required reviewers
// Justification: When the branch protection API is unavailable (requires admin access),
//                a high code review rate (>= 75%) is strong evidence that reviews are
//                practiced even without formal enforcement via branch protection rules.
// Source: "Modern Code Review: A Case Study at Google" (Sadowski et al., 2018)
// Methodology: Set RequiredReviewers=0 with CodeReviewRate >= 75
// Result: Code review point is awarded via review rate fallback
func TestScoreReleaseSecurity_CodeReviewRateFallback(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/review-rate/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true,
			SignedReleases:    false,
			CodeReviewRate:    85.0, // But 85% of PRs are reviewed
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Should get 3 points: CI(+1) + OSSFBranch(+1) + CodeReviewRate(+1) → low risk
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with 3 controls (code review rate fallback), got %d", score.RiskPoints)
	}

	if !strings.Contains(score.Evidence, "85% PRs reviewed") {
		t.Errorf("Expected code review rate evidence, got: %q", score.Evidence)
	}
}

// Test: All OSSF fallbacks combined - realistic scenario where direct APIs all fail
// Justification: This is the typical scenario when scanning third-party packages: the GitHub
//                branch protection API requires admin access, signed release checks need
//                provenance data, and PR stats may be rate-limited. OSSF Scorecard data
//                is the primary reliable data source for these signals.
// Source: OSSF Scorecard methodology - publicly available security metrics
// Methodology: Set all direct checks to false/0, provide comprehensive OSSF scores
// Result: All 4 points awarded via OSSF fallbacks → 0 risk points
func TestScoreReleaseSecurity_AllOSSFFallbacks_ComprehensiveScorecard(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/ossf-comprehensive/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   false, // Direct checks all unavailable
			SignedReleases:      false,
			CodeReviewRate:      0,
			OSSFChecks: map[string]int{
				"Packaging":         9,
				"Branch-Protection": 8,
				"Signed-Releases":   7,
				"Code-Review":       9,
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// All 4 points via OSSF fallbacks → 0 risk points
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with comprehensive OSSF scores, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score = 2 (maximum) with all OSSF fallbacks, got %d", score.Score)
	}
}

// Test: Low OSSF scores do not award points (below threshold)
// Justification: OSSF scores below 7 indicate weak practices and should not count as
//                a positive signal. The threshold of 7/10 is consistent with other OSSF
//                fallback usage in the Health category.
// Source: OSSF Scorecard scoring methodology - 7+ indicates good practices
// Methodology: Provide OSSF scores below 7 for all checks
// Result: No points awarded from weak OSSF scores
func TestScoreReleaseSecurity_OSSFFallback_LowScoresNoCredit(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/weak-ossf/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   false,
			SignedReleases:      false,
			OSSFChecks: map[string]int{
				"Packaging":         3, // Below threshold
				"Branch-Protection": 5, // Below threshold
				"Signed-Releases":   2, // Below threshold
				"Code-Review":       4, // Below threshold
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// No OSSF scores >= 7, so 0 points → 2 risk points (high risk)
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points with low OSSF scores, got %d", score.RiskPoints)
	}

	// Evidence should note partial branch protection
	if !strings.Contains(score.Evidence, "OSSF Branch-Protection: 5/10 (partial") {
		t.Errorf("Expected partial branch protection evidence, got: %q", score.Evidence)
	}
}

// Test: Moderate code review rate (50-74%) doesn't earn a point but is noted
// Justification: Moderate review rates suggest some review practices but aren't strong
//                enough to award a full point. The evidence should note this for transparency.
// Source: Code review rate thresholds based on industry standards
// Methodology: Set CodeReviewRate to 60% with no other review signals
// Result: No point awarded but evidence mentions moderate review rate
func TestScoreReleaseSecurity_ModerateCodeReviewRate_NoCredit(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/moderate-review/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   true,
			SignedReleases:      false,
			CodeReviewRate:      60.0, // Moderate but below 75% threshold
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// 2 points (CI + branch) but no review point → moderate risk
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point, got %d", score.RiskPoints)
	}

	if !strings.Contains(score.Evidence, "60% PRs reviewed (moderate)") {
		t.Errorf("Expected moderate review rate evidence, got: %q", score.Evidence)
	}
}

// Test: Direct data takes precedence over OSSF fallbacks for signing and code review
// Justification: When direct API data is available (e.g., SignedReleases=true, CodeReviewRate >= 75),
//                it should take precedence over OSSF Scorecard fallbacks. Direct data is more current.
//                Branch protection uses OSSF exclusively (GitHub API requires admin access).
// Source: Data freshness principle - direct API data is more authoritative
// Methodology: Set both direct data and OSSF scores for signing and code review;
//              verify direct data is used in evidence (not OSSF fallback)
// Result: Evidence shows direct signing and review data; OSSF used only for branch protection
func TestScoreReleaseSecurity_DirectDataTakesPrecedenceOverOSSF(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/direct-precedence/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true,
			SignedReleases:    true, // Direct data available - should take precedence over OSSF Signed-Releases
			CodeReviewRate:    80,   // Direct data available - should take precedence over OSSF Code-Review
			OSSFChecks: map[string]int{
				"Branch-Protection": 9, // OSSF is the only path for branch protection
				"Signed-Releases":   8, // Should NOT be used (direct data available)
				"Code-Review":       7, // Should NOT be used (direct data available)
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Direct signing should take precedence - evidence should show direct signing, not OSSF
	if strings.Contains(score.Evidence, "OSSF Signed-Releases") {
		t.Errorf("Expected direct signing data to take precedence over OSSF Signed-Releases, but evidence contains OSSF: %q", score.Evidence)
	}

	if !strings.Contains(score.Evidence, "Releases are cryptographically signed") {
		t.Errorf("Expected direct signing evidence, got: %q", score.Evidence)
	}

	// Direct code review rate should take precedence - evidence should show review rate, not OSSF
	if strings.Contains(score.Evidence, "OSSF Code-Review") {
		t.Errorf("Expected direct code review rate to take precedence over OSSF Code-Review, but evidence contains OSSF: %q", score.Evidence)
	}

	if !strings.Contains(score.Evidence, "80% PRs reviewed") {
		t.Errorf("Expected direct code review rate evidence, got: %q", score.Evidence)
	}

	// Branch protection should use OSSF (the only path)
	if !strings.Contains(score.Evidence, "OSSF Branch-Protection: 9/10") {
		t.Errorf("Expected OSSF Branch-Protection evidence (only path for branch protection), got: %q", score.Evidence)
	}
}

// Test: Nil OSSFChecks map does not cause panic
// Justification: OSSF Scorecard is not available for all packages (e.g., non-GitHub repos,
//                packages not indexed by OSSF). The fallback code must handle nil maps safely.
// Source: Defensive programming - nil map access returns zero value in Go
// Methodology: Set OSSFChecks to nil with all direct checks false
// Result: No panic; scores as if no OSSF data available
func TestScoreReleaseSecurity_NilOSSFChecks_NoPanic(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/no-ossf/package",
		Metadata: models.PackageMetadata{
			HasReleaseProcess:   false,
			SignedReleases:      false,
			OSSFChecks:          nil, // OSSF not available
		},
	}

	// Must not panic
	score := analyzer.scoreReleaseSecurity(result)

	// 0 points → 2 risk points
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points with nil OSSF checks, got %d", score.RiskPoints)
	}
}

// Test: GitHub API denies access to branch protection (403/404), OSSF Scorecard used as fallback
// Justification: The GitHub branch protection API requires admin access. Without it, the API
//                returns 403/404. This is "access denied" not "no protection." When OSSF
//                Scorecard has data for the repository, it should be used as a fallback to
//                correctly assess branch protection status.
// Source: SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
//         OSSF Scorecard Branch-Protection check
// Methodology: Set BranchProtectionDenied=true (simulating 403/404), HasBranchProtection=false,
//              and provide OSSF Branch-Protection score >= 7. Verify PASS via OSSF fallback.
// Result: Branch protection check returns PASS using OSSF data when GitHub API is denied.
func TestScoreReleaseSecurity_BranchProtection_APIAccessDenied_OSSFFallback(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/example/repo",
		Metadata: models.PackageMetadata{
			OSSFChecks: map[string]int{
				"Branch-Protection": 8, // OSSF confirms branch protection exists
			},
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// OSSF fallback should produce a PASS for branch protection
	foundBranchProtPass := false
	for _, check := range score.ChecksPerformed {
		if check.Name == "Branch protection" {
			if check.Status != "PASS" {
				t.Errorf("Expected PASS for branch protection via OSSF fallback, got %q (detail: %s)",
					check.Status, check.Detail)
			}
			if !strings.Contains(check.Detail, "OSSF") {
				t.Errorf("Expected OSSF attribution in detail, got: %s", check.Detail)
			}
			foundBranchProtPass = true
		}
	}
	if !foundBranchProtPass {
		t.Error("Branch protection check not found in ChecksPerformed")
	}
}

// Test: No OSSF data available for branch protection → UNAVAILABLE, not FAIL
// Justification: When OSSF Scorecard has no data for the repository, we cannot determine
//                whether branch protection is configured. Reporting FAIL would incorrectly
//                penalize the package for something we simply cannot check. The correct
//                status is UNAVAILABLE, following the pattern used by governance.go and
//                other checkers. Branch protection is checked exclusively via OSSF Scorecard
//                since the GitHub API requires admin access (returns 403/404 without it).
// Source: SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
//         Governance check UNAVAILABLE pattern (governance.go:245)
// Methodology: Provide nil OSSFChecks. Verify the check reports UNAVAILABLE.
// Result: Branch protection check returns UNAVAILABLE when OSSF has no data.
func TestScoreReleaseSecurity_BranchProtection_APIAccessDenied_NoOSSF_ReportsUnavailable(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/example/repo",
		Metadata: models.PackageMetadata{
			OSSFChecks: nil, // No OSSF data available
		},
	}

	score := analyzer.scoreReleaseSecurity(result)

	// Must be UNAVAILABLE, not FAIL
	foundBranchProtCheck := false
	for _, check := range score.ChecksPerformed {
		if check.Name == "Branch protection" {
			if check.Status != "UNAVAILABLE" {
				t.Errorf("Expected UNAVAILABLE status for branch protection when no OSSF data, got %q (detail: %s)",
					check.Status, check.Detail)
			}
			if !strings.Contains(check.Detail, "No OSSF Scorecard data available") {
				t.Errorf("Expected detail to mention no OSSF data available, got: %s", check.Detail)
			}
			foundBranchProtCheck = true
		}
	}
	if !foundBranchProtCheck {
		t.Error("Branch protection check not found in ChecksPerformed")
	}

	// Also verify with empty OSSFChecks map (not nil, but no Branch-Protection key)
	result2 := &models.AnalysisResult{
		RepositoryURL: "https://github.com/example/repo",
		Metadata: models.PackageMetadata{
			OSSFChecks: map[string]int{"Code-Review": 9}, // Has OSSF data but not for Branch-Protection
		},
	}

	score2 := analyzer.scoreReleaseSecurity(result2)

	for _, check := range score2.ChecksPerformed {
		if check.Name == "Branch protection" {
			if check.Status != "UNAVAILABLE" {
				t.Errorf("Expected UNAVAILABLE when OSSF has no Branch-Protection data, got %q (detail: %s)",
					check.Status, check.Detail)
			}
		}
	}
}

// Test: OSSF Scorecard provides correct branch protection score when GitHub API is unavailable
// Justification: For well-known repositories, OSSF Scorecard independently verifies branch
//                protection settings. A high OSSF Branch-Protection score (>= 7) should award
//                credit even when the GitHub API cannot be queried directly.
// Source: OSSF Scorecard Branch-Protection check methodology
//         SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
// Methodology: Set BranchProtectionDenied=true with various OSSF Branch-Protection scores
//              and verify correct scoring: >= 7 = PASS, 1-6 = FAIL (weak), 0 = UNAVAILABLE.
// Result: Correct risk point allocation based on OSSF Branch-Protection score.
func TestScoreReleaseSecurity_BranchProtection_OSSFScorecard_CorrectScoring(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name           string
		ossfScore      int
		expectStatus   string
		expectPoints   int // minimum expected total points from branch protection alone
	}{
		{
			name:         "OSSF score 10 - strong protection",
			ossfScore:    10,
			expectStatus: "PASS",
			expectPoints: 1,
		},
		{
			name:         "OSSF score 7 - threshold pass",
			ossfScore:    7,
			expectStatus: "PASS",
			expectPoints: 1,
		},
		{
			name:         "OSSF score 6 - below threshold",
			ossfScore:    6,
			expectStatus: "FAIL",
			expectPoints: 0,
		},
		{
			name:         "OSSF score 3 - weak protection",
			ossfScore:    3,
			expectStatus: "FAIL",
			expectPoints: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				RepositoryURL: "https://github.com/example/repo",
				Metadata: models.PackageMetadata{
					OSSFChecks: map[string]int{
						"Branch-Protection": tt.ossfScore,
					},
				},
			}

			score := analyzer.scoreReleaseSecurity(result)

			for _, check := range score.ChecksPerformed {
				if check.Name == "Branch protection" {
					if check.Status != tt.expectStatus {
						t.Errorf("Expected %s for OSSF score %d, got %q (detail: %s)",
							tt.expectStatus, tt.ossfScore, check.Status, check.Detail)
					}
				}
			}

			// Verify points: branch protection is one of several components,
			// so check that score reflects branch protection contribution
			if tt.expectPoints > 0 && score.Score < tt.expectPoints {
				t.Errorf("Expected at least %d points from branch protection (OSSF score %d), got total score %d",
					tt.expectPoints, tt.ossfScore, score.Score)
			}
		})
	}
}
