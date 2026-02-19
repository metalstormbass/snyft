package analyzer

import (
	"strings"
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: Package with no CI system detected
// Justification: No CI/CD means builds and releases are unverified - packages may be built
//                and published directly from developer machines, which are prime targets for compromise.
// Source: SLSA Build L1 - "Build: Scripted build" requires at minimum an automated build process
//         https://slsa.dev/spec/v1.0/levels
// Methodology: Set HasCI=false, CISystems empty
// Result: 2 risk points (highest risk) - no CI verification
func TestScoreCIPipelineSecurity_NoCI(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/no-ci/package",
		Metadata: models.PackageMetadata{
			HasCI:     false,
			CISystems: []string{},
		},
	}

	score := analyzer.scoreCIPipelineSecurity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for no CI, got %d", score.RiskPoints)
	}
	if score.Score != 0 {
		t.Errorf("Expected score 0 for no CI, got %d", score.Score)
	}
	if !strings.Contains(score.Evidence, "No CI/CD system detected") {
		t.Errorf("Expected no CI evidence, got: %q", score.Evidence)
	}
}

// Test: Package with CI present and no workflow risks
// Justification: CI present with secure configuration = lowest risk. The build environment
//                is automated and follows secure practices.
// Source: SLSA Build L2 - hosted build platform
//         https://slsa.dev/spec/v1.0/levels
// Methodology: Set HasCI=true with cloud-hosted build systems and no CIWorkflowRisks
// Result: 0 risk points (lowest risk) - secure CI pipeline
func TestScoreCIPipelineSecurity_SecureCI(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/secure-ci/package",
		Metadata: models.PackageMetadata{
			HasCI:     true,
			CISystems: []string{"GitHub Actions"},
			BuildSystems: []models.BuildSystemInfo{
				{
					Platform: "GitHub Actions",
					HostedBy: "GitHub",
				},
			},
			CIWorkflowRisks: []models.CIWorkflowRisk{}, // No risks
		},
	}

	score := analyzer.scoreCIPipelineSecurity(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for secure CI, got %d", score.RiskPoints)
	}
	if score.Score != 2 {
		t.Errorf("Expected score 2 for secure CI, got %d", score.Score)
	}
	if !score.Verified {
		t.Error("Expected verified score")
	}
}

// Test: Package with self-hosted runners only (no workflow config risks)
// Justification: Self-hosted runners give attackers who compromise the runner full control
//                over the build environment and published artifacts. Cloud-hosted runners are
//                isolated and controlled by the CI provider.
// Source: SLSA Build L3 - https://slsa.dev/spec/v1.0/levels
// Methodology: Set HasSelfHosted=true with no CIWorkflowRisks
// Result: 1 risk point - self-hosted alone is moderate risk
func TestScoreCIPipelineSecurity_SelfHostedOnly(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/self-hosted/package",
		Metadata: models.PackageMetadata{
			HasCI:        true,
			HasSelfHosted: true,
			CISystems:    []string{"Jenkins"},
			BuildSystems: []models.BuildSystemInfo{
				{
					Platform:     "Jenkins",
					HostedBy:     "Self-hosted",
					IsSelfHosted: true,
				},
			},
			CIWorkflowRisks: []models.CIWorkflowRisk{},
		},
	}

	score := analyzer.scoreCIPipelineSecurity(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for self-hosted only, got %d", score.RiskPoints)
	}
	if !strings.Contains(score.Evidence, "Self-hosted CI runners detected") {
		t.Errorf("Expected self-hosted evidence, got: %q", score.Evidence)
	}
}

// Test: Package with self-hosted runners AND workflow risks (combined critical)
// Justification: Self-hosted runners combined with insecure workflow configurations compound
//                the risk - an attacker can exploit both the uncontrolled build environment
//                and the insecure workflow patterns.
// Source: SLSA Build Level Requirements; Backstabber's Knife Collection (Ohm et al., 2020)
// Methodology: Set HasSelfHosted=true with moderate workflow risks
// Result: 2 risk points - combined self-hosted + moderate risks = critical
func TestScoreCIPipelineSecurity_SelfHostedWithWorkflowRisks(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/combined-risk/package",
		Metadata: models.PackageMetadata{
			HasCI:        true,
			HasSelfHosted: true,
			CISystems:    []string{"GitHub Actions"},
			BuildSystems: []models.BuildSystemInfo{
				{
					Platform:     "GitHub Actions",
					HostedBy:     "Self-hosted",
					IsSelfHosted: true,
				},
			},
			CIWorkflowRisks: []models.CIWorkflowRisk{
				{
					Platform:                     "GitHub Actions",
					UnpinnedActions:              []string{"actions/checkout@v4"},
					MissingEnvironmentProtection: true,
					RiskCount:                    2,
				},
			},
		},
	}

	score := analyzer.scoreCIPipelineSecurity(result)

	// Self-hosted + moderate workflow issues = critical (2 risk points)
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for self-hosted + workflow risks, got %d", score.RiskPoints)
	}
}

// Test: No repository URL available
// Justification: Without a repository URL, we cannot inspect CI configuration.
//                This should be treated as unverified (1 risk point) rather than worst-case.
// Source: Graceful degradation for incomplete data
// Methodology: Empty RepositoryURL
// Result: 1 risk point - unverified
func TestScoreCIPipelineSecurity_NoRepoURL(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "",
		Metadata:      models.PackageMetadata{},
	}

	score := analyzer.scoreCIPipelineSecurity(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for no repo URL, got %d", score.RiskPoints)
	}
	if score.Verified {
		t.Error("Expected unverified score when no repo URL")
	}

	// All checks should be SKIPPED
	for _, check := range score.ChecksPerformed {
		if check.Status != "SKIPPED" {
			t.Errorf("Expected SKIPPED status for check %q, got %q", check.Name, check.Status)
		}
	}
}

// Test: Script injection alone triggers critical risk
// Justification: Script injection in CI workflows enables remote code execution.
//                An attacker can craft a PR title/body that executes arbitrary commands
//                in the CI environment when interpolated into run: steps.
// Source: GitHub Security Lab - "Keeping your GitHub Actions and workflows secure"
// Methodology: Set HasScriptInjection=true
// Result: 2 risk points - critical issue
func TestScoreCIPipelineSecurity_ScriptInjectionCritical(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/inject/package",
		Metadata: models.PackageMetadata{
			HasCI:     true,
			CISystems: []string{"GitHub Actions"},
			BuildSystems: []models.BuildSystemInfo{
				{Platform: "GitHub Actions", HostedBy: "GitHub"},
			},
			CIWorkflowRisks: []models.CIWorkflowRisk{
				{
					Platform:           "GitHub Actions",
					HasScriptInjection: true,
					RiskCount:          1,
					Details:            []string{"Script injection risk"},
				},
			},
		},
	}

	score := analyzer.scoreCIPipelineSecurity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for script injection, got %d", score.RiskPoints)
	}
}

// Test: Dangerous triggers alone triggers critical risk
// Justification: pull_request_target runs with base branch secrets even for fork PRs.
//                An attacker can exfiltrate secrets by submitting a PR from a fork.
// Source: GitHub Security Lab - pwn requests
// Methodology: Set DangerousTriggers with pull_request_target
// Result: 2 risk points - critical issue
func TestScoreCIPipelineSecurity_DangerousTriggersCritical(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/triggers/package",
		Metadata: models.PackageMetadata{
			HasCI:     true,
			CISystems: []string{"GitHub Actions"},
			BuildSystems: []models.BuildSystemInfo{
				{Platform: "GitHub Actions", HostedBy: "GitHub"},
			},
			CIWorkflowRisks: []models.CIWorkflowRisk{
				{
					Platform:          "GitHub Actions",
					DangerousTriggers: []string{"pull_request_target"},
					RiskCount:         1,
					Details:           []string{"Dangerous trigger"},
				},
			},
		},
	}

	score := analyzer.scoreCIPipelineSecurity(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for dangerous triggers, got %d", score.RiskPoints)
	}
}

// Test: CI present with no workflow risks and no build systems parsed
// Justification: When CI is detected but config files couldn't be fetched (API limits, private repo),
//                the check should be marked as UNAVAILABLE rather than failing.
// Source: Graceful degradation principle
// Methodology: Set HasCI=true with CISystems but empty BuildSystems and CIWorkflowRisks
// Result: 0 risk points - CI present, no data to flag issues
func TestScoreCIPipelineSecurity_CIDetectedButConfigNotFetched(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/limited-api/package",
		Metadata: models.PackageMetadata{
			HasCI:           true,
			CISystems:       []string{"GitHub Actions"},
			BuildSystems:    []models.BuildSystemInfo{}, // No build systems parsed
			CIWorkflowRisks: []models.CIWorkflowRisk{},
		},
	}

	score := analyzer.scoreCIPipelineSecurity(result)

	// CI detected but config not fetchable → UNAVAILABLE, not FAIL
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points when CI detected but config not fetchable, got %d", score.RiskPoints)
	}

	// Should have UNAVAILABLE check for workflow security
	foundUnavailable := false
	for _, check := range score.ChecksPerformed {
		if check.Name == "CI workflow security" && check.Status == "UNAVAILABLE" {
			foundUnavailable = true
			break
		}
	}
	if !foundUnavailable {
		t.Error("Expected UNAVAILABLE status for CI workflow security when config not fetchable")
	}
}
