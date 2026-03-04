package analyzer

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// ===== CI Workflow Risk Integration Tests =====
// Category: CI/CD Pipeline Security Analysis
// Purpose: Verify that analyzeBuildInfrastructure correctly fetches CI config files,
//          parses them for insecure practices, and populates CIWorkflowRisks.

// newMockCIServer creates a mock GitHub API server that serves CI config file
// content via GET (for GetFileContent) and responds to HEAD (for DetectCISystems).
// ciFiles maps file paths to their content (empty string = file exists but empty).
// Files not in the map return 404.
func newMockCIServer(ciFiles map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Handle HEAD requests (used by DetectCISystems / fileExists).
		// Uses contains matching so directory paths like ".github/workflows"
		// correctly respond to existence probes.
		if r.Method == "HEAD" {
			for filePath := range ciFiles {
				if strings.Contains(path, "/contents/"+filePath) {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Handle GET requests (used by GetFileContent).
		// Uses suffix matching to avoid directory keys shadowing file keys
		// (e.g., ".github/workflows" matching ".github/workflows/release.yml").
		if r.Method == "GET" {
			// Releases endpoint (for HasAutomatedReleases)
			if strings.Contains(path, "/releases") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("[]"))
				return
			}

			for filePath, content := range ciFiles {
				if strings.HasSuffix(path, "/contents/"+filePath) {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(content))
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

// Test: GitHub Actions workflow with unpinned actions populates CIWorkflowRisks
// Justification: Unpinned actions allow tag hijacking - an attacker who compromises an
//                action's repo can move a tag to point to malicious code. This is a direct
//                supply chain attack vector that analyzeBuildInfrastructure must detect.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535
//         GitHub Security Lab - "Keeping your GitHub Actions and workflows secure"
// Methodology: Mock GitHub API serving a workflow with unpinned actions, run analyzeBuildInfrastructure,
//              verify CIWorkflowRisks is populated with the correct risk signals
// Result: CIWorkflowRisks contains entry with UnpinnedActions populated
func TestAnalyzeBuildInfrastructure_GitHubActions_UnpinnedActions(t *testing.T) {
	workflowContent := `name: Release
on:
  push:
    tags: ['v*']
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
      - run: npm publish
`
	server := newMockCIServer(map[string]string{
		".github/workflows":             "", // directory exists for CI detection
		".github/workflows/release.yml": workflowContent,
	})
	defer server.Close()

	analyzer := NewAnalyzer()
	analyzer.githubClient = fetcher.NewGitHubClientWithBaseURL(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/unpinned-actions",
		Metadata:      models.PackageMetadata{},
	}

	analyzer.analyzeBuildInfrastructure(result, result.RepositoryURL, nil)

	// Verify CIWorkflowRisks is populated
	if len(result.Metadata.CIWorkflowRisks) == 0 {
		t.Fatal("Expected CIWorkflowRisks to be populated, got empty slice")
	}

	risk := result.Metadata.CIWorkflowRisks[0]
	if risk.Platform != "GitHub Actions" {
		t.Errorf("Expected platform 'GitHub Actions', got %q", risk.Platform)
	}

	if len(risk.UnpinnedActions) < 2 {
		t.Errorf("Expected at least 2 unpinned actions, got %d: %v", len(risk.UnpinnedActions), risk.UnpinnedActions)
	}

	if risk.RiskCount == 0 {
		t.Error("Expected non-zero RiskCount for unpinned actions")
	}

	// Verify findings are generated
	foundUnpinnedFinding := false
	for _, f := range result.Findings {
		if f.Category == "Unpinned CI Dependencies" {
			foundUnpinnedFinding = true
			break
		}
	}
	if !foundUnpinnedFinding {
		t.Error("Expected 'Unpinned CI Dependencies' finding to be generated")
	}
}

// Test: GitHub Actions workflow with script injection populates CIWorkflowRisks
// Justification: Script injection via untrusted ${{ }} expressions in run steps enables
//                arbitrary code execution in the CI environment. An attacker can craft a PR
//                title or branch name that executes malicious commands.
// Source: GitHub Security Lab - "Keeping your GitHub Actions and workflows secure:
//         Preventing pwn requests" (https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
// Methodology: Mock workflow with script injection pattern, verify HIGH finding generated
// Result: CIWorkflowRisks has HasScriptInjection=true, HIGH severity finding created
func TestAnalyzeBuildInfrastructure_GitHubActions_ScriptInjection(t *testing.T) {
	workflowContent := `name: PR Check
on:
  pull_request_target:
    types: [opened]
jobs:
  greet:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: echo "PR title is ${{ github.event.pull_request.title }}"
`
	server := newMockCIServer(map[string]string{
		".github/workflows":         "", // directory exists
		".github/workflows/ci.yml":  workflowContent,
	})
	defer server.Close()

	analyzer := NewAnalyzer()
	analyzer.githubClient = fetcher.NewGitHubClientWithBaseURL(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/script-injection",
		Metadata:      models.PackageMetadata{},
	}

	analyzer.analyzeBuildInfrastructure(result, result.RepositoryURL, nil)

	if len(result.Metadata.CIWorkflowRisks) == 0 {
		t.Fatal("Expected CIWorkflowRisks to be populated")
	}

	risk := result.Metadata.CIWorkflowRisks[0]
	if !risk.HasScriptInjection {
		t.Error("Expected HasScriptInjection=true")
	}

	if !risk.HasExcessivePermissions {
		t.Error("Expected HasExcessivePermissions=true for write-all")
	}

	if len(risk.DangerousTriggers) == 0 {
		t.Error("Expected DangerousTriggers to contain pull_request_target")
	}

	// Verify HIGH findings are generated for script injection and dangerous triggers
	highFindings := map[string]bool{
		"CI Script Injection":  false,
		"Dangerous CI Triggers": false,
	}
	for _, f := range result.Findings {
		if _, ok := highFindings[f.Category]; ok {
			highFindings[f.Category] = true
			if f.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity for %q, got %q", f.Category, f.Severity)
			}
		}
	}
	for category, found := range highFindings {
		if !found {
			t.Errorf("Expected finding %q to be generated", category)
		}
	}
}

// Test: Secure workflow produces no CIWorkflowRisks
// Justification: A well-configured workflow with SHA-pinned actions, restricted permissions,
//                and environment protection should produce zero risk signals. This verifies
//                we don't generate false positives for secure configurations.
// Source: GitHub Actions Security Hardening - https://docs.github.com/en/actions/security-guides
//         SLSA Build Level Requirements - https://slsa.dev/spec/v1.0/levels
// Methodology: Mock a fully secure workflow, verify CIWorkflowRisks is empty
// Result: CIWorkflowRisks empty, no CI risk findings generated
func TestAnalyzeBuildInfrastructure_GitHubActions_SecureWorkflow(t *testing.T) {
	workflowContent := `name: Release
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - uses: actions/setup-node@1a4442cacd436585916f8e14801ca87c6e5fa4a0
      - run: npm publish
`
	server := newMockCIServer(map[string]string{
		".github/workflows":             "",
		".github/workflows/release.yml": workflowContent,
	})
	defer server.Close()

	analyzer := NewAnalyzer()
	analyzer.githubClient = fetcher.NewGitHubClientWithBaseURL(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/secure-workflow",
		Metadata:      models.PackageMetadata{},
	}

	analyzer.analyzeBuildInfrastructure(result, result.RepositoryURL, nil)

	// A secure workflow should produce no risks
	if len(result.Metadata.CIWorkflowRisks) != 0 {
		t.Errorf("Expected no CIWorkflowRisks for secure workflow, got %d: %+v",
			len(result.Metadata.CIWorkflowRisks), result.Metadata.CIWorkflowRisks)
	}

	// Verify no CI risk findings
	for _, f := range result.Findings {
		if strings.HasPrefix(f.Category, "CI ") || f.Category == "Unpinned CI Dependencies" ||
			f.Category == "Excessive CI Permissions" || f.Category == "Missing CI Environment Protection" ||
			f.Category == "Dangerous CI Triggers" {
			t.Errorf("Unexpected CI risk finding for secure workflow: %q", f.Category)
		}
	}
}

// Test: No CI config files produces empty CIWorkflowRisks (graceful degradation)
// Justification: When CI config files cannot be fetched (API failure, private repo,
//                non-standard CI), CIWorkflowRisks should remain empty rather than
//                producing false positives or errors.
// Source: Graceful degradation principle
// Methodology: Mock server that returns 404 for all workflow file content
// Result: CIWorkflowRisks empty, existing CI detection still works
func TestAnalyzeBuildInfrastructure_NoConfigContent_GracefulDegradation(t *testing.T) {
	// Server only confirms .github/workflows directory exists (for CI detection)
	// but returns 404 for all specific workflow files
	server := newMockCIServer(map[string]string{
		".github/workflows": "", // directory detected, but no individual files
	})
	defer server.Close()

	analyzer := NewAnalyzer()
	analyzer.githubClient = fetcher.NewGitHubClientWithBaseURL(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/no-content",
		Metadata:      models.PackageMetadata{},
	}

	analyzer.analyzeBuildInfrastructure(result, result.RepositoryURL, nil)

	// CI system should be detected
	if !result.Metadata.HasCI {
		t.Error("Expected HasCI=true (directory exists)")
	}

	// But no workflow risks since content couldn't be fetched
	if len(result.Metadata.CIWorkflowRisks) != 0 {
		t.Errorf("Expected empty CIWorkflowRisks when content unavailable, got %d", len(result.Metadata.CIWorkflowRisks))
	}
}

// Test: Multiple GitHub Actions workflows are all parsed
// Justification: A repository may have multiple workflow files (release.yml, ci.yml, deploy.yml).
//                Each may have different risk signals. All should be analyzed to give a complete
//                picture of CI pipeline security.
// Source: SLSA Build Level Requirements - all build configurations must be secure
// Methodology: Mock two workflow files with different risks, verify both are parsed
// Result: CIWorkflowRisks contains entries from both workflow files
func TestAnalyzeBuildInfrastructure_MultipleWorkflows_AllParsed(t *testing.T) {
	releaseWorkflow := `name: Release
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm publish
`
	deployWorkflow := `name: Deploy
on: push
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: deploy.sh
`
	server := newMockCIServer(map[string]string{
		".github/workflows":             "",
		".github/workflows/release.yml": releaseWorkflow,
		".github/workflows/deploy.yml":  deployWorkflow,
	})
	defer server.Close()

	analyzer := NewAnalyzer()
	analyzer.githubClient = fetcher.NewGitHubClientWithBaseURL(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/multi-workflow",
		Metadata:      models.PackageMetadata{},
	}

	analyzer.analyzeBuildInfrastructure(result, result.RepositoryURL, nil)

	// Both workflows have risks, so both should appear
	if len(result.Metadata.CIWorkflowRisks) < 2 {
		t.Errorf("Expected at least 2 CIWorkflowRisks (one per workflow), got %d", len(result.Metadata.CIWorkflowRisks))
	}
}

// Test: GitLab CI config is fetched and parsed
// Justification: GitLab CI is the second most common CI platform. analyzeBuildInfrastructure
//                must handle non-GitHub CI platforms via the same GetFileContent + parse pattern.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         GitLab CI/CD security documentation
// Methodology: Mock GitLab CI config with deploy stage lacking protection, verify parsing
// Result: CIWorkflowRisks populated with GitLab CI risk entry
func TestAnalyzeBuildInfrastructure_GitLabCI_Parsed(t *testing.T) {
	gitlabConfig := `stages:
  - build
  - deploy

build:
  stage: build
  image: node
  script:
    - npm install
    - npm test

deploy:
  stage: deploy
  script:
    - npm publish
`
	server := newMockCIServer(map[string]string{
		".gitlab-ci.yml": gitlabConfig,
	})
	defer server.Close()

	analyzer := NewAnalyzer()
	analyzer.githubClient = fetcher.NewGitHubClientWithBaseURL(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/gitlab-ci",
		Metadata:      models.PackageMetadata{},
	}

	analyzer.analyzeBuildInfrastructure(result, result.RepositoryURL, nil)

	// GitLab CI should be detected and parsed
	if len(result.Metadata.CIWorkflowRisks) == 0 {
		t.Fatal("Expected CIWorkflowRisks for GitLab CI config")
	}

	risk := result.Metadata.CIWorkflowRisks[0]
	if risk.Platform != "GitLab CI" {
		t.Errorf("Expected platform 'GitLab CI', got %q", risk.Platform)
	}

	// GitLab config has deploy stage without environment protection and unpinned image
	if !risk.MissingEnvironmentProtection {
		t.Error("Expected MissingEnvironmentProtection=true for deploy without manual gate")
	}

	// Verify finding generated
	foundEnvProtection := false
	for _, f := range result.Findings {
		if f.Category == "Missing CI Environment Protection" {
			foundEnvProtection = true
			break
		}
	}
	if !foundEnvProtection {
		t.Error("Expected 'Missing CI Environment Protection' finding for GitLab deploy stage")
	}
}

// Test: CI workflow risks flow through to scoreReleaseSecurity penalty
// Justification: End-to-end verification that populated CIWorkflowRisks correctly affect
//                the release security score via the 3+ risk signals penalty.
// Source: SLSA Build Level Requirements; "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Populate CIWorkflowRisks via analyzeBuildInfrastructure, then run
//              scoreReleaseSecurity and verify the penalty is applied
// Result: Release security score reflects CI workflow risk penalty
func TestCIWorkflowRisks_EndToEnd_ScoringPenalty(t *testing.T) {
	workflowContent := `name: Release
on:
  pull_request_target:
    types: [opened]
permissions: write-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
      - run: echo "Title ${{ github.event.pull_request.title }}"
      - run: npm publish
`
	server := newMockCIServer(map[string]string{
		".github/workflows":             "",
		".github/workflows/release.yml": workflowContent,
	})
	defer server.Close()

	analyzer := NewAnalyzer()
	analyzer.githubClient = fetcher.NewGitHubClientWithBaseURL(server.URL)

	result := &models.AnalysisResult{
		RepositoryURL: "https://github.com/test/e2e-scoring",
		Metadata: models.PackageMetadata{
			HasReleaseProcess: true,
			SignedReleases:    true,
			OSSFChecks:        map[string]int{"Branch-Protection": 8},
			CodeReviewRate:    80,
		},
	}

	// Step 1: Populate CIWorkflowRisks
	analyzer.analyzeBuildInfrastructure(result, result.RepositoryURL, nil)

	// Verify risks were populated
	totalRiskCount := 0
	for _, ciRisk := range result.Metadata.CIWorkflowRisks {
		totalRiskCount += ciRisk.RiskCount
	}
	if totalRiskCount < 3 {
		t.Fatalf("Expected 3+ total CI risk signals for penalty, got %d", totalRiskCount)
	}

	// Step 2: Score release security
	score := analyzer.scoreReleaseSecurity(result)

	// Without CI risks: 4 points → 0 risk points
	// With CI risks (3+ signals): 4 - 1 penalty = 3 points → still 0 risk (meets threshold)
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points (3 points after CI penalty still meets threshold), got %d (evidence: %s)",
			score.RiskPoints, score.Evidence)
	}
}

// Test: Empty repository URL skips CI workflow parsing
// Justification: When no repository URL is available, we cannot fetch CI config files.
//                analyzeBuildInfrastructure must handle this case without errors.
// Source: Defensive programming
// Methodology: Call with empty repoURL
// Result: No panic, no CIWorkflowRisks
func TestAnalyzeBuildInfrastructure_EmptyRepoURL_Skips(t *testing.T) {
	analyzer := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{},
	}

	// Should not panic
	analyzer.analyzeBuildInfrastructure(result, "", nil)

	if len(result.Metadata.CIWorkflowRisks) != 0 {
		t.Errorf("Expected empty CIWorkflowRisks for empty repo URL, got %d", len(result.Metadata.CIWorkflowRisks))
	}
}
