package fetcher

import (
	"testing"
)

// ===== GitHub Actions Workflow Parser Tests =====
// Category: CI/CD Workflow Security Analysis
// Purpose: Verify that the parser correctly identifies insecure patterns in GitHub Actions
//          workflows that could be exploited for supply chain attacks

// Test: Detect unpinned GitHub Actions referenced by mutable tag
// Justification: Actions referenced by tag (e.g., @v3) can be hijacked if an attacker
//                gains push access to the action's repository and moves the tag to point
//                to malicious code. SHA-pinned references are immutable.
// Source: GitHub Security Lab - "Keeping your GitHub Actions and workflows secure"
//         "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Parse workflow YAML with uses: directives referencing tags vs SHAs
// Result: Unpinned actions are detected and listed
func TestParseGitHubActionsWorkflow_UnpinnedActions(t *testing.T) {
	workflow := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
      - uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94d9d67
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if len(risk.UnpinnedActions) != 2 {
		t.Errorf("Expected 2 unpinned actions, got %d: %v", len(risk.UnpinnedActions), risk.UnpinnedActions)
	}

	// The SHA-pinned cache action should NOT be flagged
	for _, action := range risk.UnpinnedActions {
		if action == "actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94d9d67" {
			t.Error("SHA-pinned action should not be flagged as unpinned")
		}
	}
}

// Test: All SHA-pinned actions produce zero unpinned findings
// Justification: Workflows that properly pin all actions to commit SHAs follow best
//                practices and should not produce false positive risk signals.
// Source: GitHub Actions Security Hardening guide
// Methodology: Parse workflow with all actions pinned to full 40-char SHA hashes
// Result: Zero unpinned actions detected
func TestParseGitHubActionsWorkflow_AllPinned(t *testing.T) {
	workflow := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if len(risk.UnpinnedActions) != 0 {
		t.Errorf("Expected 0 unpinned actions for fully pinned workflow, got %d: %v",
			len(risk.UnpinnedActions), risk.UnpinnedActions)
	}
}

// Test: Detect excessive permissions (write-all)
// Justification: Workflows with write-all permissions grant every write scope to the
//                GITHUB_TOKEN. If the workflow is compromised, the attacker can modify
//                repo contents, create releases, push packages, and access secrets.
// Source: GitHub Actions security hardening - "Using GITHUB_TOKEN permissions"
// Methodology: Parse workflow with top-level "permissions: write-all"
// Result: HasExcessivePermissions is true
func TestParseGitHubActionsWorkflow_ExcessivePermissions_WriteAll(t *testing.T) {
	workflow := `
name: Release
on: push
permissions: write-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if !risk.HasExcessivePermissions {
		t.Error("Expected HasExcessivePermissions=true for write-all permission")
	}
}

// Test: Detect excessive permissions (contents: write)
// Justification: contents: write allows the workflow to modify repository contents,
//                including pushing commits and creating/deleting branches.
// Source: GitHub Actions permission scopes documentation
// Methodology: Parse workflow with "contents: write" permission
// Result: HasExcessivePermissions is true
func TestParseGitHubActionsWorkflow_ExcessivePermissions_ContentsWrite(t *testing.T) {
	workflow := `
name: Release
on: push
permissions:
  contents: write
  packages: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if !risk.HasExcessivePermissions {
		t.Error("Expected HasExcessivePermissions=true for contents: write")
	}
}

// Test: Restrictive permissions do not trigger false positive
// Justification: Workflows with read-only or minimal permissions follow least-privilege
//                principle and should not be flagged.
// Source: GitHub Actions security best practices
// Methodology: Parse workflow with restrictive permissions
// Result: HasExcessivePermissions is false
func TestParseGitHubActionsWorkflow_RestrictivePermissions(t *testing.T) {
	workflow := `
name: CI
on: push
permissions:
  contents: read
  packages: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if risk.HasExcessivePermissions {
		t.Error("Expected HasExcessivePermissions=false for read-only permissions")
	}
}

// Test: Detect pull_request_target trigger (inline form)
// Justification: pull_request_target runs in the context of the base branch with access
//                to secrets, even for PRs from forks. This enables secret exfiltration
//                when combined with checking out PR head code.
// Source: GitHub Security Lab - "Keeping your GitHub Actions and workflows secure:
//         Preventing pwn requests"
// Methodology: Parse workflow with pull_request_target in on: trigger
// Result: DangerousTriggers includes "pull_request_target"
func TestParseGitHubActionsWorkflow_DangerousTrigger_PullRequestTarget(t *testing.T) {
	workflow := `
name: Label
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if len(risk.DangerousTriggers) == 0 {
		t.Error("Expected pull_request_target to be detected as dangerous trigger")
	}

	found := false
	for _, trigger := range risk.DangerousTriggers {
		if trigger == "pull_request_target" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected 'pull_request_target' in DangerousTriggers, got: %v", risk.DangerousTriggers)
	}
}

// Test: Safe triggers (push, pull_request) do not produce false positives
// Justification: Standard push and pull_request triggers run in a safe context
//                (PR from forks don't have access to secrets for pull_request).
// Source: GitHub Actions trigger documentation
// Methodology: Parse workflow with only safe triggers
// Result: No dangerous triggers detected
func TestParseGitHubActionsWorkflow_SafeTriggers(t *testing.T) {
	workflow := `
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if len(risk.DangerousTriggers) != 0 {
		t.Errorf("Expected 0 dangerous triggers for safe workflow, got %d: %v",
			len(risk.DangerousTriggers), risk.DangerousTriggers)
	}
}

// Test: Detect script injection via untrusted PR title input
// Justification: When PR titles (controlled by external contributors) are interpolated
//                into run: steps, an attacker can craft a PR title that breaks out of
//                the intended command and executes arbitrary code.
// Source: GitHub Security Lab - "Understanding the risk of script injections"
// Methodology: Parse workflow with ${{ github.event.pull_request.title }} in run: step
// Result: HasScriptInjection is true
func TestParseGitHubActionsWorkflow_ScriptInjection(t *testing.T) {
	workflow := `
name: Greet
on: pull_request
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "PR Title: ${{ github.event.pull_request.title }}"
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if !risk.HasScriptInjection {
		t.Error("Expected HasScriptInjection=true for untrusted input in run: step")
	}
}

// Test: Safe expression usage (github.sha, github.ref) does not trigger script injection
// Justification: Expressions like github.sha and github.ref are controlled by the
//                repository and not user-supplied content, so they are safe to use in
//                run: steps.
// Source: GitHub Actions expression documentation
// Methodology: Parse workflow using safe expressions in run: steps
// Result: HasScriptInjection is false
func TestParseGitHubActionsWorkflow_SafeExpressions(t *testing.T) {
	workflow := `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "SHA: ${{ github.sha }}"
      - run: echo "Ref: ${{ github.ref }}"
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if risk.HasScriptInjection {
		t.Error("Expected HasScriptInjection=false for safe expressions (github.sha, github.ref)")
	}
}

// Test: Detect secrets exposed in logs via echo
// Justification: Secrets printed to workflow logs are visible to anyone with read access.
//                In public repos, all workflow logs are public.
// Source: GitHub Actions security best practices
// Methodology: Parse workflow with echo of ${{ secrets.* }}
// Result: SecretsInLogs is true
func TestParseGitHubActionsWorkflow_SecretsInLogs(t *testing.T) {
	workflow := `
name: Debug
on: push
jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Token is ${{ secrets.NPM_TOKEN }}"
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if !risk.SecretsInLogs {
		t.Error("Expected SecretsInLogs=true when echo of secrets detected")
	}
}

// Test: Detect missing environment protection on publish workflows
// Justification: Publish/deploy workflows without environment protection rules can
//                be triggered automatically without human approval, allowing automated
//                compromise to directly publish malicious packages.
// Source: SLSA Build Level 2+ - deployment requires authorization
// Methodology: Parse publish workflow without environment: directive
// Result: MissingEnvironmentProtection is true
func TestParseGitHubActionsWorkflow_MissingEnvironmentProtection(t *testing.T) {
	workflow := `
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm publish
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if !risk.MissingEnvironmentProtection {
		t.Error("Expected MissingEnvironmentProtection=true for publish workflow without environment:")
	}
}

// Test: Publish workflow with environment protection does not flag
// Justification: Workflows that use environment: with protection rules have a manual
//                approval gate, which is the correct security practice.
// Source: GitHub Actions environment protection rules
// Methodology: Parse publish workflow with environment: directive
// Result: MissingEnvironmentProtection is false
func TestParseGitHubActionsWorkflow_WithEnvironmentProtection(t *testing.T) {
	workflow := `
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - run: npm publish
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if risk.MissingEnvironmentProtection {
		t.Error("Expected MissingEnvironmentProtection=false when environment: is present")
	}
}

// Test: RiskCount accurately reflects total risk signals
// Justification: RiskCount is used by the scoring system to determine penalty severity.
//                It must accurately sum all distinct risk signals found.
// Source: Internal scoring methodology
// Methodology: Parse workflow with multiple risk patterns and verify count
// Result: RiskCount matches sum of individual findings
func TestParseGitHubActionsWorkflow_RiskCount(t *testing.T) {
	workflow := `
name: Insecure
on:
  pull_request_target:
    types: [opened]
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.pull_request.title }}"
      - run: npm publish
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if risk.RiskCount < 3 {
		t.Errorf("Expected RiskCount >= 3 for workflow with multiple risks, got %d", risk.RiskCount)
	}
}

// Test: Comments are ignored during parsing
// Justification: YAML comments should not be treated as active configuration.
//                A commented-out "permissions: write-all" should not trigger a finding.
// Source: YAML specification
// Methodology: Parse workflow with risky patterns only in comments
// Result: No risk signals detected
func TestParseGitHubActionsWorkflow_CommentsIgnored(t *testing.T) {
	workflow := `
name: CI
on: push
# permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # - uses: actions/checkout@v3
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
`
	risk := ParseGitHubActionsWorkflow(workflow)

	if risk.HasExcessivePermissions {
		t.Error("Expected HasExcessivePermissions=false when write-all is commented out")
	}
	if len(risk.UnpinnedActions) != 0 {
		t.Errorf("Expected 0 unpinned actions when unpinned action is commented out, got %d",
			len(risk.UnpinnedActions))
	}
}

// ===== CircleCI Parser Tests =====

// Test: Detect unpinned CircleCI orbs referenced by major version only
// Justification: Orbs referenced by major version (e.g., circleci/node@1) can be updated
//                by the orb author to include malicious code in minor/patch releases.
//                Exact version pinning reduces this risk.
// Source: CircleCI security best practices - orb versioning
// Methodology: Parse CircleCI config with orbs using major-only version
// Result: Unpinned orbs detected
func TestParseCircleCIConfig_UnpinnedOrbs(t *testing.T) {
	config := `
version: 2.1
orbs:
  node: circleci/node@5
  docker: circleci/docker@2.4.0
jobs:
  build:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
`
	risk := ParseCircleCIConfig(config)

	if len(risk.UnpinnedActions) != 1 {
		t.Errorf("Expected 1 unpinned orb (major version only), got %d: %v",
			len(risk.UnpinnedActions), risk.UnpinnedActions)
	}
}

// Test: Fully pinned CircleCI orbs produce no findings
// Justification: Orbs pinned to exact minor.patch versions are safer against
//                surprise updates.
// Source: CircleCI orb versioning documentation
// Methodology: Parse config with fully versioned orbs
// Result: No unpinned orbs
func TestParseCircleCIConfig_FullyPinnedOrbs(t *testing.T) {
	config := `
version: 2.1
orbs:
  node: circleci/node@5.1.0
  docker: circleci/docker@2.4.0
jobs:
  test:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
`
	risk := ParseCircleCIConfig(config)

	if len(risk.UnpinnedActions) != 0 {
		t.Errorf("Expected 0 unpinned orbs for fully pinned config, got %d: %v",
			len(risk.UnpinnedActions), risk.UnpinnedActions)
	}
}

// Test: Detect missing approval gate in CircleCI deploy workflow
// Justification: Deploy workflows without approval gates allow automated publishing
//                without human review, enabling compromised CI to publish malicious packages.
// Source: CircleCI workflow approval documentation
// Methodology: Parse deploy workflow without "type: approval" hold step
// Result: MissingEnvironmentProtection is true
func TestParseCircleCIConfig_MissingApproval(t *testing.T) {
	config := `
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
      - run: npm publish
workflows:
  deploy-flow:
    jobs:
      - deploy
`
	risk := ParseCircleCIConfig(config)

	if !risk.MissingEnvironmentProtection {
		t.Error("Expected MissingEnvironmentProtection=true for deploy without approval")
	}
}

// Test: CircleCI deploy with approval gate does not flag
// Justification: Workflows with "type: approval" hold steps require manual approval
//                before deploy, which is the correct security practice.
// Source: CircleCI workflow approval documentation
// Methodology: Parse deploy workflow with approval hold
// Result: MissingEnvironmentProtection is false
func TestParseCircleCIConfig_WithApproval(t *testing.T) {
	config := `
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
      - run: npm publish
workflows:
  deploy-flow:
    jobs:
      - hold:
          type: approval
      - deploy:
          requires:
            - hold
`
	risk := ParseCircleCIConfig(config)

	if risk.MissingEnvironmentProtection {
		t.Error("Expected MissingEnvironmentProtection=false when approval gate is present")
	}
}

// ===== GitLab CI Parser Tests =====

// Test: Detect missing environment protection in GitLab CI deploy stage
// Justification: GitLab CI deploy stages without environment protection or manual
//                approval allow automated publishing without oversight.
// Source: GitLab CI/CD environments documentation
// Methodology: Parse GitLab CI with deploy stage lacking "when: manual" or "environment:"
// Result: MissingEnvironmentProtection is true
func TestParseGitLabCIConfig_MissingDeployProtection(t *testing.T) {
	config := `
stages:
  - build
  - deploy

build:
  stage: build
  script:
    - npm run build

deploy:
  stage: deploy
  script:
    - npm publish
`
	risk := ParseGitLabCIConfig(config)

	if !risk.MissingEnvironmentProtection {
		t.Error("Expected MissingEnvironmentProtection=true for unprotected deploy stage")
	}
}

// Test: GitLab CI deploy with environment protection does not flag
// Justification: GitLab environments with manual gates provide proper approval control.
// Source: GitLab CI/CD environment protection documentation
// Methodology: Parse config with environment: and when: manual
// Result: MissingEnvironmentProtection is false
func TestParseGitLabCIConfig_WithDeployProtection(t *testing.T) {
	config := `
stages:
  - build
  - deploy

build:
  stage: build
  script:
    - npm run build

deploy:
  stage: deploy
  environment:
    name: production
  when: manual
  script:
    - npm publish
`
	risk := ParseGitLabCIConfig(config)

	if risk.MissingEnvironmentProtection {
		t.Error("Expected MissingEnvironmentProtection=false with environment protection")
	}
}

// Test: Detect unpinned Docker images in GitLab CI
// Justification: Docker images referenced by :latest or without a tag use mutable
//                references that can be replaced by attackers with registry access.
// Source: Docker content trust documentation; SLSA source requirements
// Methodology: Parse config with Docker images using :latest and no tag
// Result: Unpinned images detected
func TestParseGitLabCIConfig_UnpinnedDockerImages(t *testing.T) {
	config := `
build:
  image: node:latest
  script:
    - npm test

deploy:
  image: python
  script:
    - pip install twine
    - twine upload dist/*
`
	risk := ParseGitLabCIConfig(config)

	if len(risk.UnpinnedActions) != 2 {
		t.Errorf("Expected 2 unpinned Docker images, got %d: %v",
			len(risk.UnpinnedActions), risk.UnpinnedActions)
	}
}

// Test: Docker image pinned by digest does not flag
// Justification: Images pinned by SHA256 digest are immutable and cannot be replaced.
// Source: Docker content trust / OCI image specification
// Methodology: Parse config with digest-pinned Docker image
// Result: No unpinned images detected
func TestParseGitLabCIConfig_PinnedDockerImage(t *testing.T) {
	config := `
build:
  image: node@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
  script:
    - npm test
`
	risk := ParseGitLabCIConfig(config)

	if len(risk.UnpinnedActions) != 0 {
		t.Errorf("Expected 0 unpinned images for digest-pinned image, got %d: %v",
			len(risk.UnpinnedActions), risk.UnpinnedActions)
	}
}

// Test: Detect secrets in GitLab CI logs
// Justification: Echoing CI variables that may contain secrets exposes them in build logs.
// Source: GitLab CI/CD variable masking documentation
// Methodology: Parse config with echo of CI/secret variables
// Result: SecretsInLogs is true
func TestParseGitLabCIConfig_SecretsInLogs(t *testing.T) {
	config := `
build:
  image: node:18
  script:
    - echo $SECRET_TOKEN
    - npm test
`
	risk := ParseGitLabCIConfig(config)

	if !risk.SecretsInLogs {
		t.Error("Expected SecretsInLogs=true when echo of $SECRET variable detected")
	}
}

// ===== Generic CI Parser Tests =====

// Test: Generic parser detects secrets in logs for unknown platforms
// Justification: Even for less common CI platforms, printing secret-like variables
//                to logs is a security anti-pattern.
// Source: General CI/CD security best practices
// Methodology: Parse generic CI config with echo of password variable
// Result: SecretsInLogs is true
func TestParseGenericCIConfig_SecretsInLogs(t *testing.T) {
	config := `
pipeline:
  steps:
    - echo "password is $MY_PASSWORD"
    - run build
`
	risk := ParseGenericCIConfig(config, "Drone CI")

	if !risk.SecretsInLogs {
		t.Error("Expected SecretsInLogs=true for generic CI config with password echo")
	}
	if risk.Platform != "Drone CI" {
		t.Errorf("Expected platform 'Drone CI', got %q", risk.Platform)
	}
}

// ===== Dispatcher Tests =====

// Test: ParseCIWorkflowContent dispatches to correct parser
// Justification: The dispatcher must route to platform-specific parsers to apply
//                the right risk checks for each CI platform.
// Source: Internal architecture
// Methodology: Call dispatcher with different platform names and verify platform field
// Result: Correct platform in output for each input
func TestParseCIWorkflowContent_Dispatch(t *testing.T) {
	tests := []struct {
		platform string
		content  string
	}{
		{"GitHub Actions", "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"},
		{"CircleCI", "version: 2.1\njobs:\n  build:\n    docker:\n      - image: node:18\n"},
		{"GitLab CI", "build:\n  image: node:18\n  script:\n    - npm test\n"},
		{"Jenkins", "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n    }\n  }\n}\n"},
	}

	for _, tc := range tests {
		t.Run(tc.platform, func(t *testing.T) {
			risk := ParseCIWorkflowContent(tc.content, tc.platform)
			if risk.Platform != tc.platform {
				t.Errorf("Expected platform %q, got %q", tc.platform, risk.Platform)
			}
		})
	}
}

// ===== isSHAPin Tests =====

// Test: SHA pin validation for various ref formats
// Justification: Correct SHA detection is critical to avoid false positives (flagging
//                valid SHA pins) and false negatives (missing mutable tags).
// Source: Git SHA-1 and SHA-256 hash specifications
// Methodology: Test various ref formats against isSHAPin
// Result: Correct classification for each format
func TestIsSHAPin(t *testing.T) {
	tests := []struct {
		ref      string
		expected bool
	}{
		{"v4", false},
		{"v3.1.0", false},
		{"main", false},
		{"b4ffde65f46336ab88eb53be808477a3936bae11", true},  // 40-char SHA-1
		{"0c45773b623bea8c8e75f6c82b208c3cf94d9d67", true},  // 40-char SHA-1
		{"abc123", false},                                      // too short
		{"b4ffde65f46336ab88eb53be808477a3936bae1z", false},   // invalid hex
		{"", false},                                            // empty
	}

	for _, tc := range tests {
		t.Run(tc.ref, func(t *testing.T) {
			result := isSHAPin(tc.ref)
			if result != tc.expected {
				t.Errorf("isSHAPin(%q) = %v, want %v", tc.ref, result, tc.expected)
			}
		})
	}
}

// ===== CIConfigPaths Tests =====

// Test: CIConfigPaths returns expected platforms and paths
// Justification: Missing config paths would prevent risk analysis for a CI platform.
// Source: CI platform documentation for config file locations
// Methodology: Verify key platforms have config paths registered
// Result: All major platforms have at least one config path
func TestCIConfigPaths(t *testing.T) {
	paths := CIConfigPaths()

	expectedPlatforms := []string{
		"GitHub Actions", "CircleCI", "GitLab CI", "Travis CI",
		"Azure Pipelines", "Jenkins", "Drone CI", "Buildkite",
	}

	for _, platform := range expectedPlatforms {
		if _, ok := paths[platform]; !ok {
			t.Errorf("Expected CIConfigPaths to contain %q", platform)
		}
		if len(paths[platform]) == 0 {
			t.Errorf("Expected CIConfigPaths[%q] to have at least one path", platform)
		}
	}
}
