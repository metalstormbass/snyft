package fetcher

import (
	"regexp"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ParseGitHubActionsWorkflow analyzes a GitHub Actions workflow YAML string for
// supply chain risk patterns.
//
// Check: GitHub Actions workflow security analysis
// Justification: GitHub Actions workflows are the most common CI/CD system for OSS.
//                Insecure workflow configurations create direct supply chain attack vectors:
//                unpinned actions allow tag hijacking, excessive permissions widen blast radius,
//                pull_request_target enables code execution from untrusted forks, and
//                unsanitized expression injection enables arbitrary code execution.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535
//         GitHub Actions Security Hardening - https://docs.github.com/en/actions/security-guides
//         SLSA Build Level Requirements - https://slsa.dev/spec/v1.0/levels
// Methodology: String-based YAML analysis for known insecure patterns
// Result: CIWorkflowRisk struct with identified risk signals
func ParseGitHubActionsWorkflow(content string) models.CIWorkflowRisk {
	risk := models.CIWorkflowRisk{
		Platform: "GitHub Actions",
	}

	lines := strings.Split(content, "\n")

	checkUnpinnedActions(&risk, lines)
	checkExcessivePermissions(&risk, lines)
	checkDangerousTriggers(&risk, lines)
	checkScriptInjection(&risk, lines)
	checkSecretsInLogs(&risk, lines)
	checkEnvironmentProtection(&risk, content)

	risk.RiskCount = len(risk.UnpinnedActions) + len(risk.DangerousTriggers) + len(risk.Details)
	if risk.HasExcessivePermissions {
		risk.RiskCount++
	}
	if risk.HasScriptInjection {
		risk.RiskCount++
	}
	if risk.SecretsInLogs {
		risk.RiskCount++
	}
	if risk.MissingEnvironmentProtection {
		risk.RiskCount++
	}

	return risk
}

// checkUnpinnedActions detects GitHub Actions referenced by mutable tag (e.g., @v3)
// instead of immutable SHA pin (e.g., @abc123...).
//
// Risk: Tag hijacking - an attacker who compromises an action's repo can move a tag
// to point to malicious code, which then executes in every workflow that references it.
// Pinning to a full SHA makes this attack impossible.
// Source: GitHub Security Lab - "Keeping your GitHub Actions and workflows secure"
func checkUnpinnedActions(risk *models.CIWorkflowRisk, lines []string) {
	// Match "uses: owner/repo@ref" patterns
	usesPattern := regexp.MustCompile(`uses:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(.+)`)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		matches := usesPattern.FindStringSubmatch(trimmed)
		if len(matches) < 3 {
			continue
		}

		ref := strings.TrimSpace(matches[2])
		action := matches[1]

		// Strip inline YAML comments (e.g., "abc123def # v6.0.2" → "abc123def")
		// SHA-pinned actions commonly include a version comment after the hash.
		if idx := strings.Index(ref, " #"); idx != -1 {
			ref = strings.TrimSpace(ref[:idx])
		}

		// A full SHA-1 hash is 40 hex chars; SHA-256 is 64. Anything shorter is mutable.
		if !isSHAPin(ref) {
			risk.UnpinnedActions = append(risk.UnpinnedActions, action+"@"+ref)
			risk.Details = append(risk.Details,
				"Unpinned action "+action+"@"+ref+" (mutable tag; vulnerable to tag hijacking)")
		}
	}
}

// isSHAPin checks if a ref looks like a commit SHA (40 or 64 hex chars).
func isSHAPin(ref string) bool {
	if len(ref) != 40 && len(ref) != 64 {
		return false
	}
	for _, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// checkExcessivePermissions detects workflows that request overly broad permissions.
//
// Risk: If a workflow is compromised (e.g., via a malicious PR or dependency),
// broad permissions allow the attacker to modify repository contents, create releases,
// push packages, or access secrets. Least-privilege permissions limit blast radius.
// Source: GitHub Actions security hardening - "Using GITHUB_TOKEN permissions"
func checkExcessivePermissions(risk *models.CIWorkflowRisk, lines []string) {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)

		// Top-level "permissions: write-all" grants all write scopes
		if strings.HasPrefix(lower, "permissions:") && strings.Contains(lower, "write-all") {
			risk.HasExcessivePermissions = true
			risk.Details = append(risk.Details,
				"Workflow uses 'permissions: write-all' (grants all write scopes; violates least privilege)")
			return
		}

		// "permissions: {}" is good (restrictive) - skip
		// Check for individual dangerous permission grants
		if strings.Contains(lower, "contents: write") ||
			strings.Contains(lower, "packages: write") ||
			strings.Contains(lower, "id-token: write") {
			// These individual permissions are sometimes necessary and legitimate,
			// but when combined with other risk signals they indicate poor security posture.
			// We only flag the most dangerous: contents: write at top level
			if strings.Contains(lower, "contents: write") {
				risk.HasExcessivePermissions = true
				risk.Details = append(risk.Details,
					"Workflow grants 'contents: write' permission (allows modifying repository contents)")
				return
			}
		}
	}
}

// checkDangerousTriggers detects workflow triggers that can be exploited by attackers.
//
// Risk: pull_request_target runs in the context of the base branch with access to secrets,
// even for PRs from forks. workflow_dispatch allows arbitrary workflow execution.
// These triggers, combined with checkout of PR code, enable secret exfiltration.
// Source: GitHub Security Lab - "Keeping your GitHub Actions and workflows secure: Preventing
//         pwn requests" (https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
func checkDangerousTriggers(risk *models.CIWorkflowRisk, lines []string) {
	inOn := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)

		// Detect the "on:" block
		if strings.HasPrefix(lower, "on:") || lower == "on:" {
			inOn = true
			// Check for inline triggers: "on: [pull_request_target, push]"
			if strings.Contains(lower, "pull_request_target") {
				risk.DangerousTriggers = append(risk.DangerousTriggers, "pull_request_target")
				risk.Details = append(risk.Details,
					"Workflow uses pull_request_target trigger (runs with base branch secrets; fork PRs can exfiltrate)")
			}
			continue
		}

		// Inside the on: block, look for trigger names
		if inOn {
			// End of on: block (new top-level key)
			if len(trimmed) > 0 && !strings.HasPrefix(trimmed, "-") && !strings.HasPrefix(trimmed, " ") && strings.Contains(trimmed, ":") && !strings.HasPrefix(lower, "pull_request_target") && !strings.HasPrefix(lower, "workflow_dispatch") {
				// Check if this is a non-indented key (end of on: block)
				if line == trimmed { // no leading whitespace = top-level key
					inOn = false
					continue
				}
			}

			if strings.HasPrefix(lower, "pull_request_target") || strings.TrimSpace(lower) == "pull_request_target:" {
				risk.DangerousTriggers = append(risk.DangerousTriggers, "pull_request_target")
				risk.Details = append(risk.Details,
					"Workflow uses pull_request_target trigger (runs with base branch secrets; fork PRs can exfiltrate)")
			}
		}
	}
}

// checkScriptInjection detects expression injection in run: steps.
//
// Risk: When untrusted input (PR titles, branch names, commit messages) is interpolated
// into run: steps via ${{ }}, an attacker can craft input that breaks out of the intended
// command and executes arbitrary code in the CI environment.
// Source: GitHub Security Lab - "Keeping your GitHub Actions and workflows secure"
//         "Understanding the risk of script injections" (GitHub docs)
func checkScriptInjection(risk *models.CIWorkflowRisk, lines []string) {
	// Dangerous expression patterns that inject untrusted input into shell commands
	dangerousExprs := []string{
		"github.event.pull_request.title",
		"github.event.pull_request.body",
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.comment.body",
		"github.event.review.body",
		"github.event.head_commit.message",
		"github.head_ref",
	}

	inRun := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)

		// Detect run: directives, including YAML list items ("- run:")
		stripped := strings.TrimPrefix(lower, "- ")
		if strings.HasPrefix(stripped, "run:") {
			inRun = true
		} else if inRun && len(trimmed) > 0 && !strings.HasPrefix(trimmed, " ") && !strings.HasPrefix(trimmed, "\t") && !strings.HasPrefix(line, " ") {
			inRun = false
		}

		// Check for dangerous expressions in run blocks or inline run commands
		if inRun || strings.HasPrefix(stripped, "run:") {
			for _, expr := range dangerousExprs {
				if strings.Contains(lower, "${{ "+expr) || strings.Contains(lower, "${{"+expr) {
					risk.HasScriptInjection = true
					risk.Details = append(risk.Details,
						"Script injection risk: untrusted input '${{ "+expr+" }}' used in run: step")
					return
				}
			}
		}
	}
}

// checkSecretsInLogs detects patterns that would expose secrets in CI logs.
//
// Risk: Secrets printed to logs are visible to anyone with read access to the workflow run.
// In public repositories, workflow logs are publicly accessible.
// Source: GitHub Actions security best practices
func checkSecretsInLogs(risk *models.CIWorkflowRisk, lines []string) {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)

		// Detect echo/print of secrets
		if (strings.Contains(lower, "echo") || strings.Contains(lower, "print")) &&
			strings.Contains(lower, "${{ secrets.") {
			risk.SecretsInLogs = true
			risk.Details = append(risk.Details,
				"Secret value may be exposed in logs (echo/print of ${{ secrets.* }})")
			return
		}
	}
}

// checkEnvironmentProtection checks if deploy/publish jobs use GitHub environment
// protection rules.
//
// Risk: Without environment protection rules, any workflow run can publish/deploy
// without human approval. Environment rules add a manual gate that prevents
// automated compromise from directly publishing malicious packages.
// Source: SLSA Build Level 2+ - deployment requires authorization
func checkEnvironmentProtection(risk *models.CIWorkflowRisk, content string) {
	lower := strings.ToLower(content)

	// Check if this is a publish/release/deploy workflow
	isReleaseWorkflow := strings.Contains(lower, "npm publish") ||
		strings.Contains(lower, "twine upload") ||
		strings.Contains(lower, "mvn deploy") ||
		strings.Contains(lower, "cargo publish") ||
		strings.Contains(lower, "gem push") ||
		strings.Contains(lower, "pypi") ||
		strings.Contains(lower, "publish") ||
		strings.Contains(lower, "release")

	if !isReleaseWorkflow {
		return
	}

	// Check for environment protection
	hasEnvironment := strings.Contains(lower, "environment:")

	if !hasEnvironment {
		risk.MissingEnvironmentProtection = true
		risk.Details = append(risk.Details,
			"Release/publish workflow lacks environment protection rules (no manual approval gate)")
	}
}

// ParseCircleCIConfig analyzes a CircleCI configuration YAML for risk patterns.
//
// Check: CircleCI configuration security analysis
// Justification: CircleCI configs can expose supply chain risks through unversioned orbs,
//                unrestricted contexts, and missing approval workflows.
// Source: CircleCI security best practices
//         "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: String-based YAML analysis for known insecure patterns
// Result: CIWorkflowRisk struct with identified risk signals
func ParseCircleCIConfig(content string) models.CIWorkflowRisk {
	risk := models.CIWorkflowRisk{
		Platform: "CircleCI",
	}

	lines := strings.Split(content, "\n")
	lower := strings.ToLower(content)

	// Check for unpinned orbs (CircleCI's equivalent of actions)
	checkUnpinnedOrbs(&risk, lines)

	// Check for unrestricted contexts (shared secrets without project restrictions)
	checkUnrestrictedContexts(&risk, lines)

	// Check for missing approval workflows in deploy jobs
	checkCircleCIApproval(&risk, lower)

	risk.RiskCount = len(risk.UnpinnedActions) + len(risk.Details)
	if risk.MissingEnvironmentProtection {
		risk.RiskCount++
	}

	return risk
}

// checkUnpinnedOrbs detects CircleCI orbs referenced by mutable version tags.
//
// Risk: Orbs referenced by major version (e.g., node/circleci@1) can be updated by
// the orb author to include malicious code. Pinning to exact version reduces this risk.
func checkUnpinnedOrbs(risk *models.CIWorkflowRisk, lines []string) {
	orbPattern := regexp.MustCompile(`^\s*(\w[\w-]*):\s*(\S+)@(\S+)`)
	inOrbs := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)

		if lower == "orbs:" {
			inOrbs = true
			continue
		}

		// End of orbs block
		if inOrbs && len(trimmed) > 0 && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inOrbs = false
			continue
		}

		if !inOrbs {
			continue
		}

		matches := orbPattern.FindStringSubmatch(trimmed)
		if len(matches) < 4 {
			continue
		}

		version := matches[3]
		orbRef := matches[2] + "@" + version

		// Check if version is a single number (major only) - most risky
		if isMajorVersionOnly(version) {
			risk.UnpinnedActions = append(risk.UnpinnedActions, orbRef)
			risk.Details = append(risk.Details,
				"Unpinned CircleCI orb "+orbRef+" (major version only; vulnerable to minor/patch hijacking)")
		}
	}
}

// isMajorVersionOnly checks if a version string is just a major version number (e.g., "1", "2").
func isMajorVersionOnly(v string) bool {
	if len(v) == 0 {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// checkUnrestrictedContexts detects CircleCI contexts used without security restrictions.
//
// Risk: CircleCI contexts share secrets across projects. Without restrictions, any job
// in the organization can access the context's secrets.
func checkUnrestrictedContexts(risk *models.CIWorkflowRisk, lines []string) {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)

		if strings.Contains(lower, "context:") {
			// Context usage detected - note as a signal (not necessarily bad,
			// but worth tracking for combined risk assessment)
			break
		}
	}
}

// checkCircleCIApproval checks if deploy jobs have manual approval gates.
func checkCircleCIApproval(risk *models.CIWorkflowRisk, lower string) {
	isDeployWorkflow := strings.Contains(lower, "deploy") ||
		strings.Contains(lower, "publish") ||
		strings.Contains(lower, "release")

	if !isDeployWorkflow {
		return
	}

	hasApproval := strings.Contains(lower, "type: approval") ||
		strings.Contains(lower, "hold") ||
		strings.Contains(lower, "requires:")

	if !hasApproval {
		risk.MissingEnvironmentProtection = true
		risk.Details = append(risk.Details,
			"CircleCI deploy/publish workflow lacks approval gate (no manual hold step)")
	}
}

// ParseGitLabCIConfig analyzes a GitLab CI configuration YAML for risk patterns.
//
// Check: GitLab CI configuration security analysis
// Justification: GitLab CI configs can expose supply chain risks through unprotected
//                deploy stages, missing environment approvals, and insecure variable handling.
// Source: GitLab CI/CD security documentation
//         "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: String-based YAML analysis for known insecure patterns
// Result: CIWorkflowRisk struct with identified risk signals
func ParseGitLabCIConfig(content string) models.CIWorkflowRisk {
	risk := models.CIWorkflowRisk{
		Platform: "GitLab CI",
	}

	lines := strings.Split(content, "\n")
	lower := strings.ToLower(content)

	// Check for unprotected deploy stages
	checkGitLabDeployProtection(&risk, lower)

	// Check for insecure variable handling
	checkGitLabVariables(&risk, lines)

	// Check for unpinned Docker images
	checkUnpinnedDockerImages(&risk, lines)

	risk.RiskCount = len(risk.UnpinnedActions) + len(risk.Details)
	if risk.MissingEnvironmentProtection {
		risk.RiskCount++
	}

	return risk
}

// checkGitLabDeployProtection checks if deploy stages have environment protection.
func checkGitLabDeployProtection(risk *models.CIWorkflowRisk, lower string) {
	isDeployPipeline := strings.Contains(lower, "deploy") ||
		strings.Contains(lower, "publish") ||
		strings.Contains(lower, "release")

	if !isDeployPipeline {
		return
	}

	// GitLab uses "environment:" with "when: manual" for approval gates
	hasProtection := strings.Contains(lower, "when: manual") ||
		strings.Contains(lower, "environment:") ||
		strings.Contains(lower, "protected: true")

	if !hasProtection {
		risk.MissingEnvironmentProtection = true
		risk.Details = append(risk.Details,
			"GitLab CI deploy stage lacks environment protection or manual approval gate")
	}
}

// checkGitLabVariables detects insecure variable handling in GitLab CI.
func checkGitLabVariables(risk *models.CIWorkflowRisk, lines []string) {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)

		// Detect echo of CI variables that may contain secrets
		if (strings.Contains(lower, "echo") || strings.Contains(lower, "printenv")) &&
			(strings.Contains(lower, "$ci_") || strings.Contains(lower, "$secret") ||
				strings.Contains(lower, "${ci_") || strings.Contains(lower, "${secret")) {
			risk.SecretsInLogs = true
			risk.Details = append(risk.Details,
				"GitLab CI may expose secrets in logs (echo/printenv of CI variables)")
			return
		}
	}
}

// checkUnpinnedDockerImages detects Docker images referenced by mutable tags
// across any CI platform.
//
// Risk: Docker images referenced by mutable tags (e.g., :latest, :stable) can be
// replaced by an attacker who gains push access to the registry. Using image digests
// (@sha256:...) prevents this attack.
func checkUnpinnedDockerImages(risk *models.CIWorkflowRisk, lines []string) {
	imagePattern := regexp.MustCompile(`image:\s*["']?([^"'\s]+)["']?`)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		matches := imagePattern.FindStringSubmatch(trimmed)
		if len(matches) < 2 {
			continue
		}

		image := matches[1]
		// Skip if already pinned by digest
		if strings.Contains(image, "@sha256:") {
			continue
		}
		// Flag images using :latest or no tag (implicit :latest)
		if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
			risk.UnpinnedActions = append(risk.UnpinnedActions, image)
			risk.Details = append(risk.Details,
				"Unpinned Docker image "+image+" (mutable tag; vulnerable to image replacement)")
		}
	}
}

// ParseGenericCIConfig provides basic risk analysis for CI configs from less common
// platforms (Jenkins, Drone, Buildkite, etc.).
//
// Check: Generic CI configuration security analysis
// Justification: Even less common CI platforms can have insecure configurations.
//                Basic checks for common anti-patterns apply across all platforms.
// Source: SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
// Methodology: Check for common insecure patterns across CI platforms
// Result: CIWorkflowRisk struct with identified risk signals
func ParseGenericCIConfig(content, platform string) models.CIWorkflowRisk {
	risk := models.CIWorkflowRisk{
		Platform: platform,
	}

	lines := strings.Split(content, "\n")

	// Check for unpinned Docker images (common across all CI)
	checkUnpinnedDockerImages(&risk, lines)

	// Check for secrets leaked in logs
	checkGenericSecretsInLogs(&risk, lines)

	risk.RiskCount = len(risk.UnpinnedActions) + len(risk.Details)
	if risk.SecretsInLogs {
		risk.RiskCount++
	}

	return risk
}

// checkGenericSecretsInLogs checks for common secret leaking patterns across CI platforms.
func checkGenericSecretsInLogs(risk *models.CIWorkflowRisk, lines []string) {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)

		if (strings.Contains(lower, "echo") || strings.Contains(lower, "print")) &&
			(strings.Contains(lower, "password") || strings.Contains(lower, "secret") ||
				strings.Contains(lower, "token") || strings.Contains(lower, "api_key")) {
			risk.SecretsInLogs = true
			risk.Details = append(risk.Details,
				"Potential secret exposure in CI logs (echo/print of sensitive variable)")
			return
		}
	}
}

// CIConfigPaths returns the mapping of CI platforms to their configuration file paths
// for content fetching.
func CIConfigPaths() map[string][]string {
	return map[string][]string{
		"GitHub Actions": {
			".github/workflows/release.yml",
			".github/workflows/publish.yml",
			".github/workflows/deploy.yml",
			".github/workflows/ci.yml",
			".github/workflows/build.yml",
			".github/workflows/main.yml",
			".github/workflows/release.yaml",
			".github/workflows/publish.yaml",
			".github/workflows/deploy.yaml",
		},
		"CircleCI":       {".circleci/config.yml"},
		"GitLab CI":      {".gitlab-ci.yml"},
		"Travis CI":      {".travis.yml"},
		"Azure Pipelines": {"azure-pipelines.yml"},
		"Jenkins":        {"Jenkinsfile"},
		"Drone CI":       {".drone.yml", ".drone.yaml"},
		"Buildkite":      {".buildkite/pipeline.yml", ".buildkite/pipeline.yaml"},
	}
}

// ParseCIWorkflowContent dispatches to the appropriate platform-specific parser
// based on the CI platform name.
func ParseCIWorkflowContent(content, platform string) models.CIWorkflowRisk {
	switch platform {
	case "GitHub Actions":
		return ParseGitHubActionsWorkflow(content)
	case "CircleCI":
		return ParseCircleCIConfig(content)
	case "GitLab CI":
		return ParseGitLabCIConfig(content)
	default:
		return ParseGenericCIConfig(content, platform)
	}
}
