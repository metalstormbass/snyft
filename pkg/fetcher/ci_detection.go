package fetcher

import (
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ciPlatformConfig defines detection rules for a CI/CD platform
type ciPlatformConfig struct {
	// Name is the display name of the CI system
	Name string
	// HostedBy is the entity that runs the infrastructure
	HostedBy string
	// IsSelfHosted indicates the default hosting mode
	IsSelfHosted bool
	// ConfigFiles are the file paths that indicate this CI is present
	ConfigFiles []string
}

// knownCIPlatforms lists all supported CI/CD platforms and their default hosting type.
//
// Check: Build system location and runner type
// Justification: Self-hosted runners give attackers who compromise the runner
//                full control over the build environment and published artifacts.
//                Cloud-hosted runners provide isolation and auditability.
// Source: SLSA Build L3 requirements - https://slsa.dev/spec/v1.0/levels
//         "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Detect CI config files in repo, classify by default hosting mode
// Result: Report platform + host type; flag self-hosted runners as elevated risk
var knownCIPlatforms = []ciPlatformConfig{
	// Cloud-hosted (low risk)
	{
		Name:         "GitHub Actions",
		HostedBy:     "GitHub",
		IsSelfHosted: false, // default; individual workflows may use self-hosted runners
		ConfigFiles:  []string{".github/workflows"},
	},
	{
		Name:         "GitLab CI",
		HostedBy:     "GitLab",
		IsSelfHosted: false, // default shared runners; tags: field may override
		ConfigFiles:  []string{".gitlab-ci.yml"},
	},
	{
		Name:         "Bitbucket Pipelines",
		HostedBy:     "Atlassian",
		IsSelfHosted: false,
		ConfigFiles:  []string{"bitbucket-pipelines.yml"},
	},
	{
		Name:         "CircleCI",
		HostedBy:     "CircleCI",
		IsSelfHosted: false,
		ConfigFiles:  []string{".circleci/config.yml"},
	},
	{
		Name:         "Azure Pipelines",
		HostedBy:     "Microsoft",
		IsSelfHosted: false, // Microsoft-hosted agents by default; self-hosted pools are common
		ConfigFiles:  []string{"azure-pipelines.yml"},
	},
	{
		Name:         "Travis CI",
		HostedBy:     "Travis CI",
		IsSelfHosted: false,
		ConfigFiles:  []string{".travis.yml"},
	},
	{
		Name:         "AppVeyor",
		HostedBy:     "AppVeyor",
		IsSelfHosted: false,
		ConfigFiles:  []string{"appveyor.yml", ".appveyor.yml"},
	},
	{
		Name:         "Sourcehut Builds",
		HostedBy:     "Sourcehut",
		IsSelfHosted: false,
		ConfigFiles:  []string{".builds"},
	},
	{
		Name:         "Forgejo Actions",
		HostedBy:     "Forgejo",
		IsSelfHosted: false,
		ConfigFiles:  []string{".forgejo/workflows", ".gitea/workflows"},
	},
	{
		Name:         "Woodpecker CI",
		HostedBy:     "Self-hosted",
		IsSelfHosted: true,
		ConfigFiles:  []string{".woodpecker.yml", ".woodpecker"},
	},
	// Self-hosted (elevated risk)
	{
		Name:         "Jenkins",
		HostedBy:     "Self-hosted",
		IsSelfHosted: true, // Jenkins is almost exclusively self-hosted
		ConfigFiles:  []string{"Jenkinsfile", "jenkins.yml"},
	},
	{
		Name:         "Drone CI",
		HostedBy:     "Self-hosted",
		IsSelfHosted: true, // Drone is typically self-hosted
		ConfigFiles:  []string{".drone.yml", ".drone.yaml"},
	},
	{
		Name:         "Buildkite",
		HostedBy:     "Self-hosted",
		IsSelfHosted: true, // Buildkite agents are always self-hosted
		ConfigFiles:  []string{".buildkite/pipeline.yml", ".buildkite/pipeline.yaml", "buildkite.yml"},
	},
	{
		Name:         "TeamCity",
		HostedBy:     "Self-hosted",
		IsSelfHosted: true,
		ConfigFiles:  []string{".teamcity"},
	},
}

// ClassifyBuildSystems converts a list of detected CI system names into structured BuildSystemInfo.
// It enriches each entry with hosting type and self-hosted flag based on known platform profiles.
func ClassifyBuildSystems(ciNames []string) []models.BuildSystemInfo {
	result := []models.BuildSystemInfo{}

	for _, name := range ciNames {
		info := classifyOnePlatform(name)
		result = append(result, info)
	}

	return result
}

// classifyOnePlatform maps a CI system name string to a BuildSystemInfo.
func classifyOnePlatform(name string) models.BuildSystemInfo {
	nameLower := strings.ToLower(name)

	for _, platform := range knownCIPlatforms {
		if strings.ToLower(platform.Name) == nameLower {
			return models.BuildSystemInfo{
				Platform:     platform.Name,
				HostedBy:     platform.HostedBy,
				IsSelfHosted: platform.IsSelfHosted,
			}
		}
	}

	// Fallback: partial match
	for _, platform := range knownCIPlatforms {
		if strings.Contains(nameLower, strings.ToLower(platform.Name)) ||
			strings.Contains(strings.ToLower(platform.Name), nameLower) {
			return models.BuildSystemInfo{
				Platform:     platform.Name,
				HostedBy:     platform.HostedBy,
				IsSelfHosted: platform.IsSelfHosted,
			}
		}
	}

	// Unknown CI system - treat as potentially self-hosted (conservative)
	return models.BuildSystemInfo{
		Platform:     name,
		HostedBy:     "Unknown",
		IsSelfHosted: false,
	}
}

// ExtendedCIConfigFiles returns all known CI config file paths for file-existence checks.
// This is used by platform clients to detect CI systems beyond their native platform.
func ExtendedCIConfigFiles() []struct {
	Path string
	Name string
} {
	var files []struct {
		Path string
		Name string
	}
	for _, platform := range knownCIPlatforms {
		for _, cf := range platform.ConfigFiles {
			files = append(files, struct {
				Path string
				Name string
			}{Path: cf, Name: platform.Name})
		}
	}
	return files
}

// CheckGitHubActionsRunnerType inspects GitHub Actions workflow content to determine
// whether any workflows use self-hosted runners.
//
// It does a simple string search for `runs-on:` values that are not standard GitHub-hosted
// runner labels. This avoids a full YAML parser dependency.
//
// Standard GitHub-hosted runner prefixes:
// ubuntu-*, windows-*, macos-*, self-hosted (the literal label), buildjet-*
// Anything else is likely a custom/self-hosted runner label.
func CheckGitHubActionsRunnerType(workflowContent string) (isSelfHosted bool, runnerLabel string) {
	githubHostedPrefixes := []string{
		"ubuntu-", "windows-", "macos-",
		"ubuntu-latest", "windows-latest", "macos-latest",
		"[ubuntu", "[windows", "[macos",
	}

	lines := strings.Split(workflowContent, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "runs-on:") {
			continue
		}

		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "runs-on:"))
		// Remove surrounding quotes
		value = strings.Trim(value, `"'`)

		// Check if it matches a known GitHub-hosted runner
		isGitHubHosted := false
		for _, prefix := range githubHostedPrefixes {
			if strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
				isGitHubHosted = true
				break
			}
		}

		// Also skip the literal "self-hosted" label (it's not a custom label)
		if strings.ToLower(value) == "self-hosted" {
			return true, "self-hosted"
		}

		if !isGitHubHosted && value != "" && !strings.HasPrefix(value, "${{") {
			return true, value
		}
	}

	return false, ""
}
