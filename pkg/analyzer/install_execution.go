package analyzer

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// hasInstallTimeScripts checks if scripts include install-time hooks
func hasInstallTimeScripts(scripts map[string]string) bool {
	installScriptNames := []string{"preinstall", "install", "postinstall"}
	for _, name := range installScriptNames {
		if script, exists := scripts[name]; exists && script != "" {
			return true
		}
	}
	return false
}

// convertToModelAnalysis converts script analysis to model format
func convertToModelAnalysis(analysis ScriptAnalysis) *models.InstallScriptAnalysis {
	patterns := make([]models.DangerousPattern, len(analysis.DangerousPatterns))
	for i, p := range analysis.DangerousPatterns {
		patterns[i] = models.DangerousPattern{
			Pattern:     p.Pattern,
			Description: p.Description,
			Severity:    p.Severity,
			Match:       p.Match,
		}
	}

	return &models.InstallScriptAnalysis{
		HasDangerousPatterns: analysis.HasDangerousPatterns,
		DangerousPatterns:    patterns,
		RiskLevel:            analysis.RiskLevel,
		ScriptCount:          len(patterns),
	}
}

// scoreInstallExecution: postinstall scripts (0-2 pts)
// Scoring:
//   - 0 risk points (best): No install-time scripts
//   - 1 risk point (moderate): Single benign install script
//   - 2 risk points (worst): Multiple scripts OR dangerous content detected
func (a *Analyzer) scoreInstallExecution(result *models.AnalysisResult) models.CategoryScore {
	methodology := "Checked package manifest for install-time script hooks (preinstall, install, postinstall for npm; setup.py for PyPI; pom.xml for Maven). Analyzed script content for dangerous patterns (network requests, file system modifications, binary execution)."

	// If no install scripts present, return best score
	if !result.Metadata.HasInstallScripts || len(result.Metadata.InstallScripts) == 0 {
		return models.CategoryScore{
			Score:       2,
			RiskPoints:  0,
			Description: "No install-time scripts",
			Evidence:    "No install scripts detected in package",
			Verified:    true,
			Methodology: methodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Install-time script hooks", Status: "PASS", Detail: "No preinstall, install, or postinstall hooks found"},
				{Name: "Dangerous pattern analysis", Status: "SKIPPED", Detail: "No scripts to analyze"},
			},
		}
	}

	// If we have script analysis with dangerous patterns, return worst score
	if result.Metadata.InstallScriptAnalysis != nil && result.Metadata.InstallScriptAnalysis.HasDangerousPatterns {
		patterns := []string{}
		checks := []models.CheckResult{
			{Name: "Install-time script hooks", Status: "FAIL", Detail: "Install scripts with dangerous patterns detected"},
		}
		for _, p := range result.Metadata.InstallScriptAnalysis.DangerousPatterns {
			patterns = append(patterns, fmt.Sprintf("%s (%s)", p.Pattern, p.Severity))
			checks = append(checks, models.CheckResult{
				Name:   fmt.Sprintf("Pattern: %s", p.Pattern),
				Status: "FAIL",
				Detail: fmt.Sprintf("%s (severity: %s, match: %s)", p.Description, p.Severity, p.Match),
			})
		}

		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Dangerous install-time operations detected",
			Evidence:    fmt.Sprintf("Risk level: %s, Patterns: %s", result.Metadata.InstallScriptAnalysis.RiskLevel, strings.Join(patterns, ", ")),
			Verified:    true,
			Methodology: methodology,
			ChecksPerformed: checks,
		}
	}

	// Count install-time script hooks
	installScriptNames := []string{"preinstall", "install", "postinstall", "setup.py", "pom.xml"}
	foundScripts := []string{}

	for _, scriptName := range installScriptNames {
		if script, exists := result.Metadata.InstallScripts[scriptName]; exists && script != "" {
			foundScripts = append(foundScripts, scriptName)
		}
	}

	// Multiple install scripts without dangerous patterns = moderate risk (1 point).
	// Only dangerous content analysis (above) warrants max risk (2 points).
	// Benign install scripts (build steps, native compilation) are common in legitimate packages.
	if len(foundScripts) >= 2 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Multiple install-time scripts detected (no dangerous patterns)",
			Evidence:    fmt.Sprintf("Scripts: %s (content analyzed, no dangerous patterns found)", strings.Join(foundScripts, ", ")),
			Verified:    true,
			Methodology: methodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Install-time script hooks", Status: "WARN", Detail: fmt.Sprintf("%d install hooks found: %s", len(foundScripts), strings.Join(foundScripts, ", "))},
				{Name: "Dangerous pattern analysis", Status: "PASS", Detail: "No dangerous patterns detected in script content"},
			},
		}
	}

	// Single benign install script = moderate risk
	if len(foundScripts) == 1 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Single install-time script detected",
			Evidence:    fmt.Sprintf("Script: %s (no dangerous patterns found)", foundScripts[0]),
			Verified:    true,
			Methodology: methodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Install-time script hooks", Status: "FAIL", Detail: fmt.Sprintf("Install hook found: %s", foundScripts[0])},
				{Name: "Dangerous pattern analysis", Status: "PASS", Detail: "No dangerous patterns detected in script content"},
			},
		}
	}

	// Has scripts but none are install-time (shouldn't reach here if HasInstallScripts is correct)
	return models.CategoryScore{
		Score:       2,
		RiskPoints:  0,
		Description: "No install-time scripts",
		Evidence:    "Package has scripts but no install hooks (checked: preinstall, install, postinstall, setup.py, pom.xml)",
		Verified:    true,
		Methodology: methodology,
		ChecksPerformed: []models.CheckResult{
			{Name: "Install-time script hooks", Status: "PASS", Detail: "Scripts present but none are install-time hooks"},
		},
	}
}
