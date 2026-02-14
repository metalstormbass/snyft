package analyzer

import (
	"regexp"
	"strings"
)

// ScriptAnalysis contains the result of analyzing install-time scripts
type ScriptAnalysis struct {
	HasDangerousPatterns bool
	DangerousPatterns    []DangerousPattern
	RiskLevel            string // HIGH, MEDIUM, LOW
}

// DangerousPattern represents a dangerous operation found in a script
type DangerousPattern struct {
	Pattern     string
	Description string
	Severity    string
	Match       string
}

// AnalyzeScript analyzes a script for dangerous patterns
func AnalyzeScript(scriptContent string) ScriptAnalysis {
	analysis := ScriptAnalysis{
		DangerousPatterns: []DangerousPattern{},
	}

	// Define dangerous patterns to check
	patterns := []struct {
		regex       *regexp.Regexp
		description string
		severity    string
		pattern     string
	}{
		{
			regex:       regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(bash|sh|zsh)`),
			description: "Downloads and executes remote script without verification",
			severity:    "HIGH",
			pattern:     "curl/wget | bash",
		},
		{
			regex:       regexp.MustCompile(`(?i)eval\s*\(`),
			description: "Uses eval() which can execute arbitrary code",
			severity:    "HIGH",
			pattern:     "eval()",
		},
		{
			regex:       regexp.MustCompile(`(?i)(curl|wget|fetch|requests\.get|urllib\.request|http\.client).*http://`),
			description: "Downloads content over unencrypted HTTP",
			severity:    "MEDIUM",
			pattern:     "HTTP download",
		},
		{
			regex:       regexp.MustCompile(`(?i)(curl|wget|fetch).*\.(sh|bash|py|pl|rb|exe|dll|so|dylib)`),
			description: "Downloads executable or script files",
			severity:    "HIGH",
			pattern:     "executable download",
		},
		{
			regex:       regexp.MustCompile(`(?i)rm\s+(-rf|-fr)\s+/`),
			description: "Recursive force delete from root directory",
			severity:    "HIGH",
			pattern:     "rm -rf /",
		},
		{
			regex:       regexp.MustCompile(`(?i)(process\.env|os\.environ|System\.getenv|getenv)[\[\.]?['"]?(TOKEN|KEY|SECRET|PASSWORD|API|AWS)`),
			description: "Accesses sensitive environment variables",
			severity:    "HIGH",
			pattern:     "sensitive env access",
		},
		{
			regex:       regexp.MustCompile(`(?i)base64\s+(-d|--decode)`),
			description: "Decodes base64, potentially to hide malicious code",
			severity:    "MEDIUM",
			pattern:     "base64 decode",
		},
		{
			regex:       regexp.MustCompile(`(?i)chmod\s+(\+x|777)`),
			description: "Makes files executable or grants full permissions",
			severity:    "MEDIUM",
			pattern:     "chmod +x/777",
		},
		{
			regex:       regexp.MustCompile(`(?i)(exec|spawn|child_process|subprocess)\s*\(`),
			description: "Spawns child processes (potential for code execution)",
			severity:    "MEDIUM",
			pattern:     "process spawn",
		},
		{
			regex:       regexp.MustCompile(`(?i)(~|/root|/home)/\.(ssh|gnupg|aws|config)`),
			description: "Accesses sensitive user configuration directories",
			severity:    "HIGH",
			pattern:     "config directory access",
		},
		{
			regex:       regexp.MustCompile(`(?i)/etc/(passwd|shadow|sudoers)`),
			description: "Accesses system authentication files",
			severity:    "HIGH",
			pattern:     "system auth file access",
		},
		{
			regex:       regexp.MustCompile(`(?i)node\s+(-e|--eval)`),
			description: "Executes Node.js code from command line",
			severity:    "MEDIUM",
			pattern:     "node -e",
		},
		{
			regex:       regexp.MustCompile(`(?i)python\s+(-c|<<)`),
			description: "Executes Python code from command line",
			severity:    "MEDIUM",
			pattern:     "python -c",
		},
		{
			regex:       regexp.MustCompile(`(?i)(nc|netcat|telnet)\s+`),
			description: "Uses network tools that can exfiltrate data",
			severity:    "HIGH",
			pattern:     "netcat/telnet",
		},
		{
			regex:       regexp.MustCompile(`(?i)/dev/tcp/`),
			description: "Opens raw TCP connections",
			severity:    "HIGH",
			pattern:     "/dev/tcp",
		},
	}

	// Check for each dangerous pattern
	for _, p := range patterns {
		if matches := p.regex.FindAllString(scriptContent, -1); len(matches) > 0 {
			for _, match := range matches {
				analysis.DangerousPatterns = append(analysis.DangerousPatterns, DangerousPattern{
					Pattern:     p.pattern,
					Description: p.description,
					Severity:    p.severity,
					Match:       strings.TrimSpace(match),
				})
			}
		}
	}

	// Determine overall risk level
	analysis.HasDangerousPatterns = len(analysis.DangerousPatterns) > 0

	if analysis.HasDangerousPatterns {
		highCount := 0
		for _, p := range analysis.DangerousPatterns {
			if p.Severity == "HIGH" {
				highCount++
			}
		}
		if highCount > 0 {
			analysis.RiskLevel = "HIGH"
		} else {
			analysis.RiskLevel = "MEDIUM"
		}
	} else {
		analysis.RiskLevel = "LOW"
	}

	return analysis
}

// AnalyzeNPMScripts analyzes npm package scripts for dangerous patterns
func AnalyzeNPMScripts(scripts map[string]string) ScriptAnalysis {
	// Focus on install-time scripts
	installScripts := []string{"preinstall", "install", "postinstall"}

	combinedScript := ""
	for _, scriptName := range installScripts {
		if script, exists := scripts[scriptName]; exists && script != "" {
			combinedScript += script + "\n"
		}
	}

	return AnalyzeScript(combinedScript)
}

// AnalyzePythonSetup analyzes Python setup.py for dangerous patterns
func AnalyzePythonSetup(setupContent string) ScriptAnalysis {
	analysis := AnalyzeScript(setupContent)

	// Additional Python-specific checks
	pythonPatterns := []struct {
		regex       *regexp.Regexp
		description string
		severity    string
		pattern     string
	}{
		{
			regex:       regexp.MustCompile(`(?i)cmdclass\s*=`),
			description: "Overrides setup.py command classes (can execute arbitrary code)",
			severity:    "MEDIUM",
			pattern:     "cmdclass override",
		},
		{
			regex:       regexp.MustCompile(`(?i)import\s+(requests|urllib|http\.client)`),
			description: "Makes network requests during installation",
			severity:    "MEDIUM",
			pattern:     "network import",
		},
		{
			regex:       regexp.MustCompile(`(?i)__import__\s*\(`),
			description: "Dynamic imports (can load arbitrary modules)",
			severity:    "MEDIUM",
			pattern:     "__import__",
		},
	}

	for _, p := range pythonPatterns {
		if matches := p.regex.FindAllString(setupContent, -1); len(matches) > 0 {
			for _, match := range matches {
				analysis.DangerousPatterns = append(analysis.DangerousPatterns, DangerousPattern{
					Pattern:     p.pattern,
					Description: p.description,
					Severity:    p.severity,
					Match:       strings.TrimSpace(match),
				})
			}
		}
	}

	// Recalculate risk level
	analysis.HasDangerousPatterns = len(analysis.DangerousPatterns) > 0
	if analysis.HasDangerousPatterns {
		highCount := 0
		for _, p := range analysis.DangerousPatterns {
			if p.Severity == "HIGH" {
				highCount++
			}
		}
		if highCount > 0 {
			analysis.RiskLevel = "HIGH"
		} else {
			analysis.RiskLevel = "MEDIUM"
		}
	} else {
		analysis.RiskLevel = "LOW"
	}

	return analysis
}

// AnalyzeJavaPOM analyzes Java pom.xml for dangerous plugin configurations
func AnalyzeJavaPOM(pomContent string) ScriptAnalysis {
	analysis := ScriptAnalysis{
		DangerousPatterns: []DangerousPattern{},
	}

	// Check for dangerous Maven plugins
	dangerousPlugins := []struct {
		pattern     string
		description string
		severity    string
	}{
		{
			pattern:     "maven-exec-plugin",
			description: "Executes arbitrary commands during build",
			severity:    "HIGH",
		},
		{
			pattern:     "maven-antrun-plugin",
			description: "Runs Ant tasks during build (can execute arbitrary code)",
			severity:    "HIGH",
		},
		{
			pattern:     "exec-maven-plugin",
			description: "Executes system commands during build",
			severity:    "HIGH",
		},
		{
			pattern:     "groovy-maven-plugin",
			description: "Executes Groovy scripts during build",
			severity:    "MEDIUM",
		},
		{
			pattern:     "sql-maven-plugin",
			description: "Executes SQL during build",
			severity:    "MEDIUM",
		},
	}

	for _, plugin := range dangerousPlugins {
		if strings.Contains(pomContent, plugin.pattern) {
			analysis.DangerousPatterns = append(analysis.DangerousPatterns, DangerousPattern{
				Pattern:     plugin.pattern,
				Description: plugin.description,
				Severity:    plugin.severity,
				Match:       plugin.pattern,
			})
		}
	}

	// Check for executions bound to lifecycle phases
	if strings.Contains(pomContent, "<phase>install</phase>") ||
		strings.Contains(pomContent, "<phase>compile</phase>") ||
		strings.Contains(pomContent, "<phase>generate-sources</phase>") {
		// Only flag if there are already dangerous plugins
		if len(analysis.DangerousPatterns) > 0 {
			analysis.DangerousPatterns = append(analysis.DangerousPatterns, DangerousPattern{
				Pattern:     "lifecycle execution",
				Description: "Plugin execution bound to build lifecycle phases",
				Severity:    "MEDIUM",
				Match:       "lifecycle phase binding",
			})
		}
	}

	// Determine overall risk level
	analysis.HasDangerousPatterns = len(analysis.DangerousPatterns) > 0

	if analysis.HasDangerousPatterns {
		highCount := 0
		for _, p := range analysis.DangerousPatterns {
			if p.Severity == "HIGH" {
				highCount++
			}
		}
		if highCount > 0 {
			analysis.RiskLevel = "HIGH"
		} else {
			analysis.RiskLevel = "MEDIUM"
		}
	} else {
		analysis.RiskLevel = "LOW"
	}

	return analysis
}
