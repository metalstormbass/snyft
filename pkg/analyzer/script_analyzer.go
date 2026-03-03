package analyzer

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Compiled regexes for Maven POM plugin analysis.
// Used by AnalyzeJavaPOM to extract and inspect plugin configurations.
var (
	pluginBlockRe   = regexp.MustCompile(`(?s)<plugin>.*?</plugin>`)
	executableRe    = regexp.MustCompile(`(?i)<executable>\s*([^<\s]+)\s*</executable>`)
	antExecRe       = regexp.MustCompile(`(?i)<exec\b[^>]*\bexecutable\s*=\s*["']([^"']+)["']`)
	antBareExecRe   = regexp.MustCompile(`(?i)<exec\b`)
	antGetTaskRe    = regexp.MustCompile(`(?i)<get\b`)
	antScriptTaskRe = regexp.MustCompile(`(?i)<script\b`)
)

// dangerousExecutables are commands that indicate supply chain risk when used
// in Maven build plugins — network tools, shell interpreters, and scripting
// languages that can download or execute arbitrary payloads.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — documents
// shell interpreter and network tool abuse as Java supply chain attack vectors.
var dangerousExecutables = map[string]bool{
	"curl": true, "wget": true,
	"bash": true, "sh": true, "zsh": true, "csh": true, "ksh": true,
	"powershell": true, "pwsh": true, "cmd": true,
	"python": true, "python3": true, "ruby": true, "perl": true, "php": true,
	"nc": true, "netcat": true, "ncat": true, "telnet": true,
}

// safeBuildExecutables are standard build tools whose presence in Maven build
// plugins is expected and does not indicate supply chain risk.
var safeBuildExecutables = map[string]bool{
	"java": true, "javac": true, "javadoc": true, "jar": true,
	"mvn": true, "gradle": true, "ant": true,
	"git": true, "svn": true,
	"make": true, "cmake": true,
	"go": true, "cargo": true, "rustc": true,
	"npm": true, "npx": true, "node": true, "yarn": true, "pnpm": true,
	"docker": true, "podman": true,
}

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

	// Additional Python-specific checks for supply chain attack patterns.
	// These patterns are documented in real-world attacks against PyPI packages.
	// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
	//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
	pythonPatterns := []struct {
		regex       *regexp.Regexp
		description string
		severity    string
		pattern     string
	}{
		{
			regex:       regexp.MustCompile(`(?i)cmdclass\s*=`),
			description: "Overrides setup.py command classes (can execute arbitrary code during install/build)",
			severity:    "MEDIUM",
			pattern:     "cmdclass override",
		},
		{
			regex:       regexp.MustCompile(`(?i)import\s+(requests|urllib|http\.client|httplib|httpx|aiohttp)`),
			description: "Imports network libraries during installation — common in data exfiltration attacks",
			severity:    "MEDIUM",
			pattern:     "network import",
		},
		{
			regex:       regexp.MustCompile(`(?i)from\s+(requests|urllib|urllib\.request|http\.client|httplib|httpx|aiohttp)\s+import`),
			description: "Imports network libraries during installation — common in data exfiltration attacks",
			severity:    "MEDIUM",
			pattern:     "network from-import",
		},
		{
			regex:       regexp.MustCompile(`(?i)__import__\s*\(`),
			description: "Dynamic imports can load arbitrary modules at install time",
			severity:    "MEDIUM",
			pattern:     "__import__",
		},
		{
			regex:       regexp.MustCompile(`(?i)os\.(system|popen|exec[lv]p?e?)\s*\(`),
			description: "Executes system commands during installation — direct code execution vector",
			severity:    "HIGH",
			pattern:     "os.system/popen/exec",
		},
		{
			regex:       regexp.MustCompile(`(?i)subprocess\.(call|run|Popen|check_output|check_call|getoutput)\s*\(`),
			description: "Spawns subprocesses during installation — used in malicious packages to run payloads",
			severity:    "HIGH",
			pattern:     "subprocess call",
		},
		{
			regex:       regexp.MustCompile(`(?i)base64\.(b64decode|decodebytes|decodestring)\s*\(`),
			description: "Decodes base64 data during installation — commonly used to hide malicious payloads",
			severity:    "HIGH",
			pattern:     "base64 decode",
		},
		{
			regex:       regexp.MustCompile(`(?i)\bexec\s*\(`),
			description: "Executes dynamically constructed code — primary vector for obfuscated malware in setup.py",
			severity:    "HIGH",
			pattern:     "exec()",
		},
		{
			regex:       regexp.MustCompile(`(?i)socket\.(socket|create_connection|connect)\s*\(`),
			description: "Creates network sockets during installation — used for reverse shells and data exfiltration",
			severity:    "HIGH",
			pattern:     "socket connection",
		},
		{
			regex:       regexp.MustCompile(`(?i)import\s+socket`),
			description: "Imports socket module during installation — potential network backdoor",
			severity:    "MEDIUM",
			pattern:     "socket import",
		},
		{
			regex:       regexp.MustCompile(`(?i)codecs\.decode\s*\(`),
			description: "Uses codecs.decode which can obfuscate malicious strings (e.g., rot13 encoding)",
			severity:    "MEDIUM",
			pattern:     "codecs.decode",
		},
		{
			regex:       regexp.MustCompile(`(?i)marshal\.loads\s*\(`),
			description: "Deserializes Python bytecode — can execute arbitrary code without visible source",
			severity:    "HIGH",
			pattern:     "marshal.loads",
		},
		{
			regex:       regexp.MustCompile(`(?i)compile\s*\([^)]*,\s*['\"]exec['\"]\s*\)`),
			description: "Compiles code for execution — used to run dynamically generated malicious code",
			severity:    "HIGH",
			pattern:     "compile(exec)",
		},
		{
			regex:       regexp.MustCompile(`(?i)(ctypes\.CDLL|ctypes\.cdll|ctypes\.windll)\s*\(`),
			description: "Loads native shared libraries — can execute arbitrary native code",
			severity:    "HIGH",
			pattern:     "ctypes library load",
		},
		{
			regex:       regexp.MustCompile(`(?i)\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){7,}`),
			description: "Contains hex-escaped byte sequences — common obfuscation technique in malicious packages",
			severity:    "MEDIUM",
			pattern:     "hex-obfuscated data",
		},
		{
			regex:       regexp.MustCompile(`(?i)import\s+webbrowser`),
			description: "Imports webbrowser module during installation — can open arbitrary URLs",
			severity:    "MEDIUM",
			pattern:     "webbrowser import",
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

// isExecPluginDangerous checks if an exec-maven-plugin or maven-exec-plugin
// configuration contains dangerous operations (network tools, shell interpreters)
// rather than standard build operations (Java execution, compilation).
func isExecPluginDangerous(pluginBlock string) bool {
	matches := executableRe.FindAllStringSubmatch(pluginBlock, -1)
	for _, m := range matches {
		exe := strings.ToLower(strings.TrimSpace(m[1]))
		if dangerousExecutables[exe] {
			return true
		}
		if !safeBuildExecutables[exe] {
			return true // Unknown executable — flag conservatively
		}
	}
	if len(matches) > 0 {
		return false // All executables are safe build tools
	}

	// No <executable> — check for <mainClass> (java goal, safe)
	if strings.Contains(pluginBlock, "<mainClass>") {
		return false
	}

	// Plugin declared without execution configuration — not dangerous
	return false
}

// isAntRunPluginDangerous checks if a maven-antrun-plugin configuration contains
// operations indicating supply chain risk (arbitrary command execution, downloads,
// scripting) rather than safe file and build operations (mkdir, copy, echo).
func isAntRunPluginDangerous(pluginBlock string) bool {
	// Check for <get> task — Ant's file download task
	if antGetTaskRe.MatchString(pluginBlock) {
		return true
	}

	// Check for <script> task — runs arbitrary scripting code
	if antScriptTaskRe.MatchString(pluginBlock) {
		return true
	}

	// Check for <exec> tasks and inspect what they run
	matches := antExecRe.FindAllStringSubmatch(pluginBlock, -1)
	for _, m := range matches {
		exe := strings.ToLower(strings.TrimSpace(m[1]))
		if dangerousExecutables[exe] {
			return true
		}
		if !safeBuildExecutables[exe] {
			return true // Unknown executable — flag conservatively
		}
	}
	if len(matches) > 0 {
		return false // All exec tasks use safe build executables
	}

	// Check for <exec> without parseable executable attribute
	if antBareExecRe.MatchString(pluginBlock) {
		return true
	}

	// Only standard Ant tasks (mkdir, copy, echo, etc.)
	return false
}

// scriptFileExtensions lists file extensions considered as executable script files.
var scriptFileExtensions = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".ts": true,
	".sh": true, ".bash": true,
	".py": true, ".rb": true, ".pl": true, ".php": true,
}

// scriptInterpreters lists commands that execute script files.
var scriptInterpreters = map[string]bool{
	"node": true, "nodejs": true,
	"python": true, "python3": true,
	"sh": true, "bash": true, "zsh": true,
	"ruby": true, "perl": true, "php": true,
}

// commandSeparatorRe splits chained shell commands.
var commandSeparatorRe = regexp.MustCompile(`\s*(?:&&|\|\||;)\s*`)

// resolveScriptFilePaths extracts file paths from npm hook commands.
// Given "node scripts/postinstall.js", returns ["scripts/postinstall.js"].
// Handles chained commands (&&, ||, ;) and skips inline code flags (-e, -c).
func resolveScriptFilePaths(hookCommand string) []string {
	segments := commandSeparatorRe.Split(hookCommand, -1)

	var paths []string
	seen := map[string]bool{}

	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}

		parts := strings.Fields(seg)
		if len(parts) == 0 {
			continue
		}

		// Direct script execution: ./scripts/install.sh or scripts/setup.sh
		first := parts[0]
		if strings.HasPrefix(first, "./") || (strings.Contains(first, "/") && scriptFileExtensions[filepath.Ext(first)]) {
			path := strings.TrimPrefix(first, "./")
			if scriptFileExtensions[filepath.Ext(path)] && !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
			continue
		}

		// Interpreter + file: node scripts/postinstall.js
		if !scriptInterpreters[first] {
			continue
		}

		for i := 1; i < len(parts); i++ {
			arg := parts[i]
			// Skip flags like -e, --eval, -c, --require, etc.
			if strings.HasPrefix(arg, "-") {
				// Flags that take a value: skip the next arg too
				if arg == "-e" || arg == "--eval" || arg == "-c" || arg == "--require" || arg == "-r" {
					i++ // skip the flag's value
				}
				continue
			}
			// First non-flag arg is the script file
			path := strings.TrimPrefix(arg, "./")
			if scriptFileExtensions[filepath.Ext(path)] && !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
			break
		}
	}

	return paths
}

// analyzeNodeScript analyzes a Node.js script file for dangerous patterns.
// Extends the generic AnalyzeScript with Node.js-specific supply chain attack patterns.
func analyzeNodeScript(content string) ScriptAnalysis {
	analysis := AnalyzeScript(content)

	// Node.js-specific patterns documented in real-world npm supply chain attacks.
	// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
	//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
	nodePatterns := []struct {
		regex       *regexp.Regexp
		description string
		severity    string
		pattern     string
	}{
		{
			regex:       regexp.MustCompile(`(?i)require\s*\(\s*['"]child_process['"]\s*\)`),
			description: "Loads child_process module — enables arbitrary command execution at install time",
			severity:    "HIGH",
			pattern:     "require(child_process)",
		},
		{
			regex:       regexp.MustCompile(`(?i)require\s*\(\s*['"](http|https|net|dgram|dns)['"]\s*\)`),
			description: "Loads network module at install time — used for data exfiltration and payload download",
			severity:    "HIGH",
			pattern:     "require(network module)",
		},
		{
			regex:       regexp.MustCompile(`(?i)(?:fs\.writeFileSync|fs\.writeFile|fs\.appendFileSync|fs\.appendFile)\s*\(\s*['"](?:/usr|/etc|/tmp|/var|/bin|/sbin|/opt|~)`),
			description: "Writes to system paths at install time — can modify system files or drop payloads",
			severity:    "HIGH",
			pattern:     "fs.write to system path",
		},
		{
			regex:       regexp.MustCompile(`(?i)new\s+Function\s*\(`),
			description: "Dynamically creates function from string — equivalent to eval() for code execution",
			severity:    "HIGH",
			pattern:     "new Function()",
		},
		{
			regex:       regexp.MustCompile(`(?i)Buffer\.from\s*\([^)]*,\s*['"]base64['"]\s*\)`),
			description: "Decodes base64 data — commonly used to hide malicious payloads in npm packages",
			severity:    "MEDIUM",
			pattern:     "Buffer.from(base64)",
		},
		{
			regex:       regexp.MustCompile(`(?i)(?:execSync|exec|execFile|execFileSync|spawn|spawnSync|fork)\s*\(`),
			description: "Executes external commands via child_process — direct code execution vector",
			severity:    "HIGH",
			pattern:     "child_process exec",
		},
		{
			regex:       regexp.MustCompile(`(?i)(?:https?\.get|https?\.request|fetch)\s*\(`),
			description: "Makes HTTP requests at install time — used for data exfiltration or payload download",
			severity:    "HIGH",
			pattern:     "HTTP request",
		},
		{
			regex:       regexp.MustCompile(`(?i)(?:dns\.lookup|dns\.resolve)\s*\(`),
			description: "Performs DNS lookups at install time — used for DNS-based data exfiltration",
			severity:    "MEDIUM",
			pattern:     "DNS lookup",
		},
	}

	for _, p := range nodePatterns {
		if matches := p.regex.FindAllString(content, -1); len(matches) > 0 {
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

// isNodeFile returns true if the file path has a Node.js extension.
func isNodeFile(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".js" || ext == ".mjs" || ext == ".cjs" || ext == ".ts"
}

// AnalyzeNPMScriptFiles reads the actual script files referenced by npm install
// hooks and analyzes their content for dangerous patterns using the bare git clone.
// The readFile function reads a file from the repository (via GetCloneFileContent or GetFileContent).
// Returns dangerous patterns found, annotated with the source file and hook name.
func AnalyzeNPMScriptFiles(scripts map[string]string, readFile func(path string) (string, error)) []DangerousPattern {
	installHooks := []string{"preinstall", "install", "postinstall"}

	var patterns []DangerousPattern
	seen := map[string]bool{}

	for _, hookName := range installHooks {
		cmd, exists := scripts[hookName]
		if !exists || cmd == "" {
			continue
		}

		filePaths := resolveScriptFilePaths(cmd)
		for _, path := range filePaths {
			if seen[path] {
				continue
			}
			seen[path] = true

			content, err := readFile(path)
			if err != nil || content == "" {
				continue
			}

			// Use Node.js-aware analysis for JS/TS files, generic for shell scripts
			var analysis ScriptAnalysis
			if isNodeFile(path) {
				analysis = analyzeNodeScript(content)
			} else {
				analysis = AnalyzeScript(content)
			}

			for _, p := range analysis.DangerousPatterns {
				patterns = append(patterns, DangerousPattern{
					Pattern:     p.Pattern,
					Description: fmt.Sprintf("%s (in %s, referenced by %s hook)", p.Description, path, hookName),
					Severity:    p.Severity,
					Match:       fmt.Sprintf("%s: %s", path, p.Match),
				})
			}
		}
	}

	return patterns
}

// AnalyzeJavaPOM analyzes Java pom.xml for dangerous plugin configurations.
// For exec-maven-plugin, maven-exec-plugin, and maven-antrun-plugin, the analysis
// is context-aware: it inspects what the plugin actually does rather than flagging
// by name alone. Legitimate build uses (running Java, compiling, file operations)
// are not flagged; dangerous uses (network tools, shell interpreters, downloads) are.
func AnalyzeJavaPOM(pomContent string) ScriptAnalysis {
	analysis := ScriptAnalysis{
		DangerousPatterns: []DangerousPattern{},
	}

	pluginBlocks := pluginBlockRe.FindAllString(pomContent, -1)

	// Context-aware plugins: inspect configuration to determine risk.
	// These plugins CAN execute arbitrary code but are also used legitimately
	// by well-established projects (Spring, JMH benchmarks, etc.).
	contextAwarePlugins := []struct {
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
	}

	for _, plugin := range contextAwarePlugins {
		if !strings.Contains(pomContent, plugin.pattern) {
			continue
		}
		foundInBlock := false
		dangerous := false
		for _, block := range pluginBlocks {
			if !strings.Contains(block, plugin.pattern) {
				continue
			}
			foundInBlock = true
			switch plugin.pattern {
			case "exec-maven-plugin", "maven-exec-plugin":
				dangerous = isExecPluginDangerous(block)
			case "maven-antrun-plugin":
				dangerous = isAntRunPluginDangerous(block)
			default:
				dangerous = true
			}
			break
		}
		// Flag if config is dangerous, or if we couldn't extract
		// the plugin block (conservative fallback)
		if dangerous || !foundInBlock {
			analysis.DangerousPatterns = append(analysis.DangerousPatterns, DangerousPattern{
				Pattern:     plugin.pattern,
				Description: plugin.description,
				Severity:    plugin.severity,
				Match:       plugin.pattern,
			})
		}
	}

	// Always-flag plugins: these have no legitimate safe configuration
	alwaysFlagPlugins := []struct {
		pattern     string
		description string
		severity    string
	}{
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

	for _, plugin := range alwaysFlagPlugins {
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
