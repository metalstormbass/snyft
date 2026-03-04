package analyzer

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Pre-compiled regexes for script analysis.
// All *regexp.Regexp objects are safe for concurrent use.

// AnalyzeScript patterns — generic dangerous script operations.
var (
	reCurlWgetPipeBash = regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(bash|sh|zsh)`)
	reEvalCall         = regexp.MustCompile(`(?i)eval\s*\(`)
	reHTTPDownload     = regexp.MustCompile(`(?i)(curl|wget|fetch|requests\.get|urllib\.request|http\.client).*http://`)
	reExecDownload     = regexp.MustCompile(`(?i)(curl|wget|fetch).*\.(sh|bash|py|pl|rb|exe|dll|so|dylib)`)
	reRmRfRoot         = regexp.MustCompile(`(?i)rm\s+(-rf|-fr)\s+/`)
	reSensitiveEnv     = regexp.MustCompile(`(?i)(process\.env|os\.environ|System\.getenv|getenv)[\[\.]?['"]?(TOKEN|KEY|SECRET|PASSWORD|API|AWS)`)
	reBase64Decode     = regexp.MustCompile(`(?i)base64\s+(-d|--decode)`)
	reChmodExec        = regexp.MustCompile(`(?i)chmod\s+(\+x|777)`)
	reProcessSpawn     = regexp.MustCompile(`(?i)(exec|spawn|child_process|subprocess)\s*\(`)
	reConfigDirAccess  = regexp.MustCompile(`(?i)(~|/root|/home)/\.(ssh|gnupg|aws|config)`)
	reSysAuthFile      = regexp.MustCompile(`(?i)/etc/(passwd|shadow|sudoers)`)
	reNodeEval         = regexp.MustCompile(`(?i)node\s+(-e|--eval)`)
	rePythonExec       = regexp.MustCompile(`(?i)python\s+(-c|<<)`)
	reNetcat           = regexp.MustCompile(`(?i)(nc|netcat|telnet)\s+`)
	reDevTCP           = regexp.MustCompile(`(?i)/dev/tcp/`)
)

// Python C extension build context indicators.
// These patterns indicate setup.py is building C/C++ extensions, which legitimately
// requires subprocess/exec calls for compilation.
// Source: Python Packaging Authority (PyPA) documentation; setuptools/distutils build_ext
var (
	rePyCExtContext = regexp.MustCompile(`(?i)(?:from\s+(?:distutils|setuptools)\s+(?:import|\.)|` +
		`\bExtension\s*\(|` +
		`\bext_modules\s*=|` +
		`\bcythonize\s*\(|` +
		`from\s+Cython\b|` +
		`import\s+Cython\b|` +
		`\bbuild_ext\b|` +
		`\bnumpy\.distutils\b|` +
		`\bnumpy\.get_include\b|` +
		`\bpybind11\b|` +
		`\bcffi\b)`)
	// Benign build commands that compilers and build tools use.
	rePyBenignBuildCmd = regexp.MustCompile(`(?i)(?:gcc|g\+\+|cc\b|c\+\+|clang|clang\+\+|` +
		`cmake|make\b|pkg-config|swig|cython|gfortran|ar\b|ld\b|` +
		`python\s+setup\.py\s+build|` +
		`sdist|bdist|build_ext|egg_info)`)
	// Truly dangerous subprocess targets — network operations, downloads, unknown script execution.
	rePyDangerousSubprocessTarget = regexp.MustCompile(`(?i)(?:curl|wget|pip\s+install|` +
		`fetch\s+http|requests\.get|urllib|` +
		`bash\s+-c|sh\s+-c|` +
		`python\s+-c|` +
		`/tmp/|/var/tmp/)`)
)

// Patterns that can be explained by C extension builds.
// When ALL detected patterns are in this set AND the file has C extension context,
// findings are downgraded.
var buildExplainablePatterns = map[string]bool{
	"subprocess call":        true,
	"os.system/popen/exec":   true,
	"exec()":                 true,
	"process spawn":          true,
	"cmdclass override":      true,
	"python -c":              true,
}

// AnalyzePythonSetup patterns — Python-specific supply chain attack patterns.
var (
	rePyCmdclass      = regexp.MustCompile(`(?i)cmdclass\s*=`)
	rePyNetImport     = regexp.MustCompile(`(?i)import\s+(requests|urllib|http\.client|httplib|httpx|aiohttp)`)
	rePyNetFromImport = regexp.MustCompile(`(?i)from\s+(requests|urllib|urllib\.request|http\.client|httplib|httpx|aiohttp)\s+import`)
	rePyDynImport     = regexp.MustCompile(`(?i)__import__\s*\(`)
	rePyOsExec        = regexp.MustCompile(`(?i)os\.(system|popen|exec[lv]p?e?)\s*\(`)
	rePySubprocess    = regexp.MustCompile(`(?i)subprocess\.(call|run|Popen|check_output|check_call|getoutput)\s*\(`)
	rePyBase64Decode  = regexp.MustCompile(`(?i)base64\.(b64decode|decodebytes|decodestring)\s*\(`)
	rePyExec          = regexp.MustCompile(`(?i)\bexec\s*\(`)
	rePySocket        = regexp.MustCompile(`(?i)socket\.(socket|create_connection|connect)\s*\(`)
	rePySocketImport  = regexp.MustCompile(`(?i)import\s+socket`)
	rePyCodecsDecode  = regexp.MustCompile(`(?i)codecs\.decode\s*\(`)
	rePyMarshalLoads  = regexp.MustCompile(`(?i)marshal\.loads\s*\(`)
	rePyCompileExec   = regexp.MustCompile(`(?i)compile\s*\([^)]*,\s*['\"]exec['\"]\s*\)`)
	rePyCtypes        = regexp.MustCompile(`(?i)(ctypes\.CDLL|ctypes\.cdll|ctypes\.windll)\s*\(`)
	rePyHexObfuscated = regexp.MustCompile(`(?i)\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){7,}`)
	rePyWebbrowser    = regexp.MustCompile(`(?i)import\s+webbrowser`)
)

// analyzeNodeScript patterns — Node.js-specific supply chain attack patterns.
var (
	reNodeChildProcess = regexp.MustCompile(`(?i)require\s*\(\s*['"]child_process['"]\s*\)`)
	reNodeNetModule    = regexp.MustCompile(`(?i)require\s*\(\s*['"](http|https|net|dgram|dns)['"]\s*\)`)
	reNodeFsWrite      = regexp.MustCompile(`(?i)(?:fs\.writeFileSync|fs\.writeFile|fs\.appendFileSync|fs\.appendFile)\s*\(\s*['"](?:/usr|/etc|/tmp|/var|/bin|/sbin|/opt|~)`)
	reNodeNewFunction  = regexp.MustCompile(`(?i)new\s+Function\s*\(`)
	reNodeBase64Buffer = regexp.MustCompile(`(?i)Buffer\.from\s*\([^)]*,\s*['"]base64['"]\s*\)`)
	reNodeExecSpawn    = regexp.MustCompile(`(?i)(?:execSync|exec|execFile|execFileSync|spawn|spawnSync|fork)\s*\(`)
	reNodeHTTPRequest  = regexp.MustCompile(`(?i)(?:https?\.get|https?\.request|fetch)\s*\(`)
	reNodeDNSLookup    = regexp.MustCompile(`(?i)(?:dns\.lookup|dns\.resolve)\s*\(`)
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

	// Dangerous patterns to check (regexes pre-compiled at package level)
	patterns := []struct {
		regex       *regexp.Regexp
		description string
		severity    string
		pattern     string
	}{
		{reCurlWgetPipeBash, "Downloads and executes remote script without verification", "HIGH", "curl/wget | bash"},
		{reEvalCall, "Uses eval() which can execute arbitrary code", "HIGH", "eval()"},
		{reHTTPDownload, "Downloads content over unencrypted HTTP", "MEDIUM", "HTTP download"},
		{reExecDownload, "Downloads executable or script files", "HIGH", "executable download"},
		{reRmRfRoot, "Recursive force delete from root directory", "HIGH", "rm -rf /"},
		{reSensitiveEnv, "Accesses sensitive environment variables", "HIGH", "sensitive env access"},
		{reBase64Decode, "Decodes base64, potentially to hide malicious code", "MEDIUM", "base64 decode"},
		{reChmodExec, "Makes files executable or grants full permissions", "MEDIUM", "chmod +x/777"},
		{reProcessSpawn, "Spawns child processes (potential for code execution)", "MEDIUM", "process spawn"},
		{reConfigDirAccess, "Accesses sensitive user configuration directories", "HIGH", "config directory access"},
		{reSysAuthFile, "Accesses system authentication files", "HIGH", "system auth file access"},
		{reNodeEval, "Executes Node.js code from command line", "MEDIUM", "node -e"},
		{rePythonExec, "Executes Python code from command line", "MEDIUM", "python -c"},
		{reNetcat, "Uses network tools that can exfiltrate data", "HIGH", "netcat/telnet"},
		{reDevTCP, "Opens raw TCP connections", "HIGH", "/dev/tcp"},
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
	// Regexes pre-compiled at package level.
	pythonPatterns := []struct {
		regex       *regexp.Regexp
		description string
		severity    string
		pattern     string
	}{
		{rePyCmdclass, "Overrides setup.py command classes (can execute arbitrary code during install/build)", "MEDIUM", "cmdclass override"},
		{rePyNetImport, "Imports network libraries during installation — common in data exfiltration attacks", "MEDIUM", "network import"},
		{rePyNetFromImport, "Imports network libraries during installation — common in data exfiltration attacks", "MEDIUM", "network from-import"},
		{rePyDynImport, "Dynamic imports can load arbitrary modules at install time", "MEDIUM", "__import__"},
		{rePyOsExec, "Executes system commands during installation — direct code execution vector", "HIGH", "os.system/popen/exec"},
		{rePySubprocess, "Spawns subprocesses during installation — used in malicious packages to run payloads", "HIGH", "subprocess call"},
		{rePyBase64Decode, "Decodes base64 data during installation — commonly used to hide malicious payloads", "HIGH", "base64 decode"},
		{rePyExec, "Executes dynamically constructed code — primary vector for obfuscated malware in setup.py", "HIGH", "exec()"},
		{rePySocket, "Creates network sockets during installation — used for reverse shells and data exfiltration", "HIGH", "socket connection"},
		{rePySocketImport, "Imports socket module during installation — potential network backdoor", "MEDIUM", "socket import"},
		{rePyCodecsDecode, "Uses codecs.decode which can obfuscate malicious strings (e.g., rot13 encoding)", "MEDIUM", "codecs.decode"},
		{rePyMarshalLoads, "Deserializes Python bytecode — can execute arbitrary code without visible source", "HIGH", "marshal.loads"},
		{rePyCompileExec, "Compiles code for execution — used to run dynamically generated malicious code", "HIGH", "compile(exec)"},
		{rePyCtypes, "Loads native shared libraries — can execute arbitrary native code", "HIGH", "ctypes library load"},
		{rePyHexObfuscated, "Contains hex-escaped byte sequences — common obfuscation technique in malicious packages", "MEDIUM", "hex-obfuscated data"},
		{rePyWebbrowser, "Imports webbrowser module during installation — can open arbitrary URLs", "MEDIUM", "webbrowser import"},
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

	// Filter for C extension build patterns.
	// Packages like psycopg2, numpy, etc. legitimately use subprocess/exec calls
	// for compilation. If the setup.py has C extension build context and all
	// dangerous patterns are explainable by build operations, downgrade severity.
	// Source: PyPA documentation on building C extensions with setuptools/distutils
	analysis.DangerousPatterns = filterBuildPatterns(setupContent, analysis.DangerousPatterns)

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

// filterBuildPatterns checks if detected patterns in a setup.py are explained by
// C extension build operations. If the file has C extension context (distutils,
// setuptools Extension, Cython, etc.) and the flagged patterns match benign build
// commands (gcc, make, cmake, etc.), they are downgraded from HIGH to LOW.
// Patterns that involve network operations or downloads are never downgraded.
func filterBuildPatterns(content string, patterns []DangerousPattern) []DangerousPattern {
	// If no C extension build context, no filtering needed
	if !rePyCExtContext.MatchString(content) {
		return patterns
	}

	// Build a line index for context-aware checks
	lines := strings.Split(content, "\n")

	var filtered []DangerousPattern
	for _, p := range patterns {
		if !buildExplainablePatterns[p.Pattern] {
			// Not a build-explainable pattern, keep as-is
			filtered = append(filtered, p)
			continue
		}

		// Find the line(s) containing this match and check context
		matchLine := findMatchLine(lines, p.Match)

		if matchLine != "" && rePyDangerousSubprocessTarget.MatchString(matchLine) {
			// Line contains dangerous targets (curl, wget, pip install, etc.)
			// Keep the pattern as-is — this is not a benign build operation
			filtered = append(filtered, p)
			continue
		}

		if matchLine != "" && rePyBenignBuildCmd.MatchString(matchLine) {
			// Line contains benign build commands — downgrade to LOW
			p.Severity = "LOW"
			p.Description = p.Description + " (likely C extension build)"
			filtered = append(filtered, p)
			continue
		}

		// Match is in a build context but line doesn't have specific build commands.
		// Downgrade to LOW since the overall file context is C extension building.
		p.Severity = "LOW"
		p.Description = p.Description + " (in C extension build context)"
		filtered = append(filtered, p)
	}

	return filtered
}

// findMatchLine returns the full line from the content that contains the match string.
func findMatchLine(lines []string, match string) string {
	for _, line := range lines {
		if strings.Contains(line, match) {
			return line
		}
	}
	return ""
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
	// Regexes pre-compiled at package level.
	nodePatterns := []struct {
		regex       *regexp.Regexp
		description string
		severity    string
		pattern     string
	}{
		{reNodeChildProcess, "Loads child_process module — enables arbitrary command execution at install time", "HIGH", "require(child_process)"},
		{reNodeNetModule, "Loads network module at install time — used for data exfiltration and payload download", "HIGH", "require(network module)"},
		{reNodeFsWrite, "Writes to system paths at install time — can modify system files or drop payloads", "HIGH", "fs.write to system path"},
		{reNodeNewFunction, "Dynamically creates function from string — equivalent to eval() for code execution", "HIGH", "new Function()"},
		{reNodeBase64Buffer, "Decodes base64 data — commonly used to hide malicious payloads in npm packages", "MEDIUM", "Buffer.from(base64)"},
		{reNodeExecSpawn, "Executes external commands via child_process — direct code execution vector", "HIGH", "child_process exec"},
		{reNodeHTTPRequest, "Makes HTTP requests at install time — used for data exfiltration or payload download", "HIGH", "HTTP request"},
		{reNodeDNSLookup, "Performs DNS lookups at install time — used for DNS-based data exfiltration", "MEDIUM", "DNS lookup"},
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

