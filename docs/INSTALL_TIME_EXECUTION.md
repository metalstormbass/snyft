# Install-Time Execution Detection (Category 4)

Install-time scripts execute arbitrary code during package installation, often with elevated privileges. This is a primary vector for supply chain attacks.

## Scoring

- **0 risk points**: No install-time scripts detected
- **1 risk point**: Single benign install script present
- **2 risk points**: Multiple scripts OR dangerous operations detected

## Detection Coverage

### npm
Analyzes lifecycle scripts: `preinstall`, `install`, `postinstall`.

### Python (PyPI)
Fetches and analyzes `setup.py` for: `cmdclass` overrides, network imports (`requests`, `urllib`), dynamic imports (`__import__`), and standard dangerous patterns.

### Java (Maven)
Detects dangerous Maven plugins in `pom.xml`: `maven-exec-plugin`, `exec-maven-plugin`, `maven-antrun-plugin`, `groovy-maven-plugin`, `sql-maven-plugin`, and lifecycle phase bindings.

## Dangerous Patterns Detected

**High severity**: remote script execution (`curl | bash`), `eval()`, sensitive env var access (`AWS_SECRET_KEY`), executable downloads, root directory deletion, SSH/AWS config access, system auth files (`/etc/passwd`), network exfiltration tools (`nc`, `telnet`)

**Medium severity**: HTTP downloads, base64 decode piped to shell, permission changes (`chmod`), child process spawning, inline code execution (`node -e`, `python -c`)

## References

- [npm Scripts](https://docs.npmjs.com/cli/v9/using-npm/scripts)
- [Python setuptools](https://setuptools.pypa.io/en/latest/)
- [Maven Build Lifecycle](https://maven.apache.org/guides/introduction/introduction-to-the-lifecycle.html)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
