# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Security fixes only |
| Older versions | No |

## Reporting a Vulnerability

If you discover a security vulnerability in Snyft, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Email: **security@snyft.dev** (or use [GitHub Security Advisories](https://github.com/metalstormbass/snyft/security/advisories/new))
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Fix timeline** communicated after assessment
- **Credit** given in release notes (unless you prefer anonymity)

### Scope

The following are in scope for security reports:

- Command injection via crafted manifest files or package names
- Path traversal during file scanning
- Credential leakage (API tokens in logs, reports, or error messages)
- Denial of service via crafted input
- Dependencies with known vulnerabilities

### Out of Scope

- Risk scores produced by Snyft (these are assessments, not guarantees)
- Issues in third-party APIs that Snyft queries
- Rate limiting or availability of external services

## Security Practices

Snyft follows these security practices:

- **No credentials stored**: API tokens are read from environment variables only
- **No code execution**: Snyft never executes code from scanned packages
- **Read-only analysis**: Snyft only reads manifest files and queries public APIs
- **Dependency management**: Dependencies are kept minimal and reviewed
- **CI enforcement**: All PRs require passing tests and linting
