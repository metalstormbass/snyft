# Security Policy

## Supported Versions

Currently, snyft is in active development. We support the latest version from the main branch.

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow responsible disclosure practices:

### 🔒 Private Reporting (Preferred)

**DO NOT** open public GitHub issues for security vulnerabilities.

**Report via:**
- Email: michaelbraunbass@gmail.com with subject line: `[SECURITY] snyft vulnerability`
- GitHub Security Advisory: Use the "Security" tab → "Report a vulnerability" (private disclosure)

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if available)
- Your contact information for follow-up

### Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Initial response | 48 hours |
| Vulnerability assessment | 7 days |
| Fix development | 14-30 days (depending on severity) |
| Coordinated disclosure | 90 days or upon fix release |

### Disclosure Process

We follow **coordinated disclosure** practices:

1. **Report received** → We acknowledge receipt within 48 hours
2. **Validation** → We confirm and assess the vulnerability
3. **Fix development** → We develop and test a patch
4. **Coordinated release** → We work with you on disclosure timing
5. **Public disclosure** → We publish a security advisory and release the fix

### Security Advisories

Security advisories will be published:
- In the GitHub Security Advisory section
- In release notes for patched versions
- Referenced in CHANGELOG.md

### Recognition

We appreciate security researchers who help keep snyft secure:
- Researchers will be credited in security advisories (unless anonymity is requested)
- We follow a "thanks but no bounty" model (no financial rewards currently)

## Security Best Practices for Users

When using snyft:

1. **API Tokens:** Use read-only GitHub tokens with minimal scope
   ```bash
   export GITHUB_TOKEN="ghp_readonly_token"
   ```

2. **Dependency Analysis:** Review findings carefully; automated tools can have false positives

3. **Private Repositories:** Be cautious running snyft on private codebases from untrusted sources

4. **Supply Chain Security:** Verify snyft's own dependencies regularly
   ```bash
   go list -m all  # Check Go module dependencies
   ```

## Security Considerations

As a supply chain security tool, snyft itself should be scrutinized:

- **Dependencies:** Minimal external dependencies (see go.mod)
- **API Access:** Makes external API calls to npm, PyPI, Maven, GitHub, OSSF
- **Data Privacy:** Does not transmit your code; only queries package metadata
- **Network Access:** Requires internet access to query package registries

## Out of Scope

The following are **not** considered security vulnerabilities:
- False positives in dependency analysis
- Missing features for specific package ecosystems
- Performance issues
- Feature requests

## Questions?

For security-related questions that don't involve a specific vulnerability, open a public discussion in the GitHub Discussions section.

---

Thank you for helping keep snyft and its users safe! 🔒
