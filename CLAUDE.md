# Project Instructions for Snyft

## Core Mission

**Snyft identifies the likelihood that software packages could be compromised.**

This is NOT a CVE tracker. This is NOT a vulnerability scanner.

## What We Assess

Snyft evaluates **supply chain risk factors** that indicate a package's susceptibility to compromise:

### Risk Factors (Not Vulnerabilities)

1. **Single Maintainer** → Higher likelihood of account takeover
2. **Recent Ownership Transfer** → Potential malicious acquisition
3. **Dormant Package Reactivation** → Common compromise pattern
4. **Dangerous Install Scripts** → Direct compromise vector
5. **No Source Code Verification** → Cannot validate what you're installing
6. **Missing Provenance** → Cannot verify build integrity
7. **Low Bus Factor** → Key person risk

### What We DO NOT Do

❌ Track known CVEs (Common Vulnerabilities and Exposures)
❌ Scan for specific vulnerabilities in code
❌ Reference CVE databases
❌ Look up existing security advisories
❌ Compare against vulnerability feeds

### What We DO

✅ Assess supply chain hygiene
✅ Identify compromise likelihood factors
✅ Evaluate package maintainer practices
✅ Verify source code availability
✅ Check build reproducibility
✅ Measure community health signals
✅ Detect anomalous behavior patterns

## Design Principles

### 1. Predictive, Not Reactive

We identify packages **likely to be compromised in the future**, not packages with known past vulnerabilities.

### 2. Supply Chain Focus

We analyze the **integrity of the supply chain**, not the security of the code itself.

### 3. Academic Rigor

All risk assessments must be justified by:
- Peer-reviewed academic research
- Official security specifications (SLSA, OSSF)
- Published industry research
- Documented attack patterns

**Sources to Use:**
- Academic papers (arXiv, conference proceedings)
- SLSA specifications
- OSSF Scorecard methodology
- Sigstore documentation
- Industry whitepapers

**Sources NOT to Use:**
- CVE databases (NVD, MITRE)
- Vulnerability advisories
- Exploit databases
- Security bulletins about specific flaws

### 4. Evidence-Based Scoring

Every risk point assigned must have:
- Clear justification (why it's risky)
- Academic source citation
- Methodology documentation (what was checked)
- Evidence trail (even if no issues found)

## Scoring System

**0-14 Point Risk Score** (lower is better)

Each category scores 0-2 points:
- 0 = Good practices, low compromise risk
- 1 = Some concerns, moderate risk
- 2 = Poor practices, high compromise risk

**Categories:**
1. Publisher Control
2. Ownership Changes
3. Release Anomalies
4. Install Execution
5. Dependency Sprawl
6. Provenance
7. Health

## For All Contributors

### When Adding Features

Ask: "Does this help identify compromise likelihood?"

**Good additions:**
- Detecting typosquatting patterns
- Identifying account takeover signals
- Measuring bus factor
- Verifying build reproducibility
- Checking for install-time code execution

**Out of scope:**
- Scanning code for SQL injection
- Looking up known CVEs
- Checking dependency versions against advisories
- Static code analysis for bugs
- License compliance checking

### When Writing Tests

**Every test must include:**
```go
// Test: [Scenario being tested]
// Justification: [Why this increases compromise likelihood]
// Source: [Academic paper or specification]
// Methodology: [What APIs/methods were used]
// Result: [What the test checks for]
```

**Example:**
```go
// Test: Package with single maintainer
// Justification: Single point of compromise - if this account is
//                compromised via phishing or credential stuffing,
//                attacker gains full package control
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
// Methodology: Query maintainer count via npm registry API
// Result: Assigns 2 risk points if maintainer_count == 1
```

### When Writing Documentation

**Emphasize:**
- Supply chain compromise risk
- Likelihood of future attacks
- Proactive security posture

**Avoid:**
- Implying we find CVEs
- Suggesting we scan for vulnerabilities
- Comparing to traditional vulnerability scanners

**Correct framing:**
> "Snyft identifies packages with high supply chain risk - helping you avoid compromised dependencies before they become a problem."

**Incorrect framing:**
> ~~"Snyft finds vulnerabilities in your dependencies"~~

## Architecture Guidelines

### Multi-Platform Support

Support checking source code on:
- GitHub, GitLab, Bitbucket (Priority 1)
- Sourcehut, Codeberg (Priority 2)
- Apache/Eclipse Git (Java-specific)

### Fallback Strategies

When APIs fail:
- Web scraping for metadata
- Partial data is acceptable
- Document what couldn't be checked
- Degrade gracefully, never fail completely

### Data Sources

**Primary:**
- npm registry API
- PyPI JSON API
- Maven Central API
- GitHub/GitLab/Bitbucket APIs

**Fallback:**
- Web scraping package pages
- Repository page scraping
- Public git repository queries

## Release Guidelines

### Semantic Versioning

- v1.x.x = Major features (new categories, platforms)
- v1.x.x = Minor features (improvements to existing)
- v1.x.x = Patches (bug fixes, doc updates)

### Documentation

After every feature PR, documentation must be updated to reflect:
- What compromise risk it helps identify
- How to interpret the results
- Examples of risky vs safe patterns

The `doc-keeper` agent monitors this automatically.

## References

### Key Academic Papers

1. **Backstabber's Knife Collection** (Ohm et al., 2020)
   - Analysis of OSS supply chain attacks
   - https://arxiv.org/abs/2005.09535

2. **Towards Measuring Supply Chain Attacks** (NDSS 2020)
   - Package manager attack taxonomy
   - Focus on npm, PyPI, RubyGems

3. **Small World with High Risks** (Zimmermann et al., 2019)
   - npm dependency network analysis
   - Compromise propagation patterns

### Specifications

1. **SLSA (Supply chain Levels for Software Artifacts)**
   - https://slsa.dev/spec/v1.0/
   - Build integrity framework

2. **OSSF Scorecard**
   - https://github.com/ossf/scorecard
   - Automated security health metrics

3. **Sigstore**
   - https://www.sigstore.dev/
   - Keyless signing and transparency

## Questions?

If uncertain about whether something fits the project scope, ask:

1. "Does this help identify compromise likelihood?"
2. "Is this about supply chain integrity?"
3. "Are we looking at future risk or past vulnerabilities?"

If the answer to #3 is "past vulnerabilities" → out of scope.

---

**Remember: We predict compromise likelihood. We don't track known CVEs.**
