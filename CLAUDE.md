# Project Instructions for Snyft

## Core Mission

**Snyft answers one question: "What is the risk that this library gets compromised?"**

Every feature, every check, every test must serve this question. If it doesn't help assess the likelihood of supply chain compromise, it doesn't belong here.

This is NOT a CVE tracker. This is NOT a vulnerability scanner. This is NOT a best practices advisor.

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
❌ Recommend or enforce best practices
❌ Provide security hardening guidance

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

**0-20 Point Risk Score** (lower is better)

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
8. Governance
9. Release Security
10. Package Maturity

## For All Contributors

### When Adding Features

Ask: **"Does this help answer whether this library could be compromised?"**

If the answer is no, don't build it.

**Good additions** (directly assess compromise risk):
- Detecting typosquatting patterns → attacker impersonation
- Identifying account takeover signals → compromised publisher
- Measuring bus factor → single point of failure for takeover
- Verifying build reproducibility → tampered artifacts
- Checking for install-time code execution → direct compromise vector
- Parsing CI/CD configs → release pipeline integrity
- Checking governance files → project health signals

**Out of scope** (does not assess compromise risk):
- Scanning code for SQL injection
- Looking up known CVEs
- Checking dependency versions against advisories
- Static code analysis for bugs
- License compliance checking
- Recommending best practices or security guidelines
- Telling users how to fix or improve their packages
- Code quality metrics unrelated to supply chain integrity

### When Writing Tests

**The single guiding principle: every test must validate that we correctly assess supply chain compromise risk.** Tests should verify that the tool accurately answers "could this package be compromised?" — not that code runs without errors, not that APIs return data, not that formatting looks right.

**Bad tests** (do NOT write these):
- Tests that only check API connectivity or response parsing
- Tests that verify output formatting without tying it to risk assessment
- Tests that cover code paths just for coverage numbers
- Tests that validate internal plumbing unrelated to compromise detection

**Good tests** validate risk signals:
- "A package with 1 maintainer scores higher risk than one with 5"
- "A package with a recent ownership transfer is flagged"
- "A dormant package that suddenly publishes triggers an anomaly"
- "An API failure does NOT incorrectly inflate the risk score"

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
- Framing output as best practice recommendations
- Suggesting how to fix or improve identified risks

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

1. **"Does this help answer: what is the risk that this library gets compromised?"**
2. "Is this about supply chain integrity?"
3. "Are we looking at future risk or past vulnerabilities?"

If the answer to #1 is no → out of scope.
If the answer to #3 is "past vulnerabilities" → out of scope.

---

**The only question that matters: "What is the risk that this library gets compromised?" Everything we build must serve that question. We don't track CVEs. We don't prescribe best practices. We assess compromise likelihood.**
