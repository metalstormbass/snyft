# AI Prompts Package

This package provides structured, parameterizable prompt templates for Claude API interactions focused on supply chain security analysis.

## Overview

The AI prompts system supports Snyft's core mission: **predicting package compromise likelihood**, not tracking CVEs or known vulnerabilities. All prompts are grounded in academic research and industry specifications (SLSA, OSSF Scorecard).

## Prompt Types

### Phase 1: Active Features

These prompt types are actively used in the current Snyft implementation:

#### 1. Attack Pattern Matching (`PromptTypeAttackPatternMatch`)

Compares observed package behaviors to 8 documented supply chain attack patterns:

1. **Typosquatting** - Names resembling popular packages
2. **Account Takeover** - Compromised maintainer accounts
3. **Dependency Confusion** - Public packages overriding private ones
4. **Malicious Install Script** - Code execution during installation
5. **Abandoned Package Takeover** - Dormant packages reactivated
6. **Build Chain Compromise** - CI/CD infrastructure compromise
7. **Transitive Dependency Poisoning** - Compromised deep dependencies
8. **Subdomain Takeover** - Repository URL hijacking

**Example:**
```go
prompt := ai.NewAttackPatternMatchingPrompt(
    packageName,
    ecosystem,
    analysisResult,
)

systemPrompt, userPrompt := prompt.Render()
```

**Temperature:** 0.4 (moderate for pattern matching)
**Max Tokens:** 2500

#### 2. Executive Explanation (`PromptTypeExecutiveExplanation`)

Generates stakeholder-friendly explanations for non-technical audiences.

**Target Audiences:**
- Business leaders
- Product managers
- Engineering managers
- Legal/compliance teams

**Output Sections:**
1. Executive Summary (2-3 sentences)
2. Business Impact (consequences, compliance)
3. Technical Explanation (simple language, analogies)
4. Risk Assessment (likelihood + impact)
5. Recommendations (prioritized, actionable)
6. References (academic, industry standards)

**Example:**
```go
prompt := ai.NewExecutiveExplanationPrompt(
    packageName,
    ecosystem,
    analysisResult,
    "Engineering Manager", // target audience
)

systemPrompt, userPrompt := prompt.Render()
```

**Temperature:** 0.7 (creative for accessibility)
**Max Tokens:** 3000

#### 3. Package Comparison (`PromptTypePackageComparison`)

Compares multiple packages' supply chain security postures.

**Analysis Includes:**
- Relative risk ranking
- Risk profile comparison
- Best and worst practices identification
- Package selection recommendations

**Example:**
```go
prompt := ai.NewPackageComparisonPrompt(
    packages,          // []string
    ecosystems,        // []models.Ecosystem
    analysisResults,   // []models.AnalysisResult
)

systemPrompt, userPrompt := prompt.Render()
```

**Temperature:** 0.4
**Max Tokens:** 2500

#### 4. Custom Prompts (`PromptTypeCustom`)

Create specialized prompts for future use cases.

**Example:**
```go
prompt := ai.NewCustomPrompt(
    "You are a security expert...",  // system prompt
    "Analyze {{input}}",              // user prompt template
    map[string]string{"input": "package data"},
    0.5,   // temperature
    2000,  // max tokens
)
```

### Phase 1: Infrastructure (Not Actively Used)

These prompt types exist in the codebase as infrastructure but are **not actively used** in the current Phase 1 implementation. They were removed from the analysis flow (see PR #59) as they require additional validation and academic grounding before deployment.

#### Semantic Analysis (`PromptTypeSemanticAnalysis`)

**Status**: ❌ Not actively used in Phase 1

Analyzes package metadata and behavior to identify supply chain risk patterns.

**Potential Use Cases** (future):
- Analyzing package metadata for risk indicators
- Identifying maintainer control weaknesses
- Detecting suspicious behavioral patterns
- Assessing release integrity

**Example:**
```go
prompt := ai.NewSemanticAnalysisPrompt(
    packageName,
    ecosystem,
    metadata,
    findings,
)

systemPrompt, userPrompt := prompt.Render()
// Send to Claude API (not currently called in analysis flow)
```

**Temperature:** 0.3 (analytical)
**Max Tokens:** 2000

**Why Not Active**: Removed in PR #59 as "out of scope for supply chain risk assessment" - requires more academic justification and validation before use.

#### Code Pattern Analysis (`PromptTypeCodePatternAnalysis`)

**Status**: ❌ Not actively used in Phase 1

Examines install-time scripts (npm postinstall, Python setup.py, Java pom.xml) for dangerous patterns.

**Detected Patterns** (potential):
- Network access during installation (download-and-execute)
- File system operations outside package directory
- Privilege escalation attempts
- Obfuscation techniques
- Environment variable access (credential theft)
- Child process spawning

**Example:**
```go
prompt := ai.NewCodePatternAnalysisPrompt(
    "postinstall",  // script type
    scriptContent,   // actual script code
)

systemPrompt, userPrompt := prompt.Render()
// Send to Claude API (not currently called in analysis flow)
```

**Temperature:** 0.2 (very analytical)
**Max Tokens:** 1500

**Why Not Active**: Part of semantic analysis feature set, removed with PR #59. Static analysis of install scripts is handled by the core analyzer without AI.

## Academic Foundation

All prompts reference these sources:

### Key Papers

1. **Backstabber's Knife Collection** (Ohm et al., 2020)
   - Analysis of OSS supply chain attacks
   - Finding: 90% target maintainer accounts, not code
   - https://arxiv.org/abs/2005.09535

2. **Towards Measuring Supply Chain Attacks** (NDSS 2020)
   - Package manager attack taxonomy
   - Focus on npm, PyPI, RubyGems

3. **Small World with High Risks** (Zimmermann et al., 2019)
   - npm dependency network analysis
   - Compromise propagation patterns

### Specifications

1. **SLSA Framework** (Supply chain Levels for Software Artifacts)
   - Build integrity and provenance
   - https://slsa.dev/spec/v1.0/

2. **OSSF Scorecard**
   - Automated security health metrics
   - https://github.com/ossf/scorecard

3. **Sigstore**
   - Keyless signing and transparency
   - https://www.sigstore.dev/

## Core Concepts

### What We DO

✅ Assess supply chain compromise **likelihood**
✅ Identify maintainer control weaknesses
✅ Detect suspicious package behavior patterns
✅ Evaluate build and release integrity
✅ Measure community health signals
✅ Flag anomalous activity patterns

### What We DON'T Do

❌ Track known CVEs or security advisories
❌ Scan for code vulnerabilities (SQL injection, XSS, etc.)
❌ Reference CVE databases (NVD, MITRE)
❌ Look up existing vulnerability feeds
❌ Analyze code for bugs or logic errors

## Phase 1 Implementation Status

**Active Features:**
- ✅ **Attack Pattern Matcher** - Compares package behavior to 8 documented attack patterns
- ✅ **Executive Explainer** - Generates stakeholder-friendly risk summaries
- ✅ **Package Comparison** - Comparative supply chain security analysis

**Infrastructure (Not Active):**
- ❌ **Semantic Analyzer** - Prompt templates exist but not used (removed in PR #59)
- ❌ **Code Pattern Analysis** - Prompt templates exist but not used (removed in PR #59)

**Usage**: Only attack pattern matching and executive explanation features are invoked during `snyft scan --ai`.

## Testing

Comprehensive test suite covers:

- Prompt template rendering
- Parameter substitution
- Academic reference inclusion
- System prompt content validation
- Temperature and token settings
- Edge cases and error handling

```bash
go test ./pkg/ai/... -v
```

## Example Integration (Phase 1)

This example shows how the active AI features are used in the current implementation:

```go
package main

import (
    "context"
    "github.com/metalstormbass/snyft/pkg/ai"
    "github.com/metalstormbass/snyft/pkg/models"
)

func analyzePackage(ctx context.Context, result models.AnalysisResult, aiClient *ai.Client) {
    // 1. Initialize attack pattern matcher
    matcher := ai.NewAttackMatcher(&ai.AttackMatcherConfig{
        Client: aiClient,
    })

    // 2. Detect attack patterns (Phase 1 - Active)
    attackResult, err := matcher.AnalyzePackage(ctx,
        result.Dependency.Name,
        result.Dependency.Ecosystem,
        result,
    )
    if err != nil {
        // Handle error gracefully - AI failures don't block scans
        log.Printf("Attack pattern analysis failed: %v", err)
    }

    // 3. Generate executive explanation (Phase 1 - Active)
    explainer := ai.NewExplainer(&ai.ExplainerConfig{
        Client:         aiClient,
        TargetAudience: "Engineering Manager",
        IncludeAttacks: true,
    })

    execResult, err := explainer.ExplainRisk(ctx,
        result.Dependency.Name,
        result.Dependency.Ecosystem,
        result,
    )
    if err != nil {
        log.Printf("Executive explanation failed: %v", err)
    }

    // Note: Semantic analysis prompts exist but are NOT called in Phase 1
    // semanticPrompt := ai.NewSemanticAnalysisPrompt(...) // Infrastructure only
}
```

## Future Enhancements

Potential additions:

- **Typosquatting Detection Prompt** - Identify name similarities to popular packages
- **Maintainer Reputation Analysis** - Assess maintainer credibility and history
- **Dependency Graph Analysis** - Evaluate transitive dependency risks
- **Trend Analysis Prompt** - Detect temporal patterns and anomalies
- **Risk Prioritization Prompt** - Help teams triage multiple packages

## Prompt Engineering Guidelines

When creating new prompts:

1. **Academic Grounding** - Reference peer-reviewed research or official specs
2. **Clear Scope** - Explicitly state what the AI should and shouldn't do
3. **Supply Chain Focus** - Emphasize compromise likelihood, not code quality
4. **Parameterizable** - Use `{{placeholders}}` for dynamic content
5. **Temperature Tuning** - Lower for analytical tasks, higher for creative tasks
6. **Context Limits** - Keep prompts concise; suggested max tokens for response

## License

Part of the Snyft project. See repository LICENSE for details.

## References

- [CLAUDE.md](../../CLAUDE.md) - Project instructions and scope
- [pkg/analyzer](../analyzer) - Analysis logic that generates data for prompts
- [pkg/models](../models) - Data structures used in prompt parameters
