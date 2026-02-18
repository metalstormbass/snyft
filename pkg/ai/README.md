# AI Prompts Package

Structured prompt templates for Claude API interactions focused on supply chain security analysis. All prompts are grounded in academic research and industry specifications (SLSA, OSSF Scorecard).

## Active Prompt Types

### Attack Pattern Matching (`PromptTypeAttackPatternMatch`)

Compares package behavior against 8 documented supply chain attack patterns: typosquatting, account takeover, dependency confusion, malicious install scripts, abandoned package takeover, build chain compromise, transitive dependency poisoning, subdomain takeover.

- Temperature: 0.4 | Max Tokens: 2500

### Executive Explanation (`PromptTypeExecutiveExplanation`)

Generates stakeholder-friendly risk summaries with business impact, technical explanation, and prioritized recommendations.

- Temperature: 0.7 | Max Tokens: 3000

### Package Comparison (`PromptTypePackageComparison`)

Comparative supply chain security analysis across multiple packages.

- Temperature: 0.4 | Max Tokens: 2500

### Custom Prompts (`PromptTypeCustom`)

Create specialized prompts with custom system/user templates, temperature, and token limits.

## Inactive Infrastructure

**Semantic Analysis** and **Code Pattern Analysis** prompt templates exist in `prompts.go` but are not used in the analysis flow (removed in PR #59 pending additional validation).

## Usage

```go
// Attack pattern matching
prompt := ai.NewAttackPatternMatchingPrompt(name, ecosystem, result)
systemPrompt, userPrompt := prompt.Render()

// Executive explanation
prompt := ai.NewExecutiveExplanationPrompt(name, ecosystem, result, "Engineering Manager")
systemPrompt, userPrompt := prompt.Render()
```

## Testing

```bash
go test ./pkg/ai/... -v
```

## References

- [Backstabber's Knife Collection (Ohm et al., 2020)](https://arxiv.org/abs/2005.09535)
- [SLSA Framework](https://slsa.dev/spec/v1.0/)
- [OSSF Scorecard](https://github.com/ossf/scorecard)
- [Sigstore](https://www.sigstore.dev/)
