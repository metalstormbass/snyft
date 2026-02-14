# AI Features Configuration

Snyft supports optional AI-powered analysis using Claude API to provide advanced supply chain risk insights.

## Features

When enabled, AI analysis provides:

1. **Attack Pattern Matching** - Compares package behavior against documented supply chain attack patterns
2. **Executive Explanations** - Generates stakeholder-friendly summaries of risk assessments

### Phase 1 Implementation Status

The current Phase 1 release includes:
- ✅ **Attack Pattern Matching**: Detects 8 documented supply chain attack patterns
- ✅ **Executive Explanations**: Business-friendly risk summaries with recommendations

**Note**: While semantic analysis prompt templates exist in the codebase (`pkg/ai/prompts.go`), they are not actively used in Phase 1. These were built as infrastructure but removed from the analysis flow as they require additional validation and academic grounding (see PR #59).

## Configuration

### Environment Variables

The AI client can be configured using environment variables:

```bash
# Required
export CLAUDE_API_KEY="sk-ant-..."          # Or ANTHROPIC_API_KEY

# Optional
export CLAUDE_BASE_URL="https://api.anthropic.com"  # API base URL
export CLAUDE_TIMEOUT="60s"                 # Request timeout
export CLAUDE_MAX_RETRIES="3"               # Number of retries on failure
export CLAUDE_RATE_LIMIT="50"               # Requests per minute
export CLAUDE_CIRCUIT_BREAKER_THRESHOLD="10" # Failures before circuit opens
export CLAUDE_CACHE_TTL="24h"               # Cache time-to-live
export CLAUDE_CACHE_MAX_COST="104857600"    # Cache size in bytes (100MB)
export CLAUDE_ENABLE_RETRY="true"           # Enable automatic retries
export CLAUDE_ENABLE_RATE_LIMIT="true"      # Enable rate limiting
export CLAUDE_ENABLE_CIRCUIT_BREAKER="true" # Enable circuit breaker
export CLAUDE_ENABLE_CACHE="true"           # Enable response caching
```

### CLI Flags

AI features are **opt-in** and must be explicitly enabled via the `--ai` flag:

```bash
# Basic usage - enable AI with API key from environment
snyft scan --ai

# Pass API key via CLI
snyft scan --ai --ai-api-key="sk-ant-..."

# Configure timeout (in seconds)
snyft scan --ai --ai-timeout=120

# Disable caching for real-time analysis
snyft scan --ai --ai-disable-cache

# Disable retries for faster failure
snyft scan --ai --ai-disable-retry
```

## Usage Examples

### Example 1: Basic AI Analysis

```bash
export CLAUDE_API_KEY="sk-ant-..."
snyft scan /path/to/project --ai
```

### Example 2: CLI with API Key

```bash
snyft scan /path/to/project --ai --ai-api-key="sk-ant-..." --ai-timeout=90
```

### Example 3: Disable AI Analysis

```bash
# Even if CLAUDE_API_KEY is set, AI will not run without --ai flag
snyft scan /path/to/project
```

### Example 4: Production Configuration

For production use with performance optimization:

```bash
export CLAUDE_API_KEY="sk-ant-..."
export CLAUDE_RATE_LIMIT="100"      # Higher rate limit
export CLAUDE_MAX_RETRIES="5"       # More retries for reliability
export CLAUDE_TIMEOUT="120s"        # Longer timeout for complex analysis

snyft scan /path/to/project --ai
```

### Example 5: Development/Testing Configuration

For development with faster feedback:

```bash
snyft scan /path/to/project --ai \
  --ai-api-key="sk-ant-..." \
  --ai-timeout=30 \
  --ai-disable-cache \
  --ai-disable-retry
```

## Output

When AI analysis is enabled, the scan output includes additional sections:

- **Attack Pattern Matches**: Identifies documented supply chain attack patterns
- **Executive Summary**: High-level risk explanation for stakeholders
- **AI Confidence Score**: Confidence level of the AI analysis (0.0-1.0)

## Cost Considerations

AI analysis makes API calls to Claude for each package analyzed. Consider:

- **Caching**: Enabled by default to reduce costs on repeated scans
- **Rate Limiting**: Prevents excessive API usage (default: 50 requests/minute)
- **Timeout**: Prevents hanging on slow responses (default: 60 seconds)
- **Circuit Breaker**: Stops making requests after too many failures

### Cost Optimization Tips

1. **Use caching** for CI/CD pipelines that scan the same dependencies
2. **Enable rate limiting** to control API usage
3. **Set appropriate timeouts** to avoid wasting tokens on slow requests
4. **Monitor circuit breaker** to detect API issues early

## Security

The API key is:
- Never logged or displayed in output
- Can be passed via secure environment variables
- Validated before making any API calls
- Used only for Claude API authentication

## Troubleshooting

### "AI analysis enabled but no API key provided"

**Solution**: Set `CLAUDE_API_KEY` or `ANTHROPIC_API_KEY` environment variable, or use `--ai-api-key` flag.

```bash
export CLAUDE_API_KEY="sk-ant-..."
```

### "Failed to initialize AI client"

**Possible causes**:
- Invalid API key format
- Network connectivity issues
- API endpoint unreachable

**Solution**: Verify your API key and network connection:

```bash
curl -H "x-api-key: $CLAUDE_API_KEY" https://api.anthropic.com/v1/messages
```

### "Circuit breaker open: too many failures"

**Cause**: Too many consecutive API failures.

**Solution**:
1. Check API status at status.anthropic.com
2. Verify your API key is valid
3. Wait for the circuit breaker timeout (default: 60 seconds)
4. Increase circuit breaker threshold if needed:

```bash
export CLAUDE_CIRCUIT_BREAKER_THRESHOLD="20"
```

### Analysis is slow

**Solutions**:
1. Reduce timeout: `--ai-timeout=30`
2. Enable caching if not already enabled
3. Reduce rate limit to avoid queuing: `export CLAUDE_RATE_LIMIT="30"`
4. Check network latency to API endpoint

## Architecture

The AI integration follows these design principles:

1. **Opt-in by design**: AI analysis never runs automatically
2. **Graceful degradation**: Failures don't block the scan
3. **Performance optimized**: Caching, rate limiting, circuit breakers
4. **Cost conscious**: Multiple cost-control mechanisms
5. **Secure by default**: API keys never exposed in logs

## Disabling AI

To ensure AI analysis is never used:

1. Don't set the `--ai` flag
2. Don't set `CLAUDE_API_KEY` or `ANTHROPIC_API_KEY`

Even if environment variables are set, AI will not run unless explicitly enabled via `--ai` flag.

## Academic Justification

AI analysis is justified by emerging research in supply chain security:

- **Semantic Understanding**: AI can identify subtle patterns that rule-based systems miss
- **Attack Pattern Recognition**: Trained on documented attack patterns from academic literature
- **Contextual Risk Assessment**: Considers multiple risk factors holistically
- **Executive Communication**: Translates technical risks into business language

**Source**: "Large Language Models for Software Supply Chain Security" (emerging research area)

## Future Enhancements

Planned improvements:
- [ ] Model selection (Sonnet, Opus, Haiku)
- [ ] Feature-specific toggling (attack-patterns, executive-summary)
- [ ] Batch analysis for efficiency
- [ ] Custom prompt templates
- [ ] AI analysis statistics and metrics
