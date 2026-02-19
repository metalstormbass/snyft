# AI Features

Snyft supports optional AI-powered analysis using the Claude API for advanced supply chain risk insights.

## What AI Provides

1. **Deep Analysis** - Holistic examination of all signals to find compound risk patterns (e.g., single maintainer + dormant + sudden release = account takeover) and behavioral anomalies that rule-based scoring misses
2. **Attack Pattern Matching** - Batched comparison against 8 documented supply chain attack patterns (typosquatting, account takeover, dependency confusion, malicious install scripts, abandoned package takeover, build chain compromise, transitive dependency poisoning, subdomain takeover)
3. **Executive Summaries** - Stakeholder-friendly risk explanations with business impact and key risk areas

AI is **opt-in** and must be enabled with the `--ai` flag.

## Configuration

### Environment Variables

```bash
# Required
export CLAUDE_API_KEY="sk-ant-..."          # Or ANTHROPIC_API_KEY

# Optional tuning
export CLAUDE_RATE_LIMIT="50"               # Requests per minute (default: 50)
export CLAUDE_TIMEOUT="60s"                 # Request timeout (default: 60s)
export CLAUDE_MAX_RETRIES="3"               # Retries on failure (default: 3)
export CLAUDE_ENABLE_CACHE="true"           # Response caching (default: true)
export CLAUDE_ENABLE_CIRCUIT_BREAKER="true" # Stop after repeated failures (default: true)
```

### CLI Flags

```bash
snyft scan --ai                          # Enable AI with env key
snyft scan --ai --ai-api-key="sk-ant-..." # Pass key via CLI
snyft scan --ai --ai-timeout=120         # Custom timeout (seconds)
snyft scan --ai --ai-disable-cache       # Disable caching
snyft scan --ai --ai-disable-retry       # Disable retries
```

## Cost and Performance

- Uses 3 focused API calls per package (down from 16+ previously)
- Caching enabled by default (24h TTL) to reduce costs on repeated scans
- Rate limiting prevents excessive API usage
- Circuit breaker stops requests after too many consecutive failures
- AI failures never block the scan

## Troubleshooting

| Error | Solution |
|-------|----------|
| "no API key provided" | Set `CLAUDE_API_KEY` env var or use `--ai-api-key` |
| "Failed to initialize AI client" | Verify API key format and network connectivity |
| "Circuit breaker open" | Check API status, wait 60s, or increase `CLAUDE_CIRCUIT_BREAKER_THRESHOLD` |
| Slow analysis | Reduce `--ai-timeout`, enable caching, check network latency |

## Security

The API key is never logged or displayed in output. It can be passed via environment variables or CLI flag and is only used for Claude API authentication.
