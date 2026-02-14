#!/bin/bash
# Demonstration script for Snyft AI analysis features

set -e

echo "=================================================="
echo "Snyft AI Analysis Feature Demonstration"
echo "=================================================="
echo ""

# Check if API key is set
if [ -z "$CLAUDE_API_KEY" ] && [ -z "$1" ]; then
    echo "⚠️  No API key found!"
    echo ""
    echo "Please set CLAUDE_API_KEY environment variable or pass it as an argument:"
    echo "  export CLAUDE_API_KEY='sk-ant-...'"
    echo "  or"
    echo "  $0 'sk-ant-...'"
    echo ""
    exit 1
fi

# Use provided API key or environment variable
API_KEY=${1:-$CLAUDE_API_KEY}

echo "✅ API key configured"
echo ""

# Example 1: Basic AI analysis
echo "Example 1: Basic AI analysis with environment variable"
echo "Command: snyft scan --ai"
echo ""
CLAUDE_API_KEY="$API_KEY" snyft scan --ai --format text
echo ""
echo "=================================================="
echo ""

# Example 2: AI analysis with CLI API key
echo "Example 2: AI analysis with CLI API key"
echo "Command: snyft scan --ai --ai-api-key='***'"
echo ""
snyft scan --ai --ai-api-key="$API_KEY" --format text
echo ""
echo "=================================================="
echo ""

# Example 3: AI analysis with custom timeout
echo "Example 3: AI analysis with custom timeout"
echo "Command: snyft scan --ai --ai-timeout=90"
echo ""
CLAUDE_API_KEY="$API_KEY" snyft scan --ai --ai-timeout=90 --format text
echo ""
echo "=================================================="
echo ""

# Example 4: AI analysis with caching disabled
echo "Example 4: AI analysis without caching (for testing)"
echo "Command: snyft scan --ai --ai-disable-cache"
echo ""
CLAUDE_API_KEY="$API_KEY" snyft scan --ai --ai-disable-cache --format text
echo ""
echo "=================================================="
echo ""

# Example 5: AI analysis with retry disabled
echo "Example 5: AI analysis without retry (faster failure)"
echo "Command: snyft scan --ai --ai-disable-retry"
echo ""
CLAUDE_API_KEY="$API_KEY" snyft scan --ai --ai-disable-retry --format text
echo ""
echo "=================================================="
echo ""

# Example 6: Full configuration
echo "Example 6: Full AI configuration"
echo "Command: snyft scan --ai --ai-timeout=120 --ai-disable-cache --format json"
echo ""
CLAUDE_API_KEY="$API_KEY" snyft scan --ai --ai-timeout=120 --ai-disable-cache --format json --output ai-analysis-results.json
echo ""
echo "✅ Results saved to: ai-analysis-results.json"
echo ""
echo "=================================================="
echo ""

echo "Demonstration complete!"
echo ""
echo "Key takeaways:"
echo "  ✓ AI analysis is opt-in via --ai flag"
echo "  ✓ API key can be set via env var or CLI flag"
echo "  ✓ Timeout, caching, and retry can be configured"
echo "  ✓ All standard output formats work with AI analysis"
echo ""
echo "See docs/AI_FEATURES.md for more information"
