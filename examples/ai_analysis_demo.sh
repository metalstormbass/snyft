#!/bin/bash
# Demonstration script for Snyft AI analysis features

set -e

echo "=================================================="
echo "Snyft AI Analysis Feature Demonstration"
echo "=================================================="
echo ""

# Check if API key is set
if [ -z "$CLAUDE_API_KEY" ]; then
    echo "⚠️  No API key found!"
    echo ""
    echo "Please set CLAUDE_API_KEY environment variable:"
    echo "  export CLAUDE_API_KEY='sk-ant-...'"
    echo ""
    exit 1
fi

echo "✅ API key configured"
echo ""

# Example 1: Basic AI analysis
echo "Example 1: Basic AI analysis with environment variable"
echo "Command: snyft scan --ai"
echo ""
snyft scan --ai --format text
echo ""
echo "=================================================="
echo ""

# Example 2: AI analysis with custom timeout
echo "Example 2: AI analysis with custom timeout"
echo "Command: snyft scan --ai --ai-timeout=90"
echo ""
snyft scan --ai --ai-timeout=90 --format text
echo ""
echo "=================================================="
echo ""

# Example 3: AI analysis with caching disabled
echo "Example 3: AI analysis without caching (for testing)"
echo "Command: snyft scan --ai --ai-disable-cache"
echo ""
snyft scan --ai --ai-disable-cache --format text
echo ""
echo "=================================================="
echo ""

# Example 4: AI analysis with retry disabled
echo "Example 4: AI analysis without retry (faster failure)"
echo "Command: snyft scan --ai --ai-disable-retry"
echo ""
snyft scan --ai --ai-disable-retry --format text
echo ""
echo "=================================================="
echo ""

# Example 5: Full configuration
echo "Example 5: Full AI configuration"
echo "Command: snyft scan --ai --ai-timeout=120 --ai-disable-cache --format json"
echo ""
snyft scan --ai --ai-timeout=120 --ai-disable-cache --format json --output ai-analysis-results.json
echo ""
echo "✅ Results saved to: ai-analysis-results.json"
echo ""
echo "=================================================="
echo ""

echo "Demonstration complete!"
echo ""
echo "Key takeaways:"
echo "  ✓ AI analysis is opt-in via --ai flag"
echo "  ✓ API key is set via CLAUDE_API_KEY env var"
echo "  ✓ Timeout, caching, and retry can be configured"
echo "  ✓ All standard output formats work with AI analysis"
echo ""
echo "See docs/AI_FEATURES.md for more information"
