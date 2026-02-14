package analyzer

import (
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/ai"
)

// TestNewAnalyzer_WithAIConfig verifies that AI configuration can be passed to the analyzer
func TestNewAnalyzer_WithAIConfig(t *testing.T) {
	// Create a config with a dummy API key
	config := ai.DefaultConfig()
	config.APIKey = "sk-ant-test-key-12345"
	config.Timeout = 30 * time.Second

	// Create analyzer with AI config
	a := NewAnalyzer(WithAIConfig(config))

	// Verify AI is enabled
	if !a.aiEnabled {
		t.Error("Expected AI to be enabled with valid config")
	}

	// Verify client was initialized
	if a.claudeClient == nil {
		t.Error("Expected Claude client to be initialized")
	}
}

// TestNewAnalyzer_WithAIDisabled verifies that AI can be explicitly disabled
func TestNewAnalyzer_WithAIDisabled(t *testing.T) {
	a := NewAnalyzer(WithAIDisabled())

	// Verify AI is disabled
	if a.aiEnabled {
		t.Error("Expected AI to be disabled")
	}

	// Verify client is nil
	if a.claudeClient != nil {
		t.Error("Expected Claude client to be nil when disabled")
	}
}

// TestNewAnalyzer_WithNilConfig verifies graceful handling of nil config
func TestNewAnalyzer_WithNilConfig(t *testing.T) {
	a := NewAnalyzer(WithAIConfig(nil))

	// Verify AI is disabled
	if a.aiEnabled {
		t.Error("Expected AI to be disabled with nil config")
	}

	// Verify client is nil
	if a.claudeClient != nil {
		t.Error("Expected Claude client to be nil with nil config")
	}
}

// TestNewAnalyzer_WithEmptyAPIKey verifies graceful handling of empty API key
func TestNewAnalyzer_WithEmptyAPIKey(t *testing.T) {
	config := ai.DefaultConfig()
	config.APIKey = "" // Empty API key

	a := NewAnalyzer(WithAIConfig(config))

	// Verify AI is disabled
	if a.aiEnabled {
		t.Error("Expected AI to be disabled with empty API key")
	}

	// Verify client is nil
	if a.claudeClient != nil {
		t.Error("Expected Claude client to be nil with empty API key")
	}
}

// TestNewAnalyzer_DefaultBehavior verifies default behavior without options
func TestNewAnalyzer_DefaultBehavior(t *testing.T) {
	// Ensure no API key in environment for this test
	// (In real environment, it might be set, so we just verify the analyzer is created)
	a := NewAnalyzer()

	// Verify analyzer is properly initialized
	if a.npmClient == nil {
		t.Error("Expected NPM client to be initialized")
	}
	if a.pypiClient == nil {
		t.Error("Expected PyPI client to be initialized")
	}
	if a.mavenClient == nil {
		t.Error("Expected Maven client to be initialized")
	}
	if a.githubClient == nil {
		t.Error("Expected GitHub client to be initialized")
	}

	// AI state depends on environment, so we don't assert it here
}

// TestNewAnalyzer_MultipleOptions verifies that multiple options can be applied
func TestNewAnalyzer_MultipleOptions(t *testing.T) {
	config := ai.DefaultConfig()
	config.APIKey = "sk-ant-test-key"

	// Apply multiple options (even though it's redundant in this case)
	a := NewAnalyzer(
		WithAIConfig(config),
		WithAIDisabled(), // This should override the config
	)

	// Verify AI is disabled (last option wins)
	if a.aiEnabled {
		t.Error("Expected AI to be disabled (last option should win)")
	}
}
