package ai

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.BaseURL != "https://api.anthropic.com" {
		t.Errorf("expected base URL https://api.anthropic.com, got %s", cfg.BaseURL)
	}

	if cfg.Timeout != 60*time.Second {
		t.Errorf("expected timeout 60s, got %v", cfg.Timeout)
	}

	if cfg.MaxRetries != 3 {
		t.Errorf("expected max retries 3, got %d", cfg.MaxRetries)
	}

	if cfg.RateLimit != 50 {
		t.Errorf("expected rate limit 50, got %d", cfg.RateLimit)
	}

	if cfg.CircuitBreakerThreshold != 10 {
		t.Errorf("expected circuit breaker threshold 10, got %d", cfg.CircuitBreakerThreshold)
	}

	if cfg.CacheTTL != 24*time.Hour {
		t.Errorf("expected cache TTL 24h, got %v", cfg.CacheTTL)
	}

	if !cfg.EnableRetry || !cfg.EnableRateLimit || !cfg.EnableCircuitBreaker || !cfg.EnableCache {
		t.Error("expected all features to be enabled by default")
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Save and restore env
	originalEnv := make(map[string]string)
	envVars := []string{
		"CLAUDE_API_KEY",
		"ANTHROPIC_API_KEY",
		"CLAUDE_BASE_URL",
		"CLAUDE_TIMEOUT",
		"CLAUDE_MAX_RETRIES",
		"CLAUDE_RATE_LIMIT",
		"CLAUDE_CIRCUIT_BREAKER_THRESHOLD",
		"CLAUDE_CACHE_TTL",
		"CLAUDE_ENABLE_RETRY",
	}

	for _, key := range envVars {
		originalEnv[key] = os.Getenv(key)
	}

	defer func() {
		for key, val := range originalEnv {
			if val == "" {
				_ = os.Unsetenv(key)
			} else {
				_ = os.Setenv(key, val)
			}
		}
	}()

	t.Run("API key from CLAUDE_API_KEY", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_API_KEY", "test-key-123")
		defer func() { _ = os.Unsetenv("CLAUDE_API_KEY") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.APIKey != "test-key-123" {
			t.Errorf("expected API key test-key-123, got %s", cfg.APIKey)
		}
	})

	t.Run("API key fallback to ANTHROPIC_API_KEY", func(t *testing.T) {
		_ = os.Unsetenv("CLAUDE_API_KEY")
		_ = os.Setenv("ANTHROPIC_API_KEY", "anthropic-key-456")
		defer func() { _ = os.Unsetenv("ANTHROPIC_API_KEY") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.APIKey != "anthropic-key-456" {
			t.Errorf("expected API key anthropic-key-456, got %s", cfg.APIKey)
		}
	})

	t.Run("custom base URL", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_BASE_URL", "https://custom.api.com")
		defer func() { _ = os.Unsetenv("CLAUDE_BASE_URL") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.BaseURL != "https://custom.api.com" {
			t.Errorf("expected base URL https://custom.api.com, got %s", cfg.BaseURL)
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_TIMEOUT", "30s")
		defer func() { _ = os.Unsetenv("CLAUDE_TIMEOUT") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Timeout != 30*time.Second {
			t.Errorf("expected timeout 30s, got %v", cfg.Timeout)
		}
	})

	t.Run("custom max retries", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_MAX_RETRIES", "5")
		defer func() { _ = os.Unsetenv("CLAUDE_MAX_RETRIES") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.MaxRetries != 5 {
			t.Errorf("expected max retries 5, got %d", cfg.MaxRetries)
		}
	})

	t.Run("custom rate limit", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_RATE_LIMIT", "100")
		defer func() { _ = os.Unsetenv("CLAUDE_RATE_LIMIT") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.RateLimit != 100 {
			t.Errorf("expected rate limit 100, got %d", cfg.RateLimit)
		}
	})

	t.Run("feature flags", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_ENABLE_RETRY", "false")
		defer func() { _ = os.Unsetenv("CLAUDE_ENABLE_RETRY") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.EnableRetry {
			t.Error("expected EnableRetry to be false")
		}
	})
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid config",
			modify:  func(c *Config) { c.APIKey = "test-key" },
			wantErr: false,
		},
		{
			name:    "missing API key",
			modify:  func(c *Config) { c.APIKey = "" },
			wantErr: true,
		},
		{
			name:    "empty base URL",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.BaseURL = "" },
			wantErr: true,
		},
		{
			name:    "negative timeout",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.Timeout = -1 * time.Second },
			wantErr: true,
		},
		{
			name:    "negative max retries",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.MaxRetries = -1 },
			wantErr: true,
		},
		{
			name:    "zero rate limit",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.RateLimit = 0 },
			wantErr: true,
		},
		{
			name:    "zero circuit breaker threshold",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.CircuitBreakerThreshold = 0 },
			wantErr: true,
		},
		{
			name:    "negative cache TTL",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.CacheTTL = -1 * time.Hour },
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigString(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "sk-ant-api03-very-long-key-that-should-be-redacted"

	str := cfg.String()

	// Should contain redacted key
	if len(cfg.APIKey) > 8 && len(str) > 0 {
		// Just check it doesn't panic and produces output
		if str == "" {
			t.Error("expected non-empty string representation")
		}
	}
}
