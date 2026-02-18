package ai

import (
	"os"
	"strings"
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

	if cfg.RetryBackoffMin != 1*time.Second {
		t.Errorf("expected retry backoff min 1s, got %v", cfg.RetryBackoffMin)
	}

	if cfg.RetryBackoffMax != 10*time.Second {
		t.Errorf("expected retry backoff max 10s, got %v", cfg.RetryBackoffMax)
	}

	if cfg.RateLimit != 50 {
		t.Errorf("expected rate limit 50, got %d", cfg.RateLimit)
	}

	if cfg.CircuitBreakerThreshold != 10 {
		t.Errorf("expected circuit breaker threshold 10, got %d", cfg.CircuitBreakerThreshold)
	}

	if cfg.CircuitBreakerTimeout != 60*time.Second {
		t.Errorf("expected circuit breaker timeout 60s, got %v", cfg.CircuitBreakerTimeout)
	}

	if cfg.CacheTTL != 24*time.Hour {
		t.Errorf("expected cache TTL 24h, got %v", cfg.CacheTTL)
	}

	// 100MB default keeps memory bounded during batch package analysis
	if cfg.CacheMaxCost != 100*1024*1024 {
		t.Errorf("expected cache max cost 100MB (%d bytes), got %d", 100*1024*1024, cfg.CacheMaxCost)
	}

	if !cfg.EnableRetry || !cfg.EnableRateLimit || !cfg.EnableCircuitBreaker || !cfg.EnableCache {
		t.Error("expected all features to be enabled by default")
	}

	if !cfg.CacheEnabled {
		t.Error("expected CacheEnabled to be true by default")
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
		"CLAUDE_CACHE_MAX_COST",
		"CLAUDE_ENABLE_RETRY",
		"CLAUDE_ENABLE_RATE_LIMIT",
		"CLAUDE_ENABLE_CIRCUIT_BREAKER",
		"CLAUDE_ENABLE_CACHE",
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

	t.Run("CLAUDE_API_KEY takes priority over ANTHROPIC_API_KEY", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_API_KEY", "claude-key-primary")
		_ = os.Setenv("ANTHROPIC_API_KEY", "anthropic-key-secondary")
		defer func() {
			_ = os.Unsetenv("CLAUDE_API_KEY")
			_ = os.Unsetenv("ANTHROPIC_API_KEY")
		}()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.APIKey != "claude-key-primary" {
			t.Errorf("expected CLAUDE_API_KEY to take priority, got %s", cfg.APIKey)
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

	t.Run("custom circuit breaker threshold", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_CIRCUIT_BREAKER_THRESHOLD", "5")
		defer func() { _ = os.Unsetenv("CLAUDE_CIRCUIT_BREAKER_THRESHOLD") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.CircuitBreakerThreshold != 5 {
			t.Errorf("expected circuit breaker threshold 5, got %d", cfg.CircuitBreakerThreshold)
		}
	})

	t.Run("custom cache TTL", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_CACHE_TTL", "48h")
		defer func() { _ = os.Unsetenv("CLAUDE_CACHE_TTL") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.CacheTTL != 48*time.Hour {
			t.Errorf("expected cache TTL 48h, got %v", cfg.CacheTTL)
		}
	})

	t.Run("custom cache max cost", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_CACHE_MAX_COST", "52428800") // 50MB
		defer func() { _ = os.Unsetenv("CLAUDE_CACHE_MAX_COST") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.CacheMaxCost != 52428800 {
			t.Errorf("expected cache max cost 52428800, got %d", cfg.CacheMaxCost)
		}
	})

	t.Run("feature flags - disable retry", func(t *testing.T) {
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

	t.Run("feature flags - disable rate limit", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_ENABLE_RATE_LIMIT", "false")
		defer func() { _ = os.Unsetenv("CLAUDE_ENABLE_RATE_LIMIT") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.EnableRateLimit {
			t.Error("expected EnableRateLimit to be false")
		}
	})

	t.Run("feature flags - disable circuit breaker", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_ENABLE_CIRCUIT_BREAKER", "false")
		defer func() { _ = os.Unsetenv("CLAUDE_ENABLE_CIRCUIT_BREAKER") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.EnableCircuitBreaker {
			t.Error("expected EnableCircuitBreaker to be false")
		}
	})

	t.Run("feature flags - disable cache", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_ENABLE_CACHE", "false")
		defer func() { _ = os.Unsetenv("CLAUDE_ENABLE_CACHE") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.EnableCache {
			t.Error("expected EnableCache to be false")
		}
	})

	t.Run("feature flags - enable via '1'", func(t *testing.T) {
		_ = os.Setenv("CLAUDE_ENABLE_RETRY", "false")
		defer func() { _ = os.Unsetenv("CLAUDE_ENABLE_RETRY") }()

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.EnableRetry {
			t.Error("expected EnableRetry false via 'false'")
		}

		_ = os.Setenv("CLAUDE_ENABLE_RETRY", "1")
		cfg, err = LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.EnableRetry {
			t.Error("expected EnableRetry true via '1'")
		}
	})
}

// TestLoadFromEnv_InvalidValues verifies that malformed env vars are silently
// ignored and the default value is preserved. This is important because a typo
// in an env var should not crash supply chain analysis.
func TestLoadFromEnv_InvalidValues(t *testing.T) {
	cases := []struct {
		env      string
		value    string
		checkFn  func(*Config) bool
		wantDesc string
	}{
		{
			env:      "CLAUDE_TIMEOUT",
			value:    "not-a-duration",
			checkFn:  func(c *Config) bool { return c.Timeout == 60*time.Second },
			wantDesc: "timeout should fall back to 60s default",
		},
		{
			env:      "CLAUDE_MAX_RETRIES",
			value:    "abc",
			checkFn:  func(c *Config) bool { return c.MaxRetries == 3 },
			wantDesc: "max retries should fall back to 3 default",
		},
		{
			env:      "CLAUDE_RATE_LIMIT",
			value:    "not-a-number",
			checkFn:  func(c *Config) bool { return c.RateLimit == 50 },
			wantDesc: "rate limit should fall back to 50 default",
		},
		{
			env:      "CLAUDE_CIRCUIT_BREAKER_THRESHOLD",
			value:    "!!",
			checkFn:  func(c *Config) bool { return c.CircuitBreakerThreshold == 10 },
			wantDesc: "circuit breaker threshold should fall back to 10 default",
		},
		{
			env:      "CLAUDE_CACHE_TTL",
			value:    "badvalue",
			checkFn:  func(c *Config) bool { return c.CacheTTL == 24*time.Hour },
			wantDesc: "cache TTL should fall back to 24h default",
		},
		{
			env:      "CLAUDE_CACHE_MAX_COST",
			value:    "not-bytes",
			checkFn:  func(c *Config) bool { return c.CacheMaxCost == 100*1024*1024 },
			wantDesc: "cache max cost should fall back to 100MB default",
		},
	}

	for _, tc := range cases {
		t.Run(tc.env+"_invalid", func(t *testing.T) {
			_ = os.Setenv(tc.env, tc.value)
			defer func() { _ = os.Unsetenv(tc.env) }()

			cfg, err := LoadFromEnv()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !tc.checkFn(cfg) {
				t.Errorf("%s (env %s=%q)", tc.wantDesc, tc.env, tc.value)
			}
		})
	}
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
			name:    "zero timeout",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.Timeout = 0 },
			wantErr: true,
		},
		{
			name:    "negative timeout",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.Timeout = -1 * time.Second },
			wantErr: true,
		},
		{
			name:    "zero max retries is valid",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.MaxRetries = 0 },
			wantErr: false,
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
		{
			name:    "zero cache max cost",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.CacheMaxCost = 0 },
			wantErr: true,
		},
		{
			name:    "negative cache max cost",
			modify:  func(c *Config) { c.APIKey = "test-key"; c.CacheMaxCost = -1 },
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
	t.Run("long API key is truncated", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.APIKey = "sk-ant-api03-very-long-key-that-should-be-redacted"

		str := cfg.String()

		if str == "" {
			t.Fatal("expected non-empty string representation")
		}

		// Full API key must not appear in output
		if strings.Contains(str, cfg.APIKey) {
			t.Error("full API key must not appear in String() output")
		}

		// First 8 characters should appear as the truncated prefix
		prefix := cfg.APIKey[:8]
		if !strings.Contains(str, prefix) {
			t.Errorf("expected truncated key prefix %q to appear in String() output: %s", prefix, str)
		}

		// Key config fields should be present
		for _, want := range []string{"BaseURL", "Timeout", "MaxRetries", "RateLimit"} {
			if !strings.Contains(str, want) {
				t.Errorf("expected field %q to appear in String() output", want)
			}
		}
	})

	t.Run("short API key is not truncated", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.APIKey = "short"

		str := cfg.String()

		// Short key (<=8 chars) should appear as-is without "..."
		if !strings.Contains(str, "short") {
			t.Errorf("expected short key to appear in String() output: %s", str)
		}
	})
}

// TestConfig_RealPackageScanningWorkload validates that the default config is
// suitable for analyzing the real-world package sets found in mike-libraries.
//
// Package sets used (from /Users/mike/Projects/mike-libraries):
//   - javascript/package.json: 30 npm dependencies (express, axios, lodash, ...)
//   - python/requirements.txt: 26 PyPI packages (Flask, requests, sqlalchemy, ...)
//   - java/pom.xml: 28 Maven dependencies (spring-boot, guava, jackson, ...)
//
// Source: "Small World with High Risks" (Zimmermann et al., 2019) shows npm
// packages have average 79 transitive deps, requiring multiple API calls per
// direct dependency during supply chain risk analysis.
func TestConfig_RealPackageScanningWorkload(t *testing.T) {
	// Packages mirroring javascript/package.json in mike-libraries
	jsPackages := []string{
		"express", "axios", "dotenv", "pg", "redis", "mongoose",
		"cors", "morgan", "helmet", "joi", "jsonwebtoken", "bcryptjs",
		"winston", "lodash", "date-fns", "express-validator", "multer",
		"compression", "express-rate-limit", "passport", "passport-jwt",
		"uuid", "sharp", "socket.io", "bull", "stripe", "aws-sdk",
		"nodemailer", "agenda", "pino",
	}

	// Packages mirroring python/requirements.txt in mike-libraries
	pyPackages := []string{
		"Flask", "aiohttp", "gunicorn", "requests", "sqlalchemy",
		"psycopg2-binary", "redis", "celery", "python-dotenv", "pytest",
		"pandas", "pydantic", "numpy", "fastapi", "uvicorn", "alembic",
		"httpx", "click", "Pillow", "cryptography", "python-multipart",
		"email-validator", "passlib", "python-jose", "boto3", "stripe",
	}

	// Packages mirroring java/pom.xml in mike-libraries
	javaPackages := []string{
		"spring-boot-starter-web", "spring-boot-starter-data-jpa",
		"spring-boot-starter-data-redis", "spring-boot-starter-validation",
		"spring-boot-starter-actuator", "spring-boot-starter-security",
		"spring-boot-starter-mail", "spring-boot-starter-cache",
		"postgresql", "h2", "lombok", "jackson-databind",
		"jackson-datatype-jsr310", "commons-lang3", "commons-collections4",
		"commons-io", "guava", "caffeine", "mapstruct", "modelmapper",
		"jjwt-api", "jjwt-impl", "jjwt-jackson", "httpclient5", "okhttp",
		"flyway-core", "hibernate-validator", "springdoc-openapi-starter-webmvc-ui",
	}

	totalPackages := len(jsPackages) + len(pyPackages) + len(javaPackages) // 84 packages

	cfg := DefaultConfig()

	t.Run("rate limit covers full batch within reasonable time", func(t *testing.T) {
		// With 50 req/min, 56 packages scans in ~2 minutes - acceptable for CI
		minutesToScan := float64(totalPackages) / float64(cfg.RateLimit)
		if minutesToScan > 10.0 {
			t.Errorf("default rate limit %d req/min too low for %d packages: would take %.1f minutes",
				cfg.RateLimit, totalPackages, minutesToScan)
		}
	})

	t.Run("cache TTL suits daily dependency audits", func(t *testing.T) {
		// Package risk data changes rarely; 24h cache avoids redundant API calls
		// across repeated scans of the same manifest in CI pipelines
		if cfg.CacheTTL < 1*time.Hour {
			t.Errorf("cache TTL %v is too short for daily audit workflows; package supply chain signals do not change hourly", cfg.CacheTTL)
		}
	})

	t.Run("cache capacity handles full package result set", func(t *testing.T) {
		// Assume worst-case 50KB AI response per package analysis
		const maxResponseBytes = 50 * 1024
		requiredBytes := int64(totalPackages) * maxResponseBytes
		if cfg.CacheMaxCost < requiredBytes {
			t.Errorf("cache max cost %d bytes insufficient for %d packages at %d bytes each (need %d)",
				cfg.CacheMaxCost, totalPackages, maxResponseBytes, requiredBytes)
		}
	})

	t.Run("timeout sufficient for per-package AI analysis", func(t *testing.T) {
		// Claude API calls analyzing supply chain signals should complete well within 60s
		if cfg.Timeout < 30*time.Second {
			t.Errorf("timeout %v may be too short for AI-assisted supply chain analysis per package", cfg.Timeout)
		}
	})

	t.Run("retry config handles transient failures during batch", func(t *testing.T) {
		// Scanning 56 packages increases probability of encountering at least one
		// transient API error; at least 2 retries is prudent
		if cfg.MaxRetries < 2 {
			t.Errorf("max retries %d too low for reliable batch scanning of %d packages",
				cfg.MaxRetries, totalPackages)
		}
	})

	t.Run("circuit breaker threshold tolerates occasional failures", func(t *testing.T) {
		// With 56 packages, a threshold of 5 or fewer would trip the breaker on
		// normal transient errors before completing the batch
		if cfg.CircuitBreakerThreshold < 5 {
			t.Errorf("circuit breaker threshold %d too low for batch scanning; would trip on normal transient errors during %d-package analysis",
				cfg.CircuitBreakerThreshold, totalPackages)
		}
	})

	t.Run("default config passes validation", func(t *testing.T) {
		cfg.APIKey = "test-key"
		if err := cfg.Validate(); err != nil {
			t.Errorf("default config should be valid for real-world use: %v", err)
		}
	})
}
