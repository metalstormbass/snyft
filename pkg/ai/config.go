package ai

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds the configuration for the Claude AI client
type Config struct {
	// API Key for Claude API authentication
	APIKey string

	// BaseURL is the Claude API base URL (defaults to production)
	BaseURL string

	// Timeout for HTTP requests
	Timeout time.Duration

	// Retry configuration
	MaxRetries      int
	RetryBackoffMin time.Duration
	RetryBackoffMax time.Duration

	// Rate limiting (requests per minute)
	RateLimit int

	// Circuit breaker configuration
	CircuitBreakerThreshold int
	CircuitBreakerTimeout   time.Duration

	// Cache configuration
	CacheEnabled bool
	CacheTTL     time.Duration
	CacheMaxCost int64 // Maximum memory for cache in bytes

	// Per-call timeout for individual AI API calls (default: 45s).
	// Each AI call (deep analysis, attack patterns, unified summary) gets its own
	// independent timeout so a slow call doesn't starve subsequent calls.
	PerCallTimeout time.Duration

	// Feature flags
	EnableRetry         bool
	EnableRateLimit     bool
	EnableCircuitBreaker bool
	EnableCache         bool
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		BaseURL:                 "https://api.anthropic.com",
		Timeout:                 60 * time.Second,
		MaxRetries:              3,
		RetryBackoffMin:         1 * time.Second,
		RetryBackoffMax:         10 * time.Second,
		RateLimit:               50, // 50 requests per minute
		CircuitBreakerThreshold: 10,
		CircuitBreakerTimeout:   60 * time.Second,
		CacheEnabled:            true,
		CacheTTL:                24 * time.Hour,
		CacheMaxCost:            100 * 1024 * 1024, // 100MB
		PerCallTimeout:          45 * time.Second,
		EnableRetry:             true,
		EnableRateLimit:         true,
		EnableCircuitBreaker:    true,
		EnableCache:             true,
	}
}

// LoadFromEnv loads configuration from environment variables
// Environment variables take precedence over defaults
func LoadFromEnv() (*Config, error) {
	cfg := DefaultConfig()

	// API Key (required)
	apiKey := os.Getenv("CLAUDE_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY") // Fallback to official SDK env var
	}
	cfg.APIKey = apiKey

	// Base URL
	if baseURL := os.Getenv("CLAUDE_BASE_URL"); baseURL != "" {
		cfg.BaseURL = baseURL
	}

	// Timeout
	if timeout := os.Getenv("CLAUDE_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			cfg.Timeout = d
		}
	}

	// Max Retries
	if maxRetries := os.Getenv("CLAUDE_MAX_RETRIES"); maxRetries != "" {
		if n, err := strconv.Atoi(maxRetries); err == nil {
			cfg.MaxRetries = n
		}
	}

	// Rate Limit
	if rateLimit := os.Getenv("CLAUDE_RATE_LIMIT"); rateLimit != "" {
		if n, err := strconv.Atoi(rateLimit); err == nil {
			cfg.RateLimit = n
		}
	}

	// Circuit Breaker Threshold
	if threshold := os.Getenv("CLAUDE_CIRCUIT_BREAKER_THRESHOLD"); threshold != "" {
		if n, err := strconv.Atoi(threshold); err == nil {
			cfg.CircuitBreakerThreshold = n
		}
	}

	// Cache TTL
	if cacheTTL := os.Getenv("CLAUDE_CACHE_TTL"); cacheTTL != "" {
		if d, err := time.ParseDuration(cacheTTL); err == nil {
			cfg.CacheTTL = d
		}
	}

	// Cache Max Cost
	if cacheMaxCost := os.Getenv("CLAUDE_CACHE_MAX_COST"); cacheMaxCost != "" {
		if n, err := strconv.ParseInt(cacheMaxCost, 10, 64); err == nil {
			cfg.CacheMaxCost = n
		}
	}

	// Feature Flags
	if enableRetry := os.Getenv("CLAUDE_ENABLE_RETRY"); enableRetry != "" {
		cfg.EnableRetry = enableRetry == "true" || enableRetry == "1"
	}

	if enableRateLimit := os.Getenv("CLAUDE_ENABLE_RATE_LIMIT"); enableRateLimit != "" {
		cfg.EnableRateLimit = enableRateLimit == "true" || enableRateLimit == "1"
	}

	if enableCircuitBreaker := os.Getenv("CLAUDE_ENABLE_CIRCUIT_BREAKER"); enableCircuitBreaker != "" {
		cfg.EnableCircuitBreaker = enableCircuitBreaker == "true" || enableCircuitBreaker == "1"
	}

	if enableCache := os.Getenv("CLAUDE_ENABLE_CACHE"); enableCache != "" {
		cfg.EnableCache = enableCache == "true" || enableCache == "1"
	}

	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.APIKey == "" {
		return fmt.Errorf("API key is required (set CLAUDE_API_KEY or ANTHROPIC_API_KEY)")
	}

	if c.BaseURL == "" {
		return fmt.Errorf("base URL cannot be empty")
	}

	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	if c.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative")
	}

	if c.RateLimit <= 0 {
		return fmt.Errorf("rate limit must be positive")
	}

	if c.CircuitBreakerThreshold <= 0 {
		return fmt.Errorf("circuit breaker threshold must be positive")
	}

	if c.CacheTTL <= 0 {
		return fmt.Errorf("cache TTL must be positive")
	}

	if c.CacheMaxCost <= 0 {
		return fmt.Errorf("cache max cost must be positive")
	}

	return nil
}

// String returns a string representation of the config (with API key redacted)
func (c *Config) String() string {
	apiKey := c.APIKey
	if len(apiKey) > 8 {
		apiKey = apiKey[:8] + "..."
	}

	return fmt.Sprintf(
		"Config{APIKey: %s, BaseURL: %s, Timeout: %v, MaxRetries: %d, RateLimit: %d/min, CircuitBreaker: %d failures, Cache: %v (TTL: %v)}",
		apiKey,
		c.BaseURL,
		c.Timeout,
		c.MaxRetries,
		c.RateLimit,
		c.CircuitBreakerThreshold,
		c.EnableCache,
		c.CacheTTL,
	)
}
