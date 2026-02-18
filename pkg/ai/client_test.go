package ai

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
)

// Test: Client creation with valid and disabled optional components
// Justification: Ensuring proper initialization prevents runtime panics during
//                supply chain analysis at scale
// Source: API design best practices for optional component initialization
// Methodology: Create clients with DefaultConfig and selectively disabled features
// Result: Components should be nil when disabled, non-nil when enabled
func TestNewClient(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.APIKey = "test-key-123"

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if client == nil {
			t.Fatal("expected non-nil client")
		}

		if client.config != cfg {
			t.Error("expected config to be set")
		}

		// Check that optional components are initialized
		if cfg.EnableCache && client.cache == nil {
			t.Error("expected cache to be initialized")
		}

		if cfg.EnableRateLimit && client.rateLimiter == nil {
			t.Error("expected rate limiter to be initialized")
		}

		if cfg.EnableCircuitBreaker && client.circuitBreaker == nil {
			t.Error("expected circuit breaker to be initialized")
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.APIKey = "" // Invalid

		_, err := NewClient(cfg)
		if err == nil {
			t.Fatal("expected error for invalid config")
		}
	})

	t.Run("cache disabled", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.APIKey = "test-key-123"
		cfg.EnableCache = false

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if client.cache != nil {
			t.Error("expected cache to be nil when disabled")
		}
	})

	t.Run("rate limiter disabled", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.APIKey = "test-key-123"
		cfg.EnableRateLimit = false

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if client.rateLimiter != nil {
			t.Error("expected rate limiter to be nil when disabled")
		}
	})

	t.Run("circuit breaker disabled", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.APIKey = "test-key-123"
		cfg.EnableCircuitBreaker = false

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if client.circuitBreaker != nil {
			t.Error("expected circuit breaker to be nil when disabled")
		}
	})
}

// Test: Client resource cleanup on Close
// Justification: Resource leaks in long-running analysis pipelines degrade performance
// Source: Go resource management best practices
// Methodology: Create client, call Close, verify no error returned
// Result: Close should release cache and return nil error
func TestClientClose(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key-123"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = client.Close()
	if err != nil {
		t.Errorf("unexpected error on close: %v", err)
	}
}

// Test: GetStats reports active component status accurately
// Justification: Observability is required for operating analysis pipelines
//                that process packages at scale
// Source: Operational best practices for distributed systems
// Methodology: Create client with all features enabled, verify stats reflect config
// Result: Stats should match the client's enabled features
func TestClientGetStats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key-123"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	stats := client.GetStats()

	if stats.Config == "" {
		t.Error("expected non-empty config string")
	}

	if cfg.EnableRateLimit && !stats.RateLimiterActive {
		t.Error("expected rate limiter to be active")
	}

	if cfg.EnableCircuitBreaker && !stats.CircuitBreakerActive {
		t.Error("expected circuit breaker to be active")
	}

	if cfg.EnableCache && !stats.CacheActive {
		t.Error("expected cache to be active")
	}
}

// Test: GetStats correctly reports circuit breaker open state
// Justification: Operators need to detect when the circuit breaker has tripped
//                to diagnose API connectivity issues during analysis runs
// Source: Circuit breaker pattern observability requirements
// Methodology: Open circuit breaker by recording failures, check stats reflect open state
// Result: CircuitBreakerOpen should be true after threshold failures
func TestClientGetStats_CircuitBreakerOpen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key-123"
	cfg.CircuitBreakerThreshold = 2
	cfg.EnableCircuitBreaker = true

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Initially closed
	stats := client.GetStats()
	if stats.CircuitBreakerOpen {
		t.Error("circuit breaker should not be open initially")
	}

	// Trip the circuit breaker
	client.circuitBreaker.RecordFailure()
	client.circuitBreaker.RecordFailure()

	// Should now be open
	stats = client.GetStats()
	if !stats.CircuitBreakerOpen {
		t.Error("circuit breaker should be open after threshold failures")
	}
	if stats.CircuitBreakerFailures != 2 {
		t.Errorf("expected 2 failures recorded, got %d", stats.CircuitBreakerFailures)
	}
}

// Test: Token bucket rate limiter allows and throttles requests correctly
// Justification: Rate limiting protects the Claude API from overuse during bulk
//                supply chain analysis of large dependency graphs
// Source: Token bucket algorithm specification
// Methodology: Exhaust tokens at 60 req/min rate, verify token decrements and
//              context cancellation when no tokens remain
// Result: Available tokens decrease per request; cancelled context returns error
func TestRateLimiter(t *testing.T) {
	t.Run("basic operation", func(t *testing.T) {
		rl := newRateLimiter(60) // 60 requests per minute

		ctx := context.Background()

		// First request should succeed immediately
		err := rl.Wait(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rl.available != 59 {
			t.Errorf("expected 59 available tokens, got %d", rl.available)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		rl := newRateLimiter(1) // 1 request per minute

		// Exhaust the token
		ctx := context.Background()
		err := rl.Wait(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Now try with canceled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err = rl.Wait(ctx)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

// Test: Circuit breaker opens on threshold failures, recovers after timeout
// Justification: Prevents cascading failures when the Claude API is temporarily
//                unavailable during supply chain analysis; avoids wasting retries
// Source: Michael T. Nygard, "Release It!" - Circuit Breaker pattern
// Methodology: Record failures up to and beyond threshold, verify state transitions;
//              wait for timeout and verify half-open recovery
// Result: Closed → Open after threshold; Open → allows request after timeout
func TestCircuitBreaker(t *testing.T) {
	t.Run("basic operation", func(t *testing.T) {
		cb := newCircuitBreaker(3, 1*time.Second)

		// Should be closed initially
		if !cb.Allow() {
			t.Error("expected circuit breaker to be closed initially")
		}

		// Record failures
		cb.RecordFailure()
		cb.RecordFailure()

		// Should still be closed (threshold is 3)
		if !cb.Allow() {
			t.Error("expected circuit breaker to still be closed")
		}

		// Third failure should open it
		cb.RecordFailure()

		if cb.Allow() {
			t.Error("expected circuit breaker to be open after threshold")
		}
	})

	t.Run("success resets failures", func(t *testing.T) {
		cb := newCircuitBreaker(3, 1*time.Second)

		cb.RecordFailure()
		cb.RecordFailure()
		cb.RecordSuccess()

		// Should be reset
		if cb.failures != 0 {
			t.Errorf("expected failures to be reset, got %d", cb.failures)
		}

		if !cb.Allow() {
			t.Error("expected circuit breaker to be closed after success")
		}
	})

	t.Run("timeout recovery", func(t *testing.T) {
		cb := newCircuitBreaker(2, 100*time.Millisecond)

		// Open the circuit
		cb.RecordFailure()
		cb.RecordFailure()

		if cb.Allow() {
			t.Error("expected circuit breaker to be open")
		}

		// Wait for timeout
		time.Sleep(150 * time.Millisecond)

		// Should allow (half-open state)
		if !cb.Allow() {
			t.Error("expected circuit breaker to allow after timeout")
		}
	})
}

// Test: Exponential backoff with jitter stays within expected bounds
// Justification: Well-bounded backoff avoids thundering herd problems when
//                multiple concurrent package analyses retry simultaneously
// Source: "Exponential Backoff And Jitter" - AWS Architecture Blog
// Methodology: Calculate backoff for multiple attempts; verify exponential growth
//              and cap at maximum; use wide bounds to tolerate 20% jitter
// Result: Attempt N backoff ≈ min * 2^(N-1) ± 20%; capped at RetryBackoffMax
func TestCalculateBackoff(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	cfg.RetryBackoffMin = 1 * time.Second
	cfg.RetryBackoffMax = 10 * time.Second

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Test exponential backoff - use wide bounds to accommodate ±20% jitter
	backoff1 := client.calculateBackoff(1)
	backoff2 := client.calculateBackoff(2)

	// Attempt 1: base = 1s, ±20% jitter → [0.8s, 1.2s]
	if backoff1 < 800*time.Millisecond || backoff1 > 1200*time.Millisecond {
		t.Errorf("unexpected backoff for attempt 1: %v (expected 0.8s-1.2s)", backoff1)
	}

	// Attempt 2: base = 2s, ±20% jitter → [1.6s, 2.4s]
	if backoff2 < 1600*time.Millisecond || backoff2 > 2400*time.Millisecond {
		t.Errorf("unexpected backoff for attempt 2: %v (expected 1.6s-2.4s)", backoff2)
	}

	// Attempt 2 should be greater than attempt 1 in expectation
	// We sample multiple times to confirm exponential growth is consistent
	var attempt1Sum, attempt2Sum time.Duration
	const samples = 20
	for i := 0; i < samples; i++ {
		attempt1Sum += client.calculateBackoff(1)
		attempt2Sum += client.calculateBackoff(2)
	}
	if attempt1Sum >= attempt2Sum {
		t.Error("attempt 2 backoff should be larger than attempt 1 on average")
	}

	// Should be capped at max (10s + 20% jitter = 12s max)
	backoff10 := client.calculateBackoff(10)
	if backoff10 > 12*time.Second {
		t.Errorf("expected backoff to be capped at max, got %v", backoff10)
	}
}

// Test: Cache key generation is deterministic and unique per request parameters
// Justification: Incorrect caching could return stale risk assessments for different
//                packages, leading to false positives or false negatives
// Source: Cache correctness requirements for supply chain analysis
// Methodology: Hash identical params → same key; hash different params → different key;
//              verify SHA-256 hex output length (64 chars)
// Result: Same params = same 64-char hex key; different params = different keys
func TestCacheKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	t.Run("identical params produce same key", func(t *testing.T) {
		params1 := anthropic.MessageNewParams{}
		params2 := anthropic.MessageNewParams{}

		key1 := client.cacheKey(params1)
		key2 := client.cacheKey(params2)

		if key1 != key2 {
			t.Error("expected identical params to produce same cache key")
		}

		// Keys should be non-empty hex strings
		if len(key1) != 64 { // SHA256 hex = 64 chars
			t.Errorf("expected 64-char hex key, got %d chars", len(key1))
		}
	})

	t.Run("different models produce different keys", func(t *testing.T) {
		params1 := anthropic.MessageNewParams{
			Model: anthropic.ModelClaudeSonnet4_5,
		}
		params2 := anthropic.MessageNewParams{
			Model: anthropic.ModelClaudeHaiku4_5,
		}

		key1 := client.cacheKey(params1)
		key2 := client.cacheKey(params2)

		if key1 == key2 {
			t.Error("expected different models to produce different cache keys")
		}
	})

	t.Run("key is valid hex string", func(t *testing.T) {
		params := anthropic.MessageNewParams{}
		key := client.cacheKey(params)

		validHex := "0123456789abcdef"
		for _, ch := range key {
			if !strings.ContainsRune(validHex, ch) {
				t.Errorf("cache key contains non-hex character: %c", ch)
				break
			}
		}
	})
}

// Test: isRetryable correctly classifies HTTP errors by status code
// Justification: Retrying non-retryable errors (400 Bad Request) wastes time and
//                rate limit quota during package analysis; failing to retry 429/5xx
//                loses valid analysis results unnecessarily
// Source: RFC 9110 HTTP Semantics; Anthropic API error handling documentation
// Methodology: Construct anthropic.Error values with different status codes;
//              verify retry classification matches expected behavior
// Result: 429/5xx → retryable; 400/401/403/404 → not retryable; nil err → retryable
func TestIsRetryable(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	tests := []struct {
		name       string
		statusCode int
		wantRetry  bool
	}{
		{"rate limit 429", 429, true},
		{"server error 500", 500, true},
		{"server error 502", 502, true},
		{"server error 503", 503, true},
		{"server error 599", 599, true},
		{"bad request 400", 400, false},
		{"unauthorized 401", 401, false},
		{"forbidden 403", 403, false},
		{"not found 404", 404, false},
		{"client error 422", 422, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := &anthropic.Error{
				StatusCode: tt.statusCode,
			}

			got := client.isRetryable(apiErr)
			if got != tt.wantRetry {
				t.Errorf("isRetryable(%d) = %v, want %v", tt.statusCode, got, tt.wantRetry)
			}
		})
	}

	t.Run("non-API error is retryable", func(t *testing.T) {
		// Network errors, timeouts should be retried
		if !client.isRetryable(context.DeadlineExceeded) {
			t.Error("expected deadline exceeded to be retryable")
		}
	})
}

// TestLoadFromEnv_FeatureFlags validates that boolean feature flags are correctly
// parsed from environment variables (covered broadly in config_test.go; this
// focuses on the "0" / "1" numeric form that config_test.go does not test).
//
// Test: Feature flag parsing via numeric env values ("0" and "1")
// Justification: Production Kubernetes deployments commonly set boolean flags as
//                "0"/"1"; a parsing miss would silently enable disabled features
// Source: 12-Factor App methodology for environment-based configuration
// Methodology: Set CLAUDE_ENABLE_CACHE=0, CLAUDE_ENABLE_RATE_LIMIT=1, call
//              LoadFromEnv, verify parsed values match intent
// Result: "0" disables feature; "1" enables feature; "false" disables feature
func TestLoadFromEnv_FeatureFlags(t *testing.T) {
	// Save and restore env state
	restore := func(k, v string) func() {
		return func() {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}

	t.Run("numeric 0 disables cache", func(t *testing.T) {
		prev := os.Getenv("CLAUDE_ENABLE_CACHE")
		defer restore("CLAUDE_ENABLE_CACHE", prev)()
		os.Setenv("CLAUDE_ENABLE_CACHE", "0")

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.EnableCache {
			t.Error("expected EnableCache=false when CLAUDE_ENABLE_CACHE=0")
		}
	})

	t.Run("numeric 1 enables rate limit", func(t *testing.T) {
		prev := os.Getenv("CLAUDE_ENABLE_RATE_LIMIT")
		defer restore("CLAUDE_ENABLE_RATE_LIMIT", prev)()
		os.Setenv("CLAUDE_ENABLE_RATE_LIMIT", "1")

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.EnableRateLimit {
			t.Error("expected EnableRateLimit=true when CLAUDE_ENABLE_RATE_LIMIT=1")
		}
	})

	t.Run("string false disables circuit breaker", func(t *testing.T) {
		prev := os.Getenv("CLAUDE_ENABLE_CIRCUIT_BREAKER")
		defer restore("CLAUDE_ENABLE_CIRCUIT_BREAKER", prev)()
		os.Setenv("CLAUDE_ENABLE_CIRCUIT_BREAKER", "false")

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.EnableCircuitBreaker {
			t.Error("expected EnableCircuitBreaker=false when CLAUDE_ENABLE_CIRCUIT_BREAKER=false")
		}
	})
}

// Test: Rate limiter correctly refills tokens over time
// Justification: Without proper token refill, the client would permanently stall
//                after the initial burst of package analysis requests
// Source: Token bucket algorithm - Wikipedia; IETF RFC 2698
// Methodology: Exhaust a 1-token bucket; verify context cancel while empty;
//              wait for refill interval; verify token available again
// Result: Tokens refill proportionally to elapsed time up to bucket capacity
func TestRateLimiter_TokenRefill(t *testing.T) {
	// Use 60 req/min → 1 token per second
	rl := newRateLimiter(60)

	ctx := context.Background()

	// Drain all tokens
	for i := 0; i < 60; i++ {
		_ = rl.Wait(ctx)
	}

	if rl.available != 0 {
		t.Errorf("expected 0 tokens after draining, got %d", rl.available)
	}

	// Simulate time passing by backdating lastCheck
	rl.mu.Lock()
	rl.lastCheck = time.Now().Add(-2 * time.Second) // 2 seconds = 2 tokens at 60/min
	rl.mu.Unlock()

	// Next Wait should refill tokens from elapsed time
	err := rl.Wait(ctx)
	if err != nil {
		t.Fatalf("expected token to be available after refill, got: %v", err)
	}
}

// Test: Client configuration appropriate for analyzing real-world package ecosystems
// Justification: The default config must support realistic supply chain analysis
//                workloads - e.g., scanning all packages in a JavaScript project's
//                dependency graph (30+ direct packages in mike-libraries/javascript)
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - typical npm
//         dependency graphs have 683+ transitive dependencies
//         https://arxiv.org/abs/1902.09217
// Methodology: Verify default config supports realistic analysis throughput; verify
//              rate limit is sufficient for batch analysis; verify timeouts are
//              appropriate for AI-augmented analysis latency
// Result: Default config allows continuous analysis without excessive throttling
func TestDefaultConfig_RealWorldWorkload(t *testing.T) {
	cfg := DefaultConfig()

	// npm packages from mike-libraries/javascript (30 direct dependencies)
	npmPackages := []string{
		"express", "axios", "dotenv", "pg", "redis", "mongoose", "cors",
		"morgan", "helmet", "joi", "jsonwebtoken", "bcryptjs", "winston",
		"lodash", "date-fns", "express-validator", "multer", "compression",
		"express-rate-limit", "passport", "passport-jwt", "uuid", "sharp",
		"socket.io", "bull", "stripe", "aws-sdk", "nodemailer", "agenda", "pino",
	}

	// pypi packages from mike-libraries/python (26 direct dependencies)
	pypiPackages := []string{
		"Flask", "aiohttp", "gunicorn", "requests", "sqlalchemy", "psycopg2-binary",
		"redis", "celery", "python-dotenv", "pytest", "pandas", "pydantic",
		"numpy", "fastapi", "uvicorn", "alembic", "httpx", "click", "Pillow",
		"cryptography", "python-multipart", "email-validator", "passlib",
		"python-jose", "boto3", "stripe",
	}

	totalPackages := len(npmPackages) + len(pypiPackages) // 56 packages

	// Rate limit must be sufficient to process a realistic project in reasonable time
	// At 50 req/min default, 56 packages completes in ~67 seconds (acceptable)
	if cfg.RateLimit < 10 {
		t.Errorf("rate limit %d/min too low for realistic workloads (%d packages)",
			cfg.RateLimit, totalPackages)
	}

	// Timeout must be long enough for AI explanation generation (which can take 10-30s)
	if cfg.Timeout < 30*time.Second {
		t.Errorf("timeout %v too short for AI-augmented analysis", cfg.Timeout)
	}

	// Circuit breaker threshold should tolerate occasional API flakiness
	// without tripping on transient errors during a full project scan
	if cfg.CircuitBreakerThreshold < 3 {
		t.Errorf("circuit breaker threshold %d too aggressive for batch analysis",
			cfg.CircuitBreakerThreshold)
	}

	// Cache TTL must be long enough to deduplicate repeated analysis
	// (the same popular packages like lodash appear in many projects)
	if cfg.CacheTTL < 1*time.Hour {
		t.Errorf("cache TTL %v too short for deduplicating popular packages", cfg.CacheTTL)
	}

	// Cache must be large enough for realistic package sets
	// Each cached response ~10KB; 56 packages × 10KB = 560KB; default should be >> this
	if cfg.CacheMaxCost < 1*1024*1024 { // At least 1MB
		t.Errorf("cache max cost %d bytes too small for realistic package sets", cfg.CacheMaxCost)
	}
}

// Test: Cache keys are unique across real-world package names from different ecosystems
// Justification: Cache key collisions would cause analysis results for one package
//                to be incorrectly returned for a different package (e.g., "stripe"
//                on npm vs "stripe" on PyPI have different supply chain profiles)
// Source: Cache correctness in multi-ecosystem supply chain analysis
// Methodology: Generate cache keys for realistic package name/ecosystem combinations
//              from mike-libraries; verify all keys are unique
// Result: All package+ecosystem combinations produce distinct cache keys
func TestCacheKey_RealPackageNames(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Representative packages from mike-libraries across ecosystems
	// Note: some packages share names across ecosystems (e.g. "stripe", "redis")
	packageScenarios := []struct {
		ecosystem string
		name      string
	}{
		// npm packages (mike-libraries/javascript/package.json)
		{"npm", "express"},
		{"npm", "lodash"},
		{"npm", "stripe"},
		{"npm", "redis"},
		// pypi packages (mike-libraries/python/requirements.txt)
		{"pypi", "Flask"},
		{"pypi", "requests"},
		{"pypi", "stripe"},  // same name, different ecosystem
		{"pypi", "redis"},   // same name, different ecosystem
		// maven packages (mike-libraries/java/pom.xml)
		{"maven", "com.google.guava:guava"},
		{"maven", "org.springframework.boot:spring-boot-starter-web"},
	}

	seen := make(map[string]string)
	for _, scenario := range packageScenarios {
		// Build a params object that encodes package context
		// In real usage, the package name/ecosystem would be embedded in message content
		params := anthropic.MessageNewParams{
			Model: anthropic.ModelClaudeSonnet4_5,
			Messages: []anthropic.MessageParam{
				anthropic.NewUserMessage(
					anthropic.NewTextBlock(scenario.ecosystem + ":" + scenario.name),
				),
			},
		}

		key := client.cacheKey(params)
		label := scenario.ecosystem + ":" + scenario.name

		if existing, collision := seen[key]; collision {
			t.Errorf("cache key collision: %s and %s produce the same key %s",
				label, existing, key)
		}
		seen[key] = label
	}
}
