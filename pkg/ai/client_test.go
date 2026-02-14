package ai

import (
	"context"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
)

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

	// Test exponential backoff
	backoff1 := client.calculateBackoff(1)
	backoff2 := client.calculateBackoff(2)

	// Each should be roughly double (with jitter)
	if backoff1 < 800*time.Millisecond || backoff1 > 1200*time.Millisecond {
		t.Errorf("unexpected backoff for attempt 1: %v", backoff1)
	}

	if backoff2 < 1600*time.Millisecond || backoff2 > 2400*time.Millisecond {
		t.Errorf("unexpected backoff for attempt 2: %v", backoff2)
	}

	// Should be capped at max
	backoff10 := client.calculateBackoff(10)
	if backoff10 > 12*time.Second { // Max + jitter
		t.Errorf("expected backoff to be capped at max, got %v", backoff10)
	}
}

func TestCacheKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Mock params (using a simple struct for testing)
	params1 := anthropic.MessageNewParams{}
	params2 := anthropic.MessageNewParams{}

	key1 := client.cacheKey(params1)
	key2 := client.cacheKey(params2)

	// Same params should produce same key
	if key1 != key2 {
		t.Error("expected identical params to produce same cache key")
	}

	// Keys should be non-empty hex strings
	if len(key1) != 64 { // SHA256 hex = 64 chars
		t.Errorf("expected 64-char hex key, got %d chars", len(key1))
	}
}
