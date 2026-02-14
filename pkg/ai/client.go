package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/dgraph-io/ristretto"
)

// Client is a robust Claude API client with retry, rate limiting, circuit breaker, and caching
type Client struct {
	config *Config
	client anthropic.Client

	// Rate limiter
	rateLimiter *rateLimiter

	// Circuit breaker
	circuitBreaker *circuitBreaker

	// Cache
	cache *ristretto.Cache
}

// NewClient creates a new Claude API client with the given configuration
func NewClient(config *Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create Anthropic SDK client
	opts := []option.RequestOption{
		option.WithAPIKey(config.APIKey),
		option.WithBaseURL(config.BaseURL),
		option.WithHTTPClient(&http.Client{
			Timeout: config.Timeout,
		}),
	}

	anthropicClient := anthropic.NewClient(opts...)

	// Initialize cache if enabled
	var cache *ristretto.Cache
	if config.EnableCache {
		var err error
		cache, err = ristretto.NewCache(&ristretto.Config{
			NumCounters: 1e4,     // 10k counters for frequency tracking
			MaxCost:     config.CacheMaxCost,
			BufferItems: 64,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create cache: %w", err)
		}
	}

	// Initialize rate limiter
	var rl *rateLimiter
	if config.EnableRateLimit {
		rl = newRateLimiter(config.RateLimit)
	}

	// Initialize circuit breaker
	var cb *circuitBreaker
	if config.EnableCircuitBreaker {
		cb = newCircuitBreaker(config.CircuitBreakerThreshold, config.CircuitBreakerTimeout)
	}

	return &Client{
		config:         config,
		client:         anthropicClient,
		cache:          cache,
		rateLimiter:    rl,
		circuitBreaker: cb,
	}, nil
}

// CreateMessage sends a message to Claude with automatic retry, rate limiting, and caching
func (c *Client) CreateMessage(ctx context.Context, params anthropic.MessageNewParams) (*anthropic.Message, error) {
	// Check circuit breaker
	if c.circuitBreaker != nil && !c.circuitBreaker.Allow() {
		return nil, fmt.Errorf("circuit breaker open: too many failures")
	}

	// Check cache
	if c.cache != nil && c.config.EnableCache {
		cacheKey := c.cacheKey(params)
		if cached, found := c.cache.Get(cacheKey); found {
			if msg, ok := cached.(*anthropic.Message); ok {
				return msg, nil
			}
		}
	}

	// Rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait failed: %w", err)
		}
	}

	// Retry logic
	var lastErr error
	maxAttempts := 1
	if c.config.EnableRetry {
		maxAttempts = c.config.MaxRetries + 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := c.calculateBackoff(attempt)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		// Make the API call
		msg, err := c.client.Messages.New(ctx, params)
		if err != nil {
			lastErr = err

			// Record failure for circuit breaker
			if c.circuitBreaker != nil {
				c.circuitBreaker.RecordFailure()
			}

			// Check if error is retryable
			if !c.isRetryable(err) {
				return nil, fmt.Errorf("non-retryable error: %w", err)
			}

			continue
		}

		// Success - record for circuit breaker
		if c.circuitBreaker != nil {
			c.circuitBreaker.RecordSuccess()
		}

		// Cache the response
		if c.cache != nil && c.config.EnableCache {
			cacheKey := c.cacheKey(params)
			c.cache.SetWithTTL(cacheKey, msg, 1, c.config.CacheTTL)
		}

		return msg, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// calculateBackoff calculates exponential backoff with jitter
func (c *Client) calculateBackoff(attempt int) time.Duration {
	// Exponential backoff: min * 2^attempt
	backoff := float64(c.config.RetryBackoffMin) * math.Pow(2, float64(attempt-1))

	// Cap at max
	if backoff > float64(c.config.RetryBackoffMax) {
		backoff = float64(c.config.RetryBackoffMax)
	}

	// Add jitter (±20%)
	jitter := backoff * 0.2 * (2*float64(time.Now().UnixNano()%100)/100 - 1)
	return time.Duration(backoff + jitter)
}

// isRetryable checks if an error should trigger a retry
func (c *Client) isRetryable(err error) bool {
	// Retry on network errors, timeouts, and 5xx status codes
	// Don't retry on 4xx client errors (except 429 rate limit)

	// Check if it's an HTTP error
	if apiErr, ok := err.(*anthropic.Error); ok {
		statusCode := apiErr.StatusCode

		// Retry on server errors (5xx)
		if statusCode >= 500 && statusCode < 600 {
			return true
		}

		// Retry on rate limit (429)
		if statusCode == 429 {
			return true
		}

		// Don't retry on client errors (4xx)
		if statusCode >= 400 && statusCode < 500 {
			return false
		}
	}

	// Retry on context deadline exceeded or network errors
	return true
}

// cacheKey generates a cache key from the request parameters
func (c *Client) cacheKey(params anthropic.MessageNewParams) string {
	// Serialize params to JSON
	data, err := json.Marshal(params)
	if err != nil {
		// Fallback to timestamp-based key if serialization fails
		return fmt.Sprintf("error_%d", time.Now().UnixNano())
	}

	// Hash the JSON for a stable cache key
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Close releases resources used by the client
func (c *Client) Close() error {
	if c.cache != nil {
		c.cache.Close()
	}
	return nil
}

// GetStats returns client statistics
func (c *Client) GetStats() Stats {
	stats := Stats{
		Config: c.config.String(),
	}

	if c.rateLimiter != nil {
		stats.RateLimiterActive = true
		stats.RateLimitRemaining = c.rateLimiter.available
	}

	if c.circuitBreaker != nil {
		stats.CircuitBreakerActive = true
		stats.CircuitBreakerOpen = !c.circuitBreaker.Allow()
		stats.CircuitBreakerFailures = int(c.circuitBreaker.failures)
	}

	if c.cache != nil {
		metrics := c.cache.Metrics
		stats.CacheActive = true
		stats.CacheHits = metrics.Hits()
		stats.CacheMisses = metrics.Misses()
	}

	return stats
}

// Stats holds client statistics
type Stats struct {
	Config string

	RateLimiterActive   bool
	RateLimitRemaining  int

	CircuitBreakerActive   bool
	CircuitBreakerOpen     bool
	CircuitBreakerFailures int

	CacheActive bool
	CacheHits   uint64
	CacheMisses uint64
}

// rateLimiter implements a token bucket rate limiter
type rateLimiter struct {
	rate      int           // requests per minute
	available int           // available tokens
	lastCheck time.Time
	mu        sync.Mutex
}

func newRateLimiter(ratePerMinute int) *rateLimiter {
	return &rateLimiter{
		rate:      ratePerMinute,
		available: ratePerMinute,
		lastCheck: time.Now(),
	}
}

func (rl *rateLimiter) Wait(ctx context.Context) error {
	rl.mu.Lock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(rl.lastCheck)
	tokensToAdd := int(elapsed.Minutes() * float64(rl.rate))
	rl.available += tokensToAdd
	if rl.available > rl.rate {
		rl.available = rl.rate
	}
	rl.lastCheck = now

	// If no tokens available, wait
	if rl.available <= 0 {
		// Calculate wait time until next token
		waitTime := time.Minute / time.Duration(rl.rate)
		rl.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
		}

		rl.mu.Lock()
		rl.available = 1
	}

	rl.available--
	rl.mu.Unlock()
	return nil
}

// circuitBreaker implements a simple circuit breaker pattern
type circuitBreaker struct {
	threshold      int           // max failures before opening
	timeout        time.Duration // how long to stay open
	failures       int32         // current failure count
	lastFailure    time.Time
	state          int32 // 0 = closed, 1 = open
	mu             sync.RWMutex
}

func newCircuitBreaker(threshold int, timeout time.Duration) *circuitBreaker {
	return &circuitBreaker{
		threshold: threshold,
		timeout:   timeout,
	}
}

func (cb *circuitBreaker) Allow() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// If circuit is closed, allow
	if atomic.LoadInt32(&cb.state) == 0 {
		return true
	}

	// If timeout has passed, allow and reset (half-open state)
	if time.Since(cb.lastFailure) > cb.timeout {
		return true
	}

	return false
}

func (cb *circuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Reset on success
	atomic.StoreInt32(&cb.failures, 0)
	atomic.StoreInt32(&cb.state, 0)
}

func (cb *circuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	failures := atomic.AddInt32(&cb.failures, 1)
	cb.lastFailure = time.Now()

	// Open circuit if threshold exceeded
	if int(failures) >= cb.threshold {
		atomic.StoreInt32(&cb.state, 1)
	}
}
