package fetcher

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// GitHubRateLimiter provides adaptive rate limiting for GitHub API requests.
// It starts with no throttling and dynamically adjusts based on GitHub's
// X-RateLimit-Remaining and X-RateLimit-Reset response headers.
//
// Justification: GitHub enforces strict rate limits (60/hr unauthenticated,
// 5000/hr authenticated). When scanning large projects with 10 concurrent
// workers making ~56 API calls per dependency, exhausting the limit takes
// minutes. Adaptive throttling prevents 403 responses that degrade scan
// quality by forcing fallback to less reliable scraping data.
type GitHubRateLimiter struct {
	limiter    *rate.Limiter
	mu         sync.Mutex
	hasToken   bool
	throttled  bool       // true once throttling has been engaged
	remaining  int        // last observed X-RateLimit-Remaining value; -1 = unknown
	warnedOnce sync.Once
}

// NewGitHubRateLimiter creates a rate limiter for GitHub API requests.
//
// The limiter starts with no throttling (rate.Inf) and adaptively slows
// down when GitHub's X-RateLimit-Remaining header indicates the quota is
// running low. This approach:
//   - Avoids unnecessary throttling for small scans or test suites
//   - Engages throttling only when the quota is actually at risk
//   - Respects GitHub's actual reset window for pacing
func NewGitHubRateLimiter(hasToken bool) *GitHubRateLimiter {
	return &GitHubRateLimiter{
		// Start unlimited — throttle only when headers indicate quota pressure.
		limiter:   rate.NewLimiter(rate.Inf, 1),
		hasToken:  hasToken,
		remaining: -1, // unknown until first API response
	}
}

// Wait blocks until the rate limiter permits the request to proceed.
// When the limiter is in its initial unlimited state, this returns immediately.
// Once throttling is engaged (via Update), this blocks as needed.
func (rl *GitHubRateLimiter) Wait() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_ = rl.limiter.Wait(ctx)
}

// Update adjusts the rate limiter based on GitHub's response headers.
// When X-RateLimit-Remaining drops below the threshold, the limiter
// transitions from unlimited to a rate that spreads remaining requests
// across the reset window.
//
// Thresholds:
//   - Authenticated:   remaining < 500 (10% of 5000/hr)
//   - Unauthenticated: remaining < 10  (~17% of 60/hr)
func (rl *GitHubRateLimiter) Update(resp *http.Response) {
	if resp == nil {
		return
	}

	remainingStr := resp.Header.Get("X-RateLimit-Remaining")
	resetStr := resp.Header.Get("X-RateLimit-Reset")

	if remainingStr == "" {
		return
	}

	remaining, err := strconv.Atoi(remainingStr)
	if err != nil {
		return
	}

	// Track the last-seen remaining value for ShouldFallbackToScraping() queries.
	rl.mu.Lock()
	rl.remaining = remaining
	rl.mu.Unlock()

	// Threshold: engage throttling when remaining quota is low.
	// Authenticated: 500 remaining out of 5000
	// Unauthenticated: 10 remaining out of 60
	threshold := 500
	if !rl.hasToken {
		threshold = 10
	}

	if remaining < threshold {
		rl.warnedOnce.Do(func() {
			if rl.hasToken {
				log.Printf("Rate limit approaching (%d remaining), throttling requests.", remaining)
			} else {
				log.Printf("Rate limit approaching (%d remaining), throttling requests. Set GITHUB_TOKEN for higher limits.", remaining)
			}
		})

		// Adaptively slow down: spread remaining requests across the reset window.
		if resetStr != "" {
			resetUnix, err := strconv.ParseInt(resetStr, 10, 64)
			if err == nil {
				resetTime := time.Unix(resetUnix, 0)
				untilReset := time.Until(resetTime)
				if untilReset > 0 && remaining > 0 {
					// Spread remaining requests evenly across the reset window,
					// leaving a 10% buffer to avoid hitting the exact limit.
					newRate := rate.Limit(float64(remaining) * 0.9 / untilReset.Seconds())
					rl.mu.Lock()
					if !rl.throttled || newRate < rl.limiter.Limit() {
						rl.limiter.SetLimit(newRate)
						rl.limiter.SetBurst(1)
						rl.throttled = true
					}
					rl.mu.Unlock()
				}
			}
		} else {
			// No reset header — apply a conservative fallback rate.
			rl.mu.Lock()
			if !rl.throttled {
				if rl.hasToken {
					// ~1.3 req/sec = 80/min
					rl.limiter.SetLimit(rate.Limit(80.0 / 60.0))
				} else {
					// ~1 req/min
					rl.limiter.SetLimit(rate.Limit(1.0 / 60.0))
				}
				rl.limiter.SetBurst(1)
				rl.throttled = true
			}
			rl.mu.Unlock()
		}
	}
}

// Remaining returns the last observed X-RateLimit-Remaining value.
// Returns -1 if no rate limit header has been seen yet (e.g. no API calls made).
func (rl *GitHubRateLimiter) Remaining() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.remaining
}

// ShouldFallbackToScraping returns true when the remaining API quota is below
// the given threshold, indicating that callers should switch to scraping-only
// mode rather than continuing to consume API calls. The scan never stops —
// it falls back to web scraping for remaining packages.
//
// Returns false when remaining is unknown (-1) — we only switch to scraping
// when we have positive evidence that the quota is nearly exhausted.
func (rl *GitHubRateLimiter) ShouldFallbackToScraping(threshold int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.remaining >= 0 && rl.remaining < threshold
}

// ShouldPreferScraping returns true when the API quota is low enough that
// methods with scraping alternatives should prefer scraping over API calls.
// This preserves remaining API quota for checks that truly need it (signed
// commits, attestations, GraphQL batch queries) while scraping handles the
// rest.
//
// Thresholds:
//   - Authenticated:   remaining < 300 (6% of 5000/hr)
//   - Unauthenticated: remaining < 15  (25% of 60/hr)
//
// Returns false when remaining is unknown (-1) — we only switch to scraping
// when we have positive evidence of quota pressure.
func (rl *GitHubRateLimiter) ShouldPreferScraping() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.remaining < 0 {
		return false
	}
	if rl.hasToken {
		return rl.remaining < 300
	}
	return rl.remaining < 15
}
