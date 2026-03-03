package fetcher

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

// Test: Remaining() returns -1 when no API response has been received
// Justification: Before any GitHub API call is made, the remaining count is
//                unknown. Returning -1 ensures ShouldFallbackToScraping() does not
//                prematurely trigger scraping fallback before any rate limit data is observed.
// Source: GitHub REST API rate limiting documentation
// Methodology: Create a fresh rate limiter and query Remaining() without Update()
// Result: Remaining() returns -1
func TestRateLimiter_Remaining_InitialUnknown(t *testing.T) {
	rl := NewGitHubRateLimiter(true)
	if got := rl.Remaining(); got != -1 {
		t.Errorf("Remaining() = %d, want -1 (unknown before first API call)", got)
	}
}

// Test: Remaining() tracks the last observed X-RateLimit-Remaining header
// Justification: Accurate tracking of the remaining quota is essential for the
//                rate limit gate to decide when to switch to scraping. The value
//                must reflect the most recent API response.
// Source: GitHub REST API rate limiting documentation
// Methodology: Call Update() with a mock response containing X-RateLimit-Remaining,
//              then verify Remaining() returns that value
// Result: Remaining() matches the header value
func TestRateLimiter_Remaining_TracksHeader(t *testing.T) {
	rl := NewGitHubRateLimiter(true)

	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"4500"},
		},
	}
	rl.Update(resp)

	if got := rl.Remaining(); got != 4500 {
		t.Errorf("Remaining() = %d, want 4500", got)
	}

	// Update with a lower value
	resp.Header.Set("X-Ratelimit-Remaining", "100")
	rl.Update(resp)

	if got := rl.Remaining(); got != 100 {
		t.Errorf("Remaining() = %d after second update, want 100", got)
	}
}

// Test: ShouldFallbackToScraping() returns false when remaining is unknown
// Justification: The scan must not switch to scraping before any rate limit
//                information has been received. Unknown remaining (-1) means we
//                have no evidence of quota pressure, so we should continue with API.
// Source: GitHub REST API rate limiting documentation
// Methodology: Create a fresh rate limiter, call ShouldFallbackToScraping(50)
// Result: Returns false (no evidence of quota exhaustion)
func TestRateLimiter_ShouldFallbackToScraping_FalseWhenUnknown(t *testing.T) {
	rl := NewGitHubRateLimiter(true)
	if rl.ShouldFallbackToScraping(50) {
		t.Error("ShouldFallbackToScraping(50) = true when remaining is unknown, want false")
	}
}

// Test: ShouldFallbackToScraping() returns true when remaining is below threshold
// Justification: When the GitHub API quota drops below the scraping threshold (50),
//                the scan switches to scraping-only mode for remaining packages,
//                preserving quota for checks that truly need the API.
// Source: GitHub REST API rate limiting documentation
// Methodology: Update the limiter with a remaining count below 50, verify ShouldFallbackToScraping
// Result: Returns true
func TestRateLimiter_ShouldFallbackToScraping_TrueWhenBelowThreshold(t *testing.T) {
	rl := NewGitHubRateLimiter(true)

	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"30"},
			"X-Ratelimit-Reset":     []string{strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
		},
	}
	rl.Update(resp)

	if !rl.ShouldFallbackToScraping(50) {
		t.Error("ShouldFallbackToScraping(50) = false when remaining is 30, want true")
	}
}

// Test: ShouldFallbackToScraping() returns false when remaining is above threshold
// Justification: The scan should continue with full API access when the quota has
//                sufficient headroom above the scraping threshold.
// Source: GitHub REST API rate limiting documentation
// Methodology: Update the limiter with a remaining count above 50
// Result: Returns false
func TestRateLimiter_ShouldFallbackToScraping_FalseWhenAboveThreshold(t *testing.T) {
	rl := NewGitHubRateLimiter(true)

	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"2000"},
		},
	}
	rl.Update(resp)

	if rl.ShouldFallbackToScraping(50) {
		t.Error("ShouldFallbackToScraping(50) = true when remaining is 2000, want false")
	}
}

// Test: ShouldFallbackToScraping() returns true at exact threshold boundary
// Justification: The threshold check uses < (strictly less than), so remaining
//                exactly at the threshold should return false (we still have
//                exactly the threshold number of calls available).
// Source: GitHub REST API rate limiting documentation
// Methodology: Set remaining to exactly 50 and check ShouldFallbackToScraping(50)
// Result: Returns false (remaining == threshold is not below threshold)
func TestRateLimiter_ShouldFallbackToScraping_ExactThreshold(t *testing.T) {
	rl := NewGitHubRateLimiter(true)

	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"50"},
		},
	}
	rl.Update(resp)

	if rl.ShouldFallbackToScraping(50) {
		t.Error("ShouldFallbackToScraping(50) = true when remaining is exactly 50, want false (not strictly below)")
	}

	// But 49 should trigger
	resp.Header.Set("X-Ratelimit-Remaining", "49")
	resp.Header.Set("X-Ratelimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	rl.Update(resp)

	if !rl.ShouldFallbackToScraping(50) {
		t.Error("ShouldFallbackToScraping(50) = false when remaining is 49, want true")
	}
}

// Test: ShouldFallbackToScraping() handles nil response gracefully in Update
// Justification: Network errors may produce nil responses. The rate limiter
//                must not panic or change state on nil input.
// Source: Defense-in-depth principle
// Methodology: Call Update(nil), verify Remaining() stays -1
// Result: No crash, remaining stays unknown
func TestRateLimiter_Update_NilResponse(t *testing.T) {
	rl := NewGitHubRateLimiter(true)
	rl.Update(nil)

	if got := rl.Remaining(); got != -1 {
		t.Errorf("Remaining() = %d after nil Update, want -1", got)
	}
}

// Test: ShouldPreferScraping() returns false when remaining is unknown
// Justification: Before any API response is received, the remaining quota is
//                unknown. We should not switch to scraping mode until we have
//                positive evidence of quota pressure. Premature scraping wastes
//                the opportunity to collect richer API data.
// Source: GitHub REST API rate limiting documentation
// Methodology: Create a fresh rate limiter and query ShouldPreferScraping()
// Result: Returns false (no evidence of quota pressure)
func TestRateLimiter_ShouldPreferScraping_FalseWhenUnknown(t *testing.T) {
	rl := NewGitHubRateLimiter(true)
	if rl.ShouldPreferScraping() {
		t.Error("ShouldPreferScraping() = true when remaining is unknown, want false")
	}
}

// Test: ShouldPreferScraping() returns true for authenticated client when remaining < 300
// Justification: When the authenticated API quota (5000/hr) drops below 300,
//                methods with scraping alternatives should switch to scraping
//                to preserve remaining API calls for checks that truly need API
//                access (signed commits, attestations, GraphQL batch queries).
// Source: GitHub REST API rate limiting documentation
// Methodology: Update the limiter with remaining=200 (below 300 threshold),
//              verify ShouldPreferScraping() returns true
// Result: Returns true (scraping should be preferred)
func TestRateLimiter_ShouldPreferScraping_TrueWhenLowQuota_Authenticated(t *testing.T) {
	rl := NewGitHubRateLimiter(true)
	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"200"},
			"X-Ratelimit-Reset":     []string{strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
		},
	}
	rl.Update(resp)

	if !rl.ShouldPreferScraping() {
		t.Error("ShouldPreferScraping() = false when remaining is 200 (authenticated), want true")
	}
}

// Test: ShouldPreferScraping() returns false for authenticated client when quota is healthy
// Justification: When the authenticated API quota has ample headroom (e.g. 2000
//                remaining out of 5000), the API should be used for richer data.
//                Scraping preference should only kick in when quota is genuinely low.
// Source: GitHub REST API rate limiting documentation
// Methodology: Update the limiter with remaining=2000 (above 300 threshold),
//              verify ShouldPreferScraping() returns false
// Result: Returns false (API should be preferred)
func TestRateLimiter_ShouldPreferScraping_FalseWhenHealthyQuota_Authenticated(t *testing.T) {
	rl := NewGitHubRateLimiter(true)
	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"2000"},
		},
	}
	rl.Update(resp)

	if rl.ShouldPreferScraping() {
		t.Error("ShouldPreferScraping() = true when remaining is 2000 (authenticated), want false")
	}
}

// Test: ShouldPreferScraping() returns true for unauthenticated client when remaining < 15
// Justification: Unauthenticated clients have only 60 req/hr. When remaining
//                drops below 15, scraping should be preferred to preserve the
//                small quota for API-only checks.
// Source: GitHub REST API rate limiting documentation
// Methodology: Update the limiter with remaining=10 (below 15 threshold),
//              verify ShouldPreferScraping() returns true
// Result: Returns true (scraping should be preferred)
func TestRateLimiter_ShouldPreferScraping_TrueWhenLowQuota_Unauthenticated(t *testing.T) {
	rl := NewGitHubRateLimiter(false)
	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"10"},
			"X-Ratelimit-Reset":     []string{strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
		},
	}
	rl.Update(resp)

	if !rl.ShouldPreferScraping() {
		t.Error("ShouldPreferScraping() = false when remaining is 10 (unauthenticated), want true")
	}
}

// Test: ShouldPreferScraping() threshold boundary for authenticated client
// Justification: The threshold check uses < 300. At exactly 300 remaining,
//                the quota is at the boundary — not yet low enough to prefer
//                scraping. At 299, scraping should be preferred.
// Source: GitHub REST API rate limiting documentation
// Methodology: Test at exactly 300 (not below) and at 299 (below)
// Result: 300 returns false, 299 returns true
func TestRateLimiter_ShouldPreferScraping_BoundaryAuthenticated(t *testing.T) {
	rl := NewGitHubRateLimiter(true)

	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"300"},
		},
	}
	rl.Update(resp)

	if rl.ShouldPreferScraping() {
		t.Error("ShouldPreferScraping() = true when remaining is exactly 300, want false")
	}

	resp.Header.Set("X-Ratelimit-Remaining", "299")
	resp.Header.Set("X-Ratelimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	rl.Update(resp)

	if !rl.ShouldPreferScraping() {
		t.Error("ShouldPreferScraping() = false when remaining is 299, want true")
	}
}
