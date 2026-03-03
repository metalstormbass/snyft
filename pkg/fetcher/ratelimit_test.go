package fetcher

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

// Test: Remaining() returns -1 when no API response has been received
// Justification: Before any GitHub API call is made, the remaining count is
//                unknown. Returning -1 ensures ShouldStop() does not
//                prematurely halt a scan before any rate limit data is observed.
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
//                rate limit gate to decide when to stop scanning. The value must
//                reflect the most recent API response.
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

// Test: ShouldStop() returns false when remaining is unknown
// Justification: The scan must not stop before any rate limit information has been
//                received. Unknown remaining (-1) means we have no evidence of
//                quota pressure, so we should continue scanning.
// Source: GitHub REST API rate limiting documentation
// Methodology: Create a fresh rate limiter, call ShouldStop(50)
// Result: Returns false (no evidence of quota exhaustion)
func TestRateLimiter_ShouldStop_FalseWhenUnknown(t *testing.T) {
	rl := NewGitHubRateLimiter(true)
	if rl.ShouldStop(50) {
		t.Error("ShouldStop(50) = true when remaining is unknown, want false")
	}
}

// Test: ShouldStop() returns true when remaining is below threshold
// Justification: When the GitHub API quota drops below the stop threshold (50),
//                the scan must stop to preserve remaining quota for other tools
//                and allow the user to resume after the rate limit resets.
// Source: GitHub REST API rate limiting documentation
// Methodology: Update the limiter with a remaining count below 50, verify ShouldStop
// Result: Returns true
func TestRateLimiter_ShouldStop_TrueWhenBelowThreshold(t *testing.T) {
	rl := NewGitHubRateLimiter(true)

	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"30"},
			"X-Ratelimit-Reset":     []string{strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
		},
	}
	rl.Update(resp)

	if !rl.ShouldStop(50) {
		t.Error("ShouldStop(50) = false when remaining is 30, want true")
	}
}

// Test: ShouldStop() returns false when remaining is above threshold
// Justification: The scan should continue normally when the API quota has
//                sufficient headroom above the stop threshold.
// Source: GitHub REST API rate limiting documentation
// Methodology: Update the limiter with a remaining count above 50
// Result: Returns false
func TestRateLimiter_ShouldStop_FalseWhenAboveThreshold(t *testing.T) {
	rl := NewGitHubRateLimiter(true)

	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"2000"},
		},
	}
	rl.Update(resp)

	if rl.ShouldStop(50) {
		t.Error("ShouldStop(50) = true when remaining is 2000, want false")
	}
}

// Test: ShouldStop() returns true at exact threshold boundary
// Justification: The threshold check uses < (strictly less than), so remaining
//                exactly at the threshold should return false (we still have
//                exactly the threshold number of calls available).
// Source: GitHub REST API rate limiting documentation
// Methodology: Set remaining to exactly 50 and check ShouldStop(50)
// Result: Returns false (remaining == threshold is not below threshold)
func TestRateLimiter_ShouldStop_ExactThreshold(t *testing.T) {
	rl := NewGitHubRateLimiter(true)

	resp := &http.Response{
		Header: http.Header{
			"X-Ratelimit-Remaining": []string{"50"},
		},
	}
	rl.Update(resp)

	if rl.ShouldStop(50) {
		t.Error("ShouldStop(50) = true when remaining is exactly 50, want false (not strictly below)")
	}

	// But 49 should trigger
	resp.Header.Set("X-Ratelimit-Remaining", "49")
	resp.Header.Set("X-Ratelimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	rl.Update(resp)

	if !rl.ShouldStop(50) {
		t.Error("ShouldStop(50) = false when remaining is 49, want true")
	}
}

// Test: ShouldStop() handles nil response gracefully in Update
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
