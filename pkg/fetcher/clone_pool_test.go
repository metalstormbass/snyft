package fetcher

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test: ClonePool respects concurrency limit
// Justification: Unbounded concurrent clones could exhaust disk/network and
//   degrade the host, reducing the reliability of supply chain analysis.
// Source: General concurrency best practices; pool pattern from Go stdlib
// Methodology: Submit more clones than pool size, verify max concurrent never exceeds limit
// Result: At no point do more than maxConcurrent clones run simultaneously
func TestClonePool_ConcurrencyLimit(t *testing.T) {
	const poolSize = 3
	const totalClones = 10

	pool := NewClonePool(poolSize)
	var running atomic.Int32
	var maxRunning atomic.Int32

	var doneChans []<-chan struct{}
	for i := 0; i < totalClones; i++ {
		done := pool.Submit(func() {
			cur := running.Add(1)
			// Track peak concurrency
			for {
				old := maxRunning.Load()
				if cur <= old || maxRunning.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			running.Add(-1)
		})
		doneChans = append(doneChans, done)
	}

	// Wait for all clones to complete
	for _, done := range doneChans {
		<-done
	}

	peak := maxRunning.Load()
	if peak > int32(poolSize) {
		t.Errorf("peak concurrent clones = %d, want <= %d", peak, poolSize)
	}
	if peak == 0 {
		t.Error("no clones ran")
	}
}

// Test: ClonePool done channel signals completion
// Justification: The analysis pipeline blocks on the done channel to wait for
//   clone data before scoring. If the channel isn't closed, analysis hangs.
// Source: Go concurrency patterns; channel signaling idiom
// Methodology: Submit a clone, verify done channel closes after function returns
// Result: Done channel is closed, subsequent receives return immediately
func TestClonePool_DoneChannelClosed(t *testing.T) {
	pool := NewClonePool(1)
	executed := atomic.Bool{}

	done := pool.Submit(func() {
		executed.Store(true)
	})

	select {
	case <-done:
		// done channel closed — good
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for done channel")
	}

	if !executed.Load() {
		t.Error("clone function was not executed")
	}
}

// Test: ClonePool runs independently (no rate limiter interaction)
// Justification: Git clones use the git protocol, not the GitHub API. They must
//   not be gated by the rate limiter that throttles API calls, otherwise clones
//   would stall when the API limit is low even though they don't consume it.
// Source: GitHub docs — git protocol endpoints are separate from REST API rate limits
// Methodology: Create a pool and verify it has no dependency on any rate limiter;
//   clones proceed even when a hypothetical rate limiter would block API calls
// Result: All clones complete successfully without any rate limit check
func TestClonePool_IndependentOfRateLimiter(t *testing.T) {
	pool := NewClonePool(5)
	var completed atomic.Int32

	var doneChans []<-chan struct{}
	for i := 0; i < 10; i++ {
		done := pool.Submit(func() {
			// Simulate clone work — no rate limiter consulted
			time.Sleep(1 * time.Millisecond)
			completed.Add(1)
		})
		doneChans = append(doneChans, done)
	}

	for _, done := range doneChans {
		<-done
	}

	if completed.Load() != 10 {
		t.Errorf("completed %d clones, want 10", completed.Load())
	}
}

// Test: ClonePool.Wait blocks until all clones finish
// Justification: At scan completion, all clones must have finished so cleanup
//   and result collection are safe. Wait() provides this guarantee.
// Source: sync.WaitGroup pattern from Go stdlib
// Methodology: Submit several clones, call Wait(), verify all completed
// Result: After Wait() returns, all clone functions have executed
func TestClonePool_WaitCompletion(t *testing.T) {
	pool := NewClonePool(2)
	var completed atomic.Int32

	for i := 0; i < 5; i++ {
		pool.Submit(func() {
			time.Sleep(5 * time.Millisecond)
			completed.Add(1)
		})
	}

	pool.Wait()

	if completed.Load() != 5 {
		t.Errorf("completed %d clones after Wait(), want 5", completed.Load())
	}
}

// Test: ClonePool handles concurrent submissions safely
// Justification: Multiple analysis workers submit clones concurrently as they
//   resolve repo URLs. The pool must handle concurrent Submit calls without races.
// Source: Go data race detector validates concurrent correctness
// Methodology: Submit clones from multiple goroutines simultaneously
// Result: No data races, all clones complete
func TestClonePool_ConcurrentSubmit(t *testing.T) {
	pool := NewClonePool(5)
	var completed atomic.Int32
	var submitWg sync.WaitGroup

	allDone := make([]<-chan struct{}, 20)
	var mu sync.Mutex

	for i := 0; i < 20; i++ {
		submitWg.Add(1)
		idx := i
		go func() {
			defer submitWg.Done()
			done := pool.Submit(func() {
				time.Sleep(1 * time.Millisecond)
				completed.Add(1)
			})
			mu.Lock()
			allDone[idx] = done
			mu.Unlock()
		}()
	}

	submitWg.Wait()
	for _, done := range allDone {
		<-done
	}

	if completed.Load() != 20 {
		t.Errorf("completed %d clones, want 20", completed.Load())
	}
}

// Test: NewClonePool uses default size for invalid input
// Justification: Callers may pass 0 or negative values; the pool should fall
//   back to a sensible default rather than deadlocking or panicking.
// Source: Defensive programming pattern
// Methodology: Create pool with 0 and -1, verify it still works
// Result: Pool functions correctly with default concurrency
func TestClonePool_DefaultSize(t *testing.T) {
	for _, size := range []int{0, -1} {
		pool := NewClonePool(size)
		done := pool.Submit(func() {})
		select {
		case <-done:
			// OK
		case <-time.After(5 * time.Second):
			t.Fatalf("pool with size %d: timed out", size)
		}
	}
}
