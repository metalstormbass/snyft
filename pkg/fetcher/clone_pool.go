package fetcher

import "sync"

// DefaultClonePoolSize is the default number of concurrent git clone operations.
// Git clones use the git protocol (not the GitHub API) and should NOT be subject
// to API rate limiting. A pool of 20 allows clones to proceed independently of
// the analysis worker pool, which is typically smaller (default 10 workers).
const DefaultClonePoolSize = 20

// ClonePool manages concurrent git clone operations with a dedicated goroutine
// pool. It runs independently of the API/scraping worker pool and is NOT gated
// by the GitHub rate limiter — git clones use the git protocol, not the API.
//
// Clones are submitted as soon as their repo URLs are resolved and start
// executing immediately (up to the pool's concurrency limit). Results feed back
// into the analysis pipeline via the done channel returned by Submit.
type ClonePool struct {
	sem chan struct{}   // semaphore limiting concurrent clones
	wg  sync.WaitGroup // tracks in-flight clones for graceful shutdown
}

// NewClonePool creates a new clone pool with the given concurrency limit.
// If maxConcurrent is <= 0, DefaultClonePoolSize is used.
func NewClonePool(maxConcurrent int) *ClonePool {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultClonePoolSize
	}
	return &ClonePool{
		sem: make(chan struct{}, maxConcurrent),
	}
}

// Submit submits a clone operation to the pool. The clone starts as soon as a
// semaphore slot is available (up to pool size concurrent clones). Returns a
// channel that is closed when the clone completes.
//
// The clone function runs in its own goroutine, completely independent of the
// GitHub API rate limiter. Callers should pass a function that invokes
// GitHubClient.CloneAndAnalyze or equivalent.
func (p *ClonePool) Submit(cloneFn func()) <-chan struct{} {
	done := make(chan struct{})
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.sem <- struct{}{} // acquire slot
		defer func() { <-p.sem }() // release slot
		cloneFn()
		close(done)
	}()
	return done
}

// Wait blocks until all submitted clones have completed.
func (p *ClonePool) Wait() {
	p.wg.Wait()
}
