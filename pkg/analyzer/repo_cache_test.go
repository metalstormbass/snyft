package analyzer

import (
	"sync"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: repoAnalysisCache returns cached data for the same repo key
// Justification: When multiple packages share the same source repo, the first
//                package triggers full repo-level analysis and subsequent packages
//                should get the cached result. This is the core mechanism that
//                turns a 7,749-package scan into ~400 repo analyses.
// Source: "Small World with High Risks" (Zimmermann et al., 2019) — dependency
//         networks exhibit high repo-level duplication
// Methodology: Set data for a key, then retrieve it and verify match
// Result: Cached data is returned correctly
func TestRepoAnalysisCache_SetAndGet(t *testing.T) {
	cache := newRepoAnalysisCache()

	key := "github.com/aws/aws-sdk-java"
	data := &RepoAnalysisData{
		SourceCodeAvailable: true,
		RepoOwner:           "aws",
		RepoName:            "aws-sdk-java",
		RepoStars:           5000,
		HasCI:               true,
		CISystems:           []string{"GitHub Actions"},
		BusFactor:           15,
	}

	// First call: no cache hit, registers as inflight
	cached, ok := cache.getOrWait(key)
	if ok {
		t.Fatal("Expected cache miss on first call")
	}
	if cached != nil {
		t.Fatal("Expected nil data on cache miss")
	}

	// Set the data
	cache.set(key, data)

	// Second call: should be a cache hit
	cached, ok = cache.getOrWait(key)
	if !ok {
		t.Fatal("Expected cache hit after set")
	}
	if cached == nil {
		t.Fatal("Expected non-nil cached data")
	}
	if cached.RepoOwner != "aws" {
		t.Errorf("Expected RepoOwner 'aws', got %q", cached.RepoOwner)
	}
	if cached.RepoStars != 5000 {
		t.Errorf("Expected RepoStars 5000, got %d", cached.RepoStars)
	}
	if cached.BusFactor != 15 {
		t.Errorf("Expected BusFactor 15, got %d", cached.BusFactor)
	}
}

// Test: repoAnalysisCache singleflight pattern — concurrent waiters get result
// Justification: When multiple worker goroutines request the same repo
//                simultaneously, only one should do the actual analysis.
//                Others should block and receive the cached result once available.
// Source: Cache concurrency safety — prevents thundering herd on same-repo analysis
// Methodology: Launch multiple goroutines requesting the same key; one sets the
//              data, others should receive it via the wait mechanism
// Result: All goroutines receive the correct data
func TestRepoAnalysisCache_ConcurrentWaiters(t *testing.T) {
	cache := newRepoAnalysisCache()
	key := "github.com/spring-projects/spring-framework"

	// First goroutine gets the "inflight" slot
	cached, ok := cache.getOrWait(key)
	if ok {
		t.Fatal("Expected cache miss on first call")
	}
	_ = cached

	// Launch concurrent waiters
	var wg sync.WaitGroup
	results := make([]*RepoAnalysisData, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			data, ok := cache.getOrWait(key)
			if !ok {
				t.Errorf("Waiter %d: expected cache hit after set", idx)
				return
			}
			results[idx] = data
		}(i)
	}

	// Small delay to let waiters block
	time.Sleep(10 * time.Millisecond)

	// Set the data — this should unblock all waiters
	expected := &RepoAnalysisData{
		RepoOwner: "spring-projects",
		RepoStars: 40000,
	}
	cache.set(key, expected)

	wg.Wait()

	// All waiters should have received the same data
	for i, r := range results {
		if r == nil {
			t.Errorf("Waiter %d: got nil result", i)
			continue
		}
		if r.RepoOwner != "spring-projects" {
			t.Errorf("Waiter %d: expected RepoOwner 'spring-projects', got %q", i, r.RepoOwner)
		}
	}
}

// Test: applyRepoData correctly copies repo-level data to analysis result
// Justification: Cached repo data must be accurately applied to each per-package
//                analysis result. Incorrect field mapping would produce wrong
//                risk scores for packages using cached data.
// Source: Cache correctness — data integrity across cache consumers
// Methodology: Create RepoAnalysisData with known values, apply to a result,
//              verify all fields match
// Result: All repo-level fields are correctly copied to the result
func TestApplyRepoData(t *testing.T) {
	rd := &RepoAnalysisData{
		SourceCodeAvailable: true,
		RepoOwner:           "test-org",
		RepoName:            "test-repo",
		RepoStars:           1234,
		RepoForks:           567,
		HasCI:               true,
		CISystems:           []string{"GitHub Actions", "CircleCI"},
		BuildInfrastructure: "CI detected: GitHub Actions (GitHub), CircleCI (CircleCI)",
		BusFactor:           8,
		TopContributorPct:   25.5,
		OSSFScore:           7.5,
		Findings: []models.Finding{
			{Category: "Stale Repository", Severity: "MEDIUM"},
		},
		RiskFactors: []string{"Inactive development"},
	}

	result := &models.AnalysisResult{
		Findings:    []models.Finding{},
		RiskFactors: []string{},
	}

	applyRepoData(result, rd)

	if !result.SourceCodeAvailable {
		t.Error("Expected SourceCodeAvailable=true")
	}
	if result.Metadata.RepoOwner != "test-org" {
		t.Errorf("Expected RepoOwner 'test-org', got %q", result.Metadata.RepoOwner)
	}
	if result.Metadata.RepoStars != 1234 {
		t.Errorf("Expected RepoStars 1234, got %d", result.Metadata.RepoStars)
	}
	if result.Metadata.BusFactor != 8 {
		t.Errorf("Expected BusFactor 8, got %d", result.Metadata.BusFactor)
	}
	if result.Metadata.OSSFScore != 7.5 {
		t.Errorf("Expected OSSFScore 7.5, got %f", result.Metadata.OSSFScore)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Category != "Stale Repository" {
		t.Errorf("Expected finding category 'Stale Repository', got %q", result.Findings[0].Category)
	}
	if len(result.RiskFactors) != 1 || result.RiskFactors[0] != "Inactive development" {
		t.Errorf("Expected risk factor 'Inactive development', got %v", result.RiskFactors)
	}
}

// Test: extractRepoData captures repo-level data and filters per-package data
// Justification: When caching repo-level data from a completed analysis, only
//                repo-level findings/risk factors should be cached — per-package
//                findings (like source verification) must NOT be shared across
//                packages from the same repo.
// Source: Cache correctness — sharing per-package data across packages would
//         produce incorrect risk scores
// Methodology: Create a result with both repo-level and per-package findings,
//              extract repo data, verify only repo-level items are included
// Result: Extracted data contains only repo-level findings
func TestExtractRepoData_FiltersPerPackageFindings(t *testing.T) {
	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		BuildInfrastructure: "CI detected: GitHub Actions (GitHub)",
		Metadata: models.PackageMetadata{
			RepoOwner:  "test-org",
			RepoStars:  100,
			HasCI:      true,
			CISystems:  []string{"GitHub Actions"},
			BusFactor:  5,
		},
		Findings: []models.Finding{
			// Repo-level finding — should be included
			{Category: "No CI/CD", Severity: "MEDIUM"},
			// Per-package finding — should NOT be included
			{Category: "Source Code Verification Failed", Severity: "HIGH"},
			// Per-package finding — should NOT be included
			{Category: "Package Not Found", Severity: "HIGH"},
			// Repo-level finding — should be included
			{Category: "Low OSSF Score", Severity: "MEDIUM"},
		},
		RiskFactors: []string{
			"No automated build verification", // repo-level
			"No verifiable source code for exact version", // per-package (should not be included)
		},
	}

	rd := extractRepoData(result)

	if rd.RepoOwner != "test-org" {
		t.Errorf("Expected RepoOwner 'test-org', got %q", rd.RepoOwner)
	}

	// Should only have the 2 repo-level findings
	if len(rd.Findings) != 2 {
		t.Fatalf("Expected 2 repo-level findings, got %d: %v", len(rd.Findings), rd.Findings)
	}
	for _, f := range rd.Findings {
		if f.Category == "Source Code Verification Failed" || f.Category == "Package Not Found" {
			t.Errorf("Per-package finding %q should not be in repo cache", f.Category)
		}
	}

	// Should only have the 1 repo-level risk factor
	if len(rd.RiskFactors) != 1 {
		t.Fatalf("Expected 1 repo-level risk factor, got %d: %v", len(rd.RiskFactors), rd.RiskFactors)
	}
	if rd.RiskFactors[0] != "No automated build verification" {
		t.Errorf("Expected 'No automated build verification', got %q", rd.RiskFactors[0])
	}
}

// Test: repoAnalysisCache Len returns correct count
// Justification: The Len method is used to report repo-level dedup stats
// Source: Cache correctness
// Methodology: Add items and verify count
// Result: Len returns correct count
func TestRepoAnalysisCache_Len(t *testing.T) {
	cache := newRepoAnalysisCache()

	if cache.Len() != 0 {
		t.Errorf("Expected 0 for empty cache, got %d", cache.Len())
	}

	cache.set("repo1", &RepoAnalysisData{})
	cache.set("repo2", &RepoAnalysisData{})

	if cache.Len() != 2 {
		t.Errorf("Expected 2 after adding 2 items, got %d", cache.Len())
	}
}
