package cmd

import (
	"bytes"
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: groupByRepo groups packages sharing the same source repository
// Justification: When 100+ AWS SDK artifacts all come from github.com/aws/aws-sdk-java,
//                repo-level analysis (clone, CI, governance, health) should run once,
//                not 100 times. Grouping by repo URL enables this deduplication.
// Source: "Small World with High Risks" (Zimmermann et al., 2019) — dependency networks
//         exhibit high duplication at the repository level
// Methodology: Create deps with pre-resolved repo URLs pointing to the same repo,
//              verify they are grouped together
// Result: All deps from the same repo are in one group
func TestGroupByRepo_SameRepo(t *testing.T) {
	deps := []models.Dependency{
		{
			Name:            "aws-sdk-core",
			Version:         "2.0.0",
			Ecosystem:       models.EcosystemMaven,
			ResolvedRepoURL: "https://github.com/aws/aws-sdk-java",
		},
		{
			Name:            "aws-sdk-s3",
			Version:         "2.0.0",
			Ecosystem:       models.EcosystemMaven,
			ResolvedRepoURL: "https://github.com/aws/aws-sdk-java",
		},
		{
			Name:            "aws-sdk-ec2",
			Version:         "2.0.0",
			Ecosystem:       models.EcosystemMaven,
			ResolvedRepoURL: "https://github.com/aws/aws-sdk-java",
		},
		{
			Name:            "spring-core",
			Version:         "5.3.0",
			Ecosystem:       models.EcosystemMaven,
			ResolvedRepoURL: "https://github.com/spring-projects/spring-framework",
		},
	}

	groups, groupMap := groupByRepo(deps)

	// Should have 2 groups: aws-sdk-java and spring-framework
	if len(groups) != 2 {
		t.Fatalf("Expected 2 repo groups, got %d", len(groups))
	}

	// AWS group should have 3 deps
	awsKey := "github.com/aws/aws-sdk-java"
	awsIdx, ok := groupMap[awsKey]
	if !ok {
		t.Fatalf("Expected group for %s", awsKey)
	}
	if len(groups[awsIdx].DepIndices) != 3 {
		t.Errorf("Expected 3 deps in AWS group, got %d", len(groups[awsIdx].DepIndices))
	}

	// Spring group should have 1 dep
	springKey := "github.com/spring-projects/spring-framework"
	springIdx, ok := groupMap[springKey]
	if !ok {
		t.Fatalf("Expected group for %s", springKey)
	}
	if len(groups[springIdx].DepIndices) != 1 {
		t.Errorf("Expected 1 dep in Spring group, got %d", len(groups[springIdx].DepIndices))
	}
}

// Test: groupByRepo handles packages without resolved repo URLs
// Justification: Some packages fail repo URL resolution (private registries,
//                API errors). These should be grouped separately and still analyzed.
// Source: Defense-in-depth — partial data shouldn't break the scan pipeline
// Methodology: Create deps where some have empty ResolvedRepoURL
// Result: Unresolved deps are in a separate "" group
func TestGroupByRepo_UnresolvedURLs(t *testing.T) {
	deps := []models.Dependency{
		{
			Name:            "known-pkg",
			Ecosystem:       models.EcosystemNPM,
			ResolvedRepoURL: "https://github.com/org/known-pkg",
		},
		{
			Name:            "unknown-pkg",
			Ecosystem:       models.EcosystemNPM,
			ResolvedRepoURL: "", // could not resolve
		},
	}

	groups, groupMap := groupByRepo(deps)

	if len(groups) != 2 {
		t.Fatalf("Expected 2 groups (resolved + unresolved), got %d", len(groups))
	}

	// The empty key group should contain the unresolved dep
	emptyIdx, ok := groupMap[""]
	if !ok {
		t.Fatal("Expected a group for unresolved deps (empty key)")
	}
	if len(groups[emptyIdx].DepIndices) != 1 {
		t.Errorf("Expected 1 unresolved dep, got %d", len(groups[emptyIdx].DepIndices))
	}
}

// Test: groupByRepo normalizes URL variants to the same key
// Justification: The same repo can appear as different URL forms across packages
//                (e.g. "https://github.com/org/repo.git" vs "https://github.com/org/repo").
//                Normalization ensures they're grouped together.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — accurate repo
//         identification prevents redundant analysis
// Methodology: Create deps with different URL forms for the same repo
// Result: All variants grouped under one normalized key
func TestGroupByRepo_NormalizesURLVariants(t *testing.T) {
	deps := []models.Dependency{
		{
			Name:            "pkg-a",
			Ecosystem:       models.EcosystemNPM,
			ResolvedRepoURL: "https://github.com/org/repo.git",
		},
		{
			Name:            "pkg-b",
			Ecosystem:       models.EcosystemNPM,
			ResolvedRepoURL: "https://github.com/org/repo",
		},
		{
			Name:            "pkg-c",
			Ecosystem:       models.EcosystemNPM,
			ResolvedRepoURL: "git+https://github.com/org/repo.git",
		},
	}

	groups, _ := groupByRepo(deps)

	// All 3 should be in the same group
	if len(groups) != 1 {
		t.Fatalf("Expected 1 group (all URL variants normalize to same repo), got %d", len(groups))
	}
	if len(groups[0].DepIndices) != 3 {
		t.Errorf("Expected 3 deps in group, got %d", len(groups[0].DepIndices))
	}
}

// Test: sortDepsByRepoGroup puts same-repo packages adjacent
// Justification: When same-repo packages are adjacent in the work queue, the
//                first worker triggers full repo analysis and subsequent workers
//                get cache hits. Without sorting, workers may race to analyze
//                the same repo concurrently (still correct via singleflight, but
//                less efficient due to wait time).
// Source: Standard cache optimization — locality of reference
// Methodology: Create shuffled deps from different repos, sort, verify adjacency
// Result: Deps from the same repo are adjacent after sorting
func TestSortDepsByRepoGroup(t *testing.T) {
	deps := []models.Dependency{
		{Name: "aws-1", ResolvedRepoURL: "https://github.com/aws/sdk"},
		{Name: "spring-1", ResolvedRepoURL: "https://github.com/spring/framework"},
		{Name: "aws-2", ResolvedRepoURL: "https://github.com/aws/sdk"},
		{Name: "react-1", ResolvedRepoURL: "https://github.com/facebook/react"},
		{Name: "aws-3", ResolvedRepoURL: "https://github.com/aws/sdk"},
		{Name: "spring-2", ResolvedRepoURL: "https://github.com/spring/framework"},
	}

	sortDepsByRepoGroup(deps)

	// Verify that deps with the same repo URL are adjacent
	seen := make(map[string]bool)
	for i, dep := range deps {
		key := dep.ResolvedRepoURL
		if i > 0 && deps[i-1].ResolvedRepoURL != key && seen[key] {
			t.Errorf("Dep %q (repo %s) is not adjacent to other deps from the same repo", dep.Name, key)
		}
		seen[key] = true
	}
}

// Test: groupByRepo handles empty input
// Justification: Edge case — empty dependency lists should return empty results
// Source: Defense-in-depth principle
// Methodology: Pass empty/nil slice
// Result: Returns empty groups and map
func TestGroupByRepo_Empty(t *testing.T) {
	groups, groupMap := groupByRepo(nil)
	if len(groups) != 0 {
		t.Errorf("Expected 0 groups for nil input, got %d", len(groups))
	}
	if len(groupMap) != 0 {
		t.Errorf("Expected empty groupMap for nil input, got %d entries", len(groupMap))
	}

	groups, groupMap = groupByRepo([]models.Dependency{})
	if len(groups) != 0 {
		t.Errorf("Expected 0 groups for empty input, got %d", len(groups))
	}
	if len(groupMap) != 0 {
		t.Errorf("Expected empty groupMap for empty input, got %d entries", len(groupMap))
	}
}

// Test: printRepoGroupStats outputs meaningful dedup statistics
// Justification: Users should see how many unique repos their dependency list
//                maps to, so they understand the scan time reduction
// Source: User experience — transparent optimization communication
// Methodology: Create groups with various sizes, verify output contains key stats
// Result: Output includes package count, repo count, and top groups
func TestPrintRepoGroupStats(t *testing.T) {
	groups := []repoGroup{
		{NormalizedURL: "github.com/aws/sdk", DepIndices: make([]int, 50)},
		{NormalizedURL: "github.com/spring/framework", DepIndices: make([]int, 20)},
		{NormalizedURL: "github.com/facebook/react", DepIndices: make([]int, 1)},
		{NormalizedURL: "", DepIndices: make([]int, 5)}, // unresolved
	}

	var buf bytes.Buffer
	printRepoGroupStats(groups, 76, &buf)

	output := buf.String()
	if output == "" {
		t.Fatal("Expected non-empty stats output")
	}

	// Should mention the resolved count and repo count
	if !bytes.Contains(buf.Bytes(), []byte("71 packages")) {
		t.Errorf("Expected output to mention '71 packages', got: %s", output)
	}
	if !bytes.Contains(buf.Bytes(), []byte("3 unique repos")) {
		t.Errorf("Expected output to mention '3 unique repos', got: %s", output)
	}
}
