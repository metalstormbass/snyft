package cmd

import (
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: deduplicateDependencies keeps direct when both direct and transitive exist
// Justification: When a lock file and manifest both list the same package, the
//                dependency may appear twice — once marked direct (from manifest
//                context) and once marked transitive. The direct entry must win
//                because direct dependencies are explicitly chosen by the developer
//                and should be prominently analyzed, not hidden as transitive.
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - distinguishing
//         direct from transitive is critical for accurate risk assessment
// Methodology: Create duplicate deps where one is transitive and one is direct,
//              verify the direct entry is kept
// Result: Deduplicated list contains the direct entry, not the transitive one
func TestDeduplicateDependencies_DirectWinsOverTransitive(t *testing.T) {
	deps := []models.Dependency{
		{
			Name:         "express",
			Version:      "4.18.2",
			Ecosystem:    models.EcosystemNPM,
			Source:       "package-lock.json",
			IsTransitive: true, // First occurrence is transitive
		},
		{
			Name:         "express",
			Version:      "4.18.2",
			Ecosystem:    models.EcosystemNPM,
			Source:       "package.json",
			IsTransitive: false, // Second occurrence is direct
		},
		{
			Name:         "lodash",
			Version:      "4.17.21",
			Ecosystem:    models.EcosystemNPM,
			Source:       "package.json",
			IsTransitive: false,
		},
	}

	result := deduplicateDependencies(deps)

	if len(result) != 2 {
		t.Fatalf("Expected 2 unique dependencies, got %d", len(result))
	}

	// Find express in results
	for _, dep := range result {
		if dep.Name == "express" {
			if dep.IsTransitive {
				t.Error("express should be direct (IsTransitive=false) after dedup — direct wins over transitive")
			}
			return
		}
	}
	t.Error("express not found in deduplicated results")
}

// Test: deduplicateDependencies preserves transitive when no direct exists
// Justification: If a dependency only appears as transitive (no direct counterpart),
//                it must be preserved with its transitive flag intact for correct
//                reporting and optional filtering.
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Create transitive-only deps, verify they're preserved
// Result: Transitive deps are kept with IsTransitive=true
func TestDeduplicateDependencies_PreservesTransitive(t *testing.T) {
	deps := []models.Dependency{
		{
			Name:         "accepts",
			Version:      "1.3.8",
			Ecosystem:    models.EcosystemNPM,
			Source:       "package-lock.json",
			IsTransitive: true,
		},
		{
			Name:         "express",
			Version:      "4.18.2",
			Ecosystem:    models.EcosystemNPM,
			Source:       "package-lock.json",
			IsTransitive: false,
		},
	}

	result := deduplicateDependencies(deps)

	if len(result) != 2 {
		t.Fatalf("Expected 2 dependencies, got %d", len(result))
	}

	for _, dep := range result {
		if dep.Name == "accepts" && !dep.IsTransitive {
			t.Error("accepts should remain transitive (IsTransitive=true)")
		}
		if dep.Name == "express" && dep.IsTransitive {
			t.Error("express should remain direct (IsTransitive=false)")
		}
	}
}

// Test: deduplicateDependencies handles empty input
// Justification: Edge case — empty dependency lists should return empty, not panic
// Source: Defense-in-depth principle
// Methodology: Pass empty slice
// Result: Returns empty slice
func TestDeduplicateDependencies_Empty(t *testing.T) {
	result := deduplicateDependencies(nil)
	if len(result) != 0 {
		t.Errorf("Expected 0 dependencies for nil input, got %d", len(result))
	}

	result = deduplicateDependencies([]models.Dependency{})
	if len(result) != 0 {
		t.Errorf("Expected 0 dependencies for empty input, got %d", len(result))
	}
}
