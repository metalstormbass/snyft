package parser

import (
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ---- parsePackageJSON tests ----

// Test: parsePackageJSON extracts both regular and dev dependencies
// Justification: Accurate extraction of all dependency types is critical for
//                supply chain risk assessment - dev dependencies can also be
//                compromised (e.g., event-stream attack targeted a devDep)
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - event-stream
//         attack shows devDependencies are also attack vectors
// Methodology: Parse a package.json with both dependency types
// Result: Returns all dependencies with correct names, cleaned versions, npm ecosystem
func TestParsePackageJSON_BothDependencyTypes(t *testing.T) {
	deps, err := parsePackageJSON("testdata/package.json")
	if err != nil {
		t.Fatalf("Failed to parse package.json: %v", err)
	}

	if len(deps) != 4 {
		t.Fatalf("Expected 4 dependencies (2 regular + 2 dev), got %d", len(deps))
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Regular dependencies
	if v, ok := depMap["express"]; !ok || v != "4.18.2" {
		t.Errorf("Expected express@4.18.2, got %v", v)
	}
	if v, ok := depMap["lodash"]; !ok || v != "4.17.21" {
		t.Errorf("Expected lodash@4.17.21, got %v", v)
	}

	// Dev dependencies
	if v, ok := depMap["jest"]; !ok || v != "29.0.0" {
		t.Errorf("Expected jest@29.0.0, got %v", v)
	}
	if v, ok := depMap["eslint"]; !ok || v != "8.45.0" {
		t.Errorf("Expected eslint@8.45.0, got %v", v)
	}
}

// Test: parsePackageJSON sets correct ecosystem and source
// Justification: Ecosystem identification determines which registry APIs are
//                queried for risk assessment - wrong ecosystem = wrong analysis
// Source: OSSF Scorecard methodology - ecosystem-specific checks
// Methodology: Verify ecosystem and source fields on parsed dependencies
// Result: All dependencies have EcosystemNPM and correct source path
func TestParsePackageJSON_EcosystemAndSource(t *testing.T) {
	deps, err := parsePackageJSON("testdata/package.json")
	if err != nil {
		t.Fatalf("Failed to parse package.json: %v", err)
	}

	for _, dep := range deps {
		if dep.Ecosystem != models.EcosystemNPM {
			t.Errorf("Expected npm ecosystem for %s, got %s", dep.Name, dep.Ecosystem)
		}
		if dep.Source != "testdata/package.json" {
			t.Errorf("Expected source testdata/package.json for %s, got %s", dep.Name, dep.Source)
		}
	}
}

// Test: parsePackageJSON handles empty dependencies
// Justification: Projects without dependencies should not cause errors
// Source: Defense-in-depth principle
// Methodology: Parse package.json with no dependencies or devDependencies
// Result: Returns empty slice without error
func TestParsePackageJSON_EmptyDependencies(t *testing.T) {
	deps, err := parsePackageJSON("testdata/package-empty.json")
	if err != nil {
		t.Fatalf("Failed to parse package.json: %v", err)
	}

	if len(deps) != 0 {
		t.Errorf("Expected 0 dependencies, got %d", len(deps))
	}
}

// Test: parsePackageJSON returns error for invalid JSON
// Justification: Corrupt or malformed manifest files should produce clear errors
//                rather than silently returning wrong data
// Source: Defense-in-depth principle
// Methodology: Attempt to parse invalid JSON
// Result: Returns parse error
func TestParsePackageJSON_InvalidJSON(t *testing.T) {
	_, err := parsePackageJSON("testdata/package-invalid.json")
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// Test: parsePackageJSON returns error for nonexistent file
// Justification: Graceful error handling for missing files
// Source: Defense-in-depth principle
// Methodology: Attempt to parse a nonexistent file
// Result: Returns file read error
func TestParsePackageJSON_NonexistentFile(t *testing.T) {
	_, err := parsePackageJSON("testdata/nonexistent-package.json")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// ---- parsePackageLockJSON tests ----

// Test: parsePackageLockJSON extracts dependencies from v3 lockfile
// Justification: package-lock.json v3 (npm 7+) uses "packages" field with
//                node_modules/ paths - correct parsing identifies the full
//                dependency tree for sprawl risk assessment
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - npm
//         dependency tree depth is a key risk factor
// Methodology: Parse a v3 lockfile and verify dependency extraction
// Result: Returns all non-root packages as dependencies
func TestParsePackageLockJSON_V3Format(t *testing.T) {
	deps, err := parsePackageLockJSON("testdata/package-lock-small.json")
	if err != nil {
		t.Fatalf("Failed to parse package-lock.json: %v", err)
	}

	if len(deps) != 7 {
		t.Fatalf("Expected 7 dependencies, got %d", len(deps))
	}

	// Verify names are extracted correctly (node_modules/ prefix removed)
	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	if v, ok := depMap["express"]; !ok {
		t.Error("Expected express dependency")
	} else if v != "4.18.2" {
		t.Errorf("Expected express@4.18.2, got %s", v)
	}

	if v, ok := depMap["lodash"]; !ok {
		t.Error("Expected lodash dependency")
	} else if v != "4.17.21" {
		t.Errorf("Expected lodash@4.17.21, got %s", v)
	}
}

// Test: parsePackageLockJSON sets npm ecosystem for all dependencies
// Justification: Correct ecosystem tagging for downstream analysis
// Source: OSSF Scorecard methodology
// Methodology: Verify all parsed lock dependencies have npm ecosystem
// Result: All dependencies have EcosystemNPM
func TestParsePackageLockJSON_Ecosystem(t *testing.T) {
	deps, err := parsePackageLockJSON("testdata/package-lock-small.json")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	for _, dep := range deps {
		if dep.Ecosystem != models.EcosystemNPM {
			t.Errorf("Expected npm ecosystem for %s, got %s", dep.Name, dep.Ecosystem)
		}
	}
}

// Test: parsePackageLockJSON returns error for invalid JSON
// Justification: Corrupt lockfiles should produce errors
// Source: Defense-in-depth principle
// Methodology: Attempt to parse invalid JSON as lockfile
// Result: Returns parse error
func TestParsePackageLockJSON_InvalidJSON(t *testing.T) {
	_, err := parsePackageLockJSON("testdata/package-invalid.json")
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// ---- parseYarnLock tests ----

// Test: parseYarnLock returns empty slice (stub implementation)
// Justification: Yarn lock parser is a stub - verify it degrades gracefully
//                by returning empty results instead of errors
// Source: Snyft architecture guidelines - degrade gracefully, never fail completely
// Methodology: Call parseYarnLock and verify it returns empty slice
// Result: Returns empty slice, no error
func TestParseYarnLock_ReturnsEmpty(t *testing.T) {
	deps, err := parseYarnLock("testdata/nonexistent-yarn.lock")
	if err != nil {
		t.Fatalf("Expected no error from yarn lock stub, got: %v", err)
	}

	if len(deps) != 0 {
		t.Errorf("Expected 0 dependencies from yarn lock stub, got %d", len(deps))
	}
}

// ---- cleanVersion tests ----

// Test: cleanVersion removes common npm version prefixes
// Justification: Version prefixes (^, ~, >=) must be stripped to get the actual
//                version for registry lookups during supply chain analysis
// Source: npm semver specification - version ranges use prefix operators
// Methodology: Test each prefix type against cleanVersion
// Result: Returns version string with prefix removed
func TestCleanVersion_AllPrefixes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"^4.18.2", "4.18.2"},
		{"~4.17.21", "4.17.21"},
		{">=29.0.0", "29.0.0"},
		{"<=1.0.0", "1.0.0"},
		{">2.0.0", "2.0.0"},
		{"<3.0.0", "3.0.0"},
		{"=1.5.0", "1.5.0"},
		{"4.18.2", "4.18.2"},     // No prefix
		{" ^4.18.2 ", "4.18.2"},  // With whitespace
	}

	for _, tt := range tests {
		result := cleanVersion(tt.input)
		if result != tt.expected {
			t.Errorf("cleanVersion(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// ---- CountTransitiveDependencies tests (existing + expanded) ----

// Test: CountTransitiveDependencies with small lockfile (v3 format)
// Justification: Dependency sprawl is a key supply chain risk factor -
//                more transitive deps = larger attack surface
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Count packages in v3 lockfile excluding root
// Result: Correct transitive count, verified=true
func TestCountTransitiveDependencies_Small(t *testing.T) {
	metrics, err := CountTransitiveDependencies("testdata/package-lock-small.json")
	if err != nil {
		t.Fatalf("Failed to count dependencies: %v", err)
	}

	if metrics.TransitiveCount != 7 {
		t.Errorf("Expected 7 transitive dependencies, got %d", metrics.TransitiveCount)
	}

	if !metrics.Verified {
		t.Error("Expected verified metrics")
	}
}

// Test: CountTransitiveDependencies with medium lockfile
// Justification: Validates counting at moderate scale
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Count packages in medium v3 lockfile
// Result: Correct transitive count
func TestCountTransitiveDependencies_Medium(t *testing.T) {
	metrics, err := CountTransitiveDependencies("testdata/package-lock-medium.json")
	if err != nil {
		t.Fatalf("Failed to count dependencies: %v", err)
	}

	if metrics.TransitiveCount != 25 {
		t.Errorf("Expected 25 transitive dependencies, got %d", metrics.TransitiveCount)
	}

	if !metrics.Verified {
		t.Error("Expected verified metrics")
	}
}

// Test: CountTransitiveDependencies with large lockfile
// Justification: Validates counting at larger scale
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Count packages in large v3 lockfile
// Result: Correct transitive count
func TestCountTransitiveDependencies_Large(t *testing.T) {
	metrics, err := CountTransitiveDependencies("testdata/package-lock-large.json")
	if err != nil {
		t.Fatalf("Failed to count dependencies: %v", err)
	}

	if metrics.TransitiveCount != 60 {
		t.Errorf("Expected 60 transitive dependencies, got %d", metrics.TransitiveCount)
	}

	if !metrics.Verified {
		t.Error("Expected verified metrics")
	}
}

// Test: CountTransitiveDependencies with nonexistent file
// Justification: Graceful error for missing lockfiles
// Source: Defense-in-depth principle
// Methodology: Attempt to count deps in nonexistent file
// Result: Returns error
func TestCountTransitiveDependencies_NonExistent(t *testing.T) {
	_, err := CountTransitiveDependencies("testdata/nonexistent.json")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// Test: CountTransitiveDependencies with v1 lockfile format
// Justification: Older npm lockfiles (v1-v6) use nested "dependencies" instead
//                of flat "packages" - both formats must be handled for accurate
//                dependency sprawl assessment
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - dependency
//         tree depth is a key risk metric
// Methodology: Parse a v1 lockfile with nested dependencies
// Result: Correctly counts all unique dependencies including nested ones
func TestCountTransitiveDependencies_V1Format(t *testing.T) {
	metrics, err := CountTransitiveDependencies("testdata/package-lock-v1.json")
	if err != nil {
		t.Fatalf("Failed to count v1 dependencies: %v", err)
	}

	// v1 format: express (with accepts, mime-types, body-parser nested) + lodash = 5 unique
	if metrics.TransitiveCount != 5 {
		t.Errorf("Expected 5 transitive dependencies in v1 format, got %d", metrics.TransitiveCount)
	}

	// Direct count = top-level dependencies
	if metrics.DirectCount != 2 {
		t.Errorf("Expected 2 direct dependencies, got %d", metrics.DirectCount)
	}

	// Should track max depth (express->accepts->mime-types = depth 3)
	if metrics.MaxDepth < 2 {
		t.Errorf("Expected max depth >= 2 for nested deps, got %d", metrics.MaxDepth)
	}
}

// Test: CountTransitiveDependencies with invalid JSON
// Justification: Corrupt lockfiles should not crash the analyzer
// Source: Defense-in-depth principle
// Methodology: Attempt to parse invalid JSON as lockfile
// Result: Returns parse error
func TestCountTransitiveDependencies_InvalidJSON(t *testing.T) {
	_, err := CountTransitiveDependencies("testdata/package-invalid.json")
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// Test: CountTransitiveDependencies identifies direct dependencies in v3 format
// Justification: Distinguishing direct from transitive dependencies is essential
//                for dependency sprawl scoring - high transitive:direct ratio
//                indicates hidden attack surface
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Parse v3 lockfile with root package declaring direct dependencies
// Result: DirectCount reflects dependencies listed in root package
func TestCountTransitiveDependencies_DirectCount(t *testing.T) {
	metrics, err := CountTransitiveDependencies("testdata/package-lock-small.json")
	if err != nil {
		t.Fatalf("Failed to count dependencies: %v", err)
	}

	// The small lockfile has 2 direct deps (express, lodash) declared in root package
	if metrics.DirectCount != 2 {
		t.Errorf("Expected 2 direct dependencies, got %d", metrics.DirectCount)
	}
}
