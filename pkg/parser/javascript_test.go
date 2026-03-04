package parser

import (
	"os"
	"strings"
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

// ---- Transitive dependency tagging tests ----

// Test: parsePackageLockJSON tags direct vs transitive dependencies
// Justification: Distinguishing direct from transitive dependencies is essential
//                for supply chain risk assessment. Direct dependencies are explicitly
//                chosen by the developer; transitive ones are pulled in implicitly
//                and represent hidden attack surface that developers may not audit.
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - transitive
//         dependencies propagate compromise through the dependency graph
// Methodology: Parse package-lock-small.json which declares express and lodash as
//              direct deps in root; accepts, array-flatten, body-parser, cookie,
//              debug are transitive (not in root's dependencies)
// Result: express and lodash have IsTransitive=false, all others IsTransitive=true
func TestParsePackageLockJSON_TransitiveTagging(t *testing.T) {
	deps, err := parsePackageLockJSON("testdata/package-lock-small.json")
	if err != nil {
		t.Fatalf("Failed to parse package-lock.json: %v", err)
	}

	depMap := make(map[string]models.Dependency)
	for _, dep := range deps {
		depMap[dep.Name] = dep
	}

	// Direct dependencies (declared in root package)
	directDeps := []string{"express", "lodash"}
	for _, name := range directDeps {
		dep, ok := depMap[name]
		if !ok {
			t.Errorf("Expected dependency %s not found", name)
			continue
		}
		if dep.IsTransitive {
			t.Errorf("%s should be direct (IsTransitive=false), got IsTransitive=true", name)
		}
	}

	// Transitive dependencies (not in root package's dependencies)
	transitiveDeps := []string{"accepts", "array-flatten", "body-parser", "cookie", "debug"}
	for _, name := range transitiveDeps {
		dep, ok := depMap[name]
		if !ok {
			t.Errorf("Expected dependency %s not found", name)
			continue
		}
		if !dep.IsTransitive {
			t.Errorf("%s should be transitive (IsTransitive=true), got IsTransitive=false", name)
		}
	}
}

// Test: parsePackageLockJSON marks nested node_modules paths as transitive
// Justification: Packages installed under another package's node_modules are always
//                transitive — they exist to resolve version conflicts in the
//                dependency tree. Nested packages represent deeper supply chain
//                layers with less developer visibility.
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - deeper
//         dependency paths increase compromise propagation risk
// Methodology: Parse lockfile with nested node_modules paths
//              (e.g., node_modules/express/node_modules/qs)
// Result: Nested packages always have IsTransitive=true, even if their name
//         matches a direct dependency
func TestParsePackageLockJSON_NestedNodeModulesTransitive(t *testing.T) {
	// Create a temporary lockfile with nested node_modules
	nestedLockfile := `{
		"name": "test-project",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"dependencies": {
					"express": "^4.18.0",
					"qs": "^6.11.0"
				}
			},
			"node_modules/express": {
				"version": "4.18.2"
			},
			"node_modules/qs": {
				"version": "6.11.2"
			},
			"node_modules/express/node_modules/qs": {
				"version": "6.5.3"
			}
		}
	}`

	tmpFile := t.TempDir() + "/package-lock.json"
	if err := writeTestFile(tmpFile, nestedLockfile); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	deps, err := parsePackageLockJSON(tmpFile)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("Expected 3 dependencies, got %d", len(deps))
	}

	for _, dep := range deps {
		switch dep.Name {
		case "express":
			if dep.IsTransitive {
				t.Error("express (top-level direct) should not be transitive")
			}
		case "qs":
			if dep.IsTransitive {
				t.Error("qs (top-level direct) should not be transitive")
			}
		case "express/node_modules/qs":
			// Nested path: always transitive even though "qs" is a direct dep
			if !dep.IsTransitive {
				t.Error("express/node_modules/qs (nested) should be transitive")
			}
		default:
			t.Errorf("Unexpected dependency: %s", dep.Name)
		}
	}
}

// Test: parsePackageJSON marks all deps as direct (IsTransitive=false)
// Justification: package.json only contains direct dependencies by definition.
//                All dependencies listed there are explicitly chosen by the developer.
// Source: npm documentation - package.json contains only direct dependencies
// Methodology: Parse package.json and verify IsTransitive=false for all
// Result: All dependencies have IsTransitive=false (default zero value)
func TestParsePackageJSON_AllDirect(t *testing.T) {
	deps, err := parsePackageJSON("testdata/package.json")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	for _, dep := range deps {
		if dep.IsTransitive {
			t.Errorf("package.json dependency %s should be direct (IsTransitive=false)", dep.Name)
		}
	}
}

// ---- v1 lockfile parsing tests ----

// Test: parsePackageLockJSON extracts dependencies from v1 lockfile
// Justification: Older npm lockfiles (v1-v6) use nested "dependencies" instead
//                of flat "packages" - both formats must be handled for accurate
//                supply chain risk assessment across all npm versions
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - dependency
//         tree analysis requires parsing all lockfile formats
// Methodology: Parse a v1 lockfile and verify dependency extraction with transitive tagging
// Result: Returns all unique dependencies with correct direct/transitive flags
func TestParsePackageLockJSON_V1Format(t *testing.T) {
	deps, err := parsePackageLockJSON("testdata/package-lock-v1.json")
	if err != nil {
		t.Fatalf("Failed to parse v1 lockfile: %v", err)
	}

	// v1 format: express (direct) + lodash (direct) + accepts, mime-types, body-parser (transitive) = 5
	if len(deps) != 5 {
		t.Fatalf("Expected 5 dependencies from v1 lockfile, got %d", len(deps))
	}

	depMap := make(map[string]models.Dependency)
	for _, dep := range deps {
		depMap[dep.Name] = dep
	}

	// Direct dependencies
	if dep, ok := depMap["express"]; !ok {
		t.Error("Expected express dependency")
	} else {
		if dep.Version != "4.18.2" {
			t.Errorf("Expected express@4.18.2, got %s", dep.Version)
		}
		if dep.IsTransitive {
			t.Error("express should be direct (IsTransitive=false)")
		}
	}

	if dep, ok := depMap["lodash"]; !ok {
		t.Error("Expected lodash dependency")
	} else {
		if dep.IsTransitive {
			t.Error("lodash should be direct (IsTransitive=false)")
		}
	}

	// Transitive dependencies
	for _, name := range []string{"accepts", "mime-types", "body-parser"} {
		dep, ok := depMap[name]
		if !ok {
			t.Errorf("Expected transitive dependency %s", name)
			continue
		}
		if !dep.IsTransitive {
			t.Errorf("%s should be transitive (IsTransitive=true)", name)
		}
		if dep.Ecosystem != models.EcosystemNPM {
			t.Errorf("Expected npm ecosystem for %s", name)
		}
	}
}

// ---- Scoped package tests ----

// Test: parsePackageJSON handles scoped packages (@scope/name)
// Justification: Scoped packages are commonly used in the npm ecosystem
//                (e.g., @babel/core, @types/node). Incorrect parsing of scoped
//                package names would miss supply chain risk assessment for
//                these packages entirely.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - scoped
//         packages can also be targets for typosquatting attacks
// Methodology: Parse package.json with scoped dependencies and verify names
// Result: Scoped package names are preserved exactly as written
func TestParsePackageJSON_ScopedPackages(t *testing.T) {
	content := `{
		"name": "test-scoped",
		"version": "1.0.0",
		"dependencies": {
			"@babel/core": "^7.22.0",
			"@types/node": "^20.0.0"
		},
		"devDependencies": {
			"@testing-library/react": "^14.0.0"
		}
	}`

	tmpFile := t.TempDir() + "/package.json"
	if err := writeTestFile(tmpFile, content); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	deps, err := parsePackageJSON(tmpFile)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("Expected 3 dependencies, got %d", len(deps))
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	expected := map[string]string{
		"@babel/core":             "7.22.0",
		"@types/node":             "20.0.0",
		"@testing-library/react":  "14.0.0",
	}
	for name, version := range expected {
		if v, ok := depMap[name]; !ok {
			t.Errorf("Missing scoped package %s", name)
		} else if v != version {
			t.Errorf("Expected %s@%s, got %s", name, version, v)
		}
	}
}

// Test: parsePackageLockJSON handles scoped packages in node_modules paths
// Justification: Scoped packages in lockfiles use paths like
//                "node_modules/@scope/name" - the name extraction must preserve
//                the full scoped name for correct registry lookups
// Source: npm registry API requires full scoped name for package lookups
// Methodology: Parse lockfile with scoped package paths
// Result: Scoped names extracted correctly including @scope/ prefix
func TestParsePackageLockJSON_ScopedPackages(t *testing.T) {
	content := `{
		"name": "test-scoped",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"dependencies": {
					"@babel/core": "^7.22.0",
					"@types/node": "^20.0.0"
				}
			},
			"node_modules/@babel/core": {
				"version": "7.22.10"
			},
			"node_modules/@types/node": {
				"version": "20.4.5"
			},
			"node_modules/@babel/core/node_modules/@babel/parser": {
				"version": "7.22.7"
			}
		}
	}`

	tmpFile := t.TempDir() + "/package-lock.json"
	if err := writeTestFile(tmpFile, content); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	deps, err := parsePackageLockJSON(tmpFile)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("Expected 3 dependencies, got %d", len(deps))
	}

	depMap := make(map[string]models.Dependency)
	for _, dep := range deps {
		depMap[dep.Name] = dep
	}

	// Direct scoped packages
	if dep, ok := depMap["@babel/core"]; !ok {
		t.Error("Expected @babel/core")
	} else if dep.IsTransitive {
		t.Error("@babel/core should be direct")
	}

	if dep, ok := depMap["@types/node"]; !ok {
		t.Error("Expected @types/node")
	} else if dep.IsTransitive {
		t.Error("@types/node should be direct")
	}

	// Nested scoped package (transitive)
	nestedName := "@babel/core/node_modules/@babel/parser"
	if dep, ok := depMap[nestedName]; !ok {
		t.Errorf("Expected nested scoped package %s", nestedName)
	} else if !dep.IsTransitive {
		t.Error("Nested scoped package should be transitive")
	}
}

// ---- Workspace filtering tests ----

// Test: parsePackageLockJSON filters out workspace packages
// Justification: Workspace packages are local project members, not external
//                dependencies from the npm registry. Including them would
//                cause false positives in supply chain risk analysis since
//                they cannot be looked up on npm.
// Source: npm workspaces documentation - workspace entries in lockfile
//         represent local packages, not external dependencies
// Methodology: Parse lockfile with workspace entries (paths without node_modules/ prefix)
// Result: Only node_modules/ entries are returned as dependencies
func TestParsePackageLockJSON_WorkspaceFiltering(t *testing.T) {
	content := `{
		"name": "my-monorepo",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"workspaces": ["packages/*"],
				"dependencies": {
					"lodash": "^4.17.21"
				}
			},
			"packages/my-lib": {
				"name": "@my-org/my-lib",
				"version": "1.0.0"
			},
			"packages/my-app": {
				"name": "@my-org/my-app",
				"version": "2.0.0"
			},
			"node_modules/lodash": {
				"version": "4.17.21"
			},
			"node_modules/@my-org/my-lib": {
				"resolved": "packages/my-lib",
				"link": true
			}
		}
	}`

	tmpFile := t.TempDir() + "/package-lock.json"
	if err := writeTestFile(tmpFile, content); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	deps, err := parsePackageLockJSON(tmpFile)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	// Should get lodash + @my-org/my-lib symlink (both under node_modules/), NOT workspace entries
	for _, dep := range deps {
		if strings.HasPrefix(dep.Name, "packages/") {
			t.Errorf("Workspace package %s should have been filtered out", dep.Name)
		}
	}

	// lodash should be present
	found := false
	for _, dep := range deps {
		if dep.Name == "lodash" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected lodash dependency")
	}
}

// ---- Git and file: dependency tests ----

// Test: parsePackageJSON preserves non-semver version specs
// Justification: Git URLs and file: paths in package.json represent
//                dependencies with special resolution. Mangling these
//                through semver cleaning would produce invalid versions
//                that fail registry lookups during analysis.
// Source: npm documentation - alternative dependency specifiers
// Methodology: Parse package.json with git and file dependencies
// Result: Non-semver specs are preserved as-is
func TestParsePackageJSON_GitAndFileDependencies(t *testing.T) {
	content := `{
		"name": "test-special-deps",
		"version": "1.0.0",
		"dependencies": {
			"my-git-dep": "git+https://github.com/user/repo.git#v1.0.0",
			"my-github-dep": "github:user/repo",
			"my-file-dep": "file:../local-lib",
			"normal-dep": "^1.2.3"
		}
	}`

	tmpFile := t.TempDir() + "/package.json"
	if err := writeTestFile(tmpFile, content); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	deps, err := parsePackageJSON(tmpFile)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if len(deps) != 4 {
		t.Fatalf("Expected 4 dependencies, got %d", len(deps))
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Git and file deps should be preserved as-is
	if v := depMap["my-git-dep"]; v != "git+https://github.com/user/repo.git#v1.0.0" {
		t.Errorf("Git dep version mangled: got %q", v)
	}
	if v := depMap["my-github-dep"]; v != "github:user/repo" {
		t.Errorf("GitHub shorthand version mangled: got %q", v)
	}
	if v := depMap["my-file-dep"]; v != "file:../local-lib" {
		t.Errorf("File dep version mangled: got %q", v)
	}

	// Normal dep should still be cleaned
	if v := depMap["normal-dep"]; v != "1.2.3" {
		t.Errorf("Normal dep should be cleaned: got %q", v)
	}
}

// Test: cleanVersion handles non-semver specs
// Justification: Ensures cleanVersion does not corrupt special dependency specifiers
// Source: npm semver specification and alternative dependency types
// Methodology: Pass various non-semver specs through cleanVersion
// Result: Non-semver specs returned unchanged
func TestCleanVersion_NonSemverSpecs(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"git+https://github.com/user/repo.git", "git+https://github.com/user/repo.git"},
		{"git://github.com/user/repo.git", "git://github.com/user/repo.git"},
		{"github:user/repo", "github:user/repo"},
		{"gitlab:user/repo", "gitlab:user/repo"},
		{"bitbucket:user/repo", "bitbucket:user/repo"},
		{"file:../local-lib", "file:../local-lib"},
		{"https://example.com/pkg.tgz", "https://example.com/pkg.tgz"},
		{"http://example.com/pkg.tgz", "http://example.com/pkg.tgz"},
		{"npm:other-pkg@^1.0.0", "npm:other-pkg@^1.0.0"},
	}

	for _, tt := range tests {
		result := cleanVersion(tt.input)
		if result != tt.expected {
			t.Errorf("cleanVersion(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
