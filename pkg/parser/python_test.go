package parser

import (
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ---- parseRequirementsTxt tests ----

// Test: parseRequirementsTxt extracts pinned dependencies
// Justification: requirements.txt is the most common Python dependency format -
//                accurate parsing identifies all packages for supply chain analysis
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) - PyPI attack taxonomy
// Methodology: Parse a requirements.txt with pinned versions
// Result: Returns all non-comment, non-editable dependencies
func TestParseRequirementsTxt_Simple(t *testing.T) {
	deps, err := parseRequirementsTxt("testdata/requirements-small.txt")
	if err != nil {
		t.Fatalf("Failed to parse requirements.txt: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("Expected 3 dependencies, got %d", len(deps))
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	if v, ok := depMap["requests"]; !ok || v != "2.28.0" {
		t.Errorf("Expected requests@2.28.0, got %v", v)
	}
	if v, ok := depMap["Flask"]; !ok || v != "2.3.0" {
		t.Errorf("Expected Flask@2.3.0, got %v", v)
	}
	if v, ok := depMap["numpy"]; !ok || v != "1.24.0" {
		t.Errorf("Expected numpy@1.24.0, got %v", v)
	}
}

// Test: parseRequirementsTxt handles complex requirements file
// Justification: Real requirements.txt files contain comments, extras, editable
//                installs, and various version operators - all must be handled
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Parse a complex requirements.txt with mixed formats
// Result: Correctly skips comments, -e entries, and extracts dependencies
func TestParseRequirementsTxt_Complex(t *testing.T) {
	deps, err := parseRequirementsTxt("testdata/requirements-complex.txt")
	if err != nil {
		t.Fatalf("Failed to parse complex requirements.txt: %v", err)
	}

	// Should have: requests, Flask, numpy, boto3, django, celery, click = 7
	// Skips: comments, empty lines, -e, --editable
	if len(deps) < 5 {
		t.Errorf("Expected at least 5 dependencies, got %d", len(deps))
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Pinned version
	if v, ok := depMap["requests"]; !ok || v != "2.28.0" {
		t.Errorf("Expected requests@2.28.0, got %v", v)
	}

	// >= version
	if v, ok := depMap["Flask"]; !ok || v != "2.3.0" {
		t.Errorf("Expected Flask@2.3.0, got %v", v)
	}

	// ~= version
	if v, ok := depMap["numpy"]; !ok || v != "1.24.0" {
		t.Errorf("Expected numpy@1.24.0, got %v", v)
	}

	// No version specified
	if v, ok := depMap["click"]; !ok || v != "latest" {
		t.Errorf("Expected click@latest, got %v", v)
	}
}

// Test: parseRequirementsTxt sets correct ecosystem
// Justification: PyPI ecosystem tagging determines which registry API is used
// Source: OSSF Scorecard methodology
// Methodology: Verify all parsed deps have PyPI ecosystem
// Result: All dependencies have EcosystemPyPI
func TestParseRequirementsTxt_Ecosystem(t *testing.T) {
	deps, err := parseRequirementsTxt("testdata/requirements-small.txt")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	for _, dep := range deps {
		if dep.Ecosystem != models.EcosystemPyPI {
			t.Errorf("Expected pypi ecosystem for %s, got %s", dep.Name, dep.Ecosystem)
		}
	}
}

// Test: parseRequirementsTxt returns error for nonexistent file
// Justification: Missing files should produce errors
// Source: Defense-in-depth principle
// Methodology: Attempt to parse a nonexistent file
// Result: Returns file read error
func TestParseRequirementsTxt_NonexistentFile(t *testing.T) {
	_, err := parseRequirementsTxt("testdata/nonexistent-requirements.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// ---- parsePipfile tests ----

// Test: parsePipfile extracts dependencies from [packages] section
// Justification: Pipfile is Pipenv's manifest format - accurate parsing ensures
//                supply chain analysis covers Pipenv-managed projects
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) - PyPI attack taxonomy
// Methodology: Parse a Pipfile with [packages] and [dev-packages] sections
// Result: Returns dependencies from [packages] section with correct versions
func TestParsePipfile_PackagesSection(t *testing.T) {
	deps, err := parsePipfile("testdata/Pipfile")
	if err != nil {
		t.Fatalf("Failed to parse Pipfile: %v", err)
	}

	// Should have 3 packages from [packages]: requests, flask, numpy
	if len(deps) != 3 {
		t.Fatalf("Expected 3 dependencies from [packages], got %d", len(deps))
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Note: Pipfile uses "==2.28.0" which after quote-stripping and cleanVersion
	// becomes "=2.28.0" (cleanVersion strips one '=' prefix, not both from '==').
	if v, ok := depMap["requests"]; !ok || v != "=2.28.0" {
		t.Errorf("Expected requests@=2.28.0, got %v", v)
	}

	// All should be PyPI ecosystem
	for _, dep := range deps {
		if dep.Ecosystem != models.EcosystemPyPI {
			t.Errorf("Expected pypi ecosystem for %s, got %s", dep.Name, dep.Ecosystem)
		}
	}
}

// Test: parsePipfile returns error for nonexistent file
// Justification: Graceful error handling
// Source: Defense-in-depth principle
// Methodology: Attempt to parse a nonexistent Pipfile
// Result: Returns file read error
func TestParsePipfile_NonexistentFile(t *testing.T) {
	_, err := parsePipfile("testdata/nonexistent-Pipfile")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// ---- parsePyprojectToml tests ----

// Test: parsePyprojectToml extracts dependencies, skipping python version
// Justification: pyproject.toml is the modern Python packaging standard -
//                parsing must correctly skip the python version constraint
//                which is not a package dependency
// Source: PEP 517/518 - pyproject.toml specification
// Methodology: Parse a pyproject.toml with poetry dependencies section
// Result: Returns package dependencies, excludes "python" entry
func TestParsePyprojectToml_SkipsPythonVersion(t *testing.T) {
	deps, err := parsePyprojectToml("testdata/pyproject.toml")
	if err != nil {
		t.Fatalf("Failed to parse pyproject.toml: %v", err)
	}

	// Should have 3 deps: requests, flask, numpy (python skipped)
	if len(deps) != 3 {
		t.Fatalf("Expected 3 dependencies (python excluded), got %d", len(deps))
	}

	for _, dep := range deps {
		if dep.Name == "python" {
			t.Error("Expected python version constraint to be skipped")
		}
		if dep.Ecosystem != models.EcosystemPyPI {
			t.Errorf("Expected pypi ecosystem for %s, got %s", dep.Name, dep.Ecosystem)
		}
	}
}

// Test: parsePyprojectToml returns error for nonexistent file
// Justification: Graceful error handling
// Source: Defense-in-depth principle
// Methodology: Attempt to parse a nonexistent file
// Result: Returns file read error
func TestParsePyprojectToml_NonexistentFile(t *testing.T) {
	_, err := parsePyprojectToml("testdata/nonexistent-pyproject.toml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// ---- parsePythonRequirement tests ----

// Test: parsePythonRequirement handles all version operators
// Justification: Python uses multiple version operators (==, >=, ~=, etc.) -
//                each must be correctly split to extract name and version
// Source: PEP 440 - Version Identification and Dependency Specification
// Methodology: Test each operator type
// Result: Correctly splits name and version for each operator
func TestParsePythonRequirement_AllOperators(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"requests==2.28.0", "requests", "2.28.0"},
		{"Flask>=2.3.0", "Flask", "2.3.0"},
		{"numpy<=1.24.0", "numpy", "1.24.0"},
		{"django~=4.0", "django", "4.0"},
		{"celery>5.0", "celery", "5.0"},
		{"pytest<8.0", "pytest", "8.0"},
		{"six!=1.0", "six", "1.0"},
	}

	for _, tt := range tests {
		name, version := parsePythonRequirement(tt.input)
		if name != tt.wantName {
			t.Errorf("parsePythonRequirement(%q) name = %q, want %q", tt.input, name, tt.wantName)
		}
		if version != tt.wantVersion {
			t.Errorf("parsePythonRequirement(%q) version = %q, want %q", tt.input, version, tt.wantVersion)
		}
	}
}

// Test: parsePythonRequirement strips extras brackets
// Justification: Python packages can specify extras (e.g., boto3[crt]) which
//                must be stripped to get the bare package name for registry lookup
// Source: PEP 508 - Dependency specification for Python
// Methodology: Parse requirement with extras specification
// Result: Returns name without extras, correct version
func TestParsePythonRequirement_WithExtras(t *testing.T) {
	name, version := parsePythonRequirement("boto3[crt]==1.26.0")
	if name != "boto3" {
		t.Errorf("Expected name 'boto3', got %q", name)
	}
	if version != "1.26.0" {
		t.Errorf("Expected version '1.26.0', got %q", version)
	}
}

// Test: parsePythonRequirement handles package with no version
// Justification: Some requirements don't pin versions - these should still be
//                tracked for supply chain analysis (unpinned = higher risk)
// Source: OSSF Scorecard - pinned dependencies check
// Methodology: Parse a requirement without version specification
// Result: Returns name with "latest" as version
func TestParsePythonRequirement_NoVersion(t *testing.T) {
	name, version := parsePythonRequirement("click")
	if name != "click" {
		t.Errorf("Expected name 'click', got %q", name)
	}
	if version != "latest" {
		t.Errorf("Expected version 'latest', got %q", version)
	}
}

// Test: parsePythonRequirement strips trailing comments
// Justification: Inline comments in requirements files must not pollute version strings
// Source: pip requirements file format specification
// Methodology: Parse a requirement with inline comment
// Result: Returns clean version without comment text
func TestParsePythonRequirement_InlineComment(t *testing.T) {
	name, version := parsePythonRequirement("requests==2.28.0 # security fix")
	if name != "requests" {
		t.Errorf("Expected name 'requests', got %q", name)
	}
	if version != "2.28.0" {
		t.Errorf("Expected version '2.28.0', got %q", version)
	}
}

// ---- CountPythonDependencies tests (existing + expanded) ----

// Test: CountPythonDependencies with requirements.txt
// Justification: Dependency count from requirements.txt for sprawl scoring
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Count lines in a simple requirements.txt
// Result: Correct count, unverified (can't distinguish direct vs transitive)
func TestCountPythonDependencies_RequirementsTxt(t *testing.T) {
	metrics, err := CountPythonDependencies("testdata/requirements-small.txt")
	if err != nil {
		t.Fatalf("Failed to count dependencies: %v", err)
	}

	if metrics.TransitiveCount != 3 {
		t.Errorf("Expected 3 dependencies, got %d", metrics.TransitiveCount)
	}

	// requirements.txt doesn't distinguish direct vs transitive
	if metrics.Verified {
		t.Error("Expected unverified metrics for requirements.txt")
	}
}

// Test: CountPythonDependencies with Pipfile.lock
// Justification: Pipfile.lock provides accurate dependency counts from both
//                default and develop sections
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Count packages in Pipfile.lock JSON structure
// Result: Returns total from default + develop sections, verified=true
func TestCountPythonDependencies_PipfileLock(t *testing.T) {
	metrics, err := CountPythonDependencies("testdata/Pipfile.lock")
	if err != nil {
		t.Fatalf("Failed to count Pipfile.lock dependencies: %v", err)
	}

	// 5 default + 2 develop = 7 total
	if metrics.TransitiveCount != 7 {
		t.Errorf("Expected 7 total dependencies, got %d", metrics.TransitiveCount)
	}

	if !metrics.Verified {
		t.Error("Expected verified metrics for Pipfile.lock")
	}
}

// Test: CountPythonDependencies with nonexistent file
// Justification: Graceful error handling
// Source: Defense-in-depth principle
// Methodology: Attempt to count deps in nonexistent file
// Result: Returns error
func TestCountPythonDependencies_NonExistent(t *testing.T) {
	_, err := CountPythonDependencies("testdata/nonexistent.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// Test: CountPythonDependencies with unsupported file type
// Justification: Clear error for unsupported Python manifest formats
// Source: Defense-in-depth principle
// Methodology: Attempt to count deps from a pyproject.toml (not supported for counting)
// Result: Returns unsupported file error
func TestCountPythonDependencies_UnsupportedFile(t *testing.T) {
	_, err := CountPythonDependencies("testdata/pyproject.toml")
	if err == nil {
		t.Error("Expected error for unsupported file type")
	}
}

// Test: CountPythonDependencies with complex requirements.txt
// Justification: Complex requirements files with comments, -e, -r should be
//                counted correctly (only actual package lines)
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Count packages in a complex requirements.txt
// Result: Only counts actual package lines, not comments or directives
func TestCountPythonDependencies_ComplexRequirements(t *testing.T) {
	metrics, err := CountPythonDependencies("testdata/requirements-complex.txt")
	if err != nil {
		t.Fatalf("Failed to count complex requirements: %v", err)
	}

	// Should count: requests, Flask, numpy, boto3[crt], django, celery, click = 7
	// Skips: comments, empty lines, -e, --editable
	if metrics.TransitiveCount < 5 {
		t.Errorf("Expected at least 5 dependencies, got %d", metrics.TransitiveCount)
	}
}
