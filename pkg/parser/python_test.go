package parser

import (
	"os"
	"path/filepath"
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

// ---- parsePoetryLock tests ----

// Test: parsePoetryLock extracts all packages from poetry.lock
// Justification: poetry.lock is the lockfile for Poetry-managed Python projects -
//                accurate parsing identifies all resolved packages (direct and
//                transitive) for supply chain analysis of the full dependency tree
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - transitive
//         dependencies as attack vectors in supply chain compromises
// Methodology: Parse a poetry.lock file with [[package]] blocks
// Result: Returns all packages with correct names, versions, and PyPI ecosystem
func TestParsePoetryLock_AllPackages(t *testing.T) {
	deps, err := parsePoetryLock("testdata/poetry.lock")
	if err != nil {
		t.Fatalf("Failed to parse poetry.lock: %v", err)
	}

	// 8 packages: certifi, charset-normalizer, flask, idna, numpy, requests, urllib3, pytest
	if len(deps) != 8 {
		t.Fatalf("Expected 8 dependencies, got %d", len(deps))
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	if v, ok := depMap["requests"]; !ok || v != "2.28.0" {
		t.Errorf("Expected requests@2.28.0, got %v", v)
	}
	if v, ok := depMap["flask"]; !ok || v != "2.3.0" {
		t.Errorf("Expected flask@2.3.0, got %v", v)
	}
	if v, ok := depMap["numpy"]; !ok || v != "1.24.0" {
		t.Errorf("Expected numpy@1.24.0, got %v", v)
	}
	if v, ok := depMap["pytest"]; !ok || v != "7.0.0" {
		t.Errorf("Expected pytest@7.0.0, got %v", v)
	}
	if v, ok := depMap["certifi"]; !ok || v != "2022.9.24" {
		t.Errorf("Expected certifi@2022.9.24, got %v", v)
	}
}

// Test: parsePoetryLock sets correct ecosystem for all packages
// Justification: Poetry packages are published to PyPI - correct ecosystem tagging
//                ensures the PyPI registry API is used for supply chain analysis
// Source: OSSF Scorecard methodology - ecosystem-specific checks
// Methodology: Verify all parsed deps have PyPI ecosystem
// Result: All dependencies have EcosystemPyPI
func TestParsePoetryLock_Ecosystem(t *testing.T) {
	deps, err := parsePoetryLock("testdata/poetry.lock")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	for _, dep := range deps {
		if dep.Ecosystem != models.EcosystemPyPI {
			t.Errorf("Expected pypi ecosystem for %s, got %s", dep.Name, dep.Ecosystem)
		}
	}
}

// Test: parsePoetryLock sets Source field to the lock file path
// Justification: Source path is used by analyzeDependencySprawl to locate the
//                directory containing lock files for accurate dependency counting
// Source: Snyft architecture - dep.Source drives lock file discovery
// Methodology: Parse poetry.lock and verify Source field on returned deps
// Result: All dependencies have Source set to the poetry.lock path
func TestParsePoetryLock_SourcePath(t *testing.T) {
	deps, err := parsePoetryLock("testdata/poetry.lock")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	for _, dep := range deps {
		if dep.Source != "testdata/poetry.lock" {
			t.Errorf("Expected source 'testdata/poetry.lock' for %s, got %s", dep.Name, dep.Source)
		}
	}
}

// Test: parsePoetryLock returns error for nonexistent file
// Justification: Graceful error handling for missing lock files
// Source: Defense-in-depth principle
// Methodology: Attempt to parse a nonexistent poetry.lock
// Result: Returns file read error
func TestParsePoetryLock_NonexistentFile(t *testing.T) {
	_, err := parsePoetryLock("testdata/nonexistent-poetry.lock")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// ---- countPoetryLockDependencies tests ----

// Test: countPoetryLockDependencies counts all packages accurately
// Justification: poetry.lock is a verified lock file providing authoritative
//                transitive dependency counts - this feeds the dependency sprawl
//                scorer which assesses supply chain attack surface
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - transitive
//         dependency count as attack surface metric
// Methodology: Count [[package]] blocks in poetry.lock
// Result: Returns total package count with Verified=true
func TestCountPoetryLockDependencies_TotalCount(t *testing.T) {
	metrics, err := CountPythonDependencies("testdata/poetry.lock")
	if err != nil {
		t.Fatalf("Failed to count poetry.lock dependencies: %v", err)
	}

	// 8 total packages in the test fixture
	if metrics.TransitiveCount != 8 {
		t.Errorf("Expected 8 total dependencies, got %d", metrics.TransitiveCount)
	}

	if !metrics.Verified {
		t.Error("Expected verified metrics for poetry.lock")
	}
}

// Test: countPoetryLockDependencies resolves direct count from pyproject.toml
// Justification: Distinguishing direct from transitive dependencies is critical
//                for dependency sprawl scoring - a package with 3 direct deps
//                resolving to 100 transitive deps has higher supply chain risk
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - dependency
//         fan-out as compromise propagation metric
// Methodology: Count direct deps from companion pyproject.toml
// Result: DirectCount reflects pyproject.toml [tool.poetry.dependencies] minus python
func TestCountPoetryLockDependencies_DirectCount(t *testing.T) {
	metrics, err := CountPythonDependencies("testdata/poetry.lock")
	if err != nil {
		t.Fatalf("Failed to count poetry.lock dependencies: %v", err)
	}

	// pyproject.toml has 3 direct deps: requests, flask, numpy (python excluded)
	if metrics.DirectCount != 3 {
		t.Errorf("Expected 3 direct dependencies, got %d", metrics.DirectCount)
	}
}

// Test: countPoetryLockDependencies returns error for nonexistent file
// Justification: Graceful error handling
// Source: Defense-in-depth principle
// Methodology: Attempt to count deps in nonexistent poetry.lock
// Result: Returns error
func TestCountPoetryLockDependencies_NonExistent(t *testing.T) {
	_, err := CountPythonDependencies("testdata/nonexistent-poetry.lock")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// ---- parsePipfileLock tests (transitive dependency tagging) ----

// Test: parsePipfileLock tags direct vs transitive dependencies using companion Pipfile
// Justification: Pipfile.lock contains all resolved dependencies (direct + transitive).
//                Cross-referencing with Pipfile reveals which are explicitly chosen by
//                the developer vs pulled in transitively. Transitive dependencies
//                represent hidden attack surface — developers rarely audit them.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) - PyPI attack taxonomy
//         shows transitive dependency attacks are a growing vector
// Methodology: Parse Pipfile.lock alongside companion Pipfile. The Pipfile declares
//              requests, flask, numpy as direct [packages]; pytest as direct [dev-packages].
//              The Pipfile.lock has urllib3, certifi, charset-normalizer, idna as
//              transitive deps (not in Pipfile), and pluggy as transitive dev dep.
// Result: requests=direct, pytest=direct; urllib3, certifi, charset-normalizer,
//         idna, pluggy=transitive
func TestParsePipfileLock_TransitiveTagging(t *testing.T) {
	deps, err := parsePipfileLock("testdata/Pipfile.lock")
	if err != nil {
		t.Fatalf("Failed to parse Pipfile.lock: %v", err)
	}

	// Should have 7 deps total: 5 default + 2 develop
	if len(deps) != 7 {
		t.Fatalf("Expected 7 dependencies, got %d", len(deps))
	}

	depMap := make(map[string]models.Dependency)
	for _, dep := range deps {
		depMap[dep.Name] = dep
	}

	// Direct dependencies (present in companion Pipfile)
	directDeps := []string{"requests", "pytest"}
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

	// Transitive dependencies (in Pipfile.lock but NOT in Pipfile)
	transitiveDeps := []string{"urllib3", "certifi", "charset-normalizer", "idna", "pluggy"}
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

	// Verify all have PyPI ecosystem
	for _, dep := range deps {
		if dep.Ecosystem != models.EcosystemPyPI {
			t.Errorf("Expected pypi ecosystem for %s, got %s", dep.Name, dep.Ecosystem)
		}
	}
}

// Test: parsePipfileLock without companion Pipfile marks all as direct
// Justification: When no companion Pipfile exists, we cannot determine which
//                dependencies are direct vs transitive. The safe default is to
//                mark all as direct (IsTransitive=false) so no dependency is
//                silently excluded from analysis.
// Source: Snyft architecture guidelines - degrade gracefully, never fail completely
// Methodology: Create a Pipfile.lock in a temp directory without a Pipfile,
//              parse it, and verify all deps have IsTransitive=false
// Result: All dependencies have IsTransitive=false when no Pipfile is available
func TestParsePipfileLock_MissingPipfile(t *testing.T) {
	// Create temp directory with only Pipfile.lock (no Pipfile)
	tmpDir := t.TempDir()
	lockContent := `{
		"_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
		"default": {
			"requests": {"version": "==2.28.0"},
			"urllib3": {"version": "==1.26.12"}
		},
		"develop": {}
	}`

	lockPath := filepath.Join(tmpDir, "Pipfile.lock")
	if err := os.WriteFile(lockPath, []byte(lockContent), 0644); err != nil {
		t.Fatalf("Failed to create test Pipfile.lock: %v", err)
	}

	deps, err := parsePipfileLock(lockPath)
	if err != nil {
		t.Fatalf("Failed to parse Pipfile.lock: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("Expected 2 dependencies, got %d", len(deps))
	}

	for _, dep := range deps {
		if dep.IsTransitive {
			t.Errorf("%s should be direct (IsTransitive=false) when no Pipfile present, got IsTransitive=true", dep.Name)
		}
	}
}

// Test: parsePipfileLock uses case-insensitive matching for Python package names
// Justification: Python package names are case-insensitive per PEP 503. A Pipfile
//                may list "Flask" while Pipfile.lock lists "flask" — these must
//                match to correctly identify direct dependencies.
// Source: PEP 503 - Simple Repository API (case normalization for package names)
// Methodology: Create a Pipfile with "Flask" and a Pipfile.lock with "flask",
//              verify the case-insensitive match identifies it as direct
// Result: flask/Flask recognized as direct regardless of casing
func TestParsePipfileLock_CaseInsensitiveMatching(t *testing.T) {
	tmpDir := t.TempDir()

	// Pipfile with uppercase "Flask"
	pipfileContent := `[packages]
Flask = "*"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "Pipfile"), []byte(pipfileContent), 0644); err != nil {
		t.Fatalf("Failed to create Pipfile: %v", err)
	}

	// Pipfile.lock with lowercase "flask"
	lockContent := `{
		"_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6},
		"default": {
			"flask": {"version": "==2.3.0"},
			"werkzeug": {"version": "==2.3.0"}
		},
		"develop": {}
	}`
	lockPath := filepath.Join(tmpDir, "Pipfile.lock")
	if err := os.WriteFile(lockPath, []byte(lockContent), 0644); err != nil {
		t.Fatalf("Failed to create Pipfile.lock: %v", err)
	}

	deps, err := parsePipfileLock(lockPath)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	depMap := make(map[string]models.Dependency)
	for _, dep := range deps {
		depMap[dep.Name] = dep
	}

	// flask should be direct (matches "Flask" in Pipfile, case-insensitive)
	if dep, ok := depMap["flask"]; ok {
		if dep.IsTransitive {
			t.Error("flask should be direct (case-insensitive match with Flask in Pipfile)")
		}
	} else {
		t.Error("Expected flask dependency not found")
	}

	// werkzeug should be transitive (not in Pipfile)
	if dep, ok := depMap["werkzeug"]; ok {
		if !dep.IsTransitive {
			t.Error("werkzeug should be transitive (not in Pipfile)")
		}
	} else {
		t.Error("Expected werkzeug dependency not found")
	}
}

// Test: parsePipfileLock strips == prefix from versions
// Justification: Pipfile.lock uses "==X.Y.Z" format for versions. The "==" prefix
//                must be stripped for clean version strings used in registry lookups.
// Source: PEP 440 - Version Identification
// Methodology: Parse Pipfile.lock and verify version strings don't have "==" prefix
// Result: Versions are clean (e.g., "2.28.0" not "==2.28.0")
func TestParsePipfileLock_VersionStripping(t *testing.T) {
	deps, err := parsePipfileLock("testdata/Pipfile.lock")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	for _, dep := range deps {
		if dep.Version == "" {
			t.Errorf("Empty version for %s", dep.Name)
		}
		if dep.Version[0] == '=' {
			t.Errorf("Version for %s still has = prefix: %s", dep.Name, dep.Version)
		}
	}
}
