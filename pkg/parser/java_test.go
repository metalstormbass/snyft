package parser

import (
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ---- parsePomXML tests ----

// Test: parsePomXML extracts dependencies excluding test scope
// Justification: Maven test-scope dependencies are not shipped with the final
//                artifact and don't contribute to the runtime supply chain risk
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - focuses on
//         runtime dependency compromise
// Methodology: Parse a pom.xml with test and non-test dependencies
// Result: Returns only non-test dependencies with Maven ecosystem
func TestParsePomXML_ExcludesTestScope(t *testing.T) {
	deps, err := parsePomXML("testdata/pom-small.xml")
	if err != nil {
		t.Fatalf("Failed to parse pom.xml: %v", err)
	}

	// pom-small.xml has 3 deps: spring-boot-starter, guava, junit(test)
	// Should return 2 (junit excluded)
	if len(deps) != 2 {
		t.Fatalf("Expected 2 non-test dependencies, got %d", len(deps))
	}

	for _, dep := range deps {
		if dep.Ecosystem != models.EcosystemMaven {
			t.Errorf("Expected maven ecosystem for %s, got %s", dep.Name, dep.Ecosystem)
		}
	}

	// Verify groupId:artifactId format
	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	if v, ok := depMap["org.springframework.boot:spring-boot-starter"]; !ok || v != "3.0.0" {
		t.Errorf("Expected spring-boot-starter@3.0.0, got %v", v)
	}
	if v, ok := depMap["com.google.guava:guava"]; !ok || v != "31.1-jre" {
		t.Errorf("Expected guava@31.1-jre, got %v", v)
	}
}

// Test: parsePomXML resolves property references and BOM-managed versions
// Justification: Maven uses ${property} references and BOM-managed versions.
//                Accurate version resolution is critical for source verification
//                (sources.jar URL, git tag matching). Without correct versions,
//                source verification always fails, falsely inflating risk scores.
// Source: Maven POM specification - dependency management, property interpolation
// Methodology: Parse a pom.xml with property-referenced and BOM-managed versions,
//              verify that local resolution produces correct versions
// Result: ${project.version} resolves to project version, BOM-managed deps
//         resolve from local dependencyManagement section
func TestParsePomXML_PropertyAndBOMVersions(t *testing.T) {
	deps, err := parsePomXML("testdata/pom-bom.xml")
	if err != nil {
		t.Fatalf("Failed to parse pom-bom.xml: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("Expected 2 dependencies, got %d", len(deps))
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// BOM-managed dependency — resolved from local dependencyManagement
	// which uses ${spring.version} property (5.3.20)
	if v, ok := depMap["org.springframework:spring-core"]; !ok || v != "5.3.20" {
		t.Errorf("Expected spring-core@5.3.20 (resolved from dependencyManagement), got %v", v)
	}

	// Property-referenced version — ${project.version} resolves to 1.0.0
	if v, ok := depMap["com.example:my-lib"]; !ok || v != "1.0.0" {
		t.Errorf("Expected my-lib@1.0.0 (resolved from ${project.version}), got %v", v)
	}
}

// Test: parsePomXML resolves various property types and version ranges
// Justification: Maven projects use diverse property patterns including
//                ${project.version}, ${project.parent.version}, chained
//                property references, and version ranges. Failure to resolve
//                these produces "unknown" versions that break source verification
//                and inflate risk scores.
// Source: Maven POM reference - property inheritance, version ranges
// Methodology: Parse a pom.xml with parent, properties, derived properties,
//              project.version, parent version, version ranges, and unresolvable props
// Result: All locally-resolvable versions are correctly resolved; only
//         truly unresolvable references produce "unknown"
func TestParsePomXML_AdvancedPropertyResolution(t *testing.T) {
	deps, err := parsePomXML("testdata/pom-parent.xml")
	if err != nil {
		t.Fatalf("Failed to parse pom-parent.xml: %v", err)
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Direct property reference
	if v, ok := depMap["com.example:custom-lib"]; !ok || v != "4.5.0" {
		t.Errorf("Expected custom-lib@4.5.0 (from ${custom.version}), got %v", v)
	}

	// Chained property reference: ${derived.version} → ${custom.version} → 4.5.0
	if v, ok := depMap["com.example:derived-lib"]; !ok || v != "4.5.0" {
		t.Errorf("Expected derived-lib@4.5.0 (from chained ${derived.version}), got %v", v)
	}

	// ${project.version} → 2.0.0
	if v, ok := depMap["com.example:project-lib"]; !ok || v != "2.0.0" {
		t.Errorf("Expected project-lib@2.0.0 (from ${project.version}), got %v", v)
	}

	// ${project.parent.version} → 3.0.0
	if v, ok := depMap["com.example:parent-version-lib"]; !ok || v != "3.0.0" {
		t.Errorf("Expected parent-version-lib@3.0.0 (from ${project.parent.version}), got %v", v)
	}

	// Version range [1.0,2.0) → resolves to lower bound 1.0
	if v, ok := depMap["com.example:range-lib"]; !ok || v != "1.0" {
		t.Errorf("Expected range-lib@1.0 (from [1.0,2.0)), got %v", v)
	}

	// Exact version range [3.1.0] → 3.1.0
	if v, ok := depMap["com.example:exact-range-lib"]; !ok || v != "3.1.0" {
		t.Errorf("Expected exact-range-lib@3.1.0 (from [3.1.0]), got %v", v)
	}

	// Unresolvable property → "unknown"
	if v, ok := depMap["com.example:unresolvable-lib"]; !ok || v != "unknown" {
		t.Errorf("Expected unresolvable-lib@unknown, got %v", v)
	}

	// Parent BOM-managed dep (no local dependencyManagement entry) → "unknown"
	// (requires network resolution via ResolveBOMVersions)
	if v, ok := depMap["org.springframework.boot:spring-boot-starter-web"]; !ok || v != "unknown" {
		t.Errorf("Expected spring-boot-starter-web@unknown (needs BOM resolution), got %v", v)
	}
}

// Test: parsePomXML returns error for nonexistent file
// Justification: Graceful error handling
// Source: Defense-in-depth principle
// Methodology: Attempt to parse a nonexistent pom.xml
// Result: Returns file read error
func TestParsePomXML_NonexistentFile(t *testing.T) {
	_, err := parsePomXML("testdata/nonexistent-pom.xml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// Test: parsePomXML returns error for invalid XML
// Justification: Corrupt POM files should produce errors
// Source: Defense-in-depth principle
// Methodology: Attempt to parse invalid XML as POM
// Result: Returns XML parse error
func TestParsePomXML_InvalidXML(t *testing.T) {
	_, err := parsePomXML("testdata/package-invalid.json")
	if err == nil {
		t.Error("Expected error for invalid XML")
	}
}

// Test: ParsePomParent extracts parent POM reference
// Justification: Parent POM info is needed for external BOM resolution
//                via MavenClient.ResolveBOMVersions
// Source: Maven POM reference - parent POM inheritance
// Methodology: Parse a pom.xml with a parent declaration and verify extraction
// Result: Returns correct parent coordinates
func TestParsePomParent_WithParent(t *testing.T) {
	parent, err := ParsePomParent("testdata/pom-parent.xml")
	if err != nil {
		t.Fatalf("Failed to parse pom parent: %v", err)
	}

	if parent == nil {
		t.Fatal("Expected non-nil parent ref")
	}

	if parent.GroupID != "org.springframework.boot" {
		t.Errorf("Expected parent groupId org.springframework.boot, got %s", parent.GroupID)
	}
	if parent.ArtifactID != "spring-boot-starter-parent" {
		t.Errorf("Expected parent artifactId spring-boot-starter-parent, got %s", parent.ArtifactID)
	}
	if parent.Version != "3.0.0" {
		t.Errorf("Expected parent version 3.0.0, got %s", parent.Version)
	}
}

// Test: ParsePomParent returns nil for POM without parent
// Justification: Not all POMs have parents; nil return is expected
// Source: Maven POM reference
// Methodology: Parse a pom.xml without a parent declaration
// Result: Returns nil without error
func TestParsePomParent_NoParent(t *testing.T) {
	parent, err := ParsePomParent("testdata/pom-small.xml")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if parent != nil {
		t.Errorf("Expected nil parent for pom-small.xml, got %+v", parent)
	}
}

// Test: version range resolution
// Justification: Maven version ranges must be resolved to usable versions
//                for source verification (sources.jar lookup, git tag matching)
// Source: Maven version range specification
// Methodology: Test various range formats
// Result: Ranges resolved to appropriate single versions
func TestVersionRangeResolution(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"[1.0]", "1.0"},           // exact
		{"[1.0,2.0)", "1.0"},       // range, use lower bound
		{"[1.0,2.0]", "1.0"},       // range, use lower bound
		{"(,2.0]", "2.0"},          // no lower bound, use upper
		{"(1.0,)", "1.0"},          // no upper bound, use lower
		{"(,)", "unknown"},         // no bounds
	}

	for _, tt := range tests {
		if !isVersionRange(tt.input) {
			t.Errorf("Expected %q to be identified as a version range", tt.input)
			continue
		}
		result := resolveVersionRange(tt.input)
		if result != tt.expected {
			t.Errorf("resolveVersionRange(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// Test: isVersionRange correctly identifies ranges vs normal versions
// Justification: Only actual Maven version ranges should be processed
// Source: Maven version range specification
// Methodology: Test both ranges and non-ranges
// Result: Correctly distinguishes ranges from normal versions
func TestIsVersionRange(t *testing.T) {
	ranges := []string{"[1.0]", "[1.0,2.0)", "(,2.0]", "[1.0,)"}
	notRanges := []string{"1.0.0", "3.2.1-SNAPSHOT", "${version}", "", "ab"}

	for _, v := range ranges {
		if !isVersionRange(v) {
			t.Errorf("Expected %q to be a version range", v)
		}
	}
	for _, v := range notRanges {
		if isVersionRange(v) {
			t.Errorf("Expected %q to NOT be a version range", v)
		}
	}
}

// ---- parseBuildGradle tests ----

// Test: parseBuildGradle extracts dependencies from Gradle build file
// Justification: Gradle is used by ~40% of Java projects - accurate parsing
//                of dependency declarations ensures supply chain coverage
// Source: Maven Central/Gradle documentation
// Methodology: Parse a build.gradle with multiple dependency configurations
// Result: Returns dependencies from implementation, api, runtimeOnly, compileOnly
func TestParseBuildGradle_MultipleConfigurations(t *testing.T) {
	deps, err := parseBuildGradle("testdata/build.gradle")
	if err != nil {
		t.Fatalf("Failed to parse build.gradle: %v", err)
	}

	// build.gradle has: implementation (2), api (1), runtimeOnly (1), compileOnly (1)
	// testImplementation should NOT match (not in patterns)
	if len(deps) != 5 {
		t.Fatalf("Expected 5 dependencies, got %d", len(deps))
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// implementation with single quotes
	if v, ok := depMap["org.springframework.boot:spring-boot-starter-web"]; !ok || v != "3.0.0" {
		t.Errorf("Expected spring-boot-starter-web@3.0.0, got %v", v)
	}

	// implementation with double quotes
	if v, ok := depMap["com.google.guava:guava"]; !ok || v != "31.1-jre" {
		t.Errorf("Expected guava@31.1-jre, got %v", v)
	}

	// api configuration
	if v, ok := depMap["org.apache.commons:commons-lang3"]; !ok || v != "3.12.0" {
		t.Errorf("Expected commons-lang3@3.12.0, got %v", v)
	}

	// runtimeOnly
	if v, ok := depMap["com.h2database:h2"]; !ok || v != "2.1.214" {
		t.Errorf("Expected h2@2.1.214, got %v", v)
	}

	// compileOnly
	if v, ok := depMap["org.projectlombok:lombok"]; !ok || v != "1.18.24" {
		t.Errorf("Expected lombok@1.18.24, got %v", v)
	}
}

// Test: parseBuildGradle sets Maven ecosystem and correct source
// Justification: Gradle dependencies come from Maven repositories - ecosystem
//                must be Maven for correct registry API lookups
// Source: Gradle documentation - dependency management
// Methodology: Verify ecosystem and source on all parsed dependencies
// Result: All have EcosystemMaven and correct source path
func TestParseBuildGradle_EcosystemAndSource(t *testing.T) {
	deps, err := parseBuildGradle("testdata/build.gradle")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	for _, dep := range deps {
		if dep.Ecosystem != models.EcosystemMaven {
			t.Errorf("Expected maven ecosystem for %s, got %s", dep.Name, dep.Ecosystem)
		}
		if dep.Source != "testdata/build.gradle" {
			t.Errorf("Expected source testdata/build.gradle, got %s", dep.Source)
		}
	}
}

// Test: parseBuildGradle returns error for nonexistent file
// Justification: Graceful error handling
// Source: Defense-in-depth principle
// Methodology: Attempt to parse a nonexistent Gradle file
// Result: Returns file read error
func TestParseBuildGradle_NonexistentFile(t *testing.T) {
	_, err := parseBuildGradle("testdata/nonexistent-build.gradle")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// Test: parseBuildGradle handles empty or comment-only file
// Justification: Gradle files without dependencies should not error
// Source: Defense-in-depth principle
// Methodology: Parse a file with no dependency declarations
// Result: Returns empty slice without error
func TestParseBuildGradle_NoDependencies(t *testing.T) {
	// Use an existing file that has no Gradle dependency declarations
	deps, err := parseBuildGradle("testdata/requirements-small.txt")
	if err != nil {
		t.Fatalf("Unexpected error for file with no Gradle deps: %v", err)
	}

	if len(deps) != 0 {
		t.Errorf("Expected 0 dependencies from non-Gradle file, got %d", len(deps))
	}
}

// ---- CountMavenDependencies tests (existing + expanded) ----

// Test: CountMavenDependencies with small pom
// Justification: Dependency count from pom.xml for sprawl scoring
// Source: "Small World with High Risks" (Zimmermann et al., 2019) - applied to Maven
// Methodology: Count non-test dependencies in pom.xml
// Result: Correct direct count, unverified (pom.xml shows only direct deps)
func TestCountMavenDependencies_Small(t *testing.T) {
	metrics, err := CountMavenDependencies("testdata/pom-small.xml")
	if err != nil {
		t.Fatalf("Failed to count dependencies: %v", err)
	}

	// Should be 2 non-test dependencies (spring-boot-starter, guava)
	if metrics.TransitiveCount != 2 {
		t.Errorf("Expected 2 dependencies (excluding test scope), got %d", metrics.TransitiveCount)
	}

	if metrics.DirectCount != 2 {
		t.Errorf("Expected 2 direct dependencies, got %d", metrics.DirectCount)
	}

	// pom.xml only shows direct deps
	if metrics.Verified {
		t.Error("Expected unverified metrics for pom.xml")
	}
}

// Test: CountMavenDependencies with BOM-managed pom
// Justification: BOM-managed projects have dependencies without explicit versions -
//                they should still be counted for sprawl assessment
// Source: Maven dependency management specification
// Methodology: Count dependencies in a BOM-managed pom.xml
// Result: Counts all non-test dependencies regardless of version presence
func TestCountMavenDependencies_BOMManaged(t *testing.T) {
	metrics, err := CountMavenDependencies("testdata/pom-bom.xml")
	if err != nil {
		t.Fatalf("Failed to count BOM-managed dependencies: %v", err)
	}

	// Both non-test dependencies should be counted
	if metrics.DirectCount != 2 {
		t.Errorf("Expected 2 direct dependencies, got %d", metrics.DirectCount)
	}
}

// Test: CountMavenDependencies with nonexistent file
// Justification: Graceful error handling
// Source: Defense-in-depth principle
// Methodology: Attempt to count deps in nonexistent file
// Result: Returns error
func TestCountMavenDependencies_NonExistent(t *testing.T) {
	_, err := CountMavenDependencies("testdata/nonexistent.xml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// ---- ParsePomBOMImports tests ----

// Test: ParsePomBOMImports extracts imported BOMs from dependencyManagement
// Justification: Imported BOMs (scope=import, type=pom) define managed
//                dependency versions from external POMs. Without following
//                these imports, versions for BOM-managed dependencies remain
//                "unknown", preventing source verification and inflating risk.
// Source: Maven POM reference — BOM import mechanism
// Methodology: Parse a pom.xml with both imported BOMs and regular managed deps
// Result: Returns only imported BOM entries, not regular managed deps
func TestParsePomBOMImports(t *testing.T) {
	imports, err := ParsePomBOMImports("testdata/pom-import-bom.xml")
	if err != nil {
		t.Fatalf("Failed to parse BOM imports: %v", err)
	}

	if len(imports) != 1 {
		t.Fatalf("Expected 1 BOM import, got %d", len(imports))
	}

	if imports[0].GroupID != "org.springframework.boot" {
		t.Errorf("Expected groupId org.springframework.boot, got %s", imports[0].GroupID)
	}
	if imports[0].ArtifactID != "spring-boot-dependencies" {
		t.Errorf("Expected artifactId spring-boot-dependencies, got %s", imports[0].ArtifactID)
	}
	// Version should be resolved from ${spring.boot.version} → 3.0.0
	if imports[0].Version != "3.0.0" {
		t.Errorf("Expected version 3.0.0 (resolved from ${spring.boot.version}), got %s", imports[0].Version)
	}
}

// Test: ParsePomBOMImports returns nil for POM without BOM imports
// Justification: Not all POMs import BOMs; nil return is expected
// Source: Maven POM reference
// Methodology: Parse a pom.xml without BOM imports
// Result: Returns nil without error
func TestParsePomBOMImports_NoImports(t *testing.T) {
	imports, err := ParsePomBOMImports("testdata/pom-small.xml")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(imports) != 0 {
		t.Errorf("Expected 0 BOM imports for pom-small.xml, got %d", len(imports))
	}
}

// Test: parsePomXML correctly separates imported BOMs from regular managed deps
// Justification: BOM imports (scope=import, type=pom) should NOT be added
//                to the local dependencyManagement lookup. They are pointers
//                to external POMs, not version definitions for actual artifacts.
//                Including them pollutes the depMgmt map with incorrect entries.
// Source: Maven POM reference — BOM import vs regular dependency management
// Methodology: Parse a pom.xml with both imported BOMs and regular managed deps
// Result: Local-managed dep resolves correctly; BOM-managed dep is "unknown"
//         (waiting for remote resolution via ResolveBOMVersions)
func TestParsePomXML_ImportedBOMNotInDepMgmt(t *testing.T) {
	deps, err := parsePomXML("testdata/pom-import-bom.xml")
	if err != nil {
		t.Fatalf("Failed to parse pom.xml: %v", err)
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Local managed dep should resolve from local dependencyManagement
	if v, ok := depMap["com.example:local-managed"]; !ok || v != "2.0.0" {
		t.Errorf("Expected local-managed@2.0.0 (from local depMgmt), got %v", v)
	}

	// BOM-managed dep should be "unknown" (needs remote resolution)
	if v, ok := depMap["org.springframework.boot:spring-boot-starter-web"]; !ok || v != "unknown" {
		t.Errorf("Expected spring-boot-starter-web@unknown (needs BOM resolution), got %v", v)
	}

	// Explicit version should be preserved
	if v, ok := depMap["com.google.guava:guava"]; !ok || v != "31.1-jre" {
		t.Errorf("Expected guava@31.1-jre, got %v", v)
	}
}

// ---- ParsePomUnresolvedVersions tests ----

// Test: ParsePomUnresolvedVersions returns unresolved property references
// Justification: When a local POM uses ${property} where the property is
//                defined in a parent POM, the local parser can't resolve it.
//                Preserving the original property reference allows the remote
//                resolver to attempt resolution using parent POM properties.
// Source: Maven POM reference — property inheritance
// Methodology: Parse a pom.xml with a property ref not defined locally
// Result: Returns the original ${property} reference for resolution
func TestParsePomUnresolvedVersions(t *testing.T) {
	unresolved, err := ParsePomUnresolvedVersions("testdata/pom-parent-props.xml")
	if err != nil {
		t.Fatalf("Failed to parse unresolved versions: %v", err)
	}

	// ${parent.defined.version} is not defined locally
	if ref, ok := unresolved["com.example:parent-prop-lib"]; !ok {
		t.Error("Expected parent-prop-lib in unresolved map")
	} else if ref != "${parent.defined.version}" {
		t.Errorf("Expected unresolved ref ${parent.defined.version}, got %s", ref)
	}

	// ${local.prop} IS defined locally, should NOT be in unresolved
	if _, ok := unresolved["com.example:local-prop-lib"]; ok {
		t.Error("local-prop-lib should not be in unresolved (property is locally defined)")
	}
}

// ---- Gradle platform() tests ----

// Test: parseBuildGradle extracts version-less dependencies (BOM-managed)
// Justification: Gradle projects using platform() or enforcedPlatform() declare
//                dependencies without explicit versions. These are BOM-managed
//                and must be extracted for supply chain assessment.
// Source: Gradle documentation — dependency management with BOMs
// Methodology: Parse a build.gradle with platform() and version-less deps
// Result: BOM-managed deps extracted with "unknown" version, explicit deps preserved
func TestParseBuildGradle_PlatformDependencies(t *testing.T) {
	deps, err := parseBuildGradle("testdata/build-platform.gradle")
	if err != nil {
		t.Fatalf("Failed to parse build.gradle: %v", err)
	}

	depMap := make(map[string]string)
	for _, dep := range deps {
		depMap[dep.Name] = dep.Version
	}

	// Explicit version should be preserved
	if v, ok := depMap["com.google.guava:guava"]; !ok || v != "31.1-jre" {
		t.Errorf("Expected guava@31.1-jre, got %v", v)
	}

	// BOM-managed deps (no version) should be "unknown"
	if v, ok := depMap["org.springframework.boot:spring-boot-starter-web"]; !ok || v != "unknown" {
		t.Errorf("Expected spring-boot-starter-web@unknown (BOM-managed), got %v", v)
	}

	if v, ok := depMap["com.fasterxml.jackson.core:jackson-databind"]; !ok || v != "unknown" {
		t.Errorf("Expected jackson-databind@unknown (BOM-managed), got %v", v)
	}
}
