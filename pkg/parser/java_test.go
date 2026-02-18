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

// Test: parsePomXML handles property references and BOM-managed versions
// Justification: Maven uses ${property} references and BOM-managed versions
//                which cannot be resolved statically - these should be marked
//                "unknown" rather than passed as empty strings that create
//                malformed registry URLs
// Source: Maven POM specification - dependency management
// Methodology: Parse a pom.xml with property-referenced and BOM-managed versions
// Result: Property versions set to "unknown", BOM versions set to "unknown"
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

	// BOM-managed dependency with no version element
	if v, ok := depMap["org.springframework:spring-core"]; !ok || v != "unknown" {
		t.Errorf("Expected spring-core@unknown (BOM-managed), got %v", v)
	}

	// Property-referenced version
	if v, ok := depMap["com.example:my-lib"]; !ok || v != "unknown" {
		t.Errorf("Expected my-lib@unknown (property ref), got %v", v)
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
