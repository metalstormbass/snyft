package parser

import (
	"testing"
)

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

func TestCountMavenDependencies_NonExistent(t *testing.T) {
	_, err := CountMavenDependencies("testdata/nonexistent.xml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}
