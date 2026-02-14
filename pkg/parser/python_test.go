package parser

import (
	"testing"
)

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

func TestCountPythonDependencies_NonExistent(t *testing.T) {
	_, err := CountPythonDependencies("testdata/nonexistent.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}
