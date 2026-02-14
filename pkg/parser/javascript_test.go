package parser

import (
	"testing"
)

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

func TestCountTransitiveDependencies_NonExistent(t *testing.T) {
	_, err := CountTransitiveDependencies("testdata/nonexistent.json")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}
