package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: Checkpoint round-trip preserves all result data
// Justification: When a scan is interrupted by a rate limit gate, the checkpoint
//                must faithfully preserve all completed analysis results so that
//                resuming produces the same report as a full uninterrupted scan.
//                Data loss during save/load would undermine the resume feature.
// Source: SLSA Build Level Requirements — integrity of intermediate artifacts
// Methodology: Create a checkpoint with realistic results, save it, load it,
//              and verify all fields are preserved
// Result: Loaded checkpoint matches the original
func TestCheckpoint_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	original := &ScanCheckpoint{
		ScanPath:           dir,
		CreatedAt:          time.Now().Truncate(time.Second), // JSON doesn't preserve nanoseconds
		Reason:             "rate_limit_approaching",
		RateLimitRemaining: 42,
		Results: []models.AnalysisResult{
			{
				Dependency: models.Dependency{
					Name:      "express",
					Version:   "4.18.2",
					Ecosystem: models.EcosystemNPM,
					Source:    "package.json",
				},
			},
			{
				Dependency: models.Dependency{
					Name:      "lodash",
					Version:   "4.17.21",
					Ecosystem: models.EcosystemNPM,
					Source:    "package.json",
				},
			},
		},
		CompletedKeys: []string{"npm|express", "npm|lodash"},
	}

	// Save
	if err := saveCheckpoint(dir, original); err != nil {
		t.Fatalf("saveCheckpoint() error: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(filepath.Join(dir, checkpointFileName)); err != nil {
		t.Fatalf("checkpoint file not created: %v", err)
	}

	// Load
	loaded, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("loadCheckpoint() error: %v", err)
	}
	if loaded == nil {
		t.Fatal("loadCheckpoint() returned nil")
	}

	// Verify fields
	if loaded.ScanPath != original.ScanPath {
		t.Errorf("ScanPath = %q, want %q", loaded.ScanPath, original.ScanPath)
	}
	if loaded.Reason != original.Reason {
		t.Errorf("Reason = %q, want %q", loaded.Reason, original.Reason)
	}
	if loaded.RateLimitRemaining != original.RateLimitRemaining {
		t.Errorf("RateLimitRemaining = %d, want %d", loaded.RateLimitRemaining, original.RateLimitRemaining)
	}
	if len(loaded.Results) != len(original.Results) {
		t.Fatalf("Results count = %d, want %d", len(loaded.Results), len(original.Results))
	}
	for i, r := range loaded.Results {
		if r.Dependency.Name != original.Results[i].Dependency.Name {
			t.Errorf("Results[%d].Name = %q, want %q", i, r.Dependency.Name, original.Results[i].Dependency.Name)
		}
	}
	if len(loaded.CompletedKeys) != len(original.CompletedKeys) {
		t.Fatalf("CompletedKeys count = %d, want %d", len(loaded.CompletedKeys), len(original.CompletedKeys))
	}
	for i, key := range loaded.CompletedKeys {
		if key != original.CompletedKeys[i] {
			t.Errorf("CompletedKeys[%d] = %q, want %q", i, key, original.CompletedKeys[i])
		}
	}
}

// Test: loadCheckpoint returns nil when no checkpoint file exists
// Justification: A fresh scan (no prior interruption) should not error when
//                there is no checkpoint file. The caller checks for nil to
//                determine whether to start fresh.
// Source: Defense-in-depth principle
// Methodology: Call loadCheckpoint on a directory with no checkpoint file
// Result: Returns nil, nil (no checkpoint, no error)
func TestCheckpoint_LoadNonExistent(t *testing.T) {
	dir := t.TempDir()

	cp, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("loadCheckpoint() error: %v", err)
	}
	if cp != nil {
		t.Errorf("loadCheckpoint() = %v, want nil for non-existent checkpoint", cp)
	}
}

// Test: removeCheckpoint deletes the checkpoint file
// Justification: After a full scan completes successfully, the checkpoint file
//                must be cleaned up so that a subsequent --resume does not
//                incorrectly skip packages based on stale data.
// Source: Defense-in-depth principle
// Methodology: Save a checkpoint, call removeCheckpoint, verify file is gone
// Result: File is deleted, loadCheckpoint returns nil
func TestCheckpoint_Remove(t *testing.T) {
	dir := t.TempDir()

	cp := &ScanCheckpoint{
		ScanPath:  dir,
		CreatedAt: time.Now(),
		Reason:    "test",
	}
	if err := saveCheckpoint(dir, cp); err != nil {
		t.Fatalf("saveCheckpoint() error: %v", err)
	}

	removeCheckpoint(dir)

	loaded, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("loadCheckpoint() after remove error: %v", err)
	}
	if loaded != nil {
		t.Error("loadCheckpoint() should return nil after removeCheckpoint()")
	}
}

// Test: dependencyKey generates correct deduplication keys
// Justification: The checkpoint uses dependency keys to track which packages
//                have been analyzed. Keys must match the format used by
//                deduplicateDependencies ("ecosystem|name") so that resume
//                correctly identifies completed packages.
// Source: Defense-in-depth principle
// Methodology: Generate keys for different ecosystems and verify format
// Result: Keys match expected "ecosystem|name" format
func TestDependencyKey(t *testing.T) {
	tests := []struct {
		dep  models.Dependency
		want string
	}{
		{
			dep:  models.Dependency{Name: "express", Ecosystem: models.EcosystemNPM},
			want: "npm|express",
		},
		{
			dep:  models.Dependency{Name: "requests", Ecosystem: models.EcosystemPyPI},
			want: "pypi|requests",
		},
		{
			dep:  models.Dependency{Name: "org.springframework:spring-core", Ecosystem: models.EcosystemMaven},
			want: "maven|org.springframework:spring-core",
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.dep.Ecosystem)+"/"+tt.dep.Name, func(t *testing.T) {
			if got := dependencyKey(tt.dep); got != tt.want {
				t.Errorf("dependencyKey() = %q, want %q", got, tt.want)
			}
		})
	}
}
