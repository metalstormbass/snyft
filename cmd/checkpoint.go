package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

const checkpointFileName = ".snyft-checkpoint.json"

// ScanCheckpoint stores partial scan results so a rate-limited scan can be
// resumed later without re-analyzing already completed packages.
type ScanCheckpoint struct {
	// Metadata
	ScanPath  string    `json:"scan_path"`
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason"` // e.g. "rate_limit_approaching"

	// Rate limit state at time of stop
	RateLimitRemaining int `json:"rate_limit_remaining"`

	// Completed results (fully analyzed packages)
	Results []models.AnalysisResult `json:"results"`

	// CompletedKeys tracks which packages have been analyzed, keyed by
	// "ecosystem|name" to match the deduplication key format.
	CompletedKeys []string `json:"completed_keys"`
}

// checkpointPath returns the path to the checkpoint file for a given scan directory.
func checkpointPath(scanDir string) string {
	return filepath.Join(scanDir, checkpointFileName)
}

// saveCheckpoint writes partial scan results to a checkpoint file.
func saveCheckpoint(scanDir string, cp *ScanCheckpoint) error {
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}
	path := checkpointPath(scanDir)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write checkpoint file: %w", err)
	}
	return nil
}

// loadCheckpoint reads a checkpoint file from the scan directory.
// Returns nil, nil if no checkpoint file exists.
func loadCheckpoint(scanDir string) (*ScanCheckpoint, error) {
	path := checkpointPath(scanDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read checkpoint file: %w", err)
	}

	var cp ScanCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint file: %w", err)
	}
	return &cp, nil
}

// removeCheckpoint deletes the checkpoint file after a successful full scan.
func removeCheckpoint(scanDir string) {
	_ = os.Remove(checkpointPath(scanDir))
}

// dependencyKey returns the deduplication key for a dependency.
func dependencyKey(dep models.Dependency) string {
	return fmt.Sprintf("%s|%s", dep.Ecosystem, dep.Name)
}
