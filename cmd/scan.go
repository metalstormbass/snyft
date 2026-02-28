package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/metalstormbass/snyft/pkg/analyzer"
	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/metalstormbass/snyft/pkg/parser"
	"github.com/metalstormbass/snyft/pkg/report"
	"github.com/spf13/cobra"
)

var (
	scanPath    string
	workers     int
	outputFile  string
	verbose     bool
	outputFormat string

	// Transitive dependency flag
	includeTransitive bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project directory for dependencies and analyze supply chain security",
	Long: `Scans the specified directory (or current directory) for manifest files
(package.json, requirements.txt, pom.xml, etc.) and analyzes each dependency
for supply chain security risks.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 10, "Number of concurrent workers for analysis")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for results (default: stdout)")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output with detailed analysis")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text, markdown, json, or html")

	// Transitive dependency flag
	scanCmd.Flags().BoolVar(&includeTransitive, "include-transitive", false, "Include transitive dependencies in analysis (default: direct only)")

}

func runScan(cmd *cobra.Command, args []string) error {
	// Determine scan path
	if len(args) > 0 {
		scanPath = args[0]
	} else {
		var err error
		scanPath, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
	}

	// Validate format
	format := report.Format(outputFormat)
	if format != report.FormatText && format != report.FormatMarkdown &&
		format != report.FormatJSON && format != report.FormatHTML {
		return fmt.Errorf("unsupported format: %s (must be text, markdown, json, or html)", outputFormat)
	}

	// Route status/progress messages to stderr for machine-readable formats so
	// that stdout (or the output file) contains only the structured result.
	statusOut := os.Stdout
	if format == report.FormatJSON || format == report.FormatHTML || format == report.FormatMarkdown {
		statusOut = os.Stderr
	}

	// Determine output writer: file when -o is set, otherwise stdout
	outputWriter := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		outputWriter = f
		// When writing to a file, status messages always go to stderr regardless of format
		statusOut = os.Stderr
	}

	// Create reporter – enable progress bar for all formats.
	// For non-text formats (or file output), route the animated progress to stderr
	// so it doesn't corrupt the structured output on stdout.
	var progressWriter io.Writer
	if format != report.FormatText || outputFile != "" {
		progressWriter = os.Stderr
	}
	reporter := report.NewReporter(report.Config{
		Format:         format,
		Verbose:        verbose,
		Writer:         outputWriter,
		ShowProgress:   true,
		ProgressWriter: progressWriter,
	})

	_, _ = fmt.Fprintf(statusOut, "🔍 Scanning directory: %s\n", scanPath)

	// Parse manifest files
	manifestCount, dependencies, err := parseManifests(scanPath, statusOut)
	if err != nil {
		return fmt.Errorf("failed to parse manifests: %w", err)
	}

	reporter.SetManifestCount(manifestCount)

	if len(dependencies) == 0 {
		_, _ = fmt.Fprintln(statusOut, "⚠️  No dependencies found")
		return nil
	}

	// Count direct vs transitive dependencies for reporting
	var directCount, transitiveCount int
	for _, dep := range dependencies {
		if dep.IsTransitive {
			transitiveCount++
		} else {
			directCount++
		}
	}
	reporter.SetDependencyCounts(directCount, transitiveCount)

	// Filter out transitive deps unless --include-transitive is set
	if !includeTransitive && transitiveCount > 0 {
		var directDeps []models.Dependency
		for _, dep := range dependencies {
			if !dep.IsTransitive {
				directDeps = append(directDeps, dep)
			}
		}
		_, _ = fmt.Fprintf(statusOut, "📦 Found %d dependencies (%d direct, %d transitive)\n", len(dependencies), directCount, transitiveCount)
		_, _ = fmt.Fprintf(statusOut, "   Analyzing %d direct dependencies (use --include-transitive to analyze all)\n\n", len(directDeps))
		dependencies = directDeps
	} else {
		_, _ = fmt.Fprintf(statusOut, "📦 Found %d dependencies (%d direct, %d transitive)\n\n", len(dependencies), directCount, transitiveCount)
	}

	// Analyze dependencies in parallel
	results := analyzeDependencies(dependencies, workers, reporter, statusOut)

	// Clear progress line
	reporter.ClearProgress()

	// Generate report
	reporter.AddResults(results)
	return reporter.Generate()
}

// lockFilePreference maps manifests to their lock file equivalents.
// When both exist in the same directory, the lock file is preferred because
// it contains the complete resolved dependency tree with exact versions.
var lockFilePreference = map[string]string{
	"package.json": "package-lock.json",
	"Pipfile":      "Pipfile.lock",
}

func parseManifests(dir string, statusOut *os.File) (int, []models.Dependency, error) {
	var allDeps []models.Dependency
	var mu sync.Mutex

	// Find all manifest files
	manifestFiles, err := findManifestFiles(dir)
	if err != nil {
		return 0, nil, err
	}

	// Build a set of manifest paths for quick lookup
	manifestSet := make(map[string]bool)
	for _, f := range manifestFiles {
		manifestSet[f] = true
	}

	// Determine which manifests to skip (lock file takes precedence)
	skipped := make(map[string]bool)
	for _, file := range manifestFiles {
		base := filepath.Base(file)
		if lockName, ok := lockFilePreference[base]; ok {
			lockPath := filepath.Join(filepath.Dir(file), lockName)
			if manifestSet[lockPath] {
				skipped[file] = true
			}
		}
	}

	_, _ = fmt.Fprintf(statusOut, "📄 Found %d manifest files\n", len(manifestFiles))

	// Parse each manifest (skip those superseded by lock files)
	for _, file := range manifestFiles {
		if skipped[file] {
			if verbose {
				_, _ = fmt.Fprintf(statusOut, "  Skipping: %s (lock file present)\n", file)
			}
			continue
		}

		if verbose {
			_, _ = fmt.Fprintf(statusOut, "  Parsing: %s\n", file)
		}

		deps, err := parser.ParseManifest(file)
		if err != nil {
			_, _ = fmt.Fprintf(statusOut, "⚠️  Failed to parse %s: %v\n", file, err)
			continue
		}

		mu.Lock()
		allDeps = append(allDeps, deps...)
		mu.Unlock()
	}

	return len(manifestFiles), deduplicateDependencies(allDeps), nil
}

func findManifestFiles(dir string) ([]string, error) {
	var manifestFiles []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip node_modules, .git, and other common directories
		if info.IsDir() {
			name := info.Name()
			if name == "node_modules" || name == ".git" || name == "vendor" || name == "venv" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if file is a manifest
		if parser.IsManifestFile(info.Name()) {
			manifestFiles = append(manifestFiles, path)
		}

		return nil
	})

	return manifestFiles, err
}

func analyzeDependencies(deps []models.Dependency, numWorkers int, reporter *report.Reporter, statusOut *os.File) []models.AnalysisResult {
	results := make([]models.AnalysisResult, len(deps))
	jobs := make(chan int, len(deps))
	var wg sync.WaitGroup
	var completed int
	var mu sync.Mutex
	// currentPkg tracks what the workers are currently analyzing so the
	// heartbeat ticker can refresh the spinner even while a slow AI call
	// is in progress.
	var currentPkg string

	startTime := time.Now()
	_ = startTime // used by reporter internally

	// Create analyzer
	a := analyzer.NewAnalyzer()

	// Start a heartbeat ticker that refreshes the progress spinner every 500ms.
	// Without this, the progress bar appears frozen during long network calls
	// (registry APIs, git platform lookups, AI analysis) and looks like a hang.
	done := make(chan struct{})
	ticker := time.NewTicker(500 * time.Millisecond)
	go func() {
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				if currentPkg != "" {
					reporter.ShowProgress(completed, len(deps), currentPkg)
				}
				mu.Unlock()
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				dep := deps[idx]
				pkgLabel := fmt.Sprintf("%s@%s", dep.Name, dep.Version)

				mu.Lock()
				currentPkg = pkgLabel
				mu.Unlock()

				results[idx] = a.Analyze(dep)

				// Update progress
				mu.Lock()
				completed++
				reporter.ShowProgress(completed, len(deps), pkgLabel)
				mu.Unlock()
			}
		}()
	}

	// Queue jobs
	for i := range deps {
		jobs <- i
	}
	close(jobs)

	// Wait for completion
	wg.Wait()
	close(done)

	duration := time.Since(startTime)
	reporter.ClearProgress()
	_, _ = fmt.Fprintf(statusOut, "✅ Analysis complete in %s\n\n", formatDuration(duration))

	return results
}

// formatDuration formats a duration for display
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func deduplicateDependencies(deps []models.Dependency) []models.Dependency {
	// Track index of first occurrence so we can replace transitive with direct
	seen := make(map[string]int) // key -> index in unique slice
	var unique []models.Dependency

	for _, dep := range deps {
		key := fmt.Sprintf("%s|%s|%s", dep.Ecosystem, dep.Name, dep.Version)
		if idx, exists := seen[key]; exists {
			// If we already have a transitive entry and this one is direct, replace it
			if unique[idx].IsTransitive && !dep.IsTransitive {
				unique[idx] = dep
			}
		} else {
			seen[key] = len(unique)
			unique = append(unique, dep)
		}
	}

	return unique
}
