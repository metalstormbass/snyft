package cmd

import (
	"fmt"
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
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", true, "Verbose output with detailed analysis")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text, markdown, json, or html")
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

	// Create reporter
	reporter := report.NewReporter(report.Config{
		Format:       format,
		Verbose:      verbose,
		Writer:       os.Stdout,
		ShowProgress: format == report.FormatText, // Only show progress for text output
	})

	reporter.SetScanPath(scanPath)

	fmt.Printf("🔍 Scanning directory: %s\n", scanPath)

	// Parse manifest files
	manifestCount, dependencies, err := parseManifests(scanPath)
	if err != nil {
		return fmt.Errorf("failed to parse manifests: %w", err)
	}

	reporter.SetManifestCount(manifestCount)

	if len(dependencies) == 0 {
		fmt.Println("⚠️  No dependencies found")
		return nil
	}

	fmt.Printf("📦 Found %d dependencies across all manifests\n", len(dependencies))
	fmt.Println()

	// Analyze dependencies in parallel
	results := analyzeDependencies(dependencies, workers, reporter)

	// Clear progress line
	reporter.ClearProgress()

	// Generate report
	reporter.AddResults(results)
	return reporter.Generate()
}

func parseManifests(dir string) (int, []models.Dependency, error) {
	var allDeps []models.Dependency
	var mu sync.Mutex

	// Find all manifest files
	manifestFiles, err := findManifestFiles(dir)
	if err != nil {
		return 0, nil, err
	}

	fmt.Printf("📄 Found %d manifest files\n", len(manifestFiles))

	// Parse each manifest
	for _, file := range manifestFiles {
		if verbose {
			fmt.Printf("  Parsing: %s\n", file)
		}

		deps, err := parser.ParseManifest(file)
		if err != nil {
			fmt.Printf("⚠️  Failed to parse %s: %v\n", file, err)
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

func analyzeDependencies(deps []models.Dependency, numWorkers int, reporter *report.Reporter) []models.AnalysisResult {
	results := make([]models.AnalysisResult, len(deps))
	jobs := make(chan int, len(deps))
	var wg sync.WaitGroup
	var completed int
	var mu sync.Mutex

	startTime := time.Now()

	// Create analyzer
	a := analyzer.NewAnalyzer()

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				dep := deps[idx]
				results[idx] = a.Analyze(dep)

				// Update progress
				mu.Lock()
				completed++
				reporter.ShowProgress(completed, len(deps), fmt.Sprintf("%s@%s", dep.Name, dep.Version))
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

	duration := time.Since(startTime)
	reporter.ClearProgress()
	fmt.Printf("✅ Analysis complete in %s\n\n", formatDuration(duration))

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
	seen := make(map[string]bool)
	var unique []models.Dependency

	for _, dep := range deps {
		key := fmt.Sprintf("%s|%s|%s", dep.Ecosystem, dep.Name, dep.Version)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, dep)
		}
	}

	return unique
}
