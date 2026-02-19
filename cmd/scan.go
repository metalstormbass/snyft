package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/metalstormbass/snyft/pkg/ai"
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

	// AI configuration flags
	aiEnabled      bool
	aiAPIKey       string
	aiTimeout      int
	aiDisableCache bool
	aiDisableRetry bool
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

	// AI feature flags
	scanCmd.Flags().BoolVar(&aiEnabled, "ai", false, "Enable AI-powered analysis (requires CLAUDE_API_KEY or --ai-api-key)")
	scanCmd.Flags().StringVar(&aiAPIKey, "ai-api-key", "", "Claude API key for AI analysis (alternative to CLAUDE_API_KEY env var)")
	scanCmd.Flags().IntVar(&aiTimeout, "ai-timeout", 60, "Timeout in seconds for AI operations")
	scanCmd.Flags().BoolVar(&aiDisableCache, "ai-disable-cache", false, "Disable AI response caching")
	scanCmd.Flags().BoolVar(&aiDisableRetry, "ai-disable-retry", false, "Disable retry on AI API failures")
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

	fmt.Fprintf(statusOut, "🔍 Scanning directory: %s\n", scanPath)

	// Parse manifest files
	manifestCount, dependencies, err := parseManifests(scanPath, statusOut)
	if err != nil {
		return fmt.Errorf("failed to parse manifests: %w", err)
	}

	reporter.SetManifestCount(manifestCount)

	if len(dependencies) == 0 {
		fmt.Fprintln(statusOut, "⚠️  No dependencies found")
		return nil
	}

	fmt.Fprintf(statusOut, "📦 Found %d dependencies across all manifests\n\n", len(dependencies))

	// Configure AI if enabled
	var aiConfig *ai.Config
	if aiEnabled {
		// Load base config from environment
		aiConfig, err = ai.LoadFromEnv()
		if err != nil {
			// Create default config if env loading fails
			aiConfig = ai.DefaultConfig()
		}

		// Override with CLI flags if provided
		if aiAPIKey != "" {
			aiConfig.APIKey = aiAPIKey
		}

		if aiConfig.APIKey == "" {
			fmt.Println("⚠️  AI analysis enabled but no API key provided. Set CLAUDE_API_KEY or use --ai-api-key")
			fmt.Println("    Continuing without AI analysis...")
			aiConfig = nil
		} else {
			if aiTimeout > 0 {
				aiConfig.Timeout = time.Duration(aiTimeout) * time.Second
			}
			if aiDisableCache {
				aiConfig.EnableCache = false
			}
			if aiDisableRetry {
				aiConfig.EnableRetry = false
			}
			fmt.Fprintf(statusOut, "🤖 AI analysis enabled (timeout: %v)\n", aiConfig.Timeout)
		}
	}

	// Analyze dependencies in parallel
	results := analyzeDependencies(dependencies, workers, reporter, aiConfig, statusOut)

	// Clear progress line
	reporter.ClearProgress()

	// Generate report
	reporter.AddResults(results)
	return reporter.Generate()
}

func parseManifests(dir string, statusOut *os.File) (int, []models.Dependency, error) {
	var allDeps []models.Dependency
	var mu sync.Mutex

	// Find all manifest files
	manifestFiles, err := findManifestFiles(dir)
	if err != nil {
		return 0, nil, err
	}

	fmt.Fprintf(statusOut, "📄 Found %d manifest files\n", len(manifestFiles))

	// Parse each manifest
	for _, file := range manifestFiles {
		if verbose {
			fmt.Fprintf(statusOut, "  Parsing: %s\n", file)
		}

		deps, err := parser.ParseManifest(file)
		if err != nil {
			fmt.Fprintf(statusOut, "⚠️  Failed to parse %s: %v\n", file, err)
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

func analyzeDependencies(deps []models.Dependency, numWorkers int, reporter *report.Reporter, aiConfig *ai.Config, statusOut *os.File) []models.AnalysisResult {
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

	// Create analyzer with AI configuration
	var a *analyzer.Analyzer
	if aiConfig != nil {
		a = analyzer.NewAnalyzer(analyzer.WithAIConfig(aiConfig))
	} else {
		// Create analyzer without AI if not explicitly enabled via flags
		// This prevents automatic AI initialization from env vars unless --ai is used
		a = analyzer.NewAnalyzer(analyzer.WithAIDisabled())
	}

	// When AI is enabled, start a heartbeat ticker that refreshes the progress
	// spinner every 500ms. Without this, the progress bar appears frozen during
	// long AI API calls.
	done := make(chan struct{})
	if aiConfig != nil {
		ticker := time.NewTicker(500 * time.Millisecond)
		go func() {
			for {
				select {
				case <-ticker.C:
					mu.Lock()
					if currentPkg != "" {
						suffix := " [AI analyzing]"
						reporter.ShowProgress(completed, len(deps), currentPkg+suffix)
					}
					mu.Unlock()
				case <-done:
					ticker.Stop()
					return
				}
			}
		}()
	}

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
	fmt.Fprintf(statusOut, "✅ Analysis complete in %s\n\n", formatDuration(duration))

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
