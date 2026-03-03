package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metalstormbass/snyft/pkg/analyzer"
	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/metalstormbass/snyft/pkg/parser"
	"github.com/metalstormbass/snyft/pkg/report"
	"github.com/spf13/cobra"
)

// rateLimitScrapingThreshold is the minimum number of GitHub API calls that must
// remain before the scan switches to scraping-only mode. When the rate limit
// drops below this value, remaining packages are analyzed using web scraping
// instead of the GitHub API. The scan NEVER stops — all packages get results.
// A checkpoint file is saved so users can optionally re-run with full API
// access later via --resume.
const rateLimitScrapingThreshold = 50

var (
	scanPath    string
	workers     int
	outputFile  string
	verbose     bool
	outputFormat string

	// Transitive dependency flag
	includeTransitive bool

	// Check filter flag
	checkFilter string

	// All versions flag (skip deduplication)
	allVersions bool

	// Resume flag
	resumeScan bool
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

	// All versions flag (skip deduplication)
	scanCmd.Flags().BoolVar(&allVersions, "all-versions", false, "Scan all versions of duplicate dependencies (default: deduplicate by name, keeping the most recent version)")

	// Check filter flag
	scanCmd.Flags().StringVar(&checkFilter, "check", "", `Comma-separated list of checks to run. Valid check names:
  publisher-control, ownership-changes, release-anomalies,
  install-execution, dependency-sprawl, provenance, health,
  governance, release-security, package-maturity`)

	// Resume flag
	scanCmd.Flags().BoolVar(&resumeScan, "resume", false, "Resume a previously interrupted scan from its checkpoint file")
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

	// Parse and validate --check flag
	var selectedChecks []string
	if checkFilter != "" {
		for _, name := range strings.Split(checkFilter, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if _, valid := analyzer.ValidCheckNames[name]; !valid {
				validNames := make([]string, 0, len(analyzer.ValidCheckNames))
				for k := range analyzer.ValidCheckNames {
					validNames = append(validNames, k)
				}
				sort.Strings(validNames)
				return fmt.Errorf("invalid check name %q; valid values: %s", name, strings.Join(validNames, ", "))
			}
			selectedChecks = append(selectedChecks, name)
		}
		if len(selectedChecks) == 0 {
			return fmt.Errorf("--check flag provided but no valid check names specified")
		}
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

	// Show GitHub token status before scanning begins
	if os.Getenv("GITHUB_TOKEN") != "" {
		_, _ = fmt.Fprintln(statusOut, "🔑 GitHub token detected (authenticated API access)")
	} else {
		_, _ = fmt.Fprintln(statusOut, "💡 Tip: Set GITHUB_TOKEN for richer data and 5,000 req/hr instead of 60")
	}

	// Parse manifest files
	manifestCount, dependencies, err := parseManifests(scanPath, statusOut)
	if err != nil {
		return fmt.Errorf("failed to parse manifests: %w", err)
	}

	// Resolve Maven BOM-managed versions from parent POMs
	dependencies = resolveMavenBOMVersions(dependencies, statusOut, verbose)

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

	// Load checkpoint if resuming a previous scan
	var previousResults []models.AnalysisResult
	if resumeScan {
		cp, err := loadCheckpoint(scanPath)
		if err != nil {
			return fmt.Errorf("failed to load checkpoint: %w", err)
		}
		if cp == nil {
			_, _ = fmt.Fprintln(statusOut, "⚠️  No checkpoint file found, starting fresh scan")
		} else {
			// Build set of already-completed package keys
			completedSet := make(map[string]bool, len(cp.CompletedKeys))
			for _, key := range cp.CompletedKeys {
				completedSet[key] = true
			}

			// Filter out already-completed dependencies
			var remaining []models.Dependency
			for _, dep := range dependencies {
				if !completedSet[dependencyKey(dep)] {
					remaining = append(remaining, dep)
				}
			}

			previousResults = cp.Results
			_, _ = fmt.Fprintf(statusOut, "📂 Resuming from checkpoint: %d packages already analyzed, %d remaining\n\n",
				len(cp.Results), len(remaining))
			dependencies = remaining

			if len(dependencies) == 0 {
				_, _ = fmt.Fprintln(statusOut, "✅ All packages already analyzed in previous scan")
				reporter.ClearProgress()
				reporter.AddResults(previousResults)
				removeCheckpoint(scanPath)
				return reporter.Generate()
			}
		}
	}

	// Analyze dependencies in parallel (with rate limit gate)
	scanResult := analyzeDependenciesWithGate(dependencies, workers, reporter, selectedChecks, statusOut)

	// Clear progress line
	reporter.ClearProgress()

	// Merge with any previously completed results from checkpoint
	allResults := append(previousResults, scanResult.results...)

	if scanResult.rateLimitFallback {
		// Save checkpoint so the user can optionally re-run with full API
		// access later. The scraping-only packages in the checkpoint are
		// identified by their DataMode field in the saved results.
		var completedKeys []string
		for _, r := range allResults {
			completedKeys = append(completedKeys, dependencyKey(r.Dependency))
		}
		cp := &ScanCheckpoint{
			ScanPath:           scanPath,
			CreatedAt:          time.Now(),
			Reason:             "rate_limit_scraping_fallback",
			RateLimitRemaining: scanResult.rateLimitRemaining,
			Results:            allResults,
			CompletedKeys:      completedKeys,
		}
		if err := saveCheckpoint(scanPath, cp); err != nil {
			_, _ = fmt.Fprintf(statusOut, "⚠️  Failed to save checkpoint: %v\n", err)
		} else {
			_, _ = fmt.Fprintf(statusOut, "💾 Checkpoint saved (%d packages used scraping-only data)\n", scanResult.scrapingOnlyCount)
			_, _ = fmt.Fprintf(statusOut, "   To re-analyze with full API data: snyft scan --resume %s\n\n", scanPath)
		}
	} else {
		// Full scan complete — remove any leftover checkpoint file
		removeCheckpoint(scanPath)
	}

	// Generate report with all results (both full and scraping-only)
	reporter.AddResults(allResults)
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

	if allVersions {
		return len(manifestFiles), allDeps, nil
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

// analysisOutput holds the results from analyzeDependenciesWithGate.
type analysisOutput struct {
	results             []models.AnalysisResult
	rateLimitFallback   bool // true when scraping-only mode was activated due to rate limit
	rateLimitRemaining  int
	scrapingOnlyCount   int // number of packages analyzed in scraping-only mode
}

// analyzeDependenciesWithGate runs dependency analysis with a rate limit gate.
// When the GitHub API rate limit drops below rateLimitScrapingThreshold, it
// switches to scraping-only mode for remaining packages. The scan NEVER stops —
// ALL packages get results. Packages analyzed after the rate limit gate triggers
// will have reduced data fidelity (marked with DataMode "scraping-only").
func analyzeDependenciesWithGate(deps []models.Dependency, numWorkers int, reporter *report.Reporter, selectedChecks []string, statusOut *os.File) analysisOutput {
	results := make([]models.AnalysisResult, len(deps))
	completedFlags := make([]bool, len(deps)) // tracks which indices were actually analyzed
	scrapingOnlyFlags := make([]bool, len(deps)) // tracks which indices were analyzed in scraping-only mode
	jobs := make(chan int, len(deps))
	var wg sync.WaitGroup
	var completed int
	var mu sync.Mutex
	var currentPkg string

	startTime := time.Now()
	_ = startTime // used by reporter internally

	// Create analyzer with optional check filter
	var opts []analyzer.AnalyzerOption
	if len(selectedChecks) > 0 {
		opts = append(opts, analyzer.WithCheckFilter(selectedChecks))
	}
	a := analyzer.NewAnalyzer(opts...)

	// Start a heartbeat ticker that refreshes the progress spinner every 500ms.
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
				pkgLabel := fmt.Sprintf("%s@%s", dep.Name, dep.DisplayVersion())

				mu.Lock()
				currentPkg = pkgLabel
				isScrapingOnly := a.IsScrapingOnly()
				mu.Unlock()

				result := a.Analyze(dep)
				if isScrapingOnly {
					result.DataMode = models.DataModeScrapingOnly
				}
				results[idx] = result

				mu.Lock()
				completed++
				completedFlags[idx] = true
				scrapingOnlyFlags[idx] = isScrapingOnly
				reporter.ShowProgress(completed, len(deps), pkgLabel)
				mu.Unlock()
			}
		}()
	}

	// Queue jobs, checking rate limit before each dispatch.
	// When the gate triggers, switch to scraping-only mode and continue
	// processing remaining packages instead of stopping.
	rateLimitTriggered := false
	for i := range deps {
		if !rateLimitTriggered && a.ShouldFallbackToScraping(rateLimitScrapingThreshold) {
			rateLimitTriggered = true
			remaining := a.RateLimitRemaining()

			// Switch to scraping-only mode — all subsequent API calls will be
			// skipped and only web scraping will be used for data collection.
			a.SetScrapingOnlyMode(true)

			reporter.ClearProgress()
			_, _ = fmt.Fprintf(statusOut, "\n⚠️  Rate limit approaching: %d GitHub API calls remaining (threshold: %d)\n", remaining, rateLimitScrapingThreshold)
			_, _ = fmt.Fprintf(statusOut, "   Switching to scraping-only mode for remaining %d packages (reduced data fidelity)\n", len(deps)-i)
		}
		jobs <- i
	}
	close(jobs)

	// Wait for all workers to finish
	wg.Wait()
	close(done)

	// Collect results and count scraping-only packages
	var completedResults []models.AnalysisResult
	scrapingOnlyCount := 0
	for i, flag := range completedFlags {
		if flag {
			completedResults = append(completedResults, results[i])
			if scrapingOnlyFlags[i] {
				scrapingOnlyCount++
			}
		}
	}

	duration := time.Since(startTime)
	reporter.ClearProgress()
	if rateLimitTriggered {
		_, _ = fmt.Fprintf(statusOut, "✅ Analysis complete in %s (%d full, %d scraping-only)\n\n",
			formatDuration(duration), len(completedResults)-scrapingOnlyCount, scrapingOnlyCount)
	} else {
		_, _ = fmt.Fprintf(statusOut, "✅ Analysis complete in %s\n\n", formatDuration(duration))
	}

	return analysisOutput{
		results:            completedResults,
		rateLimitFallback:  rateLimitTriggered,
		rateLimitRemaining: a.RateLimitRemaining(),
		scrapingOnlyCount:  scrapingOnlyCount,
	}
}

// formatDuration formats a duration for display
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func deduplicateDependencies(deps []models.Dependency) []models.Dependency {
	// Key on Ecosystem|Name so the same library at different versions is
	// collapsed to a single entry using the most recent version. This avoids
	// redundant scans when a project references the same package at multiple
	// pinned versions across different manifest files.
	seen := make(map[string]int) // key -> index in unique slice
	var unique []models.Dependency

	for _, dep := range deps {
		key := fmt.Sprintf("%s|%s", dep.Ecosystem, dep.Name)
		if idx, exists := seen[key]; exists {
			existing := unique[idx]

			cmp := compareVersions(dep.Version, existing.Version)
			if cmp > 0 {
				// New version is newer — replace, but preserve direct flag
				if !existing.IsTransitive {
					dep.IsTransitive = false
				}
				unique[idx] = dep
			} else if cmp == 0 && existing.IsTransitive && !dep.IsTransitive {
				// Same version — prefer direct over transitive
				unique[idx] = dep
			} else if cmp < 0 && !dep.IsTransitive {
				// Existing version is newer but new entry is direct — keep
				// the newer version but mark it as direct
				unique[idx].IsTransitive = false
			}
		} else {
			seen[key] = len(unique)
			unique = append(unique, dep)
		}
	}

	return unique
}

// compareVersions compares two version strings and returns:
//
//	 1 if a is newer than b
//	-1 if a is older than b
//	 0 if they are equal
//
// Handles semver, Maven versions, and arbitrary dotted version strings.
// Unknown/empty versions always lose to known versions.
func compareVersions(a, b string) int {
	aUnknown := a == "" || a == "unknown"
	bUnknown := b == "" || b == "unknown"
	if aUnknown && bUnknown {
		return 0
	}
	if aUnknown {
		return -1
	}
	if bUnknown {
		return 1
	}

	// Strip leading 'v' prefix (common in git tags: v1.2.3)
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var aVal, bVal int
		if i < len(aParts) {
			aVal = parseVersionPart(aParts[i])
		}
		if i < len(bParts) {
			bVal = parseVersionPart(bParts[i])
		}
		if aVal > bVal {
			return 1
		}
		if aVal < bVal {
			return -1
		}
	}

	// Numeric parts equal — fall back to lexicographic comparison
	// to handle pre-release suffixes (e.g. 1.0.0-alpha < 1.0.0-beta)
	if a > b {
		return 1
	}
	if a < b {
		return -1
	}
	return 0
}

// parseVersionPart extracts the leading integer from a version component.
// For example: "3" -> 3, "3-beta" -> 3, "rc1" -> 0.
func parseVersionPart(s string) int {
	var num int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			num = num*10 + int(c-'0')
		} else {
			break
		}
	}
	return num
}

// resolveMavenBOMVersions resolves "unknown" versions in Maven dependencies
// by fetching parent BOMs from Maven Central. Groups dependencies by their
// source pom.xml file and resolves each group using its parent POM chain.
func resolveMavenBOMVersions(deps []models.Dependency, statusOut *os.File, verbose bool) []models.Dependency {
	// Group Maven deps with unknown versions by source pom.xml
	pomFiles := make(map[string][]int) // source path -> dep indices
	for i, dep := range deps {
		if dep.Ecosystem == models.EcosystemMaven && dep.Version == "unknown" {
			pomFiles[dep.Source] = append(pomFiles[dep.Source], i)
		}
	}

	if len(pomFiles) == 0 {
		return deps
	}

	mavenClient := fetcher.NewMavenClient()

	for pomPath, indices := range pomFiles {
		parent, err := parser.ParsePomParent(pomPath)
		if err != nil {
			continue
		}

		var parentGroupID, parentArtifactID, parentVersion string
		if parent != nil {
			parentGroupID = parent.GroupID
			parentArtifactID = parent.ArtifactID
			parentVersion = parent.Version
		}

		// Extract locally-imported BOMs (scope=import, type=pom)
		localBOMs, _ := parser.ParsePomBOMImports(pomPath)
		var bomImports []fetcher.BOMImport
		for _, bom := range localBOMs {
			bomImports = append(bomImports, fetcher.BOMImport{
				GroupID:    bom.GroupID,
				ArtifactID: bom.ArtifactID,
				Version:    bom.Version,
			})
		}

		// Extract unresolved property references
		unresolvedRefs, _ := parser.ParsePomUnresolvedVersions(pomPath)

		// Skip if no resolution sources available
		if parent == nil && len(bomImports) == 0 && len(unresolvedRefs) == 0 {
			continue
		}

		if verbose && parent != nil {
			_, _ = fmt.Fprintf(statusOut, "  Resolving BOM versions from %s:%s:%s\n",
				parentGroupID, parentArtifactID, parentVersion)
		}
		if verbose && len(bomImports) > 0 {
			_, _ = fmt.Fprintf(statusOut, "  Resolving %d imported BOM(s) from %s\n",
				len(bomImports), pomPath)
		}

		// Collect the deps for this POM
		pomDeps := make([]models.Dependency, len(indices))
		for j, idx := range indices {
			pomDeps[j] = deps[idx]
		}

		// Resolve via parent BOM chain and imported BOMs
		resolved := mavenClient.ResolveBOMVersions(pomDeps, parentGroupID, parentArtifactID, parentVersion, bomImports, unresolvedRefs)

		// Update original deps
		for j, idx := range indices {
			deps[idx] = resolved[j]
		}
	}

	return deps
}
