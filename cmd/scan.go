package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/metalstormbass/snyft/pkg/analyzer"
	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/metalstormbass/snyft/pkg/parser"
	"github.com/spf13/cobra"
)

var (
	scanPath    string
	workers     int
	outputFile  string
	verbose     bool
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
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
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

	fmt.Printf("🔍 Scanning directory: %s\n", scanPath)

	// Parse manifest files
	dependencies, err := parseManifests(scanPath)
	if err != nil {
		return fmt.Errorf("failed to parse manifests: %w", err)
	}

	if len(dependencies) == 0 {
		fmt.Println("⚠️  No dependencies found")
		return nil
	}

	fmt.Printf("📦 Found %d dependencies across all manifests\n", len(dependencies))

	// Analyze dependencies in parallel
	results := analyzeDependencies(dependencies, workers)

	// Output results
	return outputResults(results)
}

func parseManifests(dir string) ([]models.Dependency, error) {
	var allDeps []models.Dependency
	var mu sync.Mutex

	// Find all manifest files
	manifestFiles, err := findManifestFiles(dir)
	if err != nil {
		return nil, err
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

	return deduplicateDependencies(allDeps), nil
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

func analyzeDependencies(deps []models.Dependency, numWorkers int) []models.AnalysisResult {
	results := make([]models.AnalysisResult, len(deps))
	jobs := make(chan int, len(deps))
	var wg sync.WaitGroup

	// Create analyzer
	a := analyzer.NewAnalyzer()

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				dep := deps[idx]
				if verbose {
					fmt.Printf("🔬 Analyzing: %s@%s (%s)\n", dep.Name, dep.Version, dep.Ecosystem)
				}
				results[idx] = a.Analyze(dep)
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

	return results
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

func outputResults(results []models.AnalysisResult) error {
	fmt.Println("\n" + "================================================================================")
	fmt.Println("📊 Supply Chain Security Analysis Results")
	fmt.Println("================================================================================")
	fmt.Println()

	// Group by risk level
	high := 0
	medium := 0
	low := 0

	for _, result := range results {
		switch result.RiskLevel {
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}

	fmt.Printf("Risk Summary:\n")
	fmt.Printf("  🔴 HIGH:   %d\n", high)
	fmt.Printf("  🟡 MEDIUM: %d\n", medium)
	fmt.Printf("  🟢 LOW:    %d\n", low)
	fmt.Println()

	// Print detailed results
	for _, result := range results {
		printResult(result)
	}

	return nil
}

func printResult(result models.AnalysisResult) {
	icon := "🟢"
	switch result.RiskLevel {
	case "HIGH":
		icon = "🔴"
	case "MEDIUM":
		icon = "🟡"
	}

	fmt.Printf("%s %s@%s (%s) - %s\n", icon, result.Dependency.Name, result.Dependency.Version, result.Dependency.Ecosystem, result.RiskLevel)

	// Show supply chain score (always display for context)
	if result.SupplyChainScore != nil {
		fmt.Printf("   Supply Chain Score: %d/14 points (%s risk)\n",
			result.SupplyChainScore.TotalScore, result.SupplyChainScore.RiskLevel)
	}

	if verbose {
		fmt.Printf("   Repository: %s\n", result.RepositoryURL)
		fmt.Printf("   Source Available: %v\n", result.SourceCodeAvailable)
		fmt.Printf("   Build Infrastructure: %s\n", result.BuildInfrastructure)
		fmt.Printf("   Risk Score: %d/100\n", result.RiskScore)

		// Display detailed supply chain scoring breakdown
		if result.SupplyChainScore != nil {
			fmt.Printf("\n   Supply Chain Security Rubric (0-14 points):\n")
			cs := result.SupplyChainScore.CategoryScores

			printCategoryScore("Publisher Control", cs.PublisherControl)
			printCategoryScore("Ownership Changes", cs.OwnershipChanges)
			printCategoryScore("Release Anomalies", cs.ReleaseAnomalies)
			printCategoryScore("Install Execution", cs.InstallExecution)
			printCategoryScore("Dependency Sprawl", cs.DependencySprawl)
			printCategoryScore("Provenance", cs.Provenance)
			printCategoryScore("Health", cs.Health)
			fmt.Println()
		}

		// Show all security checks performed
		fmt.Printf("   Security Checks Performed:\n")
		checks := getSecurityChecks(result)
		for _, check := range checks {
			fmt.Printf("      %s %s\n", check.Icon, check.Description)
		}

		if len(result.Findings) > 0 {
			fmt.Printf("   Risk Findings:\n")
			for _, finding := range result.Findings {
				fmt.Printf("      [%s] %s\n", finding.Severity, finding.Category)
				fmt.Printf("          Description: %s\n", finding.Description)
				fmt.Printf("          Detected By: %s\n", finding.Check)
				if finding.Evidence != "" {
					fmt.Printf("          Evidence: %s\n", finding.Evidence)
				}
			}
		}
		fmt.Println()
	}
}

// SecurityCheck represents a security check and its result
type SecurityCheck struct {
	Name        string
	Icon        string
	Description string
}

// getSecurityChecks returns all security checks performed on the dependency
func getSecurityChecks(result models.AnalysisResult) []SecurityCheck {
	checks := []SecurityCheck{}

	// Track which checks found issues
	failedChecks := make(map[string]bool)
	for _, finding := range result.Findings {
		failedChecks[finding.Check] = true
	}

	// Package Registry Validation
	checks = append(checks, SecurityCheck{
		Name:        "Package Registry Validation",
		Icon:        getCheckIcon("Package Registry Validation", failedChecks),
		Description: "Package Registry Validation - verifies package exists in registry",
	})

	// Repository Availability Check
	if result.RepositoryURL != "" {
		checks = append(checks, SecurityCheck{
			Name:        "Repository Availability Check",
			Icon:        getCheckIcon("Repository Availability Check", failedChecks),
			Description: "Repository Availability Check - verifies public source code exists",
		})

		// Repository Metadata Check (only if we have a repo)
		checks = append(checks, SecurityCheck{
			Name:        "Repository Metadata Check",
			Icon:        getCheckIcon("Repository Metadata Check", failedChecks),
			Description: "Repository Metadata Check - analyzes repository statistics",
		})

		// Repository Status Check
		checks = append(checks, SecurityCheck{
			Name:        "Repository Status Check",
			Icon:        getCheckIcon("Repository Status Check", failedChecks),
			Description: "Repository Status Check - checks if repository is archived",
		})

		// Repository Activity Check
		checks = append(checks, SecurityCheck{
			Name:        "Repository Activity Check",
			Icon:        getCheckIcon("Repository Activity Check", failedChecks),
			Description: "Repository Activity Check - verifies recent development activity",
		})

		// Community Engagement Check
		checks = append(checks, SecurityCheck{
			Name:        "Community Engagement Check",
			Icon:        getCheckIcon("Community Engagement Check", failedChecks),
			Description: "Community Engagement Check - evaluates stars, forks, and community adoption",
		})

		// CI/CD Detection Check
		checks = append(checks, SecurityCheck{
			Name:        "CI/CD Detection Check",
			Icon:        getCheckIcon("CI/CD Detection Check", failedChecks),
			Description: "CI/CD Detection Check - detects automated build systems",
		})

		// Release Automation Check
		checks = append(checks, SecurityCheck{
			Name:        "Release Automation Check",
			Icon:        getCheckIcon("Release Automation Check", failedChecks),
			Description: "Release Automation Check - identifies automated release processes",
		})

		// OSSF Scorecard Check
		if result.Metadata.OSSFScore > 0 {
			checks = append(checks, SecurityCheck{
				Name:        "OSSF Scorecard Check",
				Icon:        getCheckIcon("OSSF Scorecard Check", failedChecks),
				Description: fmt.Sprintf("OSSF Scorecard Check - OpenSSF security score: %.1f/10", result.Metadata.OSSFScore),
			})
		}
	}

	return checks
}

// getCheckIcon returns the appropriate icon for a security check
func getCheckIcon(checkName string, failedChecks map[string]bool) string {
	if failedChecks[checkName] {
		return "❌"
	}
	return "✅"
}

// printCategoryScore prints a supply chain category score
func printCategoryScore(name string, score models.CategoryScore) {
	verifiedIcon := "✅"
	if !score.Verified {
		verifiedIcon = "⚠️"
	}

	riskIcon := "🟢"
	switch score.RiskPoints {
	case 2:
		riskIcon = "🔴"
	case 1:
		riskIcon = "🟡"
	}

	fmt.Printf("      %s %s %s: %d points | %s\n",
		verifiedIcon, riskIcon, name, score.RiskPoints, score.Description)
	if score.Evidence != "" {
		fmt.Printf("         Evidence: %s\n", score.Evidence)
	}
}
