package parser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

func parseRequirementsTxt(path string) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements.txt: %w", err)
	}
	defer func() { _ = file.Close() }()

	var deps []models.Dependency
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip -e and --editable installs
		if strings.HasPrefix(line, "-e") || strings.HasPrefix(line, "--editable") {
			continue
		}

		// Parse package==version or package>=version format
		name, version := parsePythonRequirement(line)
		if name != "" {
			deps = append(deps, models.Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: models.EcosystemPyPI,
				Source:    path,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading requirements.txt: %w", err)
	}

	return deps, nil
}

func parsePipfile(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pipfile: %w", err)
	}

	// Pipfile uses TOML format, but we'll do a simple parse for now
	// A full implementation would use a TOML library
	var deps []models.Dependency

	lines := strings.Split(string(data), "\n")
	inPackages := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[packages]" {
			inPackages = true
			continue
		}

		if strings.HasPrefix(line, "[") {
			inPackages = false
			continue
		}

		if inPackages && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
				deps = append(deps, models.Dependency{
					Name:      name,
					Version:   cleanVersion(version),
					Ecosystem: models.EcosystemPyPI,
					Source:    path,
				})
			}
		}
	}

	return deps, nil
}

func parsePyprojectToml(path string) ([]models.Dependency, error) {
	// pyproject.toml parsing would require a TOML library
	// For now, we'll do a simple line-based parse
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read pyproject.toml: %w", err)
	}

	var deps []models.Dependency
	lines := strings.Split(string(data), "\n")
	inDeps := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "[tool.poetry.dependencies]") || strings.Contains(line, "[project.dependencies]") {
			inDeps = true
			continue
		}

		if strings.HasPrefix(line, "[") {
			inDeps = false
			continue
		}

		if inDeps && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				// Skip python version constraint
				if name == "python" {
					continue
				}
				version := strings.Trim(strings.TrimSpace(parts[1]), "\"'^~")
				deps = append(deps, models.Dependency{
					Name:      name,
					Version:   cleanVersion(version),
					Ecosystem: models.EcosystemPyPI,
					Source:    path,
				})
			}
		}
	}

	return deps, nil
}

func parsePythonRequirement(req string) (string, string) {
	// Handle different requirement formats:
	// package==1.0.0
	// package>=1.0.0
	// package~=1.0.0
	// package[extra]==1.0.0

	// Remove extras like [extra]
	if idx := strings.Index(req, "["); idx != -1 {
		if endIdx := strings.Index(req, "]"); endIdx != -1 {
			req = req[:idx] + req[endIdx+1:]
		}
	}

	operators := []string{"==", ">=", "<=", "~=", ">", "<", "!="}

	for _, op := range operators {
		if strings.Contains(req, op) {
			parts := strings.SplitN(req, op, 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.TrimSpace(parts[1])
				// Remove any trailing comments
				if idx := strings.Index(version, "#"); idx != -1 {
					version = strings.TrimSpace(version[:idx])
				}
				return name, version
			}
		}
	}

	// No version specified
	return strings.TrimSpace(req), "latest"
}

func parsePoetryLock(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read poetry.lock: %w", err)
	}

	var deps []models.Dependency
	lines := strings.Split(string(data), "\n")

	var currentName, currentVersion string
	inPackage := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect start of a new [[package]] block
		if trimmed == "[[package]]" {
			// Save previous package if we had one
			if inPackage && currentName != "" {
				deps = append(deps, models.Dependency{
					Name:      currentName,
					Version:   currentVersion,
					Ecosystem: models.EcosystemPyPI,
					Source:    path,
				})
			}
			currentName = ""
			currentVersion = ""
			inPackage = true
			continue
		}

		// Stop parsing packages when we hit [metadata]
		if trimmed == "[metadata]" {
			if inPackage && currentName != "" {
				deps = append(deps, models.Dependency{
					Name:      currentName,
					Version:   currentVersion,
					Ecosystem: models.EcosystemPyPI,
					Source:    path,
				})
			}
			inPackage = false
			break
		}

		if !inPackage {
			continue
		}

		// Parse name and version fields within a [[package]] block
		if strings.HasPrefix(trimmed, "name = ") {
			currentName = strings.Trim(strings.TrimPrefix(trimmed, "name = "), "\"")
		} else if strings.HasPrefix(trimmed, "version = ") {
			currentVersion = strings.Trim(strings.TrimPrefix(trimmed, "version = "), "\"")
		}
	}

	// Handle last package if file doesn't end with [metadata]
	if inPackage && currentName != "" {
		deps = append(deps, models.Dependency{
			Name:      currentName,
			Version:   currentVersion,
			Ecosystem: models.EcosystemPyPI,
			Source:    path,
		})
	}

	return deps, nil
}

func countPoetryLockDependencies(lockfilePath string) (*models.DependencyMetrics, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read poetry.lock: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	totalPackages := 0
	mainPackages := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "[[package]]" {
			totalPackages++
			continue
		}

		if strings.HasPrefix(trimmed, "category = ") {
			category := strings.Trim(strings.TrimPrefix(trimmed, "category = "), "\"")
			if category == "main" {
				mainPackages++
			}
		}
	}

	// Try to read pyproject.toml to get direct dependency count
	directCount := 0
	pyprojectPath := strings.Replace(lockfilePath, "poetry.lock", "pyproject.toml", 1)
	if pyprojectData, err := os.ReadFile(pyprojectPath); err == nil {
		pyLines := strings.Split(string(pyprojectData), "\n")
		inDeps := false
		for _, line := range pyLines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "[tool.poetry.dependencies]") || strings.Contains(line, "[project.dependencies]") {
				inDeps = true
				continue
			}
			if strings.HasPrefix(line, "[") {
				inDeps = false
				continue
			}
			if inDeps && strings.Contains(line, "=") {
				name := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
				if name != "python" {
					directCount++
				}
			}
		}
	}

	metrics := &models.DependencyMetrics{
		TransitiveCount: totalPackages,
		DirectCount:     directCount,
		MaxDepth:        0,
		Verified:        true,
	}

	return metrics, nil
}

// Pipfile lock structure (simplified)
type PipfileLock struct {
	Default map[string]PipfileLockPackage `json:"default"`
	Develop map[string]PipfileLockPackage `json:"develop"`
}

type PipfileLockPackage struct {
	Version string `json:"version"`
}

// parsePipfileLock parses a Pipfile.lock and returns individual dependencies,
// tagging each as direct or transitive by cross-referencing the companion Pipfile.
func parsePipfileLock(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pipfile.lock: %w", err)
	}

	var lockfile PipfileLock
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse Pipfile.lock: %w", err)
	}

	// Try to read companion Pipfile to determine which deps are direct
	directDeps := make(map[string]bool)
	hasPipfile := false
	pipfilePath := filepath.Join(filepath.Dir(path), "Pipfile")
	if pipfileData, readErr := os.ReadFile(pipfilePath); readErr == nil {
		hasPipfile = true
		lines := strings.Split(string(pipfileData), "\n")
		inPackages := false
		inDevPackages := false

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "[packages]" {
				inPackages = true
				inDevPackages = false
				continue
			}
			if line == "[dev-packages]" {
				inDevPackages = true
				inPackages = false
				continue
			}
			if strings.HasPrefix(line, "[") {
				inPackages = false
				inDevPackages = false
				continue
			}
			if (inPackages || inDevPackages) && strings.Contains(line, "=") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					name := strings.TrimSpace(parts[0])
					// Python package names are case-insensitive; normalize to lowercase
					directDeps[strings.ToLower(name)] = true
				}
			}
		}
	}

	var deps []models.Dependency

	// Process default (production) dependencies
	for name, pkg := range lockfile.Default {
		version := strings.TrimPrefix(pkg.Version, "==")
		isTransitive := false
		if hasPipfile {
			// Case-insensitive match against Pipfile direct deps
			if !directDeps[strings.ToLower(name)] {
				isTransitive = true
			}
		}
		deps = append(deps, models.Dependency{
			Name:         name,
			Version:      version,
			Ecosystem:    models.EcosystemPyPI,
			Source:       path,
			IsTransitive: isTransitive,
		})
	}

	// Process develop dependencies
	for name, pkg := range lockfile.Develop {
		version := strings.TrimPrefix(pkg.Version, "==")
		isTransitive := false
		if hasPipfile {
			if !directDeps[strings.ToLower(name)] {
				isTransitive = true
			}
		}
		deps = append(deps, models.Dependency{
			Name:         name,
			Version:      version,
			Ecosystem:    models.EcosystemPyPI,
			Source:       path,
			IsTransitive: isTransitive,
		})
	}

	return deps, nil
}

// CountPythonDependencies analyzes Python dependency files and counts dependencies
func CountPythonDependencies(manifestPath string) (*models.DependencyMetrics, error) {
	filename := filepath.Base(strings.ToLower(manifestPath))

	// For Pipfile.lock (most accurate)
	if filename == "pipfile.lock" {
		return countPipfileLockDependencies(manifestPath)
	}

	// For poetry.lock (accurate - full lock file)
	if filename == "poetry.lock" {
		return countPoetryLockDependencies(manifestPath)
	}

	// For requirements.txt (less accurate - may be all transitives from pip freeze)
	// Match both "requirements.txt" and patterns like "requirements-small.txt"
	if strings.HasPrefix(filename, "requirements") && strings.HasSuffix(filename, ".txt") {
		return countRequirementsTxtDependencies(manifestPath)
	}

	return nil, fmt.Errorf("unsupported Python manifest for dependency counting: %s", manifestPath)
}

func countPipfileLockDependencies(lockfilePath string) (*models.DependencyMetrics, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pipfile.lock: %w", err)
	}

	var lockfile PipfileLock
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse Pipfile.lock: %w", err)
	}

	metrics := &models.DependencyMetrics{
		TransitiveCount: len(lockfile.Default) + len(lockfile.Develop),
		DirectCount:     0, // Need to check Pipfile to know direct deps
		MaxDepth:        0,
		Verified:        true,
	}

	// Try to read Pipfile to get direct dependency count
	pipfilePath := strings.Replace(lockfilePath, "Pipfile.lock", "Pipfile", 1)
	if pipfileData, err := os.ReadFile(pipfilePath); err == nil {
		directCount := 0
		lines := strings.Split(string(pipfileData), "\n")
		inPackages := false

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "[packages]" {
				inPackages = true
				continue
			}
			if strings.HasPrefix(line, "[") {
				inPackages = false
			}
			if inPackages && strings.Contains(line, "=") {
				directCount++
			}
		}
		metrics.DirectCount = directCount
	}

	return metrics, nil
}

func countRequirementsTxtDependencies(requirementsPath string) (*models.DependencyMetrics, error) {
	file, err := os.Open(requirementsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements.txt: %w", err)
	}
	defer func() { _ = file.Close() }()

	count := 0
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip -e and --editable installs
		if strings.HasPrefix(line, "-e") || strings.HasPrefix(line, "--editable") {
			continue
		}

		// Skip -r and --requirement includes
		if strings.HasPrefix(line, "-r") || strings.HasPrefix(line, "--requirement") {
			continue
		}

		count++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading requirements.txt: %w", err)
	}

	// Note: requirements.txt often contains pip freeze output with all transitives
	// We mark as unverified since we can't distinguish direct from transitive
	metrics := &models.DependencyMetrics{
		TransitiveCount: count,
		DirectCount:     0, // Unknown without separate requirements file
		MaxDepth:        0,
		Verified:        false, // Can't reliably distinguish direct vs transitive
	}

	return metrics, nil
}
