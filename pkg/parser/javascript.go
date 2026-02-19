package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// PackageJSON represents the structure of package.json
type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// PackageLockJSON represents the structure of package-lock.json
type PackageLockJSON struct {
	Name         string                               `json:"name"`
	Version      string                               `json:"version"`
	Packages     map[string]PackageLockPackage        `json:"packages"`
	Dependencies map[string]PackageLockDependencyV1   `json:"dependencies"` // For older lockfile versions
}

type PackageLockPackage struct {
	Version      string            `json:"version"`
	Dev          bool              `json:"dev"`
	Dependencies map[string]string `json:"dependencies"`
}

// PackageLockDependencyV1 represents dependencies in older lockfile formats (v1-v6)
type PackageLockDependencyV1 struct {
	Version      string                             `json:"version"`
	Dependencies map[string]PackageLockDependencyV1 `json:"dependencies"`
}

func parsePackageJSON(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	var deps []models.Dependency

	// Parse regular dependencies
	for name, version := range pkg.Dependencies {
		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: models.EcosystemNPM,
			Source:    path,
		})
	}

	// Parse dev dependencies
	for name, version := range pkg.DevDependencies {
		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: models.EcosystemNPM,
			Source:    path,
		})
	}

	return deps, nil
}

func parsePackageLockJSON(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read package-lock.json: %w", err)
	}

	var lockfile PackageLockJSON
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	// Build set of direct dependency names from root package
	directDeps := make(map[string]bool)
	if rootPkg, hasRoot := lockfile.Packages[""]; hasRoot {
		for depName := range rootPkg.Dependencies {
			directDeps[depName] = true
		}
	}

	var deps []models.Dependency

	for pkgPath, pkg := range lockfile.Packages {
		// Skip root package
		if pkgPath == "" {
			continue
		}

		// Extract package name from path (e.g., "node_modules/express" -> "express")
		name := strings.TrimPrefix(pkgPath, "node_modules/")

		// Determine if this is a transitive dependency:
		// 1. Nested node_modules paths (e.g., "node_modules/foo/node_modules/bar") are always transitive
		// 2. Top-level packages not in root's dependencies are transitive
		isTransitive := true
		if !strings.Contains(name, "/node_modules/") && directDeps[name] {
			isTransitive = false
		}

		deps = append(deps, models.Dependency{
			Name:         name,
			Version:      pkg.Version,
			Ecosystem:    models.EcosystemNPM,
			Source:       path,
			IsTransitive: isTransitive,
		})
	}

	return deps, nil
}

func parseYarnLock(path string) ([]models.Dependency, error) {
	// Yarn lock files are complex and would require a dedicated parser
	// For now, return empty slice - this can be enhanced later
	return []models.Dependency{}, nil
}

// CountTransitiveDependencies analyzes package-lock.json and counts transitive dependencies
func CountTransitiveDependencies(lockfilePath string) (*models.DependencyMetrics, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package-lock.json: %w", err)
	}

	var lockfile PackageLockJSON
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	metrics := &models.DependencyMetrics{
		TransitiveCount: 0,
		DirectCount:     0,
		MaxDepth:        0,
		Verified:        true,
	}

	// Count packages (npm v7+ format with "packages" field)
	if len(lockfile.Packages) > 0 {
		directDeps := make(map[string]bool)

		// Get direct dependencies from root package
		if rootPkg, hasRoot := lockfile.Packages[""]; hasRoot {
			for depName := range rootPkg.Dependencies {
				directDeps[depName] = true
			}
		}

		// Count all packages excluding root
		for pkgPath := range lockfile.Packages {
			if pkgPath == "" {
				continue
			}

			metrics.TransitiveCount++

			// Extract package name from path
			name := strings.TrimPrefix(pkgPath, "node_modules/")
			// Handle nested node_modules (e.g., "node_modules/foo/node_modules/bar")
			parts := strings.Split(name, "/node_modules/")
			actualName := parts[len(parts)-1]

			if directDeps[actualName] {
				metrics.DirectCount++
			}
		}
	} else if len(lockfile.Dependencies) > 0 {
		// Handle older npm lockfile format (v1-v6) with nested dependencies
		metrics.DirectCount = len(lockfile.Dependencies)
		visited := make(map[string]bool)

		// Recursively count all dependencies
		var countDeps func(deps map[string]PackageLockDependencyV1, depth int)
		countDeps = func(deps map[string]PackageLockDependencyV1, depth int) {
			if depth > metrics.MaxDepth {
				metrics.MaxDepth = depth
			}

			for name, pkg := range deps {
				key := name + "@" + pkg.Version
				if visited[key] {
					continue
				}
				visited[key] = true

				if len(pkg.Dependencies) > 0 {
					countDeps(pkg.Dependencies, depth+1)
				}
			}
		}

		countDeps(lockfile.Dependencies, 1)
		metrics.TransitiveCount = len(visited)
	}

	return metrics, nil
}

// cleanVersion removes common version prefixes like ^, ~, >=, etc.
func cleanVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<")
	version = strings.TrimPrefix(version, "=")
	return version
}
