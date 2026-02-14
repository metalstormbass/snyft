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
	Name     string                        `json:"name"`
	Version  string                        `json:"version"`
	Packages map[string]PackageLockPackage `json:"packages"`
}

type PackageLockPackage struct {
	Version string `json:"version"`
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

	var deps []models.Dependency

	for pkgPath, pkg := range lockfile.Packages {
		// Skip root package
		if pkgPath == "" {
			continue
		}

		// Extract package name from path (e.g., "node_modules/express" -> "express")
		name := strings.TrimPrefix(pkgPath, "node_modules/")

		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: models.EcosystemNPM,
			Source:    path,
		})
	}

	return deps, nil
}

func parseYarnLock(path string) ([]models.Dependency, error) {
	// Yarn lock files are complex and would require a dedicated parser
	// For now, return empty slice - this can be enhanced later
	return []models.Dependency{}, nil
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
