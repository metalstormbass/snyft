package parser

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

func parseRequirementsTxt(path string) ([]models.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements.txt: %w", err)
	}
	defer file.Close()

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

// Pipfile lock structure (simplified)
type PipfileLock struct {
	Default map[string]PipfileLockPackage `yaml:"default"`
	Develop map[string]PipfileLockPackage `yaml:"develop"`
}

type PipfileLockPackage struct {
	Version string `yaml:"version"`
}
