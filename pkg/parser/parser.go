package parser

import (
	"fmt"
	"path/filepath"

	"github.com/metalstormbass/snyft/pkg/models"
)

// IsManifestFile checks if a filename is a recognized manifest file
func IsManifestFile(filename string) bool {
	manifestFiles := []string{
		// JavaScript/Node.js
		"package.json",
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",

		// Python
		"requirements.txt",
		"Pipfile",
		"Pipfile.lock",
		"pyproject.toml",
		"poetry.lock",
		"setup.py",

		// Java/Maven
		"pom.xml",
		"build.gradle",
		"build.gradle.kts",
		"gradle.properties",
	}

	for _, mf := range manifestFiles {
		if filename == mf {
			return true
		}
	}
	return false
}

// ParseManifest parses a manifest file and returns the dependencies
func ParseManifest(path string) ([]models.Dependency, error) {
	filename := filepath.Base(path)

	switch filename {
	// JavaScript/Node.js
	case "package.json":
		return parsePackageJSON(path)
	case "package-lock.json":
		return parsePackageLockJSON(path)
	case "yarn.lock":
		return parseYarnLock(path)

	// Python
	case "requirements.txt":
		return parseRequirementsTxt(path)
	case "Pipfile":
		return parsePipfile(path)
	case "Pipfile.lock":
		return parsePipfileLock(path)
	case "pyproject.toml":
		return parsePyprojectToml(path)
	case "poetry.lock":
		return parsePoetryLock(path)

	// Java
	case "pom.xml":
		return parsePomXML(path)
	case "build.gradle", "build.gradle.kts":
		return parseBuildGradle(path)

	default:
		return nil, fmt.Errorf("unsupported manifest file: %s", filename)
	}
}
