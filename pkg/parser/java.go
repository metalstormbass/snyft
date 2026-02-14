package parser

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// PomXML represents a simplified Maven POM structure
type PomXML struct {
	XMLName      xml.Name          `xml:"project"`
	Dependencies []MavenDependency `xml:"dependencies>dependency"`
}

type MavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

func parsePomXML(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read pom.xml: %w", err)
	}

	var pom PomXML
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
	}

	var deps []models.Dependency

	for _, dep := range pom.Dependencies {
		// Skip test dependencies
		if dep.Scope == "test" {
			continue
		}

		name := dep.GroupID + ":" + dep.ArtifactID
		version := dep.Version

		// Skip if version is a property reference (e.g., ${spring.version})
		if strings.HasPrefix(version, "${") {
			version = "unknown"
		}

		deps = append(deps, models.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemMaven,
			Source:    path,
		})
	}

	return deps, nil
}

func parseBuildGradle(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read build.gradle: %w", err)
	}

	content := string(data)
	var deps []models.Dependency

	// Regular expression patterns for Gradle dependencies
	// Matches: implementation 'group:artifact:version'
	// Matches: implementation "group:artifact:version"
	// Matches: compile 'group:artifact:version'
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:implementation|api|compile|runtimeOnly|compileOnly)\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]`),
		regexp.MustCompile(`(?:implementation|api|compile|runtimeOnly|compileOnly)\s*\(\s*['"]([^:'"]+):([^:'"]+):([^'"]+)['"]\s*\)`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 4 {
				groupID := match[1]
				artifactID := match[2]
				version := match[3]

				name := groupID + ":" + artifactID

				deps = append(deps, models.Dependency{
					Name:      name,
					Version:   version,
					Ecosystem: models.EcosystemMaven,
					Source:    path,
				})
			}
		}
	}

	return deps, nil
}
