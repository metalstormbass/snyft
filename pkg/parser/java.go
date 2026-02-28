package parser

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// PomXML represents a Maven POM structure with full version resolution support.
// Includes parent references, properties, and dependencyManagement sections
// needed to resolve versions that aren't explicitly declared on dependencies.
type PomXML struct {
	XMLName              xml.Name                `xml:"project"`
	GroupID              string                  `xml:"groupId"`
	ArtifactID           string                  `xml:"artifactId"`
	Version              string                  `xml:"version"`
	Parent               PomParent               `xml:"parent"`
	Properties           PomProperties           `xml:"properties"`
	DependencyManagement PomDependencyManagement `xml:"dependencyManagement"`
	Dependencies         []MavenDependency       `xml:"dependencies>dependency"`
}

// PomParent represents a <parent> declaration in a pom.xml
type PomParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// PomProperties represents the <properties> section of a pom.xml.
// Uses a custom XML unmarshaler since property names are dynamic element names.
type PomProperties struct {
	Entries map[string]string
}

// UnmarshalXML implements custom XML unmarshaling for dynamic property elements.
// Maven properties are arbitrary key-value pairs where the element name is the key.
func (p *PomProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Entries = make(map[string]string)
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &t); err != nil {
				return err
			}
			p.Entries[t.Name.Local] = value
		case xml.EndElement:
			return nil
		}
	}
}

// PomDependencyManagement represents the <dependencyManagement> section
type PomDependencyManagement struct {
	Dependencies []MavenDependency `xml:"dependencies>dependency"`
}

type MavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// propertyRefRegex matches Maven property references like ${spring.version}
var propertyRefRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

func parsePomXML(path string) ([]models.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read pom.xml: %w", err)
	}

	var pom PomXML
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
	}

	// Build property map with built-in Maven properties and user-defined properties
	props := buildPropertyMap(&pom)

	// Build dependencyManagement lookup for BOM-managed versions
	depMgmt := buildDepMgmtMap(&pom, props)

	var deps []models.Dependency

	for _, dep := range pom.Dependencies {
		// Skip test dependencies
		if dep.Scope == "test" {
			continue
		}

		name := dep.GroupID + ":" + dep.ArtifactID
		version := dep.Version

		// Resolve property references (e.g., ${spring.version}, ${project.version})
		if strings.Contains(version, "${") {
			version = resolveAllProperties(version, props)
			// If still contains unresolved references, mark as unknown
			if strings.Contains(version, "${") {
				version = "unknown"
			}
		}

		// BOM-managed: look up from local dependencyManagement
		if version == "" {
			if managedVersion, ok := depMgmt[name]; ok && managedVersion != "" {
				version = managedVersion
			} else {
				version = "unknown"
			}
		}

		// Handle version ranges (e.g., [1.0,2.0))
		if isVersionRange(version) {
			version = resolveVersionRange(version)
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

// buildPropertyMap creates a map of all available properties for resolution.
// Includes built-in Maven properties (project.version, project.groupId, etc.)
// and user-defined properties from the <properties> section.
// Iteratively resolves property references within property values.
func buildPropertyMap(pom *PomXML) map[string]string {
	props := make(map[string]string)

	// Copy explicitly declared properties
	if pom.Properties.Entries != nil {
		for k, v := range pom.Properties.Entries {
			props[k] = v
		}
	}

	// Built-in Maven properties
	projectVersion := pom.Version
	if projectVersion == "" && pom.Parent.Version != "" {
		projectVersion = pom.Parent.Version
	}
	if projectVersion != "" {
		props["project.version"] = projectVersion
		props["pom.version"] = projectVersion // deprecated alias
		props["version"] = projectVersion     // short alias
	}

	projectGroupID := pom.GroupID
	if projectGroupID == "" && pom.Parent.GroupID != "" {
		projectGroupID = pom.Parent.GroupID
	}
	if projectGroupID != "" {
		props["project.groupId"] = projectGroupID
	}

	if pom.ArtifactID != "" {
		props["project.artifactId"] = pom.ArtifactID
	}

	if pom.Parent.Version != "" {
		props["project.parent.version"] = pom.Parent.Version
	}
	if pom.Parent.GroupID != "" {
		props["project.parent.groupId"] = pom.Parent.GroupID
	}
	if pom.Parent.ArtifactID != "" {
		props["project.parent.artifactId"] = pom.Parent.ArtifactID
	}

	// Iteratively resolve property references within property values
	// (e.g., <my.version>${spring.version}</my.version>)
	for i := 0; i < 5; i++ {
		changed := false
		for k, v := range props {
			if strings.Contains(v, "${") {
				resolved := resolveAllProperties(v, props)
				if resolved != v {
					props[k] = resolved
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	return props
}

// buildDepMgmtMap creates a lookup map from groupId:artifactId to version
// from the local <dependencyManagement> section. Property references in
// versions are resolved using the provided properties map.
func buildDepMgmtMap(pom *PomXML, props map[string]string) map[string]string {
	mgmt := make(map[string]string)
	for _, dep := range pom.DependencyManagement.Dependencies {
		key := dep.GroupID + ":" + dep.ArtifactID
		version := dep.Version

		// Resolve property references in dependencyManagement versions
		if strings.Contains(version, "${") {
			version = resolveAllProperties(version, props)
			if strings.Contains(version, "${") {
				continue // skip unresolvable
			}
		}

		mgmt[key] = version
	}
	return mgmt
}

// resolveAllProperties replaces all ${property.name} references in a string
// with their values from the properties map. Handles both full property
// references (${version}) and embedded ones (${version}-SNAPSHOT).
func resolveAllProperties(value string, props map[string]string) string {
	return propertyRefRegex.ReplaceAllStringFunc(value, func(match string) string {
		propName := match[2 : len(match)-1]
		if resolved, ok := props[propName]; ok {
			return resolved
		}
		return match // keep unresolved reference as-is
	})
}

// isVersionRange checks if a version string is a Maven version range
// (e.g., [1.0,2.0), (,1.0], [1.0])
func isVersionRange(version string) bool {
	if len(version) < 3 {
		return false
	}
	return (version[0] == '[' || version[0] == '(') &&
		(version[len(version)-1] == ']' || version[len(version)-1] == ')')
}

// resolveVersionRange extracts a usable version from a Maven version range.
// For exact ranges [1.0] returns 1.0. For ranges with bounds, returns the
// most specific bound available.
func resolveVersionRange(version string) string {
	inner := version[1 : len(version)-1]

	// Exact version: [1.0] → 1.0
	if !strings.Contains(inner, ",") {
		v := strings.TrimSpace(inner)
		if v != "" {
			return v
		}
		return "unknown"
	}

	// Range: [1.0,2.0) → prefer lower bound (minimum guaranteed version)
	parts := strings.SplitN(inner, ",", 2)
	lower := strings.TrimSpace(parts[0])
	upper := strings.TrimSpace(parts[1])

	// Prefer lower bound if available (it's the minimum version)
	if lower != "" {
		return lower
	}
	// Fall back to upper bound for ranges like (,2.0]
	if upper != "" {
		return upper
	}

	return "unknown"
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

// CountMavenDependencies analyzes pom.xml and counts dependencies
// Note: This only counts direct dependencies from pom.xml
// For accurate transitive counts, Maven dependency:tree output would be needed
func CountMavenDependencies(pomPath string) (*models.DependencyMetrics, error) {
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pom.xml: %w", err)
	}

	var pom PomXML
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
	}

	// Count non-test dependencies
	directCount := 0
	for _, dep := range pom.Dependencies {
		if dep.Scope != "test" {
			directCount++
		}
	}

	metrics := &models.DependencyMetrics{
		TransitiveCount: directCount, // We only see direct deps in pom.xml
		DirectCount:     directCount,
		MaxDepth:        1,
		Verified:        false, // pom.xml only shows direct deps, not transitives
	}

	return metrics, nil
}

// PomParentRef represents a parent POM reference for external BOM resolution.
// Exported so callers can pass parent info to MavenClient.ResolveBOMVersions.
type PomParentRef struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// ParsePomParent extracts the parent POM reference from a pom.xml file.
// Returns nil if the POM has no parent declaration.
func ParsePomParent(path string) (*PomParentRef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read pom.xml: %w", err)
	}

	var pom PomXML
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
	}

	if pom.Parent.GroupID == "" || pom.Parent.ArtifactID == "" || pom.Parent.Version == "" {
		return nil, nil
	}

	return &PomParentRef{
		GroupID:    pom.Parent.GroupID,
		ArtifactID: pom.Parent.ArtifactID,
		Version:    pom.Parent.Version,
	}, nil
}
