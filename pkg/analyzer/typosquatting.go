package analyzer

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// TyposquatResult represents a potential typosquatting match
type TyposquatResult struct {
	OriginalName  string // The package being analyzed
	SimilarTo     string // The popular package it resembles
	Confidence    string // HIGH, MEDIUM
	Technique     string // What typosquatting technique was detected
	EditDistance   int    // Levenshtein distance
	Ecosystem     models.Ecosystem
}

// popularPackages contains well-known packages per ecosystem.
// A package appearing in this list AND matching a typosquatting pattern
// is flagged as potentially malicious.
//
// Source: npm download statistics, PyPI download statistics, Maven Central popularity
// Reference: "Backstabber's Knife Collection" (Ohm et al., 2020) - Section 3.1 Typosquatting
var popularPackages = map[models.Ecosystem][]string{
	models.EcosystemNPM: {
		// Top npm packages by weekly downloads
		"lodash", "chalk", "react", "express", "axios",
		"commander", "moment", "debug", "uuid", "tslib",
		"glob", "minimist", "semver", "yargs", "mkdirp",
		"supports-color", "async", "inquirer", "rimraf", "webpack",
		"typescript", "eslint", "prettier", "babel", "jest",
		"mocha", "underscore", "request", "bluebird", "colors",
		"cross-env", "dotenv", "cors", "body-parser", "cookie-parser",
		"jsonwebtoken", "mongoose", "sequelize", "nodemon", "pm2",
		"next", "vue", "angular", "svelte", "ember",
		"electron", "puppeteer", "cheerio", "socket.io", "redis",
		"mysql", "pg", "mongodb", "firebase", "aws-sdk",
		"@types/node", "@types/react", "@babel/core", "@angular/core",
		"react-dom", "react-router", "react-redux", "redux", "mobx",
		"styled-components", "tailwindcss", "postcss", "sass", "less",
		"fs-extra", "path", "crypto-js", "bcrypt", "helmet",
		"passport", "morgan", "winston", "bunyan", "pino",
		"node-fetch", "got", "superagent", "http-proxy", "serve",
		"esbuild", "rollup", "parcel", "vite", "turbo",
	},
	models.EcosystemPyPI: {
		// Top PyPI packages by monthly downloads
		"requests", "boto3", "urllib3", "setuptools", "pip",
		"numpy", "pandas", "cryptography", "certifi", "python-dateutil",
		"six", "pyyaml", "idna", "charset-normalizer", "typing-extensions",
		"packaging", "botocore", "jinja2", "markupsafe", "click",
		"pillow", "scipy", "matplotlib", "flask", "django",
		"pytest", "coverage", "tox", "black", "mypy",
		"pylint", "flake8", "isort", "bandit", "safety",
		"sqlalchemy", "psycopg2", "pymongo", "redis", "celery",
		"fastapi", "uvicorn", "gunicorn", "starlette", "httpx",
		"pydantic", "marshmallow", "attrs", "dataclasses", "enum34",
		"tensorflow", "torch", "scikit-learn", "keras", "xgboost",
		"transformers", "huggingface-hub", "tokenizers", "datasets", "accelerate",
		"beautifulsoup4", "scrapy", "selenium", "lxml", "html5lib",
		"paramiko", "fabric", "ansible", "docker", "kubernetes",
		"protobuf", "grpcio", "jsonschema", "toml", "configparser",
		"wheel", "twine", "virtualenv", "pipenv", "poetry",
	},
	models.EcosystemMaven: {
		// Top Maven Central packages
		"com.google.guava:guava", "org.apache.commons:commons-lang3",
		"org.slf4j:slf4j-api", "junit:junit", "org.mockito:mockito-core",
		"com.fasterxml.jackson.core:jackson-databind", "org.apache.logging.log4j:log4j-core",
		"org.springframework:spring-core", "org.springframework.boot:spring-boot",
		"com.google.code.gson:gson", "org.apache.httpcomponents:httpclient",
		"commons-io:commons-io", "org.projectlombok:lombok",
		"org.apache.maven.plugins:maven-compiler-plugin",
		"io.netty:netty-all", "com.squareup.okhttp3:okhttp",
		"org.hibernate:hibernate-core", "org.postgresql:postgresql",
		"mysql:mysql-connector-java", "org.apache.kafka:kafka-clients",
	},
}

// homoglyphs maps characters to visually similar single-character alternatives.
// Attackers exploit visual similarity to trick developers.
// Reference: "Backstabber's Knife Collection" (Ohm et al., 2020)
var homoglyphs = map[rune][]rune{
	'l': {'1', 'I', '|'},
	'1': {'l', 'I', '|'},
	'I': {'l', '1', '|'},
	'0': {'O', 'o'},
	'O': {'0', 'o'},
	'o': {'0', 'O'},
	'i': {'j', '1', 'l'},
	'j': {'i'},
	'm': {'n'},
	'n': {'m', 'r'},
	'r': {'n'},
	'q': {'g'},
	'g': {'q'},
	'v': {'u'},
	'u': {'v'},
	'b': {'d'},
	'd': {'b'},
}

// checkTyposquatting checks if a package name is suspiciously similar to a popular package.
//
// Typosquatting is a common supply chain attack technique where attackers publish
// packages with names similar to popular packages, hoping developers will install
// the malicious package by mistake.
//
// Check: Typosquatting Detection
// Justification: Typosquatting is one of the most common supply chain attack vectors.
//                Attackers publish packages with names similar to popular packages
//                to trick developers into installing malicious code.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
//         "Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages"
//         (NDSS 2020)
// Methodology: Compare package name against curated list of popular packages using
//              Levenshtein distance, character swap detection, homoglyph substitution,
//              and scope/namespace confusion patterns.
// Result: Adds informational finding if potential typosquatting is detected.
func checkTyposquatting(result *models.AnalysisResult, dep models.Dependency) {
	pkgName := dep.Name
	ecosystem := dep.Ecosystem

	popular, ok := popularPackages[ecosystem]
	if !ok {
		return
	}

	// Normalize the package name for comparison
	normalizedPkg := normalizeName(pkgName, ecosystem)

	for _, popularName := range popular {
		normalizedPopular := normalizeName(popularName, ecosystem)

		// Check scope confusion BEFORE self-comparison, since @evil/react
		// normalizes to "react" which matches "react" exactly.
		if isScopeConfusion(pkgName, popularName) {
			addTyposquatFinding(result, pkgName, popularName, &TyposquatResult{
				OriginalName: pkgName,
				SimilarTo:    popularName,
				Confidence:   "MEDIUM",
				Technique:    "scope/namespace manipulation",
				EditDistance:  levenshteinDistance(normalizedPkg, normalizedPopular),
				Ecosystem:    ecosystem,
			})
			return
		}

		// Skip self-comparison (exact match means the package IS the popular one)
		if normalizedPkg == normalizedPopular {
			return
		}

		// Check various typosquatting techniques
		if match := detectTyposquatting(normalizedPkg, normalizedPopular, pkgName, popularName); match != nil {
			match.Ecosystem = ecosystem
			addTyposquatFinding(result, pkgName, popularName, match)
			return // Only report the closest match
		}
	}
}

// addTyposquatFinding adds a finding to the result for a detected typosquatting match.
func addTyposquatFinding(result *models.AnalysisResult, pkgName, popularName string, match *TyposquatResult) {
	severity := "HIGH"
	if match.Confidence == "MEDIUM" {
		severity = "MEDIUM"
	}

	result.Findings = append(result.Findings, models.Finding{
		Severity: severity,
		Category: "Typosquatting Risk",
		Description: fmt.Sprintf(
			"Package name '%s' is suspiciously similar to popular package '%s' (%s). "+
				"Edit distance: %d. This could indicate a typosquatting attack.",
			pkgName, popularName, match.Technique, match.EditDistance,
		),
		Check: "Typosquatting Detection",
		Evidence: fmt.Sprintf(
			"Technique: %s | Confidence: %s | "+
				"Source: Ohm et al. 2020 'Backstabber's Knife Collection' "+
				"(https://arxiv.org/abs/2005.09535)",
			match.Technique, match.Confidence,
		),
	})
	result.RiskFactors = append(result.RiskFactors,
		fmt.Sprintf("Possible typosquatting of '%s'", popularName))
}

// detectTyposquatting checks if pkgName is a typosquat of popularName.
// Returns a TyposquatResult if suspicious, nil otherwise.
//
// Detection order matters: more specific techniques are checked first so
// the reported technique accurately describes the attack pattern.
func detectTyposquatting(normalizedPkg, normalizedPopular, originalPkg, originalPopular string) *TyposquatResult {
	dist := levenshteinDistance(normalizedPkg, normalizedPopular)

	// 1. Check for separator confusion first (e.g., crossenv vs cross-env)
	// This is the most specific pattern and should be checked before generic ED1.
	if isSeparatorConfusion(normalizedPkg, normalizedPopular) {
		return &TyposquatResult{
			OriginalName: originalPkg,
			SimilarTo:    originalPopular,
			Confidence:   "HIGH",
			Technique:    "separator confusion",
			EditDistance:  dist,
		}
	}

	// 2. Check for homoglyph substitution (e.g., 1odash vs lodash)
	// More specific than generic substitution.
	if isHomoglyphSubstitution(normalizedPkg, normalizedPopular) {
		return &TyposquatResult{
			OriginalName: originalPkg,
			SimilarTo:    originalPopular,
			Confidence:   "HIGH",
			Technique:    "homoglyph substitution",
			EditDistance:  dist,
		}
	}

	// 3. Check for repeated character (e.g., "expresss" vs "express")
	if isRepeatedChar(normalizedPkg, normalizedPopular) {
		return &TyposquatResult{
			OriginalName: originalPkg,
			SimilarTo:    originalPopular,
			Confidence:   "HIGH",
			Technique:    "repeated character",
			EditDistance:  dist,
		}
	}

	// 4. Check for adjacent character swap (transposition)
	if isTransposition(normalizedPkg, normalizedPopular) {
		return &TyposquatResult{
			OriginalName: originalPkg,
			SimilarTo:    originalPopular,
			Confidence:   "HIGH",
			Technique:    "adjacent character transposition",
			EditDistance:  dist,
		}
	}

	// 5. Generic edit distance 1 (catch-all for remaining single-char differences)
	if dist == 1 {
		technique := classifyEditDistance1(normalizedPkg, normalizedPopular)
		return &TyposquatResult{
			OriginalName: originalPkg,
			SimilarTo:    originalPopular,
			Confidence:   "HIGH",
			Technique:    technique,
			EditDistance:  dist,
		}
	}

	// 6. Check for edit distance of 2 with short names (higher risk for short names)
	if dist == 2 && len(normalizedPopular) <= 5 {
		return &TyposquatResult{
			OriginalName: originalPkg,
			SimilarTo:    originalPopular,
			Confidence:   "MEDIUM",
			Technique:    "close name variant (short package)",
			EditDistance:  dist,
		}
	}

	return nil
}

// normalizeName normalizes a package name for comparison by stripping
// ecosystem-specific prefixes and lowercasing.
func normalizeName(name string, ecosystem models.Ecosystem) string {
	name = strings.ToLower(name)

	switch ecosystem {
	case models.EcosystemNPM:
		// Strip npm scope (e.g., @scope/package -> package)
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
	case models.EcosystemMaven:
		// For Maven, use artifact ID only (groupId:artifactId -> artifactId)
		if idx := strings.LastIndex(name, ":"); idx >= 0 {
			name = name[idx+1:]
		}
	}

	return name
}

// stripSeparators removes all common separators (hyphens, underscores, dots)
func stripSeparators(name string) string {
	r := strings.NewReplacer("-", "", "_", "", ".", "")
	return r.Replace(name)
}

// levenshteinDistance calculates the edit distance between two strings.
func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// Create matrix
	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := 0; j <= len(b); j++ {
		matrix[0][j] = j
	}

	// Fill matrix
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}

			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(a)][len(b)]
}

// classifyEditDistance1 determines what kind of single-edit produced the difference.
func classifyEditDistance1(a, b string) string {
	if len(a) > len(b) {
		return "extra character insertion"
	}
	if len(a) < len(b) {
		return "character omission"
	}
	return "character substitution"
}

// isTransposition checks if two strings differ only by swapping two adjacent characters.
func isTransposition(a, b string) bool {
	if len(a) != len(b) || len(a) < 2 {
		return false
	}

	diffCount := 0
	diffPos := -1
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			if diffCount == 0 {
				diffPos = i
			}
			diffCount++
		}
	}

	if diffCount != 2 && diffPos >= 0 && diffPos+1 < len(a) {
		return false
	}

	if diffCount == 2 && diffPos+1 < len(a) {
		return a[diffPos] == b[diffPos+1] && a[diffPos+1] == b[diffPos]
	}

	return false
}

// isHomoglyphSubstitution checks if two strings differ only by homoglyph characters.
// Checks both directions (a[i] is homoglyph of b[i] OR b[i] is homoglyph of a[i]).
func isHomoglyphSubstitution(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	hasHomoglyph := false
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			// Check both directions: a->b and b->a
			if isHomoglyphPair(rune(a[i]), rune(b[i])) {
				hasHomoglyph = true
			} else {
				return false
			}
		}
	}

	return hasHomoglyph
}

// isHomoglyphPair checks if two runes are homoglyph variants of each other.
func isHomoglyphPair(a, b rune) bool {
	// Check a -> b
	if alts, ok := homoglyphs[a]; ok {
		for _, alt := range alts {
			if alt == b {
				return true
			}
		}
	}
	// Check b -> a
	if alts, ok := homoglyphs[b]; ok {
		for _, alt := range alts {
			if alt == a {
				return true
			}
		}
	}
	return false
}

// isSeparatorConfusion checks if two names are identical except for separator characters
// (hyphens, underscores, dots). Example: "cross-env" vs "crossenv" or "cross_env".
func isSeparatorConfusion(a, b string) bool {
	strippedA := stripSeparators(a)
	strippedB := stripSeparators(b)

	// Only flag if the names are actually different but become the same
	// when separators are removed, AND at least one has a separator
	if strippedA == strippedB && a != b {
		hasSepA := strings.ContainsAny(a, "-_.")
		hasSepB := strings.ContainsAny(b, "-_.")
		return hasSepA || hasSepB
	}
	return false
}

// isScopeConfusion checks for npm scope manipulation.
// Example: @evil/react being used to confuse with react or @facebook/react.
func isScopeConfusion(pkg, popular string) bool {
	// Check if the package has a different scope but same base name as a popular package
	if !strings.HasPrefix(pkg, "@") {
		return false
	}

	// Extract base name from scoped package
	parts := strings.SplitN(pkg, "/", 2)
	if len(parts) != 2 {
		return false
	}
	pkgBase := strings.ToLower(parts[1])

	// Compare with popular package base name
	popularBase := strings.ToLower(popular)
	if strings.HasPrefix(popular, "@") {
		popParts := strings.SplitN(popular, "/", 2)
		if len(popParts) == 2 {
			popularBase = popParts[1]
		}
	}

	// Same base name with different scope is suspicious
	return pkgBase == popularBase && !strings.EqualFold(pkg, popular)
}

// isRepeatedChar checks if one string is the same as the other but with a character
// repeated. Example: "expresss" vs "express" or "reeact" vs "react".
func isRepeatedChar(a, b string) bool {
	// One should be longer than the other by exactly 1
	short, long := b, a
	if len(a) < len(b) {
		short, long = a, b
	}
	if len(long)-len(short) != 1 {
		return false
	}

	// Find the position where they differ
	for i := 0; i < len(short); i++ {
		if short[i] != long[i] {
			// The extra character in long must be the same as the adjacent character
			if i > 0 && long[i] == long[i-1] {
				return short[i:] == long[i+1:]
			}
			if i < len(long)-1 && long[i] == long[i+1] {
				return short[i:] == long[i+1:]
			}
			return false
		}
	}
	// Extra char at end - check if it's a repeat of the last char
	return len(long) > 0 && long[len(long)-1] == long[len(long)-2]
}

func min(values ...int) int {
	m := values[0]
	for _, v := range values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}
