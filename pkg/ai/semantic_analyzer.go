package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/metalstormbass/snyft/pkg/models"
)

// SemanticAnalyzer provides semantic analysis of source code for supply chain risks
type SemanticAnalyzer struct {
	client      *Client
	httpClient  *http.Client
	enableCache bool
}

// AnalyzerOptions configures the semantic analyzer behavior
type AnalyzerOptions struct {
	// AnalyzeFullSource enables full source code analysis (expensive, opt-in)
	// Default: only analyze install scripts
	AnalyzeFullSource bool

	// MaxFilesToAnalyze limits the number of files to analyze (cost control)
	// Default: 10 files maximum
	MaxFilesToAnalyze int

	// EnableCache enables file-hash-based caching
	// Default: true
	EnableCache bool

	// Temperature for AI model (0.0-1.0, lower = more deterministic)
	// Default: 0.2 for code analysis
	Temperature float64

	// MaxTokens for AI response
	// Default: 1500
	MaxTokens int
}

// DefaultAnalyzerOptions returns sensible defaults
func DefaultAnalyzerOptions() AnalyzerOptions {
	return AnalyzerOptions{
		AnalyzeFullSource: false,
		MaxFilesToAnalyze: 10,
		EnableCache:       true,
		Temperature:       0.2,
		MaxTokens:         1500,
	}
}

// NewSemanticAnalyzer creates a new semantic analyzer with the given AI client
func NewSemanticAnalyzer(client *Client) *SemanticAnalyzer {
	return &SemanticAnalyzer{
		client:      client,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		enableCache: true,
	}
}

// AnalyzeInstallScripts analyzes install-time scripts for supply chain risks
// This is the default, cost-optimized analysis mode
//
// Justification: Install scripts execute during package installation and are a
// primary attack vector for supply chain compromise (Backstabber's Knife Collection, Ohm et al. 2020)
// Historical examples: event-stream (2018), flatmap-stream (2018), crossenv (2017)
func (sa *SemanticAnalyzer) AnalyzeInstallScripts(ctx context.Context, scripts map[string]string, opts AnalyzerOptions) ([]models.SemanticFinding, error) {
	if len(scripts) == 0 {
		return []models.SemanticFinding{}, nil
	}

	findings := []models.SemanticFinding{}

	for scriptType, scriptContent := range scripts {
		// Skip empty scripts
		if strings.TrimSpace(scriptContent) == "" {
			continue
		}

		// Check cache first (if enabled)
		var cacheKey string
		if opts.EnableCache && sa.enableCache {
			cacheKey = computeFileHash(scriptContent)
			if cached, found := sa.getCachedFindings(cacheKey); found {
				// Add script type to cached findings
				for _, finding := range cached {
					finding.FilePath = scriptType
					findings = append(findings, finding)
				}
				continue
			}
		}

		// Analyze the script with Claude
		scriptFindings, err := sa.analyzeScriptContent(ctx, scriptType, scriptContent, opts)
		if err != nil {
			// Log error but continue with other scripts
			// Return partial results rather than failing completely
			continue
		}

		// Cache the results
		if opts.EnableCache && sa.enableCache && cacheKey != "" {
			sa.cacheFindings(cacheKey, scriptFindings)
		}

		findings = append(findings, scriptFindings...)
	}

	return findings, nil
}

// AnalyzeSourceCode analyzes full source code for supply chain risks (opt-in, expensive)
//
// This is an opt-in feature for deep analysis. It fetches source files from the
// repository and analyzes them for suspicious patterns.
//
// Cost optimization: Limits number of files analyzed (default: 10)
func (sa *SemanticAnalyzer) AnalyzeSourceCode(ctx context.Context, repoURL string, version string, opts AnalyzerOptions) ([]models.SemanticFinding, error) {
	if !opts.AnalyzeFullSource {
		return nil, fmt.Errorf("full source analysis is opt-in, set AnalyzeFullSource to true")
	}

	// Fetch source files from repository
	files, err := sa.fetchSourceFiles(ctx, repoURL, version, opts.MaxFilesToAnalyze)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch source files: %w", err)
	}

	findings := []models.SemanticFinding{}

	for filePath, content := range files {
		// Check cache first
		var cacheKey string
		if opts.EnableCache && sa.enableCache {
			cacheKey = computeFileHash(content)
			if cached, found := sa.getCachedFindings(cacheKey); found {
				// Add file path to cached findings
				for _, finding := range cached {
					finding.FilePath = filePath
					findings = append(findings, finding)
				}
				continue
			}
		}

		// Analyze the file
		fileFindings, err := sa.analyzeScriptContent(ctx, filePath, content, opts)
		if err != nil {
			// Continue with other files on error
			continue
		}

		// Cache the results
		if opts.EnableCache && sa.enableCache && cacheKey != "" {
			sa.cacheFindings(cacheKey, fileFindings)
		}

		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

// analyzeScriptContent uses Claude to analyze script content for suspicious patterns
func (sa *SemanticAnalyzer) analyzeScriptContent(ctx context.Context, scriptType string, scriptContent string, opts AnalyzerOptions) ([]models.SemanticFinding, error) {
	// Use the code pattern analysis prompt from prompts.go
	prompt := NewCodePatternAnalysisPrompt(scriptType, scriptContent)

	// Render the prompt
	systemPrompt, userPrompt := prompt.Render()

	// Override temperature and max tokens if specified
	temperature := prompt.Temperature
	if opts.Temperature > 0 {
		temperature = opts.Temperature
	}

	maxTokens := prompt.MaxTokens
	if opts.MaxTokens > 0 {
		maxTokens = opts.MaxTokens
	}

	// Create the API request
	params := anthropic.MessageNewParams{
		Model:       anthropic.ModelClaudeSonnet4_5_20250929,
		MaxTokens:   int64(maxTokens),
		Temperature: anthropic.Float(temperature),
		System: []anthropic.TextBlockParam{{
			Text: systemPrompt,
		}},
		Messages: []anthropic.MessageParam{{
			Role: anthropic.MessageParamRoleUser,
			Content: []anthropic.ContentBlockParamUnion{{
				OfText: &anthropic.TextBlockParam{
					Text: userPrompt,
				},
			}},
		}},
	}

	// Call Claude API
	message, err := sa.client.CreateMessage(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("claude api error: %w", err)
	}

	// Parse the response into structured findings
	findings, err := sa.parseClaudeResponse(message, scriptType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claude response: %w", err)
	}

	return findings, nil
}

// parseClaudeResponse extracts structured findings from Claude's response
// Claude returns natural language analysis, we parse it into structured data
func (sa *SemanticAnalyzer) parseClaudeResponse(message *anthropic.Message, scriptType string) ([]models.SemanticFinding, error) {
	if len(message.Content) == 0 {
		return []models.SemanticFinding{}, nil
	}

	// Extract text content
	var responseText string
	for _, block := range message.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	// Parse the response to extract findings
	findings := sa.extractFindingsFromText(responseText, scriptType)

	return findings, nil
}

// extractFindingsFromText parses Claude's natural language response into structured findings
//
// Claude's response follows this format (from prompts.go):
// - Pattern name (e.g., "Network Download", "File System Modification")
// - Specific code snippet demonstrating the pattern
// - Risk level (HIGH/MEDIUM/LOW)
// - Academic justification
// - Why this increases compromise likelihood
func (sa *SemanticAnalyzer) extractFindingsFromText(text string, scriptType string) []models.SemanticFinding {
	findings := []models.SemanticFinding{}

	// Check for explicit "benign" or "no risk" statements first
	textLower := strings.ToLower(text)
	if strings.Contains(textLower, "appears benign") ||
		strings.Contains(textLower, "no risky patterns") ||
		strings.Contains(textLower, "no risk") ||
		(strings.Contains(textLower, "no network") &&
			strings.Contains(textLower, "no file system") &&
			strings.Contains(textLower, "no privilege")) {
		// Script is benign, return empty findings
		return findings
	}

	// Pattern 1: Network Access Patterns
	if sa.containsPattern(text, []string{"network access", "network request", "network download", "downloads code", "http request", "fetch", "curl", "wget"}) &&
		!sa.containsPattern(text, []string{"no network"}) {
		finding := models.SemanticFinding{
			Type:            "suspicious_network_call",
			Description:     "Install script makes network requests, potentially downloading code from external sources",
			Confidence:      sa.calculateConfidence(text, "network"),
			Severity:        sa.extractSeverity(text, "network", "HIGH"),
			FilePath:        scriptType,
			Evidence:        sa.extractEvidence(text, "network"),
			RiskExplanation: "Downloaded code bypasses package registry audits and can be modified by attackers (Backstabber's Knife Collection, Ohm et al. 2020)",
		}
		findings = append(findings, finding)
	}

	// Pattern 2: File System Operations
	if sa.containsPattern(text, []string{"file system modification", "file system operation", "writes to", "chmod", "chown", "rm -rf"}) &&
		!sa.containsPattern(text, []string{"no file system"}) {
		finding := models.SemanticFinding{
			Type:            "dangerous_file_operation",
			Description:     "Install script performs file system operations outside package directory",
			Confidence:      sa.calculateConfidence(text, "file"),
			Severity:        sa.extractSeverity(text, "file", "MEDIUM"),
			FilePath:        scriptType,
			Evidence:        sa.extractEvidence(text, "file"),
			RiskExplanation: "Global modifications can persist malicious code beyond package lifecycle (SLSA Build Level 1 - builds should be hermetic)",
		}
		findings = append(findings, finding)
	}

	// Pattern 3: Privilege Escalation
	if sa.containsPattern(text, []string{"privilege escalation", "elevated privilege", "sudo", "su", "gain admin", "root access"}) &&
		!sa.containsPattern(text, []string{"no privilege"}) {
		finding := models.SemanticFinding{
			Type:            "privilege_escalation",
			Description:     "Install script attempts to gain elevated privileges",
			Confidence:      sa.calculateConfidence(text, "privilege"),
			Severity:        "HIGH",
			FilePath:        scriptType,
			Evidence:        sa.extractEvidence(text, "privilege"),
			RiskExplanation: "Root access enables system-wide compromise (npm 'crossenv' attack, 2017)",
		}
		findings = append(findings, finding)
	}

	// Pattern 4: Obfuscation Techniques
	if sa.containsPattern(text, []string{"obfuscation", "obfuscated", "base64", "eval", "exec", "encoded"}) {
		finding := models.SemanticFinding{
			Type:            "code_obfuscation",
			Description:     "Install script uses obfuscation techniques that hide intent",
			Confidence:      sa.calculateConfidence(text, "obfuscation"),
			Severity:        "HIGH",
			FilePath:        scriptType,
			Evidence:        sa.extractEvidence(text, "obfuscation"),
			RiskExplanation: "Malicious actors hide intent through obfuscation (event-stream attack, 2018)",
		}
		findings = append(findings, finding)
	}

	// Pattern 5: Environment Variable Access (Credential Harvesting)
	if sa.containsPattern(text, []string{"environment", "env", "credential", "password", "token", "secret", "api key"}) {
		finding := models.SemanticFinding{
			Type:            "credential_harvesting",
			Description:     "Install script accesses environment variables that may contain credentials",
			Confidence:      sa.calculateConfidence(text, "environment"),
			Severity:        "HIGH",
			FilePath:        scriptType,
			Evidence:        sa.extractEvidence(text, "environment"),
			RiskExplanation: "Credential theft during installation (multiple npm packages caught exfiltrating AWS credentials)",
		}
		findings = append(findings, finding)
	}

	// Pattern 6: Child Process Spawning
	if sa.containsPattern(text, []string{"child process", "spawn", "fork", "exec", "subprocess"}) {
		finding := models.SemanticFinding{
			Type:            "suspicious_process_spawn",
			Description:     "Install script spawns child processes that could hide malicious behavior",
			Confidence:      sa.calculateConfidence(text, "process"),
			Severity:        sa.extractSeverity(text, "process", "MEDIUM"),
			FilePath:        scriptType,
			Evidence:        sa.extractEvidence(text, "process"),
			RiskExplanation: "Process injection and sandbox escape (flatmap-stream attack)",
		}
		findings = append(findings, finding)
	}

	// If no patterns found, check if Claude explicitly said "benign"
	if len(findings) == 0 && sa.containsPattern(text, []string{"benign", "no risk", "safe", "no patterns"}) {
		// No findings - this is good!
		return findings
	}

	// If we got response but no structured patterns, add a generic finding
	if len(findings) == 0 && len(text) > 100 {
		finding := models.SemanticFinding{
			Type:            "unknown_pattern",
			Description:     "Semantic analysis identified potential concerns but couldn't classify them",
			Confidence:      0.5,
			Severity:        "LOW",
			FilePath:        scriptType,
			Evidence:        text[:min(500, len(text))],
			RiskExplanation: "Manual review recommended",
		}
		findings = append(findings, finding)
	}

	return findings
}

// containsPattern checks if text contains any of the keywords (case-insensitive)
func (sa *SemanticAnalyzer) containsPattern(text string, keywords []string) bool {
	textLower := strings.ToLower(text)
	for _, keyword := range keywords {
		if strings.Contains(textLower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// calculateConfidence estimates confidence score based on keyword presence and context
func (sa *SemanticAnalyzer) calculateConfidence(text string, patternType string) float64 {
	// Start with base confidence
	confidence := 0.7

	// Increase confidence if "HIGH" or "CRITICAL" mentioned
	if sa.containsPattern(text, []string{"high risk", "critical", "severe"}) {
		confidence = 0.9
	}

	// Decrease confidence if uncertainty markers present
	if sa.containsPattern(text, []string{"might", "possibly", "could be", "uncertain"}) {
		confidence -= 0.2
	}

	// Increase confidence if academic citation present
	if sa.containsPattern(text, []string{"ohm et al", "slsa", "backstabber", "reference:"}) {
		confidence += 0.1
	}

	// Clamp between 0.0 and 1.0
	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// extractSeverity extracts severity from text, with fallback default
func (sa *SemanticAnalyzer) extractSeverity(text string, patternType string, defaultSeverity string) string {
	textLower := strings.ToLower(text)

	// Look for explicit severity markers
	if strings.Contains(textLower, "high risk") || strings.Contains(textLower, "critical") {
		return "HIGH"
	}
	if strings.Contains(textLower, "medium risk") || strings.Contains(textLower, "moderate") {
		return "MEDIUM"
	}
	if strings.Contains(textLower, "low risk") || strings.Contains(textLower, "minor") {
		return "LOW"
	}

	return defaultSeverity
}

// extractEvidence extracts specific evidence from Claude's response
func (sa *SemanticAnalyzer) extractEvidence(text string, patternType string) string {
	// Try to find code snippets (enclosed in backticks or quotes)
	snippetRegex := regexp.MustCompile("```([^`]+)```|`([^`]+)`")
	matches := snippetRegex.FindAllStringSubmatch(text, -1)

	if len(matches) > 0 {
		for _, match := range matches {
			for i := 1; i < len(match); i++ {
				if match[i] != "" && len(strings.TrimSpace(match[i])) > 0 {
					return strings.TrimSpace(match[i])
				}
			}
		}
	}

	// Look for "Evidence:" section
	evidenceIdx := strings.Index(strings.ToLower(text), "evidence:")
	if evidenceIdx != -1 {
		evidenceText := text[evidenceIdx+9:] // Skip "Evidence:"
		// Get first line or sentence after Evidence:
		lines := strings.Split(evidenceText, "\n")
		if len(lines) > 0 {
			evidence := strings.TrimSpace(lines[0])
			if len(evidence) > 0 {
				return evidence
			}
		}
	}

	// If no code snippet, return first sentence mentioning the pattern type
	sentences := strings.Split(text, ".")
	for _, sentence := range sentences {
		sentenceLower := strings.ToLower(sentence)
		// Look for the actual pattern keywords, not just the type
		keywords := map[string][]string{
			"network":     {"network", "download", "http", "curl", "fetch"},
			"file":        {"file", "write", "chmod", "mkdir"},
			"privilege":   {"privilege", "sudo", "root"},
			"obfuscation": {"obfuscate", "base64", "eval", "encode"},
			"environment": {"environment", "env", "credential", "secret"},
			"process":     {"process", "spawn", "exec", "fork"},
		}

		if keywordList, ok := keywords[patternType]; ok {
			for _, keyword := range keywordList {
				if strings.Contains(sentenceLower, keyword) {
					return strings.TrimSpace(sentence)
				}
			}
		}
	}

	// Fallback: return first 200 characters
	if len(text) > 200 {
		return text[:200] + "..."
	}
	return text
}

// fetchSourceFiles fetches source files from a repository (GitHub, GitLab, Bitbucket)
// Returns a map of file paths to content
func (sa *SemanticAnalyzer) fetchSourceFiles(ctx context.Context, repoURL string, version string, maxFiles int) (map[string]string, error) {
	// Parse repository URL to determine platform
	platform, owner, repo, err := parseRepoURL(repoURL)
	if err != nil {
		return nil, fmt.Errorf("invalid repository URL: %w", err)
	}

	// Fetch based on platform
	switch platform {
	case "github":
		return sa.fetchGitHubFiles(ctx, owner, repo, version, maxFiles)
	case "gitlab":
		return sa.fetchGitLabFiles(ctx, owner, repo, version, maxFiles)
	case "bitbucket":
		return sa.fetchBitbucketFiles(ctx, owner, repo, version, maxFiles)
	default:
		return nil, fmt.Errorf("unsupported repository platform: %s", platform)
	}
}

// parseRepoURL parses a repository URL and extracts platform, owner, and repo name
func parseRepoURL(repoURL string) (platform, owner, repo string, err error) {
	// Remove protocol and trailing .git
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "http://")
	repoURL = strings.TrimSuffix(repoURL, ".git")

	parts := strings.Split(repoURL, "/")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid repository URL format")
	}

	domain := parts[0]
	owner = parts[1]
	repo = parts[2]

	// Determine platform from domain
	if strings.Contains(domain, "github") {
		platform = "github"
	} else if strings.Contains(domain, "gitlab") {
		platform = "gitlab"
	} else if strings.Contains(domain, "bitbucket") {
		platform = "bitbucket"
	} else {
		return "", "", "", fmt.Errorf("unsupported repository platform: %s", domain)
	}

	return platform, owner, repo, nil
}

// fetchGitHubFiles fetches source files from GitHub
func (sa *SemanticAnalyzer) fetchGitHubFiles(ctx context.Context, owner, repo, version string, maxFiles int) (map[string]string, error) {
	// GitHub API: https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={version}
	// For now, return placeholder - full implementation would require:
	// 1. List repository contents
	// 2. Filter for relevant files (scripts, config files)
	// 3. Download up to maxFiles
	// 4. Return map of path -> content

	// TODO: Implement GitHub API integration
	// Requires authentication token for higher rate limits
	return nil, fmt.Errorf("GitHub source fetching not yet implemented")
}

// fetchGitLabFiles fetches source files from GitLab
func (sa *SemanticAnalyzer) fetchGitLabFiles(ctx context.Context, owner, repo, version string, maxFiles int) (map[string]string, error) {
	// TODO: Implement GitLab API integration
	return nil, fmt.Errorf("GitLab source fetching not yet implemented")
}

// fetchBitbucketFiles fetches source files from Bitbucket
func (sa *SemanticAnalyzer) fetchBitbucketFiles(ctx context.Context, owner, repo, version string, maxFiles int) (map[string]string, error) {
	// TODO: Implement Bitbucket API integration
	return nil, fmt.Errorf("Bitbucket source fetching not yet implemented")
}

// Cache management

// getCachedFindings retrieves cached findings by file hash
func (sa *SemanticAnalyzer) getCachedFindings(fileHash string) ([]models.SemanticFinding, bool) {
	if sa.client.cache == nil {
		return nil, false
	}

	// Check cache
	cached, found := sa.client.cache.Get("semantic:" + fileHash)
	if !found {
		return nil, false
	}

	// Type assertion
	findings, ok := cached.([]models.SemanticFinding)
	if !ok {
		return nil, false
	}

	return findings, true
}

// cacheFindings stores findings in cache by file hash
func (sa *SemanticAnalyzer) cacheFindings(fileHash string, findings []models.SemanticFinding) {
	if sa.client.cache == nil {
		return
	}

	// Estimate cost (rough approximation: 1KB per finding)
	cost := int64(len(findings) * 1024)

	// Store in cache with 24 hour TTL
	sa.client.cache.SetWithTTL("semantic:"+fileHash, findings, cost, 24*time.Hour)
}

// computeFileHash computes SHA-256 hash of file content for caching
func computeFileHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// Helper functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// HIGH-LEVEL ANALYSIS FUNCTIONS
// ============================================================================

// AnalyzePackage performs comprehensive semantic analysis on a package
// This is the main entry point for semantic analysis
func (sa *SemanticAnalyzer) AnalyzePackage(ctx context.Context, pkg *models.AnalysisResult, opts AnalyzerOptions) (*models.AIAnalysisResult, error) {
	result := &models.AIAnalysisResult{
		Timestamp:        time.Now(),
		ModelVersion:     string(anthropic.ModelClaudeSonnet4_5_20250929),
		SemanticFindings: []models.SemanticFinding{},
	}

	// Phase 1: Analyze install scripts (always, this is cost-optimized)
	if len(pkg.Metadata.InstallScripts) > 0 {
		findings, err := sa.AnalyzeInstallScripts(ctx, pkg.Metadata.InstallScripts, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to analyze install scripts: %w", err)
		}
		result.SemanticFindings = append(result.SemanticFindings, findings...)
	}

	// Phase 2: Analyze full source code (opt-in, expensive)
	if opts.AnalyzeFullSource && pkg.RepositoryURL != "" {
		findings, err := sa.AnalyzeSourceCode(ctx, pkg.RepositoryURL, pkg.Dependency.Version, opts)
		if err != nil {
			// Log warning but don't fail - source analysis is optional
			result.AnalysisNotes += fmt.Sprintf("Warning: Full source analysis failed: %v\n", err)
		} else {
			result.SemanticFindings = append(result.SemanticFindings, findings...)
		}
	}

	// Calculate overall confidence (average of all findings)
	if len(result.SemanticFindings) > 0 {
		totalConfidence := 0.0
		for _, finding := range result.SemanticFindings {
			totalConfidence += finding.Confidence
		}
		result.OverallConfidence = totalConfidence / float64(len(result.SemanticFindings))
	} else {
		result.OverallConfidence = 1.0 // No findings = high confidence in safety
	}

	return result, nil
}

// AnalyzeWithAttackPatterns performs semantic analysis and matches to known attack patterns
func (sa *SemanticAnalyzer) AnalyzeWithAttackPatterns(ctx context.Context, pkg *models.AnalysisResult, opts AnalyzerOptions) (*models.AIAnalysisResult, error) {
	// First, perform standard semantic analysis
	result, err := sa.AnalyzePackage(ctx, pkg, opts)
	if err != nil {
		return nil, err
	}

	// Then, match to known attack patterns using prompts.go
	prompt := NewAttackPatternMatchingPrompt(pkg.Dependency.Name, pkg.Dependency.Ecosystem, *pkg)

	// Render the prompt
	systemPrompt, userPrompt := prompt.Render()

	// Create the API request
	params := anthropic.MessageNewParams{
		Model:       anthropic.ModelClaudeSonnet4_5_20250929,
		MaxTokens:   int64(prompt.MaxTokens),
		Temperature: anthropic.Float(prompt.Temperature),
		System: []anthropic.TextBlockParam{{
			Text: systemPrompt,
		}},
		Messages: []anthropic.MessageParam{{
			Role: anthropic.MessageParamRoleUser,
			Content: []anthropic.ContentBlockParamUnion{{
				OfText: &anthropic.TextBlockParam{
					Text: userPrompt,
				},
			}},
		}},
	}

	// Call Claude API
	message, err := sa.client.CreateMessage(ctx, params)
	if err != nil {
		// Don't fail on attack pattern matching - it's supplementary
		result.AnalysisNotes += fmt.Sprintf("Warning: Attack pattern matching failed: %v\n", err)
		return result, nil
	}

	// Parse attack patterns from response
	patterns := sa.parseAttackPatterns(message)
	result.AttackPatterns = patterns

	return result, nil
}

// parseAttackPatterns extracts attack pattern matches from Claude's response
func (sa *SemanticAnalyzer) parseAttackPatterns(message *anthropic.Message) []models.AttackPatternMatch {
	if len(message.Content) == 0 {
		return []models.AttackPatternMatch{}
	}

	// Extract text content
	var responseText string
	for _, block := range message.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	patterns := []models.AttackPatternMatch{}

	// Known attack patterns from prompts.go
	patternNames := []string{
		"Typosquatting",
		"Account Takeover",
		"Dependency Confusion",
		"Malicious Install Script",
		"Abandoned Package Takeover",
		"Build Chain Compromise",
		"Transitive Dependency Poisoning",
		"Subdomain Takeover",
	}

	for _, patternName := range patternNames {
		if sa.containsPattern(responseText, []string{patternName, strings.ToLower(patternName)}) {
			pattern := models.AttackPatternMatch{
				PatternName: patternName,
				Description: sa.extractPatternDescription(responseText, patternName),
				Confidence:  sa.calculateConfidence(responseText, patternName),
				Severity:    sa.extractSeverity(responseText, patternName, "MEDIUM"),
				Evidence:    sa.extractPatternEvidence(responseText, patternName),
				Indicators:  sa.extractPatternIndicators(responseText, patternName),
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// extractPatternDescription extracts description for a specific attack pattern
func (sa *SemanticAnalyzer) extractPatternDescription(text string, patternName string) string {
	// Find sentences mentioning the pattern
	sentences := strings.Split(text, ".")
	for _, sentence := range sentences {
		if strings.Contains(sentence, patternName) {
			return strings.TrimSpace(sentence)
		}
	}
	return fmt.Sprintf("Potential match to %s attack pattern", patternName)
}

// extractPatternEvidence extracts evidence list for attack pattern
func (sa *SemanticAnalyzer) extractPatternEvidence(text string, patternName string) []string {
	evidence := []string{}

	// Look for bullet points or numbered lists
	lines := strings.Split(text, "\n")
	inEvidenceSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check if we're in evidence section
		if strings.Contains(strings.ToLower(line), "evidence") || strings.Contains(strings.ToLower(line), "indicator") {
			inEvidenceSection = true
			continue
		}

		// Extract bullet points
		if inEvidenceSection && (strings.HasPrefix(line, "-") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "•")) {
			evidence = append(evidence, strings.TrimSpace(line[1:]))
		}

		// Stop at next section
		if inEvidenceSection && strings.Contains(line, "##") {
			break
		}
	}

	// If no structured evidence found, add generic evidence
	if len(evidence) == 0 {
		evidence = append(evidence, "See analysis notes for details")
	}

	return evidence
}

// extractPatternIndicators extracts specific indicators for attack pattern
func (sa *SemanticAnalyzer) extractPatternIndicators(text string, patternName string) []string {
	// Similar to evidence extraction but looking for "indicators" specifically
	return sa.extractPatternEvidence(text, patternName)
}

// GenerateExecutiveSummary generates a stakeholder-friendly summary
func (sa *SemanticAnalyzer) GenerateExecutiveSummary(ctx context.Context, pkg *models.AnalysisResult, targetAudience string) (*models.ExecutiveExplanation, error) {
	prompt := NewExecutiveExplanationPrompt(pkg.Dependency.Name, pkg.Dependency.Ecosystem, *pkg, targetAudience)

	// Render the prompt
	systemPrompt, userPrompt := prompt.Render()

	// Create the API request
	params := anthropic.MessageNewParams{
		Model:       anthropic.ModelClaudeSonnet4_5_20250929,
		MaxTokens:   int64(prompt.MaxTokens),
		Temperature: anthropic.Float(prompt.Temperature),
		System: []anthropic.TextBlockParam{{
			Text: systemPrompt,
		}},
		Messages: []anthropic.MessageParam{{
			Role: anthropic.MessageParamRoleUser,
			Content: []anthropic.ContentBlockParamUnion{{
				OfText: &anthropic.TextBlockParam{
					Text: userPrompt,
				},
			}},
		}},
	}

	// Call Claude API
	message, err := sa.client.CreateMessage(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("claude api error: %w", err)
	}

	// Parse the response into executive summary
	summary := sa.parseExecutiveSummary(message)

	return summary, nil
}

// parseExecutiveSummary extracts structured executive summary from Claude's response
func (sa *SemanticAnalyzer) parseExecutiveSummary(message *anthropic.Message) *models.ExecutiveExplanation {
	if len(message.Content) == 0 {
		return nil
	}

	// Extract text content
	var responseText string
	for _, block := range message.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	// Parse the structured sections from the response
	// The prompt asks for specific sections, extract them

	summary := &models.ExecutiveExplanation{
		GeneratedAt: time.Now(),
		Confidence:  0.8, // Default confidence
	}

	// Extract Executive Summary section
	summary.Summary = sa.extractSection(responseText, "Executive Summary", "Business Impact")

	// Extract Key Risks
	summary.KeyRisks = sa.extractBulletPoints(responseText, "Business Impact")

	// Extract Business Impact
	summary.BusinessImpact = sa.extractSection(responseText, "Business Impact", "Technical Explanation")

	// Extract Recommended Action
	summary.RecommendedAction = sa.extractSection(responseText, "Recommendations", "")

	// Extract Technical Details
	summary.TechnicalDetails = sa.extractSection(responseText, "Technical Explanation", "Risk Assessment")

	// If sections are empty, use full text as summary
	if summary.Summary == "" {
		summary.Summary = responseText[:min(500, len(responseText))]
	}

	return summary
}

// extractSection extracts text between two section headers
func (sa *SemanticAnalyzer) extractSection(text string, startMarker string, endMarker string) string {
	startIdx := strings.Index(text, startMarker)
	if startIdx == -1 {
		return ""
	}

	// Skip the marker itself
	startIdx += len(startMarker)

	// Find end marker
	var endIdx int
	if endMarker != "" {
		endIdx = strings.Index(text[startIdx:], endMarker)
		if endIdx != -1 {
			endIdx += startIdx
		} else {
			endIdx = len(text)
		}
	} else {
		endIdx = len(text)
	}

	section := strings.TrimSpace(text[startIdx:endIdx])
	return section
}

// extractBulletPoints extracts bullet points from a section
func (sa *SemanticAnalyzer) extractBulletPoints(text string, sectionName string) []string {
	bullets := []string{}

	// Extract section first
	section := sa.extractSection(text, sectionName, "")
	if section == "" {
		return bullets
	}

	lines := strings.Split(section, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "•") {
			bullets = append(bullets, strings.TrimSpace(line[1:]))
		}
	}

	return bullets
}

// FetchFileFromURL fetches a file from a URL (for downloading source code)
func (sa *SemanticAnalyzer) FetchFileFromURL(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := sa.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}
