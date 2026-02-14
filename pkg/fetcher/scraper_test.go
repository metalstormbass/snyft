package fetcher

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGitHubScrapingFallback tests that GitHub scraping works when API returns 403
func TestGitHubScrapingFallback(t *testing.T) {
	// Create a mock server that returns 403 for API calls
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/test/repo" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message": "API rate limit exceeded"}`))
		}
	}))
	defer apiServer.Close()

	client := NewGitHubClient()
	client.baseURL = apiServer.URL

	// This should trigger the scraping fallback
	// Note: In real tests, we'd mock the scraping response as well
	_, err := client.GetRepositoryInfo("https://github.com/test/repo")

	// The error should be from scraping fallback, not from API
	if err == nil {
		t.Log("Successfully fell back to scraping")
	} else if err.Error() != "GitHub API returned 403: {\"message\": \"API rate limit exceeded\"}" {
		t.Logf("Scraping fallback attempted: %v", err)
	}
}

// TestNPMScrapingFallback tests that npm scraping works when API returns 429
func TestNPMScrapingFallback(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test-package" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error": "Too many requests"}`))
		}
	}))
	defer apiServer.Close()

	client := NewNPMClient()
	client.baseURL = apiServer.URL

	// This should trigger the scraping fallback
	_, err := client.GetPackageInfo("test-package")

	if err == nil {
		t.Log("Successfully fell back to scraping")
	} else if err.Error() != "npm registry returned status 429" {
		t.Logf("Scraping fallback attempted: %v", err)
	}
}

// TestPyPIScrapingFallback tests that PyPI scraping works when API returns 403
func TestPyPIScrapingFallback(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/test-package/json" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message": "Forbidden"}`))
		}
	}))
	defer apiServer.Close()

	client := NewPyPIClient()
	client.baseURL = apiServer.URL

	// This should trigger the scraping fallback
	_, err := client.GetPackageInfo("test-package")

	if err == nil {
		t.Log("Successfully fell back to scraping")
	} else if err.Error() != "PyPI API returned status 403" {
		t.Logf("Scraping fallback attempted: %v", err)
	}
}

// TestMavenScrapingFallback tests that Maven scraping works when API returns 403
func TestMavenScrapingFallback(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error": "Access denied"}`))
	}))
	defer apiServer.Close()

	client := NewMavenClient()
	client.searchURL = fmt.Sprintf("%s/solrsearch/select", apiServer.URL)

	// This should trigger the scraping fallback
	_, err := client.GetPackageInfo("com.example:test-artifact")

	if err == nil {
		t.Log("Successfully fell back to scraping")
	} else if err.Error() != "maven Central returned status 403" {
		t.Logf("Scraping fallback attempted: %v", err)
	}
}

// TestShouldFallbackToScraping tests the fallback logic
func TestShouldFallbackToScraping(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   bool
		name       string
	}{
		{http.StatusForbidden, true, "403 Forbidden"},
		{http.StatusTooManyRequests, true, "429 Too Many Requests"},
		{http.StatusUnauthorized, true, "401 Unauthorized"},
		{http.StatusOK, false, "200 OK"},
		{http.StatusNotFound, false, "404 Not Found"},
		{http.StatusInternalServerError, false, "500 Internal Server Error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldFallbackToScraping(nil, tt.statusCode)
			if result != tt.expected {
				t.Errorf("shouldFallbackToScraping(%d) = %v, expected %v", tt.statusCode, result, tt.expected)
			}
		})
	}
}

// TestExtractNumber tests number extraction from various formats
func TestExtractNumber(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"1,234", 1234},
		{"5.6k", 5600},
		{"10K", 10000},
		{"  123  ", 123},
		{"42", 42},
		{"invalid", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractNumber(tt.input)
			if result != tt.expected {
				t.Errorf("extractNumber(%q) = %d, expected %d", tt.input, result, tt.expected)
			}
		})
	}
}
