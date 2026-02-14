package fetcher

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// Common user agent to avoid being blocked
const userAgent = "Mozilla/5.0 (compatible; Snyft/1.0; +https://github.com/metalstormbass/snyft)"

// scrapeWithUserAgent performs an HTTP GET with proper user-agent headers
func scrapeWithUserAgent(url string) (*goquery.Document, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("scraping returned status %d: %s", resp.StatusCode, string(body))
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	return doc, nil
}

// extractNumber extracts a number from text, removing commas and whitespace
func extractNumber(text string) int {
	// Remove commas and whitespace
	text = strings.TrimSpace(text)
	text = strings.ReplaceAll(text, ",", "")

	var multiplier int = 1

	// Handle k/K suffix for thousands
	if strings.HasSuffix(strings.ToLower(text), "k") {
		text = strings.TrimSuffix(strings.ToLower(text), "k")
		multiplier = 1000
	}

	// Try parsing as float first to handle decimal numbers
	var floatNum float64
	_, err := fmt.Sscanf(text, "%f", &floatNum)
	if err != nil {
		return 0
	}

	return int(floatNum * float64(multiplier))
}

// shouldFallbackToScraping checks if the error warrants falling back to scraping
func shouldFallbackToScraping(err error, statusCode int) bool {
	if err != nil {
		return true
	}
	// Rate limit or forbidden errors
	return statusCode == http.StatusForbidden ||
	       statusCode == http.StatusTooManyRequests ||
	       statusCode == http.StatusUnauthorized
}
