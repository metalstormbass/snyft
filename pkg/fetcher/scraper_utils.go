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

// scrapeClient is a shared HTTP client for all scraping requests. Reusing a
// single client enables HTTP keep-alive and connection pooling across the many
// scraping calls within a scan, avoiding the overhead of a fresh TCP+TLS
// handshake per request.
var scrapeClient = &http.Client{
	Timeout: 10 * time.Second,
}

// scrapeWithUserAgent performs an HTTP GET with proper user-agent headers.
// This is the primary data-fetching mechanism when no API tokens are configured.
func scrapeWithUserAgent(url string) (*goquery.Document, error) {
	client := scrapeClient

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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			return nil, fmt.Errorf("scraping returned status %d: %w", resp.StatusCode, ErrScrapingRateLimited)
		case http.StatusForbidden:
			return nil, fmt.Errorf("scraping returned status %d: %w", resp.StatusCode, ErrScrapingAccessDenied)
		default:
			return nil, fmt.Errorf("scraping returned status %d", resp.StatusCode)
		}
	}

	// Cap response body at 5 MB to prevent excessive memory usage on
	// unexpectedly large pages.
	const maxBodySize = 5 * 1024 * 1024
	doc, err := goquery.NewDocumentFromReader(io.LimitReader(resp.Body, maxBodySize))
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

	multiplier := 1

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

// maxPaginationPages is the upper bound on the number of pages fetched during
// paginated API calls or web scraping. This prevents infinite loops when an
// API returns a "next" link indefinitely and bounds the total request count.
const maxPaginationPages = 50

// parseLinkHeaderNextURL extracts the "next" URL from an HTTP Link header.
// GitHub and GitLab APIs use RFC 8288 Link headers for pagination, e.g.:
//
//	Link: <https://api.github.com/repos/o/r/releases?page=2>; rel="next", ...
//
// Returns "" when there is no "next" relation.
func parseLinkHeaderNextURL(header string) string {
	if header == "" {
		return ""
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		// Extract URL between < and >
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start >= 0 && end > start {
			return part[start+1 : end]
		}
	}
	return ""
}

// shouldFallbackToScraping checks if the API response warrants trying an
// alternative data source (scraping or raw URLs). Used when the API is the
// primary path (token set) and needs to fall back.
func shouldFallbackToScraping(err error, statusCode int) bool {
	if err != nil {
		return true
	}
	// Rate limit or forbidden errors
	return statusCode == http.StatusForbidden ||
	       statusCode == http.StatusTooManyRequests ||
	       statusCode == http.StatusUnauthorized
}
