package fetcher

import "errors"

// ErrPackageNotFound is returned when a package genuinely does not exist in the registry (HTTP 404).
// This is distinct from API failures (rate limits, network errors, server errors) which should
// not be treated as high-risk indicators but rather as requiring further investigation.
var ErrPackageNotFound = errors.New("package not found")

// ErrRateLimited is returned when an API call fails due to rate limiting (HTTP 403/429).
// Since web scraping is the primary data source, this typically only occurs for
// API-only operations (commit history, tag checks). Callers should treat this as
// "data unavailable" rather than interpreting empty results as "no issues found".
var ErrRateLimited = errors.New("API rate limited")
