package fetcher

import "errors"

// ErrPackageNotFound is returned when a package genuinely does not exist in the registry (HTTP 404).
// This is distinct from API failures (rate limits, network errors, server errors) which should
// not be treated as high-risk indicators but rather as requiring further investigation.
var ErrPackageNotFound = errors.New("package not found")
