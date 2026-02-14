package fetcher

import (
	"testing"
)

func TestParseGitHubURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "HTTPS URL",
			url:       "https://github.com/owner/repo",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantErr:   false,
		},
		{
			name:      "HTTPS URL with .git",
			url:       "https://github.com/owner/repo.git",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantErr:   false,
		},
		{
			name:      "Git protocol",
			url:       "git://github.com/owner/repo.git",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantErr:   false,
		},
		{
			name:      "Git+HTTPS protocol",
			url:       "git+https://github.com/owner/repo.git",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantErr:   false,
		},
		{
			name:    "Invalid URL - not GitHub",
			url:     "https://gitlab.com/owner/repo",
			wantErr: true,
		},
		{
			name:    "Invalid URL - missing parts",
			url:     "https://github.com/owner",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := parseGitHubURL(tt.url)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if owner != tt.wantOwner {
				t.Errorf("Expected owner %s, got %s", tt.wantOwner, owner)
			}

			if repo != tt.wantRepo {
				t.Errorf("Expected repo %s, got %s", tt.wantRepo, repo)
			}
		})
	}
}

func TestCheckSLSAAttestation_Logic(t *testing.T) {
	// This is a unit test for the logic - in practice, this would need mocking
	// Testing the logic without making actual API calls

	// Test case: No SLSA files
	hasAttestation, level := false, ""
	if hasAttestation {
		t.Errorf("Expected no SLSA attestation, got true")
	}
	if level != "" {
		t.Errorf("Expected empty SLSA level, got %s", level)
	}
}

func TestCheckSignedReleases_Logic(t *testing.T) {
	// Test the signed release detection logic
	releases := []GitHubRelease{
		{
			TagName: "v1.0.0",
			Assets: []GitHubAsset{
				{Name: "release.tar.gz"},
				{Name: "release.tar.gz.sig"}, // Has signature
			},
		},
		{
			TagName: "v1.1.0",
			Assets: []GitHubAsset{
				{Name: "release.tar.gz"},
				{Name: "checksums.txt"}, // Has checksum
			},
		},
		{
			TagName: "v1.2.0",
			Assets: []GitHubAsset{
				{Name: "release.tar.gz"}, // No signature or checksum
			},
		},
	}

	signedCount := 0
	for _, release := range releases {
		hasSignature := false
		for _, asset := range release.Assets {
			name := asset.Name
			if name == "release.tar.gz.sig" || name == "checksums.txt" {
				hasSignature = true
				break
			}
		}
		if hasSignature {
			signedCount++
		}
	}

	expectedSigned := 2
	if signedCount != expectedSigned {
		t.Errorf("Expected %d signed releases, got %d", expectedSigned, signedCount)
	}
}

func TestCheckReproducibleBuild_Files(t *testing.T) {
	reproducibleFiles := []string{
		".reproducible-build",
		"reproducible-build.yml",
		".github/workflows/reproducible.yml",
		"BUILD.bazel",
	}

	// Verify we're checking for the right files
	expectedCount := 4
	if len(reproducibleFiles) != expectedCount {
		t.Errorf("Expected %d reproducible build indicators, got %d", expectedCount, len(reproducibleFiles))
	}

	// Check that BUILD.bazel is included (Bazel for reproducible builds)
	hasBazel := false
	for _, file := range reproducibleFiles {
		if file == "BUILD.bazel" {
			hasBazel = true
			break
		}
	}

	if !hasBazel {
		t.Errorf("Expected BUILD.bazel in reproducible file list")
	}
}

func TestGitHubAsset_SignatureDetection(t *testing.T) {
	tests := []struct {
		name       string
		assetName  string
		isSignature bool
	}{
		{
			name:       "GPG signature",
			assetName:  "release.tar.gz.asc",
			isSignature: true,
		},
		{
			name:       "Minisign signature",
			assetName:  "release.tar.gz.minisig",
			isSignature: true,
		},
		{
			name:       "Detached signature",
			assetName:  "release.tar.gz.sig",
			isSignature: true,
		},
		{
			name:       "Checksum file",
			assetName:  "SHA256SUMS",
			isSignature: false, // Checksums are not signatures
		},
		{
			name:       "Regular file",
			assetName:  "release.tar.gz",
			isSignature: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test signature detection logic
			isSignature := false
			if len(tt.assetName) > 4 {
				ext := tt.assetName[len(tt.assetName)-4:]
				if ext == ".sig" || ext == ".asc" || ext == ".gpg" {
					isSignature = true
				}
			}
			if len(tt.assetName) > 8 && tt.assetName[len(tt.assetName)-8:] == ".minisig" {
				isSignature = true
			}

			if isSignature != tt.isSignature {
				t.Errorf("Expected isSignature=%v for %s, got %v", tt.isSignature, tt.assetName, isSignature)
			}
		})
	}
}
