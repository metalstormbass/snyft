package fetcher

import "testing"

// Test: NormalizeRepoURL produces stable cache keys from URL variants
// Justification: The same repository can appear under many URL forms across
//                different package registries. Normalization ensures that
//                "https://github.com/org/repo.git", "git+https://github.com/org/repo",
//                and "https://github.com/ORG/REPO" all map to the same cache key.
//                Without normalization, packages from the same repo would be analyzed
//                independently — defeating the repo-level dedup optimization.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — accurate repo
//         identification is essential for correct risk assessment
// Methodology: Test various URL forms and verify they normalize to the same key
// Result: All variants of the same repo produce identical cache keys
func TestNormalizeRepoURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		// Basic HTTPS URLs
		{
			name: "simple https",
			url:  "https://github.com/aws/aws-sdk-java",
			want: "github.com/aws/aws-sdk-java",
		},
		{
			name: "https with .git suffix",
			url:  "https://github.com/aws/aws-sdk-java.git",
			want: "github.com/aws/aws-sdk-java",
		},

		// git+ prefix
		{
			name: "git+https prefix",
			url:  "git+https://github.com/org/repo.git",
			want: "github.com/org/repo",
		},

		// Case normalization
		{
			name: "mixed case owner/repo",
			url:  "https://github.com/AWS/Aws-Sdk-Java",
			want: "github.com/aws/aws-sdk-java",
		},

		// Other platforms
		{
			name: "gitlab",
			url:  "https://gitlab.com/org/project",
			want: "gitlab.com/org/project",
		},
		{
			name: "bitbucket",
			url:  "https://bitbucket.org/org/repo",
			want: "bitbucket.org/org/repo",
		},

		// Edge cases
		{
			name: "empty string",
			url:  "",
			want: "",
		},
		{
			name: "ssh URL",
			url:  "git@github.com:org/repo.git",
			want: "github.com/org/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeRepoURL(tt.url)
			if got != tt.want {
				t.Errorf("NormalizeRepoURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

// Test: NormalizeRepoURL produces identical keys for same-repo URL variants
// Justification: Multiple URL forms for the same repo must normalize to the
//                same key for the repo analysis cache to work correctly.
// Source: Cache correctness — different keys for the same repo means
//         duplicate repo analysis, defeating the optimization
// Methodology: Compare pairs of URLs that should normalize to the same key
// Result: All URL variants for the same repo produce the same cache key
func TestNormalizeRepoURL_SameRepoVariants(t *testing.T) {
	variants := []string{
		"https://github.com/aws/aws-sdk-java",
		"https://github.com/aws/aws-sdk-java.git",
		"git+https://github.com/aws/aws-sdk-java.git",
		"https://github.com/AWS/aws-sdk-java",
		"git@github.com:aws/aws-sdk-java.git",
	}

	expected := NormalizeRepoURL(variants[0])
	for _, v := range variants[1:] {
		got := NormalizeRepoURL(v)
		if got != expected {
			t.Errorf("NormalizeRepoURL(%q) = %q, want %q (same as %q)", v, got, expected, variants[0])
		}
	}
}
