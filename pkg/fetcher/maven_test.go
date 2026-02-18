package fetcher

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Test: normalizeSCMURL strips extra path segments from known hosting prefixes
// Justification: Malformed SCM URLs with extra segments (e.g. /owner/repo/subdir/)
//
//	prevent the GitHub/GitLab clients from resolving the repository, causing
//	source code verification to fail and producing misleading risk scores.
//
// Source: Observed in the wild (mapstruct POM) during mike-libraries testing.
// Methodology: Unit test against known good and bad URL patterns.
// Result: URLs are truncated to owner/repo; non-hosting URLs are returned unchanged.
func TestNormalizeSCMURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "clean GitHub URL unchanged",
			input: "https://github.com/owner/repo",
			want:  "https://github.com/owner/repo",
		},
		{
			name:  "GitHub URL with trailing slash",
			input: "https://github.com/owner/repo/",
			want:  "https://github.com/owner/repo",
		},
		{
			name:  "GitHub URL with extra path segment",
			input: "https://github.com/mapstruct/mapstruct/mapstruct/",
			want:  "https://github.com/mapstruct/mapstruct",
		},
		{
			name:  "GitHub URL with .git suffix",
			input: "https://github.com/owner/repo.git",
			want:  "https://github.com/owner/repo",
		},
		{
			name:  "GitLab URL normalized",
			input: "https://gitlab.com/group/project/extra",
			want:  "https://gitlab.com/group/project",
		},
		{
			name:  "Bitbucket URL normalized",
			input: "https://bitbucket.org/owner/repo/src",
			want:  "https://bitbucket.org/owner/repo",
		},
		{
			name:  "non-hosting URL returned unchanged",
			input: "https://gitbox.apache.org/repos/asf/commons-lang.git",
			want:  "https://gitbox.apache.org/repos/asf/commons-lang.git",
		},
		{
			name:  "empty string returns empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSCMURL(tt.input)
			if got != tt.want {
				t.Errorf("normalizeSCMURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Test: enrichFromPOM falls back to parent POM when artifact POM has no SCM
// Justification: Multi-module Maven projects (guava, jjwt, springdoc) store
//
//	the SCM URL only in the root/parent POM. Without this fallback, snyft
//	cannot detect the source repository, preventing all source verification
//	checks and producing artificially high risk scores.
//
// Source: Maven POM reference — <scm> is inherited from parent.
//
//	https://maven.apache.org/pom.html#scm
//
// Methodology: Mock HTTP server serves artifact POM (no SCM) and parent POM
//
//	(with SCM). Verify that enrichFromPOM populates RepositoryURL.
//
// Result: pkg.RepositoryURL is set from the parent POM's <scm><url>.
func TestEnrichFromPOM_ParentFallback(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>child-artifact</artifactId>
  <version>1.0.0</version>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent-pom</artifactId>
    <version>2.0.0</version>
  </parent>
</project>`

	parentPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>parent-pom</artifactId>
  <version>2.0.0</version>
  <scm>
    <url>https://github.com/example/parent-repo</url>
    <connection>scm:git:https://github.com/example/parent-repo.git</connection>
  </scm>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/child-artifact/1.0.0/child-artifact-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, artifactPOM)
	})
	mux.HandleFunc("/com/example/parent-pom/2.0.0/parent-pom-2.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, parentPOM)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	pkg := &MavenPackage{
		GroupID:    "com.example",
		ArtifactID: "child-artifact",
	}

	err := client.enrichFromPOM(pkg, "com.example", "child-artifact", "1.0.0")
	if err != nil {
		t.Fatalf("enrichFromPOM returned error: %v", err)
	}

	want := "https://github.com/example/parent-repo"
	if pkg.RepositoryURL != want {
		t.Errorf("RepositoryURL = %q, want %q", pkg.RepositoryURL, want)
	}
}

// Test: enrichFromPOM uses own SCM when present, does not fetch parent
// Justification: Confirms the primary path still works and we don't make
//
//	unnecessary parent POM requests when the artifact POM has its own SCM.
//
// Source: Standard Maven inheritance — own declaration overrides parent.
// Methodology: Mock server serves only the artifact POM with SCM; any request
//
//	for a parent POM returns 404.
//
// Result: pkg.RepositoryURL is set from the artifact POM's own <scm><url>.
func TestEnrichFromPOM_OwnSCMPreferred(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-lib</artifactId>
  <version>3.0.0</version>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent-pom</artifactId>
    <version>1.0.0</version>
  </parent>
  <scm>
    <url>https://github.com/example/my-lib</url>
  </scm>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/my-lib/3.0.0/my-lib-3.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, artifactPOM)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Fail any unexpected request (e.g. parent POM fetch)
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	pkg := &MavenPackage{
		GroupID:    "com.example",
		ArtifactID: "my-lib",
	}

	err := client.enrichFromPOM(pkg, "com.example", "my-lib", "3.0.0")
	if err != nil {
		t.Fatalf("enrichFromPOM returned error: %v", err)
	}

	want := "https://github.com/example/my-lib"
	if pkg.RepositoryURL != want {
		t.Errorf("RepositoryURL = %q, want %q", pkg.RepositoryURL, want)
	}
}

// Test: enrichFromPOM handles missing parent POM gracefully
// Justification: Parent POM may not exist on Maven Central (e.g. external BOM,
//
//	or a version that has been removed). The scan must continue with partial
//	data rather than crashing or returning an error.
//
// Source: Snyft design principle — degrade gracefully, never fail completely.
// Methodology: Mock server returns 404 for the parent POM URL.
// Result: enrichFromPOM returns nil, pkg.RepositoryURL remains empty.
func TestEnrichFromPOM_MissingParentPOM(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>orphan</artifactId>
  <version>1.0.0</version>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>ghost-parent</artifactId>
    <version>9.9.9</version>
  </parent>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/orphan/1.0.0/orphan-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, artifactPOM)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	pkg := &MavenPackage{
		GroupID:    "com.example",
		ArtifactID: "orphan",
	}

	// Should not return error even though parent POM is missing
	err := client.enrichFromPOM(pkg, "com.example", "orphan", "1.0.0")
	if err != nil {
		t.Fatalf("enrichFromPOM should not error on missing parent POM, got: %v", err)
	}

	if pkg.RepositoryURL != "" {
		t.Errorf("RepositoryURL should be empty, got %q", pkg.RepositoryURL)
	}
}
