package fetcher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
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
			name:  "Apache gitbox path URL converted to GitHub mirror",
			input: "https://gitbox.apache.org/repos/asf/commons-lang.git",
			want:  "https://github.com/apache/commons-lang",
		},
		{
			name:  "Apache gitbox query-param URL converted to GitHub mirror",
			input: "https://gitbox.apache.org/repos/asf?p=commons-io.git",
			want:  "https://github.com/apache/commons-io",
		},
		{
			name:  "Apache gitbox query-param without .git suffix",
			input: "https://gitbox.apache.org/repos/asf?p=commons-io",
			want:  "https://github.com/apache/commons-io",
		},
		{
			name:  "Apache git.apache.org converted to GitHub mirror",
			input: "https://git.apache.org/repos/asf/tomcat.git",
			want:  "https://github.com/apache/tomcat",
		},
		{
			name:  "Apache gitbox path without .git suffix",
			input: "https://gitbox.apache.org/repos/asf/commons-io",
			want:  "https://github.com/apache/commons-io",
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

// Test: apacheGitboxToGitHub converts gitbox/git.apache.org URLs to GitHub mirrors
// Justification: Apache gitbox URLs route to the GenericGitClient which returns
//
//	ErrDataUnavailable for most risk checks.  Converting to the GitHub
//	mirror enables full risk assessment via the GitHub API.
//
// Source: https://infra.apache.org/github-actions-policy.html —
//
//	all Apache projects are mirrored on GitHub.
//
// Methodology: Unit test against known gitbox URL formats found in POM files.
// Result: Gitbox URLs are converted to https://github.com/apache/<repo>.
func TestApacheGitboxToGitHub(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "path-based with .git suffix",
			input: "https://gitbox.apache.org/repos/asf/commons-lang.git",
			want:  "https://github.com/apache/commons-lang",
		},
		{
			name:  "path-based without .git suffix",
			input: "https://gitbox.apache.org/repos/asf/commons-io",
			want:  "https://github.com/apache/commons-io",
		},
		{
			name:  "query-param style with .git",
			input: "https://gitbox.apache.org/repos/asf?p=commons-io.git",
			want:  "https://github.com/apache/commons-io",
		},
		{
			name:  "query-param style without .git",
			input: "https://gitbox.apache.org/repos/asf?p=commons-io",
			want:  "https://github.com/apache/commons-io",
		},
		{
			name:  "git.apache.org domain",
			input: "https://git.apache.org/repos/asf/tomcat.git",
			want:  "https://github.com/apache/tomcat",
		},
		{
			name:  "trailing slash stripped",
			input: "https://gitbox.apache.org/repos/asf/commons-math/",
			want:  "https://github.com/apache/commons-math",
		},
		{
			name:  "non-apache URL returns empty",
			input: "https://github.com/apache/commons-lang",
			want:  "",
		},
		{
			name:  "empty string returns empty",
			input: "",
			want:  "",
		},
		{
			name:  "listing page URL without repo returns empty",
			input: "https://gitbox.apache.org/repos/asf",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := apacheGitboxToGitHub(tt.input)
			if got != tt.want {
				t.Errorf("apacheGitboxToGitHub(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Test: enrichFromPOM converts gitbox SCM URL to GitHub mirror
// Justification: When a POM's <scm><url> points to gitbox.apache.org, the
//
//	resulting RepositoryURL should be the GitHub mirror so that the tool
//	can perform full risk assessment via the GitHub API.  Without this
//	conversion, the GenericGitClient is used and most risk signals are
//	unavailable (ErrDataUnavailable).
//
// Source: https://infra.apache.org/github-actions-policy.html —
//
//	all Apache projects are mirrored on GitHub.
//
// Methodology: Mock HTTP server serves a POM with a gitbox SCM URL.
//
//	Verify that enrichFromPOM converts it to the GitHub mirror.
//
// Result: pkg.RepositoryURL is set to https://github.com/apache/<repo>.
func TestEnrichFromPOM_GitboxSCMConverted(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-io</artifactId>
  <version>2.15.0</version>
  <scm>
    <url>https://gitbox.apache.org/repos/asf/commons-io.git</url>
    <connection>scm:git:https://gitbox.apache.org/repos/asf/commons-io.git</connection>
  </scm>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/org/apache/commons/commons-io/2.15.0/commons-io-2.15.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprint(w, artifactPOM)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	pkg := &MavenPackage{
		GroupID:    "org.apache.commons",
		ArtifactID: "commons-io",
	}

	err := client.enrichFromPOM(pkg, "org.apache.commons", "commons-io", "2.15.0")
	if err != nil {
		t.Fatalf("enrichFromPOM returned error: %v", err)
	}

	want := "https://github.com/apache/commons-io"
	if pkg.RepositoryURL != want {
		t.Errorf("RepositoryURL = %q, want %q", pkg.RepositoryURL, want)
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
		_, _ = fmt.Fprint(w, artifactPOM)
	})
	mux.HandleFunc("/com/example/parent-pom/2.0.0/parent-pom-2.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprint(w, parentPOM)
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
		_, _ = fmt.Fprint(w, artifactPOM)
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
		_, _ = fmt.Fprint(w, artifactPOM)
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

// Test: enrichFromPOM extracts repo URL from POM <url> when SCM is missing
// Justification: Many Maven POMs set the <url> element to their GitHub page
//
//	even when <scm> is absent.  Without this fallback, snyft cannot find
//	the source repository, preventing provenance and health checks from
//	running and inflating the risk score.
//
// Source: Maven Central publishing requirements — <url> is a required field.
//
//	https://central.sonatype.org/publish/requirements/
//
// Methodology: Mock server serves a POM with <url> pointing to GitHub but no
//
//	<scm> element.  Verify that enrichFromPOM populates RepositoryURL.
//
// Result: pkg.RepositoryURL is set from the POM's <url> element.
func TestEnrichFromPOM_URLFallback(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>url-only</artifactId>
  <version>1.0.0</version>
  <url>https://github.com/example/url-only</url>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/url-only/1.0.0/url-only-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, artifactPOM)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	pkg := &MavenPackage{GroupID: "com.example", ArtifactID: "url-only"}
	err := client.enrichFromPOM(pkg, "com.example", "url-only", "1.0.0")
	if err != nil {
		t.Fatalf("enrichFromPOM returned error: %v", err)
	}

	want := "https://github.com/example/url-only"
	if pkg.RepositoryURL != want {
		t.Errorf("RepositoryURL = %q, want %q", pkg.RepositoryURL, want)
	}
}

// Test: enrichFromPOM ignores POM <url> that is not a git hosting provider
// Justification: The <url> element often points to marketing sites (e.g.
//
//	spring.io, hibernate.org).  Accepting these would cause the git platform
//	client to fail and produce misleading risk data.
//
// Source: Observed in the wild — many popular packages set <url> to docs/homepage.
// Methodology: Mock server serves a POM with <url> pointing to a non-repo host.
// Result: pkg.RepositoryURL remains empty.
func TestEnrichFromPOM_URLIgnoredForNonRepoHost(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>marketing</artifactId>
  <version>1.0.0</version>
  <url>https://example.com/marketing-page</url>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/marketing/1.0.0/marketing-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, artifactPOM)
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

	pkg := &MavenPackage{GroupID: "com.example", ArtifactID: "marketing"}
	_ = client.enrichFromPOM(pkg, "com.example", "marketing", "1.0.0")

	if pkg.RepositoryURL != "" {
		t.Errorf("RepositoryURL should be empty for non-repo host, got %q", pkg.RepositoryURL)
	}
}

// Test: enrichFromPOM extracts repo URL from issueManagement URL
// Justification: Some POMs lack both <scm> and a repo-pointing <url> but
//
//	include an <issueManagement> element pointing to GitHub Issues.
//	Stripping the /issues suffix reveals the source repository, enabling
//	provenance and health checks that would otherwise be skipped.
//
// Source: Maven POM reference — <issueManagement> often mirrors the repo host.
// Methodology: Mock server serves a POM with only <issueManagement> URL.
// Result: pkg.RepositoryURL is derived by stripping /issues from the URL.
func TestEnrichFromPOM_IssueManagementFallback(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>issues-only</artifactId>
  <version>1.0.0</version>
  <url>https://example.com/docs</url>
  <issueManagement>
    <system>GitHub Issues</system>
    <url>https://github.com/example/issues-only/issues</url>
  </issueManagement>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/issues-only/1.0.0/issues-only-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, artifactPOM)
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

	pkg := &MavenPackage{GroupID: "com.example", ArtifactID: "issues-only"}
	err := client.enrichFromPOM(pkg, "com.example", "issues-only", "1.0.0")
	if err != nil {
		t.Fatalf("enrichFromPOM returned error: %v", err)
	}

	want := "https://github.com/example/issues-only"
	if pkg.RepositoryURL != want {
		t.Errorf("RepositoryURL = %q, want %q", pkg.RepositoryURL, want)
	}
}

// Test: deriveRepoFromGroupID maps well-known groupId prefixes to repo URLs
// Justification: Sonatype requires domain verification for io.github.*,
//
//	com.github.*, io.gitlab.*, and io.bitbucket.* prefixes.  Additionally,
//	well-known Java foundations (Apache, Eclipse) and major OSS organizations
//	(FasterXML, Square) host source code on GitHub with predictable naming.
//	When all POM-based strategies fail, the groupId itself is a high-confidence
//	signal for the source repository location.  Missing the repo prevents
//	all git-based risk checks (provenance, health, governance).
//
// Source: https://central.sonatype.org/publish/requirements/coordinates/
//
//	https://infra.apache.org/github-actions-policy.html (Apache → GitHub)
//	https://github.com/FasterXML, https://github.com/square
//
// Methodology: Unit test against each well-known prefix pattern.
// Result: Correct repository URL is derived from the groupId + artifactId.
func TestDeriveRepoFromGroupID(t *testing.T) {
	tests := []struct {
		name       string
		groupID    string
		artifactID string
		want       string
	}{
		{
			name:       "io.github prefix",
			groupID:    "io.github.openfeign",
			artifactID: "feign-core",
			want:       "https://github.com/openfeign/feign-core",
		},
		{
			name:       "com.github prefix (JitPack convention)",
			groupID:    "com.github.javaparser",
			artifactID: "javaparser-core",
			want:       "https://github.com/javaparser/javaparser-core",
		},
		{
			name:       "io.gitlab prefix",
			groupID:    "io.gitlab.myuser",
			artifactID: "my-lib",
			want:       "https://gitlab.com/myuser/my-lib",
		},
		{
			name:       "io.bitbucket prefix",
			groupID:    "io.bitbucket.myteam",
			artifactID: "toolkit",
			want:       "https://bitbucket.org/myteam/toolkit",
		},
		{
			name:       "org.eclipse prefix",
			groupID:    "org.eclipse.jgit",
			artifactID: "org.eclipse.jgit",
			want:       "https://github.com/eclipse/org.eclipse.jgit",
		},
		{
			name:       "org.apache prefix (Apache Foundation on GitHub)",
			groupID:    "org.apache.commons",
			artifactID: "commons-lang3",
			want:       "https://github.com/apache/commons-lang3",
		},
		{
			name:       "com.fasterxml prefix (FasterXML/Jackson on GitHub)",
			groupID:    "com.fasterxml.jackson.core",
			artifactID: "jackson-databind",
			want:       "https://github.com/FasterXML/jackson-databind",
		},
		{
			name:       "com.squareup prefix (Square on GitHub)",
			groupID:    "com.squareup.okhttp3",
			artifactID: "okhttp",
			want:       "https://github.com/square/okhttp",
		},
		{
			name:       "unrecognised prefix returns empty",
			groupID:    "com.zaxxer",
			artifactID: "HikariCP",
			want:       "",
		},
		{
			name:       "too-short groupId returns empty",
			groupID:    "io.github",
			artifactID: "something",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveRepoFromGroupID(tt.groupID, tt.artifactID)
			if got != tt.want {
				t.Errorf("deriveRepoFromGroupID(%q, %q) = %q, want %q",
					tt.groupID, tt.artifactID, got, tt.want)
			}
		})
	}
}

// Test: repoFromIssueURL strips /issues suffix from known hosting URLs
// Justification: Issue tracker URLs that point to known git hosts contain
//
//	the repository path.  Correctly deriving the repo URL enables source
//	verification checks for packages that lack <scm>.
//
// Source: Observed in the wild — many Apache and Eclipse POMs use this pattern.
// Methodology: Unit test against URLs with and without /issues suffix.
// Result: Known-host URLs have /issues stripped; non-repo hosts return empty.
func TestRepoFromIssueURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "GitHub issues URL",
			input: "https://github.com/owner/repo/issues",
			want:  "https://github.com/owner/repo",
		},
		{
			name:  "GitLab issues URL with /-/ prefix",
			input: "https://gitlab.com/group/project/-/issues",
			want:  "https://gitlab.com/group/project",
		},
		{
			name:  "non-repo host returns empty",
			input: "https://jira.example.com/browse/PROJ",
			want:  "",
		},
		{
			name:  "empty string returns empty",
			input: "",
			want:  "",
		},
		{
			name:  "repo host without /issues suffix returns empty",
			input: "https://github.com/owner/repo",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := repoFromIssueURL(tt.input)
			if got != tt.want {
				t.Errorf("repoFromIssueURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Test: enrichFromDepsDev extracts repo URL from deps.dev links
// Justification: deps.dev aggregates metadata across Maven Central and
//
//	normalises POM fields.  It succeeds for packages where our own POM
//	parsing finds nothing, significantly improving source discovery hit
//	rate and enabling risk checks that depend on repository access.
//
// Source: https://docs.deps.dev/api/v3/
// Methodology: Mock HTTP server returns a deps.dev-shaped JSON response
//
//	with a SOURCE_REPO link.  Verify that enrichFromDepsDev populates
//	RepositoryURL.
//
// Result: pkg.RepositoryURL is set from the deps.dev SOURCE_REPO link.
func TestEnrichFromDepsDev_Links(t *testing.T) {
	depsResp := depsDevVersionResponse{
		Links: []depsDevLink{
			{Label: "HOMEPAGE", URL: "https://example.com"},
			{Label: "SOURCE_REPO", URL: "https://github.com/example/my-lib.git"},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(depsResp)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
		depsDevURL: srv.URL,
	}

	pkg := &MavenPackage{
		GroupID:       "com.example",
		ArtifactID:    "my-lib",
		LatestVersion: "1.0.0",
	}

	err := client.enrichFromDepsDev(pkg)
	if err != nil {
		t.Fatalf("enrichFromDepsDev returned error: %v", err)
	}

	want := "https://github.com/example/my-lib"
	if pkg.RepositoryURL != want {
		t.Errorf("RepositoryURL = %q, want %q", pkg.RepositoryURL, want)
	}
}

// Test: enrichFromDepsDev falls back to relatedProjects when links are empty
// Justification: Some deps.dev responses provide the project key in
//
//	relatedProjects rather than as a direct link.  Supporting both paths
//	maximises the hit rate for source repository discovery.
//
// Source: https://docs.deps.dev/api/v3/
// Methodology: Mock server returns a response with only relatedProjects.
// Result: pkg.RepositoryURL is derived from the relatedProjects project key.
func TestEnrichFromDepsDev_RelatedProjects(t *testing.T) {
	depsResp := depsDevVersionResponse{
		Links: []depsDevLink{
			{Label: "HOMEPAGE", URL: "https://example.com"},
		},
		RelatedProjects: []depsDevRelatedProject{
			{
				ProjectKey:         depsDevProjectKey{ID: "github.com/example/fallback-lib"},
				RelationType:       "SOURCE_REPO",
				RelationProvenance: "UNVERIFIED_METADATA",
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(depsResp)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
		depsDevURL: srv.URL,
	}

	pkg := &MavenPackage{
		GroupID:       "com.example",
		ArtifactID:    "fallback-lib",
		LatestVersion: "2.0.0",
	}

	err := client.enrichFromDepsDev(pkg)
	if err != nil {
		t.Fatalf("enrichFromDepsDev returned error: %v", err)
	}

	want := "https://github.com/example/fallback-lib"
	if pkg.RepositoryURL != want {
		t.Errorf("RepositoryURL = %q, want %q", pkg.RepositoryURL, want)
	}
}

// Test: enrichFromDepsDev handles API failure gracefully
// Justification: deps.dev may be unavailable or rate-limited.  A failure
//
//	must not crash the scan or inflate risk scores — the tool should
//	degrade gracefully and continue with partial data.
//
// Source: Snyft design principle — degrade gracefully, never fail completely.
// Methodology: Mock server returns 500.  Verify enrichFromDepsDev returns
//
//	an error and RepositoryURL remains empty.
//
// Result: Error is returned, RepositoryURL is empty.
func TestEnrichFromDepsDev_APIFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
		depsDevURL: srv.URL,
	}

	pkg := &MavenPackage{
		GroupID:       "com.example",
		ArtifactID:    "fail-lib",
		LatestVersion: "1.0.0",
	}

	err := client.enrichFromDepsDev(pkg)
	if err == nil {
		t.Fatal("enrichFromDepsDev should return error on API failure")
	}

	if pkg.RepositoryURL != "" {
		t.Errorf("RepositoryURL should be empty on API failure, got %q", pkg.RepositoryURL)
	}
}

// Test: enrichFromPOM fallback chain ordering — SCM takes priority over <url>
// Justification: When both <scm> and <url> are present with different values,
//
//	the <scm> URL must be preferred because it explicitly declares the source
//	control location, while <url> can be a documentation or marketing site.
//	Using the wrong URL causes git platform checks to fail.
//
// Source: Maven POM reference — <scm> is the authoritative source control
//
//	declaration.  https://maven.apache.org/pom.html#scm
//
// Methodology: Mock server serves a POM with both <scm> and <url> pointing
//
//	to different GitHub repos.  Verify SCM takes priority.
//
// Result: pkg.RepositoryURL is set from <scm>, not <url>.
func TestEnrichFromPOM_SCMTakesPriorityOverURL(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>priority-test</artifactId>
  <version>1.0.0</version>
  <url>https://github.com/example/wrong-repo</url>
  <scm>
    <url>https://github.com/example/correct-repo</url>
  </scm>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/priority-test/1.0.0/priority-test-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, artifactPOM)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	pkg := &MavenPackage{GroupID: "com.example", ArtifactID: "priority-test"}
	err := client.enrichFromPOM(pkg, "com.example", "priority-test", "1.0.0")
	if err != nil {
		t.Fatalf("enrichFromPOM returned error: %v", err)
	}

	want := "https://github.com/example/correct-repo"
	if pkg.RepositoryURL != want {
		t.Errorf("RepositoryURL = %q, want %q (SCM should take priority over <url>)", pkg.RepositoryURL, want)
	}
}

// Test: enrichFromPOM uses groupId heuristic when POM/parent have no repo info
// Justification: Packages with io.github.* groupIds are verified by Sonatype
//
//	to match the GitHub username.  When all POM-based strategies fail, the
//	groupId heuristic provides a high-confidence repo URL, enabling risk
//	checks that would otherwise be entirely skipped.
//
// Source: https://central.sonatype.org/publish/requirements/coordinates/
// Methodology: Mock server serves a POM with no SCM, no repo-pointing <url>,
//
//	and no parent.  The package uses an io.github.* groupId.  Verify that
//	the groupId heuristic populates RepositoryURL.
//
// Result: pkg.RepositoryURL is derived from the groupId pattern.
func TestEnrichFromPOM_GroupIdHeuristic(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>io.github.openfeign</groupId>
  <artifactId>feign-core</artifactId>
  <version>13.0</version>
  <url>https://feign.io</url>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/io/github/openfeign/feign-core/13.0/feign-core-13.0.pom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, artifactPOM)
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

	pkg := &MavenPackage{GroupID: "io.github.openfeign", ArtifactID: "feign-core"}
	err := client.enrichFromPOM(pkg, "io.github.openfeign", "feign-core", "13.0")
	if err != nil {
		t.Fatalf("enrichFromPOM returned error: %v", err)
	}

	want := "https://github.com/openfeign/feign-core"
	if pkg.RepositoryURL != want {
		t.Errorf("RepositoryURL = %q, want %q", pkg.RepositoryURL, want)
	}
}

// Test: enrichFromPOM extracts developer info from POM <developers> section
// Justification: Maven Central does not expose a maintainer list via its API.
//
//	POM developers serve as proxy for maintainer/publisher data, enabling
//	Publisher Control (Category 1) assessment that would otherwise score
//	UNAVAILABLE for all Maven packages.
//
// Source: Maven POM reference — https://maven.apache.org/pom.html#developers
// Methodology: Mock server serves a POM with <developers> section. Verify that
//
//	enrichFromPOM populates the Developers field on MavenPackage.
//
// Result: pkg.Developers contains the developer entries from the POM.
func TestEnrichFromPOM_ExtractsDevelopers(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>dev-lib</artifactId>
  <version>1.0.0</version>
  <scm>
    <url>https://github.com/example/dev-lib</url>
  </scm>
  <developers>
    <developer>
      <id>alice</id>
      <name>Alice Smith</name>
      <email>alice@example.com</email>
      <organization>Example Corp</organization>
    </developer>
    <developer>
      <id>bob</id>
      <name>Bob Jones</name>
      <email>bob@example.com</email>
    </developer>
  </developers>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/dev-lib/1.0.0/dev-lib-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, artifactPOM)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	pkg := &MavenPackage{GroupID: "com.example", ArtifactID: "dev-lib"}
	err := client.enrichFromPOM(pkg, "com.example", "dev-lib", "1.0.0")
	if err != nil {
		t.Fatalf("enrichFromPOM returned error: %v", err)
	}

	if len(pkg.Developers) != 2 {
		t.Fatalf("expected 2 developers, got %d", len(pkg.Developers))
	}

	if pkg.Developers[0].Name != "Alice Smith" {
		t.Errorf("first developer name = %q, want %q", pkg.Developers[0].Name, "Alice Smith")
	}
	if pkg.Developers[0].Email != "alice@example.com" {
		t.Errorf("first developer email = %q, want %q", pkg.Developers[0].Email, "alice@example.com")
	}
	if pkg.Developers[0].Organization != "Example Corp" {
		t.Errorf("first developer org = %q, want %q", pkg.Developers[0].Organization, "Example Corp")
	}
	if pkg.Developers[1].ID != "bob" {
		t.Errorf("second developer id = %q, want %q", pkg.Developers[1].ID, "bob")
	}
}

// Test: enrichFromPOM counts non-test dependencies from POM
// Justification: Maven Central does not expose a dependency list via its API.
//
//	POM dependencies provide a dependency sprawl signal enabling
//	Dependency Sprawl (Category 5) assessment from Maven Central data alone,
//	even when no local pom.xml or source repository is available.
//
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Mock server serves a POM with mixed dependencies (compile + test).
//
//	Verify that enrichFromPOM counts only non-test dependencies.
//
// Result: pkg.DirectDepCount reflects only compile-scope dependencies.
func TestEnrichFromPOM_CountsDependencies(t *testing.T) {
	artifactPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>dep-lib</artifactId>
  <version>1.0.0</version>
  <scm>
    <url>https://github.com/example/dep-lib</url>
  </scm>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.0-jre</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>1.7.36</version>
      <scope>runtime</scope>
    </dependency>
  </dependencies>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/dep-lib/1.0.0/dep-lib-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, artifactPOM)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	pkg := &MavenPackage{GroupID: "com.example", ArtifactID: "dep-lib"}
	err := client.enrichFromPOM(pkg, "com.example", "dep-lib", "1.0.0")
	if err != nil {
		t.Fatalf("enrichFromPOM returned error: %v", err)
	}

	// 3 non-test deps: commons-lang3, guava, slf4j-api (runtime scope counts)
	if pkg.DirectDepCount != 3 {
		t.Errorf("DirectDepCount = %d, want 3 (exclude test scope)", pkg.DirectDepCount)
	}
}

// Test: enrichWithPublishDates fetches first and latest publish timestamps
// Justification: PublishedAt (first publish) feeds into Package Maturity age
//
//	assessment. LastPublishedAt feeds into staleness checks when no git repo
//	is available. Without these timestamps, Maven packages cannot be assessed
//	for age or staleness.
//
// Source: Maven Central Solr search API — timestamp field on version documents
// Methodology: Mock Solr API returns timestamps for oldest and newest versions.
// Result: pkg.PublishedAt and pkg.LastPublishedAt are populated from Solr data.
func TestEnrichWithPublishDates(t *testing.T) {
	callCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		sort := r.URL.Query().Get("sort")
		w.Header().Set("Content-Type", "application/json")

		if sort == "timestamp asc" {
			// Return oldest version
			_, _ = fmt.Fprint(w, `{"response":{"docs":[{"v":"1.0.0","timestamp":1400000000000}]}}`)
		} else {
			// Return newest version
			_, _ = fmt.Fprint(w, `{"response":{"docs":[{"v":"3.0.0","timestamp":1700000000000}]}}`)
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	pkg := &MavenPackage{GroupID: "com.example", ArtifactID: "dated-lib"}
	err := client.enrichWithPublishDates(pkg)
	if err != nil {
		t.Fatalf("enrichWithPublishDates returned error: %v", err)
	}

	if pkg.PublishedAt.IsZero() {
		t.Error("PublishedAt should not be zero after enrichment")
	}
	if pkg.LastPublishedAt.IsZero() {
		t.Error("LastPublishedAt should not be zero after enrichment")
	}
	if !pkg.PublishedAt.Before(pkg.LastPublishedAt) {
		t.Errorf("PublishedAt (%v) should be before LastPublishedAt (%v)",
			pkg.PublishedAt, pkg.LastPublishedAt)
	}
	if callCount != 2 {
		t.Errorf("expected 2 Solr API calls (oldest + newest), got %d", callCount)
	}
}

// Test: CheckGPGSignature detects .asc file presence
// Justification: GPG signatures on Maven Central indicate the publisher
//
//	followed proper release procedures. Presence feeds into Provenance
//	(Category 6) scoring for Maven packages.
//
// Source: https://central.sonatype.org/publish/requirements/gpg/
// Methodology: Mock server returns 200 for .asc HEAD request.
// Result: CheckGPGSignature returns true when .asc file exists.
func TestCheckGPGSignature_Present(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/signed-lib/1.0.0/signed-lib-1.0.0.jar.asc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("expected HEAD request, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
	}

	result := client.CheckGPGSignature("com.example", "signed-lib", "1.0.0")
	if !result {
		t.Error("CheckGPGSignature should return true when .asc file exists")
	}
}

// Test: CheckGPGSignature returns false when .asc file is missing
// Justification: A missing GPG signature indicates the artifact was published
//
//	without proper signing, which is a provenance concern.
//
// Source: https://central.sonatype.org/publish/requirements/gpg/
// Methodology: Mock server returns 404 for .asc HEAD request.
// Result: CheckGPGSignature returns false when .asc file is not found.
func TestCheckGPGSignature_Missing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
	}

	result := client.CheckGPGSignature("com.example", "unsigned-lib", "1.0.0")
	if result {
		t.Error("CheckGPGSignature should return false when .asc file is missing")
	}
}

// Test: getPackageInfoDirect populates VersionCount from maven-metadata.xml
// Justification: Version count is a maturity signal — packages with many
//
//	versions are more established and better vetted by the community.
//
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Mock server returns maven-metadata.xml with multiple versions.
// Result: pkg.VersionCount equals the number of versions in the metadata.
func TestGetPackageInfoDirect_VersionCount(t *testing.T) {
	metadataXML := `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>versioned-lib</artifactId>
  <versioning>
    <latest>3.0.0</latest>
    <release>3.0.0</release>
    <versions>
      <version>1.0.0</version>
      <version>2.0.0</version>
      <version>2.1.0</version>
      <version>3.0.0</version>
    </versions>
  </versioning>
</metadata>`

	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>versioned-lib</artifactId>
  <version>3.0.0</version>
  <scm><url>https://github.com/example/versioned-lib</url></scm>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/versioned-lib/maven-metadata.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprint(w, metadataXML)
	})
	mux.HandleFunc("/com/example/versioned-lib/3.0.0/versioned-lib-3.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprint(w, pomXML)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	pkg, err := client.getPackageInfoDirect("com.example", "versioned-lib")
	if err != nil {
		t.Fatalf("getPackageInfoDirect returned error: %v", err)
	}

	if pkg.VersionCount != 4 {
		t.Errorf("VersionCount = %d, want 4", pkg.VersionCount)
	}
}

// Test: ResolveBOMVersions resolves unknown versions from parent BOM chain
// Justification: Maven projects using parent BOMs (e.g. spring-boot-starter-parent)
//
//	have dependencies without explicit versions. Without resolving these,
//	source verification constructs URLs like .../unknown/artifact-unknown-sources.jar
//	which always fail, falsely inflating risk scores for all BOM-managed packages.
//
// Source: Maven POM reference — dependency management inheritance
// Methodology: Mock Maven Central with parent BOM containing dependencyManagement
//
//	and properties. Verify that unknown versions are resolved correctly.
//
// Result: Dependencies with "unknown" versions are resolved from parent BOM.
func TestResolveBOMVersions_ParentChain(t *testing.T) {
	// Parent POM with properties and dependencyManagement
	parentPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>parent-bom</artifactId>
  <version>2.0.0</version>
  <properties>
    <spring.version>5.3.20</spring.version>
    <guava.version>31.1-jre</guava.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>${spring.version}</version>
      </dependency>
      <dependency>
        <groupId>com.google.guava</groupId>
        <artifactId>guava</artifactId>
        <version>${guava.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/parent-bom/2.0.0/parent-bom-2.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprint(w, parentPOM)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	deps := []models.Dependency{
		{Name: "org.springframework:spring-core", Version: "unknown", Ecosystem: models.EcosystemMaven},
		{Name: "com.google.guava:guava", Version: "unknown", Ecosystem: models.EcosystemMaven},
		{Name: "com.example:already-resolved", Version: "1.0.0", Ecosystem: models.EcosystemMaven},
	}

	resolved := client.ResolveBOMVersions(deps, "com.example", "parent-bom", "2.0.0")

	if resolved[0].Version != "5.3.20" {
		t.Errorf("spring-core version = %q, want %q", resolved[0].Version, "5.3.20")
	}
	if resolved[1].Version != "31.1-jre" {
		t.Errorf("guava version = %q, want %q", resolved[1].Version, "31.1-jre")
	}
	// Already-resolved deps should not be modified
	if resolved[2].Version != "1.0.0" {
		t.Errorf("already-resolved version = %q, want %q", resolved[2].Version, "1.0.0")
	}
}

// Test: ResolveBOMVersions follows grandparent POM chain
// Justification: Spring Boot projects typically have:
//
//	project → spring-boot-starter-parent → spring-boot-dependencies
//	The actual version definitions are in the grandparent BOM. If we only
//	fetch one level, most Spring dependencies remain unresolved.
//
// Source: Spring Boot BOM architecture
// Methodology: Mock a two-level parent chain. Verify versions from grandparent
//
//	are resolved for dependencies not defined in the immediate parent.
//
// Result: Versions from grandparent BOM are correctly resolved.
func TestResolveBOMVersions_GrandparentChain(t *testing.T) {
	// Direct parent with its own parent reference
	parentPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>grandparent</artifactId>
    <version>1.0.0</version>
  </parent>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.example</groupId>
        <artifactId>parent-defined</artifactId>
        <version>1.1.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`

	// Grandparent with additional dependency management
	grandparentPOM := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>grandparent</artifactId>
  <version>1.0.0</version>
  <properties>
    <deep.version>9.9.9</deep.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.example</groupId>
        <artifactId>grandparent-defined</artifactId>
        <version>${deep.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`

	mux := http.NewServeMux()
	mux.HandleFunc("/com/example/parent/1.0.0/parent-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, parentPOM)
	})
	mux.HandleFunc("/com/example/grandparent/1.0.0/grandparent-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, grandparentPOM)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	deps := []models.Dependency{
		{Name: "com.example:parent-defined", Version: "unknown", Ecosystem: models.EcosystemMaven},
		{Name: "com.example:grandparent-defined", Version: "unknown", Ecosystem: models.EcosystemMaven},
	}

	resolved := client.ResolveBOMVersions(deps, "com.example", "parent", "1.0.0")

	if resolved[0].Version != "1.1.0" {
		t.Errorf("parent-defined version = %q, want %q", resolved[0].Version, "1.1.0")
	}
	if resolved[1].Version != "9.9.9" {
		t.Errorf("grandparent-defined version = %q, want %q", resolved[1].Version, "9.9.9")
	}
}

// Test: ResolveBOMVersions degrades gracefully on network failure
// Justification: Parent BOM may be unreachable (rate limiting, network error).
//
//	Failure to fetch BOM must not crash the scan or change existing versions.
//	Deps should remain "unknown" rather than producing errors.
//
// Source: Snyft design principle — degrade gracefully, never fail completely.
// Methodology: Mock server returns 500 for all requests.
// Result: All deps retain their original versions.
func TestResolveBOMVersions_NetworkFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &MavenClient{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		searchURL:  srv.URL + "/search",
	}

	deps := []models.Dependency{
		{Name: "com.example:lib", Version: "unknown", Ecosystem: models.EcosystemMaven},
	}

	resolved := client.ResolveBOMVersions(deps, "com.example", "parent", "1.0.0")

	// Should remain unknown, not crash
	if resolved[0].Version != "unknown" {
		t.Errorf("version = %q, want %q (should remain unknown on network failure)", resolved[0].Version, "unknown")
	}
}

// Test: ResolveBOMVersions returns deps unchanged when no parent info
// Justification: If parent coordinates are empty, no BOM resolution should
//
//	be attempted, and the original deps should be returned as-is.
//
// Source: Maven POM reference — parent is optional
// Methodology: Call with empty parent coordinates.
// Result: Deps unchanged.
func TestResolveBOMVersions_NoParent(t *testing.T) {
	client := NewMavenClient()

	deps := []models.Dependency{
		{Name: "com.example:lib", Version: "unknown", Ecosystem: models.EcosystemMaven},
	}

	resolved := client.ResolveBOMVersions(deps, "", "", "")

	if resolved[0].Version != "unknown" {
		t.Errorf("version = %q, want %q (no parent = no resolution)", resolved[0].Version, "unknown")
	}
}
