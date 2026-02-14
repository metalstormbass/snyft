package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetOwnershipHistory_PyPI(t *testing.T) {
	tests := []struct {
		name              string
		response          PyPIFullResponse
		wantChanges       int
		wantRecentTransfer bool
	}{
		{
			name: "stable ownership",
			response: PyPIFullResponse{
				Info: PyPIInfo{
					Name:   "test-package",
					Author: "alice",
				},
				Releases: map[string][]PyPIReleaseFile{
					"1.0.0": {
						{
							Filename:   "test-package-1.0.0.tar.gz",
							UploadTime: time.Now().AddDate(0, -12, 0),
							Uploader:   "alice",
						},
					},
					"1.1.0": {
						{
							Filename:   "test-package-1.1.0.tar.gz",
							UploadTime: time.Now().AddDate(0, -6, 0),
							Uploader:   "alice",
						},
					},
				},
			},
			wantChanges:       0,
			wantRecentTransfer: false,
		},
		{
			name: "recent ownership transfer",
			response: PyPIFullResponse{
				Info: PyPIInfo{
					Name:   "test-package",
					Author: "bob",
				},
				Releases: map[string][]PyPIReleaseFile{
					"1.0.0": {
						{
							Filename:   "test-package-1.0.0.tar.gz",
							UploadTime: time.Now().AddDate(0, -12, 0),
							Uploader:   "alice",
						},
					},
					"2.0.0": {
						{
							Filename:   "test-package-2.0.0.tar.gz",
							UploadTime: time.Now().AddDate(0, -2, 0),
							Uploader:   "bob",
						},
					},
				},
			},
			wantChanges:       1,
			wantRecentTransfer: true,
		},
		{
			name: "old ownership change",
			response: PyPIFullResponse{
				Info: PyPIInfo{
					Name:   "test-package",
					Author: "bob",
				},
				Releases: map[string][]PyPIReleaseFile{
					"1.0.0": {
						{
							Filename:   "test-package-1.0.0.tar.gz",
							UploadTime: time.Now().AddDate(-2, 0, 0),
							Uploader:   "alice",
						},
					},
					"2.0.0": {
						{
							Filename:   "test-package-2.0.0.tar.gz",
							UploadTime: time.Now().AddDate(-1, 0, 0),
							Uploader:   "bob",
						},
					},
				},
			},
			wantChanges:       1,
			wantRecentTransfer: false,
		},
		{
			name: "multiple author changes",
			response: PyPIFullResponse{
				Info: PyPIInfo{
					Name:   "test-package",
					Author: "charlie",
				},
				Releases: map[string][]PyPIReleaseFile{
					"1.0.0": {
						{
							Filename:   "test-package-1.0.0.tar.gz",
							UploadTime: time.Now().AddDate(-2, 0, 0),
							Uploader:   "alice",
						},
					},
					"2.0.0": {
						{
							Filename:   "test-package-2.0.0.tar.gz",
							UploadTime: time.Now().AddDate(-1, 0, 0),
							Uploader:   "bob",
						},
					},
					"3.0.0": {
						{
							Filename:   "test-package-3.0.0.tar.gz",
							UploadTime: time.Now().AddDate(0, -6, 0),
							Uploader:   "charlie",
						},
					},
				},
			},
			wantChanges:       2,
			wantRecentTransfer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			client := &PyPIClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
			}

			history, err := client.GetOwnershipHistory("test-package")
			if err != nil {
				t.Fatalf("GetOwnershipHistory() error = %v", err)
			}

			if history.AuthorChanges != tt.wantChanges {
				t.Errorf("GetOwnershipHistory() changes = %v, want %v", history.AuthorChanges, tt.wantChanges)
			}

			if history.RecentTransfer != tt.wantRecentTransfer {
				t.Errorf("GetOwnershipHistory() recent transfer = %v, want %v", history.RecentTransfer, tt.wantRecentTransfer)
			}
		})
	}
}

func TestGetOwnershipHistory_PyPI_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	_, err := client.GetOwnershipHistory("nonexistent-package")
	if err == nil {
		t.Error("GetOwnershipHistory() expected error, got nil")
	}
}

func TestGetOwnershipHistory_PyPI_EmptyReleases(t *testing.T) {
	response := PyPIFullResponse{
		Info: PyPIInfo{
			Name:   "test-package",
			Author: "alice",
		},
		Releases: map[string][]PyPIReleaseFile{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	history, err := client.GetOwnershipHistory("test-package")
	if err != nil {
		t.Fatalf("GetOwnershipHistory() error = %v", err)
	}

	if history.AuthorChanges != 0 {
		t.Errorf("GetOwnershipHistory() changes = %v, want 0", history.AuthorChanges)
	}

	if history.CurrentAuthor != "alice" {
		t.Errorf("GetOwnershipHistory() current author = %v, want alice", history.CurrentAuthor)
	}
}
