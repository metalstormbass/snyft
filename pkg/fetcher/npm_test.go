package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetOwnershipHistory_NPM(t *testing.T) {
	tests := []struct {
		name              string
		response          NPMRegistryResponse
		wantChanges       int
		wantRecentTransfer bool
	}{
		{
			name: "stable ownership",
			response: NPMRegistryResponse{
				Name: "test-package",
				Maintainers: []NPMMaintainer{
					{Name: "alice", Email: "alice@example.com"},
				},
				Versions: map[string]NPMVersionDetails{
					"1.0.0": {
						Version: "1.0.0",
						Maintainers: []NPMMaintainer{
							{Name: "alice", Email: "alice@example.com"},
						},
					},
					"1.1.0": {
						Version: "1.1.0",
						Maintainers: []NPMMaintainer{
							{Name: "alice", Email: "alice@example.com"},
						},
					},
				},
				Time: map[string]string{
					"1.0.0": time.Now().AddDate(0, -12, 0).Format(time.RFC3339),
					"1.1.0": time.Now().AddDate(0, -6, 0).Format(time.RFC3339),
				},
			},
			wantChanges:       0,
			wantRecentTransfer: false,
		},
		{
			name: "recent ownership transfer",
			response: NPMRegistryResponse{
				Name: "test-package",
				Maintainers: []NPMMaintainer{
					{Name: "bob", Email: "bob@example.com"},
				},
				Versions: map[string]NPMVersionDetails{
					"1.0.0": {
						Version: "1.0.0",
						Maintainers: []NPMMaintainer{
							{Name: "alice", Email: "alice@example.com"},
						},
					},
					"2.0.0": {
						Version: "2.0.0",
						Maintainers: []NPMMaintainer{
							{Name: "bob", Email: "bob@example.com"},
						},
					},
				},
				Time: map[string]string{
					"1.0.0": time.Now().AddDate(0, -12, 0).Format(time.RFC3339),
					"2.0.0": time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
				},
			},
			wantChanges:       1,
			wantRecentTransfer: true,
		},
		{
			name: "old ownership change",
			response: NPMRegistryResponse{
				Name: "test-package",
				Maintainers: []NPMMaintainer{
					{Name: "bob", Email: "bob@example.com"},
				},
				Versions: map[string]NPMVersionDetails{
					"1.0.0": {
						Version: "1.0.0",
						Maintainers: []NPMMaintainer{
							{Name: "alice", Email: "alice@example.com"},
						},
					},
					"2.0.0": {
						Version: "2.0.0",
						Maintainers: []NPMMaintainer{
							{Name: "bob", Email: "bob@example.com"},
						},
					},
				},
				Time: map[string]string{
					"1.0.0": time.Now().AddDate(-2, 0, 0).Format(time.RFC3339),
					"2.0.0": time.Now().AddDate(-1, 0, 0).Format(time.RFC3339),
				},
			},
			wantChanges:       1,
			wantRecentTransfer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			client := &NPMClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
			}

			history, err := client.GetOwnershipHistory("test-package")
			if err != nil {
				t.Fatalf("GetOwnershipHistory() error = %v", err)
			}

			if history.MaintainerChanges != tt.wantChanges {
				t.Errorf("GetOwnershipHistory() changes = %v, want %v", history.MaintainerChanges, tt.wantChanges)
			}

			if history.RecentTransfer != tt.wantRecentTransfer {
				t.Errorf("GetOwnershipHistory() recent transfer = %v, want %v", history.RecentTransfer, tt.wantRecentTransfer)
			}
		})
	}
}

func TestGetOwnershipHistory_NPM_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	_, err := client.GetOwnershipHistory("nonexistent-package")
	if err == nil {
		t.Error("GetOwnershipHistory() expected error, got nil")
	}
}
