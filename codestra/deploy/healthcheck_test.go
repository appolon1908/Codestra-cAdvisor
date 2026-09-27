package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPReadinessRequiresSuccess(t *testing.T) {
	t.Parallel()
	for name, status := range map[string]int{
		"ready":     http.StatusOK,
		"unhealthy": http.StatusServiceUnavailable,
		"redirect":  http.StatusTemporaryRedirect,
	} {
		name, status := name, status
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()
			err := checkHTTP(server.URL)
			if status == http.StatusOK && err != nil {
				t.Fatalf("successful readiness failed: %v", err)
			}
			if status != http.StatusOK && err == nil {
				t.Fatalf("HTTP %d unexpectedly passed readiness", status)
			}
		})
	}
}
