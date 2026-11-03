package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func request(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

func TestAllowedDockerRequest(t *testing.T) {
	t.Parallel()

	allowed := []struct {
		name   string
		method string
		target string
	}{
		{name: "ping", method: http.MethodGet, target: "http://docker/_ping"},
		{name: "versioned info", method: http.MethodGet, target: "http://docker/v1.45/info"},
		{name: "container list", method: http.MethodGet, target: "http://docker/containers/json?all=1&limit=100"},
		{name: "container inspect", method: http.MethodGet, target: "http://docker/containers/abc123/json"},
		{name: "container stats", method: http.MethodGet, target: "http://docker/containers/abc123/stats?stream=false"},
		{name: "events", method: http.MethodGet, target: "http://docker/events?since=1&until=2"},
		{name: "image inspect", method: http.MethodGet, target: "http://docker/images/codestra/example:1.0/json"},
		{name: "network list", method: http.MethodGet, target: "http://docker/networks?scope=local"},
		{name: "network inspect", method: http.MethodGet, target: "http://docker/networks/codestra-observability"},
		{name: "head version", method: http.MethodHead, target: "http://docker/version"},
	}

	for _, test := range allowed {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if !allowedDockerRequest(request(test.method, test.target)) {
				t.Fatalf("expected %s %s to be allowed", test.method, test.target)
			}
		})
	}
}

func TestDeniedDockerRequest(t *testing.T) {
	t.Parallel()

	requestBody := func(req *http.Request) {
		req.Body = io.NopCloser(strings.NewReader("not allowed"))
		req.ContentLength = 11
	}

	denied := []struct {
		name   string
		method string
		target string
		mutate func(*http.Request)
	}{
		{name: "create container", method: http.MethodPost, target: "http://docker/containers/create"},
		{name: "delete container", method: http.MethodDelete, target: "http://docker/containers/abc123"},
		{name: "container archive", method: http.MethodGet, target: "http://docker/containers/abc123/archive"},
		{name: "unapproved query", method: http.MethodGet, target: "http://docker/containers/abc123/json?secret=1"},
		{name: "volume list", method: http.MethodGet, target: "http://docker/volumes"},
		{name: "exec list", method: http.MethodGet, target: "http://docker/exec/abc123/json"},
		{name: "plugin list", method: http.MethodGet, target: "http://docker/plugins"},
		{name: "service list", method: http.MethodGet, target: "http://docker/services"},
		{name: "build endpoint", method: http.MethodGet, target: "http://docker/build"},
		{name: "request body", method: http.MethodGet, target: "http://docker/info", mutate: requestBody},
		{
			name:   "connection upgrade",
			method: http.MethodGet,
			target: "http://docker/events",
			mutate: func(req *http.Request) {
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "tcp")
			},
		},
		{
			name:   "too many query values",
			method: http.MethodGet,
			target: "http://docker/containers/json?all=1&all=1&all=1&all=1&all=1&all=1&all=1&all=1&all=1",
		},
		{
			name:   "oversized query value",
			method: http.MethodGet,
			target: "http://docker/containers/json?filters=" + strings.Repeat("a", 4097),
		},
	}

	for _, test := range denied {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			req := request(test.method, test.target)
			if test.mutate != nil {
				test.mutate(req)
			}
			if allowedDockerRequest(req) {
				t.Fatalf("expected %s %s to be denied", test.method, test.target)
			}
		})
	}
}

func TestVersionPrefixIsOnlyRemovedAtPathStart(t *testing.T) {
	t.Parallel()

	if allowedDockerRequest(request(http.MethodGet, "http://docker/foo/v1.45/info")) {
		t.Fatal("embedded API-version path must be denied")
	}
}
