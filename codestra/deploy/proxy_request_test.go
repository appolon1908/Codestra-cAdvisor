package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMalformedDockerRequests(t *testing.T) {
	cases := []struct {
		name, target string
		change       func(*http.Request)
	}{
		{"bad escape", "http://docker/info?ignored=%zz", nil},
		{"semicolon", "http://docker/info?ignored=1;other=2", nil},
		{"mixed valid invalid", "http://docker/containers/json?all=1&ignored=%zz", nil},
		{"unknown body", "http://docker/info", func(r *http.Request) { r.ContentLength = -1; r.Body = io.NopCloser(strings.NewReader("data")) }},
		{"chunked", "http://docker/info", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
		{"second connection header", "http://docker/info", func(r *http.Request) { r.Header.Add("Connection", "keep-alive"); r.Header.Add("Connection", "upgrade") }},
		{"dot segments", "http://docker/images/../../private/json", nil},
		{"encoded traversal", "http://docker/images/%2e%2e/private/json", nil},
		{"double encoding", "http://docker/images/%252e%252e/private/json", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if tc.change != nil {
				tc.change(r)
			}
			if allowedDockerRequest(r) {
				t.Fatal("malformed request accepted")
			}
		})
	}
}

func TestValidDockerReadsRemainAllowed(t *testing.T) {
	for _, target := range []string{
		"http://docker/_ping", "http://docker/v1.45/info", "http://docker/version",
		"http://docker/containers/json?all=1&limit=100",
		"http://docker/containers/id/json", "http://docker/containers/id/stats?stream=false&one-shot=true",
		"http://docker/events?since=1&until=2",
		"http://docker/images/codestra/example:1/json", "http://docker/images/sha256%3Aabc/json",
		"http://docker/networks?scope=local", "http://docker/networks/test",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			if !allowedDockerRequest(httptest.NewRequest(method, target, nil)) {
				t.Errorf("valid read denied: %s %s", method, target)
			}
		}
	}
}

type pingTransport struct {
	calls int
	code  int
}

func (p *pingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	p.calls++
	if _, ok := r.Context().Deadline(); !ok {
		panic("health ping must have bounded deadline")
	}
	return &http.Response{StatusCode: p.code, Body: io.NopCloser(strings.NewReader("OK")), Header: make(http.Header)}, nil
}

func TestHealthGuardRunsBeforeDockerSocket(t *testing.T) {
	transport := &pingTransport{code: 200}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("health must not use unrestricted proxy") })
	handler := dockerHandler(upstream, transport)
	for _, tc := range []struct {
		method, target string
		body           io.Reader
	}{
		{"POST", "http://docker/healthz", nil}, {"DELETE", "http://docker/healthz", nil},
		{"GET", "http://docker/healthz?ignored=%zz", nil}, {"GET", "http://docker/healthz", strings.NewReader("data")},
	} {
		before := transport.calls
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.target, tc.body))
		if w.Code != 403 || transport.calls != before {
			t.Errorf("health request not denied before socket: %s %s", tc.method, tc.target)
		}
	}
	for _, method := range []string{"GET", "HEAD"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, "http://docker/healthz", nil))
		if w.Code != 200 {
			t.Fatal("valid health check rejected")
		}
		if method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("HEAD emitted a body")
		}
	}
	transport.code = 503
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "http://docker/healthz", nil))
	if w.Code != 503 {
		t.Fatal("upstream failure became healthy")
	}
}

func TestMetricsGuardBeforeUpstream(t *testing.T) {
	calls := 0
	handler := metricsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }))
	for _, tc := range []struct {
		method, target string
		body           io.Reader
		code           int
	}{
		{"POST", "http://metrics/metrics", nil, 405},
		{"GET", "http://metrics/metrics?debug=1", nil, 403},
		{"GET", "http://metrics/metrics", strings.NewReader("data"), 403},
		{"GET", "http://metrics/healthz", strings.NewReader("data"), 403},
		{"GET", "http://metrics/debug", nil, 403},
		{"GET", "http://metrics/metrics", nil, 200},
		{"HEAD", "http://metrics/healthz", nil, 200},
	} {
		before := calls
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.target, tc.body))
		if w.Code != tc.code {
			t.Errorf("expected %d, got %d", tc.code, w.Code)
		}
		if tc.code != 200 && calls != before {
			t.Fatal("denied metrics request reached upstream")
		}
	}
	for _, target := range []string{"http://metrics/metrics", "http://metrics/healthz"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Header.Add("Connection", "keep-alive")
		r.Header.Add("Connection", "Upgrade")
		before := calls
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 403 || calls != before {
			t.Fatal("upgrade reached metrics upstream")
		}
	}
}

func TestReadOnlyEnvelopeRejectsInvalidFraming(t *testing.T) {
	if readOnlyRequest(nil) || readOnlyRequest(&http.Request{}) {
		t.Fatal("nil envelope accepted")
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.ContentLength = -1 },
		func(r *http.Request) { r.Trailer = http.Header{"X-Test": []string{"value"}} },
		func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("hidden")) },
		func(r *http.Request) { r.URL.RawPath = "/%zz" },
		func(r *http.Request) { r.URL.RawQuery = strings.Repeat("x", 8193) },
	} {
		r := httptest.NewRequest("GET", "http://docker/info", nil)
		mutate(r)
		if readOnlyRequest(r) {
			t.Fatal("invalid envelope accepted")
		}
	}
}
