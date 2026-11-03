package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	modeDockerAPI = "docker-api"
	modeMetrics   = "metrics-mtls"
)

var (
	apiVersionPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+`)
	containerInspect = regexp.MustCompile(`^/containers/[A-Za-z0-9_.-]+/json$`)
	containerStats   = regexp.MustCompile(`^/containers/[A-Za-z0-9_.-]+/stats$`)
	imageInspect     = regexp.MustCompile(`^/images/.+/json$`)
	networkInspect   = regexp.MustCompile(`^/networks/[A-Za-z0-9_.:-]+$`)
)

func main() {
	mode := os.Getenv("CODESTRA_PROXY_MODE")
	switch mode {
	case modeDockerAPI:
		if err := runDockerAPIProxy(); err != nil {
			log.Fatalf("docker API proxy failed: %v", err)
		}
	case modeMetrics:
		if err := runMetricsProxy(); err != nil {
			log.Fatalf("metrics proxy failed: %v", err)
		}
	default:
		log.Fatalf("unsupported CODESTRA_PROXY_MODE %q", mode)
	}
}

func getenv(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func maxConcurrent() int {
	value, err := strconv.Atoi(getenv("MAX_CONCURRENT_REQUESTS", "32"))
	if err != nil || value < 1 || value > 256 {
		return 32
	}
	return value
}

func withConcurrencyLimit(next http.Handler) http.Handler {
	semaphore := make(chan struct{}, maxConcurrent())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
		case <-r.Context().Done():
			http.Error(w, "request cancelled", http.StatusRequestTimeout)
			return
		default:
			http.Error(w, "too many requests", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func runDockerAPIProxy() error {
	listenAddress := getenv("PROXY_LISTEN_ADDRESS", "0.0.0.0:2375")
	socketPath := getenv("DOCKER_SOCKET_PATH", "/var/run/docker.sock")

	transport := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}

	upstream := &url.URL{Scheme: "http", Host: "docker"}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = transport
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalDirector(request)
		request.Host = "docker"
		request.Header = make(http.Header)
		request.Header.Set("User-Agent", "codestra-cadvisor-readonly-proxy/1.0")
		request.Header.Set("X-Codestra-Read-Only", "true")
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Del("Set-Cookie")
		response.Header.Set("Cache-Control", "no-store")
		response.Header.Set("X-Content-Type-Options", "nosniff")
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("docker upstream error: %v", err)
		http.Error(w, "docker metadata upstream unavailable", http.StatusBadGateway)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			if err := dockerPing(r.Context(), transport); err != nil {
				http.Error(w, "docker socket unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok\n")
			return
		}
		if !allowedDockerRequest(r) {
			http.Error(w, "Docker API operation denied", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:              listenAddress,
		Handler:           withConcurrencyLimit(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	log.Printf("starting read-only Docker API proxy on %s", listenAddress)
	return server.ListenAndServe()
}

func dockerPing(ctx context.Context, transport http.RoundTripper) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Docker ping returned HTTP %d", response.StatusCode)
	}
	return nil
}

func allowedDockerRequest(request *http.Request) bool {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		return false
	}
	if request.ContentLength > 0 || strings.Contains(strings.ToLower(request.Header.Get("Connection")), "upgrade") || request.Header.Get("Upgrade") != "" {
		return false
	}

	path := apiVersionPrefix.ReplaceAllString(request.URL.Path, "")
	allowedQuery := map[string]struct{}{}
	switch {
	case path == "/_ping", path == "/version", path == "/info":
	case path == "/containers/json":
		for _, key := range []string{"all", "limit", "size", "filters", "since", "before"} {
			allowedQuery[key] = struct{}{}
		}
	case path == "/events":
		for _, key := range []string{"since", "until", "filters"} {
			allowedQuery[key] = struct{}{}
		}
	case containerInspect.MatchString(path), imageInspect.MatchString(path), networkInspect.MatchString(path):
	case containerStats.MatchString(path):
		allowedQuery["stream"] = struct{}{}
		allowedQuery["one-shot"] = struct{}{}
	case path == "/networks":
		allowedQuery["filters"] = struct{}{}
		allowedQuery["verbose"] = struct{}{}
		allowedQuery["scope"] = struct{}{}
	default:
		return false
	}

	for key, values := range request.URL.Query() {
		if _, ok := allowedQuery[key]; !ok {
			return false
		}
		if len(values) > 8 {
			return false
		}
		for _, value := range values {
			if len(value) > 4096 {
				return false
			}
		}
	}
	return true
}

func runMetricsProxy() error {
	listenAddress := getenv("PROXY_LISTEN_ADDRESS", "0.0.0.0:9443")
	upstreamRaw := getenv("METRICS_UPSTREAM_URL", "http://cadvisor:8080")
	upstream, err := url.Parse(upstreamRaw)
	if err != nil || upstream.Scheme != "http" || upstream.Host == "" {
		return fmt.Errorf("invalid internal metrics upstream %q", upstreamRaw)
	}

	certificatePath := getenv("TLS_CERT_FILE", "/run/secrets/cadvisor_proxy_server_cert")
	keyPath := getenv("TLS_KEY_FILE", "/run/secrets/cadvisor_proxy_server_key")
	clientCAPath := getenv("TLS_CLIENT_CA_FILE", "/run/secrets/prometheus_client_ca")
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return fmt.Errorf("load metrics proxy certificate: %w", err)
	}
	clientCABytes, err := os.ReadFile(clientCAPath)
	if err != nil {
		return fmt.Errorf("read Prometheus client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCABytes) {
		return errors.New("Prometheus client CA contained no certificates")
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    false,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = transport
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalDirector(request)
		request.Host = upstream.Host
		request.Header = make(http.Header)
		request.Header.Set("User-Agent", "codestra-prometheus-cadvisor-proxy/1.0")
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Del("Set-Cookie")
		response.Header.Set("Cache-Control", "no-store")
		response.Header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		response.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		response.Header.Set("X-Content-Type-Options", "nosniff")
		response.Header.Set("X-Frame-Options", "DENY")
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("cAdvisor upstream error: %v", err)
		http.Error(w, "cAdvisor upstream unavailable", http.StatusBadGateway)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method denied", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || (r.URL.Path != "/metrics" && r.URL.Path != "/healthz") {
			http.Error(w, "path denied", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:              listenAddress,
		Handler:           withConcurrencyLimit(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}
	log.Printf("starting mTLS cAdvisor metrics proxy on %s", listenAddress)
	return server.ListenAndServeTLS("", "")
}
