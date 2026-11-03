package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const defaultAddress = "127.0.0.1:8080"

func main() {
	if endpoint := os.Getenv("CODESTRA_HEALTHCHECK_URL"); endpoint != "" {
		if err := checkHTTP(endpoint); err != nil {
			fmt.Fprintln(os.Stderr, "service readiness check failed")
			os.Exit(1)
		}
		return
	}

	address := os.Getenv("CODESTRA_HEALTHCHECK_ADDRESS")
	if address == "" {
		address = defaultAddress
	}

	connection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listener check failed for %s: %v\n", address, err)
		os.Exit(1)
	}
	_ = connection.Close()
}

func checkHTTP(endpoint string) error {
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("readiness returned HTTP %d", response.StatusCode)
	}
	return nil
}
