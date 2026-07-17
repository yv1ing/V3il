package control

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	zeekAdapterBaseURL        = "http://127.0.0.1:8765"
	maxDetectionRequestBytes  = 2 * 1024 * 1024
	maxDetectionResponseBytes = 16 * 1024 * 1024
)

var (
	detectionBundlePath   = regexp.MustCompile(`^/detection/v1/bundles/[0-9a-f]{64}$`)
	detectionActivatePath = regexp.MustCompile(`^/detection/v1/bundles/[0-9a-f]{64}/activate$`)
	detectionHTTPClient   = &http.Client{Timeout: 45 * time.Second}
)

func (s *Server) handleDetectionProxy(w http.ResponseWriter, r *http.Request) {
	if s.zeekAdapterToken == "" {
		http.Error(w, "Zeek Adapter is not configured", http.StatusServiceUnavailable)
		return
	}
	if !allowedDetectionRequest(r) {
		http.NotFound(w, r)
		return
	}
	if r.ContentLength > maxDetectionRequestBytes {
		http.Error(w, "detection request is too large", http.StatusRequestEntityTooLarge)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxDetectionRequestBytes+1))
	if err != nil {
		http.Error(w, "read detection request failed", http.StatusBadRequest)
		return
	}
	if len(body) > maxDetectionRequestBytes {
		http.Error(w, "detection request is too large", http.StatusRequestEntityTooLarge)
		return
	}

	upstreamPath := strings.TrimPrefix(r.URL.Path, "/detection")
	upstreamURL, err := url.Parse(zeekAdapterBaseURL + upstreamPath)
	if err != nil {
		http.Error(w, "invalid Zeek Adapter target", http.StatusInternalServerError)
		return
	}
	upstreamURL.RawQuery = r.URL.RawQuery
	request, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "create Zeek Adapter request failed", http.StatusInternalServerError)
		return
	}
	request.Header.Set("Authorization", "Bearer "+s.zeekAdapterToken)
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}

	response, err := detectionHTTPClient.Do(request)
	if err != nil {
		http.Error(w, "Zeek Adapter is unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxDetectionResponseBytes+1))
	if err != nil {
		http.Error(w, "read Zeek Adapter response failed", http.StatusBadGateway)
		return
	}
	if len(responseBody) > maxDetectionResponseBytes {
		http.Error(w, "Zeek Adapter response is too large", http.StatusBadGateway)
		return
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(responseBody)
}

func allowedDetectionRequest(r *http.Request) bool {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/detection/v1/health":
		return r.URL.RawQuery == ""
	case r.Method == http.MethodGet && r.URL.Path == "/detection/v1/events":
		return validDetectionEventsQuery(r.URL.Query())
	case r.Method == http.MethodPut && detectionBundlePath.MatchString(r.URL.Path):
		return r.URL.RawQuery == ""
	case r.Method == http.MethodPost && detectionActivatePath.MatchString(r.URL.Path):
		return r.URL.RawQuery == ""
	case r.Method == http.MethodPost && r.URL.Path == "/detection/v1/bundles/rollback":
		return r.URL.RawQuery == ""
	default:
		return false
	}
}

func validDetectionEventsQuery(values url.Values) bool {
	for key := range values {
		if key != "after" && key != "limit" {
			return false
		}
	}
	after, err := parseDetectionQueryInteger(values, "after", 0, 0)
	if err != nil || after < 0 {
		return false
	}
	limit, err := parseDetectionQueryInteger(values, "limit", 1000, 1)
	return err == nil && limit <= 1000
}

func parseDetectionQueryInteger(values url.Values, key string, fallback int64, minimum int64) (int64, error) {
	items, exists := values[key]
	if !exists {
		return fallback, nil
	}
	if len(items) != 1 || strings.TrimSpace(items[0]) == "" {
		return 0, fmt.Errorf("%s must contain one integer", key)
	}
	value, err := strconv.ParseInt(items[0], 10, 64)
	if err != nil || value < minimum {
		return 0, fmt.Errorf("%s is invalid", key)
	}
	return value, nil
}
