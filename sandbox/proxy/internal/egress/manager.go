package egress

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"sandbox-proxy/internal/httpx"
	"sandbox-proxy/internal/telemetry"
)

const (
	DefaultProxyAddr      = "127.0.0.1:8118"
	defaultTorSocksAddr   = "127.0.0.1:9050"
	egressProfilePath     = "/etc/profile.d/sandbox-egress.sh"
	egressUpstreamTypeKey = "SANDBOX_EGRESS_UPSTREAM_TYPE"
	egressUpstreamAddrKey = "SANDBOX_EGRESS_UPSTREAM_ADDR"

	egressUpstreamTypeHTTP   = "http"
	egressUpstreamTypeHTTPS  = "https"
	egressUpstreamTypeSOCKS5 = "socks5"
	egressUpstreamTypeTor    = "tor"
	proxyHandshakeTimeout    = 15 * time.Second
	maxEgressRequestBody     = 3000
	maxEgressRequestEvidence = 12 * 1024
)

var egressAppEnvKeys = []string{
	"HTTP_PROXY",
	"http_proxy",
	"HTTPS_PROXY",
	"https_proxy",
	"ALL_PROXY",
	"all_proxy",
	"NO_PROXY",
	"no_proxy",
}

type egressRequest struct {
	Environment map[string]string `json:"environment"`
}

type egressConfig struct {
	UpstreamType string
	UpstreamAddr string
}

type httpProxyTarget struct {
	URL    *url.URL
	UseTLS bool
}

type Manager struct {
	mu       sync.RWMutex
	env      map[string]string
	config   egressConfig
	recorder telemetry.Recorder
}

func NewManager(recorder telemetry.Recorder) *Manager {
	env := currentProcessEgressEnv()
	config := egressConfig{
		UpstreamType: os.Getenv(egressUpstreamTypeKey),
		UpstreamAddr: os.Getenv(egressUpstreamAddrKey),
	}
	return &Manager{env: env, config: config, recorder: recorder}
}

func (m *Manager) Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req egressRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	next, config, err := egressEnvFromRequest(req.Environment)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := m.Set(next, config); err != nil {
		http.Error(w, "failed to update egress", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (m *Manager) Set(env map[string]string, config egressConfig) error {
	if err := writeEgressProfile(env); err != nil {
		return err
	}

	m.mu.Lock()
	m.env = env
	m.config = config
	m.mu.Unlock()
	return nil
}

func (m *Manager) RuntimeEnvironmentOverlay() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	overlay := make([]string, 0, len(egressEnvKeys()))
	for _, key := range egressAppEnvKeys {
		overlay = append(overlay, key+"="+m.env[key])
	}
	overlay = append(overlay, egressUpstreamTypeKey+"=", egressUpstreamAddrKey+"=")
	return overlay
}

func (m *Manager) Config() egressConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

func egressEnvFromRequest(env map[string]string) (map[string]string, egressConfig, error) {
	next := make(map[string]string)
	for _, key := range egressAppEnvKeys {
		if value, ok := env[key]; ok {
			if strings.ContainsRune(value, '\x00') {
				return nil, egressConfig{}, fmt.Errorf("egress environment contains an invalid value")
			}
			next[key] = value
		}
	}
	config := egressConfig{
		UpstreamType: strings.ToLower(strings.TrimSpace(env[egressUpstreamTypeKey])),
		UpstreamAddr: strings.TrimSpace(env[egressUpstreamAddrKey]),
	}
	if len(config.UpstreamAddr) > 4096 || strings.ContainsRune(config.UpstreamAddr, '\x00') {
		return nil, egressConfig{}, fmt.Errorf("upstream proxy address is invalid")
	}
	if !isSupportedEgressUpstreamType(config.UpstreamType) {
		return nil, egressConfig{}, fmt.Errorf("unsupported upstream proxy type: %s", config.UpstreamType)
	}
	if err := validateEgressConfig(config); err != nil {
		return nil, egressConfig{}, err
	}
	return next, config, nil
}

func isSupportedEgressUpstreamType(value string) bool {
	switch value {
	case "", egressUpstreamTypeHTTP, egressUpstreamTypeHTTPS, egressUpstreamTypeSOCKS5, egressUpstreamTypeTor:
		return true
	default:
		return false
	}
}

func validateEgressConfig(config egressConfig) error {
	switch config.UpstreamType {
	case "":
		if config.UpstreamAddr != "" {
			return fmt.Errorf("upstream address requires an upstream proxy type")
		}
	case egressUpstreamTypeTor:
		if config.UpstreamAddr != "" {
			return fmt.Errorf("tor egress does not accept an upstream address")
		}
	case egressUpstreamTypeHTTP, egressUpstreamTypeHTTPS, egressUpstreamTypeSOCKS5:
		if config.UpstreamAddr == "" {
			return fmt.Errorf("upstream address is required for %s egress", config.UpstreamType)
		}
		user, password, address := splitUpstreamAuth(config.UpstreamAddr)
		if len(user) > 255 || len(password) > 255 {
			return fmt.Errorf("upstream proxy credentials are too long")
		}
		defaultPort := "1080"
		if config.UpstreamType == egressUpstreamTypeHTTP {
			defaultPort = "8080"
		} else if config.UpstreamType == egressUpstreamTypeHTTPS {
			defaultPort = "443"
		}
		if _, _, err := splitHostPortDefault(address, defaultPort); err != nil {
			return fmt.Errorf("upstream proxy address is invalid")
		}
	}
	return nil
}

func writeEgressProfile(env map[string]string) error {
	var b strings.Builder
	b.WriteString("# Generated by sandbox-proxy. Do not edit.\n")
	for _, key := range egressEnvKeys() {
		b.WriteString("unset ")
		b.WriteString(key)
		b.WriteString("\n")
	}

	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		b.WriteString("export ")
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(shellQuote(env[key]))
		b.WriteString("\n")
	}
	return os.WriteFile(egressProfilePath, []byte(b.String()), 0644)
}

func currentProcessEgressEnv() map[string]string {
	env := make(map[string]string)
	for _, key := range egressAppEnvKeys {
		if value := os.Getenv(key); value != "" {
			env[key] = value
		}
	}
	return env
}

func egressEnvKeys() []string {
	keys := append([]string{}, egressAppEnvKeys...)
	return append(keys, egressUpstreamTypeKey, egressUpstreamAddrKey)
}

func IsControlEnvironmentKey(name string) bool {
	return name == egressUpstreamTypeKey || name == egressUpstreamAddrKey
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (m *Manager) ProxyServer() *http.Server {
	return &http.Server{
		Addr:              DefaultProxyAddr,
		Handler:           http.HandlerFunc(m.handleProxyRequest),
		MaxHeaderBytes:    8 * 1024,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

func (m *Manager) handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		m.handleConnect(w, r)
		return
	}
	m.handleHTTP(w, r)
}

func (m *Manager) handleHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.URL
	if !target.IsAbs() || !strings.EqualFold(target.Scheme, "http") || target.Hostname() == "" {
		http.Error(w, "absolute HTTP proxy URL required", http.StatusBadRequest)
		return
	}
	if _, _, err := splitHostPortDefault(target.Host, "80"); err != nil {
		http.Error(w, "invalid proxy target", http.StatusBadRequest)
		return
	}
	requestEvidence, captureErr := captureEgressHTTPRequest(r)
	if captureErr != nil {
		requestEvidence["capture_error"] = captureErr.Error()
		requestEvidence["capture_complete"] = false
		m.recordBehavior(r, target, "request_rejected", "failure", http.StatusRequestEntityTooLarge, requestEvidence)
		http.Error(w, captureErr.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	m.recordBehavior(r, target, "request_attempted", "unknown", 0, requestEvidence)

	upstream, useProxyFormat, proxyAuth, err := m.dialHTTP(target)
	if err != nil {
		m.recordBehavior(r, target, "connection_failed", "failure", 0, egressErrorEvidence(err))
		log.Printf("egress HTTP dial failed target=%s upstream=%s: %v", target.Host, m.Config().LogLabel(), err)
		http.Error(w, "failed to connect upstream", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	m.recordBehavior(r, target, "connection_established", "success", 0, nil)

	req := r.Clone(r.Context())
	req.RequestURI = ""
	if useProxyFormat {
		req.URL = absoluteFormURL(target)
	} else {
		req.URL = originFormURL(target)
	}
	req.Header = cloneHeaderWithoutHopByHop(r.Header)
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	if proxyAuth != "" {
		req.Header.Set("Proxy-Authorization", proxyAuth)
	}

	if err := writeEgressHTTPRequest(req, upstream, useProxyFormat); err != nil {
		m.recordBehavior(r, target, "request_failed", "failure", 0, egressErrorEvidence(err))
		log.Printf("egress HTTP write failed target=%s: %v", target.Host, err)
		http.Error(w, "failed to write upstream request", http.StatusBadGateway)
		return
	}
	statusCode, responseErr := writeEgressResponse(w, upstream, req)
	if responseErr != nil {
		m.recordBehavior(r, target, "response_failed", "failure", statusCode, egressErrorEvidence(responseErr))
		return
	}
	m.recordBehavior(r, target, "response_received", "success", statusCode, nil)
}

func (m *Manager) handleConnect(w http.ResponseWriter, r *http.Request) {
	if _, _, err := splitHostPortDefault(r.Host, "443"); err != nil {
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	targetURL := &url.URL{Scheme: "https", Host: r.Host}
	m.recordBehavior(r, targetURL, "tunnel_attempted", "unknown", 0, nil)
	upstream, err := m.dialTunnel(r.Host, "443")
	if err != nil {
		m.recordBehavior(r, targetURL, "tunnel_failed", "failure", 0, egressErrorEvidence(err))
		log.Printf("egress CONNECT failed target=%s upstream=%s: %v", r.Host, m.Config().LogLabel(), err)
		if statusErr, ok := err.(*httpProxyStatusError); ok {
			http.Error(w, statusErr.Status, statusErr.StatusCode)
			return
		}
		http.Error(w, "failed to connect upstream", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	m.recordBehavior(r, targetURL, "tunnel_established", "success", http.StatusOK, nil)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		m.recordBehavior(r, targetURL, "tunnel_client_failed", "failure", 0, egressErrorEvidence(err))
		return
	}
	defer client.Close()

	if err := writeAll(client, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		m.recordBehavior(r, targetURL, "tunnel_client_failed", "failure", 0, egressErrorEvidence(err))
		return
	}
	result := relay(client, upstream)
	outcome := "success"
	if result.ClientError != "" || result.TargetError != "" {
		outcome = "failure"
	}
	m.recordBehavior(r, targetURL, "tunnel_closed", outcome, http.StatusOK, map[string]any{
		"bytes_to_client": result.BytesToClient,
		"bytes_to_target": result.BytesToTarget,
		"client_error":    result.ClientError,
		"target_error":    result.TargetError,
	})
}

func (m *Manager) dialHTTP(target *url.URL) (net.Conn, bool, string, error) {
	config := m.Config()
	address := ensurePort(target.Host, defaultPortForURL(target))
	if config.UpstreamType == "" {
		conn, err := net.DialTimeout("tcp", address, 15*time.Second)
		return conn, false, "", err
	}
	switch config.UpstreamType {
	case egressUpstreamTypeHTTP, egressUpstreamTypeHTTPS:
		conn, proxy, err := dialHTTPProxy(config)
		if err != nil {
			return nil, false, "", err
		}
		return conn, true, proxyAuthorizationHeader(proxy.URL), nil
	case egressUpstreamTypeSOCKS5:
		conn, err := dialViaSocks5Proxy(config.UpstreamAddr, address)
		return conn, false, "", err
	case egressUpstreamTypeTor:
		conn, err := dialViaTorProxy(address)
		return conn, false, "", err
	default:
		return nil, false, "", fmt.Errorf("unsupported upstream proxy type: %s", config.UpstreamType)
	}
}

func (m *Manager) dialTunnel(target string, defaultPort string) (net.Conn, error) {
	target = ensurePort(target, defaultPort)
	config := m.Config()
	if config.UpstreamType == "" {
		return net.DialTimeout("tcp", target, 15*time.Second)
	}
	switch config.UpstreamType {
	case egressUpstreamTypeHTTP, egressUpstreamTypeHTTPS:
		return dialViaHTTPProxy(config, target)
	case egressUpstreamTypeSOCKS5:
		return dialViaSocks5Proxy(config.UpstreamAddr, target)
	case egressUpstreamTypeTor:
		return dialViaTorProxy(target)
	default:
		return nil, fmt.Errorf("unsupported upstream proxy type: %s", config.UpstreamType)
	}
}

func dialViaHTTPProxy(config egressConfig, target string) (net.Conn, error) {
	conn, proxy, err := dialHTTPProxy(config)
	if err != nil {
		return nil, err
	}

	if err := writeHTTPProxyConnect(conn, target, proxyAuthorizationHeader(proxy.URL)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func dialHTTPProxy(config egressConfig) (net.Conn, httpProxyTarget, error) {
	proxy, err := parseHTTPProxyTarget(config.UpstreamType, config.UpstreamAddr)
	if err != nil {
		return nil, httpProxyTarget{}, err
	}

	conn, err := net.DialTimeout("tcp", proxy.URL.Host, 15*time.Second)
	if err != nil {
		return nil, httpProxyTarget{}, err
	}
	if err := conn.SetDeadline(time.Now().Add(proxyHandshakeTimeout)); err != nil {
		conn.Close()
		return nil, httpProxyTarget{}, err
	}
	defer conn.SetDeadline(time.Time{})
	if proxy.UseTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: proxy.URL.Hostname(),
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, httpProxyTarget{}, err
		}
		conn = tlsConn
	}
	return conn, proxy, nil
}

func writeHTTPProxyConnect(conn net.Conn, target string, proxyAuth string) error {
	if err := conn.SetDeadline(time.Now().Add(proxyHandshakeTimeout)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	var b strings.Builder
	b.WriteString("CONNECT ")
	b.WriteString(target)
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(target)
	b.WriteString("\r\n")
	if proxyAuth != "" {
		b.WriteString("Proxy-Authorization: ")
		b.WriteString(proxyAuth)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	if err := writeAll(conn, []byte(b.String())); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &httpProxyStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	return nil
}

type httpProxyStatusError struct {
	StatusCode int
	Status     string
}

func (e *httpProxyStatusError) Error() string {
	return "http proxy connect failed: " + e.Status
}

func (c egressConfig) LogLabel() string {
	if c.UpstreamAddr == "" {
		if c.UpstreamType == egressUpstreamTypeTor {
			return "tor://" + defaultTorSocksAddr
		}
		return "direct"
	}
	host := c.UpstreamAddr
	if _, _, address, ok := splitUserinfoHost(c.UpstreamAddr); ok {
		host = address
	}
	return c.UpstreamType + "://" + host
}

func dialViaTorProxy(target string) (net.Conn, error) {
	return dialViaSocks5Proxy(defaultTorSocksAddr, target)
}

func dialViaSocks5Proxy(upstream string, target string) (net.Conn, error) {
	user, password, address := splitUpstreamAuth(upstream)
	conn, err := net.DialTimeout("tcp", ensurePort(address, "1080"), 15*time.Second)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(proxyHandshakeTimeout)); err != nil {
		conn.Close()
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})
	if err := socks5Handshake(conn, user, password, target); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func socks5Handshake(conn net.Conn, user string, password string, target string) error {
	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x00, 0x02}
	}
	hello := []byte{0x05, byte(len(methods))}
	hello = append(hello, methods...)
	if err := writeAll(conn, hello); err != nil {
		return err
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] == 0xff {
		return fmt.Errorf("socks5 method rejected")
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		if len(user) > 255 || len(password) > 255 {
			return fmt.Errorf("socks5 credentials too long")
		}
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, []byte(user)...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, []byte(password)...)
		if err := writeAll(conn, auth); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, reply); err != nil {
			return err
		}
		if reply[0] != 0x01 || reply[1] != 0x00 {
			return fmt.Errorf("socks5 authentication failed")
		}
	default:
		return fmt.Errorf("unsupported socks5 authentication method: %d", reply[1])
	}

	host, port, err := splitHostPortDefault(target, "443")
	if err != nil {
		return err
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid target port: %s", port)
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("target host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portNum))
	req = append(req, portBytes...)
	if err := writeAll(conn, req); err != nil {
		return err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 || head[2] != 0x00 {
		return fmt.Errorf("invalid socks5 connect response")
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: %d", head[1])
	}
	switch head[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, conn, 4)
	case 0x03:
		var length [1]byte
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			return err
		}
		_, err = io.CopyN(io.Discard, conn, int64(length[0]))
	case 0x04:
		_, err = io.CopyN(io.Discard, conn, 16)
	default:
		err = fmt.Errorf("invalid socks5 address type: %d", head[3])
	}
	if err != nil {
		return err
	}
	_, err = io.CopyN(io.Discard, conn, 2)
	return err
}

func writeEgressResponse(w http.ResponseWriter, upstream net.Conn, request *http.Request) (int, error) {
	resp, err := http.ReadResponse(bufio.NewReader(upstream), request)
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return 0, err
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), cloneHeaderWithoutHopByHop(resp.Header))
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return resp.StatusCode, err
}

func (m *Manager) recordBehavior(
	request *http.Request,
	target *url.URL,
	action string,
	outcome string,
	statusCode int,
	requestEvidence map[string]any,
) {
	host, portValue, err := splitHostPortDefault(target.Host, defaultPortForURL(target))
	if err != nil {
		host = target.Hostname()
		portValue = target.Port()
	}
	port, _ := strconv.Atoi(portValue)
	destinationIP := ""
	if address := net.ParseIP(host); address != nil {
		destinationIP = address.String()
	}
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	attributes := map[string]any{
		"observer":        "egress_proxy",
		"method":          request.Method,
		"target_host":     truncateValue(host, 255),
		"target_path":     truncateValue(path, 2000),
		"upstream":        m.Config().LogLabel(),
		"response_status": statusCode,
	}
	for key, value := range requestEvidence {
		attributes[key] = value
	}
	m.recorder.Record(telemetry.Event{
		Category:        "network",
		Action:          "egress_" + action,
		Source:          "sensor",
		Direction:       "outbound",
		Outcome:         outcome,
		DestinationIP:   destinationIP,
		DestinationPort: port,
		Protocol:        target.Scheme,
		ServiceName:     truncateValue(host, 255),
		Attributes:      attributes,
	})
}

func captureEgressHTTPRequest(request *http.Request) (map[string]any, error) {
	headers := request.Header.Clone()
	targetURL := request.URL.String()
	evidence := map[string]any{
		"capture_complete": true,
		"request_headers":  headers,
		"target_query":     request.URL.RawQuery,
		"target_url":       targetURL,
	}
	if len(request.Method) > 128 {
		return evidence, fmt.Errorf("egress request method exceeds the evidence limit")
	}
	if len(targetURL) > 4000 {
		evidence["target_url_bytes"] = len(targetURL)
		evidence["target_url_sha256"] = fmt.Sprintf("%x", sha256.Sum256([]byte(targetURL)))
		delete(evidence, "target_url")
		return evidence, fmt.Errorf("egress request URL exceeds the evidence limit")
	}
	if len(request.URL.RawQuery) > 4000 {
		evidence["target_query_bytes"] = len(request.URL.RawQuery)
		evidence["target_query_sha256"] = fmt.Sprintf("%x", sha256.Sum256([]byte(request.URL.RawQuery)))
		delete(evidence, "target_query")
		return evidence, fmt.Errorf("egress request query exceeds the evidence limit")
	}
	headerPayload, err := json.Marshal(headers)
	if err != nil {
		delete(evidence, "request_headers")
		return evidence, fmt.Errorf("egress request headers could not be encoded: %w", err)
	}
	for key, values := range headers {
		if len(key) > 4000 {
			compactEgressHeaderEvidence(evidence, headerPayload)
			return evidence, fmt.Errorf("egress request header name exceeds the evidence limit")
		}
		for _, value := range values {
			if len(value) > 4000 {
				compactEgressHeaderEvidence(evidence, headerPayload)
				return evidence, fmt.Errorf("egress request header value exceeds the evidence limit")
			}
		}
	}
	if request.Body != nil {
		body, err := io.ReadAll(io.LimitReader(request.Body, maxEgressRequestBody+1))
		closeErr := request.Body.Close()
		if err != nil {
			return evidence, fmt.Errorf("egress request body could not be captured: %w", err)
		}
		if closeErr != nil {
			return evidence, fmt.Errorf("egress request body could not be closed after capture: %w", closeErr)
		}
		if len(body) > maxEgressRequestBody {
			evidence["request_body_bytes_at_least"] = len(body)
			return evidence, fmt.Errorf("egress request body exceeds the evidence limit")
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		if len(body) > 0 {
			evidence["request_body_bytes"] = len(body)
			evidence["request_body_sha256"] = fmt.Sprintf("%x", sha256.Sum256(body))
			if utf8.Valid(body) {
				evidence["request_body"] = string(body)
				evidence["request_body_encoding"] = "utf-8"
			} else {
				evidence["request_body"] = base64.StdEncoding.EncodeToString(body)
				evidence["request_body_encoding"] = "base64"
			}
		}
	}
	payload, err := json.Marshal(evidence)
	if err != nil {
		return evidence, fmt.Errorf("egress request evidence could not be encoded: %w", err)
	}
	if len(payload) > maxEgressRequestEvidence {
		compactEgressHeaderEvidence(evidence, headerPayload)
		return evidence, fmt.Errorf("egress request headers exceed the evidence limit")
	}
	return evidence, nil
}

func compactEgressHeaderEvidence(evidence map[string]any, payload []byte) {
	delete(evidence, "request_headers")
	evidence["request_headers_bytes"] = len(payload)
	evidence["request_headers_sha256"] = fmt.Sprintf("%x", sha256.Sum256(payload))
}

func egressErrorEvidence(err error) map[string]any {
	if err == nil {
		return nil
	}
	message := err.Error()
	if len(message) <= 4000 {
		return map[string]any{"error": message}
	}
	return map[string]any{
		"error_bytes":  len(message),
		"error_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(message))),
	}
}

func writeEgressHTTPRequest(req *http.Request, conn net.Conn, useProxyFormat bool) error {
	if useProxyFormat {
		return req.WriteProxy(conn)
	}
	return req.Write(conn)
}

func parseHTTPProxyTarget(proxyType string, upstream string) (httpProxyTarget, error) {
	rawURL := "http://" + upstream
	proxyURL, err := url.Parse(rawURL)
	if err != nil {
		return httpProxyTarget{}, err
	}
	if proxyURL.Hostname() == "" || proxyURL.Path != "" || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		return httpProxyTarget{}, fmt.Errorf("invalid HTTP proxy address")
	}
	useTLS := proxyType == egressUpstreamTypeHTTPS
	defaultPort := "8080"
	if useTLS {
		defaultPort = "443"
	}
	host, port, err := splitHostPortDefault(proxyURL.Host, defaultPort)
	if err != nil {
		return httpProxyTarget{}, err
	}
	proxyURL.Host = net.JoinHostPort(host, port)
	return httpProxyTarget{URL: proxyURL, UseTLS: useTLS}, nil
}

func proxyAuthorizationHeader(proxyURL *url.URL) string {
	if proxyURL.User == nil {
		return ""
	}
	password, _ := proxyURL.User.Password()
	token := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
	return "Basic " + token
}

func absoluteFormURL(target *url.URL) *url.URL {
	next := *target
	return &next
}

func originFormURL(target *url.URL) *url.URL {
	next := *target
	next.Scheme = ""
	next.Host = ""
	next.User = nil
	return &next
}

func defaultPortForURL(target *url.URL) string {
	if target.Scheme == "https" {
		return "443"
	}
	return "80"
}

func splitUpstreamAuth(upstream string) (string, string, string) {
	user, password, address, ok := splitUserinfoHost(upstream)
	if !ok {
		return "", "", upstream
	}
	return user, password, address
}

func splitUserinfoHost(value string) (string, string, string, bool) {
	index := strings.LastIndex(value, "@")
	if index < 0 {
		return "", "", value, false
	}
	before, after := value[:index], value[index+1:]
	user, password, _ := strings.Cut(before, ":")
	if decoded, err := url.PathUnescape(user); err == nil {
		user = decoded
	}
	if decoded, err := url.PathUnescape(password); err == nil {
		password = decoded
	}
	return user, password, after, true
}

func splitHostPortDefault(address string, defaultPort string) (string, string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", "", fmt.Errorf("host is required")
	}
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		if host == "" || !validPort(port) {
			return "", "", fmt.Errorf("invalid host or port")
		}
		return host, port, nil
	}
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		address = strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")
	}
	if net.ParseIP(address) != nil || !strings.Contains(address, ":") {
		if !validPort(defaultPort) {
			return "", "", fmt.Errorf("invalid default port")
		}
		return address, defaultPort, nil
	}
	return "", "", err
}

func ensurePort(address string, defaultPort string) string {
	host, port, err := splitHostPortDefault(address, defaultPort)
	if err != nil {
		return address
	}
	return net.JoinHostPort(host, port)
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
}

func copyHeader(dst http.Header, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func cloneHeaderWithoutHopByHop(src http.Header) http.Header {
	dst := make(http.Header, len(src))
	connectionHeaders := make(map[string]struct{})
	for _, value := range src.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if name := http.CanonicalHeaderKey(strings.TrimSpace(token)); name != "" {
				connectionHeaders[name] = struct{}{}
			}
		}
	}
	for key, values := range src {
		canonical := http.CanonicalHeaderKey(key)
		if isHopByHopHeader(canonical) {
			continue
		}
		if _, exists := connectionHeaders[canonical]; exists {
			continue
		}
		dst[key] = append([]string{}, values...)
	}
	return dst
}

func isHopByHopHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

type relayResult struct {
	BytesToClient int64
	BytesToTarget int64
	ClientError   string
	TargetError   string
}

type relayDirectionResult struct {
	direction string
	bytes     int64
	err       error
}

func relay(client net.Conn, target net.Conn) relayResult {
	done := make(chan relayDirectionResult, 2)
	go func() {
		bytesCopied, err := io.Copy(client, target)
		done <- relayDirectionResult{direction: "client", bytes: bytesCopied, err: err}
	}()
	go func() {
		bytesCopied, err := io.Copy(target, client)
		done <- relayDirectionResult{direction: "target", bytes: bytesCopied, err: err}
	}()
	first := <-done
	_ = client.Close()
	_ = target.Close()
	second := <-done
	result := relayResult{}
	for _, direction := range []relayDirectionResult{first, second} {
		if direction.direction == "client" {
			result.BytesToClient = direction.bytes
			result.ClientError = relayErrorString(direction.err)
		} else {
			result.BytesToTarget = direction.bytes
			result.TargetError = relayErrorString(direction.err)
		}
	}
	return result
}

func relayErrorString(err error) string {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return ""
	}
	return err.Error()
}

func truncateValue(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		payload = payload[written:]
	}
	return nil
}
