package control

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sandbox-proxy/internal/telemetry"
)

const (
	defaultServiceTelemetrySocket = "/run/v3il/telemetry.sock"
	serviceTelemetrySocketEnvName = "V3IL_TELEMETRY_SOCKET"
	maxServiceTelemetryBodyBytes  = 64 * 1024
	maxServiceTelemetryDepth      = 8
	maxServiceTelemetryItems      = 256
)

var allowedServiceTelemetryCategories = map[string]struct{}{
	"network":        {},
	"process":        {},
	"command":        {},
	"file":           {},
	"authentication": {},
	"service":        {},
	"system":         {},
}

type serviceTelemetryEvent struct {
	ObservedAt      time.Time      `json:"observed_at,omitempty"`
	Category        string         `json:"category"`
	Action          string         `json:"action"`
	Direction       string         `json:"direction,omitempty"`
	Outcome         string         `json:"outcome,omitempty"`
	SourceIP        string         `json:"source_ip,omitempty"`
	SourcePort      int            `json:"source_port,omitempty"`
	DestinationIP   string         `json:"destination_ip,omitempty"`
	DestinationPort int            `json:"destination_port,omitempty"`
	Protocol        string         `json:"protocol,omitempty"`
	ProcessID       int            `json:"process_id,omitempty"`
	ParentProcessID int            `json:"parent_process_id,omitempty"`
	ProcessName     string         `json:"process_name,omitempty"`
	CommandLine     string         `json:"command_line,omitempty"`
	FilePath        string         `json:"file_path,omitempty"`
	Username        string         `json:"username,omitempty"`
	ServiceName     string         `json:"service_name,omitempty"`
	Summary         string         `json:"summary,omitempty"`
	Attributes      map[string]any `json:"attributes,omitempty"`
}

func (s *Server) StartServiceTelemetryServer() (*http.Server, net.Listener, string, error) {
	socketPath := os.Getenv(serviceTelemetrySocketEnvName)
	if socketPath == "" {
		socketPath = defaultServiceTelemetrySocket
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return nil, nil, socketPath, err
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, socketPath, err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, nil, socketPath, err
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		listener.Close()
		return nil, nil, socketPath, err
	}
	if err := os.Chown(socketPath, 0, DeceptionRuntimeGID); err != nil {
		listener.Close()
		return nil, nil, socketPath, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/events", s.handleServiceTelemetryEvent)
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}, listener, socketPath, nil
}

func (s *Server) handleServiceTelemetryEvent(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxServiceTelemetryBodyBytes)
	var submitted serviceTelemetryEvent
	if !decodeJSON(w, r, &submitted) {
		return
	}
	event, err := normalizeServiceTelemetryEvent(submitted)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.recorder.Record(event)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func normalizeServiceTelemetryEvent(submitted serviceTelemetryEvent) (telemetry.Event, error) {
	category := strings.ToLower(strings.TrimSpace(submitted.Category))
	if _, ok := allowedServiceTelemetryCategories[category]; !ok {
		return telemetry.Event{}, fmt.Errorf("unsupported service telemetry category")
	}
	action := strings.TrimSpace(submitted.Action)
	if action == "" || len(action) > 128 {
		return telemetry.Event{}, fmt.Errorf("service telemetry action is required and cannot exceed 128 bytes")
	}
	sourceIP, err := normalizedTelemetryIPAddress(submitted.SourceIP)
	if err != nil {
		return telemetry.Event{}, fmt.Errorf("invalid service telemetry source IP")
	}
	destinationIP, err := normalizedTelemetryIPAddress(submitted.DestinationIP)
	if err != nil {
		return telemetry.Event{}, fmt.Errorf("invalid service telemetry destination IP")
	}
	if !validTelemetryPort(submitted.SourcePort) || !validTelemetryPort(submitted.DestinationPort) {
		return telemetry.Event{}, fmt.Errorf("service telemetry port is out of range")
	}
	direction := normalizedTelemetryDirection(submitted.Direction)
	outcome := normalizedTelemetryOutcome(submitted.Outcome)
	if direction == "" || outcome == "" {
		return telemetry.Event{}, fmt.Errorf("invalid service telemetry direction or outcome")
	}
	attributes, err := validateTelemetryAttributes(submitted.Attributes, 0)
	if err != nil {
		return telemetry.Event{}, err
	}
	event := telemetry.Event{
		ObservedAt:      submitted.ObservedAt,
		Category:        category,
		Action:          action,
		Source:          "service",
		Direction:       direction,
		Outcome:         outcome,
		SourceIP:        sourceIP,
		SourcePort:      submitted.SourcePort,
		DestinationIP:   destinationIP,
		DestinationPort: submitted.DestinationPort,
		Protocol:        truncateObservedValue(strings.TrimSpace(submitted.Protocol), 32),
		ProcessID:       submitted.ProcessID,
		ParentProcessID: submitted.ParentProcessID,
		ProcessName:     truncateObservedValue(strings.TrimSpace(submitted.ProcessName), 255),
		CommandLine:     truncateObservedValue(strings.TrimSpace(submitted.CommandLine), 16000),
		FilePath:        truncateObservedValue(strings.TrimSpace(submitted.FilePath), 4096),
		Username:        truncateObservedValue(strings.TrimSpace(submitted.Username), 255),
		ServiceName:     truncateObservedValue(strings.TrimSpace(submitted.ServiceName), 255),
		Summary:         truncateObservedValue(strings.TrimSpace(submitted.Summary), 4000),
		Attributes:      attributes,
	}
	if err := validateServiceTelemetryCategoryDetail(event); err != nil {
		return telemetry.Event{}, err
	}
	return event, nil
}

func validateServiceTelemetryCategoryDetail(event telemetry.Event) error {
	switch event.Category {
	case "network":
		if event.SourceIP == "" && event.DestinationIP == "" && event.SourcePort == 0 && event.DestinationPort == 0 && event.Protocol == "" {
			return fmt.Errorf("network service telemetry is missing network detail")
		}
	case "process":
		if event.ProcessID == 0 && event.ProcessName == "" {
			return fmt.Errorf("process service telemetry is missing process detail")
		}
	case "command":
		if event.CommandLine == "" {
			return fmt.Errorf("command service telemetry is missing command detail")
		}
	case "file":
		if event.FilePath == "" {
			return fmt.Errorf("file service telemetry is missing file detail")
		}
	case "authentication", "service":
		if event.ServiceName == "" {
			return fmt.Errorf("service telemetry is missing service_name")
		}
	}
	return nil
}

func normalizedTelemetryIPAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	address := net.ParseIP(value)
	if address == nil {
		return "", fmt.Errorf("invalid IP address")
	}
	return address.String(), nil
}

func validTelemetryPort(value int) bool {
	return value >= 0 && value <= 65535
}

func normalizedTelemetryDirection(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown":
		return "unknown"
	case "inbound":
		return "inbound"
	case "outbound":
		return "outbound"
	case "internal":
		return "internal"
	default:
		return ""
	}
}

func normalizedTelemetryOutcome(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown":
		return "unknown"
	case "success":
		return "success"
	case "failure":
		return "failure"
	default:
		return ""
	}
}

func validateTelemetryAttributes(attributes map[string]any, depth int) (map[string]any, error) {
	if len(attributes) == 0 {
		return nil, nil
	}
	if depth > maxServiceTelemetryDepth {
		return nil, fmt.Errorf("service telemetry attributes exceed the depth limit")
	}
	if len(attributes) > maxServiceTelemetryItems {
		return nil, fmt.Errorf("service telemetry attributes exceed the item limit")
	}
	result := make(map[string]any, len(attributes))
	for key, value := range attributes {
		validated, err := validateTelemetryValue(value, depth+1)
		if err != nil {
			return nil, err
		}
		result[key] = validated
	}
	return result, nil
}

func validateTelemetryValue(value any, depth int) (any, error) {
	if depth > maxServiceTelemetryDepth {
		return nil, fmt.Errorf("service telemetry attributes exceed the depth limit")
	}
	switch item := value.(type) {
	case map[string]any:
		return validateTelemetryAttributes(item, depth)
	case []any:
		if len(item) > maxServiceTelemetryItems {
			return nil, fmt.Errorf("service telemetry attributes exceed the item limit")
		}
		result := make([]any, 0, len(item))
		for _, entry := range item {
			validated, err := validateTelemetryValue(entry, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, validated)
		}
		return result, nil
	case string:
		if len(item) > 4000 {
			return nil, fmt.Errorf("service telemetry attribute strings exceed the length limit")
		}
		return item, nil
	case float64:
		if math.IsNaN(item) || math.IsInf(item, 0) {
			return nil, fmt.Errorf("service telemetry attributes require finite numeric values")
		}
		return item, nil
	case bool, nil:
		return value, nil
	default:
		return nil, fmt.Errorf("service telemetry attributes contain an unsupported value")
	}
}
