package telemetry

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	defaultTelemetryPath = "/var/lib/v3il/telemetry/events.jsonl"
	telemetryPathEnvName = "V3IL_TELEMETRY_PATH"
	MaxPageSize          = 1000
)

type Event struct {
	Sequence           int64          `json:"sequence"`
	ObservedAt         time.Time      `json:"observed_at"`
	Category           string         `json:"category"`
	Action             string         `json:"action"`
	Source             string         `json:"source"`
	Direction          string         `json:"direction,omitempty"`
	Outcome            string         `json:"outcome,omitempty"`
	SourceIP           string         `json:"source_ip,omitempty"`
	SourcePort         int            `json:"source_port,omitempty"`
	DestinationIP      string         `json:"destination_ip,omitempty"`
	DestinationPort    int            `json:"destination_port,omitempty"`
	Protocol           string         `json:"protocol,omitempty"`
	ProcessID          int            `json:"process_id,omitempty"`
	ParentProcessID    int            `json:"parent_process_id,omitempty"`
	ProcessName        string         `json:"process_name,omitempty"`
	CommandLine        string         `json:"command_line,omitempty"`
	FilePath           string         `json:"file_path,omitempty"`
	Username           string         `json:"username,omitempty"`
	ServiceName        string         `json:"service_name,omitempty"`
	Summary            string         `json:"summary,omitempty"`
	RawReference       string         `json:"raw_reference,omitempty"`
	Attributes         map[string]any `json:"attributes,omitempty"`
	SensorPreviousHash string         `json:"sensor_previous_hash,omitempty"`
	SensorEventHash    string         `json:"sensor_event_hash,omitempty"`
}

type Recorder interface {
	Record(event Event)
}

type Store struct {
	mu             sync.Mutex
	sensorID       string
	path           string
	file           *os.File
	sequence       int64
	hmacKey        []byte
	lastSensorHash string
	lastError      string
}

type Batch struct {
	SensorID string  `json:"sensor_id"`
	Events   []Event `json:"events"`
}

type Snapshot struct {
	SensorID  string `json:"sensor_id"`
	Sequence  int64  `json:"sequence"`
	Journal   string `json:"journal"`
	LastError string `json:"last_error"`
}

func NewStore(sensorID string, hmacKey []byte) (*Store, error) {
	if len(hmacKey) == 0 {
		return nil, fmt.Errorf("behavior sensor HMAC key is required")
	}
	path := os.Getenv(telemetryPathEnvName)
	if path == "" {
		path = defaultTelemetryPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	sequence, lastSensorHash, err := lastTelemetryState(path, hmacKey)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &Store{
		sensorID:       sensorID,
		path:           path,
		file:           file,
		sequence:       sequence,
		hmacKey:        append([]byte(nil), hmacKey...),
		lastSensorHash: lastSensorHash,
	}, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.file.Sync()
	return s.file.Close()
}

func (s *Store) Record(event Event) {
	if event.Action == "" || event.Category == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	event.Sequence = s.sequence + 1
	if event.ObservedAt.IsZero() {
		event.ObservedAt = time.Now().UTC()
	}
	event.ObservedAt = event.ObservedAt.UTC().Truncate(time.Microsecond)
	if event.Source == "" {
		event.Source = "sensor"
	}
	if event.Direction == "" {
		event.Direction = "unknown"
	}
	if event.Outcome == "" {
		event.Outcome = "unknown"
	}
	event.RawReference = fmt.Sprintf("sensor://%s/%d", s.sensorID, event.Sequence)
	event.SensorPreviousHash = s.lastSensorHash
	sensorHash, err := sensorEventHash(event, s.hmacKey)
	if err != nil {
		s.lastError = "encode sensor integrity payload: " + err.Error()
		log.Printf("%s", s.lastError)
		return
	}
	event.SensorEventHash = sensorHash
	payload, err := json.Marshal(event)
	if err != nil {
		s.lastError = "encode telemetry event: " + err.Error()
		log.Printf("%s", s.lastError)
		return
	}
	record := append(payload, '\n')
	if err := s.appendRecord(record); err != nil {
		s.lastError = "persist telemetry event: " + err.Error()
		log.Printf("%s", s.lastError)
		return
	}
	s.sequence = event.Sequence
	s.lastSensorHash = event.SensorEventHash
	if err := s.file.Sync(); err != nil {
		s.lastError = "sync telemetry event: " + err.Error()
		log.Printf("%s", s.lastError)
		return
	}
	s.lastError = ""
}

func (s *Store) appendRecord(record []byte) error {
	offset, err := s.file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	written, err := s.file.Write(record)
	if err == nil && written != len(record) {
		err = io.ErrShortWrite
	}
	if err == nil {
		return nil
	}
	if truncateErr := s.file.Truncate(offset); truncateErr != nil {
		return fmt.Errorf("%w; partial record rollback failed: %v", err, truncateErr)
	}
	if _, seekErr := s.file.Seek(0, io.SeekEnd); seekErr != nil {
		return fmt.Errorf("%w; journal seek after rollback failed: %v", err, seekErr)
	}
	return err
}

func (s *Store) ReadAfter(after int64, limit int) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	events := make([]Event, 0, limit)
	var previousSequence int64
	previousSensorHash := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("telemetry journal contains an invalid record: %w", err)
		}
		if err := validateSensorEvent(event, previousSequence+1, previousSensorHash, s.hmacKey); err != nil {
			return nil, fmt.Errorf("telemetry journal integrity validation failed: %w", err)
		}
		previousSequence = event.Sequence
		previousSensorHash = event.SensorEventHash
		if event.Sequence <= after {
			continue
		}
		events = append(events, event)
		if len(events) >= limit {
			break
		}
	}
	return events, scanner.Err()
}

func lastTelemetryState(path string, hmacKey []byte) (int64, string, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	defer file.Close()

	var last int64
	lastSensorHash := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return 0, "", fmt.Errorf("telemetry journal contains an invalid record: %w", err)
		}
		if err := validateSensorEvent(event, last+1, lastSensorHash, hmacKey); err != nil {
			return 0, "", fmt.Errorf("telemetry journal integrity validation failed: %w", err)
		}
		last = event.Sequence
		lastSensorHash = event.SensorEventHash
	}
	if err := scanner.Err(); err != nil {
		return 0, "", err
	}
	return last, lastSensorHash, nil
}

func SensorHMACKey(token string) []byte {
	digest := sha256.Sum256([]byte("v3il-sensor-hmac:" + token))
	return digest[:]
}

func sensorEventHash(event Event, hmacKey []byte) (string, error) {
	unsigned := event
	unsigned.SensorEventHash = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return "", err
	}
	var canonical map[string]json.RawMessage
	if err := json.Unmarshal(payload, &canonical); err != nil {
		return "", err
	}
	canonicalTimestamp, err := json.Marshal(
		event.ObservedAt.UTC().Format("2006-01-02T15:04:05.000000Z"),
	)
	if err != nil {
		return "", err
	}
	canonical["observed_at"] = canonicalTimestamp
	payload, err = json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, hmacKey)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func validateSensorEvent(
	event Event,
	expectedSequence int64,
	expectedPreviousHash string,
	hmacKey []byte,
) error {
	if event.Sequence != expectedSequence {
		return fmt.Errorf("expected sequence %d, received %d", expectedSequence, event.Sequence)
	}
	if event.SensorPreviousHash != expectedPreviousHash {
		return fmt.Errorf("sequence %d previous sensor hash does not match", event.Sequence)
	}
	expectedHash, err := sensorEventHash(event, hmacKey)
	if err != nil {
		return fmt.Errorf("sequence %d sensor payload is invalid: %w", event.Sequence, err)
	}
	if !hmac.Equal([]byte(event.SensorEventHash), []byte(expectedHash)) {
		return fmt.Errorf("sequence %d sensor HMAC is invalid", event.Sequence)
	}
	return nil
}

func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{
		SensorID:  s.sensorID,
		Sequence:  s.sequence,
		Journal:   s.path,
		LastError: s.lastError,
	}
}
