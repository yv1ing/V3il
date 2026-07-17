package observer

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sandbox-proxy/internal/telemetry"
)

type Observer struct {
	recorder telemetry.Recorder
	health   *healthStore
}

type HealthItem struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type healthStore struct {
	mu    sync.RWMutex
	items map[string]HealthItem
}

func New(recorder telemetry.Recorder) *Observer {
	return &Observer{
		recorder: recorder,
		health:   &healthStore{items: make(map[string]HealthItem)},
	}
}

func (o *Observer) Start(ctx context.Context) {
	go o.runPacketObserver(ctx)
	go o.runKernelProcessObserver(ctx)
	go o.runProcessReconciler(ctx)
	go o.runFilesystemObserver(ctx)
}

func (o *Observer) Snapshot() []HealthItem {
	return o.health.Snapshot()
}

func (s *healthStore) Set(name string, status string, message string) (HealthItem, bool) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.items[name]
	item := previous
	if item.StartedAt.IsZero() {
		item.StartedAt = now
	}
	item.Name = name
	item.Status = status
	item.Message = message
	item.UpdatedAt = now
	s.items[name] = item
	return previous, previous.Status != status || previous.Message != message
}

func (s *healthStore) IsActive(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.items[name].Status == "active"
}

func (s *healthStore) Snapshot() []HealthItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]HealthItem, 0, len(s.items))
	for _, item := range s.items {
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].Name < result[right].Name
	})
	return result
}

func durationFromMilliseconds(name string, fallback time.Duration, minimum time.Duration, maximum time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	milliseconds, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	duration := time.Duration(milliseconds) * time.Millisecond
	if duration < minimum {
		return minimum
	}
	if duration > maximum {
		return maximum
	}
	return duration
}

func (o *Observer) recordState(name string, action string, summary string, attributes map[string]any) {
	if attributes == nil {
		attributes = make(map[string]any)
	}
	attributes["observer"] = name
	o.recorder.Record(telemetry.Event{
		Category:   "system",
		Action:     action,
		Source:     "sensor",
		Outcome:    "success",
		Summary:    summary,
		Attributes: attributes,
	})
}

func (o *Observer) recordRecovery(name string, message string) {
	previous, changed := o.health.Set(name, "active", message)
	if !changed || previous.Status != "degraded" {
		return
	}
	o.recordState(name, "observer_recovered", "Behavior observer recovered.", map[string]any{
		"previous_message": previous.Message,
	})
}

func (o *Observer) recordFailure(name string, message string, err error) {
	detail := message
	if err != nil {
		detail += ": " + err.Error()
	}
	_, changed := o.health.Set(name, "degraded", detail)
	if !changed {
		return
	}
	o.recorder.Record(telemetry.Event{
		Category: "system",
		Action:   "observer_degraded",
		Source:   "sensor",
		Outcome:  "failure",
		Summary:  detail,
		Attributes: map[string]any{
			"observer": name,
		},
	})
}

func truncateValue(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
