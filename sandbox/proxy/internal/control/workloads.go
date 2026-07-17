package control

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"sandbox-proxy/internal/telemetry"
)

const observedTraceRoot = "/var/lib/v3il/telemetry/traces"

var (
	quotedValueRE = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	ipv4AddressRE = regexp.MustCompile(`inet_addr\("([^"]+)"\)`)
	ipv6AddressRE = regexp.MustCompile(`inet_pton\(AF_INET6, "([^"]+)"`)
	networkPortRE = regexp.MustCompile(`htons\(([0-9]+)\)`)
)

type observedWorkloadRequest struct {
	Name             string            `json:"name"`
	Command          string            `json:"command"`
	WorkingDirectory string            `json:"working_directory"`
	Environment      map[string]string `json:"environment"`
}

type observedWorkload struct {
	RunID            string     `json:"run_id"`
	Name             string     `json:"name"`
	Command          string     `json:"command"`
	WorkingDirectory string     `json:"working_directory"`
	ProcessID        int        `json:"process_id"`
	Status           string     `json:"status"`
	ExitCode         *int       `json:"exit_code"`
	Error            string     `json:"error"`
	StartedAt        time.Time  `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at"`
	command          *exec.Cmd
}

type observedWorkloadManager struct {
	mu          sync.Mutex
	workloads   map[string]*observedWorkload
	server      *Server
	traceErrors map[string]string
}

func newObservedWorkloadManager(server *Server) *observedWorkloadManager {
	return &observedWorkloadManager{
		workloads:   make(map[string]*observedWorkload),
		server:      server,
		traceErrors: make(map[string]string),
	}
}

func (m *observedWorkloadManager) Start(request observedWorkloadRequest) (*observedWorkload, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Command = strings.TrimSpace(request.Command)
	request.WorkingDirectory = strings.TrimSpace(request.WorkingDirectory)
	if request.Name == "" || len(request.Name) > 128 {
		return nil, errors.New("workload name must contain between 1 and 128 characters")
	}
	if request.Command == "" || len(request.Command) > 16000 {
		return nil, errors.New("workload command must contain between 1 and 16000 characters")
	}
	if request.WorkingDirectory == "" {
		request.WorkingDirectory = "/opt/deception"
	}
	info, err := os.Stat(request.WorkingDirectory)
	if err != nil || !info.IsDir() {
		return nil, errors.New("workload working directory does not exist")
	}
	if len(request.Environment) > 128 {
		return nil, errors.New("workload environment cannot contain more than 128 variables")
	}
	if err := os.MkdirAll(observedTraceRoot, 0o750); err != nil {
		return nil, err
	}

	runID, err := randomRunID()
	if err != nil {
		return nil, err
	}
	tracePrefix := filepath.Join(observedTraceRoot, runID)
	command := exec.Command(
		"strace",
		"-u", DeceptionRuntimeUser,
		"-ff",
		"-ttt",
		"-s", "4096",
		"-e", "trace=process,file,network",
		"-o", tracePrefix,
		"/bin/sh", "-lc", request.Command,
	)
	command.Dir = request.WorkingDirectory
	command.Env = append(m.server.RuntimeEnvironment(), m.server.egress.RuntimeEnvironmentOverlay()...)
	for key, value := range request.Environment {
		if strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
			return nil, errors.New("workload environment contains an invalid variable")
		}
		command.Env = append(command.Env, key+"="+value)
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}

	startedAt := time.Now().UTC()
	workload := &observedWorkload{
		RunID:            runID,
		Name:             request.Name,
		Command:          request.Command,
		WorkingDirectory: request.WorkingDirectory,
		ProcessID:        command.Process.Pid,
		Status:           "running",
		StartedAt:        startedAt,
		command:          command,
	}
	m.mu.Lock()
	m.workloads[runID] = workload
	m.mu.Unlock()

	m.server.recorder.Record(telemetry.Event{
		Category:    "service",
		Action:      "workload_started",
		Source:      "sensor",
		Outcome:     "success",
		ProcessID:   command.Process.Pid,
		ProcessName: "strace",
		CommandLine: request.Command,
		ServiceName: request.Name,
		Attributes:  map[string]any{"run_id": runID, "working_directory": request.WorkingDirectory},
	})
	response := cloneObservedWorkload(workload)
	go m.wait(workload, tracePrefix)
	return response, nil
}

func (m *observedWorkloadManager) List() []*observedWorkload {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]*observedWorkload, 0, len(m.workloads))
	for _, workload := range m.workloads {
		items = append(items, cloneObservedWorkload(workload))
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].StartedAt.After(items[j].StartedAt)
	})
	return items
}

func (m *observedWorkloadManager) Stop(runID string) (*observedWorkload, error) {
	m.mu.Lock()
	workload := m.workloads[runID]
	if workload == nil {
		m.mu.Unlock()
		return nil, os.ErrNotExist
	}
	if workload.Status != "running" || workload.command == nil || workload.command.Process == nil {
		result := cloneObservedWorkload(workload)
		m.mu.Unlock()
		return result, nil
	}
	processID := workload.command.Process.Pid
	m.mu.Unlock()

	if err := syscall.Kill(-processID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return nil, err
	}
	m.mu.Lock()
	result := cloneObservedWorkload(workload)
	m.mu.Unlock()
	return result, nil
}

func (m *observedWorkloadManager) wait(workload *observedWorkload, tracePrefix string) {
	done := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		m.watchObservedTrace(workload.RunID, tracePrefix, done)
		close(watchDone)
	}()
	err := workload.command.Wait()
	close(done)
	<-watchDone

	finishedAt := time.Now().UTC()
	status := "stopped"
	outcome := "success"
	errorMessage := ""
	var exitCode *int
	if workload.command.ProcessState != nil {
		code := workload.command.ProcessState.ExitCode()
		exitCode = &code
		if code != 0 {
			status = "failed"
			outcome = "failure"
		}
	}
	if err != nil {
		errorMessage = err.Error()
	}
	m.mu.Lock()
	workload.Status = status
	workload.ExitCode = exitCode
	workload.Error = errorMessage
	workload.FinishedAt = &finishedAt
	workload.command = nil
	m.mu.Unlock()

	m.server.recorder.Record(telemetry.Event{
		Category:    "service",
		Action:      "workload_stopped",
		Source:      "sensor",
		Outcome:     outcome,
		ProcessID:   workload.ProcessID,
		ServiceName: workload.Name,
		Summary:     errorMessage,
		Attributes:  map[string]any{"run_id": workload.RunID, "exit_code": exitCode},
	})
}

func cloneObservedWorkload(workload *observedWorkload) *observedWorkload {
	clone := *workload
	clone.command = nil
	return &clone
}

func randomRunID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (m *observedWorkloadManager) watchObservedTrace(runID string, tracePrefix string, done <-chan struct{}) {
	offsets := make(map[string]int64)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		m.readObservedTraceFiles(runID, tracePrefix, offsets, false)
		select {
		case <-done:
			m.readObservedTraceFiles(runID, tracePrefix, offsets, true)
			return
		case <-ticker.C:
		}
	}
}

func (m *observedWorkloadManager) readObservedTraceFiles(
	runID string,
	tracePrefix string,
	offsets map[string]int64,
	final bool,
) {
	paths, globErr := filepath.Glob(tracePrefix + ".*")
	if globErr != nil {
		m.recordTraceFailure(runID, tracePrefix, globErr)
		return
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			m.recordTraceFailure(runID, path, err)
			continue
		}
		currentOffset := offsets[path]
		if _, err := file.Seek(currentOffset, 0); err != nil {
			file.Close()
			m.recordTraceFailure(runID, path, err)
			continue
		}
		reader := bufio.NewReaderSize(file, 64*1024)
		readFailed := false
		for {
			line, readErr := reader.ReadString('\n')
			if readErr == nil {
				currentOffset += int64(len(line))
				if event := parseObservedTraceLine(runID, traceProcessID(path), line); event != nil {
					m.server.recorder.Record(*event)
				}
				continue
			}
			if errors.Is(readErr, io.EOF) {
				if final && len(line) > 0 {
					currentOffset += int64(len(line))
					if event := parseObservedTraceLine(runID, traceProcessID(path), line); event != nil {
						m.server.recorder.Record(*event)
					}
				}
				break
			}
			m.recordTraceFailure(runID, path, readErr)
			readFailed = true
			break
		}
		file.Close()
		offsets[path] = currentOffset
		if !readFailed {
			m.recordTraceRecovery(runID, path)
		}
	}
}

func (m *observedWorkloadManager) recordTraceFailure(runID string, path string, err error) {
	detail := err.Error()
	m.mu.Lock()
	if m.traceErrors[path] == detail {
		m.mu.Unlock()
		return
	}
	m.traceErrors[path] = detail
	m.mu.Unlock()
	m.server.recorder.Record(telemetry.Event{
		Category: "system",
		Action:   "observer_degraded",
		Source:   "sensor",
		Outcome:  "failure",
		Summary:  "Observed workload trace could not be read; syscall evidence may be incomplete.",
		Attributes: map[string]any{
			"observer":   "workload_trace",
			"run_id":     runID,
			"trace_file": filepath.Base(path),
			"error_type": fmt.Sprintf("%T", err),
		},
	})
}

func (m *observedWorkloadManager) recordTraceRecovery(runID string, path string) {
	m.mu.Lock()
	if _, exists := m.traceErrors[path]; !exists {
		m.mu.Unlock()
		return
	}
	delete(m.traceErrors, path)
	m.mu.Unlock()
	m.server.recorder.Record(telemetry.Event{
		Category: "system",
		Action:   "observer_recovered",
		Source:   "sensor",
		Outcome:  "success",
		Summary:  "Observed workload trace reading recovered.",
		Attributes: map[string]any{
			"observer":   "workload_trace",
			"run_id":     runID,
			"trace_file": filepath.Base(path),
		},
	})
}

func traceProcessID(path string) int {
	value := path[strings.LastIndex(path, ".")+1:]
	processID, _ := strconv.Atoi(value)
	return processID
}

func parseObservedTraceLine(runID string, processID int, line string) *telemetry.Event {
	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	observedAt := time.Now().UTC()
	if timestamp, err := strconv.ParseFloat(fields[0], 64); err == nil {
		seconds := int64(timestamp)
		nanoseconds := int64((timestamp - float64(seconds)) * float64(time.Second))
		observedAt = time.Unix(seconds, nanoseconds).UTC()
	}
	call := strings.Join(fields[1:], " ")
	open := strings.IndexByte(call, '(')
	if open < 1 {
		return nil
	}
	syscallName := call[:open]
	outcome := "success"
	if strings.Contains(call, "= -1 ") {
		outcome = "failure"
	} else if strings.Contains(call, "<unfinished ...>") || strings.Contains(call, "= ?") {
		outcome = "unknown"
	}
	event := &telemetry.Event{
		ObservedAt: observedAt,
		Source:     "sensor",
		Outcome:    outcome,
		ProcessID:  processID,
		Summary:    truncateObservedValue(call, 4000),
		Attributes: map[string]any{"run_id": runID, "syscall": syscallName},
	}

	switch syscallName {
	case "execve", "execveat":
		event.Category = "command"
		event.Action = "execute"
		event.CommandLine = truncateObservedValue(call, 16000)
		if values := quotedTraceValues(call); len(values) > 0 {
			event.ProcessName = values[0]
		}
	case "clone", "clone3", "fork", "vfork":
		event.Category = "process"
		event.Action = "spawn"
		event.ProcessName = syscallName
	case "open", "openat", "openat2", "access", "faccessat", "stat", "lstat", "newfstatat", "readlink", "readlinkat", "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "chmod", "fchmodat", "chown", "fchownat":
		values := quotedTraceValues(call)
		if len(values) == 0 {
			return nil
		}
		event.Category = "file"
		event.Action = syscallName
		event.FilePath = values[0]
		if len(values) > 1 {
			event.Attributes["destination"] = values[1]
		}
	case "connect", "accept", "accept4", "bind", "listen", "sendto", "recvfrom":
		event.Category = "network"
		event.Action = syscallName
		event.Protocol = "socket"
		event.Direction = observedDirection(syscallName)
		address := observedNetworkAddress(call)
		port := observedNetworkPort(call)
		if event.Direction == "inbound" {
			event.SourceIP = address
			event.SourcePort = port
		} else {
			event.DestinationIP = address
			event.DestinationPort = port
		}
	default:
		return nil
	}
	return event
}

func quotedTraceValues(value string) []string {
	matches := quotedValueRE.FindAllString(value, -1)
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		decoded, err := strconv.Unquote(match)
		if err == nil {
			result = append(result, decoded)
		}
	}
	return result
}

func observedDirection(syscallName string) string {
	switch syscallName {
	case "accept", "accept4", "recvfrom":
		return "inbound"
	case "connect", "sendto":
		return "outbound"
	default:
		return "internal"
	}
}

func observedNetworkAddress(value string) string {
	if match := ipv4AddressRE.FindStringSubmatch(value); len(match) == 2 {
		return match[1]
	}
	if match := ipv6AddressRE.FindStringSubmatch(value); len(match) == 2 {
		return match[1]
	}
	return ""
}

func observedNetworkPort(value string) int {
	if match := networkPortRE.FindStringSubmatch(value); len(match) == 2 {
		port, _ := strconv.Atoi(match[1])
		return port
	}
	return 0
}

func truncateObservedValue(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func (s *Server) handleObservedWorkloads(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"items": s.workloads.List()})
	case http.MethodPost:
		var request observedWorkloadRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		workload, err := s.workloads.Start(request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(workload)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleStopObservedWorkload(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	runID := strings.TrimSpace(r.URL.Query().Get("run_id"))
	if runID == "" {
		http.Error(w, "run_id is required", http.StatusBadRequest)
		return
	}
	workload, err := s.workloads.Stop(runID)
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("stop observed workload: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, workload)
}
