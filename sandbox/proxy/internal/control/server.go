package control

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strconv"
	"strings"

	"sandbox-proxy/internal/egress"
	"sandbox-proxy/internal/httpx"
	"sandbox-proxy/internal/telemetry"
)

const (
	DeceptionRuntimeUID  = 10001
	DeceptionRuntimeGID  = 10001
	DeceptionRuntimeHome = "/home/v3il-deception"
	DeceptionRuntimeUser = "v3il-deception"
)

type Server struct {
	store            *telemetry.Store
	recorder         telemetry.Recorder
	egress           *egress.Manager
	zeekAdapterToken string
	observerSnapshot func() any
	workloads        *observedWorkloadManager
}

func NewServer(store *telemetry.Store, egressManager *egress.Manager, zeekAdapterToken string, observerSnapshot func() any) *Server {
	server := &Server{
		store:            store,
		recorder:         store,
		egress:           egressManager,
		zeekAdapterToken: zeekAdapterToken,
		observerSnapshot: observerSnapshot,
	}
	server.workloads = newObservedWorkloadManager(server)
	return server
}

func (s *Server) Mux(token string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.withAuth(token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		httpx.WriteJSON(w, map[string]any{
			"service":   "v3il-deception-runtime",
			"sensor_id": s.store.Snapshot().SensorID,
		})
	}))
	mux.HandleFunc("/healthz", s.withAuth(token, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	if s.zeekAdapterToken != "" {
		mux.HandleFunc("/detection/", s.withAuth(token, s.handleDetectionProxy))
		return mux
	}
	mux.HandleFunc("/shell", s.withAuth(token, s.handleShell))
	mux.HandleFunc("/files", s.withAuth(token, s.handleListFiles))
	mux.HandleFunc("/files/info", s.withAuth(token, s.handleFileInfo))
	mux.HandleFunc("/files/read", s.withAuth(token, s.handleReadFile))
	mux.HandleFunc("/files/write", s.withAuth(token, s.handleWriteFile))
	mux.HandleFunc("/files/upload", s.withAuth(token, s.handleUploadFiles))
	mux.HandleFunc("/files/download", s.withAuth(token, s.handleDownloadFiles))
	mux.HandleFunc("/files/copy", s.withAuth(token, s.handleCopyFiles))
	mux.HandleFunc("/files/move", s.withAuth(token, s.handleMoveFiles))
	mux.HandleFunc("/files/delete", s.withAuth(token, s.handleDeleteFiles))
	mux.HandleFunc("/files/mkdir", s.withAuth(token, s.handleMkdir))
	mux.HandleFunc("/egress", s.withAuth(token, s.egress.Handler))
	mux.HandleFunc("/telemetry/events", s.withAuth(token, s.handleTelemetryEvents))
	mux.HandleFunc("/telemetry/health", s.withAuth(token, s.handleTelemetryHealth))
	mux.HandleFunc("/observed-workloads", s.withAuth(token, s.handleObservedWorkloads))
	mux.HandleFunc("/observed-workloads/stop", s.withAuth(token, s.handleStopObservedWorkload))
	return mux
}

func (s *Server) RuntimeEnvironment() []string {
	environment := make([]string, 0, len(os.Environ())+4)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if isControlOnlyEnvironmentKey(name) || egress.IsControlEnvironmentKey(name) {
			continue
		}
		environment = append(environment, entry)
	}
	return append(
		environment,
		"HOME="+DeceptionRuntimeHome,
		"USER="+DeceptionRuntimeUser,
		"LOGNAME="+DeceptionRuntimeUser,
	)
}

func isControlOnlyEnvironmentKey(name string) bool {
	return name == "SANDBOX_CONTROL_PROXY_TOKEN" ||
		name == "V3IL_SENSOR_ID" ||
		name == "V3IL_ADAPTER_TOKEN" ||
		name == "V3IL_SENSOR_HMAC_TOKEN" ||
		strings.HasPrefix(name, "V3IL_ZEEK_") ||
		name == "HOME" ||
		name == "USER" ||
		name == "LOGNAME"
}

func (s *Server) handleTelemetryEvents(w http.ResponseWriter, r *http.Request) {
	if !httpx.RequireMethod(w, r, http.MethodGet) {
		return
	}
	afterValue := r.URL.Query().Get("after")
	if afterValue == "" {
		afterValue = "0"
	}
	after, err := strconv.ParseInt(afterValue, 10, 64)
	if err != nil || after < 0 {
		http.Error(w, "after must be a non-negative integer", http.StatusBadRequest)
		return
	}
	limit := httpx.ParsePositiveInt(r.URL.Query().Get("limit"), telemetry.MaxPageSize)
	if limit > telemetry.MaxPageSize {
		http.Error(w, "limit must be between 1 and 1000", http.StatusBadRequest)
		return
	}
	events, err := s.store.ReadAfter(after, limit)
	if err != nil {
		http.Error(w, "read behavior telemetry failed", http.StatusInternalServerError)
		return
	}
	httpx.WriteJSON(w, telemetry.Batch{SensorID: s.store.Snapshot().SensorID, Events: events})
}

func (s *Server) handleTelemetryHealth(w http.ResponseWriter, r *http.Request) {
	if !httpx.RequireMethod(w, r, http.MethodGet) {
		return
	}
	payload := struct {
		telemetry.Snapshot
		Observers any `json:"observers"`
	}{
		Snapshot:  s.store.Snapshot(),
		Observers: s.observerSnapshot(),
	}
	httpx.WriteJSON(w, payload)
}

func (s *Server) withAuth(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func authorized(r *http.Request, token string) bool {
	provided := r.Header.Get("X-Sandbox-Token")
	if provided == "" {
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(authorization, "Bearer ") {
			provided = strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
		}
	}
	if provided == "" {
		provided = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}
