package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sandbox-proxy/internal/control"
	"sandbox-proxy/internal/egress"
	"sandbox-proxy/internal/observer"
	"sandbox-proxy/internal/telemetry"
)

const (
	defaultControlProxyAddr = ":8000"
	tokenEnvName            = "SANDBOX_CONTROL_PROXY_TOKEN"
	sensorIDEnvName         = "V3IL_SENSOR_ID"
	zeekAdapterTokenEnvName = "V3IL_ADAPTER_TOKEN"
)

func main() {
	token := requiredEnvironment(tokenEnvName)
	sensorID := requiredEnvironment(sensorIDEnvName)
	zeekAdapterToken := os.Getenv(zeekAdapterTokenEnvName)
	detectionOnly := zeekAdapterToken != ""
	store, err := telemetry.NewStore(sensorID, telemetry.SensorHMACKey(token))
	if err != nil {
		log.Fatalf("initialize behavior telemetry: %v", err)
	}
	defer store.Close()
	store.Record(telemetry.Event{
		Category: "system",
		Action:   "sensor_started",
		Source:   "sensor",
		Outcome:  "success",
		Summary:  "V3il behavior sensor started.",
	})

	stopObservers := func() {}
	observerSnapshot := func() any { return nil }
	if !detectionOnly {
		observerContext, cancelObservers := context.WithCancel(context.Background())
		stopObservers = cancelObservers
		defer stopObservers()
		behaviorObserver := observer.New(store)
		behaviorObserver.Start(observerContext)
		observerSnapshot = func() any { return behaviorObserver.Snapshot() }
	}
	egressManager := egress.NewManager(store)
	controlServer := control.NewServer(store, egressManager, zeekAdapterToken, observerSnapshot)

	var serviceTelemetryServer *http.Server
	var egressServer *http.Server
	if !detectionOnly {
		startedServer, listener, serviceTelemetrySocket, startErr := controlServer.StartServiceTelemetryServer()
		if startErr != nil {
			log.Fatalf("initialize service telemetry socket: %v", startErr)
		}
		serviceTelemetryServer = startedServer
		defer serviceTelemetryServer.Close()
		defer listener.Close()
		defer os.Remove(serviceTelemetrySocket)
		go func() {
			log.Printf("sandbox service telemetry listening on unix://%s", serviceTelemetrySocket)
			if err := serviceTelemetryServer.Serve(listener); err != nil && err != http.ErrServerClosed {
				log.Fatalf("sandbox service telemetry failed: %v", err)
			}
		}()

		egressServer = egressManager.ProxyServer()
		go func() {
			log.Printf("sandbox egress listening on %s", egress.DefaultProxyAddr)
			if err := egressServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("sandbox egress failed: %v", err)
			}
		}()
	}
	server := &http.Server{
		Addr:              defaultControlProxyAddr,
		Handler:           controlServer.Mux(token),
		ReadHeaderTimeout: 5 * time.Second,
	}
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdown
		stopObservers()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if serviceTelemetryServer != nil {
			_ = serviceTelemetryServer.Shutdown(shutdownContext)
		}
		if egressServer != nil {
			_ = egressServer.Shutdown(shutdownContext)
		}
		_ = server.Shutdown(shutdownContext)
	}()

	log.Printf("sandbox control proxy listening on %s", defaultControlProxyAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("sandbox control proxy failed: %v", err)
	}
}

func requiredEnvironment(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}
