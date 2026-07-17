package observer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"sandbox-proxy/internal/telemetry"
)

const (
	processPollIntervalEnvName = "V3IL_PROCESS_POLL_INTERVAL_MS"
	defaultProcessPollInterval = 50 * time.Millisecond
	connectorIndexProcess      = 0x1
	connectorValueProcess      = 0x1
	processMulticastListen     = 0x1
	processEventFork           = 0x00000001
	processEventExec           = 0x00000002
	processEventComm           = 0x00000200
	processEventExit           = 0x80000000
	netlinkHeaderBytes         = 16
	connectorHeaderBytes       = 20
	processEventHeaderBytes    = 16
)

var (
	processUsersOnce sync.Once
	processUsers     map[int]string
)

type processObservation struct {
	PID        int
	ParentPID  int
	Name       string
	Executable string
	Command    string
	Username   string
	Identity   string
}

func (o *Observer) runKernelProcessObserver(ctx context.Context) {
	fd, err := openProcessConnector()
	if err != nil {
		o.recordFailure("process_kernel", "kernel process event observer unavailable; procfs reconciliation remains active", err)
		return
	}
	defer syscall.Close(fd)
	o.health.Set("process_kernel", "active", "capturing fork, exec, rename, and exit events")
	o.recordState("process_kernel", "observer_started", "Kernel process event observer started.", nil)
	go func() {
		<-ctx.Done()
		_ = syscall.Close(fd)
	}()

	buffer := make([]byte, 256*1024)
	for {
		n, _, receiveErr := syscall.Recvfrom(fd, buffer, 0)
		if receiveErr != nil {
			if ctx.Err() != nil || errors.Is(receiveErr, syscall.EBADF) {
				o.health.Set("process_kernel", "stopped", "observer context canceled")
				return
			}
			if errors.Is(receiveErr, syscall.EINTR) {
				continue
			}
			o.recordFailure("process_kernel", "kernel process event receive failed; procfs reconciliation remains active", receiveErr)
			continue
		}
		if parseErr := o.parseProcessConnectorMessages(buffer[:n]); parseErr != nil {
			o.recordFailure("process_kernel", "kernel process event stream reported a coverage gap; procfs reconciliation remains active", parseErr)
			continue
		}
		o.recordRecovery("process_kernel", "capturing fork, exec, rename, and exit events")
	}
}

func openProcessConnector() (int, error) {
	fd, err := syscall.Socket(
		syscall.AF_NETLINK,
		syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC,
		syscall.NETLINK_CONNECTOR,
	)
	if err != nil {
		return -1, err
	}
	address := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(os.Getpid()),
		Groups: connectorIndexProcess,
	}
	if err := syscall.Bind(fd, address); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	message := make([]byte, netlinkHeaderBytes+connectorHeaderBytes+4)
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], syscall.NLMSG_DONE)
	binary.NativeEndian.PutUint32(message[12:16], uint32(os.Getpid()))
	connectorOffset := netlinkHeaderBytes
	binary.NativeEndian.PutUint32(message[connectorOffset:connectorOffset+4], connectorIndexProcess)
	binary.NativeEndian.PutUint32(message[connectorOffset+4:connectorOffset+8], connectorValueProcess)
	binary.NativeEndian.PutUint16(message[connectorOffset+16:connectorOffset+18], 4)
	binary.NativeEndian.PutUint32(message[connectorOffset+connectorHeaderBytes:], processMulticastListen)
	if err := syscall.Sendto(fd, message, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (o *Observer) parseProcessConnectorMessages(buffer []byte) error {
	for offset := 0; offset+netlinkHeaderBytes <= len(buffer); {
		messageLength := int(binary.NativeEndian.Uint32(buffer[offset : offset+4]))
		if messageLength < netlinkHeaderBytes || offset+messageLength > len(buffer) {
			return errors.New("truncated netlink message")
		}
		message := buffer[offset : offset+messageLength]
		messageType := binary.NativeEndian.Uint16(message[4:6])
		switch messageType {
		case syscall.NLMSG_NOOP:
		case syscall.NLMSG_ERROR:
			if len(message) < netlinkHeaderBytes+4 {
				return errors.New("truncated netlink error")
			}
			code := int32(binary.NativeEndian.Uint32(message[netlinkHeaderBytes : netlinkHeaderBytes+4]))
			if code != 0 {
				return fmt.Errorf("netlink error %d", code)
			}
		case syscall.NLMSG_OVERRUN:
			return errors.New("netlink receive overrun")
		case syscall.NLMSG_DONE:
			if err := o.parseProcessConnectorEvent(message); err != nil {
				return err
			}
		}
		offset += (messageLength + 3) &^ 3
	}
	return nil
}

func (o *Observer) parseProcessConnectorEvent(message []byte) error {
	dataOffset := netlinkHeaderBytes + connectorHeaderBytes
	if len(message) < dataOffset+processEventHeaderBytes {
		return errors.New("truncated process connector event")
	}
	connectorOffset := netlinkHeaderBytes
	if binary.NativeEndian.Uint32(message[connectorOffset:connectorOffset+4]) != connectorIndexProcess ||
		binary.NativeEndian.Uint32(message[connectorOffset+4:connectorOffset+8]) != connectorValueProcess {
		return nil
	}
	payloadLength := int(binary.NativeEndian.Uint16(message[connectorOffset+16 : connectorOffset+18]))
	if payloadLength < processEventHeaderBytes || dataOffset+payloadLength > len(message) {
		return errors.New("truncated process connector payload")
	}
	event := message[dataOffset : dataOffset+payloadLength]
	eventType := binary.NativeEndian.Uint32(event[0:4])
	data := event[processEventHeaderBytes:]
	switch eventType {
	case processEventFork:
		if len(data) < 16 {
			return errors.New("truncated process fork event")
		}
		parentPID := int(binary.NativeEndian.Uint32(data[0:4]))
		childPID := int(binary.NativeEndian.Uint32(data[8:12]))
		o.recordKernelProcessObservation("forked", childPID, parentPID, nil)
	case processEventExec:
		if len(data) < 8 {
			return errors.New("truncated process exec event")
		}
		processID := int(binary.NativeEndian.Uint32(data[0:4]))
		o.recordKernelProcessObservation("executed", processID, 0, nil)
	case processEventComm:
		if len(data) < 24 {
			return errors.New("truncated process comm event")
		}
		processID := int(binary.NativeEndian.Uint32(data[0:4]))
		o.recordKernelProcessObservation("renamed", processID, 0, map[string]any{
			"comm": strings.TrimRight(string(data[8:24]), "\x00"),
		})
	case processEventExit:
		if len(data) < 16 {
			return errors.New("truncated process exit event")
		}
		processID := int(binary.NativeEndian.Uint32(data[0:4]))
		if processID == os.Getpid() {
			return nil
		}
		o.recorder.Record(telemetry.Event{
			Category:  "process",
			Action:    "exited",
			Source:    "sensor",
			Outcome:   "success",
			ProcessID: processID,
			Attributes: map[string]any{
				"observer":    "proc_connector",
				"exit_code":   int(binary.NativeEndian.Uint32(data[8:12])),
				"exit_signal": int(binary.NativeEndian.Uint32(data[12:16])),
			},
		})
	}
	return nil
}

func (o *Observer) recordKernelProcessObservation(action string, processID int, parentPID int, attributes map[string]any) {
	if processID <= 0 || processID == os.Getpid() {
		return
	}
	if attributes == nil {
		attributes = make(map[string]any)
	}
	attributes["observer"] = "proc_connector"
	process, err := readProcessObservation(processID)
	if err != nil {
		o.recorder.Record(telemetry.Event{
			Category:        "process",
			Action:          action,
			Source:          "sensor",
			Outcome:         "success",
			ProcessID:       processID,
			ParentProcessID: parentPID,
			Attributes:      attributes,
		})
		return
	}
	if parentPID > 0 {
		process.ParentPID = parentPID
	}
	attributes["executable"] = process.Executable
	attributes["identity"] = process.Identity
	o.recorder.Record(telemetry.Event{
		Category:        "process",
		Action:          action,
		Source:          "sensor",
		Outcome:         "success",
		ProcessID:       process.PID,
		ParentProcessID: process.ParentPID,
		ProcessName:     process.Name,
		CommandLine:     process.Command,
		Username:        process.Username,
		Attributes:      attributes,
	})
}

func (o *Observer) runProcessReconciler(ctx context.Context) {
	interval := durationFromMilliseconds(processPollIntervalEnvName, defaultProcessPollInterval, 10*time.Millisecond, time.Second)
	known, err := readProcessObservations()
	if err != nil {
		o.recordFailure("process", "procfs process reconciler could not start", err)
		return
	}
	o.health.Set("process", "active", fmt.Sprintf("reconciling every %s", interval))
	o.recordState("process", "observer_started", "Procfs process reconciler started.", map[string]any{
		"poll_interval_ms": interval.Milliseconds(),
	})
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			o.health.Set("process", "stopped", "observer context canceled")
			return
		case <-ticker.C:
			current, readErr := readProcessObservations()
			if readErr != nil {
				o.recordFailure("process", "procfs process snapshot failed", readErr)
				continue
			}
			o.recordRecovery("process", fmt.Sprintf("reconciling every %s", interval))
			if !o.health.IsActive("process_kernel") {
				for identity, process := range current {
					if _, exists := known[identity]; exists || process.PID == os.Getpid() {
						continue
					}
					o.recordProcessObservation("started", process)
				}
				for identity, process := range known {
					if _, exists := current[identity]; exists || process.PID == os.Getpid() {
						continue
					}
					o.recordProcessObservation("exited", process)
				}
			}
			known = current
		}
	}
}

func readProcessObservations() (map[string]processObservation, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	result := make(map[string]processObservation)
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		process, readErr := readProcessObservation(pid)
		if readErr != nil {
			continue
		}
		result[process.Identity] = process
	}
	return result, nil
}

func readProcessObservation(pid int) (processObservation, error) {
	procPath := filepath.Join("/proc", strconv.Itoa(pid))
	statPayload, err := os.ReadFile(filepath.Join(procPath, "stat"))
	if err != nil {
		return processObservation{}, err
	}
	stat := string(statPayload)
	open := strings.IndexByte(stat, '(')
	close := strings.LastIndexByte(stat, ')')
	if open < 0 || close <= open {
		return processObservation{}, errors.New("invalid proc stat")
	}
	fields := strings.Fields(stat[close+1:])
	if len(fields) < 20 {
		return processObservation{}, errors.New("incomplete proc stat")
	}
	parentPID, _ := strconv.Atoi(fields[1])
	startTicks := fields[19]
	name := stat[open+1 : close]
	commandPayload, _ := os.ReadFile(filepath.Join(procPath, "cmdline"))
	command := strings.TrimSpace(strings.ReplaceAll(string(commandPayload), "\x00", " "))
	executable, _ := os.Readlink(filepath.Join(procPath, "exe"))
	statusPayload, _ := os.ReadFile(filepath.Join(procPath, "status"))
	return processObservation{
		PID:        pid,
		ParentPID:  parentPID,
		Name:       truncateValue(name, 255),
		Executable: truncateValue(executable, 4096),
		Command:    truncateValue(command, 16000),
		Username:   processUsername(statusPayload),
		Identity:   strconv.Itoa(pid) + ":" + startTicks,
	}, nil
}

func processUsername(status []byte) string {
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) == 0 {
			return ""
		}
		uid, err := strconv.Atoi(fields[0])
		if err != nil {
			return fields[0]
		}
		processUsersOnce.Do(loadProcessUsers)
		if username := processUsers[uid]; username != "" {
			return username
		}
		return strconv.Itoa(uid)
	}
	return ""
}

func loadProcessUsers() {
	processUsers = make(map[int]string)
	payload, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return
	}
	for _, record := range strings.Split(string(payload), "\n") {
		parts := strings.Split(record, ":")
		if len(parts) < 3 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err == nil {
			processUsers[uid] = parts[0]
		}
	}
}

func (o *Observer) recordProcessObservation(action string, process processObservation) {
	o.recorder.Record(telemetry.Event{
		Category:        "process",
		Action:          action,
		Source:          "sensor",
		Outcome:         "success",
		ProcessID:       process.PID,
		ParentProcessID: process.ParentPID,
		ProcessName:     process.Name,
		CommandLine:     process.Command,
		Username:        process.Username,
		Attributes: map[string]any{
			"observer":   "procfs",
			"executable": process.Executable,
			"identity":   process.Identity,
		},
	})
}
