package control

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"sandbox-proxy/internal/telemetry"
)

const (
	ioctlTIOCGPTN   = 0x80045430
	ioctlTIOCSPTLCK = 0x40045431
	ioctlTIOCSWINSZ = 0x5414
)

func (s *Server) handleShell(w http.ResponseWriter, r *http.Request) {
	if !validWebSocketUpgrade(r) {
		http.Error(w, "valid WebSocket upgrade required", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_, _ = rw.WriteString("Upgrade: websocket\r\n")
	_, _ = rw.WriteString("Connection: Upgrade\r\n")
	_, _ = rw.WriteString("Sec-WebSocket-Accept: " + websocketAccept(key) + "\r\n\r\n")
	_ = rw.Flush()

	ptmx, pts, err := openPTY()
	if err != nil {
		_ = writeWebSocketFrame(conn, websocketOpcodeClose, nil)
		return
	}
	defer ptmx.Close()

	cmd := shellCommand()
	cmd.Dir = DeceptionRuntimeHome
	cmd.Env = append(s.RuntimeEnvironment(), s.egress.RuntimeEnvironmentOverlay()...)
	cmd.Env = append(cmd.Env, "TERM=xterm-256color")
	cmd.Stdin = pts
	cmd.Stdout = pts
	cmd.Stderr = pts
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Credential: &syscall.Credential{
			Uid:         DeceptionRuntimeUID,
			Gid:         DeceptionRuntimeGID,
			NoSetGroups: true,
		},
	}
	if err := cmd.Start(); err != nil {
		pts.Close()
		_ = writeWebSocketFrame(conn, websocketOpcodeClose, nil)
		return
	}
	s.recorder.Record(telemetry.Event{
		Category:    "service",
		Action:      "shell_started",
		Source:      "control_proxy",
		Outcome:     "success",
		ProcessID:   cmd.Process.Pid,
		ProcessName: cmd.Path,
		ServiceName: "interactive_shell",
	})
	pts.Close()
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		s.recorder.Record(telemetry.Event{
			Category:    "service",
			Action:      "shell_stopped",
			Source:      "control_proxy",
			Outcome:     "success",
			ProcessID:   cmd.Process.Pid,
			ProcessName: cmd.Path,
			ServiceName: "interactive_shell",
		})
	}()

	done := make(chan struct{})
	var writeMu sync.Mutex
	writeFrame := func(opcode byte, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeWebSocketFrame(conn, opcode, payload)
	}

	// PTY reader: forwards shell output to WebSocket client.
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				if writeFrame(2, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WebSocket reader: forwards client input to PTY, handles resize.
	go func() {
		capture := terminalCommandCapture{recorder: s.recorder, processID: cmd.Process.Pid, processName: cmd.Path}
		defer capture.flush()
		reader := newWebSocketReader(conn)
		for {
			data, opcode, err := reader.ReadMessage()
			if err != nil {
				_ = cmd.Process.Kill()
				return
			}
			if opcode == websocketOpcodeClose {
				_ = cmd.Process.Kill()
				return
			}
			if opcode == websocketOpcodePing {
				_ = writeFrame(websocketOpcodePong, data)
				continue
			}
			if opcode == websocketOpcodePong {
				continue
			}
			if isResizeMessage(data) {
				applyResize(ptmx, data)
				continue
			}
			capture.Write(data)
			_, _ = ptmx.Write(data)
		}
	}()

	<-done
}

type terminalCommandCapture struct {
	recorder    telemetry.Recorder
	buffer      []byte
	processID   int
	processName string
}

func (c *terminalCommandCapture) Write(data []byte) {
	for _, value := range data {
		switch value {
		case '\r', '\n':
			c.flush()
		case '\b', 0x7f:
			if len(c.buffer) > 0 {
				c.buffer = c.buffer[:len(c.buffer)-1]
			}
		default:
			if value >= 0x20 && value != 0x1b && len(c.buffer) < 16000 {
				c.buffer = append(c.buffer, value)
			}
		}
	}
}

func (c *terminalCommandCapture) flush() {
	command := strings.TrimSpace(string(c.buffer))
	c.buffer = c.buffer[:0]
	if command == "" {
		return
	}
	c.recorder.Record(telemetry.Event{
		Category:    "command",
		Action:      "execute",
		Source:      "control_proxy",
		Outcome:     "unknown",
		ProcessID:   c.processID,
		ProcessName: c.processName,
		CommandLine: command,
	})
}

func shellCommand() *exec.Cmd {
	shell := "/bin/sh"
	if _, err := exec.LookPath("bash"); err == nil {
		shell = "bash"
	}
	return exec.Command(shell, "-l")
}

func openPTY() (master *os.File, slave *os.File, err error) {
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}

	var ptsNum uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), ioctlTIOCGPTN, uintptr(unsafe.Pointer(&ptsNum))); errno != 0 {
		ptmx.Close()
		return nil, nil, fmt.Errorf("TIOCGPTN: %v", errno)
	}

	var unlock int
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), ioctlTIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		ptmx.Close()
		return nil, nil, fmt.Errorf("TIOCSPTLCK: %v", errno)
	}

	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", ptsNum), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		ptmx.Close()
		return nil, nil, err
	}
	return ptmx, pts, nil
}

func isResizeMessage(data []byte) bool {
	return bytes.HasPrefix(data, []byte("\x00resize:"))
}

func applyResize(ptmx *os.File, data []byte) {
	msg := string(data[len("\x00resize:"):])
	parts := strings.SplitN(msg, ":", 2)
	if len(parts) != 2 {
		return
	}
	rows, err1 := strconv.Atoi(parts[0])
	cols, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || rows < 1 || cols < 1 {
		return
	}
	setTerminalSize(ptmx, rows, cols)
}

func setTerminalSize(f *os.File, rows, cols int) {
	ws := struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}{Row: uint16(rows), Col: uint16(cols)}
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), ioctlTIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
}
