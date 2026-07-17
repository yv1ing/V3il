package observer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"sandbox-proxy/internal/telemetry"
)

const observerPathsEnvName = "V3IL_OBSERVER_PATHS"

type filesystemObserver struct {
	fd      int
	mu      sync.RWMutex
	watches map[int]string
}

func (o *Observer) runFilesystemObserver(ctx context.Context) {
	watcher, err := newFilesystemObserver()
	if err != nil {
		o.recordFailure("filesystem", "inotify filesystem observer unavailable", err)
		return
	}
	defer watcher.Close()
	roots := observerPaths()
	watchCount, registrationErr := watcher.AddRoots(roots)
	if watchCount == 0 {
		o.recordFailure("filesystem", "no observable filesystem roots could be registered", registrationErr)
		return
	}
	message := fmt.Sprintf("watching %d directories", watchCount)
	if registrationErr != nil {
		o.recordFailure("filesystem", "filesystem watch registration was incomplete", registrationErr)
	} else {
		o.health.Set("filesystem", "active", message)
	}
	o.recordState("filesystem", "observer_started", "Inotify filesystem observer started.", map[string]any{
		"roots":             roots,
		"watch_count":       watchCount,
		"coverage_complete": registrationErr == nil,
	})
	go func() {
		<-ctx.Done()
		watcher.Close()
	}()
	go o.reconcileFilesystemWatches(ctx, watcher, roots)
	watcher.Run(ctx, o)
}

func (o *Observer) reconcileFilesystemWatches(ctx context.Context, watcher *filesystemObserver, roots []string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			watchCount, err := watcher.AddRoots(roots)
			if err != nil {
				o.recordFailure("filesystem", "filesystem watch reconciliation was incomplete", err)
				continue
			}
			o.recordRecovery("filesystem", fmt.Sprintf("watching %d directories", watchCount))
		}
	}
}

func newFilesystemObserver() (*filesystemObserver, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &filesystemObserver{fd: fd, watches: make(map[int]string)}, nil
}

func (o *filesystemObserver) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fd < 0 {
		return nil
	}
	err := syscall.Close(o.fd)
	o.fd = -1
	return err
}

func (o *filesystemObserver) AddRoots(roots []string) (int, error) {
	total := 0
	var firstError error
	for _, root := range roots {
		count, err := o.AddTree(root)
		total += count
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstError == nil {
			firstError = fmt.Errorf("%s: %w", root, err)
		}
	}
	return total, firstError
}

func (o *filesystemObserver) AddTree(root string) (int, error) {
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("observer root is not a directory: %s", root)
	}
	count := 0
	var firstError error
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if firstError == nil {
				firstError = walkErr
			}
			return nil
		}
		if !entry.IsDir() || excludedObserverPath(path) {
			if entry.IsDir() && excludedObserverPath(path) && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if addErr := o.Add(path); addErr != nil {
			if firstError == nil {
				firstError = addErr
			}
			return nil
		}
		count++
		return nil
	})
	if err != nil {
		return count, err
	}
	return count, firstError
}

func (o *filesystemObserver) Add(path string) error {
	const mask = syscall.IN_ACCESS | syscall.IN_ATTRIB | syscall.IN_CLOSE_WRITE |
		syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_DELETE_SELF |
		syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO | syscall.IN_OPEN |
		syscall.IN_MOVE_SELF
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fd < 0 {
		return os.ErrClosed
	}
	watch, err := syscall.InotifyAddWatch(o.fd, path, mask)
	if err != nil {
		return err
	}
	o.watches[watch] = path
	return nil
}

func (o *filesystemObserver) Run(ctx context.Context, owner *Observer) {
	buffer := make([]byte, 256*1024)
	for {
		o.mu.RLock()
		fd := o.fd
		o.mu.RUnlock()
		if fd < 0 {
			return
		}
		n, err := syscall.Read(fd, buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, syscall.EBADF) {
				owner.health.Set("filesystem", "stopped", "observer context canceled")
				return
			}
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			owner.recordFailure("filesystem", "inotify read failed", err)
			continue
		}
		for offset := 0; offset+syscall.SizeofInotifyEvent <= n; {
			event := (*syscall.InotifyEvent)(unsafe.Pointer(&buffer[offset]))
			recordLength := syscall.SizeofInotifyEvent + int(event.Len)
			if recordLength <= 0 || offset+recordLength > n {
				owner.recordFailure("filesystem", "inotify event record was truncated", nil)
				break
			}
			name := ""
			if event.Len > 0 {
				rawName := buffer[offset+syscall.SizeofInotifyEvent : offset+recordLength]
				name = strings.TrimRight(string(rawName), "\x00")
			}
			o.handleEvent(owner, int(event.Wd), event.Mask, event.Cookie, name)
			offset += recordLength
		}
	}
}

func (o *filesystemObserver) handleEvent(owner *Observer, watch int, mask uint32, cookie uint32, name string) {
	if mask&syscall.IN_Q_OVERFLOW != 0 {
		owner.recordFailure("filesystem", "inotify queue overflow; filesystem evidence may be incomplete", nil)
		return
	}
	o.mu.RLock()
	base := o.watches[watch]
	o.mu.RUnlock()
	if base == "" {
		return
	}
	path := base
	if name != "" {
		path = filepath.Join(base, name)
	}
	isDirectory := mask&syscall.IN_ISDIR != 0
	if isDirectory && (mask&syscall.IN_CREATE != 0 || mask&syscall.IN_MOVED_TO != 0) {
		if _, err := o.AddTree(path); err != nil {
			owner.recordFailure("filesystem", "new directory watch registration failed", err)
		}
	}
	for _, action := range filesystemActions(mask) {
		owner.recorder.Record(telemetry.Event{
			Category: "file",
			Action:   action,
			Source:   "sensor",
			Outcome:  "success",
			FilePath: path,
			Attributes: map[string]any{
				"observer":     "inotify",
				"is_directory": isDirectory,
				"cookie":       cookie,
				"mask":         fmt.Sprintf("0x%x", mask),
			},
		})
	}
	if mask&syscall.IN_IGNORED != 0 || mask&syscall.IN_DELETE_SELF != 0 {
		o.mu.Lock()
		delete(o.watches, watch)
		o.mu.Unlock()
	}
}

func filesystemActions(mask uint32) []string {
	actions := []struct {
		bit  uint32
		name string
	}{
		{syscall.IN_ACCESS, "accessed"},
		{syscall.IN_OPEN, "opened"},
		{syscall.IN_CREATE, "created"},
		{syscall.IN_CLOSE_WRITE, "content_changed"},
		{syscall.IN_ATTRIB, "metadata_changed"},
		{syscall.IN_MOVED_FROM, "moved_from"},
		{syscall.IN_MOVED_TO, "moved_to"},
		{syscall.IN_MOVE_SELF, "moved"},
		{syscall.IN_DELETE, "deleted"},
		{syscall.IN_DELETE_SELF, "deleted"},
	}
	result := make([]string, 0, len(actions))
	for _, action := range actions {
		if mask&action.bit != 0 {
			result = append(result, action.name)
		}
	}
	return result
}

func observerPaths() []string {
	value := os.Getenv(observerPathsEnvName)
	if strings.TrimSpace(value) == "" {
		value = "/home/v3il-deception,/srv,/var/www,/opt/deception,/tmp"
	}
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, raw := range strings.Split(value, ",") {
		path := filepath.Clean(strings.TrimSpace(raw))
		if path == "." || path == "" || excludedObserverPath(path) {
			continue
		}
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}
	return result
}

func excludedObserverPath(path string) bool {
	for _, prefix := range []string{"/dev", "/proc", "/run/v3il", "/sys", "/var/lib/v3il"} {
		if path == prefix || strings.HasPrefix(path, prefix+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
