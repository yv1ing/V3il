package control

import (
	"archive/tar"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"sandbox-proxy/internal/telemetry"
)

type fileInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Size        int64  `json:"size"`
	ModifiedAt  int64  `json:"modified_at"`
	Owner       string `json:"owner"`
	Group       string `json:"group"`
	Permissions string `json:"permissions"`
	Path        string `json:"path"`
}

type uploadItem struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	path := normalizePath(r.URL.Query().Get("path"))
	entries, err := os.ReadDir(path)
	if err != nil {
		writeFileError(w, err)
		return
	}
	files := make([]fileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, toFileInfo(filepath.Join(path, entry.Name()), info))
	}
	s.recordFileBehavior("list", path, "success", map[string]any{"entry_count": len(files)})
	writeJSON(w, map[string]any{"path": path, "files": files})
}

func (s *Server) handleFileInfo(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	path := normalizePath(r.URL.Query().Get("path"))
	info, err := os.Lstat(path)
	if err != nil {
		writeFileError(w, err)
		return
	}
	s.recordFileBehavior("metadata", path, "success", nil)
	writeJSON(w, map[string]any{"file": toFileInfo(path, info)})
}

func (s *Server) handleReadFile(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	path := normalizePath(r.URL.Query().Get("path"))
	maxBytes := parseInt(r.URL.Query().Get("max_bytes"), 1048576)
	base64Mode := r.URL.Query().Get("base64") == "true"

	file, err := os.Open(path)
	if err != nil {
		writeFileError(w, err)
		return
	}
	defer file.Close()

	payload, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)))
	if err != nil {
		writeFileError(w, err)
		return
	}
	s.recordFileBehavior("read", path, "success", map[string]any{"bytes": len(payload)})
	content := string(payload)
	if base64Mode {
		content = base64.StdEncoding.EncodeToString(payload)
	}
	writeJSON(w, map[string]any{"path": path, "content": content, "size": len(payload)})
}

func (s *Server) handleWriteFile(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	path := normalizePath(body.Path)
	if err := os.WriteFile(path, []byte(body.Content), 0o644); err != nil {
		writeFileError(w, err)
		return
	}
	s.recordFileBehavior("write", path, "success", map[string]any{"bytes": len(body.Content)})
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleUploadFiles(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	path := normalizePath(r.FormValue("path"))
	overwrite := r.FormValue("overwrite") != "false"
	uploaded := []uploadItem{}
	for _, headers := range r.MultipartForm.File {
		for _, header := range headers {
			item, err := saveUploadedFile(header, path, overwrite)
			if err != nil {
				writeFileError(w, err)
				return
			}
			uploaded = append(uploaded, item)
			s.recordFileBehavior("upload", item.Path, "success", map[string]any{"bytes": item.Size})
		}
	}
	writeJSON(w, map[string]any{"path": path, "files": uploaded})
}

func (s *Server) handleDownloadFiles(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	paths := r.URL.Query()["path"]
	if len(paths) == 0 {
		http.Error(w, "download path is required", http.StatusBadRequest)
		return
	}
	if len(paths) == 1 {
		path := normalizePath(paths[0])
		info, err := os.Lstat(path)
		if err != nil {
			writeFileError(w, err)
			return
		}
		if !info.IsDir() {
			s.recordFileBehavior("download", path, "success", map[string]any{"bytes": info.Size()})
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
			http.ServeFile(w, r, path)
			return
		}
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", `attachment; filename="container-files.tar"`)
	tw := tar.NewWriter(w)
	for _, raw := range paths {
		path := normalizePath(raw)
		rootName := filepath.Base(path)
		if rootName == "/" || rootName == "." {
			rootName = "root"
		}
		walkErr := filepath.Walk(path, func(current string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(path, current)
			name := rootName
			if rel != "." {
				name = filepath.Join(rootName, rel)
			}
			linkTarget := ""
			if info.Mode()&os.ModeSymlink != 0 {
				linkTarget, err = os.Readlink(current)
				if err != nil {
					return err
				}
			}
			hdr, err := tar.FileInfoHeader(info, linkTarget)
			if err != nil {
				return err
			}
			hdr.Name = filepath.ToSlash(name)
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("unsupported archive file type: %s", current)
			}
			f, err := os.Open(current)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, f)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		})
		if walkErr != nil {
			s.recordFileBehavior("download", path, "failure", map[string]any{"archive": true})
			return
		}
		s.recordFileBehavior("download", path, "success", map[string]any{"archive": true})
	}
	if err := tw.Close(); err != nil {
		s.recordFileBehavior("download", normalizePath(paths[0]), "failure", map[string]any{"archive": true})
	}
}

func (s *Server) handleCopyFiles(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct {
		Sources     []string `json:"sources"`
		Destination string   `json:"destination"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	for _, src := range body.Sources {
		if err := copyPath(normalizePath(src), normalizePath(body.Destination)); err != nil {
			writeFileError(w, err)
			return
		}
		s.recordFileBehavior("copy", normalizePath(src), "success", map[string]any{"destination": normalizePath(body.Destination)})
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleMoveFiles(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct {
		Sources     []string `json:"sources"`
		Destination string   `json:"destination"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	dest := normalizePath(body.Destination)
	for _, src := range body.Sources {
		target := filepath.Join(dest, filepath.Base(src))
		if err := os.Rename(normalizePath(src), target); err != nil {
			writeFileError(w, err)
			return
		}
		s.recordFileBehavior("move", normalizePath(src), "success", map[string]any{"destination": target})
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleDeleteFiles(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct {
		Paths []string `json:"paths"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	for _, p := range body.Paths {
		if err := os.RemoveAll(normalizePath(p)); err != nil {
			writeFileError(w, err)
			return
		}
		s.recordFileBehavior("delete", normalizePath(p), "success", nil)
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleMkdir(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := os.MkdirAll(normalizePath(body.Path), 0o755); err != nil {
		writeFileError(w, err)
		return
	}
	s.recordFileBehavior("mkdir", normalizePath(body.Path), "success", nil)
	writeJSON(w, map[string]any{"ok": true})
}

// --- File operation helpers ---

func toFileInfo(path string, info os.FileInfo) fileInfo {
	ft := "file"
	if info.IsDir() {
		ft = "directory"
	} else if info.Mode()&os.ModeSymlink != 0 {
		ft = "symlink"
	}
	return fileInfo{
		Name:        filepath.Base(path),
		Type:        ft,
		Size:        info.Size(),
		ModifiedAt:  info.ModTime().Unix(),
		Owner:       "",
		Group:       "",
		Permissions: fmt.Sprintf("%#o", info.Mode().Perm()),
		Path:        path,
	}
}

func saveUploadedFile(header *multipart.FileHeader, dest string, overwrite bool) (uploadItem, error) {
	name := filepath.Base(header.Filename)
	target := filepath.Join(dest, name)
	if !overwrite {
		if _, err := os.Stat(target); err == nil {
			return uploadItem{}, errors.New("file already exists")
		}
	}
	src, err := header.Open()
	if err != nil {
		return uploadItem{}, err
	}
	defer src.Close()
	f, err := os.Create(target)
	if err != nil {
		return uploadItem{}, err
	}
	defer f.Close()
	size, err := io.Copy(f, src)
	if err != nil {
		return uploadItem{}, err
	}
	return uploadItem{Name: name, Path: target, Size: size}, nil
}

func copyPath(src string, dest string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	target := filepath.Join(dest, filepath.Base(src))
	if info.IsDir() {
		return copyDir(src, target)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return copySymlink(src, target)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsupported file type: %s", src)
	}
	return copyFile(src, target, info.Mode())
}

func copyDir(src string, dest string) error {
	return filepath.Walk(src, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, current)
		target := filepath.Join(dest, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return copySymlink(current, target)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported file type: %s", current)
		}
		return copyFile(current, target, info.Mode())
	})
}

func copySymlink(src string, dest string) error {
	target, err := os.Readlink(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.Symlink(target, dest)
}

func copyFile(src string, dest string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// --- HTTP helpers ---

func normalizePath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "/"
	}
	cleaned := filepath.Clean("/" + strings.TrimPrefix(path, "/"))
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func writeFileError(w http.ResponseWriter, err error) {
	if os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if strings.Contains(err.Error(), "already exists") {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func (s *Server) recordFileBehavior(action string, path string, outcome string, attributes map[string]any) {
	s.recorder.Record(telemetry.Event{
		Category:   "file",
		Action:     action,
		Source:     "control_proxy",
		Outcome:    outcome,
		FilePath:   path,
		Attributes: attributes,
	})
}
