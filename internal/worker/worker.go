// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// Package worker is the per-session file process. It runs with the logged-in
// user's uid, gid and groups, so the kernel decides what may be read or
// written; it hands open file descriptors back to the network process.
package worker

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/btdt1983/cerberusttpd/internal/ipc"
)

const maxEntries = 20000

type Request struct {
	Op        string `json:"op"` // open, list, mkdir, upload_create, upload_status, upload_open, upload_finish, upload_cancel, album, album_save, album_create, thumb
	Path      string `json:"path"`
	Name      string `json:"name,omitempty"`
	Length    int64  `json:"length,omitempty"`
	ID        string `json:"id,omitempty"`
	Offset    int64  `json:"offset,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
	Variant   string `json:"variant,omitempty"` // thumb: t (grid) or v (lightbox)
	Album     *Album `json:"album,omitempty"`   // album_save, album_create
}

type Entry struct {
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix nanoseconds
	Album bool   `json:"album,omitempty"`
	Cover string `json:"cover,omitempty"` // album folders: the chosen cover picture, if any
}

type Response struct {
	Err      string  `json:"err,omitempty"` // notfound, forbidden, invalid, exists, conflict, nospace, internal
	Kind     string  `json:"kind,omitempty"`
	ID       string  `json:"id,omitempty"`
	Offset   int64   `json:"offset,omitempty"`
	Length   int64   `json:"length,omitempty"`
	Writable bool    `json:"writable,omitempty"`
	Name     string  `json:"name,omitempty"`
	Total    int64   `json:"total,omitempty"` // statfs: filesystem size in bytes
	Avail    int64   `json:"avail,omitempty"` // statfs: bytes this user can still use
	Size     int64   `json:"size,omitempty"`
	MTime    int64   `json:"mtime,omitempty"`
	Entries  []Entry `json:"entries,omitempty"`
	Cut      bool    `json:"cut,omitempty"`
	Album    *Album  `json:"album,omitempty"`
	Images   []Image `json:"images,omitempty"`
	Data     []byte  `json:"data,omitempty"` // thumb: the bytes, when the cache could not be written
}

// Run serves the IPC socket on fd 3 until the network process closes it.
func Run(rootDir, cacheDir string) error {
	// A compromised worker can never gain privileges via setuid binaries.
	syscall.RawSyscall(syscall.SYS_PRCTL, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0)
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	// Picture decoding is bursty: collect more eagerly as a worker nears 1 GiB.
	debug.SetMemoryLimit(1 << 30)
	tc := &thumbCache{dir: cacheDir}
	return ipc.Serve(os.NewFile(3, "ipc"), func(raw json.RawMessage) (any, []*os.File) {
		var req Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return Response{Err: "invalid"}, nil
		}
		name, ok := clean(req.Path)
		if !ok {
			return Response{Err: "notfound"}, nil
		}
		switch req.Op {
		case "open":
			return open(root, name)
		case "list":
			return list(root, name), nil
		case "statfs":
			return fsInfo(root), nil
		case "stat":
			return stat(root, name), nil
		case "delete":
			return remove(root, name, req.Recursive), nil
		case "rename":
			return rename(root, name, req.Name), nil
		case "album":
			return albumGet(root, name), nil
		case "album_save":
			return albumSave(root, name, req.Album, false), nil
		case "album_create":
			return albumSave(root, name, req.Album, true), nil
		case "thumb":
			return thumb(root, tc, name, req.Variant)
		}
		return upload(root, name, req)
	})
}

// clean turns a URL path into a root-relative name. Names starting with
// partPrefix belong to in-progress uploads and are never reachable.
func clean(p string) (string, bool) {
	name := strings.TrimPrefix(path.Clean("/"+p), "/")
	if name == "" {
		return ".", true
	}
	for _, c := range strings.Split(name, "/") {
		if strings.HasPrefix(c, partPrefix) {
			return "", false
		}
	}
	return name, true
}

func open(root *os.Root, name string) (any, []*os.File) {
	// O_NONBLOCK so opening a FIFO cannot hang the worker.
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return Response{Err: errCode(err)}, nil
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return Response{Err: errCode(err)}, nil
	}
	switch {
	case fi.IsDir():
		f.Close()
		return Response{Kind: "dir"}, nil
	case fi.Mode().IsRegular():
		return Response{Kind: "file", Size: fi.Size(), MTime: fi.ModTime().UnixNano()}, []*os.File{f}
	}
	f.Close()
	return Response{Err: "invalid"}, nil
}

func list(root *os.Root, name string) Response {
	d, err := root.Open(name)
	if err != nil {
		return Response{Err: errCode(err)}
	}
	defer d.Close()
	ents, err := d.ReadDir(maxEntries + 1)
	if err != nil && len(ents) == 0 && !errors.Is(err, errors.ErrUnsupported) {
		if fi, serr := d.Stat(); serr == nil && !fi.IsDir() {
			return Response{Err: "invalid"}
		}
	}
	resp := Response{Kind: "dir"}
	// access(2) uses our (the user's) real ids, so this is the kernel's answer.
	resp.Writable = syscall.Access("/proc/self/fd/"+strconv.Itoa(int(d.Fd())), 3) == nil
	if len(ents) > maxEntries {
		ents, resp.Cut = ents[:maxEntries], true
	}
	albums := 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), partPrefix) {
			continue
		}
		en := Entry{Name: e.Name(), Dir: e.IsDir()}
		if fi, err := e.Info(); err == nil {
			en.Size, en.MTime = fi.Size(), fi.ModTime().UnixNano()
			en.Dir = fi.IsDir()
		}
		if en.Dir {
			// One stat per folder; only the first few covers are read (small JSON files).
			if _, err := root.Lstat(path.Join(name, e.Name(), albumFile)); err == nil {
				en.Album = true
				if albums < maxAlbumCovers {
					// A cover that was deleted or renamed since is not passed on.
					if a, err := readAlbum(root, path.Join(name, e.Name())); err == nil && validName(a.Cover) {
						if fi, err := root.Lstat(path.Join(name, e.Name(), a.Cover)); err == nil && fi.Mode().IsRegular() && IsImage(a.Cover) {
							en.Cover = a.Cover
						}
					}
				}
				albums++
			}
		}
		resp.Entries = append(resp.Entries, en)
	}
	sort.Slice(resp.Entries, func(i, j int) bool {
		a, b := resp.Entries[i], resp.Entries[j]
		if a.Dir != b.Dir {
			return a.Dir
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return resp
}

func errCode(err error) string {
	switch {
	case errors.Is(err, syscall.ENOTEMPTY): // before ErrExist, which also matches it
		return "notempty"
	case errors.Is(err, fs.ErrNotExist):
		return "notfound"
	case errors.Is(err, fs.ErrPermission):
		return "forbidden"
	case errors.Is(err, fs.ErrExist):
		return "exists"
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return "nospace"
	case errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.EISDIR), errors.Is(err, syscall.EINVAL):
		return "invalid"
	case errors.Is(err, syscall.EBUSY), errors.Is(err, syscall.EROFS):
		return "forbidden"
	}
	// Escapes through symlinks or ".." are refused by os.Root.
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return "notfound"
	}
	return "internal"
}
