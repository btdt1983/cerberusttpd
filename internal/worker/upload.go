// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package worker

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"
)

// An upload is two hidden files next to the final name, so resuming works
// across sessions and server restarts and "may this user write here" is
// answered by the kernel when they are created:
//
//	.cerb-<id>.part   the bytes received so far (its size is the offset)
//	.cerb-<id>.json   {name, length}
const partPrefix = ".cerb-"

var idRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

type meta struct {
	Name   string `json:"name"`
	Length int64  `json:"length"`
}

func partName(dir, id string) string { return path.Join(dir, partPrefix+id+".part") }
func metaName(dir, id string) string { return path.Join(dir, partPrefix+id+".json") }

func validName(n string) bool {
	if n == "" || len(n) > 255 || n == "." || n == ".." || strings.HasPrefix(n, partPrefix) || !utf8.ValidString(n) {
		return false
	}
	for _, r := range n {
		if r == '/' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func upload(root *os.Root, dir string, req Request) (any, []*os.File) {
	switch req.Op {
	case "mkdir":
		if !validName(req.Name) {
			return Response{Err: "invalid"}, nil
		}
		if err := root.Mkdir(path.Join(dir, req.Name), 0o755); err != nil {
			return Response{Err: errCode(err)}, nil
		}
		return Response{}, nil
	case "upload_create":
		return create(root, dir, req), nil
	}
	if !idRE.MatchString(req.ID) {
		return Response{Err: "notfound"}, nil
	}
	m, err := readMeta(root, metaName(dir, req.ID))
	if err != nil {
		return Response{Err: "notfound"}, nil
	}
	switch req.Op {
	case "upload_status":
		fi, err := root.Lstat(partName(dir, req.ID))
		if err != nil {
			return Response{Err: errCode(err)}, nil
		}
		return Response{ID: req.ID, Offset: fi.Size(), Length: m.Length}, nil
	case "upload_open":
		return openPart(root, dir, req, m)
	case "upload_finish":
		return finish(root, dir, req.ID, m), nil
	case "upload_cancel":
		root.Remove(partName(dir, req.ID))
		root.Remove(metaName(dir, req.ID))
		return Response{}, nil
	}
	return Response{Err: "invalid"}, nil
}

func create(root *os.Root, dir string, req Request) Response {
	if !validName(req.Name) || req.Length < 0 {
		return Response{Err: "invalid"}
	}
	if fi, err := root.Stat(dir); err != nil {
		return Response{Err: errCode(err)}
	} else if !fi.IsDir() {
		return Response{Err: "invalid"}
	}
	if _, err := root.Lstat(path.Join(dir, req.Name)); err == nil {
		return Response{Err: "exists"}
	}
	id := randID()
	// O_EXCL: the kernel checks write+search permission on the directory here.
	part, err := root.OpenFile(partName(dir, id), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return Response{Err: errCode(err)}
	}
	part.Close()
	mf, err := root.OpenFile(metaName(dir, id), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err == nil {
		err = json.NewEncoder(mf).Encode(meta{Name: req.Name, Length: req.Length})
		if cerr := mf.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		root.Remove(partName(dir, id))
		root.Remove(metaName(dir, id))
		return Response{Err: errCode(err)}
	}
	resp := Response{ID: id, Length: req.Length}
	if req.Length == 0 { // nothing to send: complete right away
		f := finish(root, dir, id, meta{Name: req.Name})
		if f.Err != "" {
			return f
		}
	}
	return resp
}

// openPart hands the network process a write-only descriptor for the partial
// file; the kernel already checked our rights when we opened it.
func openPart(root *os.Root, dir string, req Request, m meta) (any, []*os.File) {
	f, err := root.OpenFile(partName(dir, req.ID), os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Response{Err: errCode(err)}, nil
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uint32(os.Getuid()) {
		f.Close()
		return Response{Err: "invalid"}, nil
	}
	if st.Size != req.Offset {
		f.Close()
		return Response{Err: "conflict", Offset: st.Size, Length: m.Length}, nil
	}
	return Response{ID: req.ID, Offset: st.Size, Length: m.Length}, []*os.File{f}
}

func finish(root *os.Root, dir, id string, m meta) Response {
	part := partName(dir, id)
	fi, err := root.Lstat(part)
	if err != nil {
		return Response{Err: errCode(err)}
	}
	if fi.Size() != m.Length {
		return Response{Err: "conflict", Offset: fi.Size(), Length: m.Length}
	}
	if err := root.Chmod(part, 0o644); err != nil {
		return Response{Err: errCode(err)}
	}
	// link(2) fails if the name exists, so an upload never replaces a file.
	if err := root.Link(part, path.Join(dir, m.Name)); err != nil {
		code := errCode(err)
		if code == "exists" { // lost a race for the name: drop the leftovers
			root.Remove(part)
			root.Remove(metaName(dir, id))
		}
		return Response{Err: code}
	}
	root.Remove(part)
	root.Remove(metaName(dir, id))
	return Response{Name: m.Name}
}

func readMeta(root *os.Root, name string) (meta, error) {
	var m meta
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return m, err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return m, err
	}
	if !validName(m.Name) || m.Length < 0 {
		return m, errors.New("bad meta")
	}
	return m, nil
}
