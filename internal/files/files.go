// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// Package files serves a directory tree read-only, confined with os.Root so
// traversal and symlink escapes are rejected by the kernel (openat), not by
// string checks.
package files

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
)

type Server struct {
	root *os.Root
}

func New(dir string) (*Server, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Server{root: r}, nil
}

func (s *Server) Close() error { return s.root.Close() }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// path.Clean on a rooted path removes ".."; os.Root enforces the rest.
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "."
	}
	f, err := s.root.Open(name)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		s.fail(w, err)
		return
	}
	if fi.IsDir() {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, path.Base(r.URL.Path)+"/", http.StatusMovedPermanently)
			return
		}
		s.list(w, r, f)
		return
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", fmt.Sprintf(`"%x-%x"`, fi.Size(), fi.ModTime().UnixNano()))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Has("dl") {
		w.Header().Set("Content-Disposition", "attachment")
	}
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, d *os.File) {
	ents, err := d.ReadDir(-1)
	if err != nil {
		s.fail(w, err)
		return
	}
	sort.Slice(ents, func(i, j int) bool {
		if ents[i].IsDir() != ents[j].IsDir() {
			return ents[i].IsDir()
		}
		return ents[i].Name() < ents[j].Name()
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>%s</title><h1>%s</h1><ul>",
		html.EscapeString(r.URL.Path), html.EscapeString(r.URL.Path))
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() {
			n += "/"
		}
		fmt.Fprintf(w, `<li><a href="%s">%s</a>`, (&url.URL{Path: n}).String(), html.EscapeString(n))
	}
	fmt.Fprint(w, "</ul>")
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case os.IsNotExist(err):
		http.Error(w, "404 not found", http.StatusNotFound)
	case os.IsPermission(err):
		http.Error(w, "403 forbidden", http.StatusForbidden)
	default:
		// Symlink/".." escapes and other os.Root refusals land here.
		http.Error(w, "404 not found", http.StatusNotFound)
	}
}
