// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"encoding/pem"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

func itoa(n int) string               { return strconv.Itoa(n) }
func hex[T ~int | ~int64](n T) string { return strconv.FormatInt(int64(n), 16) }

var funcs = template.FuncMap{
	"size": func(n int64) string {
		const u = "KMGTP"
		if n < 1024 {
			return fmt.Sprintf("%d B", n)
		}
		f, i := float64(n)/1024, 0
		for f >= 1024 && i < len(u)-1 {
			f, i = f/1024, i+1
		}
		return fmt.Sprintf("%.1f %ciB", f, u[i])
	},
}

func (s *Server) caPEM(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="cerberusttpd-ca.pem"`)
	w.Write(s.CAPEM)
}

// caDER serves the root as DER (.crt/.cer), which Windows and Android import.
func (s *Server) caDER(w http.ResponseWriter, r *http.Request) {
	b, _ := pem.Decode(s.CAPEM)
	if b == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="cerberusttpd-ca.crt"`)
	w.Write(b.Bytes)
}

// encodePath escapes each segment of a slash-separated path and adds a trailing slash.
func encodePath(p string) string {
	if p == "" {
		return ""
	}
	parts := strings.Split(p, "/")
	for i, q := range parts {
		parts[i] = url.PathEscape(q)
	}
	return strings.Join(parts, "/") + "/"
}

func humanBytes(n int64) string { return funcs["size"].(func(int64) string)(n) }

type crumb struct {
	Name, Href string
	Last       bool
}

// crumbs turns "a/b/c" into clickable path parts, each link properly escaped.
func crumbs(rel string) []crumb {
	out := []crumb{{Name: "Home", Href: "/files/"}}
	if rel = strings.Trim(rel, "/"); rel == "" {
		out[0].Last = true
		return out
	}
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		out = append(out, crumb{Name: p, Href: "/files/" + encodePath(strings.Join(parts[:i+1], "/")), Last: i == len(parts)-1})
	}
	return out
}

// rowHref is a safe relative link to one directory entry (names may hold ?, #, %, :).
func rowHref(name string) string { return (&url.URL{Path: name}).String() }

func iconFor(name string, dir bool) string {
	if dir {
		return "folder"
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".avif", ".heic":
		return "image"
	case ".zip", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".7z", ".rar", ".zst", ".iso":
		return "archive"
	case ".mp4", ".mkv", ".avi", ".mov", ".webm", ".mp3", ".flac", ".wav", ".ogg", ".m4a":
		return "media"
	}
	return "file"
}
