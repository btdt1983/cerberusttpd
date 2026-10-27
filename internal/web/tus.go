// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"syscall"

	"cerberusttpd/internal/worker"
)

// tus 1.0.0 with the creation and termination extensions. An upload id is
// "<base64url(dir)>.<random>": the directory is part of the URL so resuming
// works after the session (and its worker) is gone.
const tusVersion = "1.0.0"

func (s *Server) tusHeaders(w http.ResponseWriter) {
	w.Header().Set("Tus-Resumable", tusVersion)
	w.Header().Set("Cache-Control", "no-store")
}

func (s *Server) tusOptions(w http.ResponseWriter, r *http.Request) {
	s.tusHeaders(w)
	w.Header().Set("Tus-Version", tusVersion)
	w.Header().Set("Tus-Extension", "creation,termination")
	if s.MaxUpload > 0 {
		w.Header().Set("Tus-Max-Size", strconv.FormatInt(s.MaxUpload, 10))
	}
	w.WriteHeader(http.StatusNoContent)
}

// tusSession checks login and the protocol version.
func (s *Server) tusSession(w http.ResponseWriter, r *http.Request) *Session {
	s.tusHeaders(w)
	sess := s.current(r)
	if sess == nil {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return nil
	}
	if r.Header.Get("Tus-Resumable") != tusVersion {
		w.Header().Set("Tus-Version", tusVersion)
		http.Error(w, "unsupported tus version", http.StatusPreconditionFailed)
		return nil
	}
	return sess
}

func parseMetadata(h string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(h, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(kv), " ")
		if b, err := base64.StdEncoding.DecodeString(v); err == nil && k != "" {
			out[k] = string(b)
		}
	}
	return out
}

func (s *Server) tusCreate(w http.ResponseWriter, r *http.Request) {
	sess := s.tusSession(w, r)
	if sess == nil {
		return
	}
	length, err := strconv.ParseInt(r.Header.Get("Upload-Length"), 10, 64)
	if err != nil || length < 0 {
		http.Error(w, "Upload-Length missing", http.StatusBadRequest)
		return
	}
	if s.MaxUpload > 0 && length > s.MaxUpload {
		w.Header().Set("Tus-Max-Size", strconv.FormatInt(s.MaxUpload, 10))
		http.Error(w, "file is too large (maximum "+humanBytes(s.MaxUpload)+")", http.StatusRequestEntityTooLarge)
		return
	}
	md := parseMetadata(r.Header.Get("Upload-Metadata"))
	dir := strings.Trim(md["dir"], "/")
	var resp worker.Response
	if _, err := sess.worker.Call(worker.Request{Op: "upload_create", Path: dir, Name: md["filename"], Length: length}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err != "" {
		s.tusFail(w, resp)
		return
	}
	w.Header().Set("Location", "/tus/"+base64.RawURLEncoding.EncodeToString([]byte(dir))+"."+resp.ID)
	w.Header().Set("Upload-Offset", "0")
	w.WriteHeader(http.StatusCreated)
}

func splitID(id string) (dir, rnd string, ok bool) {
	d, rnd, found := strings.Cut(id, ".")
	b, err := base64.RawURLEncoding.DecodeString(d)
	if !found || err != nil {
		return "", "", false
	}
	return string(b), rnd, true
}

func (s *Server) tusHead(w http.ResponseWriter, r *http.Request) {
	sess := s.tusSession(w, r)
	if sess == nil {
		return
	}
	dir, id, ok := splitID(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	var resp worker.Response
	if _, err := sess.worker.Call(worker.Request{Op: "upload_status", Path: dir, ID: id}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err != "" {
		s.tusFail(w, resp)
		return
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(resp.Offset, 10))
	w.Header().Set("Upload-Length", strconv.FormatInt(resp.Length, 10))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) tusPatch(w http.ResponseWriter, r *http.Request) {
	sess := s.tusSession(w, r)
	if sess == nil {
		return
	}
	if r.Header.Get("Content-Type") != "application/offset+octet-stream" {
		http.Error(w, "wrong Content-Type", http.StatusUnsupportedMediaType)
		return
	}
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	dir, id, ok := splitID(r.PathValue("id"))
	if err != nil || offset < 0 || !ok {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var resp worker.Response
	files, err := sess.worker.Call(worker.Request{Op: "upload_open", Path: dir, ID: id, Offset: offset}, &resp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	if resp.Err != "" {
		s.tusFail(w, resp)
		return
	}
	if len(files) != 1 {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	f := files[0]
	// One writer at a time per upload.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		http.Error(w, "upload in progress", http.StatusLocked)
		return
	}
	// Re-check under the lock: another writer may have moved the offset.
	if fi, err := f.Stat(); err != nil || fi.Size() != offset {
		if err == nil {
			w.Header().Set("Upload-Offset", strconv.FormatInt(fi.Size(), 10))
		}
		http.Error(w, "offset mismatch", http.StatusConflict)
		return
	}
	remaining := resp.Length - offset
	if r.ContentLength > remaining {
		http.Error(w, "too much data", http.StatusRequestEntityTooLarge)
		return
	}
	buf := make([]byte, 256<<10)
	n, err := io.CopyBuffer(io.NewOffsetWriter(f, offset), http.MaxBytesReader(w, r.Body, remaining), buf)
	newOffset := offset + n
	if err != nil {
		// Whatever arrived is kept; the client resumes from HEAD.
		w.Header().Set("Upload-Offset", strconv.FormatInt(newOffset, 10))
		status := http.StatusBadRequest
		if _, tooBig := err.(*http.MaxBytesError); tooBig {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "upload interrupted", status)
		return
	}
	if newOffset == resp.Length {
		if err := f.Sync(); err != nil {
			http.Error(w, "write failed", http.StatusInsufficientStorage)
			return
		}
		var done worker.Response
		if _, err := sess.worker.Call(worker.Request{Op: "upload_finish", Path: dir, ID: id}, &done); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		switch done.Err {
		case "":
		case "exists":
			// Not 409: that means "offset mismatch" to tus clients.
			http.Error(w, "file already exists", http.StatusUnprocessableEntity)
			return
		default:
			s.tusFail(w, done)
			return
		}
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(newOffset, 10))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) tusDelete(w http.ResponseWriter, r *http.Request) {
	sess := s.tusSession(w, r)
	if sess == nil {
		return
	}
	dir, id, ok := splitID(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	var resp worker.Response
	if _, err := sess.worker.Call(worker.Request{Op: "upload_cancel", Path: dir, ID: id}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err != "" {
		s.tusFail(w, resp)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) tusFail(w http.ResponseWriter, resp worker.Response) {
	switch resp.Err {
	case "forbidden":
		http.Error(w, "no write permission in this folder", http.StatusForbidden)
	case "notfound":
		http.Error(w, "not found", http.StatusNotFound)
	case "exists":
		http.Error(w, "file already exists", http.StatusConflict)
	case "conflict":
		w.Header().Set("Upload-Offset", strconv.FormatInt(resp.Offset, 10))
		http.Error(w, "offset mismatch", http.StatusConflict)
	case "nospace":
		http.Error(w, "no space left or quota exceeded", http.StatusInsufficientStorage)
	case "invalid":
		http.Error(w, "invalid request", http.StatusBadRequest)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (s *Server) mkdir(w http.ResponseWriter, r *http.Request) {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	dir := strings.Trim(r.PostForm.Get("dir"), "/")
	var resp worker.Response
	if _, err := sess.worker.Call(worker.Request{Op: "mkdir", Path: dir, Name: r.PostForm.Get("name")}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err != "" {
		s.fail(w, resp.Err)
		return
	}
	http.Redirect(w, r, "/files/"+encodePath(dir), http.StatusSeeOther)
}
