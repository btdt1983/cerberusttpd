// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/btdt1983/cerberusttpd/internal/worker"
)

// A folder with a metadata file (worker.AlbumFile) is an album: it opens as a
// masonry gallery with a lightbox. The pictures are whatever images the folder
// holds; the file only adds title, description, order and captions.

// fileURL is the escaped URL of one file below prefix.
func fileURL(prefix, rel string) string {
	return prefix + strings.TrimSuffix(encodePath(rel), "/")
}

type photo struct {
	Name, Alt, Caption string
	Full, Thumb, View  string
	Download           string
	W, H               int
	Cover              bool
}

func (s *Server) album(w http.ResponseWriter, sess *Session, rel string, a worker.Response) {
	var photos []photo
	for _, im := range a.Images {
		full := path.Join(rel, im.Name)
		photos = append(photos, photo{
			Name: im.Name, Alt: firstNonEmpty(im.Caption, im.Name), Caption: im.Caption,
			Full: fileURL("/files/", full), Thumb: fileURL("/thumb/", full) + "?s=t&v=" + hex(im.MTime), View: fileURL("/thumb/", full) + "?s=v&v=" + hex(im.MTime),
			Download: fileURL("/files/", full) + "?dl", W: im.W, H: im.H,
		})
	}
	title := a.Album.Title
	if title == "" {
		title = "Album"
		if rel != "" {
			title = path.Base(rel)
		}
	}
	s.render(w, http.StatusOK, "album", map[string]any{
		"Title": title, "Description": a.Album.Description, "Crumbs": crumbs(rel), "User": sess.User, "Admin": sess.Admin,
		"Photos": photos, "Writable": a.Writable, "Dir": strings.Trim(rel, "/"), "EditURL": "/album/edit?dir=" + url.QueryEscape(strings.Trim(rel, "/")),
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// albumCreate turns a folder into an album (POST: the CSRF check applies).
func (s *Server) albumCreate(w http.ResponseWriter, r *http.Request) {
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
	dir := strings.Trim(path.Clean("/"+r.PostForm.Get("dir")), "/")
	title := strings.TrimSpace(r.PostForm.Get("title"))
	if title == "" || utf8.RuneCountInString(title) > 200 || !utf8.ValidString(title) {
		s.fail(w, "invalid")
		return
	}
	var resp worker.Response
	if _, err := sess.worker.Call(worker.Request{Op: "album_create", Path: dir, Album: &worker.Album{Title: title}}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err != "" && resp.Err != "exists" { // exists: someone was faster, just open it
		s.fail(w, resp.Err)
		return
	}
	http.Redirect(w, r, "/files/"+encodePath(dir), http.StatusSeeOther)
}

// thumb serves a grid thumbnail (s=t) or a lightbox-sized picture (s=v).
func (s *Server) thumb(w http.ResponseWriter, r *http.Request) {
	sess := s.current(r)
	if sess == nil {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	rel := r.PathValue("path")
	var resp worker.Response
	files, err := sess.worker.Call(worker.Request{Op: "thumb", Path: rel, Variant: r.URL.Query().Get("s")}, &resp)
	if err != nil {
		s.sess.destroy(cookieValue(r))
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	switch resp.Err {
	case "":
	case "notfound":
		http.Error(w, "not found", http.StatusNotFound)
		return
	case "forbidden":
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	case "invalid":
		http.Error(w, "this file cannot be shown as a picture", http.StatusUnsupportedMediaType)
		return
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "private, max-age=3600")
	mtime := time.Unix(0, resp.MTime)
	switch {
	case resp.Kind == "data":
		http.ServeContent(w, r, "thumb.jpg", mtime, bytes.NewReader(resp.Data))
	case len(files) == 1:
		name := "thumb.jpg"
		if resp.Name != "" { // the worker handed back the original picture
			name = resp.Name
		}
		h.Set("ETag", fmt.Sprintf(`"%s-%x-%x"`, r.URL.Query().Get("s"), resp.Size, resp.MTime))
		http.ServeContent(w, r, name, mtime, files[0])
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// albumEditPage shows the form for title, description, cover, captions and order.
func (s *Server) albumEditPage(w http.ResponseWriter, r *http.Request) {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	dir := relPath(r.URL.Query().Get("dir"))
	var resp worker.Response
	if _, err := sess.worker.Call(worker.Request{Op: "album", Path: dir}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err == "" && resp.Album == nil {
		resp.Err = "notfound"
	}
	if resp.Err != "" {
		s.fail(w, resp.Err)
		return
	}
	if !resp.Writable {
		s.fail(w, "forbidden")
		return
	}
	var photos []photo
	for _, im := range resp.Images {
		full := path.Join(dir, im.Name)
		photos = append(photos, photo{Name: im.Name, Caption: im.Caption, Thumb: fileURL("/thumb/", full) + "?s=t&v=" + hex(im.MTime), W: im.W, H: im.H, Cover: im.Name == resp.Album.Cover})
	}
	title := path.Base(dir)
	if dir == "" {
		title = "Files"
	}
	s.render(w, http.StatusOK, "albumedit", map[string]any{
		"Title": "Edit " + title, "User": sess.User, "Admin": sess.Admin, "Dir": dir, "Back": "/files/" + encodePath(dir),
		"Album": resp.Album, "Photos": photos, "Error": r.URL.Query().Get("err") != "",
		"RemoveURL": "/delete?path=" + url.QueryEscape(path.Join(dir, worker.AlbumFile)),
	})
}

var errAlbumForm = errors.New("invalid album form")

// albumFromForm builds the album from the edit form: name[] and caption[] are
// parallel lists in the order the user arranged the pictures.
func albumFromForm(f url.Values) (*worker.Album, error) {
	names, captions := f["name"], f["caption"]
	if len(names) != len(captions) {
		return nil, errAlbumForm
	}
	a := &worker.Album{
		Title:       strings.TrimSpace(f.Get("title")),
		Description: strings.TrimSpace(strings.ReplaceAll(f.Get("description"), "\r\n", "\n")),
		Cover:       f.Get("cover"),
	}
	if a.Title == "" || utf8.RuneCountInString(a.Title) > 200 || utf8.RuneCountInString(a.Description) > 4000 {
		return nil, errAlbumForm
	}
	seen := map[string]bool{}
	for i, n := range names {
		if n == "" || seen[n] {
			return nil, errAlbumForm
		}
		seen[n] = true
		a.Order = append(a.Order, n)
		if c := strings.TrimSpace(captions[i]); c != "" {
			if a.Captions == nil {
				a.Captions = map[string]string{}
			}
			a.Captions[n] = c
		}
	}
	if a.Cover != "" && !seen[a.Cover] {
		a.Cover = ""
	}
	return a, nil
}

func (s *Server) albumEditDo(w http.ResponseWriter, r *http.Request) {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	dir := relPath(r.PostForm.Get("dir"))
	a, err := albumFromForm(r.PostForm)
	if err != nil {
		http.Redirect(w, r, "/album/edit?err=1&dir="+url.QueryEscape(dir), http.StatusSeeOther)
		return
	}
	var resp worker.Response
	if _, err := sess.worker.Call(worker.Request{Op: "album_save", Path: dir, Album: a}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err == "invalid" {
		http.Redirect(w, r, "/album/edit?err=1&dir="+url.QueryEscape(dir), http.StatusSeeOther)
		return
	}
	if resp.Err != "" {
		s.fail(w, resp.Err)
		return
	}
	http.Redirect(w, r, "/files/"+encodePath(dir), http.StatusSeeOther)
}
