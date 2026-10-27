// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"net/http"
	"net/url"
	"path"
	"strings"

	"cerberusttpd/internal/worker"
)

// Rename and delete are plain forms: a GET page asks, a POST does it (so the
// CSRF check covers the change). The worker, running as the user, does the work.

func relPath(v string) string { return strings.Trim(path.Clean("/"+v), "/") }

func parentDir(rel string) string {
	d := path.Dir(rel)
	if d == "." {
		return ""
	}
	return d
}

// editTarget checks login and looks up what rel is.
func (s *Server) editTarget(w http.ResponseWriter, r *http.Request, rel string) (*Session, worker.Response, bool) {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, worker.Response{}, false
	}
	var st worker.Response
	if rel == "" {
		s.fail(w, "invalid")
		return nil, st, false
	}
	if _, err := sess.worker.Call(worker.Request{Op: "stat", Path: rel}, &st); err != nil {
		http.Error(w, "interne fout", http.StatusInternalServerError)
		return nil, st, false
	}
	if st.Err != "" {
		s.fail(w, st.Err)
		return nil, st, false
	}
	return sess, st, true
}

func (s *Server) editPage(mode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rel := relPath(r.URL.Query().Get("path"))
		sess, st, ok := s.editTarget(w, r, rel)
		if !ok {
			return
		}
		s.render(w, http.StatusOK, "edit", map[string]any{
			"Mode": mode, "User": sess.User, "Admin": sess.Admin, "Path": rel, "Name": st.Name,
			"IsDir": st.Kind == "dir", "Back": "/files/" + encodePath(parentDir(rel)),
		})
	}
}

func (s *Server) editDo(mode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "ongeldig verzoek", http.StatusBadRequest)
			return
		}
		rel := relPath(r.PostForm.Get("path"))
		sess, st, ok := s.editTarget(w, r, rel)
		if !ok {
			return
		}
		req := worker.Request{Op: mode, Path: rel, Name: strings.TrimSpace(r.PostForm.Get("name"))}
		var resp worker.Response
		if _, err := sess.worker.Call(req, &resp); err != nil {
			http.Error(w, "interne fout", http.StatusInternalServerError)
			return
		}
		if resp.Err != "" {
			msg := errText[resp.Err]
			if msg == "" {
				msg = "Er ging iets mis."
			}
			status := http.StatusConflict
			switch resp.Err {
			case "forbidden":
				status = http.StatusForbidden
			case "invalid":
				status = http.StatusBadRequest
			case "notfound":
				status = http.StatusNotFound
			}
			s.render(w, status, "edit", map[string]any{
				"Mode": mode, "User": sess.User, "Admin": sess.Admin, "Path": rel, "Name": st.Name,
				"IsDir": st.Kind == "dir", "Back": "/files/" + encodePath(parentDir(rel)), "Error": msg,
				"Value": req.Name, "NotEmpty": resp.Err == "notempty",
			})
			return
		}
		http.Redirect(w, r, "/files/"+encodePath(parentDir(rel)), http.StatusSeeOther)
	}
}

// actionURL is the link target for a row's rename/delete page.
func actionURL(kind, rel string) string {
	return "/" + kind + "?" + url.Values{"path": {rel}}.Encode()
}

const maxDeleteBatch = 200

var errText = map[string]string{
	"forbidden": "Geen rechten om dit te doen.",
	"exists":    "Er bestaat al iets met die naam.",
	"notempty":  "De map is niet leeg.",
	"invalid":   "Ongeldige naam.",
	"notfound":  "Niet gevonden.",
}

type delItem struct {
	Path, Name string
	IsDir      bool
	Error      string
}

// deletePaths cleans and de-duplicates the submitted paths; the root is never allowed.
func deletePaths(vals []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vals {
		rel := relPath(v)
		if rel != "" && !seen[rel] && len(out) < maxDeleteBatch {
			seen[rel] = true
			out = append(out, rel)
		}
	}
	return out
}

// deleteConfirm lists what is about to go and asks once for the whole batch.
func (s *Server) deleteConfirm(w http.ResponseWriter, r *http.Request) {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	paths := deletePaths(r.URL.Query()["path"])
	if len(paths) == 0 {
		http.Redirect(w, r, "/files/", http.StatusSeeOther)
		return
	}
	items, anyDir := s.statAll(sess, paths)
	s.render(w, http.StatusOK, "delete", map[string]any{
		"User": sess.User, "Admin": sess.Admin, "Items": items, "AnyDir": anyDir,
		"Back": "/files/" + encodePath(parentDir(paths[0])),
	})
}

func (s *Server) statAll(sess *Session, paths []string) ([]delItem, bool) {
	var items []delItem
	anyDir := false
	for _, p := range paths {
		var st worker.Response
		it := delItem{Path: p, Name: path.Base(p)}
		if _, err := sess.worker.Call(worker.Request{Op: "stat", Path: p}, &st); err != nil {
			it.Error = "Interne fout."
		} else if st.Err != "" {
			it.Error = errText[st.Err]
		} else if st.Kind == "dir" {
			it.IsDir, anyDir = true, true
		}
		items = append(items, it)
	}
	return items, anyDir
}

// deleteDo removes every selected item as the user. Failures do not stop the
// rest; they are listed afterwards.
func (s *Server) deleteDo(w http.ResponseWriter, r *http.Request) {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "ongeldig verzoek", http.StatusBadRequest)
		return
	}
	paths := deletePaths(r.PostForm["path"])
	if len(paths) == 0 {
		http.Redirect(w, r, "/files/", http.StatusSeeOther)
		return
	}
	recursive := r.PostForm.Get("recursive") == "1"
	var failed []delItem
	for _, p := range paths {
		var resp worker.Response
		it := delItem{Path: p, Name: path.Base(p)}
		if _, err := sess.worker.Call(worker.Request{Op: "delete", Path: p, Recursive: recursive}, &resp); err != nil {
			it.Error = "Interne fout."
		} else if resp.Err == "notempty" {
			it.Error = "De map is niet leeg; vink aan dat de inhoud ook weg mag."
		} else if resp.Err != "" {
			it.Error = errText[resp.Err]
			if it.Error == "" {
				it.Error = "Er ging iets mis."
			}
		}
		if it.Error != "" {
			failed = append(failed, it)
		}
	}
	back := "/files/" + encodePath(parentDir(paths[0]))
	if len(failed) == 0 {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusConflict, "deleted", map[string]any{
		"User": sess.User, "Admin": sess.Admin, "Failed": failed, "Done": len(paths) - len(failed), "Back": back,
		"Retry": "/delete?" + retryQuery(failed).Encode(),
	})
}

func retryQuery(items []delItem) url.Values {
	v := url.Values{}
	for _, it := range items {
		v.Add("path", it.Path)
	}
	return v
}
