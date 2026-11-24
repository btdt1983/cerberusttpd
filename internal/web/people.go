// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/helper"
)

// Sharing a file with chosen users or groups. The page and the lists live here;
// the decisions (who the recipient is, who is in a group, whether the owner is
// still valid) are the helper's, see internal/helper/people.go.

// names splits "jan, piet  kees" into names; the helper validates them.
func names(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';' })
}

func (s *Server) peopleSet(w http.ResponseWriter, r *http.Request) {
	if !s.postForm(w, r) {
		return
	}
	rel := relPath(r.PostForm.Get("path"))
	sess, st, ok := s.shareTarget(w, r, rel)
	if !ok {
		return
	}
	groups := r.PostForm["group"]
	picked := map[string]bool{}
	for _, g := range groups {
		picked[g] = true
	}
	var resp helper.Response
	if _, err := s.helper.Call(helper.Request{Op: "acl_set", Grant: sess.Grant, Path: rel, Users: names(r.PostForm.Get("users")), Groups: groups}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.auditSess(r, sess, "people_share", outcome(resp.Err), "share", resp.ShareID, "path", rel, "users", r.PostForm.Get("users"), "groups", strings.Join(groups, ","))
	if resp.Err != "" {
		msg := "That could not be saved. Pick at least one person or group."
		switch resp.Err {
		case "recipient":
			msg = "You cannot share with one or more of these names. Check the spelling; you cannot share with yourself."
		case "toomany":
			msg = "You are sharing too many files. Stop sharing one first."
		case "internal":
			s.fail(w, "internal")
			return
		}
		s.render(w, http.StatusBadRequest, "shareform", s.shareFormData(sess, st.Name, rel, "", msg, picked))
		return
	}
	http.Redirect(w, r, "/shared?saved", http.StatusSeeOther)
}

type sharedRow struct {
	ID, Owner, Path, Name, With string
	Created                     time.Time
}

func with(p helper.PeopleInfo) string {
	var parts []string
	parts = append(parts, p.Users...)
	for _, g := range p.Groups {
		parts = append(parts, "group "+g)
	}
	return strings.Join(parts, ", ")
}

func (s *Server) sharedPage(w http.ResponseWriter, r *http.Request) {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	var in, out helper.Response
	_, e1 := s.helper.Call(helper.Request{Op: "acl_list", Grant: sess.Grant, With: true}, &in)
	_, e2 := s.helper.Call(helper.Request{Op: "acl_list", Grant: sess.Grant}, &out)
	if e1 != nil || e2 != nil || in.Err != "" || out.Err != "" {
		s.fail(w, "internal")
		return
	}
	var withMe, byMe []sharedRow
	for _, p := range in.People {
		withMe = append(withMe, sharedRow{ID: p.ID, Owner: p.Owner, Name: path.Base(p.Path), Created: p.Created.Local()})
	}
	for _, p := range out.People {
		byMe = append(byMe, sharedRow{ID: p.ID, Path: p.Path, With: with(p), Created: p.Created.Local()})
	}
	s.render(w, http.StatusOK, "shared", map[string]any{"User": sess.User, "Admin": sess.Admin, "WithMe": withMe, "ByMe": byMe,
		"Saved": r.URL.Query().Has("saved"), "Stopped": r.URL.Query().Has("stopped")})
}

// sharedGet sends a file somebody shared with the signed-in user. Resuming is fine.
func (s *Server) sharedGet(w http.ResponseWriter, r *http.Request) {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	id := r.URL.Query().Get("id")
	var resp helper.Response
	files, err := s.helper.Call(helper.Request{Op: "acl_open", Grant: sess.Grant, ShareID: id}, &resp)
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err != "" || len(files) != 1 {
		if r.Method == http.MethodGet {
			s.auditSess(r, sess, "shared_open", outcome(resp.Err), "share", id)
		}
		switch resp.Err {
		case "busy":
			w.Header().Set("Retry-After", "5")
			http.Error(w, "The server is busy, please try again in a moment.", http.StatusServiceUnavailable)
		case "internal", "":
			s.fail(w, "internal")
		default:
			s.fail(w, "notfound")
		}
		return
	}
	if r.Method == http.MethodGet && r.Header.Get("Range") == "" {
		s.auditSess(r, sess, "shared_open", "ok", "share", id, "owner", resp.Owner, "size", resp.Size)
	}
	h := w.Header()
	h.Set("Accept-Ranges", "bytes")
	h.Set("Cache-Control", "private, no-cache")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(resp.Name)}))
	http.ServeContent(w, r, resp.Name, time.Unix(0, resp.MTime), files[0])
}

func (s *Server) peopleStop(w http.ResponseWriter, r *http.Request) {
	if !s.postForm(w, r) {
		return
	}
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	id := r.PostForm.Get("id")
	var resp helper.Response
	if _, err := s.helper.Call(helper.Request{Op: "acl_stop", Grant: sess.Grant, ShareID: id}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.auditSess(r, sess, "people_stop", outcome(resp.Err), "share", id)
	if resp.Err != "" && resp.Err != "notfound" {
		s.fail(w, "internal")
		return
	}
	http.Redirect(w, r, "/shared?stopped", http.StatusSeeOther)
}

func (s *Server) adminStop(w http.ResponseWriter, r *http.Request) {
	sess := s.admin(w, r)
	if sess == nil || !s.postForm(w, r) {
		return
	}
	id := r.PostForm.Get("id")
	var resp helper.Response
	if _, err := s.helper.Call(helper.Request{Op: "acl_stop", Grant: sess.Grant, ShareID: id, All: true}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.auditSess(r, sess, "admin_people_stop", outcome(resp.Err), "share", id)
	if resp.Err != "" && resp.Err != "notfound" {
		s.fail(w, "internal")
		return
	}
	http.Redirect(w, r, "/admin?done=share", http.StatusSeeOther)
}
