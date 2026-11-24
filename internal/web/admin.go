// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/helper"
)

// The admin page is for members of the wheel group. It shows who has shared
// what, who is signed in and what happened recently, and lets an administrator
// revoke a link or end a session. It never shows or changes files and it does
// not edit settings: those stay in the config file. Everything that changes
// something is a POST, and the helper (not this process) decides whether a
// request to touch other people's share links is allowed.

// StatusItem is one line of the settings overview.
type StatusItem struct{ Name, Value string }

const auditShown = 200

// admin checks login and the administrator flag the helper set at login.
func (s *Server) admin(w http.ResponseWriter, r *http.Request) *Session {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}
	if !sess.Admin {
		s.auditSess(r, sess, "admin", "forbidden", "path", r.URL.Path)
		s.fail(w, "forbidden")
		return nil
	}
	return sess
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	sess := s.admin(w, r)
	if sess == nil {
		return
	}
	q := r.URL.Query()
	user, event, result := strings.TrimSpace(q.Get("user")), strings.TrimSpace(q.Get("event")), strings.TrimSpace(q.Get("result"))
	data := map[string]any{"User": sess.User, "Admin": true, "Status": s.Status,
		"Done": q.Get("done"), "FUser": user, "FEvent": event, "FResult": result,
		"Events": s.ring.recent(user, event, result, auditShown), "Shown": auditShown,
		"Sessions": s.sess.list(time.Now(), s.mySessionID(r)), "ShareOn": s.Shares}
	if s.Shares {
		var resp helper.Response
		if _, err := s.helper.Call(helper.Request{Op: "share_list", Grant: sess.Grant, All: true}, &resp); err != nil || resp.Err != "" {
			s.fail(w, "internal")
			return
		}
		now := time.Now()
		var rows []shareRow
		for _, x := range resp.Shares {
			row := shareRow{ID: x.ID, Owner: x.Owner, Path: x.Path, Created: x.Created.Local(), Expires: x.Expires.Local(), HasPW: x.HasPW, Live: true, State: "active", Uses: strconv.Itoa(x.Used)}
			if x.Max > 0 {
				row.Uses += " of " + strconv.Itoa(x.Max)
			}
			switch {
			case now.After(x.Expires):
				row.State, row.Live = "expired", false
			case x.Max > 0 && x.Used >= x.Max:
				row.State, row.Live = "used up", false
			}
			rows = append(rows, row)
		}
		data["Shares"] = rows
	}
	if s.Internal() {
		var resp helper.Response
		if _, err := s.helper.Call(helper.Request{Op: "acl_list", Grant: sess.Grant, All: true}, &resp); err != nil || resp.Err != "" {
			s.fail(w, "internal")
			return
		}
		var rows []sharedRow
		for _, p := range resp.People {
			rows = append(rows, sharedRow{ID: p.ID, Owner: p.Owner, Path: p.Path, With: with(p), Created: p.Created.Local()})
		}
		data["People"] = rows
		data["PeopleOn"] = true
	}
	s.render(w, http.StatusOK, "admin", data)
}

func (s *Server) mySessionID(r *http.Request) string {
	if k, ok := key(cookieValue(r)); ok {
		return sessionID(k)
	}
	return ""
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request) {
	sess := s.admin(w, r)
	if sess == nil || !s.postForm(w, r) {
		return
	}
	id := r.PostForm.Get("id")
	var resp helper.Response
	if _, err := s.helper.Call(helper.Request{Op: "share_revoke", Grant: sess.Grant, ShareID: id, All: true}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.auditSess(r, sess, "admin_share_revoke", outcome(resp.Err), "share", id)
	if resp.Err != "" && resp.Err != "notfound" {
		s.fail(w, "internal")
		return
	}
	http.Redirect(w, r, "/admin?done=share", http.StatusSeeOther)
}

func (s *Server) adminKill(w http.ResponseWriter, r *http.Request) {
	sess := s.admin(w, r)
	if sess == nil || !s.postForm(w, r) {
		return
	}
	id := r.PostForm.Get("id")
	if id == s.mySessionID(r) {
		s.fail(w, "invalid") // signing out is what the button in the header is for
		return
	}
	who, ok := s.sess.kill(id)
	if ok {
		s.auditSess(r, sess, "admin_session_end", "ok", "target", who)
	}
	http.Redirect(w, r, "/admin?done=session", http.StatusSeeOther)
}

// postForm parses a small POST body.
func (s *Server) postForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}
