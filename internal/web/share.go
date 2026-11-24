// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/helper"
	"github.com/btdt1983/cerberusttpd/internal/worker"
)

// Share links. The owner side is an ordinary signed-in page; the public side
// (/s/...) has no session at all. Every decision, from the password to the
// download limit, is taken by the helper (see internal/helper/share.go): this
// file only carries the question over and streams the answer.

var shareTTLs = []struct {
	Label   string
	Seconds int64
}{
	{"1 hour", 3600}, {"1 day", 86400}, {"7 days", 7 * 86400}, {"30 days", 30 * 86400},
}

// shareChoices are the lifetimes the form offers, never longer than the limit.
func (s *Server) shareChoices() []map[string]any {
	var out []map[string]any
	limit := int64(s.ShareMaxDays) * 86400
	for _, t := range shareTTLs {
		if t.Seconds <= limit {
			out = append(out, map[string]any{"Label": t.Label, "Seconds": t.Seconds, "Default": t.Seconds == 7*86400})
		}
	}
	if len(out) == 0 || out[len(out)-1]["Seconds"].(int64) < limit {
		out = append(out, map[string]any{"Label": strconv.Itoa(s.ShareMaxDays) + " days", "Seconds": limit})
	}
	return out
}

// shareTarget checks login and that rel is a file the owner can see.
func (s *Server) shareTarget(w http.ResponseWriter, r *http.Request, rel string) (*Session, worker.Response, bool) {
	sess, st, ok := s.editTarget(w, r, rel)
	if !ok {
		return nil, st, false
	}
	if st.Kind != "file" {
		s.render(w, http.StatusBadRequest, "error", map[string]any{"Title": "Not a file", "Message": "Only a single file can be shared, not a folder."})
		return nil, st, false
	}
	return sess, st, true
}

func (s *Server) shareForm(w http.ResponseWriter, r *http.Request) {
	rel := relPath(r.URL.Query().Get("path"))
	sess, st, ok := s.shareTarget(w, r, rel)
	if !ok {
		return
	}
	s.render(w, http.StatusOK, "shareform", s.shareFormData(sess, st.Name, rel, "", "", nil))
}

// shareFormData is the data for the page where a file is shared, by link and
// with people. users/groups prefill the people form (or are read back from the
// existing share when nil).
func (s *Server) shareFormData(sess *Session, name, rel, errLinks, errPeople string, picked map[string]bool) map[string]any {
	d := map[string]any{"User": sess.User, "Admin": sess.Admin, "Path": rel, "Name": name,
		"Back": "/files/" + encodePath(parentDir(rel)), "Links": s.Shares, "People": s.Internal(),
		"Error": errLinks, "PeopleError": errPeople, "TTLs": s.shareChoices(), "MaxDays": s.ShareMaxDays,
		"ShareUsers": s.ShareUsers, "RequirePW": s.ShareRequirePW}
	if s.Internal() {
		var users []string
		have := map[string]bool{}
		var resp helper.Response
		if _, err := s.helper.Call(helper.Request{Op: "acl_list", Grant: sess.Grant}, &resp); err == nil {
			for _, p := range resp.People {
				if p.Path == rel {
					users = p.Users
					for _, g := range p.Groups {
						have[g] = true
					}
					d["Current"] = p.ID
				}
			}
		}
		if picked != nil {
			have = picked
		}
		var gs []map[string]any
		for _, g := range s.ShareGroups {
			gs = append(gs, map[string]any{"Name": g, "On": have[g]})
		}
		d["Groups"] = gs
		d["UserList"] = strings.Join(users, ", ")
	}
	return d
}

func (s *Server) shareCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rel := relPath(r.PostForm.Get("path"))
	sess, st, ok := s.shareTarget(w, r, rel)
	if !ok {
		return
	}
	again := func(msg string) {
		s.render(w, http.StatusBadRequest, "shareform", s.shareFormData(sess, st.Name, rel, msg, "", nil))
	}
	ttl, err := strconv.ParseInt(r.PostForm.Get("ttl"), 10, 64)
	if err != nil || ttl <= 0 || ttl > int64(s.ShareMaxDays)*86400 {
		again("Choose how long the link stays valid.")
		return
	}
	limit := 0
	if v := strings.TrimSpace(r.PostForm.Get("max")); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 || limit > 100000 {
			again("The download limit must be a number from 1 to 100000, or empty for no limit.")
			return
		}
	}
	pw := r.PostForm.Get("password")
	if s.ShareRequirePW && pw == "" {
		again("A password is required for share links.")
		return
	}
	if len(pw) > 64 {
		again("The password may be at most 64 bytes long.")
		return
	}
	var resp helper.Response
	if _, err := s.helper.Call(helper.Request{Op: "share_create", Grant: sess.Grant, Path: rel, TTL: ttl, Max: limit, Password: pw}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.auditSess(r, sess, "share_create", outcome(resp.Err), "share", resp.ShareID, "path", rel, "ttl", ttl, "max", limit, "password", pw != "")
	switch resp.Err {
	case "":
	case "toomany":
		again("You have too many active share links. Revoke one first.")
		return
	case "needpw":
		again("A password is required for share links.")
		return
	default:
		s.fail(w, "internal")
		return
	}
	link := "https://" + r.Host + "/s/" + resp.Token
	s.render(w, http.StatusOK, "sharedone", map[string]any{"User": sess.User, "Admin": sess.Admin, "Name": st.Name, "Link": link,
		"Expires": resp.Expires.Local().Format("2006-01-02 15:04"), "Max": limit, "HasPW": pw != "", "Back": "/files/" + encodePath(parentDir(rel))})
}

type shareRow struct {
	ID, Owner, Path, State string
	Created                time.Time
	Expires                time.Time
	Uses                   string
	HasPW, Live            bool
}

func (s *Server) shareList(w http.ResponseWriter, r *http.Request) {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	var resp helper.Response
	if _, err := s.helper.Call(helper.Request{Op: "share_list", Grant: sess.Grant}, &resp); err != nil || resp.Err != "" {
		s.fail(w, "internal")
		return
	}
	now := time.Now()
	var rows []shareRow
	for _, x := range resp.Shares {
		row := shareRow{ID: x.ID, Path: x.Path, Created: x.Created.Local(), Expires: x.Expires.Local(), HasPW: x.HasPW, Live: true, State: "active"}
		row.Uses = strconv.Itoa(x.Used)
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
	s.render(w, http.StatusOK, "shares", map[string]any{"User": sess.User, "Admin": sess.Admin, "Rows": rows, "Revoked": r.URL.Query().Has("revoked")})
}

func (s *Server) shareRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	id := r.PostForm.Get("id")
	var resp helper.Response
	if _, err := s.helper.Call(helper.Request{Op: "share_revoke", Grant: sess.Grant, ShareID: id}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.auditSess(r, sess, "share_revoke", outcome(resp.Err), "share", id)
	if resp.Err != "" && resp.Err != "notfound" {
		s.fail(w, "internal")
		return
	}
	http.Redirect(w, r, "/shares?revoked", http.StatusSeeOther)
}

// The public side. Unknown, expired, used up and revoked links all look the
// same from outside.

func (s *Server) shareGone(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, http.StatusNotFound, "sharegone", map[string]any{})
}

func (s *Server) sharePage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	var resp helper.Response
	if _, err := s.helper.Call(helper.Request{Op: "share_info", Token: token}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err != "" {
		s.auditAs(r, "", "share", "share_view", "unavailable", "share", resp.ShareID, "why", resp.Detail)
		s.shareGone(w)
		return
	}
	s.render(w, http.StatusOK, "sharepage", map[string]any{"Name": resp.Name, "HasPW": resp.HasPW, "Get": "/s/" + url.PathEscape(token) + "/get",
		"Expires": resp.Expires.Local().Format("2006-01-02 15:04")})
}

// shareGet hands the file over. A password comes in a POST body, never in the
// URL. A range request that does not start at byte 0 is a resumed download and
// does not use up the limit again (only on links without a limit).
func (s *Server) shareGet(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if r.Method == http.MethodHead { // a probe must neither open the file nor use up the limit
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pw := ""
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pw = r.PostForm.Get("password")
	}
	rng := r.Header.Get("Range")
	var resp helper.Response
	files, err := s.helper.Call(helper.Request{Op: "share_open", Token: token, Password: pw, RHost: clientIP(r), Range: rng}, &resp)
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err != "" {
		s.auditAs(r, "", "share", "share_open", resp.Err, "share", resp.ShareID, "why", resp.Detail)
		page := func(status int, msg string) {
			s.render(w, status, "sharepage", map[string]any{"Name": "", "HasPW": true, "Error": msg, "Get": "/s/" + url.PathEscape(token) + "/get"})
		}
		switch resp.Err {
		case "password":
			page(http.StatusUnauthorized, "")
		case "badpassword":
			page(http.StatusUnauthorized, "That password is not right.")
		case "throttled":
			w.Header().Set("Retry-After", "60")
			page(http.StatusTooManyRequests, "Too many attempts, please try again later.")
		case "busy":
			w.Header().Set("Retry-After", "5")
			http.Error(w, "The server is busy, please try again in a moment.", http.StatusServiceUnavailable)
		case "internal":
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			s.shareGone(w)
		}
		return
	}
	if len(files) != 1 {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.auditAs(r, "", "share", "share_open", "ok", "share", resp.ShareID, "size", resp.Size, "range", rng)
	h := w.Header()
	if !resp.Whole {
		h.Set("Accept-Ranges", "bytes")
	}
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(resp.Name)}))
	if resp.Whole {
		// A link with a download limit sends the whole file, every time, and
		// says so: ServeContent would offer ranges.
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Length", strconv.FormatInt(resp.Size, 10))
		h.Set("Last-Modified", time.Unix(0, resp.MTime).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		io.Copy(w, io.LimitReader(files[0], resp.Size))
		return
	}
	http.ServeContent(w, r, resp.Name, time.Unix(0, resp.MTime), files[0])
}
