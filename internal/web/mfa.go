// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"net/http"
	"strings"

	"github.com/skip2/go-qrcode"

	"cerberusttpd/internal/helper"
	"cerberusttpd/internal/ipc"
)

// pendingSession returns the session of a login waiting for its code.
func (s *Server) pendingSession(r *http.Request) (*Session, string) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil, ""
	}
	sess := s.sess.get(c.Value)
	if sess == nil || sess.Stage != StagePassword {
		return nil, ""
	}
	return sess, c.Value
}

func (s *Server) mfaPage(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.pendingSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderMFA(w, r, sess, http.StatusOK, "")
}

func (s *Server) renderMFA(w http.ResponseWriter, r *http.Request, sess *Session, status int, msg string) {
	data := map[string]any{"Error": msg, "User": sess.User, "Enroll": sess.MFAMode == "enroll"}
	if sess.MFAMode == "enroll" {
		var resp helper.Response
		if _, err := s.helper.Call(helper.Request{Op: "mfa_setup", Pending: sess.Pending}, &resp); err != nil || !resp.OK {
			s.expire(w, r)
			return
		}
		sess.uri = resp.URI
		data["Secret"] = groups4(resp.Secret)
	}
	s.render(w, status, "mfa", data)
}

// expire ends an unfinished login and sends the user back to the start.
func (s *Server) expire(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sess.destroy(c.Value)
	}
	s.setCookie(w, "", -1)
	s.render(w, http.StatusUnauthorized, "login", map[string]any{"Error": "Inloggen is verlopen of te vaak mislukt. Log opnieuw in."})
}

func (s *Server) mfaQR(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.pendingSession(r)
	if sess == nil || sess.uri == "" {
		http.NotFound(w, r)
		return
	}
	png, err := qrcode.Encode(sess.uri, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

func (s *Server) mfaSubmit(w http.ResponseWriter, r *http.Request) {
	sess, old := s.pendingSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ip := clientIP(r)
	if ok, _ := s.limit.Allow(ip, sess.User); !ok {
		s.expire(w, r)
		return
	}
	var resp helper.Response
	files, err := s.helper.Call(helper.Request{Op: "mfa_verify", Pending: sess.Pending, Code: strings.TrimSpace(r.PostForm.Get("code"))}, &resp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !resp.OK || len(files) != 1 {
		for _, f := range files {
			f.Close()
		}
		if resp.Err == "denied" {
			s.limit.Fail(ip, sess.User)
			s.renderMFA(w, r, sess, http.StatusUnauthorized, "Ongeldige code.")
			return
		}
		s.expire(w, r)
		return
	}
	s.limit.Success(ip, sess.User)
	wc, err := ipc.NewClient(files[0])
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token, err := s.sess.promote(old, &Session{User: resp.User, UID: resp.UID, Admin: resp.Admin, Stage: StageFull, worker: wc})
	if err != nil {
		wc.Close()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, token, int(maxLife.Seconds()))
	if len(resp.Recovery) > 0 {
		s.render(w, http.StatusOK, "recovery", map[string]any{"Codes": resp.Recovery})
		return
	}
	http.Redirect(w, r, "/files/", http.StatusSeeOther)
}

// groups4 writes a secret in blocks of four for easier typing.
func groups4(s string) string {
	var b strings.Builder
	for i, c := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}
