// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/helper"
	"github.com/btdt1983/cerberusttpd/internal/ipc"
)

// Single sign-on. This side only keeps the browser's half: it makes up the
// state, nonce and PKCE verifier, remembers them for a few minutes, and hands
// the provider's answer to the root process, which exchanges the code, checks
// the ID token, picks the Unix account and starts its worker. Nothing here can
// name a user or sees the client secret.

const (
	oidcCookie    = "__Host-cerb_oidc"
	oidcFlowLife  = 10 * time.Minute
	oidcMaxFlows  = 10000 // pending sign-ins in total (a few MB)
	oidcMaxPerIP  = 30    // and from one address, so one client cannot lock everyone out
	oidcLoginPath = "/oidc/login"
)

type oidcFlow struct {
	nonce, verifier string
	bind            [32]byte // sha256 of the value in this browser's cookie
	ip              string
	expires         time.Time
}

type oidcFlows struct {
	mu     sync.Mutex
	m      map[string]*oidcFlow // by state; each entry works once
	perIP  map[string]int
	pruned time.Time
}

func newOIDCFlows() *oidcFlows {
	return &oidcFlows{m: map[string]*oidcFlow{}, perIP: map[string]int{}}
}

// drop removes one entry; the caller holds the lock.
func (f *oidcFlows) drop(state string) {
	if fl := f.m[state]; fl != nil {
		if f.perIP[fl.ip]--; f.perIP[fl.ip] <= 0 {
			delete(f.perIP, fl.ip)
		}
		delete(f.m, state)
	}
}

// put stores a new flow unless the address already has its share open, or the
// store is full. Anyone can start a sign-in, so the limits are what keep one
// client from using up everybody's turns.
func (f *oidcFlows) put(state string, fl *oidcFlow) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if now.Sub(f.pruned) > 10*time.Second || len(f.m) >= oidcMaxFlows || f.perIP[fl.ip] >= oidcMaxPerIP {
		f.pruned = now
		for k, v := range f.m {
			if now.After(v.expires) {
				f.drop(k)
			}
		}
	}
	if len(f.m) >= oidcMaxFlows || f.perIP[fl.ip] >= oidcMaxPerIP {
		return false
	}
	f.m[state] = fl
	f.perIP[fl.ip]++
	return true
}

// take removes and returns the flow, if it is still valid.
func (f *oidcFlows) take(state string) *oidcFlow {
	f.mu.Lock()
	defer f.mu.Unlock()
	fl := f.m[state]
	f.drop(state)
	if fl == nil || time.Now().After(fl.expires) {
		return nil
	}
	return fl
}

func randomString() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// oidcStart begins a sign-in: POST, so the CSRF check applies.
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	state, e1 := randomString()
	nonce, e2 := randomString()
	verifier, e3 := randomString() // 43 characters: a valid PKCE verifier
	bind, e4 := randomString()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var resp helper.Response
	if _, err := s.helper.Call(helper.Request{Op: "oidc_begin", State: state, Nonce: nonce, Verifier: verifier}, &resp); err != nil || !resp.OK || resp.URL == "" {
		s.auditAs(r, "", "oidc", "login", "error")
		s.render(w, http.StatusServiceUnavailable, "login", map[string]any{"Error": "Signing in with " + s.OIDCLabel + " is not possible right now."})
		return
	}
	fl := &oidcFlow{nonce: nonce, verifier: verifier, bind: sha256.Sum256([]byte(bind)), ip: clientIP(r), expires: time.Now().Add(oidcFlowLife)}
	if !s.flows.put(state, fl) {
		s.render(w, http.StatusServiceUnavailable, "login", map[string]any{"Error": "The server is busy, please try again in a moment."})
		return
	}
	// Lax, not Strict: the provider sends the browser back with a cross-site GET.
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: bind, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(oidcFlowLife.Seconds())})
	http.Redirect(w, r, resp.URL, http.StatusSeeOther)
}

// oidcCallback is where the provider sends the browser back.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	q := r.URL.Query()
	fl := s.flows.take(q.Get("state"))
	c, cerr := r.Cookie(oidcCookie)
	if fl == nil || cerr != nil {
		s.auditAs(r, "", "oidc", "login", "denied", "why", "no matching sign-in")
		s.render(w, http.StatusBadRequest, "login", map[string]any{"Error": "That sign-in link has expired or was not started here. Please try again."})
		return
	}
	got := sha256.Sum256([]byte(c.Value))
	if subtle.ConstantTimeCompare(got[:], fl.bind[:]) != 1 {
		s.auditAs(r, "", "oidc", "login", "denied", "why", "browser mismatch")
		s.render(w, http.StatusBadRequest, "login", map[string]any{"Error": "That sign-in link has expired or was not started here. Please try again."})
		return
	}
	code := q.Get("code")
	if perr := q.Get("error"); perr != "" || code == "" || len(code) > 4096 {
		// The provider's error text is for the log, not for the page.
		s.auditAs(r, "", "oidc", "login", "denied", "why", "provider: "+trim(perr, 64))
		s.render(w, http.StatusUnauthorized, "login", map[string]any{"Error": "Signing in with " + s.OIDCLabel + " did not complete."})
		return
	}
	select {
	case s.loginSem <- struct{}{}:
		defer func() { <-s.loginSem }()
	default:
		s.render(w, http.StatusServiceUnavailable, "login", map[string]any{"Error": "The server is busy, please try again in a moment."})
		return
	}
	var resp helper.Response
	files, err := s.helper.Call(helper.Request{Op: "oidc_login", AuthCode: code, Verifier: fl.verifier, Nonce: fl.nonce, RHost: clientIP(r)}, &resp)
	if err != nil || !resp.OK || len(files) != 1 {
		for _, f := range files {
			f.Close()
		}
		status, msg, result := http.StatusUnauthorized, "Signing in with "+s.OIDCLabel+" failed.", "denied"
		switch {
		case err != nil || resp.Err == "internal":
			status, msg, result = http.StatusInternalServerError, "Signing in is not possible right now.", "error"
		case resp.Err == "throttled":
			status, msg, result = http.StatusTooManyRequests, "Too many attempts, please try again later.", "throttled"
		case resp.Err == "unmapped":
			status, msg, result = http.StatusForbidden, "Your "+s.OIDCLabel+" account is not linked to a user on this server. Ask the administrator.", "unmapped"
		}
		s.auditAs(r, resp.User, "oidc", "login", result, "idp_user", resp.IdP)
		s.render(w, status, "login", map[string]any{"Error": msg})
		return
	}
	wc, err := ipc.NewClient(files[0])
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token, err := s.sess.create(&Session{User: resp.User, UID: resp.UID, Admin: resp.Admin, Auth: "oidc", Stage: StageFull, worker: wc})
	if err != nil {
		wc.Close()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.auditAs(r, resp.User, "oidc", "login", "ok", "idp_user", resp.IdP)
	s.setCookie(w, token, int(maxLife.Seconds()))
	// Not a 303: the whole redirect chain began on the provider's site, so the
	// browser would not send our SameSite=Strict session cookie on it and the
	// user would land on the sign-in page. A page of our own, then a refresh,
	// is a same-site navigation.
	s.render(w, http.StatusOK, "continue", map[string]any{"To": "/files/"})
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
