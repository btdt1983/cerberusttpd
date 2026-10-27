// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// Package web is the unprivileged network-facing side: login, sessions and the
// file browser. It never touches user files itself; it asks the session's
// worker, which runs as that user.
package web

import (
	"embed"
	"html/template"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"cerberusttpd/internal/helper"
	"cerberusttpd/internal/ipc"
	"cerberusttpd/internal/limiter"
	"cerberusttpd/internal/worker"
)

//go:embed static
var staticFS embed.FS

type Server struct {
	helper    *ipc.Client
	sess      *sessions
	loginSem  chan struct{}
	limit     *limiter.Login
	stats     stats
	done      chan struct{} // closed on shutdown so live streams end
	doneOnce  sync.Once
	CAPEM     []byte // public root certificate, served for trust setup
	MaxUpload int64  // bytes; 0 means unlimited
	tpl       *template.Template
}

func New(h *ipc.Client) *Server {
	s := &Server{
		helper:   h,
		sess:     newSessions(),
		done:     make(chan struct{}),
		loginSem: make(chan struct{}, 8),
		limit:    limiter.NewLogin(),
		tpl:      newTemplates(),
	}
	go func() {
		for range time.Tick(time.Minute) {
			s.sess.reap()
		}
	}()
	go s.stats.run(s.sess)
	return s
}

// Shutdown ends the long-lived streams so the HTTP servers can drain.
func (s *Server) Shutdown() { s.doneOnce.Do(func() { close(s.done) }) }

// Handler returns the full routed handler with CSRF and security headers.
func (s *Server) Handler(altSvc string) http.Handler {
	static, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /2fa", s.mfaPage)
	mux.HandleFunc("POST /2fa", s.mfaSubmit)
	mux.HandleFunc("GET /2fa/qr.png", s.mfaQR)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/files/", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /files/{path...}", s.files)
	mux.HandleFunc("GET /api/stats", s.statsStream)
	mux.HandleFunc("POST /mkdir", s.mkdir)
	mux.HandleFunc("GET /rename", s.editPage("rename"))
	mux.HandleFunc("POST /rename", s.editDo("rename"))
	mux.HandleFunc("GET /delete", s.deleteConfirm)
	mux.HandleFunc("POST /delete", s.deleteDo)
	mux.HandleFunc("OPTIONS /tus/", s.tusOptions)
	mux.HandleFunc("POST /tus/", s.tusCreate)
	mux.HandleFunc("HEAD /tus/{id}", s.tusHead)
	mux.HandleFunc("PATCH /tus/{id}", s.tusPatch)
	mux.HandleFunc("DELETE /tus/{id}", s.tusDelete)
	if s.CAPEM != nil {
		mux.HandleFunc("GET /.well-known/cerberusttpd/ca.pem", s.caPEM)
		mux.HandleFunc("GET /.well-known/cerberusttpd/ca.crt", s.caDER)
		mux.HandleFunc("GET /.well-known/cerberusttpd/ca.cer", s.caDER)
	}
	// Cross-origin POSTs are rejected via Sec-Fetch-Site / Origin.
	csrf := http.NewCrossOriginProtection().Handler(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Alt-Svc", altSvc)
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.URL.Path == "/api/stats" { // the stream itself is not traffic
			csrf.ServeHTTP(w, r)
			return
		}
		cw, done := s.count(w, r)
		defer done()
		csrf.ServeHTTP(cw, r)
	})
}

func (s *Server) current(r *http.Request) *Session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	sess := s.sess.get(c.Value)
	if sess == nil || sess.Stage < StageFull {
		return nil
	}
	return sess
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.current(r) != nil {
		http.Redirect(w, r, "/files/", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login", map[string]any{})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	user, pass, ip := r.PostForm.Get("user"), r.PostForm.Get("password"), clientIP(r)
	if ok, wait := s.limit.Allow(ip, user); !ok {
		w.Header().Set("Retry-After", itoa(int(wait.Seconds())+1))
		s.render(w, http.StatusTooManyRequests, "login", map[string]any{"Error": "Te veel pogingen, probeer het later opnieuw."})
		return
	}
	select {
	case s.loginSem <- struct{}{}:
		defer func() { <-s.loginSem }()
	default:
		s.render(w, http.StatusServiceUnavailable, "login", map[string]any{"Error": "Server is druk, probeer het zo opnieuw."})
		return
	}
	var resp helper.Response
	files, err := s.helper.Call(helper.Request{Op: "login", User: user, Password: pass, RHost: ip}, &resp)
	if err != nil || !resp.OK || (resp.MFA == "" && len(files) != 1) {
		for _, f := range files {
			f.Close()
		}
		s.limit.Fail(ip, user)
		status, msg := http.StatusUnauthorized, "Ongeldige gebruikersnaam of wachtwoord."
		if resp.Err == "throttled" {
			status, msg = http.StatusTooManyRequests, "Te veel pogingen, probeer het later opnieuw."
		} else if err != nil || resp.Err == "internal" {
			status, msg = http.StatusInternalServerError, "Inloggen is nu niet mogelijk."
		}
		s.render(w, status, "login", map[string]any{"Error": msg})
		return
	}
	if resp.MFA != "" {
		// Password ok, no files yet: park the login until the code is checked.
		token, err := s.sess.create(&Session{User: resp.User, Stage: StagePassword, Pending: resp.Pending, MFAMode: resp.MFA})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.setCookie(w, token, int(pendingLife.Seconds()))
		http.Redirect(w, r, "/2fa", http.StatusSeeOther)
		return
	}
	s.limit.Success(ip, user)
	wc, err := ipc.NewClient(files[0])
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Fresh token per login prevents session fixation.
	token, err := s.sess.create(&Session{User: resp.User, UID: resp.UID, Admin: resp.Admin, Stage: StageFull, worker: wc})
	if err != nil {
		wc.Close()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, token, int(maxLife.Seconds()))
	http.Redirect(w, r, "/files/", http.StatusSeeOther)
}

func (s *Server) setCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: maxAge,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sess.destroy(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) files(w http.ResponseWriter, r *http.Request) {
	sess := s.current(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	rel := r.PathValue("path")
	var resp worker.Response
	files, err := sess.worker.Call(worker.Request{Op: "open", Path: rel}, &resp)
	if err != nil {
		s.sess.destroy(cookieValue(r))
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	if resp.Err != "" {
		s.fail(w, resp.Err)
		return
	}
	if resp.Kind == "dir" {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, path.Base(r.URL.Path)+"/", http.StatusMovedPermanently)
			return
		}
		s.listing(w, sess, rel)
		return
	}
	if len(files) != 1 {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Accept-Ranges", "bytes")
	h.Set("ETag", `"`+hex(resp.Size)+"-"+hex(resp.MTime)+`"`)
	// Files are user content on our origin: never let them run as pages.
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "private, no-cache")
	name := path.Base(rel)
	if r.URL.Query().Has("dl") || risky(name) {
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	}
	http.ServeContent(w, r, name, time.Unix(0, resp.MTime), files[0])
}

func risky(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".html", ".htm", ".xhtml", ".svg", ".xml", ".js", ".mjs", ".xsl", ".xslt":
		return true
	}
	return false
}

func (s *Server) listing(w http.ResponseWriter, sess *Session, rel string) {
	var resp worker.Response
	if _, err := sess.worker.Call(worker.Request{Op: "list", Path: rel}, &resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if resp.Err != "" {
		s.fail(w, resp.Err)
		return
	}
	type row struct {
		Name, Href, Rename, Delete, Full, Icon, Download string
		Dir                                              bool
		Size                                             int64
		MTime                                            time.Time
	}
	var rows []row
	for _, e := range resp.Entries {
		n := e.Name
		if e.Dir {
			n += "/"
		}
		full := path.Join(rel, e.Name)
		rows = append(rows, row{Name: n, Href: rowHref(n), Rename: actionURL("rename", full), Delete: actionURL("delete", full), Full: full,
			Icon: iconFor(e.Name, e.Dir), Download: rowHref(e.Name) + "?dl", Dir: e.Dir, Size: e.Size, MTime: time.Unix(0, e.MTime)})
	}
	cur := "/" + strings.Trim(rel, "/")
	if cur != "/" {
		cur += "/"
	}
	title := "Bestanden"
	if rel != "" {
		title = path.Base(rel)
	}
	s.render(w, http.StatusOK, "browse", map[string]any{"Title": title, "Crumbs": crumbs(rel), "User": sess.User, "Admin": sess.Admin, "Path": cur, "Rows": rows, "Root": rel == "", "Cut": resp.Cut, "Writable": resp.Writable, "Dir": strings.Trim(rel, "/")})
}

// fail answers an HTML page request with a readable error page.
func (s *Server) fail(w http.ResponseWriter, code string) {
	status, title, msg := http.StatusInternalServerError, "Er ging iets mis", "Probeer het later opnieuw."
	switch code {
	case "forbidden":
		status, title, msg = http.StatusForbidden, "Geen toegang", "Je hebt geen rechten voor deze map of dit bestand."
	case "notfound":
		status, title, msg = http.StatusNotFound, "Niet gevonden", "Dit bestand of deze map bestaat niet (meer)."
	case "invalid":
		status, title, msg = http.StatusBadRequest, "Ongeldig verzoek", "Dit verzoek kan niet worden uitgevoerd."
	}
	s.render(w, status, "error", map[string]any{"Title": title, "Message": msg})
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		os.Stderr.WriteString("web: render: " + err.Error() + "\n")
	}
}

func cookieValue(r *http.Request) string {
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}
