// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/helper"
	"github.com/btdt1983/cerberusttpd/internal/ipc"
)

var farFuture = time.Now().Add(24 * time.Hour)

// fakeRoot stands in for the root process: it records what the network side
// sends and answers oidc_begin / oidc_login with a canned result.
type fakeRoot struct {
	begin, login helper.Request
	loginCalls   int
	result       helper.Response
	keep         []*os.File
}

func newServerWithFakeRoot(t *testing.T, label string) (*Server, *fakeRoot, *bytesLog) {
	t.Helper()
	mine, theirs, err := ipc.Pair()
	if err != nil {
		t.Fatal(err)
	}
	fr := &fakeRoot{result: helper.Response{OK: true, User: "jan", UID: 1001, IdP: "jan@example.com"}}
	go ipc.Serve(mine, func(raw json.RawMessage) (any, []*os.File) {
		var req helper.Request
		json.Unmarshal(raw, &req)
		switch req.Op {
		case "oidc_begin":
			fr.begin = req
			return helper.Response{OK: true, URL: "https://idp.example/auth?state=" + url.QueryEscape(req.State)}, nil
		case "oidc_login":
			fr.login = req
			fr.loginCalls++
			if !fr.result.OK {
				return fr.result, nil
			}
			a, b, err := ipc.Pair()
			if err != nil {
				t.Error(err)
			}
			fr.keep = append(fr.keep, b)
			return fr.result, []*os.File{a}
		}
		return helper.Response{Err: "internal"}, nil
	})
	hc, err := ipc.NewClient(theirs)
	if err != nil {
		t.Fatal(err)
	}
	s := New(hc)
	s.OIDCLabel = label
	return s, fr, &bytesLog{auditTo(s)}
}

type bytesLog struct{ b interface{ String() string } }

func (l *bytesLog) String() string { return l.b.String() }

func post(h http.Handler, path string, c *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, nil)
	r.RemoteAddr = "192.0.2.5:1"
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func get(h http.Handler, target string, c *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", target, nil)
	r.RemoteAddr = "192.0.2.5:1"
	r.Header.Set("Sec-Fetch-Site", "cross-site") // the provider sends the browser back
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	return nil
}

func start(t *testing.T, h http.Handler, fr *fakeRoot) (state string, bind *http.Cookie) {
	t.Helper()
	w := post(h, "/oidc/login", nil)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "https://idp.example/auth?state=") {
		t.Fatalf("start: %d %q", w.Code, w.Header().Get("Location"))
	}
	bind = cookieNamed(w, oidcCookie)
	if bind == nil || bind.SameSite != http.SameSiteLaxMode || !bind.Secure || !bind.HttpOnly {
		t.Fatalf("binding cookie %+v", bind)
	}
	if fr.begin.State == "" || fr.begin.Nonce == "" || len(fr.begin.Verifier) < 43 {
		t.Fatalf("begin %+v", fr.begin)
	}
	return fr.begin.State, bind
}

func TestOIDCSignInFlow(t *testing.T) {
	s, fr, log := newServerWithFakeRoot(t, "Microsoft")
	h := s.Handler("")
	state, bind := start(t, h, fr)

	w := get(h, "/oidc/callback?code=abc&state="+url.QueryEscape(state), bind)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `http-equiv="refresh"`) || !strings.Contains(w.Body.String(), "/files/") {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	sc := cookieNamed(w, cookieName)
	if sc == nil || sc.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie %+v", sc)
	}
	if fr.login.AuthCode != "abc" || fr.login.Nonce != fr.begin.Nonce || fr.login.Verifier != fr.begin.Verifier {
		t.Errorf("root got %+v, started with %+v", fr.login, fr.begin)
	}
	if sess := s.current(requestWith(sc)); sess == nil || sess.User != "jan" || sess.Auth != "oidc" {
		t.Errorf("session %+v", sess)
	}
	out := log.String()
	for _, want := range []string{"event=login", "user=jan", "auth=oidc", "result=ok", "idp_user=jan@example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit lacks %q: %s", want, out)
		}
	}
	for _, secret := range []string{"abc", state, fr.begin.Nonce, fr.begin.Verifier, sc.Value} {
		if strings.Contains(out, secret) {
			t.Errorf("audit log contains %q", secret)
		}
	}
	// A state works once.
	if w := get(h, "/oidc/callback?code=abc&state="+url.QueryEscape(state), bind); w.Code != http.StatusBadRequest {
		t.Errorf("replay: %d", w.Code)
	}
	if fr.loginCalls != 1 {
		t.Errorf("root asked %d times", fr.loginCalls)
	}
}

func requestWith(c *http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", "/files/", nil)
	r.AddCookie(c)
	return r
}

func TestOIDCCallbackNeedsTheStartingBrowser(t *testing.T) {
	s, fr, _ := newServerWithFakeRoot(t, "Microsoft")
	h := s.Handler("")
	q := "/oidc/callback?code=abc&state="
	type tc struct {
		target string
		cookie *http.Cookie
	}
	// each case gets a fresh sign-in so one failure cannot hide another
	cases := map[string]func() tc{
		"no cookie": func() tc { st, _ := start(t, h, fr); return tc{q + url.QueryEscape(st), nil} },
		"other cookie": func() tc {
			st, _ := start(t, h, fr)
			return tc{q + url.QueryEscape(st), &http.Cookie{Name: oidcCookie, Value: "someone-elses"}}
		},
		"unknown state": func() tc { _, b := start(t, h, fr); return tc{q + "nope", b} },
		"no state":      func() tc { _, b := start(t, h, fr); return tc{"/oidc/callback?code=abc", b} },
	}
	for name, mk := range cases {
		c := mk()
		if w := get(h, c.target, c.cookie); w.Code != http.StatusBadRequest || cookieNamed(w, cookieName) != nil {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if fr.loginCalls != 0 {
		t.Errorf("root was asked %d times", fr.loginCalls)
	}
}

func TestOIDCRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		res    helper.Response
		query  string
		status int
		calls  int
		want   string
	}{
		"not mapped":        {helper.Response{Err: "unmapped", IdP: "pete@example.com"}, "code=abc", http.StatusForbidden, 1, "result=unmapped"},
		"denied":            {helper.Response{Err: "denied", IdP: "x"}, "code=abc", http.StatusUnauthorized, 1, "result=denied"},
		"throttled":         {helper.Response{Err: "throttled"}, "code=abc", http.StatusTooManyRequests, 1, "result=throttled"},
		"root side failed":  {helper.Response{Err: "internal"}, "code=abc", http.StatusInternalServerError, 1, "result=error"},
		"user said no":      {helper.Response{}, "error=access_denied&error_description=AADSTS65004+declined", http.StatusUnauthorized, 0, "result=denied"},
		"no code, no error": {helper.Response{}, "", http.StatusUnauthorized, 0, "result=denied"},
	} {
		t.Run(name, func(t *testing.T) {
			s, fr, log := newServerWithFakeRoot(t, "Microsoft")
			fr.result = c.res
			h := s.Handler("")
			state, bind := start(t, h, fr)
			w := get(h, "/oidc/callback?state="+url.QueryEscape(state)+"&"+c.query, bind)
			if w.Code != c.status || cookieNamed(w, cookieName) != nil {
				t.Fatalf("status %d, session cookie %v", w.Code, cookieNamed(w, cookieName))
			}
			if fr.loginCalls != c.calls {
				t.Errorf("root asked %d times", fr.loginCalls)
			}
			if !strings.Contains(log.String(), c.want) {
				t.Errorf("audit lacks %q: %s", c.want, log.String())
			}
			if strings.Contains(w.Body.String(), "AADSTS") {
				t.Error("provider error text shown to the user")
			}
		})
	}
}

func TestOIDCOffByDefault(t *testing.T) {
	s, _, _ := newServerWithFakeRoot(t, "")
	h := s.Handler("")
	if w := post(h, "/oidc/login", nil); w.Code != http.StatusNotFound {
		t.Errorf("start: %d", w.Code)
	}
	if w := get(h, "/oidc/callback?code=a&state=b", nil); w.Code != http.StatusNotFound {
		t.Errorf("callback: %d", w.Code)
	}
	if w := get(h, "/login", nil); strings.Contains(w.Body.String(), "/oidc/login") {
		t.Error("button shown while single sign-on is off")
	}
	s2, _, _ := newServerWithFakeRoot(t, "Contoso")
	if w := get(s2.Handler(""), "/login", nil); !strings.Contains(w.Body.String(), "Sign in with Contoso") {
		t.Error("no button while single sign-on is on")
	}
}

func TestOIDCStateStoreIsBounded(t *testing.T) {
	f := newOIDCFlows()
	for i := 0; i < oidcMaxPerIP; i++ {
		if !f.put("a"+itoa(i), &oidcFlow{ip: "192.0.2.1", expires: farFuture}) {
			t.Fatalf("refused entry %d", i)
		}
	}
	if f.put("one too many", &oidcFlow{ip: "192.0.2.1", expires: farFuture}) {
		t.Error("one address got more than its share")
	}
	// Somebody else can still sign in, and the first address again once one finishes.
	if !f.put("other", &oidcFlow{ip: "192.0.2.2", expires: farFuture}) {
		t.Error("a second address was locked out by the first")
	}
	f.take("a0")
	if !f.put("again", &oidcFlow{ip: "192.0.2.1", expires: farFuture}) {
		t.Error("a finished sign-in did not free a slot")
	}
	// Abandoned flows expire and stop counting.
	g := newOIDCFlows()
	for i := 0; i < oidcMaxPerIP; i++ {
		g.put("x"+itoa(i), &oidcFlow{ip: "192.0.2.3", expires: time.Now().Add(-time.Second)})
	}
	if !g.put("fresh", &oidcFlow{ip: "192.0.2.3", expires: farFuture}) {
		t.Error("expired flows still count against the address")
	}
	// The overall cap holds across addresses.
	h := newOIDCFlows()
	for i := 0; i < oidcMaxFlows; i++ {
		if !h.put(itoa(i), &oidcFlow{ip: "10.0." + itoa(i/200) + "." + itoa(i%200), expires: farFuture}) {
			t.Fatalf("refused entry %d", i)
		}
	}
	if h.put("one too many", &oidcFlow{ip: "198.51.100.1", expires: farFuture}) {
		t.Error("store grew past its limit")
	}
}
