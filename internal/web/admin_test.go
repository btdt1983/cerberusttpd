// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuditRing(t *testing.T) {
	r := newRing()
	for i := 0; i < ringSize+10; i++ {
		u := "a"
		if i%2 == 1 {
			u = "b"
		}
		r.add(auditEvent{Event: "login", User: u, Result: "ok", Detail: itoa(i)})
	}
	all := r.recent("", "", "", 5)
	if len(all) != 5 || all[0].Detail != itoa(ringSize+9) || all[4].Detail != itoa(ringSize+5) {
		t.Fatalf("newest first: %+v", all)
	}
	b := r.recent("b", "login", "ok", 3)
	if len(b) != 3 || b[0].User != "b" || b[1].Detail != itoa(ringSize+7) {
		t.Fatalf("filter: %+v", b)
	}
	if got := r.recent("nobody", "", "", 10); len(got) != 0 {
		t.Fatalf("no match: %+v", got)
	}
	if got := len(r.recent("", "", "", ringSize*2)); got != ringSize {
		t.Fatalf("old events were not dropped: %d", got)
	}
	if n := len(newRing().recent("", "", "", 5)); n != 0 {
		t.Fatalf("empty ring returned %d events", n)
	}
}

func TestSessionListKill(t *testing.T) {
	ss := newSessions()
	t1, _ := ss.create(&Session{User: "jan", Stage: StageFull, IP: "1.2.3.4", Auth: "password"})
	ss.create(&Session{User: "piet", Stage: StageFull})
	ss.create(&Session{User: "pending", Stage: StagePassword}) // not signed in yet
	k, _ := key(t1)
	rows := ss.list(time.Now(), sessionID(k))
	if len(rows) != 2 {
		t.Fatalf("rows: %+v", rows)
	}
	var mine, other string
	for _, r := range rows {
		if r.Mine {
			mine = r.User
		} else {
			other = r.ID
		}
	}
	if mine != "jan" {
		t.Errorf("own session not marked: %+v", rows)
	}
	if _, ok := ss.kill("0000000000000000"); ok {
		t.Error("killed a session that does not exist")
	}
	if who, ok := ss.kill(other); !ok || who != "piet" {
		t.Errorf("kill: %q %v", who, ok)
	}
	if len(ss.list(time.Now(), "")) != 1 {
		t.Error("session still listed after kill")
	}
}

func adminReq(h http.Handler, method, target, cookie, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAdminAccess(t *testing.T) {
	s := New(nil)
	s.Status = []StatusItem{{"Version", "x"}}
	h := s.Handler("")
	user, _ := s.sess.create(&Session{User: "jan", Stage: StageFull})
	adm, _ := s.sess.create(&Session{User: "beheer", Admin: true, Stage: StageFull, IP: "9.9.9.9", Auth: "password"})
	victim, _ := s.sess.create(&Session{User: "piet", Stage: StageFull})
	vk, _ := key(victim)

	if w := adminReq(h, "GET", "/admin", "", ""); w.Code != http.StatusSeeOther {
		t.Errorf("anonymous: %d", w.Code)
	}
	for _, c := range []struct{ m, u, body string }{
		{"GET", "/admin", ""}, {"POST", "/admin/kill", "id=" + sessionID(vk)}, {"POST", "/admin/revoke", "id=x"},
	} {
		if w := adminReq(h, c.m, c.u, user, c.body); w.Code != http.StatusForbidden {
			t.Errorf("non-admin %s %s: %d", c.m, c.u, w.Code)
		}
	}
	if s.sess.peek(victim) == nil {
		t.Fatal("a non-admin ended someone's session")
	}
	w := adminReq(h, "GET", "/admin", adm, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "piet") || !strings.Contains(w.Body.String(), "9.9.9.9") {
		t.Fatalf("admin page: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), victim) || strings.Contains(w.Body.String(), adm) {
		t.Error("the page shows a session token")
	}
	// An administrator cannot end their own session here.
	ak, _ := key(adm)
	if w := adminReq(h, "POST", "/admin/kill", adm, url.Values{"id": {sessionID(ak)}}.Encode()); w.Code == http.StatusSeeOther || s.sess.peek(adm) == nil {
		t.Errorf("own session ended: %d", w.Code)
	}
	if w := adminReq(h, "POST", "/admin/kill", adm, url.Values{"id": {sessionID(vk)}}.Encode()); w.Code != http.StatusSeeOther {
		t.Errorf("kill: %d", w.Code)
	}
	if s.sess.peek(victim) != nil {
		t.Error("session still alive")
	}
	if ev := s.ring.recent("beheer", "admin_session_end", "ok", 5); len(ev) != 1 || !strings.Contains(ev[0].Detail, "piet") {
		t.Errorf("not audited: %+v", ev)
	}
	if ev := s.ring.recent("jan", "admin", "forbidden", 5); len(ev) == 0 {
		t.Error("refused access not audited")
	}
}

// Sharing with people and share links are separate switches.
func TestSharingSwitches(t *testing.T) {
	code := func(s *Server, method, target string) int {
		return adminReq(s.Handler(""), method, target, "", "").Code
	}
	people := New(nil)
	people.ShareUsers = true
	if got := code(people, "GET", "/shared"); got != http.StatusSeeOther {
		t.Errorf("people only: /shared is %d, want a redirect to the login", got)
	}
	if got := code(people, "GET", "/share?path=a"); got != http.StatusSeeOther {
		t.Errorf("people only: /share is %d", got)
	}
	if got := code(people, "GET", "/shares"); got != http.StatusNotFound {
		t.Errorf("people only: /shares is %d, want 404", got)
	}
	if got := code(people, "GET", "/s/x/get"); got != http.StatusNotFound {
		t.Errorf("people only: a public link route exists (%d)", got)
	}
	links := New(nil)
	links.Shares = true
	if got := code(links, "GET", "/shared"); got != http.StatusNotFound {
		t.Errorf("links only: /shared is %d, want 404", got)
	}
	if got := code(links, "GET", "/shares"); got != http.StatusSeeOther {
		t.Errorf("links only: /shares is %d", got)
	}
	none := New(nil)
	for _, p := range []string{"/share?path=a", "/shared", "/shares", "/s/x"} {
		if got := code(none, "GET", p); got != http.StatusNotFound {
			t.Errorf("nothing on: %s is %d, want 404", p, got)
		}
	}
	if !people.Sharing() || !people.Internal() || links.Internal() || none.Sharing() {
		t.Error("Sharing/Internal do not follow the settings")
	}
}
