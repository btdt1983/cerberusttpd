// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/limiter"
)

func testServer(t *testing.T) *server {
	t.Helper()
	s := &server{Config: Config{Shares: true, ShareMaxTTL: 48 * time.Hour, DataDir: t.TempDir()}, limit: limiter.NewLogin()}
	s.shares = loadShares(s.DataDir)
	s.shareSem = make(chan struct{}, 4)
	s.shareLimit = limiter.NewLogin()
	return s
}

func TestShareLifecycle(t *testing.T) {
	s := testServer(t)
	jan, piet := s.newGrant("jan"), s.newGrant("piet")

	if r := s.shareCreate(Request{Grant: "nope", Path: "a.txt", TTL: 60}); r.Err != "denied" {
		t.Fatalf("bad grant: %q", r.Err)
	}
	for name, req := range map[string]Request{
		"no path":     {Grant: jan, TTL: 60},
		"part file":   {Grant: jan, Path: "x/.cerb-1.part", TTL: 60},
		"no ttl":      {Grant: jan, Path: "a.txt"},
		"ttl too big": {Grant: jan, Path: "a.txt", TTL: 49 * 3600},
		"negative":    {Grant: jan, Path: "a.txt", TTL: 60, Max: -1},
		"long pw":     {Grant: jan, Path: "a.txt", TTL: 60, Password: string(make([]byte, 65))},
	} {
		if r := s.shareCreate(req); r.Err != "invalid" {
			t.Errorf("%s: err %q, want invalid", name, r.Err)
		}
	}
	r := s.shareCreate(Request{Grant: jan, Path: "../a/./b.txt", TTL: 3600, Max: 2, Password: "geheim"})
	if r.Err != "" || r.Token == "" || r.ShareID == "" {
		t.Fatalf("create: %+v", r)
	}
	rec := s.shares.byToken(r.Token)
	if rec == nil || rec.Path != "a/b.txt" || rec.Owner != "jan" || rec.PW == "" || rec.PW == "geheim" {
		t.Fatalf("record: %+v", rec)
	}
	// The token itself is not on disk.
	if st := loadShares(s.DataDir); st.byToken(r.Token) == nil || len(st.m) != 1 {
		t.Fatal("share not persisted")
	}
	if b := readFile(t, s.shares.file); contains(b, r.Token) {
		t.Fatal("token is stored in the clear")
	}

	if l := s.shareList(Request{Grant: piet}); len(l.Shares) != 0 {
		t.Fatalf("piet sees jan's shares: %+v", l.Shares)
	}
	if l := s.shareList(Request{Grant: jan}); len(l.Shares) != 1 || !l.Shares[0].HasPW {
		t.Fatalf("jan's list: %+v", l.Shares)
	}
	if rv := s.shareRevoke(Request{Grant: piet, ShareID: r.ShareID}); rv.Err != "notfound" {
		t.Fatalf("piet revoked jan's share: %+v", rv)
	}
	if in := s.shareInfo(Request{Token: r.Token}); !in.OK || in.Name != "b.txt" || !in.HasPW {
		t.Fatalf("info: %+v", in)
	}
	if rv := s.shareRevoke(Request{Grant: jan, ShareID: r.ShareID}); !rv.OK {
		t.Fatalf("revoke: %+v", rv)
	}
	if in := s.shareInfo(Request{Token: r.Token}); in.Err != "unavailable" {
		t.Fatalf("revoked share still answers: %+v", in)
	}
	if st := loadShares(s.DataDir); len(st.m) != 0 {
		t.Fatal("revocation not persisted")
	}
}

func TestShareOffAndLimits(t *testing.T) {
	s := testServer(t)
	g := s.newGrant("jan")
	for i := 0; i < shareMaxPerUser; i++ {
		if r := s.shareCreate(Request{Grant: g, Path: "a.txt", TTL: 60}); r.Err != "" {
			t.Fatalf("create %d: %q", i, r.Err)
		}
	}
	if r := s.shareCreate(Request{Grant: g, Path: "a.txt", TTL: 60}); r.Err != "toomany" {
		t.Fatalf("cap: %q", r.Err)
	}
	s.Shares = false
	if r := s.shareCreate(Request{Grant: g, Path: "a.txt", TTL: 60}); r.Err != "disabled" {
		t.Fatalf("off: %q", r.Err)
	}
	if r, f := s.shareOpen(Request{Token: "x"}); r.Err != "unavailable" || f != nil {
		t.Fatalf("open while off: %+v", r)
	}
}

func TestShareUsableAndPurge(t *testing.T) {
	now := time.Now()
	r := &shareRec{Expires: now.Add(time.Hour), Max: 2, Used: 1}
	if usable(r, now) != "" {
		t.Error("fresh share unusable")
	}
	r.Used = 2
	if usable(r, now) != "exhausted" {
		t.Error("used up share usable")
	}
	r.Used, r.Expires = 0, now.Add(-time.Second)
	if usable(r, now) != "expired" {
		t.Error("expired share usable")
	}

	s := testServer(t)
	g := s.newGrant("jan")
	a := s.shareCreate(Request{Grant: g, Path: "a", TTL: 60})
	s.shares.byToken(a.Token).Expires = now.Add(-2 * shareKeepAfter)
	b := s.shareCreate(Request{Grant: g, Path: "b", TTL: 60})
	s.purgeShares(now)
	if s.shares.byToken(a.Token) != nil || s.shares.byToken(b.Token) == nil {
		t.Error("purge removed the wrong records")
	}
}

func TestGrantExpires(t *testing.T) {
	s := testServer(t)
	g := s.newGrant("jan")
	if u, ok := s.grantUser(g); !ok || u != "jan" {
		t.Fatal("grant not accepted")
	}
	s.purgeGrants(time.Now().Add(grantLife + time.Minute))
	if _, ok := s.grantUser(g); ok {
		t.Error("expired grant accepted")
	}
	if _, ok := s.grantUser(""); ok {
		t.Error("empty grant accepted")
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestCountsAsDownload(t *testing.T) {
	for _, c := range []struct {
		max  int
		rng  string
		want bool
	}{
		{0, "", true}, {0, "bytes=0-", true}, {0, "bytes=1000-", false}, {0, "bytes=0-0", false},
		{1, "", true}, {1, "bytes=0-99999999", true}, {1, "bytes=1000-", true}, {1, "bytes=0-0", true},
	} {
		if got := countsAsDownload(c.max, c.rng); got != c.want {
			t.Errorf("max=%d range=%q: %v, want %v", c.max, c.rng, got, c.want)
		}
	}
}
